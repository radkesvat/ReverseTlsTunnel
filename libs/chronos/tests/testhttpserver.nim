#                Chronos Test Suite
#            (c) Copyright 2021-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[strutils, algorithm]
import ".."/chronos/unittest2/asynctests,
       ".."/chronos,
       ".."/chronos/apps/http/[httpserver, httpcommon, httpdebug]
import stew/base10

{.used.}

suite "HTTP server testing suite":
  type
    TooBigTest = enum
      GetBodyTest, ConsumeBodyTest, PostUrlTest, PostMultipartTest
    TestHttpResponse = object
      headers: HttpTable
      data: string

  proc httpClient(address: TransportAddress,
                  data: string): Future[string] {.async.} =
    var transp: StreamTransport
    try:
      transp = await connect(address)
      if len(data) > 0:
        let wres {.used.} = await transp.write(data)
      var rres = await transp.read()
      return bytesToString(rres)
    except CatchableError:
      return "EXCEPTION"
    finally:
      if not(isNil(transp)):
        await closeWait(transp)

  proc httpClient2(transp: StreamTransport,
                   request: string,
                   length: int): Future[TestHttpResponse] {.async.} =
    var buffer = newSeq[byte](4096)
    var sep = @[0x0D'u8, 0x0A'u8, 0x0D'u8, 0x0A'u8]
    let wres = await transp.write(request)
    if wres != len(request):
      raise newException(ValueError, "Unable to write full request")
    let hres = await transp.readUntil(addr buffer[0], len(buffer), sep)
    var hdata = @buffer
    hdata.setLen(hres)
    zeroMem(addr buffer[0], len(buffer))
    await transp.readExactly(addr buffer[0], length)
    let data = bytesToString(buffer.toOpenArray(0, length - 1))
    let headers =
      block:
        let resp = parseResponse(hdata, false)
        if resp.failed():
          raise newException(ValueError, "Unable to decode response headers")
        var res = HttpTable.init()
        for key, value in resp.headers(hdata):
          res.add(key, value)
        res
    return TestHttpResponse(headers: headers, data: data)

  proc testTooBigBodyChunked(operation: TooBigTest): Future[bool] {.async.} =
    var serverRes = false
    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      if r.isOk():
        let request = r.get()
        try:
          case operation
          of GetBodyTest:
            let body {.used.} = await request.getBody()
          of ConsumeBodyTest:
            await request.consumeBody()
          of PostUrlTest:
            let ptable {.used.} = await request.post()
          of PostMultipartTest:
            let ptable {.used.} = await request.post()
        except HttpCriticalError as exc:
          if exc.code == Http413:
            serverRes = true
          # Reraising exception, because processor should properly handle it.
          raise exc
      else:
        return defaultResponse()

    let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
    let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                maxRequestBodySize = 10,
                                socketFlags = socketFlags)
    if res.isErr():
      return false

    let server = res.get()
    server.start()
    let address = server.instance.localAddress()

    let request =
      case operation
      of GetBodyTest, ConsumeBodyTest, PostUrlTest:
        "POST / HTTP/1.1\r\n" &
        "Content-Type: application/x-www-form-urlencoded\r\n" &
        "Transfer-Encoding: chunked\r\n" &
        "Cookie: 2\r\n\r\n" &
        "5\r\na=a&b\r\n5\r\n=b&c=\r\n4\r\nc&d=\r\n4\r\n%D0%\r\n" &
        "2\r\n9F\r\n0\r\n\r\n"
      of PostMultipartTest:
        "POST / HTTP/1.1\r\n" &
        "Host: 127.0.0.1:30080\r\n" &
        "Transfer-Encoding: chunked\r\n" &
        "Content-Type: multipart/form-data; boundary=f98f0\r\n\r\n" &
        "3b\r\n--f98f0\r\nContent-Disposition: form-data; name=\"key1\"" &
        "\r\n\r\nA\r\n\r\n" &
        "3b\r\n--f98f0\r\nContent-Disposition: form-data; name=\"key2\"" &
        "\r\n\r\nB\r\n\r\n" &
        "3b\r\n--f98f0\r\nContent-Disposition: form-data; name=\"key3\"" &
        "\r\n\r\nC\r\n\r\n" &
        "b\r\n--f98f0--\r\n\r\n" &
        "0\r\n\r\n"

    let data = await httpClient(address, request)
    await server.stop()
    await server.closeWait()
    return serverRes and (data.startsWith("HTTP/1.1 413"))

  test "Request headers timeout test":
    proc testTimeout(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          let request = r.get()
          return await request.respond(Http200, "TEST_OK", HttpTable.init())
        else:
          if r.error.kind == HttpServerError.TimeoutError:
            serverRes = true
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"),
                                  process, socketFlags = socketFlags,
                                  httpHeadersTimeout = 100.milliseconds)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()
      let data = await httpClient(address, "")
      await server.stop()
      await server.closeWait()
      return serverRes and (data.startsWith("HTTP/1.1 408"))

    check waitFor(testTimeout()) == true

  test "Empty headers test":
    proc testEmpty(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          let request = r.get()
          return await request.respond(Http200, "TEST_OK", HttpTable.init())
        else:
          if r.error.kind == HttpServerError.CriticalError:
            serverRes = true
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"),
                                  process, socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let data = await httpClient(address, "\r\n\r\n")
      await server.stop()
      await server.closeWait()
      return serverRes and (data.startsWith("HTTP/1.1 400"))

    check waitFor(testEmpty()) == true

  test "Too big headers test":
    proc testTooBig(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          let request = r.get()
          return await request.respond(Http200, "TEST_OK", HttpTable.init())
        else:
          if r.error.error == HttpServerError.CriticalError:
            serverRes = true
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  maxHeadersSize = 10,
                                  socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let data = await httpClient(address, "GET / HTTP/1.1\r\n\r\n")
      await server.stop()
      await server.closeWait()
      return serverRes and (data.startsWith("HTTP/1.1 431"))

    check waitFor(testTooBig()) == true

  test "Too big request body test (content-length)":
    proc testTooBigBody(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          discard
        else:
          if r.error.error == HttpServerError.CriticalError:
            serverRes = true
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  maxRequestBodySize = 10,
                                  socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let request = "GET / HTTP/1.1\r\nContent-Length: 20\r\n\r\n"
      let data = await httpClient(address, request)
      await server.stop()
      await server.closeWait()
      return serverRes and (data.startsWith("HTTP/1.1 413"))

    check waitFor(testTooBigBody()) == true

  test "Too big request body test (getBody()/chunked encoding)":
    check:
      waitFor(testTooBigBodyChunked(GetBodyTest)) == true

  test "Too big request body test (consumeBody()/chunked encoding)":
    check:
      waitFor(testTooBigBodyChunked(ConsumeBodyTest)) == true

  test "Too big request body test (post()/urlencoded/chunked encoding)":
    check:
      waitFor(testTooBigBodyChunked(PostUrlTest)) == true

  test "Too big request body test (post()/multipart/chunked encoding)":
    check:
      waitFor(testTooBigBodyChunked(PostMultipartTest)) == true

  test "Query arguments test":
    proc testQuery(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          let request = r.get()
          var kres = newSeq[string]()
          for k, v in request.query.stringItems():
            kres.add(k & ":" & v)
          sort(kres)
          serverRes = true
          return await request.respond(Http200, "TEST_OK:" & kres.join(":"),
                                       HttpTable.init())
        else:
          serverRes = false
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let data1 = await httpClient(address,
                                  "GET /?a=1&a=2&b=3&c=4 HTTP/1.0\r\n\r\n")
      let data2 = await httpClient(address,
              "GET /?a=%D0%9F&%D0%A4=%D0%91&b=%D0%A6&c=%D0%AE HTTP/1.0\r\n\r\n")
      await server.stop()
      await server.closeWait()
      let r = serverRes and
              (data1.find("TEST_OK:a:1:a:2:b:3:c:4") >= 0) and
              (data2.find("TEST_OK:a:П:b:Ц:c:Ю:Ф:Б") >= 0)
      return r

    check waitFor(testQuery()) == true

  test "Headers test":
    proc testHeaders(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          let request = r.get()
          var kres = newSeq[string]()
          for k, v in request.headers.stringItems():
            kres.add(k & ":" & v)
          sort(kres)
          serverRes = true
          return await request.respond(Http200, "TEST_OK:" & kres.join(":"),
                                       HttpTable.init())
        else:
          serverRes = false
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let message =
        "GET / HTTP/1.0\r\n" &
        "Host: www.google.com\r\n" &
        "Content-Type: text/html\r\n" &
        "Expect: 100-continue\r\n" &
        "Cookie: 1\r\n" &
        "Cookie: 2\r\n\r\n"
      let expect = "TEST_OK:content-type:text/html:cookie:1:cookie:2" &
                   ":expect:100-continue:host:www.google.com"
      let data = await httpClient(address, message)
      await server.stop()
      await server.closeWait()
      return serverRes and (data.find(expect) >= 0)

    check waitFor(testHeaders()) == true

  test "POST arguments (urlencoded/content-length) test":
    proc testPostUrl(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          var kres = newSeq[string]()
          let request = r.get()
          if request.meth in PostMethods:
            let post = await request.post()
            for k, v in post.stringItems():
              kres.add(k & ":" & v)
            sort(kres)
            serverRes = true
          return await request.respond(Http200, "TEST_OK:" & kres.join(":"),
                                       HttpTable.init())
        else:
          serverRes = false
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let message =
        "POST / HTTP/1.0\r\n" &
        "Content-Type: application/x-www-form-urlencoded\r\n" &
        "Content-Length: 20\r\n" &
        "Cookie: 2\r\n\r\n" &
        "a=a&b=b&c=c&d=%D0%9F"
      let data = await httpClient(address, message)
      let expect = "TEST_OK:a:a:b:b:c:c:d:П"
      await server.stop()
      await server.closeWait()
      return serverRes and (data.find(expect) >= 0)

    check waitFor(testPostUrl()) == true

  test "POST arguments (urlencoded/chunked encoding) test":
    proc testPostUrl2(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          var kres = newSeq[string]()
          let request = r.get()
          if request.meth in PostMethods:
            let post = await request.post()
            for k, v in post.stringItems():
              kres.add(k & ":" & v)
            sort(kres)
            serverRes = true
          return await request.respond(Http200, "TEST_OK:" & kres.join(":"),
                                       HttpTable.init())
        else:
          serverRes = false
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let message =
        "POST / HTTP/1.0\r\n" &
        "Content-Type: application/x-www-form-urlencoded\r\n" &
        "Transfer-Encoding: chunked\r\n" &
        "Cookie: 2\r\n\r\n" &
        "5\r\na=a&b\r\n5\r\n=b&c=\r\n4\r\nc&d=\r\n4\r\n%D0%\r\n" &
        "2\r\n9F\r\n0\r\n\r\n"
      let data = await httpClient(address, message)
      let expect = "TEST_OK:a:a:b:b:c:c:d:П"
      await server.stop()
      await server.closeWait()
      return serverRes and (data.find(expect) >= 0)

    check waitFor(testPostUrl2()) == true

  test "POST arguments (multipart/content-length) test":
    proc testPostMultipart(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          var kres = newSeq[string]()
          let request = r.get()
          if request.meth in PostMethods:
            let post = await request.post()
            for k, v in post.stringItems():
              kres.add(k & ":" & v)
            sort(kres)
            serverRes = true
          return await request.respond(Http200, "TEST_OK:" & kres.join(":"),
                                       HttpTable.init())
        else:
          serverRes = false
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let message =
        "POST / HTTP/1.0\r\n" &
        "Host: 127.0.0.1:30080\r\n" &
        "User-Agent: curl/7.55.1\r\n" &
        "Accept: */*\r\n" &
        "Content-Length: 343\r\n" &
        "Content-Type: multipart/form-data; " &
        "boundary=------------------------ab5706ba6f80b795\r\n\r\n" &
        "--------------------------ab5706ba6f80b795\r\n" &
        "Content-Disposition: form-data; name=\"key1\"\r\n\r\n" &
        "value1\r\n" &
        "--------------------------ab5706ba6f80b795\r\n" &
        "Content-Disposition: form-data; name=\"key2\"\r\n\r\n" &
        "value2\r\n" &
        "--------------------------ab5706ba6f80b795\r\n" &
        "Content-Disposition: form-data; name=\"key2\"\r\n\r\n" &
        "value4\r\n" &
        "--------------------------ab5706ba6f80b795--\r\n"
      let data = await httpClient(address, message)
      let expect = "TEST_OK:key1:value1:key2:value2:key2:value4"
      await server.stop()
      await server.closeWait()
      return serverRes and (data.find(expect) >= 0)

    check waitFor(testPostMultipart()) == true

  test "POST arguments (multipart/chunked encoding) test":
    proc testPostMultipart2(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          var kres = newSeq[string]()
          let request = r.get()
          if request.meth in PostMethods:
            let post = await request.post()
            for k, v in post.stringItems():
              kres.add(k & ":" & v)
            sort(kres)
          serverRes = true
          return await request.respond(Http200, "TEST_OK:" & kres.join(":"),
                                       HttpTable.init())
        else:
          serverRes = false
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let message =
        "POST / HTTP/1.0\r\n" &
        "Host: 127.0.0.1:30080\r\n" &
        "Transfer-Encoding: chunked\r\n" &
        "Content-Type: multipart/form-data; boundary=---" &
        "---------------------f98f0e32c55fa2ae\r\n\r\n" &
        "271\r\n" &
        "--------------------------f98f0e32c55fa2ae\r\n" &
        "Content-Disposition: form-data; name=\"key1\"\r\n\r\n" &
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" &
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\r\n" &
        "--------------------------f98f0e32c55fa2ae\r\n" &
        "Content-Disposition: form-data; name=\"key2\"\r\n\r\n" &
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" &
        "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB\r\n" &
        "--------------------------f98f0e32c55fa2ae\r\n" &
        "Content-Disposition: form-data; name=\"key2\"\r\n\r\n" &
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" &
        "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC\r\n" &
        "--------------------------f98f0e32c55fa2ae--\r\n" &
        "\r\n0\r\n\r\n"

      let data = await httpClient(address, message)
      let expect = "TEST_OK:key1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" &
                   "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" &
                   "AAAAA:key2:BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" &
                   "BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB" &
                   "BBB:key2:CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC" &
                   "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC"
      await server.stop()
      await server.closeWait()
      return serverRes and (data.find(expect) >= 0)

    check waitFor(testPostMultipart2()) == true

  test "drop() connections test":
    const ClientsCount = 10

    proc testHTTPdrop(): Future[bool] {.async.} =
      var eventWait = newAsyncEvent()
      var eventContinue = newAsyncEvent()
      var count = 0

      proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
        if r.isOk():
          let request = r.get()
          inc(count)
          if count == ClientsCount:
            eventWait.fire()
          await eventContinue.wait()
          return await request.respond(Http404, "", HttpTable.init())
        else:
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  socketFlags = socketFlags,
                                  maxConnections = 100)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      var clients: seq[Future[string]]
      let message = "GET / HTTP/1.0\r\nHost: https://127.0.0.1:80\r\n\r\n"
      for i in 0 ..< ClientsCount:
        var clientFut = httpClient(address, message)
        if clientFut.finished():
          return false
        clients.add(clientFut)
      # Waiting for all clients to connect to the server
      await eventWait.wait()
      # Dropping
      await server.closeWait()
      # We are firing second event to unblock client loops, but this loops
      # must be already cancelled.
      eventContinue.fire()
      # Now all clients should be dropped
      discard await allFutures(clients).withTimeout(1.seconds)
      for item in clients:
        if item.read() != "":
          return false
      return true

    check waitFor(testHTTPdrop()) == true

  test "Content-Type multipart boundary test":
    const AllowedCharacters = {
      'a' .. 'z', 'A' .. 'Z', '0' .. '9',
      '\'', '(', ')', '+', '_', ',', '-', '.' ,'/', ':', '=', '?'
    }

    const FailureVectors = [
      "",
      "multipart/byteranges; boundary=A",
      "multipart/form-data;",
      "multipart/form-data; boundary",
      "multipart/form-data; boundary=",
      "multipart/form-data; boundaryMore=A",
      "multipart/form-data; charset=UTF-8; boundary",
      "multipart/form-data; charset=UTF-8; boundary=",
      "multipart/form-data; charset=UTF-8; boundary =",
      "multipart/form-data; charset=UTF-8; boundary= ",
      "multipart/form-data; charset=UTF-8; boundaryMore=",
      "multipart/form-data; charset=UTF-8; boundaryMore=A",
      "multipart/form-data; charset=UTF-8; boundaryMore=AAAAAAAAAAAAAAAAAAAA" &
      "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    ]

    const SuccessVectors = [
      ("multipart/form-data; boundary=A", "A"),
      ("multipart/form-data; charset=UTF-8; boundary=B", "B"),
      ("multipart/form-data; charset=UTF-8; boundary=--------------------" &
       "--------------------------------------------------", "-----------" &
       "-----------------------------------------------------------"),
      ("multipart/form-data; boundary=--------------------" &
       "--------------------------------------------------", "-----------" &
       "-----------------------------------------------------------"),
      ("multipart/form-data; boundary=--------------------" &
       "--------------------------------------------------; charset=UTF-8",
       "-----------------------------------------------------------------" &
       "-----"),
      ("multipart/form-data; boundary=\"ABCDEFGHIJKLMNOPQRST" &
       "UVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()+_,-.\"; charset=UTF-8",
       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()" &
       "+_,-."),
      ("multipart/form-data; boundary=\"ABCDEFGHIJKLMNOPQRST" &
       "UVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()+?=:/\"; charset=UTF-8",
       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()" &
       "+?=:/"),
      ("multipart/form-data; charset=UTF-8; boundary=\"ABCDEFGHIJKLMNOPQRST" &
       "UVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()+_,-.\"",
       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()" &
       "+_,-."),
      ("multipart/form-data; charset=UTF-8; boundary=\"ABCDEFGHIJKLMNOPQRST" &
       "UVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()+?=:/\"",
       "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789'()" &
       "+?=:/"),
      ("multipart/form-data; charset=UTF-8; boundary=0123456789ABCDEFGHIJKL" &
       "MNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+-",
       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+-"),
      ("multipart/form-data; boundary=0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZa" &
       "bcdefghijklmnopqrstuvwxyz+-; charset=UTF-8",
       "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz+-")
    ]
    proc performCheck(ch: openArray[string]): HttpResult[string] =
      let cdata = ? getContentType(ch)
      if cdata.mediaType != MediaType.init("multipart/form-data"):
        return err("Invalid media type")
      getMultipartBoundary(cdata)

    for i in 0 ..< 256:
      let boundary = "multipart/form-data; boundary=\"" & $char(i) & "\""
      if char(i) in AllowedCharacters:
        check performCheck([boundary]).isOk()
      else:
        check performCheck([boundary]).isErr()

    check:
      performCheck([]).isErr()
      performCheck(["multipart/form-data; boundary=A",
                    "multipart/form-data; boundary=B"]).isErr()
    for item in FailureVectors:
      check performCheck([item]).isErr()
    for item in SuccessVectors:
      let res = performCheck([item[0]])
      check:
        res.isOk()
        item[1] == res.get()

  test "HttpTable integer parser test":
    const TestVectors = [
      ("", 0'u64), ("0", 0'u64), ("-0", 0'u64), ("0-", 0'u64),
      ("01", 1'u64), ("001", 1'u64), ("0000000000001", 1'u64),
      ("18446744073709551615", 0xFFFF_FFFF_FFFF_FFFF'u64),
      ("18446744073709551616", 0'u64),
      ("99999999999999999999", 0'u64),
      ("999999999999999999999999999999999999", 0'u64),
      ("FFFFFFFFFFFFFFFF", 0'u64),
      ("0123456789ABCDEF", 0'u64)
    ]
    for i in 0 ..< 256:
      let res = Base10.decode(uint64, [char(i)])
      if char(i) in {'0' .. '9'}:
        check:
          res.isOk()
          res.get() == uint64(i - ord('0'))
      else:
        check res.isErr()

    for item in TestVectors:
      var ht = HttpTable.init([("test", item[0])])
      let value = ht.getInt("test")
      check value == item[1]

  test "HttpTable behavior test":
    var table1 = HttpTable.init()
    var table2 = HttpTable.init([("Header1", "value1"), ("Header2", "value2")])
    check:
      table1.isEmpty() == true
      table2.isEmpty() == false

    table1.add("Header1", "value1")
    table1.add("Header2", "value2")
    table1.add("HEADER2", "VALUE3")
    check:
      table1.getList("HeAdEr2") == @["value2", "VALUE3"]
      table1.getString("HeAdEr2") == "value2,VALUE3"
      table2.getString("HEADER1") == "value1"
      table1.count("HEADER2") == 2
      table1.count("HEADER1") == 1
      table1.getLastString("HEADER1") == "value1"
      table1.getLastString("HEADER2") == "VALUE3"
      "header1" in table1 == true
      "HEADER1" in table1 == true
      "header2" in table1 == true
      "HEADER2" in table1 == true
      "HEADER3" in table1 == false

    var
      data1: seq[tuple[key: string, value: string]]
      data2: seq[tuple[key: string, value: seq[string]]]
    for key, value in table1.stringItems(true):
      data1.add((key, value))
    for key, value in table1.items(true):
      data2.add((key, value))

    check:
      data1 == @[("Header2", "value2"), ("Header2", "VALUE3"),
                 ("Header1", "value1")]
      data2 == @[("Header2", @["value2", "VALUE3"]),
                 ("Header1", @["value1"])]

    table1.set("header2", "value4")
    check:
      table1.getList("header2") == @["value4"]
      table1.getString("header2") == "value4"
      table1.count("header2") == 1
      table1.getLastString("header2") == "value4"

  test "getTransferEncoding() test":
    var encodings = [
      "chunked", "compress", "deflate", "gzip", "identity", "x-gzip"
    ]

    const FlagsVectors = [
      {
        TransferEncodingFlags.Identity, TransferEncodingFlags.Chunked,
        TransferEncodingFlags.Compress, TransferEncodingFlags.Deflate,
        TransferEncodingFlags.Gzip
      },
      {
        TransferEncodingFlags.Identity, TransferEncodingFlags.Compress,
        TransferEncodingFlags.Deflate, TransferEncodingFlags.Gzip
      },
      {
        TransferEncodingFlags.Identity, TransferEncodingFlags.Deflate,
        TransferEncodingFlags.Gzip
      },
      { TransferEncodingFlags.Identity, TransferEncodingFlags.Gzip },
      { TransferEncodingFlags.Identity, TransferEncodingFlags.Gzip },
      { TransferEncodingFlags.Gzip },
      { TransferEncodingFlags.Identity }
    ]

    for i in 0 ..< 7:
      var checkEncodings = @encodings
      if i - 1 >= 0:
        for k in 0 .. (i - 1):
          checkEncodings.delete(0)

      while nextPermutation(checkEncodings):
        let res1 = getTransferEncoding([checkEncodings.join(", ")])
        let res2 = getTransferEncoding([checkEncodings.join(",")])
        let res3 = getTransferEncoding([checkEncodings.join("")])
        let res4 = getTransferEncoding([checkEncodings.join(" ")])
        let res5 = getTransferEncoding([checkEncodings.join(" , ")])
        check:
          res1.isOk()
          res1.get() == FlagsVectors[i]
          res2.isOk()
          res2.get() == FlagsVectors[i]
          res3.isErr()
          res4.isErr()
          res5.isOk()
          res5.get() == FlagsVectors[i]

    check:
      getTransferEncoding([]).tryGet() == { TransferEncodingFlags.Identity }
      getTransferEncoding(["", ""]).tryGet() ==
        { TransferEncodingFlags.Identity }

  test "getContentEncoding() test":
    var encodings = [
      "br", "compress", "deflate", "gzip", "identity", "x-gzip"
    ]

    const FlagsVectors = [
      {
        ContentEncodingFlags.Identity, ContentEncodingFlags.Br,
        ContentEncodingFlags.Compress, ContentEncodingFlags.Deflate,
        ContentEncodingFlags.Gzip
      },
      {
        ContentEncodingFlags.Identity, ContentEncodingFlags.Compress,
        ContentEncodingFlags.Deflate, ContentEncodingFlags.Gzip
      },
      {
        ContentEncodingFlags.Identity, ContentEncodingFlags.Deflate,
        ContentEncodingFlags.Gzip
      },
      { ContentEncodingFlags.Identity, ContentEncodingFlags.Gzip },
      { ContentEncodingFlags.Identity, ContentEncodingFlags.Gzip },
      { ContentEncodingFlags.Gzip },
      { ContentEncodingFlags.Identity }
    ]

    for i in 0 ..< 7:
      var checkEncodings = @encodings
      if i - 1 >= 0:
        for k in 0 .. (i - 1):
          checkEncodings.delete(0)

      while nextPermutation(checkEncodings):
        let res1 = getContentEncoding([checkEncodings.join(", ")])
        let res2 = getContentEncoding([checkEncodings.join(",")])
        let res3 = getContentEncoding([checkEncodings.join("")])
        let res4 = getContentEncoding([checkEncodings.join(" ")])
        let res5 = getContentEncoding([checkEncodings.join(" , ")])
        check:
          res1.isOk()
          res1.get() == FlagsVectors[i]
          res2.isOk()
          res2.get() == FlagsVectors[i]
          res3.isErr()
          res4.isErr()
          res5.isOk()
          res5.get() == FlagsVectors[i]

    check:
      getContentEncoding([]).tryGet() == { ContentEncodingFlags.Identity }
      getContentEncoding(["", ""]).tryGet() == { ContentEncodingFlags.Identity }

  test "queryParams() test":
    const Vectors = [
      ("id=1&id=2&id=3&id=4", {}, "id:1,id:2,id:3,id:4"),
      ("id=1,2,3,4", {}, "id:1,2,3,4"),
      ("id=1%2C2%2C3%2C4", {}, "id:1,2,3,4"),
      ("id=", {}, "id:"),
      ("id=&id=", {}, "id:,id:"),
      ("id=1&id=2&id=3&id=4", {QueryParamsFlag.CommaSeparatedArray},
       "id:1,id:2,id:3,id:4"),
      ("id=1,2,3,4", {QueryParamsFlag.CommaSeparatedArray},
       "id:1,id:2,id:3,id:4"),
      ("id=1%2C2%2C3%2C4", {QueryParamsFlag.CommaSeparatedArray},
       "id:1,id:2,id:3,id:4"),
      ("id=", {QueryParamsFlag.CommaSeparatedArray}, "id:"),
      ("id=&id=", {QueryParamsFlag.CommaSeparatedArray}, "id:,id:"),
      ("id=,", {QueryParamsFlag.CommaSeparatedArray}, "id:,id:"),
      ("id=,,", {QueryParamsFlag.CommaSeparatedArray}, "id:,id:,id:"),
      ("id=1&id=2&id=3,4,5,6&id=7%2C8%2C9%2C10",
       {QueryParamsFlag.CommaSeparatedArray},
       "id:1,id:2,id:3,id:4,id:5,id:6,id:7,id:8,id:9,id:10")
    ]

    proc toString(ht: HttpTable): string =
      var res: seq[string]
      for key, value in ht.items():
        for item in value:
          res.add(key & ":" & item)
      res.join(",")

    for vector in Vectors:
      var table = HttpTable.init()
      for key, value in queryParams(vector[0], vector[1]):
        table.add(key, value)
      check toString(table) == vector[2]

  test "preferredContentType() test":
    const
      jsonMediaType = MediaType.init("application/json")
      sszMediaType = MediaType.init("application/octet-stream")
      plainTextMediaType = MediaType.init("text/plain")
      imageMediaType = MediaType.init("image/jpg")

    proc createRequest(acceptHeader: string): HttpRequestRef =
      let headers = HttpTable.init([("accept", acceptHeader)])
      HttpRequestRef(headers: headers)

    proc createRequest(): HttpRequestRef =
      HttpRequestRef(headers: HttpTable.init())

    var singleHeader = @[
      (
        createRequest("application/json"),
        @[
          "application/json"
        ]
      )
    ]

    var complexHeaders = @[
      (
        createRequest(),
        @[
          "*/*",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/json",
          "image/jpg"
        ]
      ),
      (
        createRequest(""),
        @[
          "*/*",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/json",
          "image/jpg"
        ]
      ),
      (
        createRequest("application/json, application/octet-stream"),
        @[
          "application/json",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/json"
        ]
      ),
      (
        createRequest("application/octet-stream, application/json"),
        @[
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/json"
        ]
      ),
      (
        createRequest("application/json;q=0.9, application/octet-stream"),
        @[
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/octet-stream",
          "application/octet-stream",
          "application/octet-stream",
          "application/octet-stream"
        ]
      ),
      (
        createRequest("application/json, application/octet-stream;q=0.9"),
        @[
          "application/json",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/json",
          "application/json",
          "application/json"
        ]
      ),
      (
        createRequest("application/json;q=0.9, application/octet-stream;q=0.8"),
        @[
          "application/json",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/json",
          "application/json",
          "application/json"
        ]
      ),
       (
        createRequest("application/json;q=0.8, application/octet-stream;q=0.9"),
        @[
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/octet-stream",
          "application/octet-stream",
          "application/octet-stream",
          "application/octet-stream"
        ]
      ),
      (
      createRequest("text/plain, application/octet-stream, application/json"),
        @[
          "text/plain",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/json"
        ]
      ),
      (
      createRequest("text/plain, application/json;q=0.8, " &
                    "application/octet-stream;q=0.8"),
        @[
          "text/plain",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "text/plain",
          "text/plain"
        ]
      ),
      (
      createRequest("text/plain, application/json;q=0.8, " &
                    "application/octet-stream;q=0.5"),
        @[
          "text/plain",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/json",
          "text/plain",
          "text/plain"
        ]
      ),
      (
       createRequest("text/plain;q=0.8, application/json, " &
                     "application/octet-stream;q=0.8"),
        @[
          "application/json",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/json",
          "application/json",
          "application/json"
        ]
      ),
      (
      createRequest("text/*, application/json;q=0.8, " &
                    "application/octet-stream;q=0.8"),
        @[
          "text/*",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "text/plain",
          "text/plain"
        ]
      ),
      (
      createRequest("text/*, application/json;q=0.8, " &
                    "application/octet-stream;q=0.5"),
        @[
          "text/*",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/json",
          "text/plain",
          "text/plain"
        ]
      ),
      (createRequest("image/jpg, text/plain, application/octet-stream, " &
                     "application/json"),
         @[
            "image/jpg",
            "application/json",
            "application/octet-stream",
            "application/json",
            "application/octet-stream",
            "application/json",
            "image/jpg"
           ]
        ),
        (createRequest("image/jpg;q=1, text/plain;q=0.2, " &
                       "application/octet-stream;q=0.2, " &
                       "application/json;q=0.2"),
         @[
            "image/jpg",
            "application/json",
            "application/octet-stream",
            "application/json",
            "application/octet-stream",
            "application/json",
            "image/jpg"
           ]
        ),
      (
      createRequest("*/*, application/json;q=0.8, " &
                    "application/octet-stream;q=0.5"),
        @[
          "*/*",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/json",
          "image/jpg"
        ]
      ),
      (
        createRequest("*/*"),
        @[
          "*/*",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/json",
          "image/jpg"
        ]
      ),
      (
        createRequest("application/*"),
        @[
          "application/*",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/octet-stream",
          "application/json",
          "application/json"
        ]
      )
    ]

    for req in singleHeader:
      check $req[0].preferredContentMediaType() == req[1][0]
      let r0 = req[0].preferredContentType()
      let r1 = req[0].preferredContentType(jsonMediaType)
      let r2 = req[0].preferredContentType(sszMediaType)
      let r3 = req[0].preferredContentType(jsonMediaType,
                                           sszMediaType)
      let r4 = req[0].preferredContentType(sszMediaType,
                                           jsonMediaType)
      let r5 = req[0].preferredContentType(jsonMediaType,
                                           sszMediaType,
                                           plainTextMediaType)
      let r6 = req[0].preferredContentType(imageMediaType,
                                           jsonMediaType,
                                           sszMediaType,
                                           plainTextMediaType)
      check:
        r0.isOk() == true
        r1.isOk() == true
        r2.isErr() == true
        r3.isOk() == true
        r4.isOk() == true
        r5.isOk() == true
        r6.isOk() == true
        r0.get() == MediaType.init(req[1][0])
        r1.get() == MediaType.init(req[1][0])
        r3.get() == MediaType.init(req[1][0])
        r4.get() == MediaType.init(req[1][0])
        r5.get() == MediaType.init(req[1][0])
        r6.get() == MediaType.init(req[1][0])

    for req in complexHeaders:
      let r0 = req[0].preferredContentType()
      let r1 = req[0].preferredContentType(jsonMediaType)
      let r2 = req[0].preferredContentType(sszMediaType)
      let r3 = req[0].preferredContentType(jsonMediaType,
                                           sszMediaType)
      let r4 = req[0].preferredContentType(sszMediaType,
                                           jsonMediaType)
      let r5 = req[0].preferredContentType(jsonMediaType,
                                           sszMediaType,
                                           plainTextMediaType)
      let r6 = req[0].preferredContentType(imageMediaType,
                                           jsonMediaType,
                                           sszMediaType,
                                           plainTextMediaType)
      check:
        r0.isOk() == true
        r1.isOk() == true
        r2.isOk() == true
        r3.isOk() == true
        r4.isOk() == true
        r5.isOk() == true
        r6.isOk() == true
        r0.get() == MediaType.init(req[1][0])
        r1.get() == MediaType.init(req[1][1])
        r2.get() == MediaType.init(req[1][2])
        r3.get() == MediaType.init(req[1][3])
        r4.get() == MediaType.init(req[1][4])
        r5.get() == MediaType.init(req[1][5])
        r6.get() == MediaType.init(req[1][6])

  test "SSE server-side events stream test":
    proc testPostMultipart2(): Future[bool] {.async.} =
      var serverRes = false
      proc process(r: RequestFence): Future[HttpResponseRef] {.
           async.} =
        if r.isOk():
          let request = r.get()
          let response = request.getResponse()
          await response.prepareSSE()
          await response.send("event: event1\r\ndata: data1\r\n\r\n")
          await response.send("event: event2\r\ndata: data2\r\n\r\n")
          await response.sendEvent("event3", "data3")
          await response.sendEvent("event4", "data4")
          await response.send("data: data5\r\n\r\n")
          await response.sendEvent("", "data6")
          await response.finish()
          serverRes = true
          return response
        else:
          serverRes = false
          return defaultResponse()

      let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                  socketFlags = socketFlags)
      if res.isErr():
        return false

      let server = res.get()
      server.start()
      let address = server.instance.localAddress()

      let message =
        "GET / HTTP/1.1\r\n" &
        "Host: 127.0.0.1:30080\r\n" &
        "Accept: text/event-stream\r\n" &
        "\r\n"

      let data = await httpClient(address, message)
      let expect = "event: event1\r\ndata: data1\r\n\r\n" &
                   "event: event2\r\ndata: data2\r\n\r\n" &
                   "event: event3\r\ndata: data3\r\n\r\n" &
                   "event: event4\r\ndata: data4\r\n\r\n" &
                   "data: data5\r\n\r\n" &
                   "data: data6\r\n\r\n"
      await server.stop()
      await server.closeWait()
      return serverRes and (data.find(expect) >= 0)

    check waitFor(testPostMultipart2()) == true

  asyncTest "HTTP/1.1 pipeline test":
    const TestMessages = [
      ("GET / HTTP/1.0\r\n\r\n",
       {HttpServerFlags.Http11Pipeline}, false, "close"),
      ("GET / HTTP/1.0\r\nConnection: close\r\n\r\n",
       {HttpServerFlags.Http11Pipeline}, false, "close"),
      ("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
       {HttpServerFlags.Http11Pipeline}, false, "close"),
      ("GET / HTTP/1.0\r\n\r\n",
       {}, false, "close"),
      ("GET / HTTP/1.0\r\nConnection: close\r\n\r\n",
       {}, false, "close"),
      ("GET / HTTP/1.0\r\nConnection: keep-alive\r\n\r\n",
       {}, false, "close"),
      ("GET / HTTP/1.1\r\n\r\n",
       {HttpServerFlags.Http11Pipeline}, true, "keep-alive"),
      ("GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
       {HttpServerFlags.Http11Pipeline}, false, "close"),
      ("GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n",
       {HttpServerFlags.Http11Pipeline}, true, "keep-alive"),
      ("GET / HTTP/1.1\r\n\r\n",
       {}, false, "close"),
      ("GET / HTTP/1.1\r\nConnection: close\r\n\r\n",
       {}, false, "close"),
      ("GET / HTTP/1.1\r\nConnection: keep-alive\r\n\r\n",
       {}, false, "close")
    ]

    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        return await request.respond(Http200, "TEST_OK", HttpTable.init())
      else:
        return defaultResponse()

    for test in TestMessages:
      let
        socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
        serverFlags = test[1]
        res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                socketFlags = socketFlags,
                                serverFlags = serverFlags)
      check res.isOk()

      let
        server = res.get()
        address = server.instance.localAddress()

      server.start()
      var transp: StreamTransport

      transp = await connect(address)
      block:
        let response = await transp.httpClient2(test[0], 7)
        check:
          response.data == "TEST_OK"
          response.headers.getString("connection") == test[3]
      # We do this sleeping here just because we running both server and
      # client in single process, so when we received response from server
      # it does not mean that connection has been immediately closed - it
      # takes some more calls, so we trying to get this calls happens.
      await sleepAsync(50.milliseconds)
      let connectionStillAvailable =
        try:
          let response {.used.} = await transp.httpClient2(test[0], 7)
          true
        except CatchableError:
          false

      check connectionStillAvailable == test[2]

      if not(isNil(transp)):
        await transp.closeWait()
      await server.stop()
      await server.closeWait()

  asyncTest "HTTP debug tests":
    const
      TestsCount = 10
      TestRequest = "GET /httpdebug HTTP/1.1\r\nConnection: keep-alive\r\n\r\n"

    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        return await request.respond(Http200, "TEST_OK", HttpTable.init())
      else:
        return defaultResponse()

    proc client(address: TransportAddress,
                data: string): Future[StreamTransport] {.async.} =
      var transp: StreamTransport
      var buffer = newSeq[byte](4096)
      var sep = @[0x0D'u8, 0x0A'u8, 0x0D'u8, 0x0A'u8]
      try:
        transp = await connect(address)
        let wres {.used.} =
          await transp.write(data)
        let hres {.used.} =
          await transp.readUntil(addr buffer[0], len(buffer), sep)
        transp
      except CatchableError:
        if not(isNil(transp)): await transp.closeWait()
        nil

    let socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
    let res = HttpServerRef.new(initTAddress("127.0.0.1:0"), process,
                                serverFlags = {HttpServerFlags.Http11Pipeline},
                                socketFlags = socketFlags)
    check res.isOk()

    let server = res.get()
    server.start()
    let address = server.instance.localAddress()

    let info = server.getServerInfo()

    check:
      info.connectionType == ConnectionType.NonSecure
      info.address == address
      info.state == HttpServerState.ServerRunning
      info.flags == {HttpServerFlags.Http11Pipeline}
      info.socketFlags == socketFlags

    var clientFutures: seq[Future[StreamTransport]]
    for i in 0 ..< TestsCount:
      clientFutures.add(client(address, TestRequest))
    await allFutures(clientFutures)

    let connections = server.getConnections()
    check len(connections) == TestsCount
    let currentTime = Moment.now()
    for index, connection in connections.pairs():
      let transp = clientFutures[index].read()
      check:
        connection.remoteAddress.get() == transp.localAddress()
        connection.localAddress.get() == transp.remoteAddress()
        connection.connectionType == ConnectionType.NonSecure
        connection.connectionState == ConnectionState.Alive
        connection.query.get("") == "/httpdebug"
        (currentTime - connection.createMoment.get()) != ZeroDuration
        (currentTime - connection.acceptMoment) != ZeroDuration
    var pending: seq[Future[void]]
    for transpFut in clientFutures:
      pending.add(closeWait(transpFut.read()))
    await allFutures(pending)
    await server.stop()
    await server.closeWait()

  test "Leaks test":
    checkLeaks()
