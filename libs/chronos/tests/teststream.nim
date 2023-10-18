#                Chronos Test Suite
#            (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[strutils, os]
import ".."/chronos/unittest2/asynctests
import ".."/chronos, ".."/chronos/[osdefs, oserrno]

{.used.}

when defined(windows):
  proc get_osfhandle*(fd: FileHandle): HANDLE {.
       importc: "_get_osfhandle", header:"<io.h>".}

suite "Stream Transport test suite":
  const
    ConstantMessage = "SOMEDATA"
    BigMessagePattern = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    FilesTestName = "tests/teststream.nim"
    BigMessageCount = 100
    ClientsCount = 5
    MessagesCount = 10
    MessageSize = 20
    FilesCount = 10
    TestsCount = 100

  when defined(windows):
    let addresses = [
      initTAddress("127.0.0.1:33335"),
      initTAddress(r"/LOCAL\testpipe")
    ]
  else:
    let addresses = [
      initTAddress("127.0.0.1:0"),
      initTAddress(r"/tmp/testpipe")
    ]

  let prefixes = ["[IP] ", "[UNIX] "]

  var markFD: int

  proc getCurrentFD(): int =
    let local = initTAddress("127.0.0.1:0")
    let sock = createAsyncSocket(local.getDomain(), SockType.SOCK_DGRAM,
                                 Protocol.IPPROTO_UDP)
    closeSocket(sock)
    return int(sock)

  proc createBigMessage(size: int): seq[byte] =
    var message = "MESSAGE"
    result = newSeq[byte](size)
    for i in 0 ..< len(result):
      result[i] = byte(message[i mod len(message)])

  proc serveClient1(server: StreamServer, transp: StreamTransport) {.async.} =
    while not transp.atEof():
      var data = await transp.readLine()
      if len(data) == 0:
        doAssert(transp.atEof())
        break
      doAssert(data.startsWith("REQUEST"))
      var numstr = data[7..^1]
      var num = parseInt(numstr)
      var ans = "ANSWER" & $num & "\r\n"
      var res = await transp.write(cast[pointer](addr ans[0]), len(ans))
      doAssert(res == len(ans))
    transp.close()
    await transp.join()

  proc serveClient2(server: StreamServer, transp: StreamTransport) {.async.} =
    var buffer: array[20, char]
    var check = "REQUEST"
    while not transp.atEof():
      zeroMem(addr buffer[0], MessageSize)
      try:
        await transp.readExactly(addr buffer[0], MessageSize)
      except TransportIncompleteError:
        break
      doAssert(equalMem(addr buffer[0], addr check[0], len(check)))
      var numstr = ""
      var i = 7
      while i < MessageSize and (buffer[i] in {'0'..'9'}):
        numstr.add(buffer[i])
        inc(i)
      var num = parseInt(numstr)
      var ans = "ANSWER" & $num
      zeroMem(addr buffer[0], MessageSize)
      copyMem(addr buffer[0], addr ans[0], len(ans))
      var res = await transp.write(cast[pointer](addr buffer[0]), MessageSize)
      doAssert(res == MessageSize)
    transp.close()
    await transp.join()

  proc serveClient3(server: StreamServer, transp: StreamTransport) {.async.} =
    var buffer: array[20, char]
    var check = "REQUEST"
    var suffixStr = "SUFFIX"
    var suffix = newSeq[byte](6)
    copyMem(addr suffix[0], addr suffixStr[0], len(suffixStr))
    var counter = MessagesCount
    while counter > 0:
      zeroMem(addr buffer[0], MessageSize)
      var res = await transp.readUntil(addr buffer[0], MessageSize, suffix)
      doAssert(equalMem(addr buffer[0], addr check[0], len(check)))
      var numstr = ""
      var i = 7
      while i < MessageSize and (buffer[i] in {'0'..'9'}):
        numstr.add(buffer[i])
        inc(i)
      var num = parseInt(numstr)
      doAssert(len(numstr) < 8)
      var ans = "ANSWER" & $num & "SUFFIX"
      zeroMem(addr buffer[0], MessageSize)
      copyMem(addr buffer[0], addr ans[0], len(ans))
      res = await transp.write(cast[pointer](addr buffer[0]), len(ans))
      doAssert(res == len(ans))
      dec(counter)
    transp.close()
    await transp.join()

  proc serveClient4(server: StreamServer, transp: StreamTransport) {.async.} =
    var pathname = await transp.readLine()
    var size = await transp.readLine()
    var sizeNum = parseInt(size)
    doAssert(sizeNum >= 0)
    var rbuffer = newSeq[byte](sizeNum)
    await transp.readExactly(addr rbuffer[0], sizeNum)
    var lbuffer = readFile(pathname)
    doAssert(len(lbuffer) == sizeNum)
    doAssert(equalMem(addr rbuffer[0], addr lbuffer[0], sizeNum))
    var answer = "OK\r\n"
    var res = await transp.write(cast[pointer](addr answer[0]), len(answer))
    doAssert(res == len(answer))
    transp.close()
    await transp.join()

  proc serveClient7(server: StreamServer, transp: StreamTransport) {.async.} =
    var answer = "DONE\r\n"
    var expect = ""
    var line = await transp.readLine()
    doAssert(len(line) == BigMessageCount * len(BigMessagePattern))
    for i in 0..<BigMessageCount:
      expect.add(BigMessagePattern)
    doAssert(line == expect)
    var res = await transp.write(answer)
    doAssert(res == len(answer))
    transp.close()
    await transp.join()
    server.stop()
    server.close()

  proc serveClient8(server: StreamServer, transp: StreamTransport) {.async.} =
    var answer = "DONE\r\n"
    var strpattern = BigMessagePattern
    var pattern = newSeq[byte](len(BigMessagePattern))
    var expect = newSeq[byte]()
    var data = newSeq[byte]((BigMessageCount + 1) * len(BigMessagePattern))
    var sep = @[0x0D'u8, 0x0A'u8]
    copyMem(addr pattern[0], addr strpattern[0], len(BigMessagePattern))
    var count = await transp.readUntil(addr data[0], len(data), sep = sep)
    doAssert(count == BigMessageCount * len(BigMessagePattern) + 2)
    for i in 0..<BigMessageCount:
      expect.add(pattern)
    expect.add(sep)
    data.setLen(count)
    doAssert(expect == data)
    var res = await transp.write(answer)
    doAssert(res == len(answer))
    transp.close()
    await transp.join()
    server.stop()
    server.close()

  proc swarmWorker1(address: TransportAddress): Future[int] {.async.} =
    var transp = await connect(address)
    for i in 0..<MessagesCount:
      var data = "REQUEST" & $i & "\r\n"
      var res = await transp.write(cast[pointer](addr data[0]), len(data))
      doAssert(res == len(data))
      var ans = await transp.readLine()
      doAssert(ans.startsWith("ANSWER"))
      var numstr = ans[6..^1]
      var num = parseInt(numstr)
      doAssert(num == i)
      inc(result)
    transp.close()
    await transp.join()

  proc swarmWorker2(address: TransportAddress): Future[int] {.async.} =
    var transp = await connect(address)
    var buffer: array[MessageSize, char]
    var check = "ANSWER"
    for i in 0..<MessagesCount:
      var data = "REQUEST" & $i & "\r\n"
      zeroMem(addr buffer[0], MessageSize)
      copyMem(addr buffer[0], addr data[0], min(MessageSize, len(data)))
      var res = await transp.write(cast[pointer](addr buffer[0]), MessageSize)
      doAssert(res == MessageSize)
      zeroMem(addr buffer[0], MessageSize)
      await transp.readExactly(addr buffer[0], MessageSize)
      doAssert(equalMem(addr buffer[0], addr check[0], len(check)))
      var numstr = ""
      var k = 6
      while k < MessageSize and (buffer[k] in {'0'..'9'}):
        numstr.add(buffer[k])
        inc(k)
      var num = parseInt(numstr)
      doAssert(num == i)
      inc(result)
    transp.close()
    await transp.join()

  proc swarmWorker3(address: TransportAddress): Future[int] {.async.} =
    var transp = await connect(address)
    var buffer: array[MessageSize, char]
    var check = "ANSWER"
    var suffixStr = "SUFFIX"
    var suffix = newSeq[byte](6)
    copyMem(addr suffix[0], addr suffixStr[0], len(suffixStr))
    for i in 0..<MessagesCount:
      var data = "REQUEST" & $i & "SUFFIX"
      doAssert(len(data) <= MessageSize)
      zeroMem(addr buffer[0], MessageSize)
      copyMem(addr buffer[0], addr data[0], len(data))
      var res = await transp.write(cast[pointer](addr buffer[0]), len(data))
      doAssert(res == len(data))
      zeroMem(addr buffer[0], MessageSize)
      res = await transp.readUntil(addr buffer[0], MessageSize, suffix)
      doAssert(equalMem(addr buffer[0], addr check[0], len(check)))
      var numstr = ""
      var k = 6
      while k < MessageSize and (buffer[k] in {'0'..'9'}):
        numstr.add(buffer[k])
        inc(k)
      var num = parseInt(numstr)
      doAssert(num == i)
      inc(result)
    transp.close()
    await transp.join()

  proc swarmWorker4(address: TransportAddress): Future[int] {.async.} =
    var transp = await connect(address)
    var ssize: string
    var handle = 0
    var name = FilesTestName
    var size = int(getFileSize(FilesTestName))
    var fhandle = open(FilesTestName)
    when defined(windows):
      handle = int(get_osfhandle(getFileHandle(fhandle)))
    else:
      handle = int(getFileHandle(fhandle))
    doAssert(handle > 0)
    name = name & "\r\n"
    var res = await transp.write(cast[pointer](addr name[0]), len(name))
    doAssert(res == len(name))
    ssize = $size & "\r\n"
    res = await transp.write(cast[pointer](addr ssize[0]), len(ssize))
    doAssert(res == len(ssize))
    var checksize = await transp.writeFile(handle, 0'u, size)
    doAssert(checksize == size)
    close(fhandle)
    var ans = await transp.readLine()
    doAssert(ans == "OK")
    result = 1
    transp.close()
    await transp.join()

  proc swarmWorker7(address: TransportAddress): Future[int] {.async.} =
    var transp = await connect(address)
    var data = BigMessagePattern
    var crlf = "\r\n"
    for i in 0..<BigMessageCount:
      var res = await transp.write(data)
      doAssert(res == len(data))
    var res = await transp.write(crlf)
    doAssert(res == len(crlf))
    var line = await transp.readLine()
    doAssert(line == "DONE")
    result = 1
    transp.close()
    await transp.join()

  proc swarmWorker8(address: TransportAddress): Future[int] {.async.} =
    var transp = await connect(address)
    var data = BigMessagePattern
    var crlf = "\r\n"
    for i in 0..<BigMessageCount:
      var res = await transp.write(data)
      doAssert(res == len(data))
    var res = await transp.write(crlf)
    doAssert(res == len(crlf))
    var line = await transp.readLine()
    doAssert(line == "DONE")
    result = 1
    transp.close()
    await transp.join()

  proc waitAll[T](futs: seq[Future[T]]): Future[void] =
    var counter = len(futs)
    var retFuture = newFuture[void]("waitAll")
    proc cb(udata: pointer) =
      dec(counter)
      if counter == 0:
        retFuture.complete()
    for fut in futs:
      fut.addCallback(cb)
    return retFuture

  proc swarmManager1(address: TransportAddress): Future[int] {.async.} =
    var workers = newSeq[Future[int]](ClientsCount)
    for i in 0..<ClientsCount:
      workers[i] = swarmWorker1(address)
    await waitAll(workers)
    for i in 0..<ClientsCount:
      var res = workers[i].read()
      result += res

  proc swarmManager2(address: TransportAddress): Future[int] {.async.} =
    var workers = newSeq[Future[int]](ClientsCount)
    for i in 0..<ClientsCount:
      workers[i] = swarmWorker2(address)
    await waitAll(workers)
    for i in 0..<ClientsCount:
      var res = workers[i].read()
      result += res

  proc swarmManager3(address: TransportAddress): Future[int] {.async.} =
    var workers = newSeq[Future[int]](ClientsCount)
    for i in 0..<ClientsCount:
      workers[i] = swarmWorker3(address)
    await waitAll(workers)
    for i in 0..<ClientsCount:
      var res = workers[i].read()
      result += res

  proc swarmManager4(address: TransportAddress): Future[int] {.async.} =
    var workers = newSeq[Future[int]](FilesCount)
    for i in 0..<FilesCount:
      workers[i] = swarmWorker4(address)
    await waitAll(workers)
    for i in 0..<FilesCount:
      var res = workers[i].read()
      result += res

  proc test1(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient1, {ReuseAddr})
    server.start()
    result = await swarmManager1(server.local)
    server.stop()
    server.close()
    await server.join()

  proc test2(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient2, {ReuseAddr})
    server.start()
    result = await swarmManager2(server.local)
    server.stop()
    server.close()
    await server.join()

  proc test3(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient3, {ReuseAddr})
    server.start()
    result = await swarmManager3(server.local)
    server.stop()
    server.close()
    await server.join()

  proc testSendFile(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient4, {ReuseAddr})
    server.start()
    result = await swarmManager4(server.local)
    server.stop()
    server.close()
    await server.join()

  proc testWR(address: TransportAddress): Future[int] {.async.} =
    var counter = ClientsCount

    proc swarmWorker(address: TransportAddress): Future[int] {.async.} =
      var transp = await connect(address)
      var data = ConstantMessage
      for i in 0..<MessagesCount:
        var res = await transp.write(data)
        doAssert(res == len(data))
      result = MessagesCount
      transp.close()
      await transp.join()

    proc swarmManager(address: TransportAddress): Future[int] {.async.} =
      var workers = newSeq[Future[int]](ClientsCount)
      for i in 0..<ClientsCount:
        workers[i] = swarmWorker(address)
      await waitAll(workers)
      for i in 0..<ClientsCount:
        var res = workers[i].read()
        result += res

    proc serveClient(server: StreamServer, transp: StreamTransport) {.async.} =
      var data = await transp.read()
      doAssert(len(data) == len(ConstantMessage) * MessagesCount)
      transp.close()
      var expect = ""
      for i in 0..<MessagesCount:
        expect.add(ConstantMessage)
      doAssert(equalMem(addr expect[0], addr data[0], len(data)))
      dec(counter)
      if counter == 0:
        server.stop()
        server.close()

    var server = createStreamServer(address, serveClient, {ReuseAddr})
    server.start()
    result = await swarmManager(server.local)
    await server.join()

  proc testWCR(address: TransportAddress): Future[int] {.async.} =
    var counter = ClientsCount

    proc serveClient(server: StreamServer, transp: StreamTransport) {.async.} =
      var expect = ConstantMessage
      var skip = await transp.consume(len(ConstantMessage) * (MessagesCount - 1))
      doAssert(skip == len(ConstantMessage) * (MessagesCount - 1))
      var data = await transp.read()
      doAssert(len(data) == len(ConstantMessage))
      transp.close()
      doAssert(equalMem(addr data[0], addr expect[0], len(expect)))
      dec(counter)
      if counter == 0:
        server.stop()
        server.close()

    proc swarmWorker(address: TransportAddress): Future[int] {.async.} =
      var transp = await connect(address)
      var data = ConstantMessage
      var seqdata = newSeq[byte](len(data))
      copyMem(addr seqdata[0], addr data[0], len(data))
      for i in 0..<MessagesCount:
        var res = await transp.write(seqdata)
        doAssert(res == len(seqdata))
      result = MessagesCount
      transp.close()
      await transp.join()

    proc swarmManager(address: TransportAddress): Future[int] {.async.} =
      var workers = newSeq[Future[int]](ClientsCount)
      for i in 0..<ClientsCount:
        workers[i] = swarmWorker(address)
      await waitAll(workers)
      for i in 0..<ClientsCount:
        var res = workers[i].read()
        result += res

    var server = createStreamServer(address, serveClient, {ReuseAddr})
    server.start()
    result = await swarmManager(server.local)
    await server.join()

  proc test7(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient7, {ReuseAddr})
    server.start()
    result = await swarmWorker7(server.local)
    server.stop()
    server.close()
    await server.join()

  proc test8(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient8, {ReuseAddr})
    server.start()
    result = await swarmWorker8(server.local)
    await server.join()

  # proc serveClient9(server: StreamServer, transp: StreamTransport) {.async.} =
  #   var expect = ""
  #   for i in 0..<BigMessageCount:
  #     expect.add(BigMessagePattern)
  #   var res = await transp.write(expect)
  #   doAssert(res == len(expect))
  #   transp.close()
  #   await transp.join()

  # proc swarmWorker9(address: TransportAddress): Future[int] {.async.} =
  #   var transp = await connect(address)
  #   var expect = ""
  #   for i in 0..<BigMessageCount:
  #     expect.add(BigMessagePattern)
  #   var line = await transp.readLine()
  #   if line == expect:
  #     result = 1
  #   else:
  #     result = 0
  #   transp.close()
  #   await transp.join()

  # proc test9(address: TransportAddress): Future[int] {.async.} =
  #   let flags = {ReuseAddr, NoPipeFlash}
  #   var server = createStreamServer(address, serveClient9, flags)
  #   server.start()
  #   result = await swarmWorker9(address)
  #   server.stop()
  #   server.close()
  #   await server.join()

  # proc serveClient10(server: StreamServer, transp: StreamTransport) {.async.} =
  #   var expect = ""
  #   for i in 0..<BigMessageCount:
  #     expect.add(BigMessagePattern)
  #   var res = await transp.write(expect)
  #   doAssert(res == len(expect))
  #   transp.close()
  #   await transp.join()

  # proc swarmWorker10(address: TransportAddress): Future[int] {.async.} =
  #   var transp = await connect(address)
  #   var expect = ""
  #   for i in 0..<BigMessageCount:
  #     expect.add(BigMessagePattern)
  #   var line = await transp.read()
  #   if equalMem(addr line[0], addr expect[0], len(expect)):
  #     result = 1
  #   else:
  #     result = 0
  #   transp.close()
  #   await transp.join()

  # proc test10(address: TransportAddress): Future[int] {.async.} =
  #   var server = createStreamServer(address, serveClient10, {ReuseAddr})
  #   server.start()
  #   result = await swarmWorker10(address)
  #   server.stop()
  #   server.close()
  #   await server.join()

  proc serveClient11(server: StreamServer, transp: StreamTransport) {.async.} =
    var res = await transp.write(BigMessagePattern)
    doAssert(res == len(BigMessagePattern))
    transp.close()
    await transp.join()

  proc swarmWorker11(address: TransportAddress): Future[int] {.async.} =
    var buffer: array[len(BigMessagePattern) + 1, byte]
    var transp = await connect(address)
    try:
      await transp.readExactly(addr buffer[0], len(buffer))
    except TransportIncompleteError:
      result = 1
    transp.close()
    await transp.join()

  proc test11(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient11, {ReuseAddr})
    server.start()
    result = await swarmWorker11(server.local)
    server.stop()
    server.close()
    await server.join()

  proc serveClient12(server: StreamServer, transp: StreamTransport) {.async.} =
    var res = await transp.write(BigMessagePattern)
    doAssert(res == len(BigMessagePattern))
    transp.close()
    await transp.join()

  proc swarmWorker12(address: TransportAddress): Future[int] {.async.} =
    var buffer: array[len(BigMessagePattern), byte]
    var sep = @[0x0D'u8, 0x0A'u8]
    var transp = await connect(address)
    try:
      var res = await transp.readUntil(addr buffer[0], len(buffer), sep)
      doAssert(res == 0)
    except TransportIncompleteError:
      result = 1
    transp.close()
    await transp.join()

  proc test12(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient12, {ReuseAddr})
    server.start()
    result = await swarmWorker12(server.local)
    server.stop()
    server.close()
    await server.join()

  proc serveClient13(server: StreamServer, transp: StreamTransport) {.async.} =
    transp.close()
    await transp.join()

  proc swarmWorker13(address: TransportAddress): Future[int] {.async.} =
    var transp = await connect(address)
    var line = await transp.readLine()
    if line == "":
      result = 1
    else:
      result = 0
    transp.close()
    await transp.join()

  proc test13(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient13, {ReuseAddr})
    server.start()
    result = await swarmWorker13(server.local)
    server.stop()
    server.close()
    await server.join()

  # proc serveClient14(server: StreamServer, transp: StreamTransport) {.async.} =
  #   discard

  proc test14(address: TransportAddress): Future[int] {.async.} =
    var subres = 0
    var server = createStreamServer(address, serveClient13, {ReuseAddr})

    proc swarmWorker(transp: StreamTransport): Future[void] {.async.} =
      var line = await transp.readLine()
      if line == "":
        subres = 1
      else:
        subres = 0

    server.start()
    var transp = await connect(server.local)
    var fut = swarmWorker(transp)
    # We perfrom shutdown(SHUT_RD/SD_RECEIVE) for the socket, in such way its
    # possible to emulate socket's EOF.
    discard shutdown(SocketHandle(transp.fd), 0)
    await fut
    server.stop()
    server.close()
    await server.join()
    transp.close()
    await transp.join()
    result = subres

  proc testConnectionRefused(address: TransportAddress): Future[bool] {.async.} =
    try:
      var transp = await connect(address)
      doAssert(isNil(transp))
    except TransportOsError as e:
      when defined(windows):
        return (e.code == ERROR_FILE_NOT_FOUND) or
               (e.code == ERROR_CONNECTION_REFUSED)
      else:
        return (e.code == oserrno.ECONNREFUSED) or (e.code == oserrno.ENOENT)

  proc serveClient16(server: StreamServer, transp: StreamTransport) {.async.} =
    var res = await transp.write(BigMessagePattern)
    doAssert(res == len(BigMessagePattern))
    transp.close()
    await transp.join()

  proc swarmWorker16(address: TransportAddress): Future[int] {.async.} =
    var buffer = newString(5)
    var transp = await connect(address)
    const readLength = 3

    var prevLen = 0
    while not transp.atEof():
      if prevLen + readLength > buffer.len:
        buffer.setLen(prevLen + readLength)

      let bytesRead = await transp.readOnce(addr buffer[prevLen], readLength)
      inc(prevLen, bytesRead)

    buffer.setLen(prevLen)
    doAssert(buffer == BigMessagePattern)

    result = 1
    transp.close()
    await transp.join()

  proc test16(address: TransportAddress): Future[int] {.async.} =
    var server = createStreamServer(address, serveClient16, {ReuseAddr})
    server.start()
    result = await swarmWorker16(server.local)
    server.stop()
    server.close()
    await server.join()

  proc testCloseTransport(address: TransportAddress): Future[int] {.async.} =
    proc client(server: StreamServer, transp: StreamTransport) {.async.} =
      discard
    var server = createStreamServer(address, client, {ReuseAddr})
    server.start()
    server.stop
    server.close()
    try:
      await wait(server.join(), 10.seconds)
      result = 1
    except CatchableError:
      discard

  proc testWriteConnReset(address: TransportAddress): Future[int] {.async.} =
    var syncFut = newFuture[void]()
    proc client(server: StreamServer, transp: StreamTransport) {.async.} =
      await transp.closeWait()
      syncFut.complete()
    var n = 10
    var server = createStreamServer(address, client, {ReuseAddr})
    server.start()
    var msg = "HELLO"
    var ntransp = await connect(server.local)
    await syncFut
    while true:
      var res = await ntransp.write(msg)
      if res == 0:
        result = 1
        break
      else:
        dec(n)
      if n == 0:
        break

    server.stop()
    await ntransp.closeWait()
    await server.closeWait()

  proc testAnyAddress(): Future[bool] {.async.} =
    var serverRemote, serverLocal: TransportAddress
    var connRemote, connLocal: TransportAddress

    proc serveClient(server: StreamServer, transp: StreamTransport) {.async.} =
      serverRemote = transp.remoteAddress()
      serverLocal = transp.localAddress()
      await transp.closeWait()
      server.stop()
      server.close()

    var ta = initTAddress("0.0.0.0:0")
    var server = createStreamServer(ta, serveClient, {ReuseAddr})
    var la = server.localAddress()
    server.start()
    var connFut = connect(la)
    if await withTimeout(connFut, 5.seconds):
      var conn = connFut.read()
      connRemote = conn.remoteAddress()
      connLocal = conn.localAddress()
      await server.join()
      await conn.closeWait()
      result = (connRemote == serverLocal) and (connLocal == serverRemote)
    else:
      server.stop()
      server.close()

  proc testWriteReturn(address: TransportAddress): Future[bool] {.async.} =
    var bigMessageSize = 10 * 1024 * 1024 - 1
    var finishMessage = "DONE"
    var cdata = newSeqOfCap[byte](bigMessageSize)
    proc serveClient(server: StreamServer, transp: StreamTransport) {.async.} =
      cdata = await transp.read(bigMessageSize)
      var size = await transp.write(finishMessage)
      doAssert(size == len(finishMessage))
      await transp.closeWait()
      server.stop()
      server.close()

    var flag = false
    var server = createStreamServer(address, serveClient, {ReuseAddr})
    server.start()

    var transp: StreamTransport

    try:
      transp = await connect(server.local)
      flag = true
    except CatchableError:
      server.stop()
      server.close()
      await server.join()

    if flag:
      flag = false
      try:
        var msg = createBigMessage(bigMessageSize)
        var size = await transp.write(msg)
        var data = await transp.read()
        doAssert(cdata == msg)
        doAssert(len(data) == len(finishMessage))
        doAssert(equalMem(addr data[0], addr finishMessage[0], len(data)))

        flag = (size == bigMessageSize)
      finally:
        await transp.closeWait()
        await server.join()
    result = flag

  proc testReadLine(address: TransportAddress): Future[bool] {.async.} =
    proc serveClient(server: StreamServer, transp: StreamTransport) {.async.} =
      discard await transp.write("DATA\r\r\r\r\r\n")
      transp.close()
      await transp.join()

    var server = createStreamServer(address, serveClient, {ReuseAddr})
    server.start()
    try:
      var r1, r2, r3, r4, r5: string
      var t1 = await connect(server.local)
      try:
        r1 = await t1.readLine(4)
      finally:
        await t1.closeWait()

      var t2 = await connect(server.local)
      try:
        r2 = await t2.readLine(6)
      finally:
        await t2.closeWait()

      var t3 = await connect(server.local)
      try:
        r3 = await t3.readLine(8)
      finally:
        await t3.closeWait()

      var t4 = await connect(server.local)
      try:
        r4 = await t4.readLine(8)
      finally:
        await t4.closeWait()

      var t5 = await connect(server.local)
      try:
        r5 = await t5.readLine()
      finally:
        await t5.closeWait()

      doAssert(r1 == "DATA")
      doAssert(r2 == "DATA\r\r")
      doAssert(r3 == "DATA\r\r\r\r")
      doAssert(r4 == "DATA\r\r\r\r")
      doAssert(r5 == "DATA\r\r\r\r")

      result = true
    finally:
      server.stop()
      server.close()
      await server.join()
  proc readLV(transp: StreamTransport,
              maxLen: int): Future[seq[byte]] {.async.} =
    # Read length-prefixed value where length is a 32-bit integer in native
    # endian (don't do this at home)
    var
      valueLen = 0'u32
      res: seq[byte]
      error: ref CatchableError

    proc predicate(data: openArray[byte]): tuple[consumed: int, done: bool] =
      if len(data) == 0:
        # There will be no more data, length-value incomplete
        error = newException(TransportIncompleteError, "LV incomplete")
        return (0, true)

      var consumed = 0

      if valueLen == 0:
        if len(data) < 4:
          return (0, false)
        copyMem(addr valueLen, unsafeAddr data[0], sizeof(valueLen))
        if valueLen == 0:
          return (sizeof(valueLen), true)
        if int(valueLen) > maxLen:
          error = newException(ValueError, "Size is too big")
          return (sizeof(valueLen), true)
        consumed += sizeof(valueLen)

      let
        dataLeft = len(data) - consumed
        count = min(dataLeft, int(valueLen) - len(res))

      res.add(data.toOpenArray(consumed, count + consumed - 1))
      return (consumed + count, len(res) == int(valueLen))

    await transp.readMessage(predicate)
    if not isNil(error):
      raise error
    else:
      return res

  proc createMessage(size: uint32): seq[byte] =
    var message = "MESSAGE"
    result = newSeq[byte](int(size))
    for i in 0 ..< size:
      result[int(i)] = byte(message[int(i) mod len(message)])

  proc createLVMessage(size: uint32): seq[byte] =
    var message = "MESSAGE"
    result = newSeq[byte](sizeof(size) + int(size))
    copyMem(addr result[0], unsafeAddr size, sizeof(size))
    for i in 0 ..< size:
      result[int(i) + sizeof(size)] = byte(message[int(i) mod len(message)])

  proc testReadMessage(address: TransportAddress): Future[bool] {.async.} =
    var state = 0
    var c1, c2, c3, c4, c5, c6, c7: bool

    proc serveClient(server: StreamServer, transp: StreamTransport) {.async.} =
      if state == 0:
        # EOF from the beginning.
        state = 1
        await transp.closeWait()
      elif state == 1:
        # Message has only zero-size header.
        var message = createLVMessage(0'u32)
        discard await transp.write(message)
        state = 2
        await transp.closeWait()
      elif state == 2:
        # Message has header, but do not have any data at all.
        var message = createLVMessage(4'u32)
        message.setLen(4)
        discard await transp.write(message)
        state = 3
        await transp.closeWait()
      elif state == 3:
        # Message do not have enough data for specified size in header.
        var message = createLVMessage(1024'u32)
        message.setLen(1024)
        discard await transp.write(message)
        state = 4
        await transp.closeWait()
      elif state == 4:
        # Good encoded message with oversize.
        var message = createLVMessage(1024'u32)
        discard await transp.write(message)
        state = 5
        await transp.closeWait()
      elif state == 5:
        # Good encoded message.
        var message = createLVMessage(1024'u32)
        discard await transp.write(message)
        state = 6
        await transp.closeWait()
      elif state == 6:
        # Good encoded message with additional data.
        var message = createLVMessage(1024'u32)
        discard await transp.write(message)
        discard await transp.write("DONE")
        state = 7
        await transp.closeWait()
      else:
        doAssert(false)

    var server = createStreamServer(address, serveClient, {ReuseAddr})
    server.start()

    var t1 = await connect(server.local)
    try:
      discard await t1.readLV(2000)
    except TransportIncompleteError:
      c1 = true
    finally:
      await t1.closeWait()

    if not c1:
      server.stop()
      server.close()
      await server.join()
      return false

    var t2 = await connect(server.local)
    try:
      var r2 = await t2.readLV(2000)
      c2 = (r2 == @[])
    finally:
      await t2.closeWait()

    if not c2:
      server.stop()
      server.close()
      await server.join()
      return false

    var t3 = await connect(server.local)
    try:
      discard await t3.readLV(2000)
    except TransportIncompleteError:
      c3 = true
    finally:
      await t3.closeWait()

    if not c3:
      server.stop()
      server.close()
      await server.join()
      return false

    var t4 = await connect(server.local)
    try:
      discard await t4.readLV(2000)
    except TransportIncompleteError:
      c4 = true
    finally:
      await t4.closeWait()

    if not c4:
      server.stop()
      server.close()
      await server.join()
      return false

    var t5 = await connect(server.local)
    try:
      discard await t5.readLV(1000)
    except ValueError:
      c5 = true
    finally:
      await t5.closeWait()

    if not c5:
      server.stop()
      server.close()
      await server.join()
      return false

    var t6 = await connect(server.local)
    try:
      var expectMsg = createMessage(1024)
      var r6 = await t6.readLV(2000)
      if len(r6) == 1024 and r6 == expectMsg:
        c6 = true
    finally:
      await t6.closeWait()

    if not c6:
      server.stop()
      server.close()
      await server.join()
      return false

    var t7 = await connect(server.local)
    try:
      var expectMsg = createMessage(1024)
      var expectDone = "DONE"
      var r7 = await t7.readLV(2000)
      if len(r7) == 1024 and r7 == expectMsg:
        var m = await t7.read(4)
        if len(m) == 4 and equalMem(addr m[0], addr expectDone[0], 4):
          c7 = true
    finally:
      await t7.closeWait()

    server.stop()
    server.close()
    await server.join()
    result = c7

  proc testAccept(address: TransportAddress): Future[bool] {.async.} =
    var server = createStreamServer(address, flags = {ReuseAddr})
    var connected = 0
    var accepted = 0

    proc acceptTask(server: StreamServer) {.async.} =
      for i in 0 ..< TestsCount:
        let transp = await server.accept()
        await transp.closeWait()
        inc(accepted)

    var acceptFut = acceptTask(server)
    var transp: StreamTransport

    try:
      for i in 0 ..< TestsCount:
        transp = await connect(server.local)
        await sleepAsync(10.milliseconds)
        await transp.closeWait()
        inc(connected)
      if await withTimeout(acceptFut, 5.seconds):
        if acceptFut.finished() and not(acceptFut.failed()):
          result = (connected == TestsCount) and (connected == accepted)
    finally:
      await server.closeWait()
      if not(isNil(transp)):
        await transp.closeWait()

  proc testAcceptClose(address: TransportAddress): Future[bool] {.async.} =
    var server = createStreamServer(address, flags = {ReuseAddr})

    proc acceptTask(server: StreamServer) {.async.} =
      let transp = await server.accept()
      await transp.closeWait()

    var acceptFut = acceptTask(server)
    await server.closeWait()

    if await withTimeout(acceptFut, 5.seconds):
      if acceptFut.finished() and acceptFut.failed():
        if acceptFut.readError() of TransportUseClosedError:
          result = true
    else:
      result = false

  when not(defined(windows)):
    proc testAcceptTooMany(address: TransportAddress): Future[bool] {.async.} =
      let maxFiles = getMaxOpenFiles()
      var server = createStreamServer(address, flags = {ReuseAddr})
      let isock = int(server.sock)
      let newMaxFiles = isock + 4
      setMaxOpenFiles(newMaxFiles)

      proc acceptTask(server: StreamServer): Future[bool] {.async.} =
        var transports = newSeq[StreamTransport]()
        try:
          for i in 0 ..< 3:
            let transp = await server.accept()
            transports.add(transp)
        except TransportTooManyError:
          var pending = newSeq[Future[void]]()
          for item in transports:
            pending.add(closeWait(item))
          await allFutures(pending)
          return true

      var acceptFut = acceptTask(server)

      try:
        for i in 0 ..< 3:
          try:
            let transp = await connect(server.local)
            await sleepAsync(10.milliseconds)
            await transp.closeWait()
          except TransportTooManyError:
            break
        if await withTimeout(acceptFut, 5.seconds):
          if acceptFut.finished() and not(acceptFut.failed()):
            if acceptFut.read() == true:
              result = true
      finally:
        await server.closeWait()
        setMaxOpenFiles(maxFiles)

  proc testWriteOnClose(address: TransportAddress): Future[bool] {.async.} =
    var server = createStreamServer(address, flags = {ReuseAddr, NoPipeFlash})
    var res = 0

    proc acceptTask(server: StreamServer) {.async.} =
      let transp = await server.accept()
      var futs = newSeq[Future[int]]()
      var msg = createBigMessage(1024)
      var tries = 0

      while futs.len() < TestsCount:
        let fut = transp.write(msg)
        # `write` has a fast path that puts the data in the OS socket buffer -
        # we'll keep writing until we get EAGAIN from the OS so that we have
        # data in the in-chronos queue to fail on close
        if not fut.completed():
          futs.add(fut)
        else:
          tries += 1
          if tries > 65*1024:
            # We've queued 64mb on the socket and it still allows writing,
            # something is wrong - we'll break here which will cause the test
            # to fail
            break

      await transp.closeWait()
      await sleepAsync(100.milliseconds)

      for i in 0 ..< len(futs):
        # writes may complete via fast write
        if futs[i].failed() and (futs[i].error of TransportUseClosedError):
          inc(res)

      await server.closeWait()

    var acceptFut = acceptTask(server)
    var transp = await connect(server.local)
    await server.join()
    await transp.closeWait()
    await acceptFut
    return (res == TestsCount)

  proc testReadOnClose(address: TransportAddress): Future[bool] {.async.} =
    var server = createStreamServer(address, flags = {ReuseAddr, NoPipeFlash})
    var res = false

    proc acceptTask(server: StreamServer) {.async.} =
      let transp = await server.accept()
      var buffer = newSeq[byte](1024)
      var fut = transp.readOnce(addr buffer[0], len(buffer))
      await transp.closeWait()
      await sleepAsync(100.milliseconds)
      if fut.failed() and (fut.error of TransportUseClosedError):
        res = true
      await server.closeWait()

    var acceptFut = acceptTask(server)
    var transp = await connect(server.local)
    await server.join()
    await transp.closeWait()
    await acceptFut
    return res

  proc testAcceptRace(address: TransportAddress): Future[bool] {.async.} =
    proc test1(address: TransportAddress) {.async.} =
      let server = createStreamServer(address, flags = {ReuseAddr})
      let acceptFut = server.accept()
      server.close()
      await allFutures(acceptFut.cancelAndWait(), server.join())

    proc test2(address: TransportAddress) {.async.} =
      let server = createStreamServer(address, flags = {ReuseAddr})
      let acceptFut = server.accept()
      await acceptFut.cancelAndWait()
      server.close()
      await server.join()

    proc test3(address: TransportAddress) {.async.} =
      let server = createStreamServer(address, flags = {ReuseAddr})
      let acceptFut = server.accept()
      server.stop()
      server.close()
      await allFutures(acceptFut.cancelAndWait(), server.join())

    proc test4(address: TransportAddress) {.async.} =
      let server = createStreamServer(address, flags = {ReuseAddr})
      let acceptFut = server.accept()
      await acceptFut.cancelAndWait()
      server.stop()
      server.close()
      await server.join()

    try:
      await test1(address).wait(5.seconds)
      await test2(address).wait(5.seconds)
      await test3(address).wait(5.seconds)
      await test4(address).wait(5.seconds)
      return true
    except AsyncTimeoutError:
      return false

  proc testPipe(): Future[bool] {.async.} =
    let (rfd, wfd) = createAsyncPipe()

    let
      message = createBigMessage(16384 * 1024)
      rtransp = fromPipe(rfd)
      wtransp = fromPipe(wfd)
    var
      buffer = newSeq[byte](16384 * 1024)

    proc writer(transp: StreamTransport): Future[int] {.async.} =
      let res =
        try:
          await transp.write(message)
        except CatchableError:
          -1
      return res

    var fut {.used.} = wtransp.writer()
    try:
      await rtransp.readExactly(addr buffer[0], 16384 * 1024)
    except CatchableError:
      discard

    await allFutures(rtransp.closeWait(), wtransp.closeWait())
    return buffer == message

  proc testConnectBindLocalAddress() {.async.} =

    proc client(server: StreamServer, transp: StreamTransport) {.async.} =
      await transp.closeWait()

    let server1 = createStreamServer(initTAddress("127.0.0.1:0"), client)
    let server2 = createStreamServer(initTAddress("127.0.0.1:0"), client)
    let server3 = createStreamServer(initTAddress("127.0.0.1:0"), client, {ReusePort})

    server1.start()
    server2.start()
    server3.start()

    # It works cause even though there's an active listening socket bound to
    # dst3, we are using ReusePort
    var transp1 = await connect(
      server1.localAddress(), localAddress = server3.localAddress(),
      flags = {SocketFlags.ReusePort})
    var transp2 = await connect(
      server2.localAddress(), localAddress = server3.localAddress(),
      flags = {SocketFlags.ReusePort})

    expect(TransportOsError):
      var transp2 {.used.} = await connect(
        server2.localAddress(), localAddress = server3.localAddress())

    expect(TransportOsError):
      var transp3 {.used.} = await connect(
        server2.localAddress(),
        localAddress = initTAddress("::", server3.localAddress().port))

    await transp1.closeWait()
    await transp2.closeWait()

    server1.stop()
    await server1.closeWait()

    server2.stop()
    await server2.closeWait()

    server3.stop()
    await server3.closeWait()

  proc testConnectCancelLeaksTest() {.async.} =
    proc client(server: StreamServer, transp: StreamTransport) {.async.} =
      await transp.closeWait()

    let
      server = createStreamServer(initTAddress("127.0.0.1:0"), client)
      address = server.localAddress()

    var counter = 0
    while true:
      let transpFut = connect(address)
      if counter > 0:
        await stepsAsync(counter)
      if not(transpFut.finished()):
        await cancelAndWait(transpFut)
        doAssert(cancelled(transpFut),
                 "Future should be Cancelled at this point")
        inc(counter)
      else:
        let transp = await transpFut
        await transp.closeWait()
        break
    server.stop()
    await server.closeWait()

  proc testAcceptCancelLeaksTest() {.async.} =
    var
      counter = 0
      exitLoop = false

    # This timer will help to awake events poll in case its going to stuck
    # usually happens on MacOS.
    let sleepFut = sleepAsync(1.seconds)

    while not(exitLoop):
      let
        server = createStreamServer(initTAddress("127.0.0.1:0"))
        address = server.localAddress()

      let
        transpFut = connect(address)
        acceptFut = server.accept()

      if counter > 0:
        await stepsAsync(counter)

      exitLoop =
        if not(acceptFut.finished()):
          await cancelAndWait(acceptFut)
          doAssert(cancelled(acceptFut),
                   "Future should be Cancelled at this point")
          inc(counter)
          false
        else:
          let transp = await acceptFut
          await transp.closeWait()
          true

      if not(transpFut.finished()):
        await transpFut.cancelAndWait()

      if transpFut.completed():
        let transp = transpFut.value
        await transp.closeWait()

      server.stop()
      await server.closeWait()

    if not(sleepFut.finished()):
      await cancelAndWait(sleepFut)

  markFD = getCurrentFD()

  for i in 0..<len(addresses):
    test prefixes[i] & "close(transport) test":
      check waitFor(testCloseTransport(addresses[i])) == 1
    test prefixes[i] & "readUntil() buffer overflow test":
      check waitFor(test8(addresses[i])) == 1
    test prefixes[i] & "readLine() buffer overflow test":
      check waitFor(test7(addresses[i])) == 1
    test prefixes[i] & "readExactly() unexpected disconnect test":
      check waitFor(test11(addresses[i])) == 1
    test prefixes[i] & "readUntil() unexpected disconnect test":
      check waitFor(test12(addresses[i])) == 1
    test prefixes[i] & "readLine() unexpected disconnect empty string test":
      check waitFor(test13(addresses[i])) == 1
    test prefixes[i] & "Closing socket while operation pending test (issue #8)":
      check waitFor(test14(addresses[i])) == 1
    test prefixes[i] & "readLine() multiple clients with messages (" &
        $ClientsCount & " clients x " & $MessagesCount & " messages)":
      check waitFor(test1(addresses[i])) == ClientsCount * MessagesCount
    test prefixes[i] & "readExactly() multiple clients with messages (" &
        $ClientsCount & " clients x " & $MessagesCount & " messages)":
      check waitFor(test2(addresses[i])) == ClientsCount * MessagesCount
    test prefixes[i] & "readUntil() multiple clients with messages (" &
        $ClientsCount & " clients x " & $MessagesCount & " messages)":
      check waitFor(test3(addresses[i])) == ClientsCount * MessagesCount
    test prefixes[i] & "write(string)/read(int) multiple clients (" &
        $ClientsCount & " clients x " & $MessagesCount & " messages)":
      check waitFor(testWR(addresses[i])) == ClientsCount * MessagesCount
    test prefixes[i] & "write(seq[byte])/consume(int)/read(int) multiple clients (" &
         $ClientsCount & " clients x " & $MessagesCount & " messages)":
      check waitFor(testWCR(addresses[i])) == ClientsCount * MessagesCount
    test prefixes[i] & "writeFile() multiple clients (" & $FilesCount & " files)":
      when defined(windows):
        if addresses[i].family == AddressFamily.IPv4:
          check waitFor(testSendFile(addresses[i])) == FilesCount
        else:
          skip()
      else:
        if defined(emscripten):
          skip()
        else:
          check waitFor(testSendFile(addresses[i])) == FilesCount
    test prefixes[i] & "Connection refused test":
      var address: TransportAddress
      if addresses[i].family == AddressFamily.Unix:
        address = initTAddress("/tmp/notexistingtestpipe")
      else:
        address = initTAddress("127.0.0.1:43335")
      check waitFor(testConnectionRefused(address)) == true
    test prefixes[i] & "readOnce() read until atEof() test":
      check waitFor(test16(addresses[i])) == 1
    test prefixes[i] & "Connection reset test on send() only":
      when defined(macosx):
        skip()
      else:
        check waitFor(testWriteConnReset(addresses[i])) == 1
    test prefixes[i] & "0.0.0.0/::0 (INADDR_ANY) test":
      if addresses[i].family == AddressFamily.IPv4:
        check waitFor(testAnyAddress()) == true
      else:
        skip()
    test prefixes[i] & "write() return value test (issue #73)":
      check waitFor(testWriteReturn(addresses[i])) == true
    test prefixes[i] & "readLine() partial separator test":
      check waitFor(testReadLine(addresses[i])) == true
    test prefixes[i] & "readMessage() test":
      check waitFor(testReadMessage(addresses[i])) == true
    test prefixes[i] & "accept() test":
      check waitFor(testAccept(addresses[i])) == true
    test prefixes[i] & "close() while in accept() waiting test":
      check waitFor(testAcceptClose(addresses[i])) == true
    test prefixes[i] & "Intermediate transports leak test #1":
      checkLeaks()
      when defined(windows):
        skip()
      else:
        checkLeaks(StreamTransportTrackerName)
    test prefixes[i] & "accept() too many file descriptors test":
      when defined(windows):
        skip()
      else:
        check waitFor(testAcceptTooMany(addresses[i])) == true
    test prefixes[i] & "accept() and close() race test":
      check waitFor(testAcceptRace(addresses[i])) == true
    test prefixes[i] & "write() queue notification on close() test":
      check waitFor(testWriteOnClose(addresses[i])) == true
    test prefixes[i] & "read() notification on close() test":
      check waitFor(testReadOnClose(addresses[i])) == true
  test "[PIPE] readExactly()/write() test":
    check waitFor(testPipe()) == true
  test "[IP] bind connect to local address test":
    waitFor(testConnectBindLocalAddress())
  test "[IP] connect() cancellation leaks test":
    waitFor(testConnectCancelLeaksTest())
  test "[IP] accept() cancellation leaks test":
    waitFor(testAcceptCancelLeaksTest())
  test "Leaks test":
    checkLeaks()
  test "File descriptors leak test":
    when defined(windows):
      # Windows handle numbers depends on many conditions, so we can't use
      # our FD leak detection method.
      skip()
    else:
      check getCurrentFD() == markFD
