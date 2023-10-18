#                Chronos Test Suite
#            (c) Copyright 2021-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[strutils, sha1]
import ".."/chronos/unittest2/asynctests
import ".."/chronos,
       ".."/chronos/apps/http/[httpserver, shttpserver, httpclient]
import stew/base10

{.used.}

# To create self-signed certificate and key you can use openssl
# openssl req -new -x509 -sha256 -newkey rsa:2048 -nodes \
# -keyout example-com.key.pem -days 3650 -out example-com.cert.pem
const HttpsSelfSignedRsaKey = """
-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCn7tXGLKMIMzOG
tVzUixax1/ftlSLcpEAkZMORuiCCnYjtIJhGZdzRFZC8fBlfAJZpLIAOfX2L2f1J
ZuwpwDkOIvNqKMBrl5Mvkl5azPT0rtnjuwrcqN5NFtbmZPKFYvbjex2aXGqjl5MW
nQIs/ZA++DVEXmaN9oDxcZsvRMDKfrGQf9iLeoVL47Gx9KpqNqD/JLIn4LpieumV
yYidm6ukTOqHRvrWm36y6VvKW4TE97THacULmkeahtTf8zDJbbh4EO+gifgwgJ2W
BUS0+5hMcWu8111mXmanlOVlcoW8fH8RmPjL1eK1Z3j3SVHEf7oWZtIVW5gGA0jQ
nfA4K51RAgMBAAECggEANZ7/R13tWKrwouy6DWuz/WlWUtgx333atUQvZhKmWs5u
cDjeJmxUC7b1FhoSB9GqNT7uTLIpKkSaqZthgRtNnIPwcU890Zz+dEwqMJgNByvl
it+oYjjRco/+YmaNQaYN6yjelPE5Y678WlYb4b29Fz4t0/zIhj/VgEKkKH2tiXpS
TIicoM7pSOscEUfaW3yp5bS5QwNU6/AaF1wws0feBACd19ZkcdPvr52jopbhxlXw
h3XTV/vXIJd5zWGp0h/Jbd4xcD4MVo2GjfkeORKY6SjDaNzt8OGtePcKnnbUVu8b
2XlDxukhDQXqJ3g0sHz47mhvo4JeIM+FgymRm+3QmQKBgQDTawrEA3Zy9WvucaC7
Zah02oE9nuvpF12lZ7WJh7+tZ/1ss+Fm7YspEKaUiEk7nn1CAVFtem4X4YCXTBiC
Oqq/o+ipv1yTur0ae6m4pwLm5wcMWBh3H5zjfQTfrClNN8yjWv8u3/sq8KesHPnT
R92/sMAptAChPgTzQphWbxFiYwKBgQDLWFaBqXfZYVnTyUvKX8GorS6jGWc6Eh4l
lAFA+2EBWDICrUxsDPoZjEXrWCixdqLhyehaI3KEFIx2bcPv6X2c7yx3IG5lA/Gx
TZiKlY74c6jOTstkdLW9RJbg1VUHUVZMf/Owt802YmEfUI5S5v7jFmKW6VG+io+K
+5KYeHD1uwKBgQDMf53KPA82422jFwYCPjLT1QduM2q97HwIomhWv5gIg63+l4BP
rzYMYq6+vZUYthUy41OAMgyLzPQ1ZMXQMi83b7R9fTxvKRIBq9xfYCzObGnE5vHD
SDDZWvR75muM5Yxr9nkfPkgVIPMO6Hg+hiVYZf96V0LEtNjU9HWmJYkLQQKBgQCQ
ULGUdGHKtXy7AjH3/t3CiKaAupa4cANVSCVbqQy/l4hmvfdu+AbH+vXkgTzgNgKD
nHh7AI1Vj//gTSayLlQn/Nbh9PJkXtg5rYiFUn+VdQBo6yMOuIYDPZqXFtCx0Nge
kvCwisHpxwiG4PUhgS+Em259DDonsM8PJFx2OYRx4QKBgEQpGhg71Oi9MhPJshN7
dYTowaMS5eLTk2264ARaY+hAIV7fgvUa+5bgTVaWL+Cfs33hi4sMRqlEwsmfds2T
cnQiJ4cU20Euldfwa5FLnk6LaWdOyzYt/ICBJnKFRwfCUbS4Bu5rtMEM+3t0wxnJ
IgaD04WhoL9EX0Qo3DC1+0kG
-----END PRIVATE KEY-----
"""

# This SSL certificate will expire 13 October 2030.
const HttpsSelfSignedRsaCert = """
-----BEGIN CERTIFICATE-----
MIIDnzCCAoegAwIBAgIUUdcusjDd3XQi3FPM8urdFG3qI+8wDQYJKoZIhvcNAQEL
BQAwXzELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoM
GEludGVybmV0IFdpZGdpdHMgUHR5IEx0ZDEYMBYGA1UEAwwPMTI3LjAuMC4xOjQz
ODA4MB4XDTIwMTAxMjIxNDUwMVoXDTMwMTAxMDIxNDUwMVowXzELMAkGA1UEBhMC
QVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGEludGVybmV0IFdpZGdp
dHMgUHR5IEx0ZDEYMBYGA1UEAwwPMTI3LjAuMC4xOjQzODA4MIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEAp+7VxiyjCDMzhrVc1IsWsdf37ZUi3KRAJGTD
kboggp2I7SCYRmXc0RWQvHwZXwCWaSyADn19i9n9SWbsKcA5DiLzaijAa5eTL5Je
Wsz09K7Z47sK3KjeTRbW5mTyhWL243sdmlxqo5eTFp0CLP2QPvg1RF5mjfaA8XGb
L0TAyn6xkH/Yi3qFS+OxsfSqajag/ySyJ+C6YnrplcmInZurpEzqh0b61pt+sulb
yluExPe0x2nFC5pHmobU3/MwyW24eBDvoIn4MICdlgVEtPuYTHFrvNddZl5mp5Tl
ZXKFvHx/EZj4y9XitWd490lRxH+6FmbSFVuYBgNI0J3wOCudUQIDAQABo1MwUTAd
BgNVHQ4EFgQUBKha84woY5WkFxKw7qx1cONg1H8wHwYDVR0jBBgwFoAUBKha84wo
Y5WkFxKw7qx1cONg1H8wDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAHZMYt9Ry+Xj3vTbzpGFQzYQVTJlfJWSN6eWNOivRFQE5io9kOBEe5noa8aLo
dLkw6ztxRP2QRJmlhGCO9/HwS17ckrkgZp3EC2LFnzxcBmoZu+owfxOT1KqpO52O
IKOl8eVohi1pEicE4dtTJVcpI7VCMovnXUhzx1Ci4Vibns4a6H+BQa19a1JSpifN
tO8U5jkjJ8Jprs/VPFhJj2O3di53oDHaYSE5eOrm2ZO14KFHSk9cGcOGmcYkUv8B
nV5vnGadH5Lvfxb/BCpuONabeRdOxMt9u9yQ89vNpxFtRdZDCpGKZBCfmUP+5m3m
N8r5CwGcIX/XPC3lKazzbZ8baA==
-----END CERTIFICATE-----
"""

suite "HTTP client testing suite":

  type
    TestResponseTuple = tuple[status: int, data: string, count: int]

  proc createBigMessage(message: string, size: int): seq[byte] =
    var res = newSeq[byte](size)
    for i in 0 ..< len(res):
      res[i] = byte(message[i mod len(message)])
    res

  proc createServer(address: TransportAddress,
                    process: HttpProcessCallback, secure: bool): HttpServerRef =
    let
      socketFlags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
      serverFlags = {HttpServerFlags.Http11Pipeline}
    if secure:
      let secureKey = TLSPrivateKey.init(HttpsSelfSignedRsaKey)
      let secureCert = TLSCertificate.init(HttpsSelfSignedRsaCert)
      let res = SecureHttpServerRef.new(address, process,
                                        socketFlags = socketFlags,
                                        serverFlags = serverFlags,
                                        tlsPrivateKey = secureKey,
                                        tlsCertificate = secureCert)
      HttpServerRef(res.get())
    else:
      let res = HttpServerRef.new(address, process,
                                  socketFlags = socketFlags,
                                  serverFlags = serverFlags)
      res.get()

  proc createSession(secure: bool,
                     maxRedirections = HttpMaxRedirections): HttpSessionRef =
    if secure:
      HttpSessionRef.new({HttpClientFlag.NoVerifyHost,
                          HttpClientFlag.NoVerifyServerName,
                          HttpClientFlag.Http11Pipeline},
                         maxRedirections = maxRedirections)
    else:
      HttpSessionRef.new({HttpClientFlag.Http11Pipeline},
                         maxRedirections = maxRedirections)

  proc testMethods(secure: bool): Future[int] {.async.} =
    let RequestTests = [
      (MethodGet, "/test/get"),
      (MethodPost, "/test/post"),
      (MethodHead, "/test/head"),
      (MethodPut, "/test/put"),
      (MethodDelete, "/test/delete"),
      (MethodTrace, "/test/trace"),
      (MethodOptions, "/test/options"),
      (MethodConnect, "/test/connect"),
      (MethodPatch, "/test/patch")
    ]
    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/test/get", "/test/post", "/test/head", "/test/put",
           "/test/delete", "/test/trace", "/test/options", "/test/connect",
           "/test/patch", "/test/error":
          return await request.respond(Http200, request.uri.path)
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()
    var counter = 0

    var session = createSession(secure)

    for item in RequestTests:
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, item[1])
        else:
          getAddress(address, HttpClientScheme.NonSecure, item[1])
      var req = HttpClientRequestRef.new(session, ha, item[0])
      let response = await fetch(req)
      if response.status == 200:
        let data = cast[string](response.data)
        if data == item[1]:
          inc(counter)
      await req.closeWait()
    await session.closeWait()

    for item in RequestTests:
      var session = createSession(secure)
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, item[1])
        else:
          getAddress(address, HttpClientScheme.NonSecure, item[1])
      var req = HttpClientRequestRef.new(session, ha, item[0])
      let response = await fetch(req)
      if response.status == 200:
        let data = cast[string](response.data)
        if data == item[1]:
          inc(counter)
      await req.closeWait()
      await session.closeWait()

    await server.stop()
    await server.closeWait()
    return counter

  proc testResponseStreamReadingTest(secure: bool): Future[int] {.async.} =
    let ResponseTests = [
      (MethodGet, "/test/short_size_response", 65600, 1024,
       "SHORTSIZERESPONSE"),
      (MethodGet, "/test/long_size_response", 262400, 1024,
       "LONGSIZERESPONSE"),
      (MethodGet, "/test/short_chunked_response", 65600, 1024,
       "SHORTCHUNKRESPONSE"),
      (MethodGet, "/test/long_chunked_response", 262400, 1024,
       "LONGCHUNKRESPONSE")
    ]
    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/test/short_size_response":
          var response = request.getResponse()
          var data = createBigMessage(ResponseTests[0][4], ResponseTests[0][2])
          response.status = Http200
          await response.sendBody(data)
          return response
        of "/test/long_size_response":
          var response = request.getResponse()
          var data = createBigMessage(ResponseTests[1][4], ResponseTests[1][2])
          response.status = Http200
          await response.sendBody(data)
          return response
        of "/test/short_chunked_response":
          var response = request.getResponse()
          var data = createBigMessage(ResponseTests[2][4], ResponseTests[2][2])
          response.status = Http200
          await response.prepare()
          var offset = 0
          while true:
            if len(data) == offset:
              break
            let toWrite = min(1024, len(data) - offset)
            await response.sendChunk(addr data[offset], toWrite)
            offset = offset + toWrite
          await response.finish()
          return response
        of "/test/long_chunked_response":
          var response = request.getResponse()
          var data = createBigMessage(ResponseTests[3][4], ResponseTests[3][2])
          response.status = Http200
          await response.prepare()
          var offset = 0
          while true:
            if len(data) == offset:
              break
            let toWrite = min(1024, len(data) - offset)
            await response.sendChunk(addr data[offset], toWrite)
            offset = offset + toWrite
          await response.finish()
          return response
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()
    var counter = 0

    var session = createSession(secure)
    for item in ResponseTests:
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, item[1])
        else:
          getAddress(address, HttpClientScheme.NonSecure, item[1])
      var req = HttpClientRequestRef.new(session, ha, item[0])
      var response = await send(req)
      if response.status == 200:
        var reader = response.getBodyReader()
        var res: seq[byte]
        while true:
          var data = await reader.read(item[3])
          res.add(data)
          if len(data) != item[3]:
            break
        await reader.closeWait()
        if len(res) == item[2]:
          let expect = createBigMessage(item[4], len(res))
          if expect == res:
            inc(counter)
      await response.closeWait()
      await req.closeWait()
    await session.closeWait()

    for item in ResponseTests:
      var session = createSession(secure)
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, item[1])
        else:
          getAddress(address, HttpClientScheme.NonSecure, item[1])
      var req = HttpClientRequestRef.new(session, ha, item[0])
      var response = await send(req)
      if response.status == 200:
        var reader = response.getBodyReader()
        var res: seq[byte]
        while true:
          var data = await reader.read(item[3])
          res.add(data)
          if len(data) != item[3]:
            break
        await reader.closeWait()
        if len(res) == item[2]:
          let expect = createBigMessage(item[4], len(res))
          if expect == res:
            inc(counter)
      await response.closeWait()
      await req.closeWait()
      await session.closeWait()

    await server.stop()
    await server.closeWait()
    return counter

  proc testRequestSizeStreamWritingTest(secure: bool): Future[int] {.async.} =
    let RequestTests = [
      (MethodPost, "/test/big_request", 65600),
      (MethodPost, "/test/big_request", 262400)
    ]
    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/test/big_request":
          if request.hasBody():
            let body = await request.getBody()
            let digest = $secureHash(cast[string](body))
            return await request.respond(Http200, digest)
          else:
            return await request.respond(Http400, "Missing content body")
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()
    var counter = 0

    var session = createSession(secure)
    for item in RequestTests:
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, item[1])
        else:
          getAddress(address, HttpClientScheme.NonSecure, item[1])
      var data = createBigMessage("REQUESTSTREAMMESSAGE", item[2])
      let headers = [
        ("Content-Type", "application/octet-stream"),
        ("Content-Length", Base10.toString(uint64(len(data))))
      ]
      var request = HttpClientRequestRef.new(
        session, ha, item[0], headers = headers
      )

      var expectDigest = $secureHash(cast[string](data))
      # Sending big request by 1024bytes long chunks
      var writer = await open(request)
      var offset = 0
      while true:
        if len(data) == offset:
          break
        let toWrite = min(1024, len(data) - offset)
        await writer.write(addr data[offset], toWrite)
        offset = offset + toWrite
      await writer.finish()
      await writer.closeWait()
      var response = await request.finish()

      if response.status == 200:
        var res = await response.getBodyBytes()
        if cast[string](res) == expectDigest:
          inc(counter)
      await response.closeWait()
      await request.closeWait()
    await session.closeWait()

    await server.stop()
    await server.closeWait()
    return counter

  proc testRequestChunkedStreamWritingTest(
                                          secure: bool): Future[int] {.async.} =
    let RequestTests = [
      (MethodPost, "/test/big_chunk_request", 65600),
      (MethodPost, "/test/big_chunk_request", 262400)
    ]
    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/test/big_chunk_request":
          if request.hasBody():
            let body = await request.getBody()
            let digest = $secureHash(cast[string](body))
            return await request.respond(Http200, digest)
          else:
            return await request.respond(Http400, "Missing content body")
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()
    var counter = 0

    var session = createSession(secure)
    for item in RequestTests:
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, item[1])
        else:
          getAddress(address, HttpClientScheme.NonSecure, item[1])
      var data = createBigMessage("REQUESTSTREAMMESSAGE", item[2])
      let headers = [
        ("Content-Type", "application/octet-stream"),
        ("Transfer-Encoding", "chunked")
      ]
      var request = HttpClientRequestRef.new(
        session, ha, item[0], headers = headers
      )

      var expectDigest = $secureHash(cast[string](data))
      # Sending big request by 1024bytes long chunks
      var writer = await open(request)
      var offset = 0
      while true:
        if len(data) == offset:
          break
        let toWrite = min(1024, len(data) - offset)
        await writer.write(addr data[offset], toWrite)
        offset = offset + toWrite
      await writer.finish()
      await writer.closeWait()
      var response = await request.finish()

      if response.status == 200:
        var res = await response.getBodyBytes()
        if cast[string](res) == expectDigest:
          inc(counter)
      await response.closeWait()
      await request.closeWait()
    await session.closeWait()

    await server.stop()
    await server.closeWait()
    return counter

  proc testRequestPostUrlEncodedTest(secure: bool): Future[int] {.async.} =
    let PostRequests = [
      ("/test/post/urlencoded_size",
       "field1=value1&field2=value2&field3=value3", "value1:value2:value3"),
      ("/test/post/urlencoded_chunked",
       "field1=longlonglongvalue1&field2=longlonglongvalue2&" &
       "field3=longlonglongvalue3", "longlonglongvalue1:longlonglongvalue2:" &
       "longlonglongvalue3")
    ]

    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/test/post/urlencoded_size", "/test/post/urlencoded_chunked":
          if request.hasBody():
            var postTable = await request.post()
            let body = postTable.getString("field1") & ":" &
                       postTable.getString("field2") & ":" &
                       postTable.getString("field3")
            return await request.respond(Http200, body)
          else:
            return await request.respond(Http400, "Missing content body")
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()
    var counter = 0

    ## Sized url-encoded form
    block:
      var session = createSession(secure)
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, PostRequests[0][0])
        else:
          getAddress(address, HttpClientScheme.NonSecure, PostRequests[0][0])
      let headers = [
        ("Content-Type", "application/x-www-form-urlencoded"),
      ]
      var request = HttpClientRequestRef.new(
        session, ha, MethodPost, headers = headers,
        body = cast[seq[byte]](PostRequests[0][1]))
      var response = await send(request)

      if response.status == 200:
        var res = await response.getBodyBytes()
        if cast[string](res) == PostRequests[0][2]:
          inc(counter)
      await response.closeWait()
      await request.closeWait()
      await session.closeWait()

    ## Chunked url-encoded form
    block:
      var session = createSession(secure)
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, PostRequests[1][0])
        else:
          getAddress(address, HttpClientScheme.NonSecure, PostRequests[1][0])
      let headers = [
        ("Content-Type", "application/x-www-form-urlencoded"),
        ("Transfer-Encoding", "chunked")
      ]
      var request = HttpClientRequestRef.new(
        session, ha, MethodPost, headers = headers)

      var data = PostRequests[1][1]

      var writer = await open(request)
      var offset = 0
      while true:
        if len(data) == offset:
          break
        let toWrite = min(16, len(data) - offset)
        await writer.write(addr data[offset], toWrite)
        offset = offset + toWrite
      await writer.finish()
      await writer.closeWait()
      var response = await request.finish()
      if response.status == 200:
        var res = await response.getBodyBytes()
        if cast[string](res) == PostRequests[1][2]:
          inc(counter)
      await response.closeWait()
      await request.closeWait()
      await session.closeWait()

    await server.stop()
    await server.closeWait()
    return counter

  proc testRequestPostMultipartTest(secure: bool): Future[int] {.async.} =
    let PostRequests = [
      ("/test/post/multipart_size", "some-part-boundary",
       [("field1", "value1"), ("field2", "value2"), ("field3", "value3")],
       "value1:value2:value3"),
      ("/test/post/multipart_chunked", "some-part-boundary",
       [("field1", "longlonglongvalue1"), ("field2", "longlonglongvalue2"),
        ("field3", "longlonglongvalue3")],
       "longlonglongvalue1:longlonglongvalue2:longlonglongvalue3")
    ]

    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/test/post/multipart_size", "/test/post/multipart_chunked":
          if request.hasBody():
            var postTable = await request.post()
            let body = postTable.getString("field1") & ":" &
                       postTable.getString("field2") & ":" &
                       postTable.getString("field3")
            return await request.respond(Http200, body)
          else:
            return await request.respond(Http400, "Missing content body")
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()
    var counter = 0

    ## Sized multipart form
    block:
      var mp = MultiPartWriter.init(PostRequests[0][1])
      mp.begin()
      for item in PostRequests[0][2]:
        mp.beginPart(item[0], "", HttpTable.init())
        mp.write(item[1])
        mp.finishPart()
      let data = mp.finish()

      var session = createSession(secure)
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, PostRequests[0][0])
        else:
          getAddress(address, HttpClientScheme.NonSecure, PostRequests[0][0])
      let headers = [
        ("Content-Type", "multipart/form-data; boundary=" & PostRequests[0][1]),
      ]
      var request = HttpClientRequestRef.new(
        session, ha, MethodPost, headers = headers, body = data)
      var response = await send(request)
      if response.status == 200:
        var res = await response.getBodyBytes()
        if cast[string](res) == PostRequests[0][3]:
          inc(counter)
      await response.closeWait()
      await request.closeWait()
      await session.closeWait()

    ## Chunked multipart form
    block:
      var session = createSession(secure)
      let ha =
        if secure:
          getAddress(address, HttpClientScheme.Secure, PostRequests[0][0])
        else:
          getAddress(address, HttpClientScheme.NonSecure, PostRequests[0][0])
      let headers = [
        ("Content-Type", "multipart/form-data; boundary=" & PostRequests[1][1]),
        ("Transfer-Encoding", "chunked")
      ]
      var request = HttpClientRequestRef.new(
        session, ha, MethodPost, headers = headers)
      var writer = await open(request)
      var mpw = MultiPartWriterRef.new(writer, PostRequests[1][1])
      await mpw.begin()
      for item in PostRequests[1][2]:
        await mpw.beginPart(item[0], "", HttpTable.init())
        await mpw.write(item[1])
        await mpw.finishPart()
      await mpw.finish()
      await writer.finish()
      await writer.closeWait()
      let response = await request.finish()
      if response.status == 200:
        var res = await response.getBodyBytes()
        if cast[string](res) == PostRequests[1][3]:
          inc(counter)
      await response.closeWait()
      await request.closeWait()
      await session.closeWait()

    await server.stop()
    await server.closeWait()
    return counter

  proc testRequestRedirectTest(secure: bool,
                               max: int): Future[string] {.async.} =
    var lastAddress: Uri

    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/":
          return await request.redirect(Http302, "/redirect/1")
        of "/redirect/1":
          return await request.redirect(Http302, "/next/redirect/2")
        of "/next/redirect/2":
          return await request.redirect(Http302, "redirect/3")
        of "/next/redirect/redirect/3":
          return await request.redirect(Http302, "next/redirect/4")
        of "/next/redirect/redirect/next/redirect/4":
          return await request.redirect(Http302, lastAddress)
        of "/final/5":
          return await request.respond(Http200, "ok-5")
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()

    var session = createSession(secure, maxRedirections = max)

    let ha =
      if secure:
        getAddress(address, HttpClientScheme.Secure, "/")
      else:
        getAddress(address, HttpClientScheme.NonSecure, "/")

    lastAddress = ha.getUri().combine(parseUri("/final/5"))

    if session.maxRedirections >= 5:
      let (code, data) = await session.fetch(ha.getUri())
      await session.closeWait()
      await server.stop()
      await server.closeWait()
      return data.bytesToString() & "-" & $code
    else:
      let res =
        try:
          let (code {.used.}, data {.used.}) = await session.fetch(ha.getUri())
          false
        except HttpRedirectError:
          true
        except CatchableError:
          false
      await session.closeWait()
      await server.stop()
      await server.closeWait()
      return "redirect-" & $res

  proc testSendCancelLeaksTest(secure: bool): Future[bool] {.async.} =
    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()

    let ha =
      if secure:
        getAddress(address, HttpClientScheme.Secure, "/")
      else:
        getAddress(address, HttpClientScheme.NonSecure, "/")

    var counter = 0
    while true:
      let
        session = createSession(secure)
        request = HttpClientRequestRef.new(session, ha, MethodGet)
        requestFut = request.send()

      if counter > 0:
        await stepsAsync(counter)
      let exitLoop =
        if not(requestFut.finished()):
          await cancelAndWait(requestFut)
          doAssert(cancelled(requestFut) or completed(requestFut),
                   "Future should be Cancelled or Completed at this point")
          if requestFut.completed():
            let response = await requestFut
            await response.closeWait()

          inc(counter)
          false
        else:
          let response = await requestFut
          await response.closeWait()
          true

      await request.closeWait()
      await session.closeWait()

      if exitLoop:
        break

    await server.stop()
    await server.closeWait()
    return true

  proc testOpenCancelLeaksTest(secure: bool): Future[bool] {.async.} =
    proc process(r: RequestFence): Future[HttpResponseRef] {.
         async.} =
      return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()

    let ha =
      if secure:
        getAddress(address, HttpClientScheme.Secure, "/")
      else:
        getAddress(address, HttpClientScheme.NonSecure, "/")

    var counter = 0
    while true:
      let
        session = createSession(secure)
        request = HttpClientRequestRef.new(session, ha, MethodPost)
        bodyFut = request.open()

      if counter > 0:
        await stepsAsync(counter)
      let exitLoop =
        if not(bodyFut.finished()):
          await cancelAndWait(bodyFut)
          doAssert(cancelled(bodyFut) or completed(bodyFut),
                   "Future should be Cancelled or Completed at this point")

          if bodyFut.completed():
            let bodyWriter = await bodyFut
            await bodyWriter.closeWait()

          inc(counter)
          false
        else:
          let bodyWriter = await bodyFut
          await bodyWriter.closeWait()
          true

      await request.closeWait()
      await session.closeWait()

      if exitLoop:
        break

    await server.stop()
    await server.closeWait()
    return true

  # proc testBasicAuthorization(): Future[bool] {.async.} =
  #   let session = HttpSessionRef.new({HttpClientFlag.NoVerifyHost},
  #                                    maxRedirections = 10)
  #   let url = parseUri("https://guest:guest@jigsaw.w3.org/HTTP/Basic/")
  #   let resp = await session.fetch(url)
  #   await session.closeWait()
  #   if (resp.status == 200) and
  #      ("Your browser made it!" in bytesToString(resp.data)):
  #     return true
  #   else:
  #     echo "RESPONSE STATUS = [", resp.status, "]"
  #     echo "RESPONSE = [", bytesToString(resp.data), "]"
  #     return false

  proc testConnectionManagement(): Future[bool] {.
       async.} =
    proc test1(
           a1: HttpAddress,
           version: HttpVersion,
           sessionFlags: set[HttpClientFlag],
           requestFlags: set[HttpClientRequestFlag]
         ): Future[TestResponseTuple] {.async.} =
      let session = HttpSessionRef.new(flags = sessionFlags)
      var
        data: HttpResponseTuple
        count = -1
        request = HttpClientRequestRef.new(session, a1, version = version,
                                           flags = requestFlags)
      try:
        data = await request.fetch()
        await request.closeWait()
        count = session.connectionsCount
      finally:
        await session.closeWait()
      return (data.status, data.data.bytesToString(), count)

    proc test2(
           a1, a2: HttpAddress,
           version: HttpVersion,
           sessionFlags: set[HttpClientFlag],
           requestFlags: set[HttpClientRequestFlag]
         ): Future[seq[TestResponseTuple]] {.async.} =
      let session = HttpSessionRef.new(flags = sessionFlags)
      var
        data1: HttpResponseTuple
        data2: HttpResponseTuple
        count: int = -1
        request1 = HttpClientRequestRef.new(session, a1, version = version,
                                            flags = requestFlags)
        request2 = HttpClientRequestRef.new(session, a2, version = version,
                                            flags = requestFlags)
      try:
        data1 = await request1.fetch()
        data2 = await request2.fetch()
        await request1.closeWait()
        await request2.closeWait()
        count = session.connectionsCount
      finally:
        await session.closeWait()
      return @[(data1.status, data1.data.bytesToString(), count),
               (data2.status, data2.data.bytesToString(), count)]

    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/keep":
          let headers = HttpTable.init([("connection", "keep-alive")])
          return await request.respond(Http200, "ok", headers = headers)
        of "/drop":
          let headers = HttpTable.init([("connection", "close")])
          return await request.respond(Http200, "ok", headers = headers)
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, false)
    server.start()
    let address = server.instance.localAddress()

    let
      keepHa = getAddress(address, HttpClientScheme.NonSecure, "/keep")
      dropHa = getAddress(address, HttpClientScheme.NonSecure, "/drop")

    try:
      let
        r1 = await test1(keepHa, HttpVersion10, {}, {})
        r2 = await test1(keepHa, HttpVersion10,
                         {HttpClientFlag.NewConnectionAlways}, {})
        r3 = await test1(keepHa, HttpVersion10, {},
                         {HttpClientRequestFlag.DedicatedConnection})
        r4 = await test1(keepHa, HttpVersion10, {},
                         {HttpClientRequestFlag.DedicatedConnection,
                          HttpClientRequestFlag.CloseConnection})
        r5 = await test1(dropHa, HttpVersion10, {}, {})
        r6 = await test1(dropHa, HttpVersion10,
                         {HttpClientFlag.NewConnectionAlways}, {})
        r7 = await test1(dropHa, HttpVersion10, {},
                         {HttpClientRequestFlag.DedicatedConnection})
        r8 = await test1(dropHa, HttpVersion10, {},
                         {HttpClientRequestFlag.DedicatedConnection,
                          HttpClientRequestFlag.CloseConnection})
      check:
        r1 == (200, "ok", 0)
        r2 == (200, "ok", 0)
        r3 == (200, "ok", 0)
        r4 == (200, "ok", 0)
        r5 == (200, "ok", 0)
        r6 == (200, "ok", 0)
        r7 == (200, "ok", 0)
        r8 == (200, "ok", 0)

      let
        d1 = await test2(keepHa, dropHa, HttpVersion10, {}, {})
        d2 = await test2(keepHa, dropHa, HttpVersion10,
                         {HttpClientFlag.NewConnectionAlways}, {})
        d3 = await test2(keepHa, dropHa, HttpVersion10, {},
                         {HttpClientRequestFlag.DedicatedConnection})
        d4 = await test2(keepHa, dropHa, HttpVersion10, {},
                         {HttpClientRequestFlag.DedicatedConnection,
                          HttpClientRequestFlag.CloseConnection})
        d5 = await test2(dropHa, keepHa, HttpVersion10, {}, {})
        d6 = await test2(dropHa, keepHa, HttpVersion10,
                         {HttpClientFlag.NewConnectionAlways}, {})
        d7 = await test2(dropHa, keepHa, HttpVersion10, {},
                         {HttpClientRequestFlag.DedicatedConnection})
        d8 = await test2(dropHa, keepHa, HttpVersion10, {},
                         {HttpClientRequestFlag.DedicatedConnection,
                          HttpClientRequestFlag.CloseConnection})
      check:
        d1 == @[(200, "ok", 0), (200, "ok", 0)]
        d2 == @[(200, "ok", 0), (200, "ok", 0)]
        d3 == @[(200, "ok", 0), (200, "ok", 0)]
        d4 == @[(200, "ok", 0), (200, "ok", 0)]
        d5 == @[(200, "ok", 0), (200, "ok", 0)]
        d6 == @[(200, "ok", 0), (200, "ok", 0)]
        d7 == @[(200, "ok", 0), (200, "ok", 0)]
        d8 == @[(200, "ok", 0), (200, "ok", 0)]

      let
        n1 = await test1(keepHa, HttpVersion11,
                         {HttpClientFlag.Http11Pipeline}, {})
        n2 = await test2(keepHa, keepHa, HttpVersion11,
                         {HttpClientFlag.Http11Pipeline}, {})
        n3 = await test1(dropHa, HttpVersion11,
                         {HttpClientFlag.Http11Pipeline}, {})
        n4 = await test2(dropHa, dropHa, HttpVersion11,
                         {HttpClientFlag.Http11Pipeline}, {})
        n5 = await test1(keepHa, HttpVersion11,
                         {HttpClientFlag.NewConnectionAlways,
                          HttpClientFlag.Http11Pipeline}, {})
        n6 = await test1(keepHa, HttpVersion11,
                         {HttpClientFlag.Http11Pipeline},
                         {HttpClientRequestFlag.DedicatedConnection})
        n7 = await test1(keepHa, HttpVersion11,
                         {HttpClientFlag.Http11Pipeline},
                         {HttpClientRequestFlag.DedicatedConnection,
                          HttpClientRequestFlag.CloseConnection})
        n8 = await test1(keepHa, HttpVersion11,
                         {HttpClientFlag.Http11Pipeline},
                         {HttpClientRequestFlag.CloseConnection})
        n9 = await test1(keepHa, HttpVersion11,
                         {HttpClientFlag.NewConnectionAlways,
                          HttpClientFlag.Http11Pipeline},
                         {HttpClientRequestFlag.CloseConnection})
      check:
        n1 == (200, "ok", 1)
        n2 == @[(200, "ok", 2), (200, "ok", 2)]
        n3 == (200, "ok", 0)
        n4 == @[(200, "ok", 0), (200, "ok", 0)]
        n5 == (200, "ok", 0)
        n6 == (200, "ok", 1)
        n7 == (200, "ok", 0)
        n8 == (200, "ok", 0)
        n9 == (200, "ok", 0)
    finally:
      await server.stop()
      await server.closeWait()

    return true

  proc testIdleConnection(): Future[bool] {.async.} =
    proc test(
           session: HttpSessionRef,
           a: HttpAddress
         ): Future[TestResponseTuple] {.async.} =

      var
        data: HttpResponseTuple
        request = HttpClientRequestRef.new(session, a, version = HttpVersion11)
      try:
        data = await request.fetch()
      finally:
        await request.closeWait()
      return (data.status, data.data.bytesToString(), 0)

    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/test":
          return await request.respond(Http200, "ok")
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, false)
    server.start()
    let
      address = server.instance.localAddress()
      ha = getAddress(address, HttpClientScheme.NonSecure, "/test")
      session = HttpSessionRef.new({HttpClientFlag.Http11Pipeline},
                                   idleTimeout = 1.seconds,
                                   idlePeriod = 200.milliseconds)
    try:
      var f1 = test(session, ha)
      var f2 = test(session, ha)
      await allFutures(f1, f2)
      check:
        f1.finished()
        f1.completed()
        f2.finished()
        f2.completed()
        f1.read() == (200, "ok", 0)
        f2.read() == (200, "ok", 0)
        session.connectionsCount == 2

      await sleepAsync(1500.milliseconds)
      let resp = await test(session, ha)
      check:
        resp == (200, "ok", 0)
        session.connectionsCount == 1
    finally:
      await session.closeWait()
      await server.stop()
      await server.closeWait()

    return true

  proc testNoPipeline(): Future[bool] {.async.} =
    proc test(
           session: HttpSessionRef,
           a: HttpAddress
         ): Future[TestResponseTuple] {.async.} =

      var
        data: HttpResponseTuple
        request = HttpClientRequestRef.new(session, a, version = HttpVersion11)
      try:
        data = await request.fetch()
      finally:
        await request.closeWait()
      return (data.status, data.data.bytesToString(), 0)

    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        case request.uri.path
        of "/test":
          return await request.respond(Http200, "ok")
        of "/keep-test":
          let headers = HttpTable.init([("Connection", "keep-alive")])
          return await request.respond(Http200, "not-alive", headers)
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, false)
    server.start()
    let
      address = server.instance.localAddress()
      ha = getAddress(address, HttpClientScheme.NonSecure, "/test")
      hb = getAddress(address, HttpClientScheme.NonSecure, "/keep-test")
      session = HttpSessionRef.new(idleTimeout = 100.seconds,
                                   idlePeriod = 10.milliseconds)
    try:
      var f1 = test(session, ha)
      var f2 = test(session, ha)
      await allFutures(f1, f2)
      check:
        f1.finished()
        f1.completed()
        f2.finished()
        f2.completed()
        f1.read() == (200, "ok", 0)
        f2.read() == (200, "ok", 0)
        session.connectionsCount == 0

      await sleepAsync(100.milliseconds)
      block:
        let resp = await test(session, ha)
        check:
          resp == (200, "ok", 0)
          session.connectionsCount == 0
      block:
        let resp = await test(session, hb)
        check:
          resp == (200, "not-alive", 0)
          session.connectionsCount == 0
    finally:
      await session.closeWait()
      await server.stop()
      await server.closeWait()

    return true

  proc testServerSentEvents(secure: bool): Future[bool] {.async.} =
    const
      SingleGoodTests = [
        ("/test/single/1", "a:b\r\nc: d\re:f\n:comment\r\ng:\n h: j \n\n",
         @[("a", "b"), ("c", "d"), ("e", "f"), ("g", ""), (" h", "j ")]),
        ("/test/single/2", ":comment\r:\nfield1\r\nfield2:\n\n",
         @[("field1", ""), ("field2", "")]),
        ("/test/single/3", ":c1\r:c2\nfield1:value1", @[("field1", "value1")]),
        ("/test/single/4", ":c1\r:c2\nfield1:", @[("field1", "")]),
        ("/test/single/5", ":c1\r:c2\nfield1", @[("field1", "")]),
        ("/test/single/6", "a", @[("a", "")]),
        ("/test/single/7", "b:", @[("b", "")]),
        ("/test/single/8", "c:d", @[("c", "d")]),
        ("/test/single/9", ":", @[]),
        ("/test/single/10", "", @[]),
        ("/test/single/11", ":c1\n", @[]),
        ("/test/single/12", ":c1\n:c2\n", @[]),
        ("/test/single/13", ":c1\n:c2\n:c3\n", @[]),
        ("/test/single/14", ":c1\n:c2\n:c3\n:c4", @[]),
        ("/test/single/15", "\r\r", @[("", "")]),
        ("/test/single/15", "\n\n", @[("", "")]),
        ("/test/single/17", "\r\n\r\n", @[("", "")]),
        ("/test/single/18", "\r\n", @[("", "")]),
        ("/test/single/19", "\r", @[("", "")]),
        ("/test/single/20", "\n", @[("", "")])
      ]
      MultipleGoodTests = [
        ("/test/multiple/1", "a:b\nc:d\n\ne:f\rg:h\r\ri:j\r\nk:l\r\n\r\n", 3,
         @[@[("a", "b"), ("c", "d")], @[("e", "f"), ("g", "h")],
           @[("i", "j"), ("k", "l")]]),
        ("/test/multiple/2", "a:b\nc:d\n\ne:f\rg:h\r\ri:j\r\nk:l\r\n\r\n\r\n",
          4, @[@[("a", "b"), ("c", "d")], @[("e", "f"), ("g", "h")],
             @[("i", "j"), ("k", "l")], @[("", "")]]),
      ]
      OverflowTests = [
        ("/test/overflow/1", ":verylongcomment", 1, false),
        ("/test/overflow/2", ":verylongcomment\n:anotherone", 1, false),
        ("/test/overflow/3", "aa\n", 1, true),
        ("/test/overflow/4", "a:b\n", 2, true)
      ]

    proc `==`(a: ServerSentEvent, b: tuple[name: string, value: string]): bool =
      a.name == b.name and a.data == b.value

    proc `==`(a: seq[ServerSentEvent],
              b: seq[tuple[name: string, value: string]]): bool =
      if len(a) != len(b):
        return false
      for index, value in a.pairs():
        if value != b[index]:
          return false
      true

    proc `==`(a: seq[seq[ServerSentEvent]],
              b: seq[seq[tuple[name: string, value: string]]]): bool =
      if len(a) != len(b):
        return false
      for index, value in a.pairs():
        if value != b[index]:
          return false
      true

    proc process(r: RequestFence): Future[HttpResponseRef] {.async.} =
      if r.isOk():
        let request = r.get()
        if request.uri.path.startsWith("/test/single/"):
          let index =
            block:
              var res = -1
              for index, value in SingleGoodTests.pairs():
                if value[0] == request.uri.path:
                  res = index
                  break
              res
          if index < 0:
            return await request.respond(Http404, "Page not found")
          var response = request.getResponse()
          response.status = Http200
          await response.sendBody(SingleGoodTests[index][1])
          return response
        elif request.uri.path.startsWith("/test/multiple/"):
          let index =
            block:
              var res = -1
              for index, value in MultipleGoodTests.pairs():
                if value[0] == request.uri.path:
                  res = index
                  break
              res
          if index < 0:
            return await request.respond(Http404, "Page not found")
          var response = request.getResponse()
          response.status = Http200
          await response.sendBody(MultipleGoodTests[index][1])
          return response
        elif request.uri.path.startsWith("/test/overflow/"):
          let index =
            block:
              var res = -1
              for index, value in OverflowTests.pairs():
                if value[0] == request.uri.path:
                  res = index
                  break
              res
          if index < 0:
            return await request.respond(Http404, "Page not found")
          var response = request.getResponse()
          response.status = Http200
          await response.sendBody(OverflowTests[index][1])
          return response
        else:
          return await request.respond(Http404, "Page not found")
      else:
        return defaultResponse()

    var server = createServer(initTAddress("127.0.0.1:0"), process, secure)
    server.start()
    let address = server.instance.localAddress()

    var session = createSession(secure)

    try:
      for item in SingleGoodTests:
        let ha =
          if secure:
            getAddress(address, HttpClientScheme.Secure, item[0])
          else:
            getAddress(address, HttpClientScheme.NonSecure, item[0])
        let
          req = HttpClientRequestRef.new(session, ha, HttpMethod.MethodGet)
          response = await req.send()
          events = await response.getServerSentEvents()
        check events == item[2]
        await response.closeWait()
        await req.closeWait()

      for item in MultipleGoodTests:
        let ha =
          if secure:
            getAddress(address, HttpClientScheme.Secure, item[0])
          else:
            getAddress(address, HttpClientScheme.NonSecure, item[0])
        var req = HttpClientRequestRef.new(session, ha, HttpMethod.MethodGet)
        var response = await send(req)
        let events =
          block:
            var res: seq[seq[ServerSentEvent]]
            for i in 0 ..< item[2]:
              let ires = await response.getServerSentEvents()
              res.add(ires)
            res
        check events == item[3]
        await closeWait(response)
        await closeWait(req)

      for item in OverflowTests:
        let ha =
          if secure:
            getAddress(address, HttpClientScheme.Secure, item[0])
          else:
            getAddress(address, HttpClientScheme.NonSecure, item[0])
        var req = HttpClientRequestRef.new(session, ha, HttpMethod.MethodGet)
        var response = await send(req)
        let error =
          try:
            let events {.used.} = await response.getServerSentEvents(item[2])
            false
          except HttpReadLimitError:
            true
          except CatchableError:
            false
        check error == item[3]
        await closeWait(response)
        await closeWait(req)

    finally:
      await closeWait(session)
      await server.stop()
      await server.closeWait()

    return true

  test "HTTP all request methods test":
    check waitFor(testMethods(false)) == 18

  test "HTTP(S) all request methods test":
    check waitFor(testMethods(true)) == 18

  test "HTTP client response streaming test":
    check waitFor(testResponseStreamReadingTest(false)) == 8

  test "HTTP(S) client response streaming test":
    check waitFor(testResponseStreamReadingTest(true)) == 8

  test "HTTP client (size) request streaming test":
    check waitFor(testRequestSizeStreamWritingTest(false)) == 2

  test "HTTP(S) client (size) request streaming test":
    check waitFor(testRequestSizeStreamWritingTest(true)) == 2

  test "HTTP client (chunked) request streaming test":
    check waitFor(testRequestChunkedStreamWritingTest(false)) == 2

  test "HTTP(S) client (chunked) request streaming test":
    check waitFor(testRequestChunkedStreamWritingTest(true)) == 2

  test "HTTP client (size + chunked) url-encoded POST test":
    check waitFor(testRequestPostUrlEncodedTest(false)) == 2

  test "HTTP(S) client (size + chunked) url-encoded POST test":
    check waitFor(testRequestPostUrlEncodedTest(true)) == 2

  test "HTTP client (size + chunked) multipart POST test":
    check waitFor(testRequestPostMultipartTest(false)) == 2

  test "HTTP(S) client (size + chunked) multipart POST test":
    check waitFor(testRequestPostMultipartTest(true)) == 2

  test "HTTP client redirection test":
    check waitFor(testRequestRedirectTest(false, 5)) == "ok-5-200"

  test "HTTP(S) client redirection test":
    check waitFor(testRequestRedirectTest(true, 5)) == "ok-5-200"

  test "HTTP client maximum redirections test":
    check waitFor(testRequestRedirectTest(false, 4)) == "redirect-true"

  test "HTTP(S) client maximum redirections test":
    check waitFor(testRequestRedirectTest(true, 4)) == "redirect-true"

  test "HTTP send() cancellation leaks test":
    check waitFor(testSendCancelLeaksTest(false)) == true

  test "HTTP(S) send() cancellation leaks test":
    check waitFor(testSendCancelLeaksTest(true)) == true

  test "HTTP open() cancellation leaks test":
    check waitFor(testOpenCancelLeaksTest(false)) == true

  test "HTTP(S) open() cancellation leaks test":
    check waitFor(testOpenCancelLeaksTest(true)) == true

  test "HTTPS basic authorization test":
    skip()
    # This test disabled because remote service is pretty flaky and fails pretty
    # often. As soon as more stable service will be found this test should be
    # recovered
    # check waitFor(testBasicAuthorization()) == true

  test "HTTP client connection management test":
    check waitFor(testConnectionManagement()) == true

  test "HTTP client idle connection test":
    check waitFor(testIdleConnection()) == true

  test "HTTP client no-pipeline test":
    check waitFor(testNoPipeline()) == true

  test "HTTP client server-sent events test":
    check waitFor(testServerSentEvents(false)) == true

  test "HTTP getHttpAddress() test":
    block:
      # HTTP client supports only `http` and `https` schemes in URL.
      let res = getHttpAddress("ftp://ftp.scene.org")
      check:
        res.isErr()
        res.error == HttpAddressErrorType.InvalidUrlScheme
        res.error.isCriticalError()
    block:
      # HTTP URL default ports and custom ports test
      let
        res1 = getHttpAddress("http://www.google.com")
        res2 = getHttpAddress("https://www.google.com")
        res3 = getHttpAddress("http://www.google.com:35000")
        res4 = getHttpAddress("https://www.google.com:25000")
      check:
        res1.isOk()
        res2.isOk()
        res3.isOk()
        res4.isOk()
        res1.get().port == 80
        res2.get().port == 443
        res3.get().port == 35000
        res4.get().port == 25000
    block:
      # HTTP URL invalid port values test
      let
        res1 = getHttpAddress("http://www.google.com:-80")
        res2 = getHttpAddress("http://www.google.com:0")
        res3 = getHttpAddress("http://www.google.com:65536")
        res4 = getHttpAddress("http://www.google.com:65537")
        res5 = getHttpAddress("https://www.google.com:-443")
        res6 = getHttpAddress("https://www.google.com:0")
        res7 = getHttpAddress("https://www.google.com:65536")
        res8 = getHttpAddress("https://www.google.com:65537")
      check:
        res1.isErr() and res1.error == HttpAddressErrorType.InvalidPortNumber
        res1.error.isCriticalError()
        res2.isOk()
        res2.get().port == 0
        res3.isErr() and res3.error == HttpAddressErrorType.InvalidPortNumber
        res3.error.isCriticalError()
        res4.isErr() and res4.error == HttpAddressErrorType.InvalidPortNumber
        res4.error.isCriticalError()
        res5.isErr() and res5.error == HttpAddressErrorType.InvalidPortNumber
        res5.error.isCriticalError()
        res6.isOk()
        res6.get().port == 0
        res7.isErr() and res7.error == HttpAddressErrorType.InvalidPortNumber
        res7.error.isCriticalError()
        res8.isErr() and res8.error == HttpAddressErrorType.InvalidPortNumber
        res8.error.isCriticalError()
    block:
      # HTTP URL missing hostname
      let
        res1 = getHttpAddress("http://")
        res2 = getHttpAddress("https://")
      check:
        res1.isErr() and res1.error == HttpAddressErrorType.MissingHostname
        res1.error.isCriticalError()
        res2.isErr() and res2.error == HttpAddressErrorType.MissingHostname
        res2.error.isCriticalError()
    block:
      # No resolution flags and incorrect URL
      let
        flags = {HttpClientFlag.NoInet4Resolution,
                 HttpClientFlag.NoInet6Resolution}
        res1 = getHttpAddress("http://256.256.256.256", flags)
        res2 = getHttpAddress(
          "http://[FFFFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]", flags)
      check:
        res1.isErr() and res1.error == HttpAddressErrorType.InvalidIpHostname
        res1.error.isCriticalError()
        res2.isErr() and res2.error == HttpAddressErrorType.InvalidIpHostname
        res2.error.isCriticalError()
    block:
      # Resolution of non-existent hostname
      let res = getHttpAddress("http://eYr6bdBo.com")
      check:
        res.isErr() and res.error == HttpAddressErrorType.NameLookupFailed
        res.error.isRecoverableError()
        not(res.error.isCriticalError())

  test "Leaks test":
    checkLeaks()
