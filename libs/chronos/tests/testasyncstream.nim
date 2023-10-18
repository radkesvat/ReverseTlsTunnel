#                Chronos Test Suite
#            (c) Copyright 2019-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import unittest2
import bearssl/[x509]
import ".."/chronos/unittest2/asynctests
import ".."/chronos/streams/[tlsstream, chunkstream, boundstream]

{.used.}

# To create self-signed certificate and key you can use openssl
# openssl req -new -x509 -sha256 -newkey rsa:2048 -nodes \
# -keyout example-com.key.pem -days 3650 -out example-com.cert.pem

const SelfSignedRsaKey = """
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
const SelfSignedRsaCert = """
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

let SelfSignedTrustAnchors {.importc: "SelfSignedTAs".}: array[1, X509TrustAnchor]
{.compile: "testasyncstream.c".}

proc createBigMessage(message: string, size: int): seq[byte] =
  var res = newSeq[byte](size)
  for i in 0 ..< len(res):
    res[i] = byte(ord(message[i mod len(message)]))
  res

suite "AsyncStream test suite":
  test "AsyncStream(StreamTransport) readExactly() test":
    proc testReadExactly(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        await wstream.write("000000000011111111112222222222")
        await wstream.finish()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var buffer = newSeq[byte](10)
      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      await rstream.readExactly(addr buffer[0], 10)
      check cast[string](buffer) == "0000000000"
      await rstream.readExactly(addr buffer[0], 10)
      check cast[string](buffer) == "1111111111"
      await rstream.readExactly(addr buffer[0], 10)
      check cast[string](buffer) == "2222222222"
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testReadExactly()) == true

  test "AsyncStream(StreamTransport) readUntil() test":
    proc testReadUntil(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        await wstream.write("0000000000NNz1111111111NNz2222222222NNz")
        await wstream.finish()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var buffer = newSeq[byte](13)
      var sep = @[byte('N'), byte('N'), byte('z')]
      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var r1 = await rstream.readUntil(addr buffer[0], len(buffer), sep)
      check:
        r1 == 13
        cast[string](buffer) == "0000000000NNz"
      var r2 = await rstream.readUntil(addr buffer[0], len(buffer), sep)
      check:
        r2 == 13
        cast[string](buffer) == "1111111111NNz"
      var r3 = await rstream.readUntil(addr buffer[0], len(buffer), sep)
      check:
        r3 == 13
        cast[string](buffer) == "2222222222NNz"

      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testReadUntil()) == true

  test "AsyncStream(StreamTransport) readLine() test":
    proc testReadLine(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        await wstream.write("0000000000\r\n1111111111\r\n2222222222\r\n")
        await wstream.finish()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var r1 = await rstream.readLine()
      check r1 == "0000000000"
      var r2 = await rstream.readLine()
      check r2 == "1111111111"
      var r3 = await rstream.readLine()
      check r3 == "2222222222"
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testReadLine()) == true

  test "AsyncStream(StreamTransport) read() test":
    proc testRead(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        await wstream.write("000000000011111111112222222222")
        await wstream.finish()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var buf1 = await rstream.read(10)
      check cast[string](buf1) == "0000000000"
      var buf2 = await rstream.read()
      check cast[string](buf2) == "11111111112222222222"
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testRead()) == true

  test "AsyncStream(StreamTransport) consume() test":
    proc testConsume(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        await wstream.write("0000000000111111111122222222223333333333")
        await wstream.finish()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var res1 = await rstream.consume(10)
      check:
        res1 == 10
      var buf1 = await rstream.read(10)
      check cast[string](buf1) == "1111111111"
      var res2 = await rstream.consume(10)
      check:
        res2 == 10
      var buf2 = await rstream.read(10)
      check cast[string](buf2) == "3333333333"
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testConsume()) == true

  test "AsyncStream(StreamTransport) leaks test":
    checkLeaks()

  test "AsyncStream(AsyncStream) readExactly() test":
    proc testReadExactly2(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var wstream2 = newChunkedStreamWriter(wstream)
        var s1 = "00000"
        var s2 = "11111"
        var s3 = "22222"
        await wstream2.write("00000")
        await wstream2.write(addr s1[0], len(s1))
        await wstream2.write("11111")
        await wstream2.write(cast[seq[byte]](s2))
        await wstream2.write("22222")
        await wstream2.write(addr s3[0], len(s3))

        await wstream2.finish()
        await wstream.finish()
        await wstream2.closeWait()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var buffer = newSeq[byte](10)
      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)
      await rstream2.readExactly(addr buffer[0], 10)
      check cast[string](buffer) == "0000000000"
      await rstream2.readExactly(addr buffer[0], 10)
      check cast[string](buffer) == "1111111111"
      await rstream2.readExactly(addr buffer[0], 10)
      check cast[string](buffer) == "2222222222"

      # We need to consume all the stream with finish markers, but there will
      # be no actual data.
      let left = await rstream2.consume()
      check:
        left == 0
        rstream2.atEof() == true

      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testReadExactly2()) == true

  test "AsyncStream(AsyncStream) readUntil() test":
    proc testReadUntil2(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var wstream2 = newChunkedStreamWriter(wstream)
        var s1 = "00000NNz"
        var s2 = "11111NNz"
        var s3 = "22222NNz"
        await wstream2.write("00000")
        await wstream2.write(addr s1[0], len(s1))
        await wstream2.write("11111")
        await wstream2.write(s2)
        await wstream2.write("22222")
        await wstream2.write(cast[seq[byte]](s3))
        await wstream2.finish()
        await wstream.finish()
        await wstream2.closeWait()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var buffer = newSeq[byte](13)
      var sep = @[byte('N'), byte('N'), byte('z')]
      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)

      var r1 = await rstream2.readUntil(addr buffer[0], len(buffer), sep)
      check:
        r1 == 13
        cast[string](buffer) == "0000000000NNz"
      var r2 = await rstream2.readUntil(addr buffer[0], len(buffer), sep)
      check:
        r2 == 13
        cast[string](buffer) == "1111111111NNz"
      var r3 = await rstream2.readUntil(addr buffer[0], len(buffer), sep)
      check:
        r3 == 13
        cast[string](buffer) == "2222222222NNz"

      # We need to consume all the stream with finish markers, but there will
      # be no actual data.
      let left = await rstream2.consume()
      check:
        left == 0
        rstream2.atEof() == true

      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testReadUntil2()) == true

  test "AsyncStream(AsyncStream) readLine() test":
    proc testReadLine2(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var wstream2 = newChunkedStreamWriter(wstream)
        await wstream2.write("00000")
        await wstream2.write("00000\r\n")
        await wstream2.write("11111")
        await wstream2.write("11111\r\n")
        await wstream2.write("22222")
        await wstream2.write("22222\r\n")
        await wstream2.finish()
        await wstream.finish()
        await wstream2.closeWait()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)
      var r1 = await rstream2.readLine()
      check r1 == "0000000000"
      var r2 = await rstream2.readLine()
      check r2 == "1111111111"
      var r3 = await rstream2.readLine()
      check r3 == "2222222222"

      # We need to consume all the stream with finish markers, but there will
      # be no actual data.
      let left = await rstream2.consume()
      check:
        left == 0
        rstream2.atEof() == true

      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testReadLine2()) == true

  test "AsyncStream(AsyncStream) read() test":
    proc testRead2(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var wstream2 = newChunkedStreamWriter(wstream)
        var s2 = "1111111111"
        var s3 = "2222222222"
        await wstream2.write("0000000000")
        await wstream2.write(s2)
        await wstream2.write(cast[seq[byte]](s3))
        await wstream2.finish()
        await wstream.finish()
        await wstream2.closeWait()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)
      var buf1 = await rstream2.read(10)
      check cast[string](buf1) == "0000000000"
      var buf2 = await rstream2.read()
      check cast[string](buf2) == "11111111112222222222"

      # read() call will consume all the bytes and finish markers too, so
      # we just check stream for EOF.
      check rstream2.atEof() == true

      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testRead2()) == true

  test "AsyncStream(AsyncStream) consume() test":
    proc testConsume2(): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        const
          S4 = @[byte('3'), byte('3'), byte('3'), byte('3'), byte('3')]
        var wstream = newAsyncStreamWriter(transp)
        var wstream2 = newChunkedStreamWriter(wstream)

        var s1 = "00000"
        var s2 = cast[seq[byte]]("11111")
        var s3 = "22222"

        await wstream2.write("00000")
        await wstream2.write(s1)
        await wstream2.write("11111")
        await wstream2.write(s2)
        await wstream2.write("22222")
        await wstream2.write(addr s3[0], len(s3))
        await wstream2.write("33333")
        await wstream2.write(S4)
        await wstream2.finish()
        await wstream.finish()
        await wstream2.closeWait()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)

      var res1 = await rstream2.consume(10)
      check:
        res1 == 10
      var buf1 = await rstream2.read(10)
      check cast[string](buf1) == "1111111111"
      var res2 = await rstream2.consume(10)
      check:
        res2 == 10
      var buf2 = await rstream2.read(10)
      check cast[string](buf2) == "3333333333"

      # We need to consume all the stream with finish markers, but there will
      # be no actual data.
      let left = await rstream2.consume()
      check:
        left == 0
        rstream2.atEof() == true

      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = true
    check waitFor(testConsume2()) == true

  test "AsyncStream(AsyncStream) write(eof) test":
    proc testWriteEof(): Future[bool] {.async.} =
      let
        size = 10240
        message = createBigMessage("ABCDEFGHIJKLMNOP", size)

      proc processClient(server: StreamServer,
                         transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var wbstream = newBoundedStreamWriter(wstream, uint64(size))
        try:
          check wbstream.atEof() == false
          await wbstream.write(message)
          check wbstream.atEof() == false
          await wbstream.finish()
          check wbstream.atEof() == true
          expect AsyncStreamWriteEOFError:
            await wbstream.write(message)
          expect AsyncStreamWriteEOFError:
            await wbstream.write(message)
          expect AsyncStreamWriteEOFError:
            await wbstream.write(message)
          check wbstream.atEof() == true
          await wbstream.closeWait()
          check wbstream.atEof() == true
        finally:
          await wstream.closeWait()
          await transp.closeWait()

      let flags = {ServerFlags.ReuseAddr, ServerFlags.TcpNoDelay}
      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      processClient, flags = flags)
      server.start()
      var conn = await connect(server.localAddress())
      try:
        discard await conn.consume()
      finally:
        await conn.closeWait()
        server.stop()
        await server.closeWait()
      return true

    check waitFor(testWriteEof()) == true

  test "AsyncStream(AsyncStream) leaks test":
    checkLeaks()

suite "ChunkedStream test suite":
  test "ChunkedStream test vectors":
    const ChunkedVectors = [
      ["4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n",
       "Wikipedia in\r\n\r\nchunks."],
      ["4\r\nWiki\r\n5\r\npedia\r\nE\r\n in\r\n\r\nchunks.\r\n0\r\n\r\n0\r\n\r\n",
       "Wikipedia in\r\n\r\nchunks."],
      ["3b\r\n--f98f0\r\nContent-Disposition: form-data; name=\"key1\"" &
       "\r\n\r\nA\r\n\r\n" &
       "3b\r\n--f98f0\r\nContent-Disposition: form-data; name=\"key2\"" &
       "\r\n\r\nB\r\n\r\n" &
       "3b\r\n--f98f0\r\nContent-Disposition: form-data; name=\"key3\"" &
       "\r\n\r\nC\r\n\r\n" &
       "b\r\n--f98f0--\r\n\r\n" &
       "0\r\n\r\n",
       "--f98f0\r\nContent-Disposition: form-data; name=\"key1\"" &
       "\r\n\r\nA\r\n" &
       "--f98f0\r\nContent-Disposition: form-data; name=\"key2\"" &
       "\r\n\r\nB\r\n" &
       "--f98f0\r\nContent-Disposition: form-data; name=\"key3\"" &
       "\r\n\r\nC\r\n" &
       "--f98f0--\r\n"
      ],
      ["4;position=1\r\nWiki\r\n5;position=2\r\npedia\r\nE;position=3\r\n" &
       " in\r\n\r\nchunks.\r\n0;position=4\r\n\r\n",
       "Wikipedia in\r\n\r\nchunks."],
    ]
    proc checkVector(inputstr: string): Future[string] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var data = inputstr
        await wstream.write(data)
        await wstream.finish()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)
      var res = await rstream2.read()
      var ress = cast[string](res)
      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = ress

    proc testVectors(): Future[bool] {.async.} =
      var res = true
      for i in 0..<len(ChunkedVectors):
        var r = await checkVector(ChunkedVectors[i][0])
        if r != ChunkedVectors[i][1]:
          res = false
          break
      result = res
    check waitFor(testVectors()) == true

  test "ChunkedStream incorrect chunk test":
    const BadVectors = [
      ["10000000;\r\n1"],
      ["10000000\r\n1"],
      ["FFFFFFFF;extension1=value1;extension2=value2\r\n1"],
      ["FFFFFFFF\r\n1"],
      ["100000000\r\n1"],
      ["10000000 \r\n1"],
      ["100000000 ;\r\n"],
      ["FFFFFFFF0\r\n1"],
      ["FFFFFFFF \r\n1"],
      ["FFFFFFFF ;\r\n1"],
      ["z\r\n1"]
    ]
    proc checkVector(inputstr: string): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var data = inputstr
        await wstream.write(data)
        await wstream.finish()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var res = false
      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)
      try:
        var r = await rstream2.read()
        doAssert(len(r) > 0)
      except ChunkedStreamIncompleteError:
        case inputstr
        of "10000000;\r\n1":
          res = true
        of "10000000\r\n1":
          res = true
        of "FFFFFFFF;extension1=value1;extension2=value2\r\n1":
          res = true
        of "FFFFFFFF\r\n1":
          res = true
        else:
          res = false
      except ChunkedStreamProtocolError:
        case inputstr
        of "100000000\r\n1":
          res = true
        of "10000000 \r\n1":
          res = true
        of "100000000 ;\r\n":
          res = true
        of "z\r\n1":
          res = true
        of "FFFFFFFF0\r\n1":
          res = true
        of "FFFFFFFF \r\n1":
          res = true
        of "FFFFFFFF ;\r\n1":
          res = true
        else:
          res = false

      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      result = res

    proc testVectors2(): Future[bool] {.async.} =
      var res = true
      for i in 0..<len(BadVectors):
        var r = await checkVector(BadVectors[i][0])
        if not(r):
          res = false
          break
      result = res
    check waitFor(testVectors2()) == true

  test "ChunkedStream hex decoding test":
    for i in 0 ..< 256:
      let ch = char(i)
      case ch
      of '0' .. '9':
        check hexValue(byte(ch)) == ord(ch) - ord('0')
      of 'a' .. 'f':
        check hexValue(byte(ch)) == ord(ch) - ord('a') + 10
      of 'A' .. 'F':
        check hexValue(byte(ch)) == ord(ch) - ord('A') + 10
      else:
        check hexValue(byte(ch)) == -1

  test "ChunkedStream too big chunk header test":
    proc checkTooBigChunkHeader(inputstr: seq[byte]): Future[bool] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        await wstream.write(inputstr)
        await wstream.finish()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)
      let res =
        try:
          var datares {.used.} = await rstream2.read()
          false
        except ChunkedStreamProtocolError:
          true
        except CatchableError:
          false
      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      return res

    var data1 = createBigMessage("REQUESTSTREAMMESSAGE", 65600)
    var data2 = createBigMessage("REQUESTSTREAMMESSAGE", 262400)
    check waitFor(checkTooBigChunkHeader(data1)) == true
    check waitFor(checkTooBigChunkHeader(data2)) == true

  test "ChunkedStream read/write test":
    proc checkVector(inputstr: seq[byte],
                     chunkSize: int): Future[seq[byte]] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var wstream2 = newChunkedStreamWriter(wstream)
        var data = inputstr
        var offset = 0
        while true:
          if len(data) == offset:
            break
          let toWrite = min(chunkSize, len(data) - offset)
          await wstream2.write(addr data[offset], toWrite)
          offset = offset + toWrite
        await wstream2.finish()
        await wstream2.closeWait()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)
      var res = await rstream2.read()
      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      return res

    proc testBigData(datasize: int, chunksize: int): Future[bool] {.async.} =
      var data = createBigMessage("REQUESTSTREAMMESSAGE", datasize)
      var check = await checkVector(data, chunksize)
      return (data == check)

    check waitFor(testBigData(65600, 1024)) == true
    check waitFor(testBigData(262400, 4096)) == true
    check waitFor(testBigData(767309, 4457)) == true

  test "ChunkedStream read small chunks test":
    proc checkVector(inputstr: seq[byte],
                     writeChunkSize: int,
                     readChunkSize: int): Future[seq[byte]] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var wstream2 = newChunkedStreamWriter(wstream)
        var data = inputstr
        var offset = 0
        while true:
          if len(data) == offset:
            break
          let toWrite = min(writeChunkSize, len(data) - offset)
          await wstream2.write(addr data[offset], toWrite)
          offset = offset + toWrite
        await wstream2.finish()
        await wstream2.closeWait()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newChunkedStreamReader(rstream)
      var res: seq[byte]
      while not(rstream2.atEof()):
        var chunk = await rstream2.read(readChunkSize)
        res.add(chunk)
      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      return res

    proc testSmallChunk(datasize: int,
                        writeChunkSize: int,
                        readChunkSize: int): Future[bool] {.async.} =
      var data = createBigMessage("REQUESTSTREAMMESSAGE", datasize)
      var check = await checkVector(data, writeChunkSize, readChunkSize)
      return (data == check)

    check waitFor(testSmallChunk(4457, 128, 1)) == true
    check waitFor(testSmallChunk(65600, 1024, 17)) == true
    check waitFor(testSmallChunk(262400, 4096, 61)) == true
    check waitFor(testSmallChunk(767309, 4457, 173)) == true

  test "ChunkedStream leaks test":
    checkLeaks()

suite "TLSStream test suite":
  const HttpHeadersMark = @[byte(0x0D), byte(0x0A), byte(0x0D), byte(0x0A)]
  test "Simple HTTPS connection":
    proc headerClient(address: TransportAddress,
                      name: string): Future[bool] {.async.} =
      var mark = "HTTP/1.1 "
      var buffer = newSeq[byte](8192)
      var transp = await connect(address)
      var reader = newAsyncStreamReader(transp)
      var writer = newAsyncStreamWriter(transp)
      var tlsstream = newTLSClientAsyncStream(reader, writer, name)
      await tlsstream.writer.write("GET / HTTP/1.1\r\nHost: " & name &
                                   "\r\nConnection: close\r\n\r\n")
      var readFut = tlsstream.reader.readUntil(addr buffer[0], len(buffer),
                                               HttpHeadersMark)
      let res = await withTimeout(readFut, 5.seconds)
      if res:
        var length = readFut.read()
        buffer.setLen(length)
        if len(buffer) > len(mark):
          if equalMem(addr buffer[0], addr mark[0], len(mark)):
            result = true

      await tlsstream.reader.closeWait()
      await tlsstream.writer.closeWait()
      await reader.closeWait()
      await writer.closeWait()
      await transp.closeWait()

    let res = waitFor(headerClient(resolveTAddress("www.google.com:443")[0],
                      "www.google.com"))
    check res == true

  proc checkSSLServer(pemkey, pemcert: string): Future[bool] {.async.} =
    var key: TLSPrivateKey
    var cert: TLSCertificate
    let testMessage = "TEST MESSAGE"

    proc serveClient(server: StreamServer,
                     transp: StreamTransport) {.async.} =
      var reader = newAsyncStreamReader(transp)
      var writer = newAsyncStreamWriter(transp)
      var sstream = newTLSServerAsyncStream(reader, writer, key, cert)
      await handshake(sstream)
      await sstream.writer.write(testMessage & "\r\n")
      await sstream.writer.finish()
      await sstream.writer.closeWait()
      await sstream.reader.closeWait()
      await reader.closeWait()
      await writer.closeWait()
      await transp.closeWait()
      server.stop()
      server.close()

    key = TLSPrivateKey.init(pemkey)
    cert = TLSCertificate.init(pemcert)

    var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                    serveClient, {ServerFlags.ReuseAddr})
    server.start()
    var conn = await connect(server.localAddress())
    var creader = newAsyncStreamReader(conn)
    var cwriter = newAsyncStreamWriter(conn)
    # We are using self-signed certificate
    let flags = {NoVerifyHost, NoVerifyServerName}
    var cstream = newTLSClientAsyncStream(creader, cwriter, "", flags = flags)
    let res = await cstream.reader.read()
    await cstream.reader.closeWait()
    await cstream.writer.closeWait()
    await creader.closeWait()
    await cwriter.closeWait()
    await conn.closeWait()
    await server.join()
    return cast[string](res) == (testMessage & "\r\n")

  test "Simple server with RSA self-signed certificate":
    let res = waitFor(checkSSLServer(SelfSignedRsaKey, SelfSignedRsaCert))
    check res == true

  test "Custom TrustAnchors test":
    proc checkTrustAnchors(testMessage: string): Future[string] {.async.} =
      var key = TLSPrivateKey.init(SelfSignedRsaKey)
      var cert = TLSCertificate.init(SelfSignedRsaCert)
      let trustAnchors = TrustAnchorStore.new(SelfSignedTrustAnchors)

      proc serveClient(server: StreamServer,
                      transp: StreamTransport) {.async.} =
        var reader = newAsyncStreamReader(transp)
        var writer = newAsyncStreamWriter(transp)
        var sstream = newTLSServerAsyncStream(reader, writer, key, cert)
        await handshake(sstream)
        await sstream.writer.write(testMessage & "\r\n")
        await sstream.writer.finish()
        await sstream.writer.closeWait()
        await sstream.reader.closeWait()
        await reader.closeWait()
        await writer.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var conn = await connect(server.localAddress())
      var creader = newAsyncStreamReader(conn)
      var cwriter = newAsyncStreamWriter(conn)
      let flags = {NoVerifyServerName}
      var cstream = newTLSClientAsyncStream(creader, cwriter, "", flags = flags,
        trustAnchors = trustAnchors)
      let res = await cstream.reader.read()
      await cstream.reader.closeWait()
      await cstream.writer.closeWait()
      await creader.closeWait()
      await cwriter.closeWait()
      await conn.closeWait()
      await server.join()
      return cast[string](res)
    let res = waitFor checkTrustAnchors("Some message")
    check res == "Some message\r\n"

  test "TLSStream leaks test":
    checkLeaks()

suite "BoundedStream test suite":

  type
    BoundarySizeTest = enum
      SizeReadWrite, SizeOverflow, SizeIncomplete, SizeEmpty
    BoundaryBytesTest = enum
      BoundaryRead, BoundaryDouble, BoundarySize, BoundaryIncomplete,
      BoundaryEmpty

  for itemComp in [BoundCmp.Equal, BoundCmp.LessOrEqual]:
    for itemSize in [100, 60000]:

      proc boundaryTest(btest: BoundaryBytesTest,
                        size: int, boundary: seq[byte],
                        cmp: BoundCmp): Future[bool] {.async.} =
        var message = createBigMessage("ABCDEFGHIJKLMNOP", size)
        var clientRes = false

        proc processClient(server: StreamServer,
                           transp: StreamTransport) {.async.} =
          var wstream = newAsyncStreamWriter(transp)
          case btest
          of BoundaryRead:
            await wstream.write(message)
            await wstream.write(boundary)
            await wstream.finish()
            await wstream.closeWait()
            clientRes = true
          of BoundaryDouble:
            await wstream.write(message)
            await wstream.write(boundary)
            await wstream.write(message)
            await wstream.finish()
            await wstream.closeWait()
            clientRes = true
          of BoundarySize:
            var ncmessage = message
            ncmessage.setLen(len(message) - 2)
            await wstream.write(ncmessage)
            await wstream.write(@[0x2D'u8, 0x2D'u8])
            await wstream.finish()
            await wstream.closeWait()
            clientRes = true
          of BoundaryIncomplete:
            var ncmessage = message
            ncmessage.setLen(len(message) - 2)
            await wstream.write(ncmessage)
            await wstream.finish()
            await wstream.closeWait()
            clientRes = true
          of BoundaryEmpty:
            await wstream.write(boundary)
            await wstream.finish()
            await wstream.closeWait()
            clientRes = true

          await transp.closeWait()
          server.stop()
          server.close()

        var res = false
        let flags = {ServerFlags.ReuseAddr, ServerFlags.TcpNoDelay}
        var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                        processClient, flags = flags)
        server.start()
        var conn = await connect(server.localAddress())
        var rstream = newAsyncStreamReader(conn)
        case btest
        of BoundaryRead:
          var rbstream = newBoundedStreamReader(rstream, boundary)
          let response = await rbstream.read()
          if response == message:
            res = true
          await rbstream.closeWait()
        of BoundaryDouble:
          var rbstream = newBoundedStreamReader(rstream, boundary)
          let response1 = await rbstream.read()
          await rbstream.closeWait()
          let response2 = await rstream.read()
          if (response1 == message) and (response2 == message):
            res = true
        of BoundarySize:
          var expectMessage = message
          expectMessage[^2] = 0x2D'u8
          expectMessage[^1] = 0x2D'u8
          var rbstream = newBoundedStreamReader(rstream, uint64(size), boundary)
          let response = await rbstream.read()
          await rbstream.closeWait()
          if (len(response) == size) and response == expectMessage:
            res = true
        of BoundaryIncomplete:
          var rbstream = newBoundedStreamReader(rstream, boundary)
          try:
            let response {.used.} = await rbstream.read()
          except BoundedStreamIncompleteError:
            res = true
          await rbstream.closeWait()
        of BoundaryEmpty:
          var rbstream = newBoundedStreamReader(rstream, boundary)
          let response = await rbstream.read()
          await rbstream.closeWait()
          if len(response) == 0:
            res = true

        await rstream.closeWait()
        await conn.closeWait()
        await server.join()
        return (res and clientRes)

      proc boundedTest(stest: BoundarySizeTest,
                       size: int, cmp: BoundCmp): Future[bool] {.async.} =
        var clientRes = false
        var res = false

        let messagePart = createBigMessage("ABCDEFGHIJKLMNOP",
                                           int(itemSize) div 10)
        var message: seq[byte]
        for i in 0 ..< 10:
          message.add(messagePart)

        proc processClient(server: StreamServer,
                           transp: StreamTransport) {.async.} =
          var wstream = newAsyncStreamWriter(transp)
          var wbstream = newBoundedStreamWriter(wstream, uint64(size),
                                                comparison = cmp)
          case stest
          of SizeReadWrite:
            for i in 0 ..< 10:
              await wbstream.write(messagePart)
            await wbstream.finish()
            await wbstream.closeWait()
            clientRes = true
          of SizeOverflow:
            for i in 0 ..< 10:
              await wbstream.write(messagePart)
            try:
              await wbstream.write(messagePart)
            except BoundedStreamOverflowError:
              clientRes = true
            await wbstream.closeWait()
          of SizeIncomplete:
            for i in 0 ..< 9:
              await wbstream.write(messagePart)
            case cmp
            of BoundCmp.Equal:
              try:
                await wbstream.finish()
              except BoundedStreamIncompleteError:
                clientRes = true
            of BoundCmp.LessOrEqual:
              try:
                await wbstream.finish()
                clientRes = true
              except BoundedStreamIncompleteError:
                discard
            await wbstream.closeWait()
          of SizeEmpty:
            case cmp
            of BoundCmp.Equal:
              try:
                await wbstream.finish()
              except BoundedStreamIncompleteError:
                clientRes = true
            of BoundCmp.LessOrEqual:
              try:
                await wbstream.finish()
                clientRes = true
              except BoundedStreamIncompleteError:
                discard
            await wbstream.closeWait()

          await wstream.closeWait()
          await transp.closeWait()
          server.stop()
          server.close()

        let flags = {ServerFlags.ReuseAddr, ServerFlags.TcpNoDelay}
        var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                        processClient, flags = flags)
        server.start()
        var conn = await connect(server.localAddress())
        var rstream = newAsyncStreamReader(conn)
        var rbstream = newBoundedStreamReader(rstream, uint64(size),
                                              comparison = cmp)
        case stest
        of SizeReadWrite:
          let response = await rbstream.read()
          await rbstream.closeWait()
          if response == message:
            res = true
        of SizeOverflow:
          let response = await rbstream.read()
          await rbstream.closeWait()
          if response == message:
            res = true
        of SizeIncomplete:
          case cmp
          of BoundCmp.Equal:
            try:
              let response {.used.} = await rbstream.read()
            except BoundedStreamIncompleteError:
              res = true
          of BoundCmp.LessOrEqual:
            try:
              let response = await rbstream.read()
              if len(response) == 9 * len(messagePart):
                res = true
            except BoundedStreamIncompleteError:
              res = false
          await rbstream.closeWait()
        of SizeEmpty:
          case cmp
          of BoundCmp.Equal:
            try:
              let response {.used.} = await rbstream.read()
            except BoundedStreamIncompleteError:
              res = true
          of BoundCmp.LessOrEqual:
            try:
              let response = await rbstream.read()
              if len(response) == 0:
                res = true
            except BoundedStreamIncompleteError:
              res = false
          await rbstream.closeWait()

        await rstream.closeWait()
        await conn.closeWait()
        await server.join()
        return (res and clientRes)

      let suffix =
        case itemComp
        of BoundCmp.Equal:
          "== " & $itemSize
        of BoundCmp.LessOrEqual:
          "<= " & $itemSize

      test "BoundedStream(size) reading/writing test [" & suffix & "]":
        check waitFor(boundedTest(SizeReadWrite, itemSize,
                                  itemComp)) == true
      test "BoundedStream(size) overflow test [" & suffix & "]":
        check waitFor(boundedTest(SizeOverflow, itemSize,
                                  itemComp)) == true
      test "BoundedStream(size) incomplete test [" & suffix & "]":
        check waitFor(boundedTest(SizeIncomplete, itemSize,
                                  itemComp)) == true
      test "BoundedStream(size) empty message test [" & suffix & "]":
        check waitFor(boundedTest(SizeEmpty, itemSize,
                                  itemComp)) == true
      test "BoundedStream(boundary) reading test [" & suffix & "]":
        check waitFor(boundaryTest(BoundaryRead, itemSize,
                                   @[0x2D'u8, 0x2D'u8, 0x2D'u8], itemComp))
      test "BoundedStream(boundary) double message test [" & suffix & "]":
        check waitFor(boundaryTest(BoundaryDouble, itemSize,
                                   @[0x2D'u8, 0x2D'u8, 0x2D'u8], itemComp))
      test "BoundedStream(size+boundary) reading size-bound test [" &
           suffix & "]":
        check waitFor(boundaryTest(BoundarySize, itemSize,
                                   @[0x2D'u8, 0x2D'u8, 0x2D'u8], itemComp))
      test "BoundedStream(boundary) reading incomplete test [" &
           suffix & "]":
        check waitFor(boundaryTest(BoundaryIncomplete, itemSize,
                                   @[0x2D'u8, 0x2D'u8, 0x2D'u8], itemComp))
      test "BoundedStream(boundary) empty message test [" &
           suffix & "]":
        check waitFor(boundaryTest(BoundaryEmpty, itemSize,
                                   @[0x2D'u8, 0x2D'u8, 0x2D'u8], itemComp))

  test "BoundedStream read small chunks test":
    proc checkVector(inputstr: seq[byte],
                     writeChunkSize: int,
                     readChunkSize: int): Future[seq[byte]] {.async.} =
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var wstream2 = newBoundedStreamWriter(wstream, uint64(len(inputstr)))
        var data = inputstr
        var offset = 0
        while true:
          if len(data) == offset:
            break
          let toWrite = min(writeChunkSize, len(data) - offset)
          await wstream2.write(addr data[offset], toWrite)
          offset = offset + toWrite
        await wstream2.finish()
        await wstream2.closeWait()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var rstream2 = newBoundedStreamReader(rstream, 1048576,
                                            comparison = BoundCmp.LessOrEqual)
      var res: seq[byte]
      while not(rstream2.atEof()):
        var chunk = await rstream2.read(readChunkSize)
        res.add(chunk)
      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      return res

    proc testSmallChunk(datasize: int, writeChunkSize: int,
                        readChunkSize: int): Future[bool] {.async.} =
      var data = createBigMessage("0123456789ABCDEFGHI", datasize)
      var check = await checkVector(data, writeChunkSize, readChunkSize)
      return (data == check)

    check waitFor(testSmallChunk(4457, 128, 1)) == true
    check waitFor(testSmallChunk(65600, 1024, 17)) == true
    check waitFor(testSmallChunk(262400, 4096, 61)) == true
    check waitFor(testSmallChunk(767309, 4457, 173)) == true

  test "BoundedStream zero-sized streams test":
    proc checkEmptyStreams(): Future[bool] {.async.} =
      var writer1Res = false
      proc serveClient(server: StreamServer,
                       transp: StreamTransport) {.async.} =
        var wstream = newAsyncStreamWriter(transp)
        var wstream2 = newBoundedStreamWriter(wstream, 0'u64)
        await wstream2.finish()
        let res = wstream2.atEof()
        await wstream2.closeWait()
        await wstream.closeWait()
        await transp.closeWait()
        server.stop()
        server.close()
        writer1Res = res

      var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                      serveClient, {ReuseAddr})
      server.start()
      var transp = await connect(server.localAddress())
      var rstream = newAsyncStreamReader(transp)
      var wstream3 = newAsyncStreamWriter(transp)
      var rstream2 = newBoundedStreamReader(rstream, 0'u64)
      var wstream4 = newBoundedStreamWriter(wstream3, 0'u64)

      let readerRes = rstream2.atEof()
      let writer2Res =
        try:
          await wstream4.write("data")
          false
        except BoundedStreamOverflowError:
          true
        except CatchableError:
          false

      await wstream4.closeWait()
      await wstream3.closeWait()
      await rstream2.closeWait()
      await rstream.closeWait()
      await transp.closeWait()
      await server.join()
      return (writer1Res and writer2Res and readerRes)

    check waitFor(checkEmptyStreams()) == true

  test "BoundedStream leaks test":
    checkLeaks()
