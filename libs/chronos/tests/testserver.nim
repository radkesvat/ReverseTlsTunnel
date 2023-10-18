#                Chronos Test Suite
#            (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

import ../chronos/unittest2/asynctests

{.used.}

suite "Server's test suite":
  type
    CustomServer = ref object of StreamServer
      test1: string
      test2: string
      test3: string

    CustomTransport = ref object of StreamTransport
      test: string

    CustomData = ref object
      test: string

  teardown:
    checkLeaks()

  proc serveStreamClient(server: StreamServer,
                         transp: StreamTransport) {.async.} =
    discard

  proc serveCustomStreamClient(server: StreamServer,
                               transp: StreamTransport) {.async.} =
    var cserver = cast[CustomServer](server)
    var ctransp = cast[CustomTransport](transp)
    cserver.test1 = "CONNECTION"
    cserver.test2 = ctransp.test
    cserver.test3 = await transp.readLine()
    var answer = "ANSWER\r\n"
    discard await transp.write(answer)
    transp.close()
    await transp.join()

  proc serveUdataStreamClient(server: StreamServer,
                              transp: StreamTransport) {.async.} =
    var udata = getUserData[CustomData](server)
    var line = await transp.readLine()
    var msg = line & udata.test & "\r\n"
    discard await transp.write(msg)
    transp.close()
    await transp.join()

  proc customServerTransport(server: StreamServer,
                             fd: AsyncFD): StreamTransport =
    var transp = CustomTransport()
    transp.test = "CUSTOM"
    result = cast[StreamTransport](transp)

  asyncTest "Stream Server start/stop test":
    var ta = initTAddress("127.0.0.1:31354")
    var server1 = createStreamServer(ta, serveStreamClient, {ReuseAddr})
    server1.start()
    server1.stop()
    server1.close()
    await server1.join()

    var server2 = createStreamServer(ta, serveStreamClient, {ReuseAddr})
    server2.start()
    server2.stop()
    server2.close()
    await server2.join()

  asyncTest "Stream Server stop without start test":
    var ta = initTAddress("127.0.0.1:0")
    var server1 = createStreamServer(ta, serveStreamClient, {ReuseAddr})
    ta = server1.localAddress()
    server1.stop()
    server1.close()

    await server1.join()
    var server2 = createStreamServer(ta, serveStreamClient, {ReuseAddr})
    server2.stop()
    server2.close()
    await server2.join()

  asyncTest "Stream Server inherited object test":
    var server = CustomServer()
    server.test1 = "TEST"
    var ta = initTAddress("127.0.0.1:0")
    var pserver = createStreamServer(ta, serveCustomStreamClient, {ReuseAddr},
                                     child = server,
                                     init = customServerTransport)
    check:
      pserver == server

    var transp = CustomTransport()
    transp.test = "CLIENT"
    server.start()
    var ptransp = await connect(server.localAddress(), child = transp)
    var etransp = cast[CustomTransport](ptransp)
    doAssert(etransp.test == "CLIENT")
    var msg = "TEST\r\n"
    discard await transp.write(msg)
    var line = await transp.readLine()
    doAssert(len(line) > 0)
    transp.close()
    server.stop()
    server.close()
    await server.join()

    check:
      server.test1 == "CONNECTION"
      server.test2 == "CUSTOM"

  asyncTest "StreamServer[T] test":
    var co = CustomData()
    co.test = "CUSTOMDATA"
    var ta = initTAddress("127.0.0.1:0")
    var server = createStreamServer(ta, serveUdataStreamClient, {ReuseAddr},
                                    udata = co)

    server.start()
    var transp = await connect(server.localAddress())
    var msg = "TEST\r\n"
    discard await transp.write(msg)
    var line = await transp.readLine()
    check:
      line == "TESTCUSTOMDATA"
    transp.close()
    server.stop()
    server.close()
    await server.join()

  asyncTest "Backlog and connect cancellation":
    var ta = initTAddress("127.0.0.1:0")
    var server1 = createStreamServer(ta, serveStreamClient, {ReuseAddr}, backlog = 1)
    ta = server1.localAddress()

    var clients: seq[Future[StreamTransport]]
    for i in 0..<10:
      clients.add(connect(server1.localAddress))

    # Check for leaks in cancellation / connect when server is not accepting
    for c in clients:
      if not c.finished:
        await c.cancelAndWait()
      else:
        # The backlog connection "should" end up here
        try:
          await c.read().closeWait()
        except CatchableError:
          discard

    server1.close()
    await server1.join()
