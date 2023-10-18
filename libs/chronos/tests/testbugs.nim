#                Chronos Test Suite
#            (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import unittest2
import ../chronos

{.used.}

suite "Asynchronous issues test suite":
  const HELLO_PORT = 45679
  const TEST_MSG = "testmsg"
  const MSG_LEN = TEST_MSG.len()
  const TestsCount = 100

  type
    CustomData = ref object
      test: string

  proc udp4DataAvailable(transp: DatagramTransport,
                         remote: TransportAddress) {.async, gcsafe.} =
    var udata = getUserData[CustomData](transp)
    var expect = TEST_MSG
    var data: seq[byte]
    var datalen: int
    transp.peekMessage(data, datalen)
    if udata.test == "CHECK" and datalen == MSG_LEN and
       equalMem(addr data[0], addr expect[0], datalen):
      udata.test = "OK"
    transp.close()

  proc issue6(): Future[bool] {.async.} =
    var myself = initTAddress("127.0.0.1:" & $HELLO_PORT)
    var data = CustomData()
    data.test = "CHECK"
    var dsock4 = newDatagramTransport(udp4DataAvailable, udata = data,
                                      local = myself)
    await dsock4.sendTo(myself, TEST_MSG, MSG_LEN)
    await dsock4.join()
    if data.test == "OK":
      result = true

  proc testWait(): Future[bool] {.async.} =
    for i in 0 ..< TestsCount:
      try:
        await wait(sleepAsync(4.milliseconds), 4.milliseconds)
      except AsyncTimeoutError:
        discard
    result = true

  proc testWithTimeout(): Future[bool] {.async.} =
    for i in 0 ..< TestsCount:
      discard await withTimeout(sleepAsync(4.milliseconds), 4.milliseconds)
    result = true

  proc testMultipleAwait(): Future[bool] {.async.} =
    var promise = newFuture[void]()
    var checkstr = ""

    proc believers(name: string) {.async.} =
      await promise
      checkstr = checkstr & name

    asyncSpawn believers("Foo")
    asyncSpawn believers("Bar")
    asyncSpawn believers("Baz")

    await sleepAsync(100.milliseconds)
    promise.complete()
    await sleepAsync(100.milliseconds)
    result = (checkstr == "FooBarBaz")

  proc testDefer(): Future[bool] {.async.} =
    proc someConnect() {.async.} =
      await sleepAsync(100.milliseconds)

    proc someClose() {.async.} =
      await sleepAsync(100.milliseconds)

    proc testFooFails(): Future[bool] {.async.} =
      await someConnect()
      defer:
        await someClose()
        result = true

    proc testFooSucceed(): Future[bool] {.async.} =
      try:
        await someConnect()
      finally:
        await someClose()
        result = true

    let r1 = await testFooFails()
    let r2 = await testFooSucceed()

    result = r1 and r2

  proc createBigMessage(size: int): seq[byte] =
    var message = "MESSAGE"
    var res = newSeq[byte](size)
    for i in 0 ..< len(result):
      res[i] = byte(message[i mod len(message)])
    res

  proc testIndexError(): Future[bool] {.async.} =
    var server = createStreamServer(initTAddress("127.0.0.1:0"),
                                    flags = {ReuseAddr})
    let messageSize = DefaultStreamBufferSize * 4
    var buffer = newSeq[byte](messageSize)
    let msg = createBigMessage(messageSize)
    let address = server.localAddress()
    let afut = server.accept()
    let outTransp = await connect(address)
    let inpTransp = await afut
    let bytesSent = await outTransp.write(msg)
    check bytesSent == messageSize
    var rfut {.used.} = inpTransp.readExactly(addr buffer[0], messageSize)

    proc waiterProc(udata: pointer) {.raises: [], gcsafe.} =
      try:
        waitFor(sleepAsync(0.milliseconds))
      except CatchableError:
        raiseAssert "Unexpected exception happened"
    let timer {.used.} = setTimer(Moment.fromNow(0.seconds), waiterProc, nil)
    await sleepAsync(100.milliseconds)

    await inpTransp.closeWait()
    await outTransp.closeWait()
    await server.closeWait()
    return true

  test "Issue #6":
    check waitFor(issue6()) == true

  test "Callback-race double completion [wait()] test":
    check waitFor(testWait()) == true

  test "Callback-race double completion [withTimeout()] test":
    check waitFor(testWithTimeout()) == true

  test "Multiple await on single future test [Nim's issue #13889]":
    check waitFor(testMultipleAwait()) == true

  test "Defer for asynchronous procedures test [Nim's issue #13899]":
    check waitFor(testDefer()) == true

  test "IndexError crash test":
    check waitFor(testIndexError()) == true
