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

suite "callSoon() tests suite":
  test "User-defined callback argument test":
    proc test(): bool =
      var soonTest = 0'u

      proc callback(udata: pointer) {.gcsafe.} =
        soonTest = soonTest xor cast[uint](udata)

      callSoon(callback, cast[pointer](0x12345678'u))
      callSoon(callback, cast[pointer](0x23456789'u))
      callSoon(callback, cast[pointer](0x3456789A'u))
      callSoon(callback, cast[pointer](0x456789AB'u))
      callSoon(callback, cast[pointer](0x56789ABC'u))
      callSoon(callback, cast[pointer](0x6789ABCD'u))
      callSoon(callback, cast[pointer](0x789ABCDE'u))
      callSoon(callback, cast[pointer](0x89ABCDEF'u))
      callSoon(callback, cast[pointer](0x9ABCDEF1'u))
      callSoon(callback, cast[pointer](0xABCDEF12'u))
      callSoon(callback, cast[pointer](0xBCDEF123'u))
      callSoon(callback, cast[pointer](0xCDEF1234'u))
      callSoon(callback, cast[pointer](0xDEF12345'u))
      callSoon(callback, cast[pointer](0xEF123456'u))
      callSoon(callback, cast[pointer](0xF1234567'u))
      callSoon(callback, cast[pointer](0x12345678'u))
      ## All callbacks must be processed exactly with 1 poll() call.
      poll()

      var values = [0x12345678'u, 0x23456789'u, 0x3456789A'u, 0x456789AB'u,
                    0x56789ABC'u, 0x6789ABCD'u, 0x789ABCDE'u, 0x89ABCDEF'u,
                    0x9ABCDEF1'u, 0xABCDEF12'u, 0xBCDEF123'u, 0xCDEF1234'u,
                    0xDEF12345'u, 0xEF123456'u, 0xF1234567'u, 0x12345678'u]
      var expect = 0'u
      for item in values:
        expect = expect xor item

      soonTest == expect

    check test() == true

  test "`Asynchronous dead end` #7193 test":
    const CallSoonTests = 5
    proc test() =
      var
        timeoutsTest1 = 0
        timeoutsTest2 = 0
        stopFlag = false

      var callbackproc: proc(udata: pointer) {.gcsafe, raises: [].}
      callbackproc = proc (udata: pointer) {.gcsafe, raises: [].} =
        timeoutsTest2 += 1
        if not(stopFlag):
          callSoon(callbackproc)

      proc testProc() {.async.} =
        for i in 1 .. CallSoonTests:
          await sleepAsync(10.milliseconds)
          timeoutsTest1 += 1

      callSoon(callbackproc)
      waitFor(testProc())
      stopFlag = true
      poll()

      check:
        timeoutsTest1 == CallSoonTests
        timeoutsTest2 > CallSoonTests * 2

    test()

  test "`callSoon() is not working prior getGlobalDispatcher()` #7192 test":
    proc test(): bool =
      var soonTest = 0

      proc testCallback(udata: pointer) =
        soonTest = 987654321

      callSoon(testCallback)
      poll()
      soonTest == 987654321

    check test() == true
