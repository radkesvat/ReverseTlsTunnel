#                Chronos Test Suite
#            (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import unittest2
import ../chronos, ../chronos/oserrno

{.used.}

when not defined(windows):
  import posix

suite "Signal handling test suite":
  proc testSignal(signal, value: int): Future[bool] {.async.} =
    var
      signalCounter = 0
      sigFd: SignalHandle
      handlerFut = newFuture[void]("signal.handler")

    proc signalHandler(udata: pointer) {.gcsafe.} =
      signalCounter = cast[int](udata)
      let res = removeSignal2(sigFd)
      if res.isErr():
        handlerFut.fail(newException(ValueError, osErrorMsg(res.error())))
      else:
        handlerFut.complete()

    sigFd =
      block:
        let res = addSignal2(signal, signalHandler, cast[pointer](value))
        if res.isErr():
          raiseAssert osErrorMsg(res.error())
        res.get()

    when defined(windows):
      discard raiseSignal(cint(signal))
    else:
      discard posix.kill(posix.getpid(), cint(signal))

    await handlerFut.wait(5.seconds)
    return signalCounter == value

  proc testWait(signal: int): Future[bool] {.async.} =
    var fut = waitSignal(signal)
    when defined(windows):
      discard raiseSignal(cint(signal))
    else:
      discard posix.kill(posix.getpid(), cint(signal))
    await fut.wait(5.seconds)
    return true

  when defined(windows):
    proc testCtrlC(): Future[bool] {.async, used.} =
      var fut = waitSignal(SIGINT)
      let res = raiseConsoleCtrlSignal()
      if res.isErr():
        raiseAssert osErrorMsg(res.error())
      await fut.wait(5.seconds)
      return true

  test "SIGINT test":
    let res = waitFor testSignal(SIGINT, 31337)
    check res == true

  test "SIGTERM test":
    let res = waitFor testSignal(SIGTERM, 65537)
    check res == true

  test "waitSignal(SIGINT) test":
    let res = waitFor testWait(SIGINT)
    check res == true

  test "waitSignal(SIGTERM) test":
    let res = waitFor testWait(SIGTERM)
    check res == true

  # This test doesn't work well in test suite, because it generates CTRL+C
  # event in Windows console, parent process receives this signal and stops
  # test suite execution.

  # test "Windows [CTRL+C] test":
  #   when defined(windows):
  #     let res = waitFor testCtrlC()
  #     check res == true
  #   else:
  #     skip()
