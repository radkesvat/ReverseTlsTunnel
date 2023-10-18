#                Chronos Test Suite
#            (c) Copyright 2023-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[cpuinfo, locks, strutils]
import ../chronos/unittest2/asynctests
import ../chronos/threadsync

{.used.}

type
  ThreadResult = object
    value: int

  ThreadResultPtr = ptr ThreadResult

  LockPtr = ptr Lock

  ThreadArg = object
    signal: ThreadSignalPtr
    retval: ThreadResultPtr
    index: int

  ThreadArg2 = object
    signal1: ThreadSignalPtr
    signal2: ThreadSignalPtr
    retval: ThreadResultPtr

  ThreadArg3 = object
    lock: LockPtr
    signal: ThreadSignalPtr
    retval: ThreadResultPtr
    index: int

  WaitSendKind {.pure.} = enum
    Sync, Async

const
  TestsCount = 1000

suite "Asynchronous multi-threading sync primitives test suite":
  proc setResult(thr: ThreadResultPtr, value: int) =
    thr[].value = value

  proc new(t: typedesc[ThreadResultPtr], value: int = 0): ThreadResultPtr =
    var res = cast[ThreadResultPtr](allocShared0(sizeof(ThreadResult)))
    res[].value = value
    res

  proc free(thr: ThreadResultPtr) =
    doAssert(not(isNil(thr)))
    deallocShared(thr)

  let numProcs = countProcessors() * 2

  template threadSignalTest(sendFlag, waitFlag: WaitSendKind) =
    proc testSyncThread(arg: ThreadArg) {.thread.} =
      let res = waitSync(arg.signal, 1500.milliseconds)
      if res.isErr():
        arg.retval.setResult(1)
      else:
        if res.get():
          arg.retval.setResult(2)
        else:
          arg.retval.setResult(3)

    proc testAsyncThread(arg: ThreadArg) {.thread.} =
      proc testAsyncCode(arg: ThreadArg) {.async.} =
        try:
          await wait(arg.signal).wait(1500.milliseconds)
          arg.retval.setResult(2)
        except AsyncTimeoutError:
          arg.retval.setResult(3)
        except CatchableError:
          arg.retval.setResult(1)

      waitFor testAsyncCode(arg)

    let signal = ThreadSignalPtr.new().tryGet()
    var args: seq[ThreadArg]
    var threads = newSeq[Thread[ThreadArg]](numProcs)
    for i in 0 ..< numProcs:
      let
        res = ThreadResultPtr.new()
        arg = ThreadArg(signal: signal, retval: res, index: i)
      args.add(arg)
      case waitFlag
      of WaitSendKind.Sync:
        createThread(threads[i], testSyncThread, arg)
      of WaitSendKind.Async:
        createThread(threads[i], testAsyncThread, arg)

    await sleepAsync(500.milliseconds)
    case sendFlag
    of WaitSendKind.Sync:
      check signal.fireSync().isOk()
    of WaitSendKind.Async:
      await signal.fire()

    joinThreads(threads)

    var ncheck: array[3, int]
    for item in args:
      if item.retval[].value == 1:
        inc(ncheck[0])
      elif item.retval[].value == 2:
        inc(ncheck[1])
      elif item.retval[].value == 3:
        inc(ncheck[2])
      free(item.retval)
    check:
      signal.close().isOk()
      ncheck[0] == 0
      ncheck[1] == 1
      ncheck[2] == numProcs - 1

  template threadSignalTest2(testsCount: int,
                             sendFlag, waitFlag: WaitSendKind) =
    proc testSyncThread(arg: ThreadArg2) {.thread.} =
      for i in 0 ..< testsCount:
        block:
          let res = waitSync(arg.signal1, 1500.milliseconds)
          if res.isErr():
            arg.retval.setResult(-1)
            return
          if not(res.get()):
            arg.retval.setResult(-2)
            return

        block:
          let res = arg.signal2.fireSync()
          if res.isErr():
            arg.retval.setResult(-3)
            return

        arg.retval.setResult(i + 1)

    proc testAsyncThread(arg: ThreadArg2) {.thread.} =
      proc testAsyncCode(arg: ThreadArg2) {.async.} =
        for i in 0 ..< testsCount:
          try:
            await wait(arg.signal1).wait(1500.milliseconds)
          except AsyncTimeoutError:
            arg.retval.setResult(-2)
            return
          except AsyncError:
            arg.retval.setResult(-1)
            return
          except CatchableError:
            arg.retval.setResult(-3)
            return

          try:
            await arg.signal2.fire()
          except AsyncError:
            arg.retval.setResult(-4)
            return
          except CatchableError:
            arg.retval.setResult(-5)
            return

          arg.retval.setResult(i + 1)

      waitFor testAsyncCode(arg)

    let
      signal1 = ThreadSignalPtr.new().tryGet()
      signal2 = ThreadSignalPtr.new().tryGet()
      retval = ThreadResultPtr.new()
      arg = ThreadArg2(signal1: signal1, signal2: signal2, retval: retval)
    var thread: Thread[ThreadArg2]

    case waitFlag
    of WaitSendKind.Sync:
      createThread(thread, testSyncThread, arg)
    of WaitSendKind.Async:
      createThread(thread, testAsyncThread, arg)

    let start = Moment.now()
    for i in 0 ..< testsCount:
      case sendFlag
      of WaitSendKind.Sync:
        block:
          let res = signal1.fireSync()
          check res.isOk()
        block:
          let res = waitSync(arg.signal2, 1500.milliseconds)
          check:
            res.isOk()
            res.get() == true
      of WaitSendKind.Async:
        await arg.signal1.fire()
        await wait(arg.signal2).wait(1500.milliseconds)
    joinThreads(thread)
    let finish = Moment.now()
    let perf = (float64(nanoseconds(1.seconds)) /
      float64(nanoseconds(finish - start))) * float64(testsCount)
    echo "Switches tested: ", testsCount, ", elapsed time: ", (finish - start),
         ", performance = ", formatFloat(perf, ffDecimal, 4),
         " switches/second"

    check:
      arg.retval[].value == testsCount

  template threadSignalTest3(testsCount: int,
                             sendFlag, waitFlag: WaitSendKind) =
    proc testSyncThread(arg: ThreadArg3) {.thread.} =
      withLock(arg.lock[]):
        let res = waitSync(arg.signal, 10.milliseconds)
        if res.isErr():
          arg.retval.setResult(1)
        else:
          if res.get():
            arg.retval.setResult(2)
          else:
            arg.retval.setResult(3)

    proc testAsyncThread(arg: ThreadArg3) {.thread.} =
      proc testAsyncCode(arg: ThreadArg3) {.async.} =
        withLock(arg.lock[]):
          try:
            await wait(arg.signal).wait(10.milliseconds)
            arg.retval.setResult(2)
          except AsyncTimeoutError:
            arg.retval.setResult(3)
          except CatchableError:
            arg.retval.setResult(1)

      waitFor testAsyncCode(arg)

    let signal = ThreadSignalPtr.new().tryGet()
    var args: seq[ThreadArg3]
    var threads = newSeq[Thread[ThreadArg3]](numProcs)
    var lockPtr = cast[LockPtr](allocShared0(sizeof(Lock)))
    initLock(lockPtr[])
    acquire(lockPtr[])

    for i in 0 ..< numProcs:
      let
        res = ThreadResultPtr.new()
        arg = ThreadArg3(signal: signal, retval: res, index: i, lock: lockPtr)
      args.add(arg)
      case waitFlag
      of WaitSendKind.Sync:
        createThread(threads[i], testSyncThread, arg)
      of WaitSendKind.Async:
        createThread(threads[i], testAsyncThread, arg)

    await sleepAsync(500.milliseconds)
    case sendFlag
    of WaitSendKind.Sync:
      for i in 0 ..< testsCount:
        check signal.fireSync().isOk()
    of WaitSendKind.Async:
      for i in 0 ..< testsCount:
        await signal.fire()

    release(lockPtr[])
    joinThreads(threads)
    deinitLock(lockPtr[])
    deallocShared(lockPtr)

    var ncheck: array[3, int]
    for item in args:
      if item.retval[].value == 1:
        inc(ncheck[0])
      elif item.retval[].value == 2:
        inc(ncheck[1])
      elif item.retval[].value == 3:
        inc(ncheck[2])
      free(item.retval)
    check:
      signal.close().isOk()
      ncheck[0] == 0
      ncheck[1] == 1
      ncheck[2] == numProcs - 1

  template threadSignalTest4(testsCount: int,
                             sendFlag, waitFlag: WaitSendKind) =
    let signal = ThreadSignalPtr.new().tryGet()
    let start = Moment.now()
    for i in 0 ..< testsCount:
      case sendFlag
      of WaitSendKind.Sync:
        check signal.fireSync().isOk()
      of WaitSendKind.Async:
        await signal.fire()

      case waitFlag
      of WaitSendKind.Sync:
        check waitSync(signal).isOk()
      of WaitSendKind.Async:
        await wait(signal)
    let finish = Moment.now()
    let perf = (float64(nanoseconds(1.seconds)) /
      float64(nanoseconds(finish - start))) * float64(testsCount)
    echo "Switches tested: ", testsCount, ", elapsed time: ", (finish - start),
         ", performance = ", formatFloat(perf, ffDecimal, 4),
         " switches/second"

    check:
      signal.close.isOk()

  asyncTest "ThreadSignal: Multiple [" & $numProcs &
            "] threads waiting test [sync -> sync]":
    threadSignalTest(WaitSendKind.Sync, WaitSendKind.Sync)

  asyncTest "ThreadSignal: Multiple [" & $numProcs &
            "] threads waiting test [async -> async]":
    threadSignalTest(WaitSendKind.Async, WaitSendKind.Async)

  asyncTest "ThreadSignal: Multiple [" & $numProcs &
            "] threads waiting test [async -> sync]":
    threadSignalTest(WaitSendKind.Async, WaitSendKind.Sync)

  asyncTest "ThreadSignal: Multiple [" & $numProcs &
            "] threads waiting test [sync -> async]":
    threadSignalTest(WaitSendKind.Sync, WaitSendKind.Async)

  asyncTest "ThreadSignal: Multiple thread switches [" & $TestsCount &
            "] test [sync -> sync]":
    threadSignalTest2(TestsCount, WaitSendKind.Sync, WaitSendKind.Sync)

  asyncTest "ThreadSignal: Multiple thread switches [" & $TestsCount &
            "] test [async -> async]":
    threadSignalTest2(TestsCount, WaitSendKind.Async, WaitSendKind.Async)

  asyncTest "ThreadSignal: Multiple thread switches [" & $TestsCount &
            "] test [sync -> async]":
    threadSignalTest2(TestsCount, WaitSendKind.Sync, WaitSendKind.Async)

  asyncTest "ThreadSignal: Multiple thread switches [" & $TestsCount &
            "] test [async -> sync]":
    threadSignalTest2(TestsCount, WaitSendKind.Async, WaitSendKind.Sync)

  asyncTest "ThreadSignal: Multiple signals [" & $TestsCount &
            "] to multiple threads [" & $numProcs & "] test [sync -> sync]":
    threadSignalTest3(TestsCount, WaitSendKind.Sync, WaitSendKind.Sync)

  asyncTest "ThreadSignal: Multiple signals [" & $TestsCount &
            "] to multiple threads [" & $numProcs & "] test [async -> async]":
    threadSignalTest3(TestsCount, WaitSendKind.Async, WaitSendKind.Async)

  asyncTest "ThreadSignal: Multiple signals [" & $TestsCount &
            "] to multiple threads [" & $numProcs & "] test [sync -> async]":
    threadSignalTest3(TestsCount, WaitSendKind.Sync, WaitSendKind.Async)

  asyncTest "ThreadSignal: Multiple signals [" & $TestsCount &
            "] to multiple threads [" & $numProcs & "] test [async -> sync]":
    threadSignalTest3(TestsCount, WaitSendKind.Async, WaitSendKind.Sync)

  asyncTest "ThreadSignal: Single threaded switches [" & $TestsCount &
            "] test [sync -> sync]":
    threadSignalTest4(TestsCount, WaitSendKind.Sync, WaitSendKind.Sync)

  asyncTest "ThreadSignal: Single threaded switches [" & $TestsCount &
            "] test [sync -> sync]":
    threadSignalTest4(TestsCount, WaitSendKind.Async, WaitSendKind.Async)

  asyncTest "ThreadSignal: Single threaded switches [" & $TestsCount &
            "] test [sync -> async]":
    threadSignalTest4(TestsCount, WaitSendKind.Sync, WaitSendKind.Async)

  asyncTest "ThreadSignal: Single threaded switches [" & $TestsCount &
            "] test [async -> sync]":
    threadSignalTest4(TestsCount, WaitSendKind.Async, WaitSendKind.Sync)
