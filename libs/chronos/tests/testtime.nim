#                Chronos Test Suite
#            (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/os
import unittest2
import ../chronos, ../chronos/timer

{.used.}

static:
  doAssert Moment.high - Moment.low == Duration.high
  doAssert Moment.low.epochSeconds == 0
  doAssert Moment.low.epochNanoSeconds == 0

suite "Asynchronous timers & steps test suite":
  const TimersCount = 10

  proc timeWorker(time: Duration): Future[Duration] {.async.} =
    var st = Moment.now()
    await sleepAsync(time)
    var et = Moment.now()
    result = et - st

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

  proc test(timeout: Duration): Future[Duration] {.async.} =
    var workers = newSeq[Future[Duration]](TimersCount)
    for i in 0..<TimersCount:
      workers[i] = timeWorker(timeout)
    await waitAll(workers)
    var sum: Duration
    for i in 0..<TimersCount:
      var time = workers[i].read()
      sum = sum + time
    result = sum div 10'i64

  proc testTimer(): bool =
    let a = Moment.now()
    waitFor(sleepAsync(1000.milliseconds))
    let b = Moment.now()
    let d = b - a
    result = (d >= 1000.milliseconds) and (d <= 3000.milliseconds)
    if not result:
      echo d

  test "Timer reliability test [" & asyncTimer & "]":
    check testTimer() == true
  test $TimersCount & " timers with 10ms timeout":
    var res = waitFor(test(10.milliseconds))
    check (res >= 10.milliseconds) and (res <= 100.milliseconds)
  test $TimersCount & " timers with 100ms timeout":
    var res = waitFor(test(100.milliseconds))
    check (res >= 100.milliseconds) and (res <= 1000.milliseconds)
  test $TimersCount & " timers with 1000ms timeout":
    var res = waitFor(test(1000.milliseconds))
    check (res >= 1000.milliseconds) and (res <= 5000.milliseconds)
  test "Timer stringification test":
    check:
      $weeks(1) == "1w"
      $days(1) == "1d"
      $hours(1) == "1h"
      $minutes(1) == "1m"
      $seconds(1) == "1s"
      $milliseconds(1) == "1ms"
      $microseconds(1) == "1us"
      $nanoseconds(1) == "1ns"
      $(weeks(1) + days(1)) == "1w1d"
      $(days(1) + hours(1)) == "1d1h"
      $(hours(1) + minutes(1)) == "1h1m"
      $(minutes(1) + seconds(1)) == "1m1s"
      $(seconds(1) + milliseconds(1)) == "1s1ms"
      $(milliseconds(1) + microseconds(1)) == "1ms1us"
      $nanoseconds(1_000_000_000) == "1s"
      $nanoseconds(1_900_000_000) == "1s900ms"
      $nanoseconds(1_000_900_000) == "1s900us"
      $nanoseconds(1_000_000_900) == "1s900ns"
      $nanoseconds(1_800_700_000) == "1s800ms700us"
      $nanoseconds(1_800_000_600) == "1s800ms600ns"

  test "Asynchronous steps test":
    var fut1 = stepsAsync(1)
    var fut2 = stepsAsync(2)
    var fut3 = stepsAsync(3)

    check:
      fut1.completed() == false
      fut2.completed() == false
      fut3.completed() == false

    # We need `fut` because `stepsAsync` do not power `poll()` anymore.
    block:
      var fut {.used.} = sleepAsync(50.milliseconds)
      poll()

    check:
      fut1.completed() == true
      fut2.completed() == false
      fut3.completed() == false

    block:
      var fut {.used.} = sleepAsync(50.milliseconds)
      poll()

    check:
      fut2.completed() == true
      fut3.completed() == false

    block:
      var fut {.used.} = sleepAsync(50.milliseconds)
      poll()

    check:
      fut3.completed() == true
