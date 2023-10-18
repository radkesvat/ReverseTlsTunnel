#                Chronos Test Suite
#            (c) Copyright 2022-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

{.used.}

import unittest2
import ../chronos
import ../chronos/ratelimit

suite "Token Bucket":
  test "Sync test":
    var bucket = TokenBucket.new(1000, 1.milliseconds)
    let
      start = Moment.now()
      fullTime = start + 1.milliseconds
    check:
      bucket.tryConsume(800, start) == true
      bucket.tryConsume(200, start) == true

      # Out of budget
      bucket.tryConsume(100, start) == false
      bucket.tryConsume(800, fullTime) == true
      bucket.tryConsume(200, fullTime) == true

      # Out of budget
      bucket.tryConsume(100, fullTime) == false

  test "Async test":
    var bucket = TokenBucket.new(1000, 1000.milliseconds)
    check: bucket.tryConsume(1000) == true

    var toWait = newSeq[Future[void]]()
    for _ in 0..<15:
      toWait.add(bucket.consume(100))

    let start = Moment.now()
    waitFor(allFutures(toWait))
    let duration = Moment.now() - start

    check: duration in 1400.milliseconds .. 2200.milliseconds

  test "Over budget async":
    var bucket = TokenBucket.new(100, 100.milliseconds)
    # Consume 10* the budget cap
    let beforeStart = Moment.now()
    waitFor(bucket.consume(1000).wait(5.seconds))
    check Moment.now() - beforeStart in 900.milliseconds .. 2200.milliseconds

  test "Sync manual replenish":
    var bucket = TokenBucket.new(1000, 0.seconds)
    let start = Moment.now()
    check:
      bucket.tryConsume(1000, start) == true
      bucket.tryConsume(1000, start) == false
    bucket.replenish(2000)
    check:
      bucket.tryConsume(1000, start) == true
      # replenish is capped to the bucket max
      bucket.tryConsume(1000, start) == false

  test "Async manual replenish":
    var bucket = TokenBucket.new(10 * 150, 0.seconds)
    check:
      bucket.tryConsume(10 * 150) == true
      bucket.tryConsume(1000) == false
    var toWait = newSeq[Future[void]]()
    for _ in 0..<150:
      toWait.add(bucket.consume(10))

    let lastOne = bucket.consume(10)

    # Test cap as well
    bucket.replenish(1000000)
    waitFor(allFutures(toWait).wait(10.milliseconds))

    check: not lastOne.finished()

    bucket.replenish(10)
    waitFor(lastOne.wait(10.milliseconds))

  test "Async cancellation":
    var bucket = TokenBucket.new(100, 0.seconds)
    let
      fut1 = bucket.consume(20)
      futBlocker = bucket.consume(1000)
      fut2 = bucket.consume(50)

    waitFor(fut1.wait(10.milliseconds))
    waitFor(sleepAsync(10.milliseconds))
    check:
      futBlocker.finished == false
      fut2.finished == false

    futBlocker.cancelSoon()
    waitFor(fut2.wait(10.milliseconds))

  test "Very long replenish":
    var bucket = TokenBucket.new(7000, 1.hours)
    let start = Moment.now()
    check bucket.tryConsume(7000, start)
    check bucket.tryConsume(1, start) == false

    # With this setting, it takes 514 milliseconds
    # to tick one. Check that we can eventually
    # consume, even if we update multiple time
    # before that
    var fakeNow = start
    while fakeNow - start < 514.milliseconds:
      check bucket.tryConsume(1, fakeNow) == false
      fakeNow += 30.milliseconds

    check bucket.tryConsume(1, fakeNow) == true

  test "Short replenish":
    skip()
    # TODO (cheatfate): This test was disabled, because it continuosly fails in
    # Github Actions Windows x64 CI when using Nim 1.6.14 version.
    # Unable to reproduce failure locally.

    # var bucket = TokenBucket.new(15000, 1.milliseconds)
    # let start = Moment.now()
    # check bucket.tryConsume(15000, start)
    # check bucket.tryConsume(1, start) == false

    # check bucket.tryConsume(15000, start + 1.milliseconds) == true
