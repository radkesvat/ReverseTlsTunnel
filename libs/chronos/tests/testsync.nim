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

suite "Asynchronous sync primitives test suite":
  var testLockResult {.threadvar.}: string
  var testEventResult {.threadvar.}: string
  var testQueue1Result = 0
  var testQueue2Result = 0
  var testQueue3Result = 0

  proc testLock(n: int, lock: AsyncLock) {.async.} =
    await lock.acquire()
    testLockResult = testLockResult & $n
    lock.release()

  proc test1(): string =
    var lock = newAsyncLock()
    waitFor lock.acquire()
    discard testLock(0, lock)
    discard testLock(1, lock)
    discard testLock(2, lock)
    discard testLock(3, lock)
    discard testLock(4, lock)
    discard testLock(5, lock)
    discard testLock(6, lock)
    discard testLock(7, lock)
    discard testLock(8, lock)
    discard testLock(9, lock)
    lock.release()
    ## There must be exactly 20 poll() calls
    for i in 0..<20:
      poll()
    result = testLockResult

  proc testFlag(): Future[bool] {.async.} =
    var lock = newAsyncLock()
    var futs: array[4, Future[void]]
    futs[0] = lock.acquire()
    futs[1] = lock.acquire()
    futs[2] = lock.acquire()
    futs[3] = lock.acquire()

    proc checkFlags(b0, b1, b2, b3, b4: bool): bool =
      (lock.locked == b0) and
        (futs[0].finished == b1) and (futs[1].finished == b2) and
        (futs[2].finished == b3) and (futs[3].finished == b4)

    if not(checkFlags(true, true, false, false ,false)):
      return false

    lock.release()
    if not(checkFlags(true, true, false, false, false)):
      return false
    await sleepAsync(10.milliseconds)
    if not(checkFlags(true, true, true, false, false)):
      return false

    lock.release()
    if not(checkFlags(true, true, true, false, false)):
      return false
    await sleepAsync(10.milliseconds)
    if not(checkFlags(true, true, true, true, false)):
      return false

    lock.release()
    if not(checkFlags(true, true, true, true, false)):
      return false
    await sleepAsync(10.milliseconds)
    if not(checkFlags(true, true, true, true, true)):
      return false

    lock.release()
    if not(checkFlags(false, true, true, true, true)):
      return false
    await sleepAsync(10.milliseconds)
    if not(checkFlags(false, true, true, true, true)):
      return false

    return true

  proc testNoAcquiredRelease(): Future[bool] {.async.} =
    var lock = newAsyncLock()
    var res = false
    try:
      lock.release()
    except AsyncLockError:
      res = true
    return res

  proc testDoubleRelease(): Future[bool] {.async.} =
    var lock = newAsyncLock()
    var fut0 = lock.acquire()
    var fut1 = lock.acquire()
    var res = false
    asyncSpawn fut0
    asyncSpawn fut1
    lock.release()
    try:
      lock.release()
    except AsyncLockError:
      res = true
    return res

  proc testBehaviorLock(n1, n2, n3: Duration): Future[seq[int]] {.async.} =
    var stripe: seq[int]

    proc task(lock: AsyncLock, n: int, timeout: Duration) {.async.} =
      await lock.acquire()
      stripe.add(n * 10)
      await sleepAsync(timeout)
      lock.release()
      await lock.acquire()
      stripe.add(n * 10 + 1)
      await sleepAsync(timeout)
      lock.release()

    var lock = newAsyncLock()
    var fut1 = task(lock, 1, n1)
    var fut2 = task(lock, 2, n2)
    var fut3 = task(lock, 3, n3)
    await allFutures(fut1, fut2, fut3)
    result = stripe

  proc testCancelLock(n1, n2, n3: Duration,
                      cancelIndex: int): Future[seq[int]] {.async.} =
    var stripe: seq[int]

    proc task(lock: AsyncLock, n: int, timeout: Duration) {.async.} =
      await lock.acquire()
      stripe.add(n * 10)
      await sleepAsync(timeout)
      lock.release()

      await lock.acquire()
      stripe.add(n * 10 + 1)
      await sleepAsync(timeout)
      lock.release()

    var lock = newAsyncLock()
    var fut1 = task(lock, 1, n1)
    var fut2 = task(lock, 2, n2)
    var fut3 = task(lock, 3, n3)
    if cancelIndex == 2:
      fut2.cancelSoon()
    else:
      fut3.cancelSoon()
    await allFutures(fut1, fut2, fut3)
    result = stripe


  proc testEvent(n: int, ev: AsyncEvent) {.async.} =
    await ev.wait()
    testEventResult = testEventResult & $n

  proc test2(): string =
    var event = newAsyncEvent()
    event.clear()
    discard testEvent(0, event)
    discard testEvent(1, event)
    discard testEvent(2, event)
    discard testEvent(3, event)
    discard testEvent(4, event)
    discard testEvent(5, event)
    discard testEvent(6, event)
    discard testEvent(7, event)
    discard testEvent(8, event)
    discard testEvent(9, event)
    event.fire()
    ## There must be exactly 1 poll() call
    poll()
    result = testEventResult

  proc task1(aq: AsyncQueue[int]) {.async.} =
    var item1 = await aq.get()
    var item2 = await aq.get()
    testQueue1Result = item1 + item2

  proc task2(aq: AsyncQueue[int]) {.async.} =
    await aq.put(1000)
    await aq.put(2000)

  proc test3(): int =
    var queue = newAsyncQueue[int](1)
    discard task1(queue)
    discard task2(queue)
    ## There must be exactly 2 poll() calls
    poll()
    poll()
    result = testQueue1Result

  const testsCount = 1000
  const queueSize = 10

  proc task3(aq: AsyncQueue[int]) {.async.} =
    for i in 1..testsCount:
      var item = await aq.get()
      testQueue2Result -= item

  proc task4(aq: AsyncQueue[int]) {.async.} =
    for i in 1..testsCount:
      await aq.put(i)
      testQueue2Result += i

  proc test4(): int =
    var queue = newAsyncQueue[int](queueSize)
    waitFor(allFutures(task3(queue), task4(queue)))
    result = testQueue2Result

  proc task51(aq: AsyncQueue[int]) {.async.} =
    var item1 = await aq.popFirst()
    var item2 = await aq.popLast()
    var item3 = await aq.get()
    testQueue3Result = item1 - item2 + item3

  proc task52(aq: AsyncQueue[int]) {.async.} =
    await aq.put(100)
    await aq.addLast(1000)
    await aq.addFirst(2000)

  proc test5(): int =
    var queue = newAsyncQueue[int](3)
    discard task51(queue)
    discard task52(queue)
    poll()
    poll()
    result = testQueue3Result

  proc test6(): bool =
    var queue = newAsyncQueue[int]()
    queue.putNoWait(1)
    queue.putNoWait(2)
    queue.putNoWait(3)
    queue.putNoWait(4)
    queue.putNoWait(5)
    queue.clear()
    result = (len(queue) == 0)

  proc test7(): bool =
    var queue = newAsyncQueue[int]()
    var arr1 = @[1, 2, 3, 4, 5]
    var arr2 = @[2, 2, 2, 2, 2]
    var arr3 = @[1, 2, 3, 4, 5]
    queue.putNoWait(1)
    queue.putNoWait(2)
    queue.putNoWait(3)
    queue.putNoWait(4)
    queue.putNoWait(5)
    var index = 0
    for item in queue.items():
      result = (item == arr1[index])
      inc(index)

    if not result: return

    queue[0] = 2

    result = (queue[0] == 2)

    if not result: return

    for item in queue.mitems():
      item = 2

    index = 0
    for item in queue.items():
      result = (item == arr2[index])
      inc(index)

    if not result: return

    queue[0] = 1
    queue[1] = 2
    queue[2] = 3
    queue[3] = 4
    queue[^1] = 5

    for i, item in queue.pairs():
      result = (item == arr3[i])

  proc test8(): bool =
    var q0 = newAsyncQueue[int]()
    q0.putNoWait(1)
    q0.putNoWait(2)
    q0.putNoWait(3)
    q0.putNoWait(4)
    q0.putNoWait(5)
    result = ($q0 == "[1, 2, 3, 4, 5]")
    if not result: return

    var q1 = newAsyncQueue[string]()
    q1.putNoWait("1")
    q1.putNoWait("2")
    q1.putNoWait("3")
    q1.putNoWait("4")
    q1.putNoWait("5")
    result = ($q1 == "[\"1\", \"2\", \"3\", \"4\", \"5\"]")

  proc test9(): bool =
    var q = newAsyncQueue[int]()
    q.putNoWait(1)
    q.putNoWait(2)
    q.putNoWait(3)
    q.putNoWait(4)
    q.putNoWait(5)
    result = (5 in q and not(6 in q))

  test "AsyncLock() behavior test":
    check:
      test1() == "0123456789"
      waitFor(testBehaviorLock(10.milliseconds,
                               20.milliseconds,
                               50.milliseconds)) == @[10, 20, 30, 11, 21, 31]
      waitFor(testBehaviorLock(50.milliseconds,
                               20.milliseconds,
                               10.milliseconds)) == @[10, 20, 30, 11, 21, 31]
  test "AsyncLock() cancellation test":
    check:
      waitFor(testCancelLock(10.milliseconds,
                             20.milliseconds,
                             50.milliseconds, 2)) == @[10, 30, 11, 31]
      waitFor(testCancelLock(50.milliseconds,
                             20.milliseconds,
                             10.milliseconds, 3)) == @[10, 20, 11, 21]
  test "AsyncLock() flag consistency test":
    check waitFor(testFlag()) == true
  test "AsyncLock() double release test":
    check waitFor(testDoubleRelease()) == true
  test "AsyncLock() non-acquired release test":
    check waitFor(testNoAcquiredRelease()) == true
  test "AsyncEvent() behavior test":
    check test2() == "0123456789"
  test "AsyncQueue() behavior test":
    check test3() == 3000
  test "AsyncQueue() many iterations test":
    check test4() == 0
  test "AsyncQueue() addLast/addFirst/popLast/popFirst test":
    check test5() == 1100
  test "AsyncQueue() clear test":
    check test6() == true
  test "AsyncQueue() iterators/assignments test":
    check test7() == true
  test "AsyncQueue() representation test":
    check test8() == true
  test "AsyncQueue() contains test":
    check test9() == true

  test "AsyncEventQueue() behavior test":
    let eventQueue = newAsyncEventQueue[int]()
    let key = eventQueue.register()
    eventQueue.emit(100)
    eventQueue.emit(200)
    eventQueue.emit(300)

    proc test1() =
      let dataFut = eventQueue.waitEvents(key)
      check:
        dataFut.finished() == true
        dataFut.read() == @[100, 200, 300]

    proc test2() =
      let dataFut = eventQueue.waitEvents(key)
      check:
        dataFut.finished() == false
      eventQueue.emit(400)
      eventQueue.emit(500)
      poll()
      check:
        dataFut.finished() == true
        dataFut.read() == @[400, 500]

    test1()
    test2()
    waitFor eventQueue.closeWait()

  test "AsyncEventQueue() concurrency test":
    let eventQueue = newAsyncEventQueue[int]()
    let key0 = eventQueue.register()
    let key1 = eventQueue.register()
    eventQueue.emit(100)
    let key2 = eventQueue.register()
    eventQueue.emit(200)
    eventQueue.emit(300)
    let key3 = eventQueue.register()
    eventQueue.emit(400)
    eventQueue.emit(500)
    eventQueue.emit(600)
    let key4 = eventQueue.register()
    eventQueue.emit(700)
    eventQueue.emit(800)
    eventQueue.emit(900)
    eventQueue.emit(1000)
    let key5 = eventQueue.register()
    let key6 = eventQueue.register()

    let dataFut1 = eventQueue.waitEvents(key1)
    let dataFut2 = eventQueue.waitEvents(key2)
    let dataFut3 = eventQueue.waitEvents(key3)
    let dataFut4 = eventQueue.waitEvents(key4)
    let dataFut5 = eventQueue.waitEvents(key5)
    let dataFut6 = eventQueue.waitEvents(key6)
    check:
      dataFut1.finished() == true
      dataFut1.read() == @[100, 200, 300, 400, 500, 600, 700, 800, 900, 1000]
      dataFut2.finished() == true
      dataFut2.read() == @[200, 300, 400, 500, 600, 700, 800, 900, 1000]
      dataFut3.finished() == true
      dataFut3.read() == @[400, 500, 600, 700, 800, 900, 1000]
      dataFut4.finished() == true
      dataFut4.read() == @[700, 800, 900, 1000]
      dataFut5.finished() == false
      dataFut6.finished() == false

    eventQueue.emit(2000)
    poll()
    let dataFut0 = eventQueue.waitEvents(key0)
    check:
      dataFut5.finished() == true
      dataFut5.read() == @[2000]
      dataFut6.finished() == true
      dataFut6.read() == @[2000]
      dataFut0.finished() == true
      dataFut0.read() == @[100, 200, 300, 400, 500, 600, 700, 800, 900, 1000,
                           2000]

    waitFor eventQueue.closeWait()

  test "AsyncEventQueue() specific number test":
    let eventQueue = newAsyncEventQueue[int]()
    let key = eventQueue.register()

    let dataFut1 = eventQueue.waitEvents(key, 1)
    eventQueue.emit(100)
    eventQueue.emit(200)
    eventQueue.emit(300)
    eventQueue.emit(400)
    check dataFut1.finished() == false
    poll()
    check:
      dataFut1.finished() == true
      dataFut1.read() == @[100]

    let dataFut2 = eventQueue.waitEvents(key, 2)
    check:
      dataFut2.finished() == true
      dataFut2.read() == @[200, 300]

    let dataFut3 = eventQueue.waitEvents(key, 5)
    check dataFut3.finished() == false
    eventQueue.emit(500)
    eventQueue.emit(600)
    eventQueue.emit(700)
    eventQueue.emit(800)
    check dataFut3.finished() == false
    poll()
    check:
      dataFut3.finished() == true
      dataFut3.read() == @[400, 500, 600, 700, 800]

    let dataFut4 = eventQueue.waitEvents(key, -1)
    check dataFut4.finished() == false
    eventQueue.emit(900)
    eventQueue.emit(1000)
    eventQueue.emit(1100)
    eventQueue.emit(1200)
    eventQueue.emit(1300)
    eventQueue.emit(1400)
    eventQueue.emit(1500)
    eventQueue.emit(1600)
    check dataFut4.finished() == false
    poll()
    check:
      dataFut4.finished() == true
      dataFut4.read() == @[900, 1000, 1100, 1200, 1300, 1400, 1500, 1600]

    waitFor eventQueue.closeWait()

  test "AsyncEventQueue() register()/unregister() test":
    var emptySeq: seq[int]
    let eventQueue = newAsyncEventQueue[int]()
    let key1 = eventQueue.register()

    let dataFut1 = eventQueue.waitEvents(key1, 1)
    check dataFut1.finished() == false
    eventQueue.unregister(key1)
    check dataFut1.finished() == false
    poll()
    check:
      dataFut1.finished() == true
      dataFut1.read() == emptySeq

    let key2 = eventQueue.register()
    let dataFut2 = eventQueue.waitEvents(key2, 5)
    check dataFut2.finished() == false
    eventQueue.emit(100)
    eventQueue.emit(200)
    eventQueue.emit(300)
    eventQueue.emit(400)
    eventQueue.emit(500)
    check dataFut2.finished() == false
    eventQueue.unregister(key2)
    poll()
    check:
      dataFut2.finished() == true
      dataFut2.read() == emptySeq

    let key3 = eventQueue.register()
    let dataFut3 = eventQueue.waitEvents(key3, 5)
    check dataFut3.finished() == false
    eventQueue.emit(100)
    eventQueue.emit(200)
    eventQueue.emit(300)
    check dataFut3.finished() == false
    poll()
    eventQueue.unregister(key3)
    eventQueue.emit(400)
    check dataFut3.finished() == false
    poll()
    check:
      dataFut3.finished() == true
      dataFut3.read() == @[100, 200, 300]

    waitFor eventQueue.closeWait()

  test "AsyncEventQueue() garbage collection test":
    let eventQueue = newAsyncEventQueue[int]()
    let key1 = eventQueue.register()
    check len(eventQueue) == 0
    eventQueue.emit(100)
    eventQueue.emit(200)
    eventQueue.emit(300)
    check len(eventQueue) == 3
    let key2 = eventQueue.register()
    eventQueue.emit(400)
    eventQueue.emit(500)
    eventQueue.emit(600)
    eventQueue.emit(700)
    check len(eventQueue) == 7
    let key3 = eventQueue.register()
    eventQueue.emit(800)
    eventQueue.emit(900)
    eventQueue.emit(1000)
    eventQueue.emit(1100)
    eventQueue.emit(1200)
    check len(eventQueue) == 12
    let dataFut1 = eventQueue.waitEvents(key1)
    check:
      dataFut1.finished() == true
      dataFut1.read() == @[100, 200, 300, 400, 500, 600, 700, 800, 900, 1000,
                           1100, 1200]
      len(eventQueue) == 9

    let dataFut3 = eventQueue.waitEvents(key3)
    check:
      dataFut3.finished() == true
      dataFut3.read() == @[800, 900, 1000, 1100, 1200]
      len(eventQueue) == 9

    let dataFut2 = eventQueue.waitEvents(key2)
    check:
      dataFut2.finished() == true
      dataFut2.read() == @[400, 500, 600, 700, 800, 900, 1000, 1100, 1200]
      len(eventQueue) == 0

    waitFor eventQueue.closeWait()

  test "AsyncEventQueue() 1,000,000 of events to 10 clients test":
    proc test() {.async.} =
      let eventQueue = newAsyncEventQueue[int]()
      var keys = @[
        eventQueue.register(), eventQueue.register(),
        eventQueue.register(), eventQueue.register(),
        eventQueue.register(), eventQueue.register(),
        eventQueue.register(), eventQueue.register(),
        eventQueue.register(), eventQueue.register()
      ]

      proc clientTask(queue: AsyncEventQueue[int],
                      key: EventQueueKey): Future[seq[int]] {.async.} =
        var events: seq[int]
        while true:
          let res = await queue.waitEvents(key)
          if len(res) == 0:
            break
          events.add(res)
        queue.unregister(key)
        return events

      var futs = @[
        clientTask(eventQueue, keys[0]), clientTask(eventQueue, keys[1]),
        clientTask(eventQueue, keys[2]), clientTask(eventQueue, keys[3]),
        clientTask(eventQueue, keys[4]), clientTask(eventQueue, keys[5]),
        clientTask(eventQueue, keys[6]), clientTask(eventQueue, keys[7]),
        clientTask(eventQueue, keys[8]), clientTask(eventQueue, keys[9])
      ]

      for i in 1 .. 1_000_000:
        if (i mod 1000) == 0:
          # Give some CPU for clients.
          await sleepAsync(0.milliseconds)
        eventQueue.emit(i)

      await eventQueue.closeWait()

      await allFutures(futs)
      for index in 0 ..< len(futs):
        let fut = futs[index]
        check fut.finished() == true
        let data = fut.read()
        var counter = 1
        for item in data:
          check item == counter
          inc(counter)
        futs[index] = nil

    waitFor test()

  test "AsyncEventQueue() one consumer limits test":
    proc test() {.async.} =
      let eventQueue = newAsyncEventQueue[int](4)
      check len(eventQueue) == 0
      eventQueue.emit(100)
      eventQueue.emit(200)
      eventQueue.emit(300)
      eventQueue.emit(400)
      # There no consumers, so all the items should be discarded
      check len(eventQueue) == 0
      let key1 = eventQueue.register()
      check len(eventQueue) == 0
      eventQueue.emit(500)
      eventQueue.emit(600)
      eventQueue.emit(700)
      eventQueue.emit(800)
      # So exact `limit` number of items added, consumer should receive all of
      # them.
      check len(eventQueue) == 4
      let dataFut1 = eventQueue.waitEvents(key1)
      check:
        dataFut1.finished() == true
        dataFut1.read() == @[500, 600, 700, 800]
        len(eventQueue) == 0

      eventQueue.emit(900)
      eventQueue.emit(1000)
      eventQueue.emit(1100)
      eventQueue.emit(1200)
      check len(eventQueue) == 4
      # Overfilling queue
      eventQueue.emit(1300)
      # Because overfill for single consumer happend, whole queue should become
      # empty.
      check len(eventQueue) == 0
      eventQueue.emit(1400)
      eventQueue.emit(1500)
      eventQueue.emit(1600)
      eventQueue.emit(1700)
      eventQueue.emit(1800)
      check len(eventQueue) == 0
      let errorFut1 = eventQueue.waitEvents(key1)
      check errorFut1.finished() == true
      let checkException =
        try:
          let res {.used.} = await errorFut1
          false
        except AsyncEventQueueFullError:
          true
        except CatchableError:
          false
      check checkException == true
      # There should be no items because consumer was overflowed.
      check len(eventQueue) == 0
      eventQueue.unregister(key1)
      # All items should be garbage collected after unregister.
      check len(eventQueue) == 0
      await eventQueue.closeWait()

    waitFor test()

  test "AsyncEventQueue() many consumers limits test":
    proc test() {.async.} =
      let eventQueue = newAsyncEventQueue[int](4)
      block:
        let key1 = eventQueue.register()
        eventQueue.emit(100)
        check len(eventQueue) == 1
        let key2 = eventQueue.register()
        eventQueue.emit(200)
        check len(eventQueue) == 2
        let key3 = eventQueue.register()
        eventQueue.emit(300)
        check len(eventQueue) == 3
        let key4 = eventQueue.register()
        eventQueue.emit(400)
        check len(eventQueue) == 4
        let key5 = eventQueue.register()
        eventQueue.emit(500)
        # At this point consumer with `key1` is overfilled, so after `emit()`
        # queue length should be decreased by one item.
        # So queue should look like this: [200, 300, 400, 500]
        check len(eventQueue) == 4
        eventQueue.emit(600)
        # At this point consumers with `key2` is overfilled, so after `emit()`
        # queue length should be decreased by one item.
        # So queue should look like this: [300, 400, 500, 600]
        check len(eventQueue) == 4
        eventQueue.emit(700)
        # At this point consumers with `key3` is overfilled, so after `emit()`
        # queue length should be decreased by one item.
        # So queue should look like this: [400, 500, 600, 700]
        check len(eventQueue) == 4
        eventQueue.emit(800)
        # At this point consumers with `key4` is overfilled, so after `emit()`
        # queue length should be decreased by one item.
        # So queue should look like this: [500, 600, 700, 800]
        check len(eventQueue) == 4
        # Consumer with key5 is not overfilled.
        let dataFut5 = eventQueue.waitEvents(key5)
        check:
          dataFut5.finished() == true
          dataFut5.read() == @[500, 600, 700, 800]
        # No more items should be left because all other consumers are overfilled.
        check len(eventQueue) == 0
        eventQueue.unregister(key5)
        check len(eventQueue) == 0

        let dataFut2 = eventQueue.waitEvents(key2)
        check dataFut2.finished() == true
        expect AsyncEventQueueFullError:
          let res {.used.} = dataFut2.read()
        check len(eventQueue) == 0
        eventQueue.unregister(key2)
        check len(eventQueue) == 0

        let dataFut4 = eventQueue.waitEvents(key4)
        check dataFut4.finished() == true
        expect AsyncEventQueueFullError:
          let res {.used.} = dataFut4.read()
        check len(eventQueue) == 0
        eventQueue.unregister(key4)
        check len(eventQueue) == 0

        let dataFut3 = eventQueue.waitEvents(key3)
        check dataFut3.finished() == true
        expect AsyncEventQueueFullError:
          let res {.used.} = dataFut3.read()
        check len(eventQueue) == 0
        eventQueue.unregister(key3)
        check len(eventQueue) == 0

        let dataFut1 = eventQueue.waitEvents(key1)
        check dataFut1.finished() == true
        expect AsyncEventQueueFullError:
          let res {.used.} = dataFut1.read()
        check len(eventQueue) == 0
        eventQueue.unregister(key1)
        check len(eventQueue) == 0

      block:
        let key1 = eventQueue.register()
        eventQueue.emit(100)
        check len(eventQueue) == 1
        let key2 = eventQueue.register()
        eventQueue.emit(200)
        check len(eventQueue) == 2
        let key3 = eventQueue.register()
        eventQueue.emit(300)
        check len(eventQueue) == 3
        let key4 = eventQueue.register()
        eventQueue.emit(400)
        check len(eventQueue) == 4
        let key5 = eventQueue.register()
        eventQueue.emit(500)
        # At this point consumer with `key1` is overfilled, so after `emit()`
        # queue length should be decreased by one item.
        # So queue should look like this: [200, 300, 400, 500]
        check len(eventQueue) == 4
        eventQueue.emit(600)
        # At this point consumer with `key2` is overfilled, so after `emit()`
        # queue length should be decreased by one item.
        # So queue should look like this: [300, 400, 500, 600]
        check len(eventQueue) == 4
        eventQueue.emit(700)
        # At this point consumer with `key3` is overfilled, so after `emit()`
        # queue length should be decreased by one item.
        # So queue should look like this: [400, 500, 600, 700]
        check len(eventQueue) == 4
        eventQueue.emit(800)
        # At this point consumer with `key4` is overfilled, so after `emit()`
        # queue length should be decreased by one item.
        # So queue should look like this: [500, 600, 700, 800]
        check len(eventQueue) == 4
        eventQueue.emit(900)
        # At this point all consumers are overfilled, so after `emit()`
        # queue length should become 0.
        check len(eventQueue) == 0
        eventQueue.emit(1000)
        eventQueue.emit(1100)
        eventQueue.emit(1200)
        eventQueue.emit(1300)
        eventQueue.emit(1400)
        eventQueue.emit(1500)
        eventQueue.emit(1600)
        eventQueue.emit(1700)
        eventQueue.emit(1800)
        eventQueue.emit(1900)
        # No more events should be accepted.
        check len(eventQueue) == 0

        let dataFut1 = eventQueue.waitEvents(key1)
        check dataFut1.finished() == true
        expect AsyncEventQueueFullError:
          let res {.used.} = dataFut1.read()
        check len(eventQueue) == 0
        eventQueue.unregister(key1)
        check len(eventQueue) == 0

        let dataFut2 = eventQueue.waitEvents(key2)
        check dataFut2.finished() == true
        expect AsyncEventQueueFullError:
          let res {.used.} = dataFut2.read()
        check len(eventQueue) == 0
        eventQueue.unregister(key2)
        check len(eventQueue) == 0

        let dataFut3 = eventQueue.waitEvents(key3)
        check dataFut3.finished() == true
        expect AsyncEventQueueFullError:
          let res {.used.} = dataFut3.read()
        check len(eventQueue) == 0
        eventQueue.unregister(key3)
        check len(eventQueue) == 0

        let dataFut4 = eventQueue.waitEvents(key4)
        check dataFut4.finished() == true
        expect AsyncEventQueueFullError:
          let res {.used.} = dataFut4.read()
        check len(eventQueue) == 0
        eventQueue.unregister(key4)
        check len(eventQueue) == 0

        let dataFut5 = eventQueue.waitEvents(key5)
        check dataFut5.finished() == true
        expect AsyncEventQueueFullError:
          let res {.used.} = dataFut5.read()
        check len(eventQueue) == 0
        eventQueue.unregister(key5)
        check len(eventQueue) == 0
      await eventQueue.closeWait()

    waitFor test()

  test "AsyncEventQueue() slow and fast consumer test":
    proc test() {.async.} =
      let eventQueue = newAsyncEventQueue[int](1)
      let
        fastConsumer = eventQueue.register()
        slowConsumer = eventQueue.register()
        slowFut = eventQueue.waitEvents(slowConsumer)

      for i in 0 ..< 1000:
        eventQueue.emit(i)
        let fastData {.used.} = await eventQueue.waitEvents(fastConsumer)

      check len(eventQueue) == 0
      await allFutures(slowFut)
      check len(eventQueue) == 0
      expect AsyncEventQueueFullError:
        let res {.used.} = slowFut.read()

      check len(eventQueue) == 0
      eventQueue.unregister(fastConsumer)
      check len(eventQueue) == 0
      eventQueue.unregister(slowConsumer)
      check len(eventQueue) == 0
      await eventQueue.closeWait()

    waitFor test()
