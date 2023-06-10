#
#
#                   AsyncSync
#        (c) Copyright 2018 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements some core synchronization primitives, which
## `asyncdispatch` is really lacking.
import asyncdispatch, deques

type
  AsyncLock* = ref object of RootRef
    ## A primitive lock is a synchronization primitive that is not owned by
    ## a particular coroutine when locked. A primitive lock is in one of two
    ## states, ``locked`` or ``unlocked``.
    ##
    ## When more than one coroutine is blocked in ``acquire()`` waiting for
    ## the state to turn to unlocked, only one coroutine proceeds when a
    ## ``release()`` call resets the state to unlocked; first coroutine which
    ## is blocked in ``acquire()`` is being processed.
    locked: bool
    waiters: Deque[Future[void]]

  AsyncEv* = ref object of RootRef
    ## A primitive event object.
    ##
    ## An event manages a flag that can be set to `true` with the ``fire()``
    ## procedure and reset to `false` with the ``clear()`` procedure.
    ## The ``wait()`` coroutine blocks until the flag is `false`.
    ##
    ## If more than one coroutine blocked in ``wait()`` waiting for event
    ## state to be signaled, when event get fired, then all coroutines
    ## continue proceeds in order, they have entered waiting state.

    flag: bool
    waiters: Deque[Future[void]]

  AsyncQueue*[T] = ref object of RootRef
    ## A queue, useful for coordinating producer and consumer coroutines.
    ##
    ## If ``maxsize`` is less than or equal to zero, the queue size is
    ## infinite. If it is an integer greater than ``0``, then "await put()"
    ## will block when the queue reaches ``maxsize``, until an item is
    ## removed by "await get()".
    getters: Deque[Future[void]]
    putters: Deque[Future[void]]
    queue: Deque[T]
    maxsize: int

  AsyncQueueEmptyError* = object of CatchableError
    ## ``AsyncQueue`` is empty.
  AsyncQueueFullError* = object of CatchableError
    ## ``AsyncQueue`` is full.
  AsyncLockError* = object of CatchableError
    ## ``AsyncLock`` is either locked or unlocked.

proc newAsyncLock*(): AsyncLock =
  ## Creates new asynchronous lock ``AsyncLock``.
  ##
  ## Lock is created in the unlocked state. When the state is unlocked,
  ## ``acquire()`` changes the state to locked and returns immediately.
  ## When the state is locked, ``acquire()`` blocks until a call to
  ## ``release()`` in another coroutine changes it to unlocked.
  ##
  ## The ``release()`` procedure changes the state to unlocked and returns
  ## immediately.

  # Workaround for callSoon() not worked correctly before
  # getGlobalDispatcher() call.
  discard getGlobalDispatcher()
  result = new AsyncLock
  result.waiters = initDeque[Future[void]]()
  result.locked = false

proc acquire*(lock: AsyncLock) {.async.} =
  ## Acquire a lock ``lock``.
  ##
  ## This procedure blocks until the lock ``lock`` is unlocked, then sets it
  ## to locked and returns.
  if not lock.locked:
    lock.locked = true
  else:
    var w = newFuture[void]("asynclock.acquire")
    lock.waiters.addLast(w)
    yield w
    lock.locked = true

proc own*(lock: AsyncLock) =
  ## Acquire a lock ``lock``.
  ##
  ## This procedure not blocks, if ``lock`` is locked, then ``AsyncLockError``
  ## exception would be raised.
  if lock.locked:
    raise newException(AsyncLockError, "AsyncLock is already acquired!")
  lock.locked = true

proc locked*(lock: AsyncLock): bool =
  ## Return `true` if the lock ``lock`` is acquired, `false` otherwise.
  result = lock.locked

proc release*(lock: AsyncLock) =
  ## Release a lock ``lock``.
  ##
  ## When the ``lock`` is locked, reset it to unlocked, and return. If any
  ## other coroutines are blocked waiting for the lock to become unlocked,
  ## allow exactly one of them to proceed.
  var w: Future[void]
  proc wakeup() = w.complete()

  if lock.locked:
    lock.locked = false
    while len(lock.waiters) > 0:
      w = lock.waiters.popFirst()
      if not w.finished:
        callSoon(wakeup)
        break
  else:
    raise newException(AsyncLockError, "AsyncLock is not acquired!")

proc newAsyncEv*(): AsyncEv =
  ## Creates new asyncronous event ``AsyncEv``.
  ##
  ## An event manages a flag that can be set to `true` with the `fire()`
  ## procedure and reset to `false` with the `clear()` procedure.
  ## The `wait()` procedure blocks until the flag is `true`. The flag is
  ## initially `false`.

  # Workaround for callSoon() not worked correctly before
  # getGlobalDispatcher() call.
  discard getGlobalDispatcher()
  result = new AsyncEv
  result.waiters = initDeque[Future[void]]()
  result.flag = false

proc wait*(event: AsyncEv) {.async.} =
  ## Block until the internal flag of ``event`` is `true`.
  ## If the internal flag is `true` on entry, return immediately. Otherwise,
  ## block until another task calls `fire()` to set the flag to `true`,
  ## then return.
  if event.flag:
    discard
  else:
    var w = newFuture[void]("asyncev.wait")
    event.waiters.addLast(w)
    yield w

proc fire*(event: AsyncEv) =
  ## Set the internal flag of ``event`` to `true`. All tasks waiting for it
  ## to become `true` are awakened. Task that call `wait()` once the flag is
  ## `true` will not block at all.
  proc wakeupAll() {.gcsafe.} =
    if len(event.waiters) > 0:
      var w = event.waiters.popFirst()
      if not w.finished:
        w.complete()
      callSoon(wakeupAll)

  if not event.flag:
    event.flag = true
    callSoon(wakeupAll)

proc clear*(event: AsyncEv) =
  ## Reset the internal flag of ``event`` to `false`. Subsequently, tasks
  ## calling `wait()` will block until `fire()` is called to set the internal
  ## flag to `true` again.
  event.flag = false

proc isSet*(event: AsyncEv): bool =
  ## Return `true` if and only if the internal flag of ``event`` is `true`.
  result = event.flag

proc newAsyncQueue*[T](maxsize: int = 0): AsyncQueue[T] =
  ## Creates a new asynchronous queue ``AsyncQueue``.

  # Workaround for callSoon() not worked correctly before
  # getGlobalDispatcher() call.
  discard getGlobalDispatcher()
  result = new AsyncQueue[T]
  result.getters = initDeque[Future[void]]()
  result.putters = initDeque[Future[void]]()
  result.queue = initDeque[T]()
  result.maxsize = maxsize

proc full*[T](aq: AsyncQueue[T]): bool {.inline.} =
  ## Return ``true`` if there are ``maxsize`` items in the queue.
  ##
  ## Note: If the ``aq`` was initialized with ``maxsize = 0`` (default),
  ## then ``full()`` is never ``true``.
  if aq.maxsize <= 0:
    result = false
  else:
    result = len(aq.queue) >= aq.maxsize

proc empty*[T](aq: AsyncQueue[T]): bool {.inline.} =
  ## Return ``true`` if the queue is empty, ``false`` otherwise.
  result = (len(aq.queue) == 0)

proc putNoWait*[T](aq: AsyncQueue[T], item: T) =
  ## Put an item into the queue ``aq`` immediately.
  ##
  ## If queue ``aq`` is full, then ``AsyncQueueFullError`` exception raised
  var w: Future[void]
  proc wakeup() = w.complete()

  if aq.full():
    raise newException(AsyncQueueFullError, "AsyncQueue is full!")
  aq.queue.addLast(item)

  while len(aq.getters) > 0:
    w = aq.getters.popFirst()
    if not w.finished:
      callSoon(wakeup)

proc getNoWait*[T](aq: AsyncQueue[T]): T =
  ## Remove and return ``item`` from the queue immediately.
  ##
  ## If queue ``aq`` is empty, then ``AsyncQueueEmptyError`` exception raised.
  var w: Future[void]
  proc wakeup() = w.complete()

  if aq.empty():
    raise newException(AsyncQueueEmptyError, "AsyncQueue is empty!")
  result = aq.queue.popFirst()
  while len(aq.putters) > 0:
    w = aq.putters.popFirst()
    if not w.finished:
      callSoon(wakeup)

proc put*[T](aq: AsyncQueue[T], item: T) {.async.} =
  ## Put an ``item`` into the queue ``aq``. If the queue is full, wait until
  ## a free slot is available before adding item.
  while aq.full():
    var putter = newFuture[void]("asyncqueue.putter")
    aq.putters.addLast(putter)
    yield putter
  aq.putNoWait(item)

proc get*[T](aq: AsyncQueue[T]): Future[T] {.async.} =
  ## Remove and return an item from the queue ``aq``.
  ##
  ## If queue is empty, wait until an item is available.
  while aq.empty():
    var getter = newFuture[void]("asyncqueue.getter")
    aq.getters.addLast(getter)
    yield getter
  result = aq.getNoWait()

proc len*[T](aq: AsyncQueue[T]): int {.inline.} =
  ## Return the number of elements in ``aq``.
  result = len(aq.queue)

proc size*[T](aq: AsyncQueue[T]): int {.inline.} =
  ## Return the maximum number of elements in ``aq``.
  result = len(aq.maxsize)

when isMainModule:
  # Locks test
  block:
    var test = ""
    var lock = newAsyncLock()

    proc testLock(n: int, lock: AsyncLock) {.async.} =
      await lock.acquire()
      test = test & $n
      lock.release()

    lock.own()
    asyncCheck testLock(0, lock)
    asyncCheck testLock(1, lock)
    asyncCheck testLock(2, lock)
    asyncCheck testLock(3, lock)
    asyncCheck testLock(4, lock)
    asyncCheck testLock(5, lock)
    asyncCheck testLock(6, lock)
    asyncCheck testLock(7, lock)
    asyncCheck testLock(8, lock)
    asyncCheck testLock(9, lock)
    lock.release()
    poll()
    doAssert(test == "0123456789")

  # BotAdminEvents test
  block:
    var test = ""
    var event = newAsyncEv()

    proc testEvent(n: int, ev: AsyncEv) {.async.} =
      await ev.wait()
      test = test & $n

    event.clear()
    asyncCheck testEvent(0, event)
    asyncCheck testEvent(1, event)
    asyncCheck testEvent(2, event)
    asyncCheck testEvent(3, event)
    asyncCheck testEvent(4, event)
    asyncCheck testEvent(5, event)
    asyncCheck testEvent(6, event)
    asyncCheck testEvent(7, event)
    asyncCheck testEvent(8, event)
    asyncCheck testEvent(9, event)
    event.fire()
    poll()
    doAssert(test == "0123456789")

  # Queues test
  block:
    const queueSize = 10
    const testsCount = 1000
    var test = 0

    proc task1(aq: AsyncQueue[int]) {.async.} =
      for i in 1..(testsCount - 1):
        var item = await aq.get()
        test -= item

    proc task2(aq: AsyncQueue[int]) {.async.} =
      for i in 1..testsCount:
        await aq.put(i)
        test += i

    var queue = newAsyncQueue[int](queueSize)
    discard task1(queue) or task2(queue)
    poll()
    doAssert(test == testsCount)
