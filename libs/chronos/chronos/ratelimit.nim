#               Chronos Rate Limiter
#            (c) Copyright 2022-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

{.push raises: [Defect].}

import ../chronos
import timer

export timer

type
  BucketWaiter = object
    future: Future[void]
    value: int
    alreadyConsumed: int

  TokenBucket* = ref object
    budget: int
    budgetCap: int
    lastUpdate: Moment
    fillDuration: Duration
    workFuture: Future[void]
    pendingRequests: seq[BucketWaiter]
    manuallyReplenished: AsyncEvent

proc update(bucket: TokenBucket) =
  if bucket.fillDuration == default(Duration):
    bucket.budget = min(bucket.budgetCap, bucket.budget)
    return

  let
    currentTime = Moment.now()
    timeDelta = currentTime - bucket.lastUpdate
    fillPercent = timeDelta.milliseconds.float / bucket.fillDuration.milliseconds.float
    replenished =
      int(bucket.budgetCap.float * fillPercent)
    deltaFromReplenished =
      int(bucket.fillDuration.milliseconds.float *
      replenished.float / bucket.budgetCap.float)

  bucket.lastUpdate += milliseconds(deltaFromReplenished)
  bucket.budget = min(bucket.budgetCap, bucket.budget + replenished)

proc tryConsume*(bucket: TokenBucket, tokens: int): bool =
  ## If `tokens` are available, consume them,
  ## Otherwhise, return false.

  if bucket.budget >= tokens:
    bucket.budget -= tokens
    return true

  bucket.update()

  if bucket.budget >= tokens:
    bucket.budget -= tokens
    true
  else:
    false

proc worker(bucket: TokenBucket) {.async.} =
  while bucket.pendingRequests.len > 0:
    bucket.manuallyReplenished.clear()
    template waiter: untyped = bucket.pendingRequests[0]

    if bucket.tryConsume(waiter.value):
      waiter.future.complete()
      bucket.pendingRequests.delete(0)
    else:
      waiter.value -= bucket.budget
      waiter.alreadyConsumed += bucket.budget
      bucket.budget = 0

      let eventWaiter = bucket.manuallyReplenished.wait()
      if bucket.fillDuration.milliseconds > 0:
        let
          nextCycleValue = float(min(waiter.value, bucket.budgetCap))
          budgetRatio = nextCycleValue.float / bucket.budgetCap.float
          timeToTarget = int(budgetRatio * bucket.fillDuration.milliseconds.float) + 1
          #TODO this will create a timer for each blocked bucket,
          #which may cause performance issue when creating many
          #buckets
          sleeper = sleepAsync(milliseconds(timeToTarget))
        await sleeper or eventWaiter
        sleeper.cancel()
        eventWaiter.cancel()
      else:
        await eventWaiter

  bucket.workFuture = nil

proc consume*(bucket: TokenBucket, tokens: int): Future[void] =
  ## Wait for `tokens` to be available, and consume them.

  let retFuture = newFuture[void]("TokenBucket.consume")
  if isNil(bucket.workFuture) or bucket.workFuture.finished():
    if bucket.tryConsume(tokens):
      retFuture.complete()
      return retFuture

  bucket.pendingRequests.add(BucketWaiter(future: retFuture, value: tokens))
  if isNil(bucket.workFuture) or bucket.workFuture.finished():
    bucket.workFuture = worker(bucket)

  proc cancellation(udata: pointer) =
    for index in 0..<bucket.pendingRequests.len:
      if bucket.pendingRequests[index].future == retFuture:
        bucket.budget += bucket.pendingRequests[index].alreadyConsumed
        bucket.pendingRequests.delete(index)
        if index == 0:
          bucket.manuallyReplenished.fire()
        break
  retFuture.cancelCallback = cancellation
  return retFuture

proc replenish*(bucket: TokenBucket, tokens: int) =
  ## Add `tokens` to the budget (capped to the bucket capacity)
  bucket.budget += tokens
  bucket.update()
  bucket.manuallyReplenished.fire()

proc new*(
  T: type[TokenBucket],
  budgetCap: int,
  fillDuration: Duration = 1.seconds): T =

  ## Create a TokenBucket
  T(
    budget: budgetCap,
    budgetCap: budgetCap,
    fillDuration: fillDuration,
    lastUpdate: Moment.now(),
    manuallyReplenished: newAsyncEvent()
  )
