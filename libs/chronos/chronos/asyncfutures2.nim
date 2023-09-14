#
#                     Chronos
#
#  (c) Copyright 2015 Dominik Picheta
#  (c) Copyright 2018-2023 Status Research & Development GmbH
#
#                Licensed under either of
#    Apache License, version 2.0, (LICENSE-APACHEv2)
#                MIT license (LICENSE-MIT)

import std/sequtils
import stew/base10
import "."/srcloc
export srcloc

when chronosStackTrace:
  when defined(nimHasStacktracesModule):
    import system/stacktraces
  else:
    const
      reraisedFromBegin = -10
      reraisedFromEnd = -100

  type StackTrace = string

const
  LocCreateIndex* = 0
  LocFinishIndex* = 1

template LocCompleteIndex*: untyped {.deprecated: "LocFinishIndex".} =
  LocFinishIndex

when chronosStrictException:
  when (NimMajor, NimMinor) < (1, 4):
    {.pragma: closureIter, raises: [Defect, CatchableError], gcsafe.}
  else:
    {.pragma: closureIter, raises: [CatchableError], gcsafe.}
else:
  {.pragma: closureIter, raises: [Exception], gcsafe.}

type
  FutureState* {.pure.} = enum
    Pending, Completed, Cancelled, Failed

  FutureBase* = ref object of RootObj ## Untyped future.
    location*: array[2, ptr SrcLoc]
    callbacks: seq[AsyncCallback]
    cancelcb*: CallbackFunc
    child*: FutureBase
    state*: FutureState
    error*: ref CatchableError ## Stored exception
    mustCancel*: bool
    closure*: iterator(f: FutureBase): FutureBase {.closureIter.}

    when chronosFutureId:
      id*: uint

    when chronosStackTrace:
      errorStackTrace*: StackTrace
      stackTrace: StackTrace ## For debugging purposes only.

    when chronosFutureTracking:
      next*: FutureBase
      prev*: FutureBase

  Future*[T] = ref object of FutureBase ## Typed future.
    when T isnot void:
      value*: T ## Stored value

  FutureStr*[T] = ref object of Future[T]
    ## Future to hold GC strings
    gcholder*: string

  FutureSeq*[A, B] = ref object of Future[A]
    ## Future to hold GC seqs
    gcholder*: seq[B]

  FutureDefect* = object of Defect
    cause*: FutureBase

  FutureError* = object of CatchableError

  CancelledError* = object of FutureError

  FutureList* = object
    head*: FutureBase
    tail*: FutureBase
    count*: uint

# Backwards compatibility for old FutureState name
template Finished* {.deprecated: "Use Completed instead".} = Completed
template Finished*(T: type FutureState): FutureState {.deprecated: "Use FutureState.Completed instead".} = FutureState.Completed

when chronosFutureId:
  var currentID* {.threadvar.}: uint
else:
  template id*(f: FutureBase): uint =
    cast[uint](addr f[])

when chronosFutureTracking:
  var futureList* {.threadvar.}: FutureList

template setupFutureBase(loc: ptr SrcLoc) =
  new(result)
  result.state = FutureState.Pending
  when chronosStackTrace:
    result.stackTrace = getStackTrace()
  when chronosFutureId:
    currentID.inc()
    result.id = currentID
  result.location[LocCreateIndex] = loc

  when chronosFutureTracking:
    result.next = nil
    result.prev = futureList.tail
    if not(isNil(futureList.tail)):
      futureList.tail.next = result
    futureList.tail = result
    if isNil(futureList.head):
      futureList.head = result
    futureList.count.inc()

proc newFutureImpl[T](loc: ptr SrcLoc): Future[T] =
  setupFutureBase(loc)

proc newFutureSeqImpl[A, B](loc: ptr SrcLoc): FutureSeq[A, B] =
  setupFutureBase(loc)

proc newFutureStrImpl[T](loc: ptr SrcLoc): FutureStr[T] =
  setupFutureBase(loc)

template newFuture*[T](fromProc: static[string] = ""): Future[T] =
  ## Creates a new future.
  ##
  ## Specifying ``fromProc``, which is a string specifying the name of the proc
  ## that this future belongs to, is a good habit as it helps with debugging.
  newFutureImpl[T](getSrcLocation(fromProc))

template newFutureSeq*[A, B](fromProc: static[string] = ""): FutureSeq[A, B] =
  ## Create a new future which can hold/preserve GC sequence until future will
  ## not be completed.
  ##
  ## Specifying ``fromProc``, which is a string specifying the name of the proc
  ## that this future belongs to, is a good habit as it helps with debugging.
  newFutureSeqImpl[A, B](getSrcLocation(fromProc))

template newFutureStr*[T](fromProc: static[string] = ""): FutureStr[T] =
  ## Create a new future which can hold/preserve GC string until future will
  ## not be completed.
  ##
  ## Specifying ``fromProc``, which is a string specifying the name of the proc
  ## that this future belongs to, is a good habit as it helps with debugging.
  newFutureStrImpl[T](getSrcLocation(fromProc))

proc finished*(future: FutureBase): bool {.inline.} =
  ## Determines whether ``future`` has finished, i.e. ``future`` state changed
  ## from state ``Pending`` to one of the states (``Finished``, ``Cancelled``,
  ## ``Failed``).
  (future.state != FutureState.Pending)

proc cancelled*(future: FutureBase): bool {.inline.} =
  ## Determines whether ``future`` has cancelled.
  (future.state == FutureState.Cancelled)

proc failed*(future: FutureBase): bool {.inline.} =
  ## Determines whether ``future`` finished with an error.
  (future.state == FutureState.Failed)

proc completed*(future: FutureBase): bool {.inline.} =
  ## Determines whether ``future`` finished with a value.
  (future.state == FutureState.Completed)

proc done*(future: FutureBase): bool {.deprecated: "Use `completed` instead".} =
  ## This is an alias for ``completed(future)`` procedure.
  completed(future)

when chronosFutureTracking:
  proc futureDestructor(udata: pointer) =
    ## This procedure will be called when Future[T] got completed, cancelled or
    ## failed and all Future[T].callbacks are already scheduled and processed.
    let future = cast[FutureBase](udata)
    if future == futureList.tail: futureList.tail = future.prev
    if future == futureList.head: futureList.head = future.next
    if not(isNil(future.next)): future.next.prev = future.prev
    if not(isNil(future.prev)): future.prev.next = future.next
    futureList.count.dec()

  proc scheduleDestructor(future: FutureBase) {.inline.} =
    callSoon(futureDestructor, cast[pointer](future))

proc checkFinished(future: FutureBase, loc: ptr SrcLoc) =
  ## Checks whether `future` is finished. If it is then raises a
  ## ``FutureDefect``.
  if future.finished():
    var msg = ""
    msg.add("An attempt was made to complete a Future more than once. ")
    msg.add("Details:")
    msg.add("\n  Future ID: " & Base10.toString(future.id))
    msg.add("\n  Creation location:")
    msg.add("\n    " & $future.location[LocCreateIndex])
    msg.add("\n  First completion location:")
    msg.add("\n    " & $future.location[LocFinishIndex])
    msg.add("\n  Second completion location:")
    msg.add("\n    " & $loc)
    when chronosStackTrace:
      msg.add("\n  Stack trace to moment of creation:")
      msg.add("\n" & indent(future.stackTrace.strip(), 4))
      msg.add("\n  Stack trace to moment of secondary completion:")
      msg.add("\n" & indent(getStackTrace().strip(), 4))
    msg.add("\n\n")
    var err = newException(FutureDefect, msg)
    err.cause = future
    raise err
  else:
    future.location[LocFinishIndex] = loc

proc finish(fut: FutureBase, state: FutureState) =
  # We do not perform any checks here, because:
  # 1. `finish()` is a private procedure and `state` is under our control.
  # 2. `fut.state` is checked by `checkFinished()`.
  fut.state = state
  doAssert fut.cancelcb == nil or state != FutureState.Cancelled
  fut.cancelcb = nil # release cancellation callback memory
  for item in fut.callbacks.mitems():
    if not(isNil(item.function)):
      callSoon(item)
    item = default(AsyncCallback) # release memory as early as possible
  fut.callbacks = default(seq[AsyncCallback]) # release seq as well

  when chronosFutureTracking:
    scheduleDestructor(fut)

proc complete[T](future: Future[T], val: T, loc: ptr SrcLoc) =
  if not(future.cancelled()):
    checkFinished(future, loc)
    doAssert(isNil(future.error))
    future.value = val
    future.finish(FutureState.Completed)

template complete*[T](future: Future[T], val: T) =
  ## Completes ``future`` with value ``val``.
  complete(future, val, getSrcLocation())

proc complete(future: Future[void], loc: ptr SrcLoc) =
  if not(future.cancelled()):
    checkFinished(future, loc)
    doAssert(isNil(future.error))
    future.finish(FutureState.Completed)

template complete*(future: Future[void]) =
  ## Completes a void ``future``.
  complete(future, getSrcLocation())

proc fail(future: FutureBase, error: ref CatchableError, loc: ptr SrcLoc) =
  if not(future.cancelled()):
    checkFinished(future, loc)
    future.error = error
    when chronosStackTrace:
      future.errorStackTrace = if getStackTrace(error) == "":
                                 getStackTrace()
                               else:
                                 getStackTrace(error)
    future.finish(FutureState.Failed)

template fail*(future: FutureBase, error: ref CatchableError) =
  ## Completes ``future`` with ``error``.
  fail(future, error, getSrcLocation())

template newCancelledError(): ref CancelledError =
  (ref CancelledError)(msg: "Future operation cancelled!")

proc cancelAndSchedule(future: FutureBase, loc: ptr SrcLoc) =
  if not(future.finished()):
    checkFinished(future, loc)
    future.error = newCancelledError()
    when chronosStackTrace:
      future.errorStackTrace = getStackTrace()
    future.finish(FutureState.Cancelled)

template cancelAndSchedule*(future: FutureBase) =
  cancelAndSchedule(future, getSrcLocation())

proc cancel(future: FutureBase, loc: ptr SrcLoc): bool =
  ## Request that Future ``future`` cancel itself.
  ##
  ## This arranges for a `CancelledError` to be thrown into procedure which
  ## waits for ``future`` on the next cycle through the event loop.
  ## The procedure then has a chance to clean up or even deny the request
  ## using `try/except/finally`.
  ##
  ## This call do not guarantee that the ``future`` will be cancelled: the
  ## exception might be caught and acted upon, delaying cancellation of the
  ## ``future`` or preventing cancellation completely. The ``future`` may also
  ## return value or raise different exception.
  ##
  ## Immediately after this procedure is called, ``future.cancelled()`` will
  ## not return ``true`` (unless the Future was already cancelled).
  if future.finished():
    return false

  if not(isNil(future.child)):
    # If you hit this assertion, you should have used the `CancelledError`
    # mechanism and/or use a regular `addCallback`
    doAssert future.cancelcb.isNil,
      "futures returned from `{.async.}` functions must not use `cancelCallback`"

    if cancel(future.child, getSrcLocation()):
      return true

  else:
    if not(isNil(future.cancelcb)):
      future.cancelcb(cast[pointer](future))
      future.cancelcb = nil
    cancelAndSchedule(future, getSrcLocation())

  future.mustCancel = true
  return true

template cancel*(future: FutureBase) =
  ## Cancel ``future``.
  discard cancel(future, getSrcLocation())

proc clearCallbacks(future: FutureBase) =
  future.callbacks = default(seq[AsyncCallback])

proc addCallback*(future: FutureBase, cb: CallbackFunc, udata: pointer) =
  ## Adds the callbacks proc to be called when the future completes.
  ##
  ## If future has already completed then ``cb`` will be called immediately.
  doAssert(not isNil(cb))
  if future.finished():
    callSoon(cb, udata)
  else:
    future.callbacks.add AsyncCallback(function: cb, udata: udata)

proc addCallback*(future: FutureBase, cb: CallbackFunc) =
  ## Adds the callbacks proc to be called when the future completes.
  ##
  ## If future has already completed then ``cb`` will be called immediately.
  future.addCallback(cb, cast[pointer](future))

proc removeCallback*(future: FutureBase, cb: CallbackFunc,
                     udata: pointer) =
  ## Remove future from list of callbacks - this operation may be slow if there
  ## are many registered callbacks!
  doAssert(not isNil(cb))
  # Make sure to release memory associated with callback, or reference chains
  # may be created!
  future.callbacks.keepItIf:
    it.function != cb or it.udata != udata

proc removeCallback*(future: FutureBase, cb: CallbackFunc) =
  future.removeCallback(cb, cast[pointer](future))

proc `callback=`*(future: FutureBase, cb: CallbackFunc, udata: pointer) =
  ## Clears the list of callbacks and sets the callback proc to be called when
  ## the future completes.
  ##
  ## If future has already completed then ``cb`` will be called immediately.
  ##
  ## It's recommended to use ``addCallback`` or ``then`` instead.
  # ZAH: how about `setLen(1); callbacks[0] = cb`
  future.clearCallbacks
  future.addCallback(cb, udata)

proc `callback=`*(future: FutureBase, cb: CallbackFunc) =
  ## Sets the callback proc to be called when the future completes.
  ##
  ## If future has already completed then ``cb`` will be called immediately.
  `callback=`(future, cb, cast[pointer](future))

proc `cancelCallback=`*(future: FutureBase, cb: CallbackFunc) =
  ## Sets the callback procedure to be called when the future is cancelled.
  ##
  ## This callback will be called immediately as ``future.cancel()`` invoked and
  ## must be set before future is finished.

  doAssert not future.finished(),
    "cancellation callback must be set before finishing the future"
  future.cancelcb = cb

{.push stackTrace: off.}
proc futureContinue*(fut: FutureBase) {.raises: [Defect], gcsafe.}

proc internalContinue(fut: pointer) {.raises: [Defect], gcsafe.} =
  let asFut = cast[FutureBase](fut)
  GC_unref(asFut)
  futureContinue(asFut)

proc futureContinue*(fut: FutureBase) {.raises: [Defect], gcsafe.} =
  # This function is responsible for calling the closure iterator generated by
  # the `{.async.}` transformation either until it has completed its iteration
  # or raised and error / been cancelled.
  #
  # Every call to an `{.async.}` proc is redirected to call this function
  # instead with its original body captured in `fut.closure`.
  var next: FutureBase
  try:
    while true:
      # Call closure to make progress on `fut` until it reaches `yield` (inside
      # `await` typically) or completes / fails / is cancelled
      next = fut.closure(fut)
      if fut.closure.finished(): # Reached the end of the transformed proc
        break

      if next == nil:
        raiseAssert "Async procedure (" & ($fut.location[LocCreateIndex]) &
                    ") yielded `nil`, are you await'ing a `nil` Future?"

      if not next.finished():
        # We cannot make progress on `fut` until `next` has finished - schedule
        # `fut` to continue running when that happens
        GC_ref(fut)
        next.addCallback(CallbackFunc(internalContinue), cast[pointer](fut))

        # return here so that we don't remove the closure below
        return

      # Continue while the yielded future is already finished.
  except CancelledError:
    fut.cancelAndSchedule()
  except CatchableError as exc:
    fut.fail(exc)
  except Exception as exc:
    if exc of Defect:
      raise (ref Defect)(exc)

    fut.fail((ref ValueError)(msg: exc.msg, parent: exc))
  finally:
    next = nil # GC hygiene

  # `futureContinue` will not be called any more for this future so we can
  # clean it up
  fut.closure = nil
  fut.child = nil

{.pop.}

when chronosStackTrace:
  import std/strutils

  template getFilenameProcname(entry: StackTraceEntry): (string, string) =
    when compiles(entry.filenameStr) and compiles(entry.procnameStr):
      # We can't rely on "entry.filename" and "entry.procname" still being valid
      # cstring pointers, because the "string.data" buffers they pointed to might
      # be already garbage collected (this entry being a non-shallow copy,
      # "entry.filename" no longer points to "entry.filenameStr.data", but to the
      # buffer of the original object).
      (entry.filenameStr, entry.procnameStr)
    else:
      ($entry.filename, $entry.procname)

  proc `$`(stackTraceEntries: seq[StackTraceEntry]): string =
    try:
      when defined(nimStackTraceOverride) and declared(addDebuggingInfo):
        let entries = addDebuggingInfo(stackTraceEntries)
      else:
        let entries = stackTraceEntries

      # Find longest filename & line number combo for alignment purposes.
      var longestLeft = 0
      for entry in entries:
        let (filename, procname) = getFilenameProcname(entry)

        if procname == "": continue

        let leftLen = filename.len + len($entry.line)
        if leftLen > longestLeft:
          longestLeft = leftLen

      var indent = 2
      # Format the entries.
      for entry in entries:
        let (filename, procname) = getFilenameProcname(entry)

        if procname == "":
          if entry.line == reraisedFromBegin:
            result.add(spaces(indent) & "#[\n")
            indent.inc(2)
          elif entry.line == reraisedFromEnd:
            indent.dec(2)
            result.add(spaces(indent) & "]#\n")
          continue

        let left = "$#($#)" % [filename, $entry.line]
        result.add((spaces(indent) & "$#$# $#\n") % [
          left,
          spaces(longestLeft - left.len + 2),
          procname
        ])
    except ValueError as exc:
      return exc.msg # Shouldn't actually happen since we set the formatting
                    # string

  proc injectStacktrace(error: ref Exception) =
    const header = "\nAsync traceback:\n"

    var exceptionMsg = error.msg
    if header in exceptionMsg:
      # This is messy: extract the original exception message from the msg
      # containing the async traceback.
      let start = exceptionMsg.find(header)
      exceptionMsg = exceptionMsg[0..<start]

    var newMsg = exceptionMsg & header

    let entries = getStackTraceEntries(error)
    newMsg.add($entries)

    newMsg.add("Exception message: " & exceptionMsg & "\n")

    # # For debugging purposes
    # newMsg.add("Exception type:")
    # for entry in getStackTraceEntries(future.error):
    #   newMsg.add "\n" & $entry
    error.msg = newMsg

proc internalCheckComplete*(fut: FutureBase) {.
     raises: [Defect, CatchableError].} =
  # For internal use only. Used in asyncmacro
  if not(isNil(fut.error)):
    when chronosStackTrace:
      injectStacktrace(fut.error)
    raise fut.error

proc internalRead*[T](fut: Future[T]): T {.inline.} =
  # For internal use only. Used in asyncmacro
  when T isnot void:
    return fut.value

proc read*[T](future: Future[T] ): T {.
     raises: [Defect, CatchableError].} =
  ## Retrieves the value of ``future``. Future must be finished otherwise
  ## this function will fail with a ``ValueError`` exception.
  ##
  ## If the result of the future is an error then that error will be raised.
  if future.finished():
    internalCheckComplete(future)
    internalRead(future)
  else:
    # TODO: Make a custom exception type for this?
    raise newException(ValueError, "Future still in progress.")

proc readError*(future: FutureBase): ref CatchableError {.
     raises: [Defect, ValueError].} =
  ## Retrieves the exception stored in ``future``.
  ##
  ## An ``ValueError`` exception will be thrown if no exception exists
  ## in the specified Future.
  if not(isNil(future.error)):
    return future.error
  else:
    # TODO: Make a custom exception type for this?
    raise newException(ValueError, "No error in future.")

template taskFutureLocation(future: FutureBase): string =
  let loc = future.location[0]
  "[" & (
    if len(loc.procedure) == 0: "[unspecified]" else: $loc.procedure & "()"
    ) & " at " & $loc.file & ":" & $(loc.line) & "]"

template taskErrorMessage(future: FutureBase): string =
  "Asynchronous task " & taskFutureLocation(future) &
  " finished with an exception \"" & $future.error.name &
  "\"!\nMessage: " & future.error.msg &
  "\nStack trace: " & future.error.getStackTrace()
template taskCancelMessage(future: FutureBase): string =
  "Asynchronous task " & taskFutureLocation(future) & " was cancelled!"

proc asyncSpawn*(future: Future[void]) =
  ## Spawns a new concurrent async task.
  ##
  ## Tasks may not raise exceptions or be cancelled - a ``Defect`` will be
  ## raised when this happens.
  ##
  ## This should be used instead of ``discard`` and ``asyncCheck`` when calling
  ## an ``async`` procedure without ``await``, to ensure exceptions in the
  ## returned future are not silently discarded.
  ##
  ## Note, that if passed ``future`` is already finished, it will be checked
  ## and processed immediately.
  doAssert(not isNil(future), "Future is nil")

  proc cb(data: pointer) =
    if future.failed():
      raise newException(FutureDefect, taskErrorMessage(future))
    elif future.cancelled():
      raise newException(FutureDefect, taskCancelMessage(future))

  if not(future.finished()):
    # We adding completion callback only if ``future`` is not finished yet.
    future.addCallback(cb)
  else:
    cb(nil)

proc asyncCheck*[T](future: Future[T]) {.
    deprecated: "Raises Defect on future failure, fix your code and use" &
                " asyncSpawn!".} =
  ## This function used to raise an exception through the `poll` call if
  ## the given future failed - there's no way to handle such exceptions so this
  ## function is now an alias for `asyncSpawn`
  ##
  when T is void:
    asyncSpawn(future)
  else:
    proc cb(data: pointer) =
      if future.failed():
        raise newException(FutureDefect, taskErrorMessage(future))
      elif future.cancelled():
        raise newException(FutureDefect, taskCancelMessage(future))

    if not(future.finished()):
      # We adding completion callback only if ``future`` is not finished yet.
      future.addCallback(cb)
    else:
      cb(nil)

proc asyncDiscard*[T](future: Future[T]) {.
    deprecated: "Use asyncSpawn or `discard await`".} = discard
  ## `asyncDiscard` will discard the outcome of the operation - unlike `discard`
  ## it also throws away exceptions! Use `asyncSpawn` if you're sure your
  ## code doesn't raise exceptions, or `discard await` to ignore successful
  ## outcomes

proc `and`*[T, Y](fut1: Future[T], fut2: Future[Y]): Future[void] {.
  deprecated: "Use allFutures[T](varargs[Future[T]])".} =
  ## Returns a future which will complete once both ``fut1`` and ``fut2``
  ## finish.
  ##
  ## If cancelled, ``fut1`` and ``fut2`` futures WILL NOT BE cancelled.
  var retFuture = newFuture[void]("chronos.`and`")
  proc cb(data: pointer) =
    if not(retFuture.finished()):
      if fut1.finished() and fut2.finished():
        if cast[pointer](fut1) == data:
          if fut1.failed():
            retFuture.fail(fut1.error)
          else:
            retFuture.complete()
        else:
          if fut2.failed():
            retFuture.fail(fut2.error)
          else:
            retFuture.complete()
  fut1.callback = cb
  fut2.callback = cb

  proc cancellation(udata: pointer) =
    # On cancel we remove all our callbacks only.
    if not(fut1.finished()):
      fut1.removeCallback(cb)
    if not(fut2.finished()):
      fut2.removeCallback(cb)

  retFuture.cancelCallback = cancellation
  return retFuture

proc `or`*[T, Y](fut1: Future[T], fut2: Future[Y]): Future[void] =
  ## Returns a future which will complete once either ``fut1`` or ``fut2``
  ## finish.
  ##
  ## If ``fut1`` or ``fut2`` future is failed, the result future will also be
  ## failed with an error stored in ``fut1`` or ``fut2`` respectively.
  ##
  ## If both ``fut1`` and ``fut2`` future are completed or failed, the result
  ## future will depend on the state of ``fut1`` future. So if ``fut1`` future
  ## is failed, the result future will also be failed, if ``fut1`` future is
  ## completed, the result future will also be completed.
  ##
  ## If cancelled, ``fut1`` and ``fut2`` futures WILL NOT BE cancelled.
  var retFuture = newFuture[void]("chronos.or")
  var cb: proc(udata: pointer) {.gcsafe, raises: [Defect].}
  cb = proc(udata: pointer) {.gcsafe, raises: [Defect].} =
    if not(retFuture.finished()):
      var fut = cast[FutureBase](udata)
      if cast[pointer](fut1) == udata:
        fut2.removeCallback(cb)
      else:
        fut1.removeCallback(cb)
      if fut.failed():
        retFuture.fail(fut.error)
      else:
        retFuture.complete()

  proc cancellation(udata: pointer) =
    # On cancel we remove all our callbacks only.
    if not(fut1.finished()):
      fut1.removeCallback(cb)
    if not(fut2.finished()):
      fut2.removeCallback(cb)

  if fut1.finished():
    if fut1.failed():
      retFuture.fail(fut1.error)
    else:
      retFuture.complete()
    return retFuture

  if fut2.finished():
    if fut2.failed():
      retFuture.fail(fut2.error)
    else:
      retFuture.complete()
    return retFuture

  fut1.addCallback(cb)
  fut2.addCallback(cb)

  retFuture.cancelCallback = cancellation
  return retFuture

proc all*[T](futs: varargs[Future[T]]): auto {.
  deprecated: "Use allFutures(varargs[Future[T]])".} =
  ## Returns a future which will complete once all futures in ``futs`` finish.
  ## If the argument is empty, the returned future completes immediately.
  ##
  ## If the awaited futures are not ``Future[void]``, the returned future
  ## will hold the values of all awaited futures in a sequence.
  ##
  ## If the awaited futures *are* ``Future[void]``, this proc returns
  ## ``Future[void]``.
  ##
  ## Note, that if one of the futures in ``futs`` will fail, result of ``all()``
  ## will also be failed with error from failed future.
  ##
  ## TODO: This procedure has bug on handling cancelled futures from ``futs``.
  ## So if future from ``futs`` list become cancelled, what must be returned?
  ## You can't cancel result ``retFuture`` because in such way infinite
  ## recursion will happen.
  let totalFutures = len(futs)
  var completedFutures = 0

  # Because we can't capture varargs[T] in closures we need to create copy.
  var nfuts = @futs

  when T is void:
    var retFuture = newFuture[void]("chronos.all(void)")
    proc cb(udata: pointer) =
      if not(retFuture.finished()):
        inc(completedFutures)
        if completedFutures == totalFutures:
          for nfut in nfuts:
            if nfut.failed():
              retFuture.fail(nfut.error)
              break
          if not(retFuture.failed()):
            retFuture.complete()

    for fut in nfuts:
      fut.addCallback(cb)

    if len(nfuts) == 0:
      retFuture.complete()

    return retFuture
  else:
    var retFuture = newFuture[seq[T]]("chronos.all(T)")
    var retValues = newSeq[T](totalFutures)

    proc cb(udata: pointer) =
      if not(retFuture.finished()):
        inc(completedFutures)
        if completedFutures == totalFutures:
          for k, nfut in nfuts:
            if nfut.failed():
              retFuture.fail(nfut.error)
              break
            else:
              retValues[k] = nfut.value
          if not(retFuture.failed()):
            retFuture.complete(retValues)

    for fut in nfuts:
      fut.addCallback(cb)

    if len(nfuts) == 0:
      retFuture.complete(retValues)

    return retFuture

proc oneIndex*[T](futs: varargs[Future[T]]): Future[int] {.
  deprecated: "Use one[T](varargs[Future[T]])".} =
  ## Returns a future which will complete once one of the futures in ``futs``
  ## complete.
  ##
  ## If the argument is empty, the returned future FAILS immediately.
  ##
  ## Returned future will hold index of completed/failed future in ``futs``
  ## argument.
  var nfuts = @futs
  var retFuture = newFuture[int]("chronos.oneIndex(T)")

  proc cb(udata: pointer) =
    var res = -1
    if not(retFuture.finished()):
      var rfut = cast[FutureBase](udata)
      for i in 0..<len(nfuts):
        if cast[FutureBase](nfuts[i]) != rfut:
          nfuts[i].removeCallback(cb)
        else:
          res = i
      retFuture.complete(res)

  for fut in nfuts:
    fut.addCallback(cb)

  if len(nfuts) == 0:
    retFuture.fail(newException(ValueError, "Empty Future[T] list"))

  return retFuture

proc oneValue*[T](futs: varargs[Future[T]]): Future[T] {.
  deprecated: "Use one[T](varargs[Future[T]])".} =
  ## Returns a future which will finish once one of the futures in ``futs``
  ## finish.
  ##
  ## If the argument is empty, returned future FAILS immediately.
  ##
  ## Returned future will hold value of completed ``futs`` future, or error
  ## if future was failed.
  var nfuts = @futs
  var retFuture = newFuture[T]("chronos.oneValue(T)")

  proc cb(udata: pointer) =
    var resFut: Future[T]
    if not(retFuture.finished()):
      var rfut = cast[FutureBase](udata)
      for i in 0..<len(nfuts):
        if cast[FutureBase](nfuts[i]) != rfut:
          nfuts[i].removeCallback(cb)
        else:
          resFut = nfuts[i]
      if resFut.failed():
        retFuture.fail(resFut.error)
      else:
        when T is void:
          retFuture.complete()
        else:
          retFuture.complete(resFut.read())

  for fut in nfuts:
    fut.addCallback(cb)

  if len(nfuts) == 0:
    retFuture.fail(newException(ValueError, "Empty Future[T] list"))

  return retFuture

proc cancelAndWait*(fut: FutureBase): Future[void] =
  ## Initiate cancellation process for Future ``fut`` and wait until ``fut`` is
  ## done e.g. changes its state (become completed, failed or cancelled).
  ##
  ## If ``fut`` is already finished (completed, failed or cancelled) result
  ## Future[void] object will be returned complete.
  var retFuture = newFuture[void]("chronos.cancelAndWait(T)")
  proc continuation(udata: pointer) =
    if not(retFuture.finished()):
      retFuture.complete()
  proc cancellation(udata: pointer) =
    if not(fut.finished()):
      fut.removeCallback(continuation)
  if fut.finished():
    retFuture.complete()
  else:
    fut.addCallback(continuation)
    retFuture.cancelCallback = cancellation
    # Initiate cancellation process.
    fut.cancel()
  return retFuture

proc allFutures*(futs: varargs[FutureBase]): Future[void] =
  ## Returns a future which will complete only when all futures in ``futs``
  ## will be completed, failed or canceled.
  ##
  ## If the argument is empty, the returned future COMPLETES immediately.
  ##
  ## On cancel all the awaited futures ``futs`` WILL NOT BE cancelled.
  var retFuture = newFuture[void]("chronos.allFutures()")
  let totalFutures = len(futs)
  var finishedFutures = 0

  # Because we can't capture varargs[T] in closures we need to create copy.
  var nfuts = @futs

  proc cb(udata: pointer) =
    if not(retFuture.finished()):
      inc(finishedFutures)
      if finishedFutures == totalFutures:
        retFuture.complete()

  proc cancellation(udata: pointer) =
    # On cancel we remove all our callbacks only.
    for i in 0..<len(nfuts):
      if not(nfuts[i].finished()):
        nfuts[i].removeCallback(cb)

  for fut in nfuts:
    if not(fut.finished()):
      fut.addCallback(cb)
    else:
      inc(finishedFutures)

  retFuture.cancelCallback = cancellation
  if len(nfuts) == 0 or len(nfuts) == finishedFutures:
    retFuture.complete()

  return retFuture

proc allFutures*[T](futs: varargs[Future[T]]): Future[void] =
  ## Returns a future which will complete only when all futures in ``futs``
  ## will be completed, failed or canceled.
  ##
  ## If the argument is empty, the returned future COMPLETES immediately.
  ##
  ## On cancel all the awaited futures ``futs`` WILL NOT BE cancelled.
  # Because we can't capture varargs[T] in closures we need to create copy.
  var nfuts: seq[FutureBase]
  for future in futs:
    nfuts.add(future)
  allFutures(nfuts)

proc allFinished*[T](futs: varargs[Future[T]]): Future[seq[Future[T]]] =
  ## Returns a future which will complete only when all futures in ``futs``
  ## will be completed, failed or canceled.
  ##
  ## Returned sequence will hold all the Future[T] objects passed to
  ## ``allFinished`` with the order preserved.
  ##
  ## If the argument is empty, the returned future COMPLETES immediately.
  ##
  ## On cancel all the awaited futures ``futs`` WILL NOT BE cancelled.
  var retFuture = newFuture[seq[Future[T]]]("chronos.allFinished()")
  let totalFutures = len(futs)
  var finishedFutures = 0

  var nfuts = @futs

  proc cb(udata: pointer) =
    if not(retFuture.finished()):
      inc(finishedFutures)
      if finishedFutures == totalFutures:
        retFuture.complete(nfuts)

  proc cancellation(udata: pointer) =
    # On cancel we remove all our callbacks only.
    for fut in nfuts.mitems():
      if not(fut.finished()):
        fut.removeCallback(cb)

  for fut in nfuts:
    if not(fut.finished()):
      fut.addCallback(cb)
    else:
      inc(finishedFutures)

  retFuture.cancelCallback = cancellation
  if len(nfuts) == 0 or len(nfuts) == finishedFutures:
    retFuture.complete(nfuts)

  return retFuture

proc one*[T](futs: varargs[Future[T]]): Future[Future[T]] =
  ## Returns a future which will complete and return completed Future[T] inside,
  ## when one of the futures in ``futs`` will be completed, failed or canceled.
  ##
  ## If the argument is empty, the returned future FAILS immediately.
  ##
  ## On success returned Future will hold finished Future[T].
  ##
  ## On cancel futures in ``futs`` WILL NOT BE cancelled.
  var retFuture = newFuture[Future[T]]("chronos.one()")

  if len(futs) == 0:
    retFuture.fail(newException(ValueError, "Empty Future[T] list"))
    return retFuture

  # If one of the Future[T] already finished we return it as result
  for fut in futs:
    if fut.finished():
      retFuture.complete(fut)
      return retFuture

  # Because we can't capture varargs[T] in closures we need to create copy.
  var nfuts = @futs

  var cb: proc(udata: pointer) {.gcsafe, raises: [Defect].}
  cb = proc(udata: pointer) {.gcsafe, raises: [Defect].} =
    if not(retFuture.finished()):
      var res: Future[T]
      var rfut = cast[FutureBase](udata)
      for i in 0..<len(nfuts):
        if cast[FutureBase](nfuts[i]) != rfut:
          nfuts[i].removeCallback(cb)
        else:
          res = nfuts[i]
      retFuture.complete(res)

  proc cancellation(udata: pointer) =
    # On cancel we remove all our callbacks only.
    for i in 0..<len(nfuts):
      if not(nfuts[i].finished()):
        nfuts[i].removeCallback(cb)

  for fut in nfuts:
    fut.addCallback(cb)

  retFuture.cancelCallback = cancellation
  return retFuture

proc race*(futs: varargs[FutureBase]): Future[FutureBase] =
  ## Returns a future which will complete and return completed FutureBase,
  ## when one of the futures in ``futs`` will be completed, failed or canceled.
  ##
  ## If the argument is empty, the returned future FAILS immediately.
  ##
  ## On success returned Future will hold finished FutureBase.
  ##
  ## On cancel futures in ``futs`` WILL NOT BE cancelled.
  let retFuture = newFuture[FutureBase]("chronos.race()")

  if len(futs) == 0:
    retFuture.fail(newException(ValueError, "Empty Future[T] list"))
    return retFuture

  # If one of the Future[T] already finished we return it as result
  for fut in futs:
    if fut.finished():
      retFuture.complete(fut)
      return retFuture

  # Because we can't capture varargs[T] in closures we need to create copy.
  var nfuts = @futs

  var cb: proc(udata: pointer) {.gcsafe, raises: [Defect].}
  cb = proc(udata: pointer) {.gcsafe, raises: [Defect].} =
    if not(retFuture.finished()):
      var res: FutureBase
      var rfut = cast[FutureBase](udata)
      for i in 0..<len(nfuts):
        if nfuts[i] != rfut:
          nfuts[i].removeCallback(cb)
        else:
          res = nfuts[i]
      retFuture.complete(res)

  proc cancellation(udata: pointer) =
    # On cancel we remove all our callbacks only.
    for i in 0..<len(nfuts):
      if not(nfuts[i].finished()):
        nfuts[i].removeCallback(cb)

  for fut in nfuts:
    fut.addCallback(cb, cast[pointer](fut))

  retFuture.cancelCallback = cancellation

  return retFuture
