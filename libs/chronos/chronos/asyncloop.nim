#
#                     Chronos
#
#           (c) Copyright 2015 Dominik Picheta
#  (c) Copyright 2018-Present Status Research & Development GmbH
#
#                Licensed under either of
#    Apache License, version 2.0, (LICENSE-APACHEv2)
#                MIT license (LICENSE-MIT)

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
  {.pragma: callbackFunc, stdcall, gcsafe, raises: [Defect].}
else:
  {.push raises: [].}
  {.pragma: callbackFunc, stdcall, gcsafe, raises: [].}

from nativesockets import Port
import std/[tables, strutils, heapqueue, deques]
import stew/results
import "."/[config, osdefs, oserrno, osutils, timer]

export Port
export timer, results

#{.injectStmt: newGcInvariant().}

## Chronos
## *************
##
## This module implements asynchronous IO. This includes a dispatcher,
## a ``Future`` type implementation, and an ``async`` macro which allows
## asynchronous code to be written in a synchronous style with the ``await``
## keyword.
##
## The dispatcher acts as a kind of event loop. You must call ``poll`` on it
## (or a function which does so for you such as ``waitFor`` or ``runForever``)
## in order to poll for any outstanding events. The underlying implementation
## is based on epoll on Linux, IO Completion Ports on Windows and select on
## other operating systems.
##
## The ``poll`` function will not, on its own, return any events. Instead
## an appropriate ``Future`` object will be completed. A ``Future`` is a
## type which holds a value which is not yet available, but which *may* be
## available in the future. You can check whether a future is finished
## by using the ``finished`` function. When a future is finished it means that
## either the value that it holds is now available or it holds an error instead.
## The latter situation occurs when the operation to complete a future fails
## with an exception. You can distinguish between the two situations with the
## ``failed`` function.
##
## Future objects can also store a callback procedure which will be called
## automatically once the future completes.
##
## Futures therefore can be thought of as an implementation of the proactor
## pattern. In this
## pattern you make a request for an action, and once that action is fulfilled
## a future is completed with the result of that action. Requests can be
## made by calling the appropriate functions. For example: calling the ``recv``
## function will create a request for some data to be read from a socket. The
## future which the ``recv`` function returns will then complete once the
## requested amount of data is read **or** an exception occurs.
##
## Code to read some data from a socket may look something like this:
##
##   .. code-block::nim
##      var future = socket.recv(100)
##      future.addCallback(
##        proc () =
##          echo(future.read)
##      )
##
## All asynchronous functions returning a ``Future`` will not block. They
## will not however return immediately. An asynchronous function will have
## code which will be executed before an asynchronous request is made, in most
## cases this code sets up the request.
##
## In the above example, the ``recv`` function will return a brand new
## ``Future`` instance once the request for data to be read from the socket
## is made. This ``Future`` instance will complete once the requested amount
## of data is read, in this case it is 100 bytes. The second line sets a
## callback on this future which will be called once the future completes.
## All the callback does is write the data stored in the future to ``stdout``.
## The ``read`` function is used for this and it checks whether the future
## completes with an error for you (if it did it will simply raise the
## error), if there is no error however it returns the value of the future.
##
## Asynchronous procedures
## -----------------------
##
## Asynchronous procedures remove the pain of working with callbacks. They do
## this by allowing you to write asynchronous code the same way as you would
## write synchronous code.
##
## An asynchronous procedure is marked using the ``{.async.}`` pragma.
## When marking a procedure with the ``{.async.}`` pragma it must have a
## ``Future[T]`` return type or no return type at all. If you do not specify
## a return type then ``Future[void]`` is assumed.
##
## Inside asynchronous procedures ``await`` can be used to call any
## procedures which return a
## ``Future``; this includes asynchronous procedures. When a procedure is
## "awaited", the asynchronous procedure it is awaited in will
## suspend its execution
## until the awaited procedure's Future completes. At which point the
## asynchronous procedure will resume its execution. During the period
## when an asynchronous procedure is suspended other asynchronous procedures
## will be run by the dispatcher.
##
## The ``await`` call may be used in many contexts. It can be used on the right
## hand side of a variable declaration: ``var data = await socket.recv(100)``,
## in which case the variable will be set to the value of the future
## automatically. It can be used to await a ``Future`` object, and it can
## be used to await a procedure returning a ``Future[void]``:
## ``await socket.send("foobar")``.
##
## If an awaited future completes with an error, then ``await`` will re-raise
## this error.
##
## Handling Exceptions
## -------------------
##
## The ``async`` procedures also offer support for the try statement.
##
##    .. code-block:: Nim
##      try:
##        let data = await sock.recv(100)
##        echo("Received ", data)
##      except CancelledError as exc:
##        # Handle exc
##
## Discarding futures
## ------------------
##
## Futures should **never** be discarded. This is because they may contain
## errors. If you do not care for the result of a Future then you should
## use the ``asyncSpawn`` procedure instead of the ``discard`` keyword.
## ``asyncSpawn`` will transform any exception thrown by the called procedure
## to a Defect
##
## Limitations/Bugs
## ----------------
##
## * The effect system (``raises: []``) does not work with async procedures.

# TODO: Check if yielded future is nil and throw a more meaningful exception

const
  MaxEventsCount* = 64

when defined(windows):
  import std/[sets, hashes]
elif defined(macosx) or defined(freebsd) or defined(netbsd) or
     defined(openbsd) or defined(dragonfly) or defined(macos) or
     defined(linux) or defined(android) or defined(solaris):
  import "."/selectors2
  export SIGHUP, SIGINT, SIGQUIT, SIGILL, SIGTRAP, SIGABRT,
         SIGBUS, SIGFPE, SIGKILL, SIGUSR1, SIGSEGV, SIGUSR2,
         SIGPIPE, SIGALRM, SIGTERM, SIGPIPE
  export oserrno

type
  CallbackFunc* = proc (arg: pointer) {.gcsafe, raises: [Defect].}

  AsyncCallback* = object
    function*: CallbackFunc
    udata*: pointer

  AsyncError* = object of CatchableError
    ## Generic async exception
  AsyncTimeoutError* = object of AsyncError
    ## Timeout exception

  TimerCallback* = ref object
    finishAt*: Moment
    function*: AsyncCallback

  TrackerBase* = ref object of RootRef
    id*: string
    dump*: proc(): string {.gcsafe, raises: [Defect].}
    isLeaked*: proc(): bool {.gcsafe, raises: [Defect].}

  PDispatcherBase = ref object of RootRef
    timers*: HeapQueue[TimerCallback]
    callbacks*: Deque[AsyncCallback]
    idlers*: Deque[AsyncCallback]
    trackers*: Table[string, TrackerBase]

proc sentinelCallbackImpl(arg: pointer) {.gcsafe.} =
  raiseAssert "Sentinel callback MUST not be scheduled"

const
  SentinelCallback = AsyncCallback(function: sentinelCallbackImpl,
                                   udata: nil)

proc isSentinel(acb: AsyncCallback): bool =
  acb == SentinelCallback

proc `<`(a, b: TimerCallback): bool =
  result = a.finishAt < b.finishAt

func getAsyncTimestamp*(a: Duration): auto {.inline.} =
  ## Return rounded up value of duration with milliseconds resolution.
  ##
  ## This function also take care on int32 overflow, because Linux and Windows
  ## accepts signed 32bit integer as timeout.
  let milsec = Millisecond.nanoseconds()
  let nansec = a.nanoseconds()
  var res = nansec div milsec
  let mid = nansec mod milsec
  when defined(windows):
    res = min(int64(high(int32) - 1), res)
    result = cast[DWORD](res)
    result += DWORD(min(1'i32, cast[int32](mid)))
  else:
    res = min(int64(high(int32) - 1), res)
    result = cast[int32](res)
    result += min(1, cast[int32](mid))

template processTimersGetTimeout(loop, timeout: untyped) =
  var lastFinish = curTime
  while loop.timers.len > 0:
    if loop.timers[0].function.function.isNil:
      discard loop.timers.pop()
      continue

    lastFinish = loop.timers[0].finishAt
    if curTime < lastFinish:
      break

    loop.callbacks.addLast(loop.timers.pop().function)

  if loop.timers.len > 0:
    timeout = (lastFinish - curTime).getAsyncTimestamp()

  if timeout == 0:
    if (len(loop.callbacks) == 0) and (len(loop.idlers) == 0):
      when defined(windows):
        timeout = INFINITE
      else:
        timeout = -1
  else:
    if (len(loop.callbacks) != 0) or (len(loop.idlers) != 0):
      timeout = 0

template processTimers(loop: untyped) =
  var curTime = Moment.now()
  while loop.timers.len > 0:
    if loop.timers[0].function.function.isNil:
      discard loop.timers.pop()
      continue

    if curTime < loop.timers[0].finishAt:
      break
    loop.callbacks.addLast(loop.timers.pop().function)

template processIdlers(loop: untyped) =
  if len(loop.idlers) > 0:
    loop.callbacks.addLast(loop.idlers.popFirst())

template processCallbacks(loop: untyped) =
  while true:
    let callable = loop.callbacks.popFirst()  # len must be > 0 due to sentinel
    if isSentinel(callable):
      break
    if not(isNil(callable.function)):
      callable.function(callable.udata)

proc raiseAsDefect*(exc: ref Exception, msg: string) {.noreturn, noinline.} =
  # Reraise an exception as a Defect, where it's unexpected and can't be handled
  # We include the stack trace in the message because otherwise, it's easily
  # lost - Nim doesn't print it for `parent` exceptions for example (!)
  raise (ref Defect)(
    msg: msg & "\n" & exc.msg & "\n" & exc.getStackTrace(), parent: exc)

proc raiseOsDefect*(error: OSErrorCode, msg = "") {.noreturn, noinline.} =
  # Reraise OS error code as a Defect, where it's unexpected and can't be
  # handled. We include the stack trace in the message because otherwise,
  # it's easily lost.
  raise (ref Defect)(msg: msg & "\n[" & $int(error) & "] " & osErrorMsg(error) &
                          "\n" & getStackTrace())

func toPointer(error: OSErrorCode): pointer =
  when sizeof(int) == 8:
    cast[pointer](uint64(uint32(error)))
  else:
    cast[pointer](uint32(error))

func toException*(v: OSErrorCode): ref OSError = newOSError(v)
  # This helper will allow to use `tryGet()` and raise OSError for
  # Result[T, OSErrorCode] values.

when defined(windows):
  export SIGINT, SIGQUIT, SIGTERM
  type
    CompletionKey = ULONG_PTR

    CompletionData* = object
      cb*: CallbackFunc
      errCode*: OSErrorCode
      bytesCount*: uint32
      udata*: pointer

    CustomOverlapped* = object of OVERLAPPED
      data*: CompletionData

    DispatcherFlag* = enum
      SignalHandlerInstalled

    PDispatcher* = ref object of PDispatcherBase
      ioPort: HANDLE
      handles: HashSet[AsyncFD]
      connectEx*: WSAPROC_CONNECTEX
      acceptEx*: WSAPROC_ACCEPTEX
      getAcceptExSockAddrs*: WSAPROC_GETACCEPTEXSOCKADDRS
      transmitFile*: WSAPROC_TRANSMITFILE
      getQueuedCompletionStatusEx*: LPFN_GETQUEUEDCOMPLETIONSTATUSEX
      flags: set[DispatcherFlag]

    PtrCustomOverlapped* = ptr CustomOverlapped

    RefCustomOverlapped* = ref CustomOverlapped

    PostCallbackData = object
      ioPort: HANDLE
      handleFd: AsyncFD
      waitFd: HANDLE
      udata: pointer
      ovlref: RefCustomOverlapped
      ovl: pointer

    WaitableHandle* = ref PostCallbackData
    ProcessHandle* = distinct WaitableHandle
    SignalHandle* = distinct WaitableHandle

    WaitableResult* {.pure.} = enum
      Ok, Timeout

    AsyncFD* = distinct int

  proc hash(x: AsyncFD): Hash {.borrow.}
  proc `==`*(x: AsyncFD, y: AsyncFD): bool {.borrow, gcsafe.}

  proc getFunc(s: SocketHandle, fun: var pointer, guid: GUID): bool =
    var bytesRet: DWORD
    fun = nil
    wsaIoctl(s, SIO_GET_EXTENSION_FUNCTION_POINTER, unsafeAddr(guid),
             DWORD(sizeof(GUID)), addr fun, DWORD(sizeof(pointer)),
             addr(bytesRet), nil, nil) == 0

  proc globalInit() =
    var wsa = WSAData()
    let res = wsaStartup(0x0202'u16, addr wsa)
    if res != 0:
      raiseOsDefect(osLastError(),
                    "globalInit(): Unable to initialize Windows Sockets API")

  proc initAPI(loop: PDispatcher) =
    var funcPointer: pointer = nil

    let kernel32 = getModuleHandle(newWideCString("kernel32.dll"))
    loop.getQueuedCompletionStatusEx = cast[LPFN_GETQUEUEDCOMPLETIONSTATUSEX](
      getProcAddress(kernel32, "GetQueuedCompletionStatusEx"))

    let sock = osdefs.socket(osdefs.AF_INET, 1, 6)
    if sock == osdefs.INVALID_SOCKET:
      raiseOsDefect(osLastError(), "initAPI(): Unable to create control socket")

    block:
      let res = getFunc(sock, funcPointer, WSAID_CONNECTEX)
      if not(res):
        raiseOsDefect(osLastError(), "initAPI(): Unable to initialize " &
                                     "dispatcher's ConnectEx()")
      loop.connectEx = cast[WSAPROC_CONNECTEX](funcPointer)

    block:
      let res = getFunc(sock, funcPointer, WSAID_ACCEPTEX)
      if not(res):
        raiseOsDefect(osLastError(), "initAPI(): Unable to initialize " &
                                     "dispatcher's AcceptEx()")
      loop.acceptEx = cast[WSAPROC_ACCEPTEX](funcPointer)

    block:
      let res = getFunc(sock, funcPointer, WSAID_GETACCEPTEXSOCKADDRS)
      if not(res):
        raiseOsDefect(osLastError(), "initAPI(): Unable to initialize " &
                                     "dispatcher's GetAcceptExSockAddrs()")
      loop.getAcceptExSockAddrs =
        cast[WSAPROC_GETACCEPTEXSOCKADDRS](funcPointer)

    block:
      let res = getFunc(sock, funcPointer, WSAID_TRANSMITFILE)
      if not(res):
        raiseOsDefect(osLastError(), "initAPI(): Unable to initialize " &
                                     "dispatcher's TransmitFile()")
      loop.transmitFile = cast[WSAPROC_TRANSMITFILE](funcPointer)

    if closeFd(sock) != 0:
      raiseOsDefect(osLastError(), "initAPI(): Unable to close control socket")

  proc newDispatcher*(): PDispatcher =
    ## Creates a new Dispatcher instance.
    let port = createIoCompletionPort(osdefs.INVALID_HANDLE_VALUE,
                                      HANDLE(0), 0, 1)
    if port == osdefs.INVALID_HANDLE_VALUE:
      raiseOsDefect(osLastError(), "newDispatcher(): Unable to create " &
                                   "IOCP port")
    var res = PDispatcher(
      ioPort: port,
      handles: initHashSet[AsyncFD](),
      timers: initHeapQueue[TimerCallback](),
      callbacks: initDeque[AsyncCallback](64),
      idlers: initDeque[AsyncCallback](),
      trackers: initTable[string, TrackerBase]()
    )
    res.callbacks.addLast(SentinelCallback)
    initAPI(res)
    res

  var gDisp{.threadvar.}: PDispatcher ## Global dispatcher

  proc setThreadDispatcher*(disp: PDispatcher) {.gcsafe, raises: [Defect].}
  proc getThreadDispatcher*(): PDispatcher {.gcsafe, raises: [Defect].}

  proc getIoHandler*(disp: PDispatcher): HANDLE =
    ## Returns the underlying IO Completion Port handle (Windows) or selector
    ## (Unix) for the specified dispatcher.
    disp.ioPort

  proc register2*(fd: AsyncFD): Result[void, OSErrorCode] =
    ## Register file descriptor ``fd`` in thread's dispatcher.
    let loop = getThreadDispatcher()
    if createIoCompletionPort(HANDLE(fd), loop.ioPort, cast[CompletionKey](fd),
                              1) == osdefs.INVALID_HANDLE_VALUE:
      return err(osLastError())
    loop.handles.incl(fd)
    ok()

  proc register*(fd: AsyncFD) {.raises: [Defect, OSError].} =
    ## Register file descriptor ``fd`` in thread's dispatcher.
    register2(fd).tryGet()

  proc unregister*(fd: AsyncFD) =
    ## Unregisters ``fd``.
    getThreadDispatcher().handles.excl(fd)

  {.push stackTrace: off.}
  proc waitableCallback(param: pointer, timerOrWaitFired: WINBOOL) {.
       callbackFunc.} =
    # This procedure will be executed in `wait thread`, so it must not use
    # GC related objects.
    # We going to ignore callbacks which was spawned when `isNil(param) == true`
    # because we unable to indicate this error.
    if isNil(param): return
    var wh = cast[ptr PostCallbackData](param)
    # We ignore result of postQueueCompletionStatus() call because we unable to
    # indicate error.
    discard postQueuedCompletionStatus(wh[].ioPort, DWORD(timerOrWaitFired),
                                       ULONG_PTR(wh[].handleFd),
                                       wh[].ovl)
  {.pop.}

  proc registerWaitable(
         handle: HANDLE,
         flags: ULONG,
         timeout: Duration,
         cb: CallbackFunc,
         udata: pointer
       ): Result[WaitableHandle, OSErrorCode] =
    ## Register handle of (Change notification, Console input, Event,
    ## Memory resource notification, Mutex, Process, Semaphore, Thread,
    ## Waitable timer) for waiting, using specific Windows' ``flags`` and
    ## ``timeout`` value.
    ##
    ## Callback ``cb`` will be scheduled with ``udata`` parameter when
    ## ``handle`` become signaled.
    ##
    ## Result of this procedure call ``WaitableHandle`` should be closed using
    ## closeWaitable() call.
    ##
    ## NOTE: This is private procedure, not supposed to be publicly available,
    ## please use ``waitForSingleObject()``.
    let loop = getThreadDispatcher()
    var ovl = RefCustomOverlapped(data: CompletionData(cb: cb))

    var whandle = (ref PostCallbackData)(
      ioPort: loop.getIoHandler(),
      handleFd: AsyncFD(handle),
      udata: udata,
      ovlref: ovl,
      ovl: cast[pointer](ovl)
    )

    ovl.data.udata = cast[pointer](whandle)

    let dwordTimeout =
      if timeout == InfiniteDuration:
        DWORD(INFINITE)
      else:
        DWORD(timeout.milliseconds)

    if registerWaitForSingleObject(addr(whandle[].waitFd), handle,
                                   cast[WAITORTIMERCALLBACK](waitableCallback),
                                   cast[pointer](whandle),
                                   dwordTimeout,
                                   flags) == WINBOOL(0):
      ovl.data.udata = nil
      whandle.ovlref = nil
      whandle.ovl = nil
      return err(osLastError())

    ok(WaitableHandle(whandle))

  proc closeWaitable(wh: WaitableHandle): Result[void, OSErrorCode] =
    ## Close waitable handle ``wh`` and clear all the resources. It is safe
    ## to close this handle, even if wait operation is pending.
    ##
    ## NOTE: This is private procedure, not supposed to be publicly available,
    ## please use ``waitForSingleObject()``.
    doAssert(not(isNil(wh)))

    let pdata = (ref PostCallbackData)(wh)
    # We are not going to clear `ref` fields in PostCallbackData object because
    # it possible that callback is already scheduled.
    if unregisterWait(pdata.waitFd) == 0:
      let res = osLastError()
      if res != ERROR_IO_PENDING:
        return err(res)
    ok()

  proc addProcess2*(pid: int, cb: CallbackFunc,
                    udata: pointer = nil): Result[ProcessHandle, OSErrorCode] =
    ## Registers callback ``cb`` to be called when process with process
    ## identifier ``pid`` exited. Returns process identifier, which can be
    ## used to clear process callback via ``removeProcess``.
    doAssert(pid > 0, "Process identifier must be positive integer")
    let
      hProcess = openProcess(SYNCHRONIZE, WINBOOL(0), DWORD(pid))
      flags = WT_EXECUTEINWAITTHREAD or WT_EXECUTEONLYONCE

    var wh: WaitableHandle = nil

    if hProcess == HANDLE(0):
      return err(osLastError())

    proc continuation(udata: pointer) {.gcsafe.} =
      doAssert(not(isNil(udata)))
      doAssert(not(isNil(wh)))
      discard closeFd(hProcess)
      cb(wh[].udata)

    wh =
      block:
        let res = registerWaitable(hProcess, flags, InfiniteDuration,
                                   continuation, udata)
        if res.isErr():
          discard closeFd(hProcess)
          return err(res.error())
        res.get()
    ok(ProcessHandle(wh))

  proc removeProcess2*(procHandle: ProcessHandle): Result[void, OSErrorCode] =
    ## Remove process' watching using process' descriptor ``procHandle``.
    let waitableHandle = WaitableHandle(procHandle)
    doAssert(not(isNil(waitableHandle)))
    ? closeWaitable(waitableHandle)
    ok()

  proc addProcess*(pid: int, cb: CallbackFunc,
                   udata: pointer = nil): ProcessHandle {.
       raises: [Defect, OSError].} =
    ## Registers callback ``cb`` to be called when process with process
    ## identifier ``pid`` exited. Returns process identifier, which can be
    ## used to clear process callback via ``removeProcess``.
    addProcess2(pid, cb, udata).tryGet()

  proc removeProcess*(procHandle: ProcessHandle) {.
       raises: [Defect, OSError].} =
    ## Remove process' watching using process' descriptor ``procHandle``.
    removeProcess2(procHandle).tryGet()

  {.push stackTrace: off.}
  proc consoleCtrlEventHandler(dwCtrlType: DWORD): uint32 {.callbackFunc.} =
    ## This procedure will be executed in different thread, so it MUST not use
    ## any GC related features (strings, seqs, echo etc.).
    case dwCtrlType
    of CTRL_C_EVENT:
      return
        (if raiseSignal(SIGINT).valueOr(false): TRUE else: FALSE)
    of CTRL_BREAK_EVENT:
      return
        (if raiseSignal(SIGINT).valueOr(false): TRUE else: FALSE)
    of CTRL_CLOSE_EVENT:
      return
        (if raiseSignal(SIGTERM).valueOr(false): TRUE else: FALSE)
    of CTRL_LOGOFF_EVENT:
      return
        (if raiseSignal(SIGQUIT).valueOr(false): TRUE else: FALSE)
    else:
      FALSE
  {.pop.}

  proc addSignal2*(signal: int, cb: CallbackFunc,
                   udata: pointer = nil): Result[SignalHandle, OSErrorCode] =
    ## Start watching signal ``signal``, and when signal appears, call the
    ## callback ``cb`` with specified argument ``udata``. Returns signal
    ## identifier code, which can be used to remove signal callback
    ## via ``removeSignal``.
    ##
    ## NOTE: On Windows only subset of signals are supported: SIGINT, SIGTERM,
    ##       SIGQUIT
    const supportedSignals = [SIGINT, SIGTERM, SIGQUIT]
    doAssert(cint(signal) in supportedSignals, "Signal is not supported")
    let loop = getThreadDispatcher()
    var hWait: WaitableHandle = nil

    proc continuation(ucdata: pointer) {.gcsafe.} =
      doAssert(not(isNil(ucdata)))
      doAssert(not(isNil(hWait)))
      cb(hWait[].udata)

    if SignalHandlerInstalled notin loop.flags:
      if getConsoleCP() != 0'u32:
        # Console application, we going to cleanup Nim default signal handlers.
        if setConsoleCtrlHandler(consoleCtrlEventHandler, TRUE) == FALSE:
          return err(osLastError())
        loop.flags.incl(SignalHandlerInstalled)
      else:
        return err(ERROR_NOT_SUPPORTED)

    let
      flags = WT_EXECUTEINWAITTHREAD
      hEvent = ? openEvent($getSignalName(signal))

    hWait = registerWaitable(hEvent, flags, InfiniteDuration,
                             continuation, udata).valueOr:
      discard closeFd(hEvent)
      return err(error)
    ok(SignalHandle(hWait))

  proc removeSignal2*(signalHandle: SignalHandle): Result[void, OSErrorCode] =
    ## Remove watching signal ``signal``.
    ? closeWaitable(WaitableHandle(signalHandle))
    ok()

  proc addSignal*(signal: int, cb: CallbackFunc,
                  udata: pointer = nil): SignalHandle {.
       raises: [Defect, ValueError].} =
    ## Registers callback ``cb`` to be called when signal ``signal`` will be
    ## raised. Returns signal identifier, which can be used to clear signal
    ## callback via ``removeSignal``.
    addSignal2(signal, cb, udata).valueOr:
      raise newException(ValueError, osErrorMsg(error))

  proc removeSignal*(signalHandle: SignalHandle) {.
       raises: [Defect, ValueError].} =
    ## Remove signal's watching using signal descriptor ``signalfd``.
    let res = removeSignal2(signalHandle)
    if res.isErr():
      raise newException(ValueError, osErrorMsg(res.error()))

  proc poll*() =
    ## Perform single asynchronous step, processing timers and completing
    ## tasks. Blocks until at least one event has completed.
    ##
    ## Exceptions raised here indicate that waiting for tasks to be unblocked
    ## failed - exceptions from within tasks are instead propagated through
    ## their respective futures and not allowed to interrrupt the poll call.
    let loop = getThreadDispatcher()
    var
      curTime = Moment.now()
      curTimeout = DWORD(0)
      events: array[MaxEventsCount, osdefs.OVERLAPPED_ENTRY]

    # On reentrant `poll` calls from `processCallbacks`, e.g., `waitFor`,
    # complete pending work of the outer `processCallbacks` call.
    # On non-reentrant `poll` calls, this only removes sentinel element.
    processCallbacks(loop)

    # Moving expired timers to `loop.callbacks` and calculate timeout
    loop.processTimersGetTimeout(curTimeout)

    let networkEventsCount =
      if isNil(loop.getQueuedCompletionStatusEx):
        let res = getQueuedCompletionStatus(
          loop.ioPort,
          addr events[0].dwNumberOfBytesTransferred,
          addr events[0].lpCompletionKey,
          cast[ptr POVERLAPPED](addr events[0].lpOverlapped),
          curTimeout
        )
        if res == FALSE:
          let errCode = osLastError()
          if not(isNil(events[0].lpOverlapped)):
            1
          else:
            if uint32(errCode) != WAIT_TIMEOUT:
              raiseOsDefect(errCode, "poll(): Unable to get OS events")
            0
        else:
          1
      else:
        var eventsReceived = ULONG(0)
        let res = loop.getQueuedCompletionStatusEx(
          loop.ioPort,
          addr events[0],
          ULONG(len(events)),
          eventsReceived,
          curTimeout,
          WINBOOL(0)
        )
        if res == FALSE:
          let errCode = osLastError()
          if uint32(errCode) != WAIT_TIMEOUT:
            raiseOsDefect(errCode, "poll(): Unable to get OS events")
          0
        else:
          int(eventsReceived)

    for i in 0 ..< networkEventsCount:
      var customOverlapped = PtrCustomOverlapped(events[i].lpOverlapped)
      customOverlapped.data.errCode =
        block:
          let res = cast[uint64](customOverlapped.internal)
          if res == 0'u64:
            OSErrorCode(-1)
          else:
            OSErrorCode(rtlNtStatusToDosError(res))
      customOverlapped.data.bytesCount = events[i].dwNumberOfBytesTransferred
      let acb = AsyncCallback(function: customOverlapped.data.cb,
                              udata: cast[pointer](customOverlapped))
      loop.callbacks.addLast(acb)

    # Moving expired timers to `loop.callbacks`.
    loop.processTimers()

    # We move idle callbacks to `loop.callbacks` only if there no pending
    # network events.
    if networkEventsCount == 0:
      loop.processIdlers()

    # All callbacks which will be added during `processCallbacks` will be
    # scheduled after the sentinel and are processed on next `poll()` call.
    loop.callbacks.addLast(SentinelCallback)
    processCallbacks(loop)

    # All callbacks done, skip `processCallbacks` at start.
    loop.callbacks.addFirst(SentinelCallback)

  proc closeSocket*(fd: AsyncFD, aftercb: CallbackFunc = nil) =
    ## Closes a socket and ensures that it is unregistered.
    let loop = getThreadDispatcher()
    loop.handles.excl(fd)
    let
      param = toPointer(
        if closeFd(SocketHandle(fd)) == 0:
          OSErrorCode(0)
        else:
          osLastError()
      )
    if not(isNil(aftercb)):
      loop.callbacks.addLast(AsyncCallback(function: aftercb, udata: param))

  proc closeHandle*(fd: AsyncFD, aftercb: CallbackFunc = nil) =
    ## Closes a (pipe/file) handle and ensures that it is unregistered.
    let loop = getThreadDispatcher()
    loop.handles.excl(fd)
    let
      param = toPointer(
        if closeFd(HANDLE(fd)) == 0:
          OSErrorCode(0)
        else:
          osLastError()
      )

    if not(isNil(aftercb)):
      loop.callbacks.addLast(AsyncCallback(function: aftercb, udata: param))

  proc contains*(disp: PDispatcher, fd: AsyncFD): bool =
    ## Returns ``true`` if ``fd`` is registered in thread's dispatcher.
    fd in disp.handles

elif defined(macosx) or defined(freebsd) or defined(netbsd) or
     defined(openbsd) or defined(dragonfly) or defined(macos) or
     defined(linux) or defined(android) or defined(solaris):
  const
    SIG_IGN = cast[proc(x: cint) {.raises: [], noconv, gcsafe.}](1)

  type
    AsyncFD* = distinct cint

    SelectorData* = object
      reader*: AsyncCallback
      writer*: AsyncCallback

    PDispatcher* = ref object of PDispatcherBase
      selector: Selector[SelectorData]
      keys: seq[ReadyKey]

  proc `==`*(x, y: AsyncFD): bool {.borrow, gcsafe.}

  proc globalInit() =
    # We are ignoring SIGPIPE signal, because we are working with EPIPE.
    signal(cint(SIGPIPE), SIG_IGN)

  proc initAPI(disp: PDispatcher) =
    discard

  proc newDispatcher*(): PDispatcher =
    ## Create new dispatcher.
    let selector =
      block:
        let res = Selector.new(SelectorData)
        if res.isErr(): raiseOsDefect(res.error(),
                                      "Could not initialize selector")
        res.get()

    var res = PDispatcher(
      selector: selector,
      timers: initHeapQueue[TimerCallback](),
      callbacks: initDeque[AsyncCallback](asyncEventsCount),
      idlers: initDeque[AsyncCallback](),
      keys: newSeq[ReadyKey](asyncEventsCount),
      trackers: initTable[string, TrackerBase]()
    )
    res.callbacks.addLast(SentinelCallback)
    initAPI(res)
    res

  var gDisp{.threadvar.}: PDispatcher ## Global dispatcher

  proc setThreadDispatcher*(disp: PDispatcher) {.gcsafe, raises: [Defect].}
  proc getThreadDispatcher*(): PDispatcher {.gcsafe, raises: [Defect].}

  proc getIoHandler*(disp: PDispatcher): Selector[SelectorData] =
    ## Returns system specific OS queue.
    disp.selector

  proc contains*(disp: PDispatcher, fd: AsyncFD): bool {.inline.} =
    ## Returns ``true`` if ``fd`` is registered in thread's dispatcher.
    cint(fd) in disp.selector

  proc register2*(fd: AsyncFD): Result[void, OSErrorCode] =
    ## Register file descriptor ``fd`` in thread's dispatcher.
    var data: SelectorData
    getThreadDispatcher().selector.registerHandle2(cint(fd), {}, data)

  proc unregister2*(fd: AsyncFD): Result[void, OSErrorCode] =
    ## Unregister file descriptor ``fd`` from thread's dispatcher.
    getThreadDispatcher().selector.unregister2(cint(fd))

  proc addReader2*(fd: AsyncFD, cb: CallbackFunc,
                   udata: pointer = nil): Result[void, OSErrorCode] =
    ## Start watching the file descriptor ``fd`` for read availability and then
    ## call the callback ``cb`` with specified argument ``udata``.
    let loop = getThreadDispatcher()
    var newEvents = {Event.Read}
    withData(loop.selector, cint(fd), adata) do:
      let acb = AsyncCallback(function: cb, udata: udata)
      adata.reader = acb
      if not(isNil(adata.writer.function)):
        newEvents.incl(Event.Write)
    do:
      return err(osdefs.EBADF)
    loop.selector.updateHandle2(cint(fd), newEvents)

  proc removeReader2*(fd: AsyncFD): Result[void, OSErrorCode] =
    ## Stop watching the file descriptor ``fd`` for read availability.
    let loop = getThreadDispatcher()
    var newEvents: set[Event]
    withData(loop.selector, cint(fd), adata) do:
      # We need to clear `reader` data, because `selectors` don't do it
      adata.reader = default(AsyncCallback)
      if not(isNil(adata.writer.function)):
        newEvents.incl(Event.Write)
    do:
      return err(osdefs.EBADF)
    loop.selector.updateHandle2(cint(fd), newEvents)

  proc addWriter2*(fd: AsyncFD, cb: CallbackFunc,
                   udata: pointer = nil): Result[void, OSErrorCode] =
    ## Start watching the file descriptor ``fd`` for write availability and then
    ## call the callback ``cb`` with specified argument ``udata``.
    let loop = getThreadDispatcher()
    var newEvents = {Event.Write}
    withData(loop.selector, cint(fd), adata) do:
      let acb = AsyncCallback(function: cb, udata: udata)
      adata.writer = acb
      if not(isNil(adata.reader.function)):
        newEvents.incl(Event.Read)
    do:
      return err(osdefs.EBADF)
    loop.selector.updateHandle2(cint(fd), newEvents)

  proc removeWriter2*(fd: AsyncFD): Result[void, OSErrorCode] =
    ## Stop watching the file descriptor ``fd`` for write availability.
    let loop = getThreadDispatcher()
    var newEvents: set[Event]
    withData(loop.selector, cint(fd), adata) do:
      # We need to clear `writer` data, because `selectors` don't do it
      adata.writer = default(AsyncCallback)
      if not(isNil(adata.reader.function)):
        newEvents.incl(Event.Read)
    do:
      return err(osdefs.EBADF)
    loop.selector.updateHandle2(cint(fd), newEvents)

  proc register*(fd: AsyncFD) {.raises: [Defect, OSError].} =
    ## Register file descriptor ``fd`` in thread's dispatcher.
    register2(fd).tryGet()

  proc unregister*(fd: AsyncFD) {.raises: [Defect, OSError].} =
    ## Unregister file descriptor ``fd`` from thread's dispatcher.
    unregister2(fd).tryGet()

  proc addReader*(fd: AsyncFD, cb: CallbackFunc, udata: pointer = nil) {.
       raises: [Defect, OSError].} =
    ## Start watching the file descriptor ``fd`` for read availability and then
    ## call the callback ``cb`` with specified argument ``udata``.
    addReader2(fd, cb, udata).tryGet()

  proc removeReader*(fd: AsyncFD) {.raises: [Defect, OSError].} =
    ## Stop watching the file descriptor ``fd`` for read availability.
    removeReader2(fd).tryGet()

  proc addWriter*(fd: AsyncFD, cb: CallbackFunc, udata: pointer = nil) {.
       raises: [Defect, OSError].} =
    ## Start watching the file descriptor ``fd`` for write availability and then
    ## call the callback ``cb`` with specified argument ``udata``.
    addWriter2(fd, cb, udata).tryGet()

  proc removeWriter*(fd: AsyncFD) {.raises: [Defect, OSError].} =
    ## Stop watching the file descriptor ``fd`` for write availability.
    removeWriter2(fd).tryGet()

  proc unregisterAndCloseFd*(fd: AsyncFD): Result[void, OSErrorCode] =
    ## Unregister from system queue and close asynchronous socket.
    ##
    ## NOTE: Use this function to close temporary sockets/pipes only (which
    ## are not exposed to the public and not supposed to be used/reused).
    ## Please use closeSocket(AsyncFD) and closeHandle(AsyncFD) instead.
    doAssert(fd != AsyncFD(osdefs.INVALID_SOCKET))
    ? unregister2(fd)
    if closeFd(cint(fd)) != 0:
      err(osLastError())
    else:
      ok()

  proc closeSocket*(fd: AsyncFD, aftercb: CallbackFunc = nil) =
    ## Close asynchronous socket.
    ##
    ## Please note, that socket is not closed immediately. To avoid bugs with
    ## closing socket, while operation pending, socket will be closed as
    ## soon as all pending operations will be notified.
    let loop = getThreadDispatcher()

    proc continuation(udata: pointer) =
      let
        param = toPointer(
          if SocketHandle(fd) in loop.selector:
            let ures = unregister2(fd)
            if ures.isErr():
              discard closeFd(cint(fd))
              ures.error()
            else:
              if closeFd(cint(fd)) != 0:
                osLastError()
              else:
                OSErrorCode(0)
          else:
            osdefs.EBADF
        )
      if not(isNil(aftercb)): aftercb(param)

    withData(loop.selector, cint(fd), adata) do:
      # We are scheduling reader and writer callbacks to be called
      # explicitly, so they can get an error and continue work.
      # Callbacks marked as deleted so we don't need to get REAL notifications
      # from system queue for this reader and writer.

      if not(isNil(adata.reader.function)):
        loop.callbacks.addLast(adata.reader)
        adata.reader = default(AsyncCallback)

      if not(isNil(adata.writer.function)):
        loop.callbacks.addLast(adata.writer)
        adata.writer = default(AsyncCallback)

    # We can't unregister file descriptor from system queue here, because
    # in such case processing queue will stuck on poll() call, because there
    # can be no file descriptors registered in system queue.
    var acb = AsyncCallback(function: continuation)
    loop.callbacks.addLast(acb)

  proc closeHandle*(fd: AsyncFD, aftercb: CallbackFunc = nil) =
    ## Close asynchronous file/pipe handle.
    ##
    ## Please note, that socket is not closed immediately. To avoid bugs with
    ## closing socket, while operation pending, socket will be closed as
    ## soon as all pending operations will be notified.
    ## You can execute ``aftercb`` before actual socket close operation.
    closeSocket(fd, aftercb)

  when asyncEventEngine in ["epoll", "kqueue"]:
    type
      ProcessHandle* = distinct int
      SignalHandle* = distinct int

    proc addSignal2*(
           signal: int,
           cb: CallbackFunc,
           udata: pointer = nil
         ): Result[SignalHandle, OSErrorCode] =
      ## Start watching signal ``signal``, and when signal appears, call the
      ## callback ``cb`` with specified argument ``udata``. Returns signal
      ## identifier code, which can be used to remove signal callback
      ## via ``removeSignal``.
      let loop = getThreadDispatcher()
      var data: SelectorData
      let sigfd = ? loop.selector.registerSignal(signal, data)
      withData(loop.selector, sigfd, adata) do:
        adata.reader = AsyncCallback(function: cb, udata: udata)
      do:
        return err(osdefs.EBADF)
      ok(SignalHandle(sigfd))

    proc addProcess2*(
           pid: int,
           cb: CallbackFunc,
           udata: pointer = nil
         ): Result[ProcessHandle, OSErrorCode] =
      ## Registers callback ``cb`` to be called when process with process
      ## identifier ``pid`` exited. Returns process' descriptor, which can be
      ## used to clear process callback via ``removeProcess``.
      let loop = getThreadDispatcher()
      var data: SelectorData
      let procfd = ? loop.selector.registerProcess(pid, data)
      withData(loop.selector, procfd, adata) do:
        adata.reader = AsyncCallback(function: cb, udata: udata)
      do:
        return err(osdefs.EBADF)
      ok(ProcessHandle(procfd))

    proc removeSignal2*(signalHandle: SignalHandle): Result[void, OSErrorCode] =
      ## Remove watching signal ``signal``.
      getThreadDispatcher().selector.unregister2(cint(signalHandle))

    proc removeProcess2*(procHandle: ProcessHandle): Result[void, OSErrorCode] =
      ## Remove process' watching using process' descriptor ``procfd``.
      getThreadDispatcher().selector.unregister2(cint(procHandle))

    proc addSignal*(signal: int, cb: CallbackFunc,
                    udata: pointer = nil): SignalHandle {.
         raises: [Defect, OSError].} =
      ## Start watching signal ``signal``, and when signal appears, call the
      ## callback ``cb`` with specified argument ``udata``. Returns signal
      ## identifier code, which can be used to remove signal callback
      ## via ``removeSignal``.
      addSignal2(signal, cb, udata).tryGet()

    proc removeSignal*(signalHandle: SignalHandle) {.
         raises: [Defect, OSError].} =
      ## Remove watching signal ``signal``.
      removeSignal2(signalHandle).tryGet()

    proc addProcess*(pid: int, cb: CallbackFunc,
                     udata: pointer = nil): ProcessHandle {.
         raises: [Defect, OSError].} =
      ## Registers callback ``cb`` to be called when process with process
      ## identifier ``pid`` exited. Returns process identifier, which can be
      ## used to clear process callback via ``removeProcess``.
      addProcess2(pid, cb, udata).tryGet()

    proc removeProcess*(procHandle: ProcessHandle) {.
         raises: [Defect, OSError].} =
      ## Remove process' watching using process' descriptor ``procHandle``.
      removeProcess2(procHandle).tryGet()

  proc poll*() {.gcsafe.} =
    ## Perform single asynchronous step.
    let loop = getThreadDispatcher()
    var curTime = Moment.now()
    var curTimeout = 0

    # On reentrant `poll` calls from `processCallbacks`, e.g., `waitFor`,
    # complete pending work of the outer `processCallbacks` call.
    # On non-reentrant `poll` calls, this only removes sentinel element.
    processCallbacks(loop)

    # Moving expired timers to `loop.callbacks` and calculate timeout.
    loop.processTimersGetTimeout(curTimeout)

    # Processing IO descriptors and all hardware events.
    let count =
      block:
        let res = loop.selector.selectInto2(curTimeout, loop.keys)
        if res.isErr():
          raiseOsDefect(res.error(), "poll(): Unable to get OS events")
        res.get()

    for i in 0 ..< count:
      let fd = loop.keys[i].fd
      let events = loop.keys[i].events

      withData(loop.selector, cint(fd), adata) do:
        if (Event.Read in events) or (events == {Event.Error}):
          if not isNil(adata.reader.function):
            loop.callbacks.addLast(adata.reader)

        if (Event.Write in events) or (events == {Event.Error}):
          if not isNil(adata.writer.function):
            loop.callbacks.addLast(adata.writer)

        if Event.User in events:
          if not isNil(adata.reader.function):
            loop.callbacks.addLast(adata.reader)

        when asyncEventEngine in ["epoll", "kqueue"]:
          let customSet = {Event.Timer, Event.Signal, Event.Process,
                           Event.Vnode}
          if customSet * events != {}:
            if not isNil(adata.reader.function):
              loop.callbacks.addLast(adata.reader)

    # Moving expired timers to `loop.callbacks`.
    loop.processTimers()

    # We move idle callbacks to `loop.callbacks` only if there no pending
    # network events.
    if count == 0:
      loop.processIdlers()

    # All callbacks which will be added during `processCallbacks` will be
    # scheduled after the sentinel and are processed on next `poll()` call.
    loop.callbacks.addLast(SentinelCallback)
    processCallbacks(loop)

    # All callbacks done, skip `processCallbacks` at start.
    loop.callbacks.addFirst(SentinelCallback)

else:
  proc initAPI() = discard
  proc globalInit() = discard

proc setThreadDispatcher*(disp: PDispatcher) =
  ## Set current thread's dispatcher instance to ``disp``.
  if not(gDisp.isNil()):
    doAssert gDisp.callbacks.len == 0
  gDisp = disp

proc getThreadDispatcher*(): PDispatcher =
  ## Returns current thread's dispatcher instance.
  if gDisp.isNil():
    setThreadDispatcher(newDispatcher())
  gDisp

proc setGlobalDispatcher*(disp: PDispatcher) {.
      gcsafe, deprecated: "Use setThreadDispatcher() instead".} =
  setThreadDispatcher(disp)

proc getGlobalDispatcher*(): PDispatcher {.
      gcsafe, deprecated: "Use getThreadDispatcher() instead".} =
  getThreadDispatcher()

proc setTimer*(at: Moment, cb: CallbackFunc,
               udata: pointer = nil): TimerCallback =
  ## Arrange for the callback ``cb`` to be called at the given absolute
  ## timestamp ``at``. You can also pass ``udata`` to callback.
  let loop = getThreadDispatcher()
  result = TimerCallback(finishAt: at,
                         function: AsyncCallback(function: cb, udata: udata))
  loop.timers.push(result)

proc clearTimer*(timer: TimerCallback) {.inline.} =
  timer.function = default(AsyncCallback)

proc addTimer*(at: Moment, cb: CallbackFunc, udata: pointer = nil) {.
     inline, deprecated: "Use setTimer/clearTimer instead".} =
  ## Arrange for the callback ``cb`` to be called at the given absolute
  ## timestamp ``at``. You can also pass ``udata`` to callback.
  discard setTimer(at, cb, udata)

proc addTimer*(at: int64, cb: CallbackFunc, udata: pointer = nil) {.
     inline, deprecated: "Use addTimer(Duration, cb, udata)".} =
  discard setTimer(Moment.init(at, Millisecond), cb, udata)

proc addTimer*(at: uint64, cb: CallbackFunc, udata: pointer = nil) {.
     inline, deprecated: "Use addTimer(Duration, cb, udata)".} =
  discard setTimer(Moment.init(int64(at), Millisecond), cb, udata)

proc removeTimer*(at: Moment, cb: CallbackFunc, udata: pointer = nil) =
  ## Remove timer callback ``cb`` with absolute timestamp ``at`` from waiting
  ## queue.
  let loop = getThreadDispatcher()
  var list = cast[seq[TimerCallback]](loop.timers)
  var index = -1
  for i in 0..<len(list):
    if list[i].finishAt == at and list[i].function.function == cb and
       list[i].function.udata == udata:
      index = i
      break
  if index != -1:
    loop.timers.del(index)

proc removeTimer*(at: int64, cb: CallbackFunc, udata: pointer = nil) {.
     inline, deprecated: "Use removeTimer(Duration, cb, udata)".} =
  removeTimer(Moment.init(at, Millisecond), cb, udata)

proc removeTimer*(at: uint64, cb: CallbackFunc, udata: pointer = nil) {.
     inline, deprecated: "Use removeTimer(Duration, cb, udata)".} =
  removeTimer(Moment.init(int64(at), Millisecond), cb, udata)

proc callSoon*(acb: AsyncCallback) =
  ## Schedule `cbproc` to be called as soon as possible.
  ## The callback is called when control returns to the event loop.
  getThreadDispatcher().callbacks.addLast(acb)

proc callSoon*(cbproc: CallbackFunc, data: pointer) {.
     gcsafe.} =
  ## Schedule `cbproc` to be called as soon as possible.
  ## The callback is called when control returns to the event loop.
  doAssert(not isNil(cbproc))
  callSoon(AsyncCallback(function: cbproc, udata: data))

proc callSoon*(cbproc: CallbackFunc) =
  callSoon(cbproc, nil)

proc callIdle*(acb: AsyncCallback) =
  ## Schedule ``cbproc`` to be called when there no pending network events
  ## available.
  ##
  ## **WARNING!** Despite the name, "idle" callbacks called on every loop
  ## iteration if there no network events available, not when the loop is
  ## actually "idle".
  getThreadDispatcher().idlers.addLast(acb)

proc callIdle*(cbproc: CallbackFunc, data: pointer) =
  ## Schedule ``cbproc`` to be called when there no pending network events
  ## available.
  ##
  ## **WARNING!** Despite the name, "idle" callbacks called on every loop
  ## iteration if there no network events available, not when the loop is
  ## actually "idle".
  doAssert(not isNil(cbproc))
  callIdle(AsyncCallback(function: cbproc, udata: data))

proc callIdle*(cbproc: CallbackFunc) =
  callIdle(cbproc, nil)

include asyncfutures2


when defined(macosx) or defined(macos) or defined(freebsd) or
     defined(netbsd) or defined(openbsd) or defined(dragonfly) or
     defined(linux) or defined(windows):

  proc waitSignal*(signal: int): Future[void] {.raises: [Defect].} =
    var retFuture = newFuture[void]("chronos.waitSignal()")
    var signalHandle: Opt[SignalHandle]

    template getSignalException(e: OSErrorCode): untyped =
      newException(AsyncError, "Could not manipulate signal handler, " &
                   "reason [" & $int(e) & "]: " & osErrorMsg(e))

    proc continuation(udata: pointer) {.gcsafe.} =
      if not(retFuture.finished()):
        if signalHandle.isSome():
          let res = removeSignal2(signalHandle.get())
          if res.isErr():
            retFuture.fail(getSignalException(res.error()))
          else:
            retFuture.complete()

    proc cancellation(udata: pointer) {.gcsafe.} =
      if not(retFuture.finished()):
        if signalHandle.isSome():
          let res = removeSignal2(signalHandle.get())
          if res.isErr():
            retFuture.fail(getSignalException(res.error()))

    signalHandle =
      block:
        let res = addSignal2(signal, continuation)
        if res.isErr():
          retFuture.fail(getSignalException(res.error()))
        Opt.some(res.get())

    retFuture.cancelCallback = cancellation
    retFuture

proc sleepAsync*(duration: Duration): Future[void] =
  ## Suspends the execution of the current async procedure for the next
  ## ``duration`` time.
  var retFuture = newFuture[void]("chronos.sleepAsync(Duration)")
  let moment = Moment.fromNow(duration)
  var timer: TimerCallback

  proc completion(data: pointer) {.gcsafe.} =
    if not(retFuture.finished()):
      retFuture.complete()

  proc cancellation(udata: pointer) {.gcsafe.} =
    if not(retFuture.finished()):
      clearTimer(timer)

  retFuture.cancelCallback = cancellation
  timer = setTimer(moment, completion, cast[pointer](retFuture))
  return retFuture

proc sleepAsync*(ms: int): Future[void] {.
     inline, deprecated: "Use sleepAsync(Duration)".} =
  result = sleepAsync(ms.milliseconds())

proc stepsAsync*(number: int): Future[void] =
  ## Suspends the execution of the current async procedure for the next
  ## ``number`` of asynchronous steps (``poll()`` calls).
  ##
  ## This primitive can be useful when you need to create more deterministic
  ## tests and cases.
  ##
  ## WARNING! Do not use this primitive to perform switch between tasks, because
  ## this can lead to 100% CPU load in the moments when there are no I/O
  ## events. Usually when there no I/O events CPU consumption should be near 0%.
  var retFuture = newFuture[void]("chronos.stepsAsync(int)")
  var counter = 0

  var continuation: proc(data: pointer) {.gcsafe, raises: [Defect].}
  continuation = proc(data: pointer) {.gcsafe, raises: [Defect].} =
    if not(retFuture.finished()):
      inc(counter)
      if counter < number:
        callSoon(continuation, nil)
      else:
        retFuture.complete()

  proc cancellation(udata: pointer) =
    discard

  if number <= 0:
    retFuture.complete()
  else:
    retFuture.cancelCallback = cancellation
    callSoon(continuation, nil)

  retFuture

proc idleAsync*(): Future[void] =
  ## Suspends the execution of the current asynchronous task until "idle" time.
  ##
  ## "idle" time its moment of time, when no network events were processed by
  ## ``poll()`` call.
  var retFuture = newFuture[void]("chronos.idleAsync()")

  proc continuation(data: pointer) {.gcsafe.} =
    if not(retFuture.finished()):
      retFuture.complete()

  proc cancellation(udata: pointer) {.gcsafe.} =
    discard

  retFuture.cancelCallback = cancellation
  callIdle(continuation, nil)
  retFuture

proc withTimeout*[T](fut: Future[T], timeout: Duration): Future[bool] =
  ## Returns a future which will complete once ``fut`` completes or after
  ## ``timeout`` milliseconds has elapsed.
  ##
  ## If ``fut`` completes first the returned future will hold true,
  ## otherwise, if ``timeout`` milliseconds has elapsed first, the returned
  ## future will hold false.
  var retFuture = newFuture[bool]("chronos.`withTimeout`")
  var moment: Moment
  var timer: TimerCallback
  var cancelling = false

  # TODO: raises annotation shouldn't be needed, but likely similar issue as
  # https://github.com/nim-lang/Nim/issues/17369
  proc continuation(udata: pointer) {.gcsafe, raises: [Defect].} =
    if not(retFuture.finished()):
      if not(cancelling):
        if not(fut.finished()):
          # Timer exceeded first, we going to cancel `fut` and wait until it
          # not completes.
          cancelling = true
          fut.cancel()
        else:
          # Future `fut` completed/failed/cancelled first.
          if not(isNil(timer)):
            clearTimer(timer)
          retFuture.complete(true)
      else:
        retFuture.complete(false)

  # TODO: raises annotation shouldn't be needed, but likely similar issue as
  # https://github.com/nim-lang/Nim/issues/17369
  proc cancellation(udata: pointer) {.gcsafe, raises: [Defect].} =
    if not isNil(timer):
      clearTimer(timer)
    if not(fut.finished()):
      fut.removeCallback(continuation)
      fut.cancel()

  if fut.finished():
    retFuture.complete(true)
  else:
    if timeout.isZero():
      retFuture.complete(false)
    elif timeout.isInfinite():
      retFuture.cancelCallback = cancellation
      fut.addCallback(continuation)
    else:
      moment = Moment.fromNow(timeout)
      retFuture.cancelCallback = cancellation
      timer = setTimer(moment, continuation, nil)
      fut.addCallback(continuation)

  return retFuture

proc withTimeout*[T](fut: Future[T], timeout: int): Future[bool] {.
     inline, deprecated: "Use withTimeout(Future[T], Duration)".} =
  result = withTimeout(fut, timeout.milliseconds())

proc wait*[T](fut: Future[T], timeout = InfiniteDuration): Future[T] =
  ## Returns a future which will complete once future ``fut`` completes
  ## or if timeout of ``timeout`` milliseconds has been expired.
  ##
  ## If ``timeout`` is ``-1``, then statement ``await wait(fut)`` is
  ## equal to ``await fut``.
  ##
  ## TODO: In case when ``fut`` got cancelled, what result Future[T]
  ## should return, because it can't be cancelled too.
  var retFuture = newFuture[T]("chronos.wait()")
  var moment: Moment
  var timer: TimerCallback
  var cancelling = false

  proc continuation(udata: pointer) {.raises: [Defect].} =
    if not(retFuture.finished()):
      if not(cancelling):
        if not(fut.finished()):
          # Timer exceeded first.
          cancelling = true
          fut.cancel()
        else:
          # Future `fut` completed/failed/cancelled first.
          if not isNil(timer):
            clearTimer(timer)

          if fut.failed():
            retFuture.fail(fut.error)
          else:
            when T is void:
              retFuture.complete()
            else:
              retFuture.complete(fut.value)
      else:
        retFuture.fail(newException(AsyncTimeoutError, "Timeout exceeded!"))

  var cancellation: proc(udata: pointer) {.gcsafe, raises: [Defect].}
  cancellation = proc(udata: pointer) {.gcsafe, raises: [Defect].} =
    if not isNil(timer):
      clearTimer(timer)
    if not(fut.finished()):
      fut.removeCallback(continuation)
      fut.cancel()

  if fut.finished():
    if fut.failed():
      retFuture.fail(fut.error)
    else:
      when T is void:
        retFuture.complete()
      else:
        retFuture.complete(fut.value)
  else:
    if timeout.isZero():
      retFuture.fail(newException(AsyncTimeoutError, "Timeout exceeded!"))
    elif timeout.isInfinite():
      retFuture.cancelCallback = cancellation
      fut.addCallback(continuation)
    else:
      moment = Moment.fromNow(timeout)
      retFuture.cancelCallback = cancellation
      timer = setTimer(moment, continuation, nil)
      fut.addCallback(continuation)

  return retFuture

proc wait*[T](fut: Future[T], timeout = -1): Future[T] {.
     inline, deprecated: "Use wait(Future[T], Duration)".} =
  if timeout == -1:
    wait(fut, InfiniteDuration)
  elif timeout == 0:
    wait(fut, ZeroDuration)
  else:
    wait(fut, timeout.milliseconds())

include asyncmacro2

proc runForever*() {.raises: [Defect, CatchableError].} =
  ## Begins a never ending global dispatcher poll loop.
  ## Raises different exceptions depending on the platform.
  while true:
    poll()

proc waitFor*[T](fut: Future[T]): T {.raises: [Defect, CatchableError].} =
  ## **Blocks** the current thread until the specified future completes.
  ## There's no way to tell if poll or read raised the exception
  while not(fut.finished()):
    poll()

  fut.read()

proc addTracker*[T](id: string, tracker: T) =
  ## Add new ``tracker`` object to current thread dispatcher with identifier
  ## ``id``.
  let loop = getThreadDispatcher()
  loop.trackers[id] = tracker

proc getTracker*(id: string): TrackerBase =
  ## Get ``tracker`` from current thread dispatcher using identifier ``id``.
  let loop = getThreadDispatcher()
  result = loop.trackers.getOrDefault(id, nil)

when chronosFutureTracking:
  iterator pendingFutures*(): FutureBase =
    ## Iterates over the list of pending Futures (Future[T] objects which not
    ## yet completed, cancelled or failed).
    var slider = futureList.head
    while not(isNil(slider)):
      yield slider
      slider = slider.next

  proc pendingFuturesCount*(): uint =
    ## Returns number of pending Futures (Future[T] objects which not yet
    ## completed, cancelled or failed).
    futureList.count

when defined(windows):
  proc waitForSingleObject*(handle: HANDLE,
                            timeout: Duration): Future[WaitableResult] {.
       raises: [Defect].} =
    ## Waits until the specified object is in the signaled state or the
    ## time-out interval elapses. WaitForSingleObject() for asynchronous world.
    let flags = WT_EXECUTEONLYONCE

    var
      retFuture = newFuture[WaitableResult]("chronos.waitForSingleObject()")
      waitHandle: WaitableHandle = nil

    proc continuation(udata: pointer) {.gcsafe.} =
      doAssert(not(isNil(waitHandle)))
      if not(retFuture.finished()):
        let
          ovl = cast[PtrCustomOverlapped](udata)
          returnFlag = WINBOOL(ovl.data.bytesCount)
          res = closeWaitable(waitHandle)
        if res.isErr():
          retFuture.fail(newException(AsyncError, osErrorMsg(res.error())))
        else:
          if returnFlag == TRUE:
            retFuture.complete(WaitableResult.Timeout)
          else:
            retFuture.complete(WaitableResult.Ok)

    proc cancellation(udata: pointer) {.gcsafe.} =
      doAssert(not(isNil(waitHandle)))
      if not(retFuture.finished()):
        discard closeWaitable(waitHandle)

    let wres = uint32(waitForSingleObject(handle, DWORD(0)))
    if wres == WAIT_OBJECT_0:
      retFuture.complete(WaitableResult.Ok)
      return retFuture
    elif wres == WAIT_ABANDONED:
      retFuture.fail(newException(AsyncError, "Handle was abandoned"))
      return retFuture
    elif wres == WAIT_FAILED:
      retFuture.fail(newException(AsyncError, osErrorMsg(osLastError())))
      return retFuture

    if timeout == ZeroDuration:
      retFuture.complete(WaitableResult.Timeout)
      return retFuture

    waitHandle =
      block:
        let res = registerWaitable(handle, flags, timeout, continuation, nil)
        if res.isErr():
          retFuture.fail(newException(AsyncError, osErrorMsg(res.error())))
          return retFuture
        res.get()

    retFuture.cancelCallback = cancellation
    return retFuture

# Perform global per-module initialization.
globalInit()
