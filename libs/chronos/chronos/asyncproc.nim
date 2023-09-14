#
#         Chronos' asynchronous process management
#
#  (c) Copyright 2022-Present Status Research & Development GmbH
#
#                Licensed under either of
#    Apache License, version 2.0, (LICENSE-APACHEv2)
#                MIT license (LICENSE-MIT)

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
  {.pragma: apforward, gcsafe, raises: [Defect].}
else:
  {.push raises: [].}
  {.pragma: apforward, gcsafe, raises: [].}

import std/strtabs
import "."/[config, asyncloop, handles, osdefs, osutils, oserrno],
           streams/asyncstream
import stew/[results, byteutils]
from std/os import quoteShell, quoteShellWindows, quoteShellPosix, envPairs

export strtabs, results
export quoteShell, quoteShellWindows, quoteShellPosix, envPairs

const
  AsyncProcessTrackerName* = "async.process"
    ## AsyncProcess leaks tracker name



type
  AsyncProcessError* = object of CatchableError

  AsyncProcessResult*[T] = Result[T, OSErrorCode]

  AsyncProcessOption* {.pure.} = enum
    UsePath,
    EvalCommand,
    StdErrToStdOut,
    ProcessGroup

  StandardKind {.pure.} = enum
    Stdin, Stdout, Stderr

  ProcessFlag {.pure.} = enum
    UserStdin, UserStdout, UserStderr,
    AutoStdin, AutoStdout, AutoStderr,
    NoStdin, NoStdout, NoStderr,
    CopyStdout

  ProcessStreamHandleKind {.pure.} = enum
    None, Auto, ProcHandle, Transport, StreamReader, StreamWriter

  ProcessStreamHandle* = object
    case kind: ProcessStreamHandleKind
    of ProcessStreamHandleKind.None:
      discard
    of ProcessStreamHandleKind.Auto:
      discard
    of ProcessStreamHandleKind.ProcHandle:
      handle: AsyncFD
    of ProcessStreamHandleKind.Transport:
      transp: StreamTransport
    of ProcessStreamHandleKind.StreamReader:
      reader: AsyncStreamReader
    of ProcessStreamHandleKind.StreamWriter:
      writer: AsyncStreamWriter

  StreamHolderFlag {.pure.} = enum
    Transport, Stream

  StreamKind {.pure.} = enum
    None, Reader, Writer

  AsyncStreamHolder = object
    case kind: StreamKind
    of StreamKind.Reader:
      reader: AsyncStreamReader
    of StreamKind.Writer:
      writer: AsyncStreamWriter
    of StreamKind.None:
      discard
    flags: set[StreamHolderFlag]

  AsyncProcessPipes = object
    flags: set[ProcessFlag]
    stdinHolder: AsyncStreamHolder
    stdoutHolder: AsyncStreamHolder
    stderrHolder: AsyncStreamHolder
    stdinHandle: AsyncFD
    stdoutHandle: AsyncFD
    stderrHandle: AsyncFD

  AsyncProcess* = object

  AsyncProcessImpl = object of RootObj
    when defined(windows):
      processHandle: HANDLE
      threadHandle: HANDLE
      processId: DWORD
    else:
      processId: Pid
    pipes: AsyncProcessPipes
    exitStatus: Opt[int]
    flags: set[ProcessFlag]
    options: set[AsyncProcessOption]

  AsyncProcessRef* = ref AsyncProcessImpl

  CommandExResponse* = object
    stdOutput*: string
    stdError*: string
    status*: int

  AsyncProcessTracker* = ref object of TrackerBase
    opened*: int64
    closed*: int64

template Pipe*(t: typedesc[AsyncProcess]): ProcessStreamHandle =
  ProcessStreamHandle(kind: ProcessStreamHandleKind.Auto)

proc setupAsyncProcessTracker(): AsyncProcessTracker {.gcsafe.}

proc getAsyncProcessTracker(): AsyncProcessTracker {.inline.} =
  var res = cast[AsyncProcessTracker](getTracker(AsyncProcessTrackerName))
  if isNil(res):
    res = setupAsyncProcessTracker()
  res

proc dumpAsyncProcessTracking(): string {.gcsafe.} =
  var tracker = getAsyncProcessTracker()
  let res = "Started async processes: " & $tracker.opened & "\n" &
            "Closed async processes: " & $tracker.closed
  res

proc leakAsyncProccessTracker(): bool {.gcsafe.} =
  var tracker = getAsyncProcessTracker()
  tracker.opened != tracker.closed

proc trackAsyncProccess(t: AsyncProcessRef) {.inline.} =
  var tracker = getAsyncProcessTracker()
  inc(tracker.opened)

proc untrackAsyncProcess(t: AsyncProcessRef) {.inline.}  =
  var tracker = getAsyncProcessTracker()
  inc(tracker.closed)

proc setupAsyncProcessTracker(): AsyncProcessTracker {.gcsafe.} =
  var res = AsyncProcessTracker(
    opened: 0,
    closed: 0,
    dump: dumpAsyncProcessTracking,
    isLeaked: leakAsyncProccessTracker
  )
  addTracker(AsyncProcessTrackerName, res)
  res

proc init*(t: typedesc[AsyncFD], handle: ProcessStreamHandle): AsyncFD =
  case handle.kind
  of ProcessStreamHandleKind.ProcHandle:
    handle.handle
  of ProcessStreamHandleKind.Transport:
    handle.transp.fd
  of ProcessStreamHandleKind.StreamReader:
    doAssert(not(isNil(handle.reader.tsource)))
    handle.reader.tsource.fd
  of ProcessStreamHandleKind.StreamWriter:
    doAssert(not(isNil(handle.writer.tsource)))
    handle.writer.tsource.fd
  of ProcessStreamHandleKind.Auto:
    raiseAssert "ProcessStreamHandle could not be auto at this moment"
  of ProcessStreamHandleKind.None:
    raiseAssert "ProcessStreamHandle could not be empty at this moment"

proc init*(t: typedesc[AsyncStreamHolder], handle: AsyncStreamReader,
           baseFlags: set[StreamHolderFlag] = {}): AsyncStreamHolder =
  AsyncStreamHolder(kind: StreamKind.Reader, reader: handle, flags: baseFlags)

proc init*(t: typedesc[AsyncStreamHolder], handle: AsyncStreamWriter,
           baseFlags: set[StreamHolderFlag] = {}): AsyncStreamHolder =
  AsyncStreamHolder(kind: StreamKind.Writer, writer: handle, flags: baseFlags)

proc init*(t: typedesc[AsyncStreamHolder]): AsyncStreamHolder =
  AsyncStreamHolder(kind: StreamKind.None)

proc init*(t: typedesc[AsyncStreamHolder], handle: ProcessStreamHandle,
           kind: StreamKind, baseFlags: set[StreamHolderFlag] = {}
          ): AsyncProcessResult[AsyncStreamHolder] =
  case handle.kind
  of ProcessStreamHandleKind.ProcHandle:
    case kind
    of StreamKind.Reader:
      let
        transp = ? fromPipe2(handle.handle)
        reader = newAsyncStreamReader(transp)
        flags = baseFlags + {StreamHolderFlag.Stream,
                             StreamHolderFlag.Transport}
      ok(AsyncStreamHolder(kind: StreamKind.Reader, reader: reader,
                           flags: flags))
    of StreamKind.Writer:
      let
        transp = ? fromPipe2(handle.handle)
        writer = newAsyncStreamWriter(transp)
        flags = baseFlags + {StreamHolderFlag.Stream,
                             StreamHolderFlag.Transport}
      ok(AsyncStreamHolder(kind: StreamKind.Writer, writer: writer,
                           flags: flags))
    of StreamKind.None:
      ok(AsyncStreamHolder(kind: StreamKind.None))
  of ProcessStreamHandleKind.Transport:
    case kind
    of StreamKind.Reader:
      let
        reader = newAsyncStreamReader(handle.transp)
        flags = baseFlags + {StreamHolderFlag.Stream}
      ok(AsyncStreamHolder(kind: StreamKind.Reader, reader: reader,
                           flags: flags))
    of StreamKind.Writer:
      let
        writer = newAsyncStreamWriter(handle.transp)
        flags = baseFlags + {StreamHolderFlag.Stream}
      ok(AsyncStreamHolder(kind: StreamKind.Writer, writer: writer,
                           flags: flags))
    of StreamKind.None:
      ok(AsyncStreamHolder(kind: StreamKind.None))
  of ProcessStreamHandleKind.StreamReader:
    ok(AsyncStreamHolder(kind: StreamKind.Reader, reader: handle.reader,
                         flags: baseFlags))
  of ProcessStreamHandleKind.StreamWriter:
    ok(AsyncStreamHolder(kind: StreamKind.Writer, writer: handle.writer,
                         flags: baseFlags))
  of ProcessStreamHandleKind.None, ProcessStreamHandleKind.Auto:
    ok(AsyncStreamHolder(kind: StreamKind.None))

proc init*(t: typedesc[ProcessStreamHandle]): ProcessStreamHandle =
  ProcessStreamHandle(kind: ProcessStreamHandleKind.None)

proc init*(t: typedesc[ProcessStreamHandle],
           handle: AsyncFD): ProcessStreamHandle =
  ProcessStreamHandle(kind: ProcessStreamHandleKind.ProcHandle, handle: handle)

proc init*(t: typedesc[ProcessStreamHandle],
           transp: StreamTransport): ProcessStreamHandle =
  doAssert(transp.kind == TransportKind.Pipe,
           "Only pipe transports can be used as process streams")
  ProcessStreamHandle(kind: ProcessStreamHandleKind.ProcHandle, transp: transp)

proc init*(t: typedesc[ProcessStreamHandle],
           reader: AsyncStreamReader): ProcessStreamHandle =
  ProcessStreamHandle(kind: ProcessStreamHandleKind.StreamReader,
                      reader: reader)

proc init*(t: typedesc[ProcessStreamHandle],
           writer: AsyncStreamWriter): ProcessStreamHandle =
  ProcessStreamHandle(kind: ProcessStreamHandleKind.StreamWriter,
                      writer: writer)

proc isEmpty*(handle: ProcessStreamHandle): bool =
  handle.kind == ProcessStreamHandleKind.None

proc suspend*(p: AsyncProcessRef): AsyncProcessResult[void] {.apforward.}
proc resume*(p: AsyncProcessRef): AsyncProcessResult[void] {.apforward.}
proc terminate*(p: AsyncProcessRef): AsyncProcessResult[void] {.apforward.}
proc kill*(p: AsyncProcessRef): AsyncProcessResult[void] {.apforward.}
proc running*(p: AsyncProcessRef): AsyncProcessResult[bool] {.apforward.}
proc peekExitCode*(p: AsyncProcessRef): AsyncProcessResult[int] {.apforward.}
proc preparePipes(options: set[AsyncProcessOption],
                  stdinHandle, stdoutHandle, stderrHandle: ProcessStreamHandle
                 ): AsyncProcessResult[AsyncProcessPipes] {.apforward.}
proc closeProcessHandles(pipes: var AsyncProcessPipes,
                         options: set[AsyncProcessOption],
                         lastError: OSErrorCode): OSErrorCode {.apforward.}
proc closeProcessStreams(pipes: AsyncProcessPipes,
                         options: set[AsyncProcessOption]): Future[void] {.
     apforward.}
proc closeWait(holder: AsyncStreamHolder): Future[void] {.apforward.}

template isOk(code: OSErrorCode): bool =
  when defined(windows):
    code == ERROR_SUCCESS
  else:
    code == OSErrorCode(0)

template closePipe(handle: AsyncFD): bool =
  let fd =
    when defined(windows):
      osdefs.HANDLE(handle)
    else:
      cint(handle)
  closeFd(fd) != -1

proc closeProcessHandles(pipes: var AsyncProcessPipes,
                         options: set[AsyncProcessOption],
                         lastError: OSErrorCode): OSErrorCode =
  # We trying to preserve error code of last failed operation.
  var currentError = lastError

  if ProcessFlag.AutoStdin in pipes.flags:
    if pipes.stdinHandle != asyncInvalidPipe:
      if currentError.isOk():
        if not(closePipe(pipes.stdinHandle)):
          currentError = osLastError()
      else:
        discard closePipe(pipes.stdinHandle)
      pipes.stdinHandle = asyncInvalidPipe

  if ProcessFlag.AutoStdout in pipes.flags:
    if pipes.stdoutHandle != asyncInvalidPipe:
      if currentError.isOk():
        if not(closePipe(pipes.stdoutHandle)):
          currentError = osLastError()
      else:
        discard closePipe(pipes.stdoutHandle)
      pipes.stdoutHandle = asyncInvalidPipe

  if ProcessFlag.AutoStderr in pipes.flags:
    if pipes.stderrHandle != asyncInvalidPipe:
      if currentError.isOk():
        if not(closePipe(pipes.stderrHandle)):
          currentError = osLastError()
      else:
        discard closePipe(pipes.stderrHandle)
      pipes.stderrHandle = asyncInvalidPipe

  currentError

template pipesPresent*(pipes: AsyncProcessPipes): bool =
  let mask = {ProcessFlag.AutoStdin, ProcessFlag.AutoStdout,
              ProcessFlag.AutoStderr,ProcessFlag.UserStdin,
              ProcessFlag.UserStdout, ProcessFlag.UserStderr}
  pipes.flags * mask != {}

proc raiseAsyncProcessError(msg: string, exc: ref CatchableError = nil) {.
     noreturn, noinit, noinline, raises: [AsyncProcessError].} =
  let message =
    if isNil(exc):
      msg
    else:
      msg & " ([" & $exc.name & "]: " & $exc.msg & ")"
  raise newException(AsyncProcessError, message)

proc raiseAsyncProcessError(msg: string, error: OSErrorCode|cint) {.
     noreturn, noinit, noinline, raises: [AsyncProcessError].} =
  when error is OSErrorCode:
    let message = msg & " ([OSError]: " & osErrorMsg(error) & ")"
  else:
    let message = msg & " ([OSError]: " & osErrorMsg(OSErrorCode(error)) & ")"
  raise newException(AsyncProcessError, message)

when defined(windows):

  proc getStdinHandle(pipes: AsyncProcessPipes): HANDLE =
    if pipes.flags * {ProcessFlag.AutoStdin, ProcessFlag.UserStdin} != {}:
      HANDLE(pipes.stdinHandle)
    else:
      getStdHandle(STD_INPUT_HANDLE)

  proc getStdoutHandle(pipes: AsyncProcessPipes): HANDLE =
    if pipes.flags * {ProcessFlag.AutoStdout, ProcessFlag.UserStdout} != {}:
      HANDLE(pipes.stdoutHandle)
    else:
      getStdHandle(STD_OUTPUT_HANDLE)

  proc getStderrHandle(pipes: AsyncProcessPipes): HANDLE =
    if pipes.flags * {ProcessFlag.AutoStderr, ProcessFlag.UserStderr,
                      ProcessFlag.CopyStdout} != {}:
      HANDLE(pipes.stderrHandle)
    else:
      getStdHandle(STD_ERROR_HANDLE)

  proc getProcessEnvironment*(): StringTableRef =
    var res = newStringTable(modeCaseInsensitive)
    var env = getEnvironmentStringsW()
    if isNil(env):
      return res
    var slider = env
    while int(slider[]) != 0:
      let pos = wcschr(slider, WCHAR(0x0000))
      let line = slider.toString().valueOr("")
      slider = cast[LPWSTR](cast[uint](pos) + uint(sizeof(WCHAR)))
      if len(line) > 0:
        let delim = line.find('=')
        if delim > 0:
          res[substr(line, 0, delim - 1)] = substr(line, delim + 1)
    discard freeEnvironmentStringsW(env)
    res

  proc buildCommandLine(a: string, args: openArray[string]): string =
    # TODO: Procedures quoteShell/(Windows, Posix)() needs security and bug review
    # or reimplementation, for example quoteShellWindows() do not handle `\`
    # properly.
    # https://docs.microsoft.com/en-us/cpp/cpp/main-function-command-line-args?redirectedfrom=MSDN&view=msvc-170#parsing-c-command-line-arguments
    var res = quoteShell(a)
    for i in 0 ..< len(args):
      res.add(' ')
      res.add(quoteShell(args[i]))
    res

  proc buildEnvironment(env: StringTableRef): Result[LPWSTR, OSErrorCode] =
    var str: string
    for key, value in pairs(env):
      doAssert('=' notin key, "`=` must not be present in key name")
      str.add(key)
      str.add('=')
      str.add(value)
      str.add('\x00')
    str.add("\x00\x00")
    toWideString(str)

  proc closeThreadAndProcessHandle(p: AsyncProcessRef
                                  ): AsyncProcessResult[void] =
    if p.threadHandle != HANDLE(0):
      if closeHandle(p.threadHandle) == FALSE:
        discard closeHandle(p.processHandle)
        return err(osLastError())
      p.threadHandle = HANDLE(0)

    if p.processHandle != HANDLE(0):
      if closeHandle(p.processHandle) == FALSE:
        return err(osLastError())
      p.processHandle = HANDLE(0)

  proc startProcess*(command: string, workingDir: string = "",
                     arguments: seq[string] = @[],
                     environment: StringTableRef = nil,
                     options: set[AsyncProcessOption] = {},
                     stdinHandle = ProcessStreamHandle(),
                     stdoutHandle = ProcessStreamHandle(),
                     stderrHandle = ProcessStreamHandle(),
                    ): Future[AsyncProcessRef] {.async.} =
    var
      pipes = preparePipes(options, stdinHandle, stdoutHandle,
                           stderrHandle).valueOr:
        raiseAsyncProcessError("Unable to initialze process pipes", error)

    let
      commandLine =
        if AsyncProcessOption.EvalCommand in options:
          chronosProcShell & " /C " & command
        else:
          buildCommandLine(command, arguments)
      workingDirectory =
        if len(workingDir) > 0:
          workingDir.toWideString().valueOr:
            raiseAsyncProcessError("Unable to proceed working directory path",
                                   error)
        else:
          nil
      environment =
        if not(isNil(environment)):
          buildEnvironment(environment).valueOr:
            raiseAsyncProcessError("Unable to build child process environment",
                                   error)
        else:
          nil
      flags = CREATE_UNICODE_ENVIRONMENT
    var
      psa = getSecurityAttributes(false)
      tsa = getSecurityAttributes(false)
      startupInfo =
        block:
          var res = STARTUPINFO(cb: DWORD(sizeof(STARTUPINFO)))
          if pipes.pipesPresent():
            res.dwFlags = STARTF_USESTDHANDLES
            res.hStdInput = pipes.getStdinHandle()
            res.hStdOutput = pipes.getStdoutHandle()
            res.hStdError = pipes.getStderrHandle()
          res
      procInfo = PROCESS_INFORMATION()

    let wideCommandLine = commandLine.toWideString().valueOr:
      raiseAsyncProcessError("Unable to proceed command line", error)

    let res = createProcess(
      nil,
      wideCommandLine,
      addr psa, addr tsa,
      TRUE, # NOTE: This is very important flag and MUST not be modified.
            # All overloaded pipe handles will not work if this flag will be
            # set to FALSE.
      flags,
      environment,
      workingDirectory,
      startupInfo, procInfo
    )

    if(not(isNil(environment))):
      free(environment)
    free(wideCommandLine)

    var currentError = osLastError()
    if res == FALSE:
      await pipes.closeProcessStreams(options)
    currentError = closeProcessHandles(pipes, options, currentError)

    if res == FALSE:
      raiseAsyncProcessError("Unable to spawn process", currentError)

    let process = AsyncProcessRef(
      processHandle: procInfo.hProcess,
      threadHandle: procInfo.hThread,
      processId: procInfo.dwProcessId,
      pipes: pipes,
      options: options,
      flags: pipes.flags
    )

    trackAsyncProccess(process)
    return process

  proc peekProcessExitCode(p: AsyncProcessRef): AsyncProcessResult[int] =
    var wstatus: DWORD = 0
    if p.exitStatus.isSome():
      return ok(p.exitStatus.get())

    let res = getExitCodeProcess(p.processHandle, wstatus)
    if res == TRUE:
      if wstatus != STILL_ACTIVE:
        let status = int(wstatus)
        p.exitStatus = Opt.some(status)
        ok(status)
      else:
        ok(-1)
    else:
      err(osLastError())

  proc suspend(p: AsyncProcessRef): AsyncProcessResult[void] =
    if suspendThread(p.threadHandle) != 0xFFFF_FFFF'u32:
      ok()
    else:
      err(osLastError())

  proc resume(p: AsyncProcessRef): AsyncProcessResult[void] =
    if resumeThread(p.threadHandle) != 0xFFFF_FFFF'u32:
      ok()
    else:
      err(osLastError())

  proc terminate(p: AsyncProcessRef): AsyncProcessResult[void] =
    if terminateProcess(p.processHandle, 0) != 0'u32:
      ok()
    else:
      err(osLastError())

  proc kill(p: AsyncProcessRef): AsyncProcessResult[void] =
    p.terminate()

  proc running(p: AsyncProcessRef): AsyncProcessResult[bool] =
    let res = ? p.peekExitCode()
    if res == -1:
      ok(true)
    else:
      ok(false)

  proc waitForExit*(p: AsyncProcessRef,
                    timeout = InfiniteDuration): Future[int] {.async.} =
    if p.exitStatus.isSome():
      return p.exitStatus.get()

    let wres =
      try:
        await waitForSingleObject(p.processHandle, timeout)
      except ValueError as exc:
        raiseAsyncProcessError("Unable to wait for process handle", exc)

    if wres == WaitableResult.Timeout:
      let res = p.kill()
      if res.isErr():
        raiseAsyncProcessError("Unable to terminate process", res.error())

    let exitCode = p.peekProcessExitCode().valueOr:
      raiseAsyncProcessError("Unable to peek process exit code", error)

    if exitCode >= 0:
      p.exitStatus = Opt.some(exitCode)
    return exitCode

  proc peekExitCode(p: AsyncProcessRef): AsyncProcessResult[int] =
    if p.exitStatus.isSome():
      return ok(p.exitStatus.get())
    let res = waitForSingleObject(p.processHandle, DWORD(0))
    if res != WAIT_TIMEOUT:
      let exitCode = ? p.peekProcessExitCode()
      ok(exitCode)
    else:
      ok(-1)
else:
  import std/strutils

  type
    SpawnAttr = object
      attrs: PosixSpawnAttr
      actions: PosixSpawnFileActions

  proc fd(h: AsyncStreamHolder): cint =
    case h.kind
    of StreamKind.Reader:
      cint(h.reader.tsource.fd)
    of StreamKind.Writer:
      cint(h.writer.tsource.fd)
    of StreamKind.None:
      raiseAssert "Incorrect stream holder"

  proc isEmpty(h: AsyncStreamHolder): bool =
    h.kind == StreamKind.None

  proc initSpawn(pipes: AsyncProcessPipes, options: set[AsyncProcessOption]
                ): Result[SpawnAttr, OSErrorCode] =
    template doCheck(body: untyped): untyped =
      let res = body
      if res != 0:
        return err(OSErrorCode(res))

    var
      attrs =
        block:
          var value: PosixSpawnAttr
          let res = posixSpawnAttrInit(value)
          if res != 0:
            return err(OSErrorCode(res))
          value
      actions =
        block:
          var value: PosixSpawnFileActions
          let res = posixSpawnFileActionsInit(value)
          if res != 0:
            discard posixSpawnAttrDestroy(attrs)
            return err(OSErrorCode(res))
          value
      mask =
        block:
          var res: Sigset
          discard sigemptyset(res)
          res

    doCheck(posixSpawnAttrSetSigMask(attrs, mask))
    if AsyncProcessOption.ProcessGroup in options:
      doCheck(posixSpawnAttrSetPgroup(attrs, 0))
      doCheck(posixSpawnAttrSetFlags(attrs, osdefs.POSIX_SPAWN_USEVFORK or
                                     osdefs.POSIX_SPAWN_SETSIGMASK or
                                     osdefs.POSIX_SPAWN_SETPGROUP))
    else:
      doCheck(posixSpawnAttrSetFlags(attrs, osdefs.POSIX_SPAWN_USEVFORK or
                                     osdefs.POSIX_SPAWN_SETSIGMASK))

    if pipes.flags * {ProcessFlag.AutoStdin, ProcessFlag.UserStdin} != {}:
      # Close child process STDIN.
      doCheck(posixSpawnFileActionsAddClose(actions, cint(0)))
      # Make a duplicate of `stdinHandle` as child process STDIN.
      doCheck(posixSpawnFileActionsAddDup2(actions, cint(pipes.stdinHandle),
                                           cint(0)))
      # Close child process side of `stdinHandle`.
      doCheck(posixSpawnFileActionsAddClose(actions,
                                            cint(pipes.stdinHandle)))
      # Close parent process side of `stdinHandle`.
      if not(pipes.stdinHolder.isEmpty()):
        let fd = cint(pipes.stdinHolder.fd())
        doCheck(posixSpawnFileActionsAddClose(actions, fd))

    if pipes.flags * {ProcessFlag.AutoStdout, ProcessFlag.UserStdout} != {}:
      # Close child process STDOUT.
      doCheck(posixSpawnFileActionsAddClose(actions, cint(1)))
      # Make a duplicate of `stdoutHandle` as child process STDOUT.
      doCheck(posixSpawnFileActionsAddDup2(actions, cint(pipes.stdoutHandle),
                                           cint(1)))
      if AsyncProcessOption.StdErrToStdOut notin options:
        # Close child process side of `stdoutHandle`.
        doCheck(posixSpawnFileActionsAddClose(actions,
                                              cint(pipes.stdoutHandle)))
        # Close parent process side of `stdoutHandle`.
        if not(pipes.stdoutHolder.isEmpty()):
          let fd = cint(pipes.stdoutHolder.fd())
          doCheck(posixSpawnFileActionsAddClose(actions, fd))

    if pipes.flags * {ProcessFlag.AutoStderr, ProcessFlag.UserStderr} != {}:
      # Close child process STDERR.
      doCheck(posixSpawnFileActionsAddClose(actions, cint(2)))
      # Make a duplicate of `stderrHandle` as child process STDERR.
      doCheck(posixSpawnFileActionsAddDup2(actions, cint(pipes.stderrHandle),
                                           cint(2)))
      # Close child process side of `stderrHandle`.
      doCheck(posixSpawnFileActionsAddClose(actions,
                                            cint(pipes.stderrHandle)))
      # Close parent process side of `stderrHandle`.
      if not(pipes.stderrHolder.isEmpty()):
        let fd = cint(pipes.stderrHolder.fd())
        doCheck(posixSpawnFileActionsAddClose(actions, fd))
    else:
      if AsyncProcessOption.StdErrToStdOut in options:
        # Close child process STDERR.
        doCheck(posixSpawnFileActionsAddClose(actions, cint(2)))
        # Make a duplicate of `stdoutHandle` as child process STDERR.
        doCheck(posixSpawnFileActionsAddDup2(actions, cint(pipes.stdoutHandle),
                                             cint(2)))
        # Close child process side of `stdoutHandle`.
        doCheck(posixSpawnFileActionsAddClose(actions,
                                              cint(pipes.stdoutHandle)))
        # Close parent process side of `stdoutHandle`.
        if not(pipes.stdoutHolder.isEmpty()):
          let fd = cint(pipes.stdoutHolder.fd())
          doCheck(posixSpawnFileActionsAddClose(actions, fd))
    ok(SpawnAttr(attrs: attrs, actions: actions))

  proc free(v: var SpawnAttr): Result[void, OSErrorCode] =
    block:
      let res = posixSpawnAttrDestroy(v.attrs)
      if res != 0:
        discard posixSpawnFileActionsDestroy(v.actions)
        return err(OSErrorCode(res))
    block:
      let res = posixSpawnFileActionsDestroy(v.actions)
      if res != 0:
        return err(OSErrorCode(res))
    ok()

  proc getKeyValueItem(key: string, value: string): cstring =
    var p = cast[cstring](alloc(len(key) + len(value) + 1 + 1))
    var offset = 0
    if len(key) > 0:
      copyMem(addr p[offset], unsafeAddr(key[0]), len(key))
      inc(offset, len(key))
    p[offset] = '='
    inc(offset)
    if len(value) > 0:
      copyMem(addr p[offset], unsafeAddr(value[0]), len(value))
      inc(offset, len(value))
    p[offset] = '\x00'
    p

  proc envToCStringArray(t: StringTableRef): cstringArray =
    let itemsCount = len(t)
    var
      res = cast[cstringArray](alloc((itemsCount + 1) * sizeof(cstring)))
      i = 0
    for key, value in pairs(t):
      res[i] = getKeyValueItem(key, value)
      inc(i)
    res[i] = nil # Last item in CStringArray should be `nil`.
    res

  proc envToCStringArray(): cstringArray =
    let itemsCount =
      block:
        var res = 0
        for key, value in envPairs(): inc(res)
        res
    var
      res = cast[cstringArray](alloc((itemsCount + 1) * sizeof(cstring)))
      i = 0
    for key, value in envPairs():
      res[i] = getKeyValueItem(key, value)
      inc(i)
    res[i] = nil # Last item in CStringArray should be `nil`.
    res

  when defined(macosx) or defined(macos) or defined(ios):
    proc getEnvironment(): ptr cstringArray {.
      importc: "_NSGetEnviron", header: "<crt_externs.h>".}
  else:
    var globalEnv {.importc: "environ", header: "<unistd.h>".}: cstringArray

  proc getProcessEnvironment*(): StringTableRef =
    var res = newStringTable(modeCaseInsensitive)
    let env =
      when defined(macosx) or defined(macos) or defined(ios):
        getEnvironment()[]
      else:
        globalEnv
    var i = 0
    while not(isNil(env[i])):
      let line = $env[i]
      if len(line) > 0:
        let delim = line.find('=')
        if delim > 0:
          res[substr(line, 0, delim - 1)] = substr(line, delim + 1)
      inc(i)
    res

  func exitStatusLikeShell(status: int): int =
    if WAITIFSIGNALED(cint(status)):
      # like the shell!
      128 + WAITTERMSIG(cint(status))
    else:
      WAITEXITSTATUS(cint(status))

  proc getCurrentDirectory(): AsyncProcessResult[string] =
    var bufsize = 1024
    var res = newString(bufsize)

    proc strLength(a: string): int {.nimcall.} =
      for i in 0 ..< len(a):
        if a[i] == '\x00':
          return i
      len(a)

    while true:
      if osdefs.getcwd(cstring(res), bufsize) != nil:
        setLen(res, strLength(res))
        return ok(res)
      else:
        let errorCode = osLastError()
        if errorCode == oserrno.ERANGE:
          bufsize = bufsize shl 1
          doAssert(bufsize >= 0)
          res = newString(bufsize)
        else:
          return err(errorCode)

  proc setCurrentDirectory(dir: string): AsyncProcessResult[void] =
    let res = osdefs.chdir(cstring(dir))
    if res == -1:
      return err(osLastError())
    ok()

  proc closeThreadAndProcessHandle(p: AsyncProcessRef
                                  ): AsyncProcessResult[void] =
    discard

  proc startProcess*(command: string, workingDir: string = "",
                     arguments: seq[string] = @[],
                     environment: StringTableRef = nil,
                     options: set[AsyncProcessOption] = {},
                     stdinHandle = ProcessStreamHandle(),
                     stdoutHandle = ProcessStreamHandle(),
                     stderrHandle = ProcessStreamHandle(),
                    ): Future[AsyncProcessRef] {.async.} =
    var
      pid: Pid
      pipes = preparePipes(options, stdinHandle, stdoutHandle,
                           stderrHandle).valueOr:
        raiseAsyncProcessError("Unable to initialze process pipes",
                               error)
      sa = pipes.initSpawn(options).valueOr:
        discard closeProcessHandles(pipes, options, OSErrorCode(0))
        await pipes.closeProcessStreams(options)
        raiseAsyncProcessError("Unable to initalize spawn attributes", 0)

    let
      (commandLine, commandArguments) =
        if AsyncProcessOption.EvalCommand in options:
          let args = @[chronosProcShell, "-c", command]
          (chronosProcShell, allocCStringArray(args))
        else:
          var res = @[command]
          for arg in arguments.items():
            res.add(arg)
          (command, allocCStringArray(res))
      commandEnv =
        if isNil(environment):
          envToCStringArray()
        else:
          envToCStringArray(environment)

    var currentError: OSErrorCode
    var currentDir: string

    try:
      currentDir =
        if len(workingDir) > 0:
          # Save current working directory and change it to `workingDir`.
          let cres = getCurrentDirectory()
          if cres.isErr():
            raiseAsyncProcessError("Unable to obtain current directory",
                                   cres.error())
          let sres = setCurrentDirectory(workingDir)
          if sres.isErr():
            raiseAsyncProcessError("Unable to change current directory",
                                   sres.error())
          cres.get()
        else:
          ""

      let res =
        if AsyncProcessOption.UsePath in options:
          posixSpawnp(pid, cstring(commandLine), sa.actions, sa.attrs,
                      commandArguments, commandEnv)
        else:
          posixSpawn(pid, cstring(commandLine), sa.actions, sa.attrs,
                     commandArguments, commandEnv)

      if res != 0:
        await pipes.closeProcessStreams(options)
      currentError = closeProcessHandles(pipes, options, OSErrorCode(res))

    finally:
      # Restore working directory
      if (len(workingDir) > 0) and (len(currentDir) > 0):
        # Restore working directory.
        let cres = getCurrentDirectory()
        if cres.isErr():
          # On error we still try to restore original working directory.
          if currentError.isOk():
            currentError = cres.error()
          discard setCurrentDirectory(currentDir)
        else:
          if cres.get() != currentDir:
            let sres = setCurrentDirectory(currentDir)
            if sres.isErr():
              if currentError.isOk():
                currentError = sres.error()

      # Cleanup allocated memory
      deallocCStringArray(commandArguments)
      deallocCStringArray(commandEnv)

      # Cleanup posix_spawn attributes and file operations
      if not(currentError.isOk()):
        discard sa.free()
      else:
        let res = sa.free()
        if res.isErr():
          currentError = res.error()

      # If currentError has been set, raising an exception.
      if not(currentError.isOk()):
        raiseAsyncProcessError("Unable to spawn process", currentError)

    let process = AsyncProcessRef(
      processId: pid,
      pipes: pipes,
      options: options,
      flags: pipes.flags
    )

    trackAsyncProccess(process)
    return process

  proc peekProcessExitCode(p: AsyncProcessRef,
                           reap = false): AsyncProcessResult[int] =
    var wstatus: cint = 0
    if p.exitStatus.isSome():
      return ok(p.exitStatus.get())
    let
      flags = if reap: cint(0) else: osdefs.WNOHANG
      waitRes =
        block:
          var res: cint = 0
          while true:
            res = osdefs.waitpid(p.processId, wstatus, flags)
            if not((res == -1) and (osLastError() == oserrno.EINTR)):
              break
          res
    if waitRes == p.processId:
      if WAITIFEXITED(wstatus) or WAITIFSIGNALED(wstatus):
        let status = int(wstatus)
        p.exitStatus = Opt.some(status)
        ok(status)
      else:
        ok(-1)
    elif waitRes == 0:
      ok(-1)
    else:
      err(osLastError())

  proc suspend(p: AsyncProcessRef): AsyncProcessResult[void] =
    if osdefs.kill(p.processId, osdefs.SIGSTOP) == 0:
      ok()
    else:
      err(osLastError())

  proc resume(p: AsyncProcessRef): AsyncProcessResult[void] =
    if osdefs.kill(p.processId, osdefs.SIGCONT) == 0:
      ok()
    else:
      err(osLastError())

  proc terminate(p: AsyncProcessRef): AsyncProcessResult[void] =
    if osdefs.kill(p.processId, osdefs.SIGTERM) == 0:
      ok()
    else:
      err(osLastError())

  proc kill(p: AsyncProcessRef): AsyncProcessResult[void] =
    if osdefs.kill(p.processId, osdefs.SIGKILL) == 0:
      ok()
    else:
      err(osLastError())

  proc running(p: AsyncProcessRef): AsyncProcessResult[bool] =
    let res = ? p.peekProcessExitCode()
    if res == -1:
      ok(true)
    else:
      ok(false)

  proc waitForExit*(p: AsyncProcessRef,
                    timeout = InfiniteDuration): Future[int] =
    var
      retFuture = newFuture[int]("chronos.waitForExit()")
      processHandle: ProcessHandle
      timer: TimerCallback = nil

    if p.exitStatus.isSome():
      retFuture.complete(p.exitStatus.get())
      return retFuture

    if timeout == ZeroDuration:
      let res = p.kill()
      if res.isErr():
        retFuture.fail(newException(AsyncProcessError, osErrorMsg(res.error())))
        return retFuture

    block:
      let exitCode = p.peekProcessExitCode().valueOr:
        retFuture.fail(newException(AsyncProcessError, osErrorMsg(error)))
        return retFuture
      if exitCode != -1:
        retFuture.complete(exitStatusLikeShell(exitCode))
        return retFuture

    if timeout == ZeroDuration:
      retFuture.complete(-1)
      return retFuture

    proc continuation(udata: pointer) {.gcsafe.} =
      let source = cast[int](udata)
      if not(retFuture.finished()):
        if source == 1:
          # Process exited.
          let res = removeProcess2(processHandle)
          if res.isErr():
            retFuture.fail(newException(AsyncProcessError,
                                        osErrorMsg(res.error())))
            return
          if not(isNil(timer)):
            clearTimer(timer)
          let exitCode = p.peekProcessExitCode().valueOr:
            retFuture.fail(newException(AsyncProcessError, osErrorMsg(error)))
            return
          if exitCode == -1:
            retFuture.complete(-1)
          else:
            retFuture.complete(exitStatusLikeShell(exitCode))
        else:
          # Timeout exceeded.
          let res = p.kill()
          if res.isErr():
            retFuture.fail(newException(AsyncProcessError,
                                        osErrorMsg(res.error())))

    proc cancellation(udata: pointer) {.gcsafe.} =
      if not(retFuture.finished()):
        if not(isNil(timer)):
          clearTimer(timer)
        # Ignore any errors because of cancellation.
        discard removeProcess2(processHandle)

    if timeout != InfiniteDuration:
      timer = setTimer(Moment.fromNow(timeout), continuation, cast[pointer](2))

    processHandle = addProcess2(int(p.processId), continuation,
                                cast[pointer](1)).valueOr:
      if error == oserrno.ESRCH:
        # "zombie death race" problem.
        # If process exited right after `waitpid()` - `kqueue` call
        # could return ESRCH error. So we need to handle it properly and
        # try to reap process code from exiting process.
        let exitCode = p.peekProcessExitCode(true).valueOr:
          retFuture.fail(newException(AsyncProcessError, osErrorMsg(error)))
          return retFuture
        if exitCode == -1:
          # This should not be happens one more time, so we just report
          # original error.
          retFuture.fail(newException(AsyncProcessError,
                         osErrorMsg(oserrno.ESRCH)))
        else:
          retFuture.complete(exitStatusLikeShell(exitCode))
      else:
        retFuture.fail(newException(AsyncProcessError, osErrorMsg(error)))
      return retFuture

    # addProcess2() has race condition problem inside. Its possible that child
    # process (we going to wait) sends SIGCHLD right after addProcess2() blocks
    # signals and before it starts monitoring for signal (`signalfd` or
    # `kqueue`). To avoid this problem we going to check process for completion
    # one more time.
    block:
      let exitCode = p.peekProcessExitCode().valueOr:
        discard removeProcess2(processHandle)
        retFuture.fail(newException(AsyncProcessError, osErrorMsg(error)))
        return retFuture
      if exitCode != -1:
        discard removeProcess2(processHandle)
        retFuture.complete(exitStatusLikeShell(exitCode))
        return retFuture

    # Process is still running, so we going to wait for SIGCHLD.
    retFuture.cancelCallback = cancellation
    return retFuture

  proc peekExitCode(p: AsyncProcessRef): AsyncProcessResult[int] =
    let res = ? p.peekProcessExitCode()
    ok(exitStatusLikeShell(res))

proc createPipe(kind: StandardKind
               ): Result[tuple[read: AsyncFD, write: AsyncFD], OSErrorCode] =
  case kind
  of StandardKind.Stdin:
    let pipes =
      when defined(windows):
        let
          readFlags: set[DescriptorFlag] = {DescriptorFlag.NonBlock}
          writeFlags: set[DescriptorFlag] = {DescriptorFlag.NonBlock}
        ? createOsPipe(readFlags, writeFlags)
      else:
        let
          readFlags: set[DescriptorFlag] = {}
          writeFlags: set[DescriptorFlag] = {DescriptorFlag.NonBlock}
        ? createOsPipe(readFlags, writeFlags)
    ok((read: AsyncFD(pipes.read), write: AsyncFD(pipes.write)))
  of StandardKind.Stdout, StandardKind.Stderr:
    let pipes =
      when defined(windows):
        let
          readFlags: set[DescriptorFlag] = {DescriptorFlag.NonBlock}
          writeFlags: set[DescriptorFlag] = {DescriptorFlag.NonBlock}
        ? createOsPipe(readFlags, writeFlags)
      else:
        let
          readFlags: set[DescriptorFlag] = {DescriptorFlag.NonBlock}
          writeFlags: set[DescriptorFlag] = {}
        ? createOsPipe(readFlags, writeFlags)
    ok((read: AsyncFD(pipes.read), write: AsyncFD(pipes.write)))

proc preparePipes(options: set[AsyncProcessOption],
                  stdinHandle, stdoutHandle,
                  stderrHandle: ProcessStreamHandle
                 ): AsyncProcessResult[AsyncProcessPipes] =

  let
    (stdinFlags, localStdin, remoteStdin) =
      case stdinHandle.kind
      of ProcessStreamHandleKind.None:
        ({ProcessFlag.NoStdin}, AsyncStreamHolder.init(),
         asyncInvalidPipe)
      of ProcessStreamHandleKind.Auto:
        let (pipeIn, pipeOut) = ? createPipe(StandardKind.Stdin)
        let holder = ? AsyncStreamHolder.init(
          ProcessStreamHandle.init(pipeOut), StreamKind.Writer, {})
        ({ProcessFlag.AutoStdin}, holder, pipeIn)
      else:
        ({ProcessFlag.UserStdin},
         AsyncStreamHolder.init(), AsyncFD.init(stdinHandle))
    (stdoutFlags, localStdout, remoteStdout) =
      case stdoutHandle.kind
      of ProcessStreamHandleKind.None:
        ({ProcessFlag.NoStdout}, AsyncStreamHolder.init(),
         asyncInvalidPipe)
      of ProcessStreamHandleKind.Auto:
        let (pipeIn, pipeOut) = ? createPipe(StandardKind.Stdout)
        let holder = ? AsyncStreamHolder.init(
          ProcessStreamHandle.init(pipeIn), StreamKind.Reader, {})
        ({ProcessFlag.AutoStdout}, holder, pipeOut)
      else:
        ({ProcessFlag.UserStdout},
         AsyncStreamHolder.init(), AsyncFD.init(stdoutHandle))
    (stderrFlags, localStderr, remoteStderr) =
      if AsyncProcessOption.StdErrToStdOut in options:
        doAssert(stderrHandle.isEmpty(),
                 "`stderrHandle` argument must not be set, when" &
                 "`AsyncProcessOption.StdErrToStdOut` flag is used")
        case stdoutHandle.kind
        of ProcessStreamHandleKind.None:
          raiseAssert "`stdoutHandle` argument must be present, when " &
                      "`AsyncProcessOption.StdErrToStdOut` flag is used"
        of ProcessStreamHandleKind.Auto:
          ({ProcessFlag.CopyStdout}, localStdout, remoteStdout)
        else:
          ({ProcessFlag.CopyStdout}, localStdout, remoteStdout)
      else:
        case stderrHandle.kind
        of ProcessStreamHandleKind.None:
          ({ProcessFlag.NoStderr}, AsyncStreamHolder.init(),
           asyncInvalidPipe)
        of ProcessStreamHandleKind.Auto:
          let (pipeIn, pipeOut) = ? createPipe(StandardKind.Stderr)
          let holder = ? AsyncStreamHolder.init(
            ProcessStreamHandle.init(pipeIn), StreamKind.Reader, {})
          ({ProcessFlag.AutoStderr}, holder, pipeOut)
        else:
          ({ProcessFlag.UserStderr},
           AsyncStreamHolder.init(), AsyncFD.init(stderrHandle))

  ok(AsyncProcessPipes(
    flags: stdinFlags + stdoutFlags + stderrFlags,
    stdinHolder: localStdin,
    stdoutHolder: localStdout,
    stderrHolder: localStderr,
    stdinHandle: remoteStdin,
    stdoutHandle: remoteStdout,
    stderrHandle: remoteStderr
  ))

proc closeWait(holder: AsyncStreamHolder) {.async.} =
  let (future, transp) =
    case holder.kind
    of StreamKind.None:
      (nil, nil)
    of StreamKind.Reader:
      if StreamHolderFlag.Stream in holder.flags:
        (holder.reader.closeWait(), holder.reader.tsource)
      else:
        (nil, holder.reader.tsource)
    of StreamKind.Writer:
      if StreamHolderFlag.Stream in holder.flags:
        (holder.writer.closeWait(), holder.writer.tsource)
      else:
        (nil, holder.writer.tsource)

  let pending =
    block:
      var res: seq[Future[void]]
      if not(isNil(future)):
        res.add(future)
      if not(isNil(transp)):
        if StreamHolderFlag.Transport in holder.flags:
          res.add(transp.closeWait())
      res

  if len(pending) > 0:
    await allFutures(pending)

proc closeProcessStreams(pipes: AsyncProcessPipes,
                         options: set[AsyncProcessOption]): Future[void] =
  let pending =
    block:
      var res: seq[Future[void]]
      if ProcessFlag.AutoStdin in pipes.flags:
        res.add(pipes.stdinHolder.closeWait())
      if ProcessFlag.AutoStdout in pipes.flags:
        res.add(pipes.stdoutHolder.closeWait())
      if ProcessFlag.AutoStderr in pipes.flags:
        res.add(pipes.stderrHolder.closeWait())
      res
  allFutures(pending)

proc closeWait*(p: AsyncProcessRef) {.async.} =
  # Here we ignore all possible errrors, because we do not want to raise
  # exceptions.
  discard closeProcessHandles(p.pipes, p.options, OSErrorCode(0))
  await p.pipes.closeProcessStreams(p.options)
  discard p.closeThreadAndProcessHandle()
  untrackAsyncProcess(p)

proc stdinStream*(p: AsyncProcessRef): AsyncStreamWriter =
  doAssert(p.pipes.stdinHolder.kind == StreamKind.Writer,
           "StdinStreamWriter is not available")
  p.pipes.stdinHolder.writer

proc stdoutStream*(p: AsyncProcessRef): AsyncStreamReader =
  doAssert(p.pipes.stdoutHolder.kind == StreamKind.Reader,
           "StdoutStreamReader is not available")
  p.pipes.stdoutHolder.reader

proc stderrStream*(p: AsyncProcessRef): AsyncStreamReader =
  doAssert(p.pipes.stderrHolder.kind == StreamKind.Reader,
           "StderrStreamReader is not available")
  p.pipes.stderrHolder.reader

proc execCommand*(command: string,
                  options = {AsyncProcessOption.EvalCommand},
                  timeout = InfiniteDuration
                 ): Future[int] {.async.} =
  let poptions = options + {AsyncProcessOption.EvalCommand}
  let process = await startProcess(command, options = poptions)
  let res =
    try:
      await process.waitForExit(timeout)
    finally:
      await process.closeWait()
  return res

proc execCommandEx*(command: string,
                    options = {AsyncProcessOption.EvalCommand},
                    timeout = InfiniteDuration
                   ): Future[CommandExResponse] {.async.} =
  let
    process = await startProcess(command, options = options,
                                 stdoutHandle = AsyncProcess.Pipe,
                                 stderrHandle = AsyncProcess.Pipe)
    outputReader = process.stdoutStream.read()
    errorReader = process.stderrStream.read()
    res =
      try:
        await allFutures(outputReader, errorReader)
        let
          status = await process.waitForExit(timeout)
          output =
            try:
              string.fromBytes(outputReader.read())
            except AsyncStreamError as exc:
              raiseAsyncProcessError("Unable to read process' stdout channel",
                                     exc)
          error =
            try:
              string.fromBytes(errorReader.read())
            except AsyncStreamError as exc:
              raiseAsyncProcessError("Unable to read process' stderr channel",
                                     exc)
        CommandExResponse(status: status, stdOutput: output, stdError: error)
      finally:
        await process.closeWait()

  return res

proc pid*(p: AsyncProcessRef): int =
  ## Returns process ``p`` identifier.
  int(p.processId)

template processId*(p: AsyncProcessRef): int = pid(p)
