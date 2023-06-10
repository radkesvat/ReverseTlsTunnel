#
#
#       Asynchronous tools for Nim Language
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements cross-platform asynchronous inter-process
## communication.
##
## Module uses shared memory for Windows, and fifos for Linux/BSD/MacOS.
##
## .. code-block:: nim
##
##   var inBuffer = newString(64)
##   var outBuffer = "TEST STRING BUFFER"
##
##   # create new IPC object
##   let ipc = createIpc("test")
##   # open `read` side channel to IPC object
##   let readHandle = open("test", sideReader)
##   # open `write` side channel to IPC object
##   let writeHandle = open("test", sideWriter)
##
##   # writing string to IPC object
##   waitFor write(writeHandle, cast[pointer](addr outBuffer[0]), len(outBuffer))
##   # reading data from IPC object
##   var c = waitFor readInto(readHandle, cast[pointer](addr inBuffer[0]), 64)
##
##   inBuffer.setLen(c)
##   doAssert(inBuffer == outBuffer)
##
##   # Close `read` side channel
##   close(readHandle)
##   # Close `write` side channel
##   close(writeHandle)
##   # Close IPC object
##   close(ipc)

import asyncdispatch, os, strutils

type
  SideType* = enum ## Enum represents side of IPC channel (Read or Write)
    sideReader, sideWriter

when defined(nimdoc):
  type
    AsyncIpc* = object
      ## Object represents IPC object.

    AsyncIpcHandle* = object
      ## Object represents channel to IPC object.

  proc createIpc*(name: string, size = 65536): AsyncIpc =
    ## Creates new ``AsyncIpc`` object with internal buffer size ``size``.

  proc close*(ipc: AsyncIpc) =
    ## Closes ``ipc`` object.

  proc open*(name: string, side: SideType, register = true): AsyncIpcHandle =
    ## Opens channel with type ``side`` to ``AsyncIpc`` object with name
    ## ``name``.
    ##
    ## If ``register`` is `false`, then created channel will not be registerd
    ## with current dispatcher.

  proc close*(ipch: AsyncIpcHandle, unregister = true) =
    ## Closes channel to ``AsyncIpc`` object.
    ##
    ## If ``unregister`` is `false`, channel will not be unregistered from
    ## current dispatcher.

  proc write*(ipch: AsyncIpcHandle, data: pointer, size: int): Future[void] =
    ## This procedure writes an untyped ``data`` of ``size`` size to the
    ## channel ``ipch``.
    ##
    ## The returned future will complete once ``all`` data has been sent.

  proc readInto*(ipch: AsyncIpcHandle, data: pointer, size: int): Future[int] =
    ## This procedure reads **up to** ``size`` bytes from channel ``ipch``
    ## into ``data``, which must at least be of that size.
    ##
    ## Returned future will complete once all the data requested is read or
    ## part of the data has been read.

  proc `$`*(ipc: AsyncIpc): string =
    ## Returns string representation of ``ipc`` object.

  proc `$`*(ipch: AsyncIpcHandle): string =
    ## Returns string representation of ``ipch`` object.

elif defined(windows):
  import winlean
  import sets, hashes # this import only for HackDispatcher

  when not declared(PCustomOverlapped):
    type
      PCustomOverlapped = CustomRef

  const
    mapHeaderName = "asyncipc_"
    eventHeaderName = "asyncpipc_"
    mapMinSize = 4096
    EVENT_MODIFY_STATE = 0x0002.Dword
    FILE_MAP_ALL_ACCESS = 0x000F0000 or 0x01 or 0x02 or 0x04 or 0x08 or 0x10

  type
    AsyncIpc* = object
      handleMap, eventChange: Handle
      name: string
      size: int32

    AsyncIpcHandle* = object
      data: pointer
      handleMap, eventChange: Handle
      size: int
      side: SideType

    CallbackDataImpl = object
      ioPort: Handle
      handleFd: AsyncFD
      waitFd: Handle
      ovl: PCustomOverlapped
    CallbackData = ptr CallbackDataImpl

    HackDispatcherImpl = object
      reserverd: array[56, char]
      ioPort: Handle
      handles: HashSet[AsyncFD]
    HackDispatcher = ptr HackDispatcherImpl

  proc openEvent(dwDesiredAccess: Dword, bInheritHandle: WINBOOL,
                 lpName: WideCString): Handle
       {.importc: "OpenEventW", stdcall, dynlib: "kernel32".}
  proc openFileMapping(dwDesiredAccess: Dword, bInheritHandle: Winbool,
                       lpName: WideCString): Handle
       {.importc: "OpenFileMappingW", stdcall, dynlib: "kernel32".}
  proc interlockedOr(a: ptr int32, b: int32)
       {.importc: "_InterlockedOr", header: "intrin.h".}
  proc interlockedAnd(a: ptr int32, b: int32)
       {.importc: "_InterlockedAnd", header: "intrin.h".}

  proc getCurrentDispatcher(): HackDispatcher =
    result = cast[HackDispatcher](getGlobalDispatcher())

  proc `$`*(ipc: AsyncIpc): string =
    if ipc.handleMap == Handle(0):
      result = "AsyncIpc [invalid or inactive handle]"
    else:
      var data = mapViewOfFileEx(ipc.handleMap, FILE_MAP_READ, 0, 0, mapMinSize,
                                 nil)
      if data == nil:
        result = "AsyncIpc [invalid or inactive handle]"
      else:
        var status = ""
        var stat = cast[ptr int32](data)[]
        if (stat and 1) != 0: status &= "R"
        if (stat and 2) != 0: status &= "W"
        discard unmapViewOfFile(data)
        result = "AsyncIpc [handle = 0x" & toHex(int(ipc.handleMap)) & ", " &
                 "event = 0x" & toHex(int(ipc.eventChange)) & ", " &
                 "name = \"" & ipc.name & "\", " &
                 "size = " & $ipc.size & ", " &
                 "status = [" & status & "]" &
                 "]"

  proc `$`*(ipch: AsyncIpcHandle): string =
    var side = if ipch.side == sideWriter: "writer" else: "reader"
    result = "AsyncIpcHandle [handle = 0x" & toHex(int(ipch.handleMap)) & ", " &
             "event = 0x" & toHex(int(ipch.eventChange)) & ", " &
             "data = 0x" & toHex(cast[int](ipch.data)) & ", " &
             "size = " & $ipch.size & ", " &
             "side = " & side &
             "]"

  proc createIpc*(name: string, size = 65536): AsyncIpc =
    var sa = SECURITY_ATTRIBUTES(nLength: sizeof(SECURITY_ATTRIBUTES).cint,
                                 lpSecurityDescriptor: nil, bInheritHandle: 1)
    let mapName = newWideCString(mapHeaderName & name)
    let nameChange = newWideCString(eventHeaderName & name & "_change")
    let mapSize = size + mapMinSize

    doAssert(size > mapMinSize)

    let handleMap = createFileMappingW(INVALID_HANDLE_VALUE,
                                       cast[pointer](addr sa),
                                       PAGE_READWRITE, 0, mapSize.Dword,
                                       cast[pointer](mapName))
    if handleMap == 0:
      raiseOSError(osLastError())
    var eventChange = createEvent(addr sa, 0, 0, addr nameChange[0])
    if eventChange == 0:
      let err = osLastError()
      discard closeHandle(handleMap)
      raiseOSError(err)

    var data = mapViewOfFileEx(handleMap, FILE_MAP_WRITE, 0, 0, mapMinSize, nil)
    if data == nil:
      let err = osLastError()
      discard closeHandle(handleMap)
      discard closeHandle(eventChange)
      raiseOSError(err)

    cast[ptr int32](cast[uint](data) + sizeof(int32).uint * 2)[] = size.int32

    result = AsyncIpc(
      name: name,
      handleMap: handleMap,
      size: size.int32,
      eventChange: eventChange
    )

  proc close*(ipc: AsyncIpc) =
    if closeHandle(ipc.handleMap) == 0:
      raiseOSError(osLastError())
    if closeHandle(ipc.eventChange) == 0:
      raiseOSError(osLastError())

  proc open*(name: string, side: SideType, register = true): AsyncIpcHandle =
    let mapName = newWideCString(mapHeaderName & name)
    let nameChange = newWideCString(eventHeaderName & name & "_change")

    var handleMap = openFileMapping(FILE_MAP_ALL_ACCESS, 1, mapName)
    if handleMap == 0:
      raiseOSError(osLastError())

    var eventChange = openEvent(EVENT_MODIFY_STATE or SYNCHRONIZE,
                                0, nameChange)
    if eventChange == 0:
      let err = osLastError()
      discard closeHandle(handleMap)
      raiseOSError(err)

    var data = mapViewOfFileEx(handleMap, FILE_MAP_WRITE, 0, 0, mapMinSize, nil)
    if data == nil:
      let err = osLastError()
      discard closeHandle(handleMap)
      discard closeHandle(eventChange)
      raiseOSError(err)

    var size = cast[ptr int32](cast[uint](data) + sizeof(int32).uint * 2)[]
    doAssert(size > mapMinSize)

    if unmapViewOfFile(data) == 0:
      let err = osLastError()
      discard closeHandle(handleMap)
      discard closeHandle(eventChange)
      raiseOSError(err)

    when declared(WinSizeT):
      let sizeB = size.WinSizeT
    else:
      let sizeB = size

    data = mapViewOfFileEx(handleMap, FILE_MAP_WRITE, 0, 0, sizeB, nil)
    if data == nil:
      let err = osLastError()
      discard closeHandle(handleMap)
      discard closeHandle(eventChange)
      raiseOSError(err)

    if side == sideWriter:
      interlockedOr(cast[ptr int32](data), 2)
    else:
      interlockedOr(cast[ptr int32](data), 1)

    if register:
      let p = getCurrentDispatcher()
      p.handles.incl(AsyncFD(eventChange))

    result = AsyncIpcHandle(
      data: data,
      size: size,
      handleMap: handleMap,
      eventChange: eventChange,
      side: side
    )

  proc close*(ipch: AsyncIpcHandle, unregister = true) =
    if ipch.side == sideWriter:
      interlockedAnd(cast[ptr int32](ipch.data), not(2))
    else:
      interlockedAnd(cast[ptr int32](ipch.data), not(1))

    if unregister:
      let p = getCurrentDispatcher()
      p.handles.excl(AsyncFD(ipch.eventChange))

    if unmapViewOfFile(ipch.data) == 0:
      raiseOSError(osLastError())
    if closeHandle(ipch.eventChange) == 0:
      raiseOSError(osLastError())
    if closeHandle(ipch.handleMap) == 0:
      raiseOSError(osLastError())

  template getSize(ipch: AsyncIpcHandle): int32 =
    cast[ptr int32](cast[uint](ipch.data) + sizeof(int32).uint)[]

  template getPointer(ipch: AsyncIpcHandle): pointer =
    cast[pointer](cast[uint](ipch.data) + sizeof(int32).uint * 3)

  template setSize(ipc: AsyncIpcHandle, size: int) =
    cast[ptr int32](cast[uint](ipc.data) + sizeof(int32).uint)[] = size.int32

  template setData(ipc: AsyncIpcHandle, data: pointer, size: int) =
    copyMem(getPointer(ipc), data, size)

  template getData(ipc: AsyncIpcHandle, data: pointer, size: int) =
    copyMem(data, getPointer(ipc), size)

  {.push stackTrace:off.}
  proc waitableCallback(param: pointer,
                        timerOrWaitFired: WINBOOL): void {.stdcall.} =
    var p = cast[CallbackData](param)
    discard postQueuedCompletionStatus(p.ioPort, timerOrWaitFired.Dword,
                                       ULONG_PTR(p.handleFd),
                                       cast[pointer](p.ovl))
  {.pop.}

  template registerWaitableChange(ipc: AsyncIpcHandle, pcd, handleCallback) =
    let p = getCurrentDispatcher()
    var flags = (WT_EXECUTEINWAITTHREAD or WT_EXECUTEONLYONCE).Dword
    pcd.ioPort = cast[Handle](p.ioPort)
    pcd.handleFd = AsyncFD(ipc.eventChange)
    var ol = PCustomOverlapped()
    GC_ref(ol)
    ol.data = CompletionData(fd: AsyncFD(ipc.eventChange), cb: handleCallback)
    # We need to protect our callback environment value, so GC will not free it
    # accidentally.
    ol.data.cell = system.protect(rawEnv(ol.data.cb))
    pcd.ovl = ol
    if not registerWaitForSingleObject(addr(pcd.waitFd), ipc.eventChange,
                                    cast[WAITORTIMERCALLBACK](waitableCallback),
                                       cast[pointer](pcd), INFINITE, flags):
      GC_unref(ol)
      deallocShared(cast[pointer](pcd))
      raiseOSError(osLastError())

  proc write*(ipch: AsyncIpcHandle, data: pointer, size: int): Future[void] =
    var retFuture = newFuture[void]("asyncipc.write")
    doAssert(ipch.size >= size and size > 0)
    doAssert(ipch.side == sideWriter)

    if getSize(ipch) == 0:
      setData(ipch, data, size)
      setSize(ipch, size)
      if setEvent(ipch.eventChange) == 0:
        retFuture.fail(newException(OSError, osErrorMsg(osLastError())))
      else:
        retFuture.complete()
    else:
      var pcd = cast[CallbackData](allocShared0(sizeof(CallbackDataImpl)))

      proc writecb(fd: AsyncFD, bytesCount: DWord, errcode: OSErrorCode) =
        # unregistering wait handle and free `CallbackData`
        if unregisterWait(pcd.waitFd) == 0:
          let err = osLastError()
          if err.int32 != ERROR_IO_PENDING:
            retFuture.fail(newException(OSError, osErrorMsg(osLastError())))
        deallocShared(cast[pointer](pcd))

        if not retFuture.finished:
          if errcode == OSErrorCode(-1):
            setData(ipch, data, size)
            setSize(ipch, size)
            if setEvent(ipch.eventChange) == 0:
              retFuture.fail(newException(OSError, osErrorMsg(osLastError())))
            else:
              retFuture.complete()
          else:
            retFuture.fail(newException(OSError, osErrorMsg(errcode)))

      registerWaitableChange(ipch, pcd, writecb)

    return retFuture

  proc readInto*(ipch: AsyncIpcHandle, data: pointer, size: int): Future[int] =
    var retFuture = newFuture[int]("asyncipc.readInto")
    doAssert(size > 0)
    doAssert(ipch.side == sideReader)

    var packetSize = getSize(ipch)
    if packetSize == 0:
      var pcd = cast[CallbackData](allocShared0(sizeof(CallbackDataImpl)))

      proc readcb(fd: AsyncFD, bytesCount: DWord, errcode: OSErrorCode) =
        # unregistering wait handle and free `CallbackData`
        if unregisterWait(pcd.waitFd) == 0:
          let err = osLastError()
          if err.int32 != ERROR_IO_PENDING:
            retFuture.fail(newException(OSError, osErrorMsg(osLastError())))
        deallocShared(cast[pointer](pcd))

        if not retFuture.finished:
          if errcode == OSErrorCode(-1):
            packetSize = getSize(ipch)
            if packetSize > 0:
              getData(ipch, data, packetSize)
              setSize(ipch, 0)
            if setEvent(ipch.eventChange) == 0:
              retFuture.fail(newException(OSError, osErrorMsg(osLastError())))
            else:
              retFuture.complete(packetSize)
          else:
            retFuture.fail(newException(OSError, osErrorMsg(errcode)))

      registerWaitableChange(ipch, pcd, readcb)
    else:
      if size < packetSize:
        packetSize = size.int32
      getData(ipch, data, packetSize)
      setSize(ipch, 0)
      if setEvent(ipch.eventChange) == 0:
        retFuture.fail(newException(OSError, osErrorMsg(osLastError())))
      else:
        retFuture.complete(packetSize)

    return retFuture
else:
  import posix

  const
    pipeHeaderName = r"/tmp/asyncipc_"

  type
    AsyncIpc* = object
      name: string
      size: int

  type
    AsyncIpcHandle* = object
      fd: AsyncFD
      side: SideType

  proc `$`*(ipc: AsyncIpc): string =
    let ipcName = pipeHeaderName & ipc.name
    if posix.access(cstring(ipcName), F_OK) != 0:
      result = "AsyncIpc [invalid or inactive handle]"
    else:
      result = "AsyncIpc [name = \"" & ipc.name & "\", " &
               "size = " & $ipc.size &
               "]"

  proc `$`*(ipch: AsyncIpcHandle): string =
    let side = if ipch.side == sideWriter: "writer" else: "reader"
    result = "AsyncIpcHandle [fd = 0x" & toHex(cint(ipch.fd)) & ", " &
             "side = " & side &
             "]"

  proc setNonBlocking(fd: cint) {.inline.} =
    var x = fcntl(fd, F_GETFL, 0)
    if x == -1:
      raiseOSError(osLastError())
    else:
      var mode = x or O_NONBLOCK
      if fcntl(fd, F_SETFL, mode) == -1:
        raiseOSError(osLastError())

  proc createIpc*(name: string, size = 65536): AsyncIpc =
    let pipeName = pipeHeaderName & name
    if mkfifo(cstring(pipeName), Mode(0x1B6)) != 0:
      raiseOSError(osLastError())
    result = AsyncIpc(
      name: name,
      size: size
    )

  proc close*(ipc: AsyncIpc) =
    let pipeName = pipeHeaderName & ipc.name
    if posix.unlink(cstring(pipeName)) != 0:
      raiseOSError(osLastError())

  proc open*(name: string, side: SideType, register = true): AsyncIpcHandle =
    var pipeFd: cint = 0
    let pipeName = pipeHeaderName & name

    if side == sideReader:
      pipeFd = open(pipeName, O_NONBLOCK or O_RDWR)
    else:
      pipeFd = open(pipeName, O_NONBLOCK or O_WRONLY)

    if pipeFd < 0:
      raiseOSError(osLastError())

    let afd = AsyncFD(pipeFd)
    if register:
      register(afd)

    result = AsyncIpcHandle(
      fd: afd,
      side: side,
    )

  proc close*(ipch: AsyncIpcHandle) =
    if close(cint(ipch.fd)) != 0:
      raiseOSError(osLastError())

  proc write*(ipch: AsyncIpcHandle, data: pointer, nbytes: int): Future[void] =
    var retFuture = newFuture[void]("asyncipc.write")
    var written = 0

    proc cb(fd: AsyncFD): bool =
      result = true
      let reminder = nbytes - written
      let pdata = cast[pointer](cast[uint](data) + written.uint)
      let res = posix.write(cint(ipch.fd), pdata, cint(reminder))
      if res < 0:
        let err = osLastError()
        if err.int32 != EAGAIN:
          retFuture.fail(newException(OSError, osErrorMsg(err)))
        else:
          result = false # We still want this callback to be called.
      else:
        written.inc(res)
        if res != reminder:
          result = false
        else:
          retFuture.complete()

    doAssert(ipch.side == sideWriter)

    if not cb(ipch.fd):
      addWrite(ipch.fd, cb)

    return retFuture

  proc readInto*(ipch: AsyncIpcHandle, data: pointer,
                 nbytes: int): Future[int] =
    var retFuture = newFuture[int]("asyncipc.readInto")
    proc cb(fd: AsyncFD): bool =
      result = true
      let res = posix.read(cint(ipch.fd), data, cint(nbytes))
      if res < 0:
        let lastError = osLastError()
        if lastError.int32 != EAGAIN:
          retFuture.fail(newException(OSError, osErrorMsg(lastError)))
        else:
          result = false # We still want this callback to be called.
      elif res == 0:
        retFuture.fail(newException(OSError, osErrorMsg(osLastError())))
      else:
        retFuture.complete(res)

    doAssert(ipch.side == sideReader)

    if not cb(ipch.fd):
      addRead(ipch.fd, cb)
    return retFuture

when isMainModule:
  when not defined(windows):
    discard posix.unlink(pipeHeaderName & "test")

  var inBuffer = newString(64)
  var outBuffer = "TEST STRING BUFFER"
  let ipc = createIpc("test")
  let readHandle = open("test", sideReader)
  let writeHandle = open("test", sideWriter)

  waitFor write(writeHandle, cast[pointer](addr outBuffer[0]), len(outBuffer))
  var c = waitFor readInto(readHandle, cast[pointer](addr inBuffer[0]), 64)
  inBuffer.setLen(c)
  doAssert(inBuffer == outBuffer)
  close(readHandle)
  close(writeHandle)
  close(ipc)
