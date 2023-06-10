#
#
#       Asynchronous tools for Nim Language
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements cross-platform asynchronous PTY interface.
##
## Please note, that Windows does not support UNIX98 style virtual character
## devices, so named pipe with duplex access is used as replacement. If you
## want to display information from pipe you need to implement terminal by
## yourself.
##
## .. code-block:: nim
##   var inBuffer = newString(64)
##   var outBuffer = "Hello world!"
##
##   # Create new pipe
##   var o = newAsyncPty()
##
##   # show pty name
##   echo "pty device name is " & o.name
##
##   # Read data from pty
##   var c = waitFor readInto(o, cast[pointer](addr inBuffer[0]), inBuffer.len)
##
##   # Close pty
##   close(o)

import asyncdispatch, os

when defined(nimdoc):
  type
    AsyncPty* = ref object ## Object represents ``AsyncPty``.

  proc newAsyncPty*(): AsyncPty
    ## Creates new pseudoterminal device on Posix OSes or new Named Pipe on
    ## Windows with unique name.
    ##
    ## Returns ``AsyncPty`` object.

  proc close*(pty: AsyncPty)
    ## Closes pseudoterminal device.

  proc readInto*(pty: AsyncPty, data: pointer, nbytes: int): Future[int]
    ## This procedure reads up to ``size`` bytes from pty device ``pty``
    ## into ``data``, which must at least be of that size.
    ##
    ## Returned future will complete once all the data requested is read or
    ## part of the data has been read.

  proc write*(pty: AsyncPty, data: pointer, nbytes: int): Future[int]
    ## This procedure writes an untyped ``data`` of ``size`` size to the
    ## pty device ``pty``.
    ##
    ## The returned future will complete once ``all`` data has been sent or
    ## part of the data has been sent.

  proc `$`*(pty: AsyncPty): string
    ## Returns string representation of ``AsyncPty`` object.

else:

  when defined(windows):
    import winlean
  else:
    import posix

  when defined(windows):
    proc QueryPerformanceCounter(res: var int64)
         {.importc: "QueryPerformanceCounter", stdcall, dynlib: "kernel32".}
    proc connectNamedPipe(hNamedPipe: Handle, lpOverlapped: pointer): WINBOOL
         {.importc: "ConnectNamedPipe", stdcall, dynlib: "kernel32".}
    proc disconnectNamedPipe(hNamedPipe: Handle): WINBOOL
         {.importc: "DisconnectNamedPipe", stdcall, dynlib: "kernel32".}
    proc cancelIo(hFile: Handle): WINBOOL
         {.importc: "CancelIo", stdcall, dynlib: "kernel32".}

    const
      ptyHeaderName = r"\\.\pipe\asyncpty_"
      DEFAULT_PIPE_SIZE = 65536'i32
      FILE_FLAG_FIRST_PIPE_INSTANCE = 0x00080000'i32
      PIPE_WAIT = 0x00000000'i32
      PIPE_TYPE_BYTE = 0x00000000'i32
      PIPE_READMODE_BYTE = 0x00000000'i32
      ERROR_PIPE_CONNECTED = 535
      ERROR_PIPE_BUSY = 231
      ERROR_BROKEN_PIPE = 109
      ERROR_PIPE_NOT_CONNECTED = 233
      ERROR_NO_DATA = 232
      PIPE_UNLIMITED_INSTANCES = 255'i32

    type
      CustomOverlapped = object of OVERLAPPED
        data*: CompletionData

      PCustomOverlapped* = ref CustomOverlapped

      AsyncPty* = ref object of RootRef
        name*: string
        fd: Handle
        confuture: Future[void]

    proc `$`*(pty: AsyncPty): string =
      result = "AsyncPty [name = \"" & pty.name & "\"" &
               ", handle = " & $(cast[int](pty.fd)) & "]"

    proc startConnect(pty: AsyncPty, reconnect = false) =
      if reconnect:
        if disconnectNamedPipe(pty.fd) == 0:
          raiseOSError(osLastError())

      pty.confuture = newFuture[void]("asyncpty.startConnect")
      var ol = PCustomOverlapped()
      GC_ref(ol)
      ol.data = CompletionData(fd: AsyncFD(pty.fd), cb:
        proc(fd: AsyncFD, bytesCount: Dword, errcode: OSErrorCode) =
          doAssert(pty.confuture != nil)
          if not pty.confuture.finished:
            if errcode == OSErrorCode(-1):
              pty.confuture.complete()
            else:
              pty.confuture.fail(newException(OSError, osErrorMsg(errcode)))
      )

      let res = connectNamedPipe(pty.fd, cast[pointer](ol))
      if res == 0:
        let err = osLastError()
        if err.int32 == ERROR_PIPE_CONNECTED:
          GC_unref(ol)
          pty.confuture.complete()
        elif err.int32 != ERROR_IO_PENDING:
          GC_unref(ol)
          pty.confuture.fail(newException(OSError, osErrorMsg(err)))
          raiseOSError(err)

    proc newAsyncPty*(): AsyncPty =
      var number = 0'i64
      var ptyWName: WideCString
      var ptyName: string
      var ptyHandle: Handle

      var sa = SECURITY_ATTRIBUTES(nLength: sizeof(SECURITY_ATTRIBUTES).cint,
                                   lpSecurityDescriptor: nil, bInheritHandle: 1)
      while true:
        QueryPerformanceCounter(number)
        ptyName = ptyHeaderName & $number
        ptyWName = newWideCString(ptyName)
        var openMode = FILE_FLAG_FIRST_PIPE_INSTANCE or FILE_FLAG_OVERLAPPED or
                       PIPE_ACCESS_DUPLEX
        var pipeMode = PIPE_TYPE_BYTE or PIPE_READMODE_BYTE or PIPE_WAIT
        ptyHandle = createNamedPipe(ptyWName, openMode, pipeMode, 1'i32,
                                    DEFAULT_PIPE_SIZE, DEFAULT_PIPE_SIZE,
                                    PIPE_UNLIMITED_INSTANCES, addr sa)
        if ptyHandle == INVALID_HANDLE_VALUE:
          let err = osLastError()
          if err.int32 != ERROR_PIPE_BUSY:
            raiseOsError(err)
        else:
          break

      result = AsyncPty(fd: ptyHandle, name: ptyName)
      register(AsyncFD(ptyHandle))

      startConnect(result, false)

    proc readIntoImpl(pty: AsyncPty, data: pointer, nbytes: int): Future[int] =
      var retFuture = newFuture[int]("asyncpty.readIntoImpl")
      var ol = PCustomOverlapped()

      GC_ref(ol)
      ol.data = CompletionData(fd: AsyncFD(pty.fd), cb:
        proc (fd: AsyncFD, bytesCount: DWord, errcode: OSErrorCode) =
          if not retFuture.finished:
            if errcode == OSErrorCode(-1):
              assert(bytesCount > 0 and bytesCount <= nbytes.int32)
              retFuture.complete(bytesCount)
            else:
              if errcode.int32 in {ERROR_BROKEN_PIPE,
                                   ERROR_PIPE_NOT_CONNECTED}:
                retFuture.complete(bytesCount)
              else:
                retFuture.fail(newException(OSError, osErrorMsg(errcode)))
      )
      let res = readFile(pty.fd, data, nbytes.int32, nil,
                         cast[POVERLAPPED](ol)).bool
      if not res:
        let err = osLastError()
        if err.int32 in {ERROR_BROKEN_PIPE, ERROR_PIPE_NOT_CONNECTED}:
          GC_unref(ol)
          retFuture.complete(0)
        elif err.int32 != ERROR_IO_PENDING:
          GC_unref(ol)
          retFuture.fail(newException(OSError, osErrorMsg(err)))
      return retFuture

    proc readInto*(pty: AsyncPty, data: pointer,
                   nbytes: int): Future[int] {.async.} =
      if not pty.confuture.finished:
        await pty.confuture

      result = await readIntoImpl(pty, data, nbytes)

      if result == 0:
        startConnect(pty, true)

    proc writeImpl(pty: AsyncPty, data: pointer, nbytes: int): Future[int] =
      var retFuture = newFuture[int]("asyncpty.writeImpl")
      var ol = PCustomOverlapped()

      GC_ref(ol)
      ol.data = CompletionData(fd: AsyncFD(pty.fd), cb:
        proc (fd: AsyncFD, bytesCount: DWord, errcode: OSErrorCode) =
          if not retFuture.finished:
            if errcode == OSErrorCode(-1):
              retFuture.complete(bytesCount)
            else:
              if errcode.int32 == ERROR_NO_DATA:
                retFuture.complete(0)
              else:
                retFuture.fail(newException(OSError, osErrorMsg(errcode)))
      )
      let res = writeFile(pty.fd, data, nbytes.int32, nil,
                          cast[POVERLAPPED](ol)).bool
      if not res:
        let errcode = osLastError()
        if errcode.int32 == ERROR_NO_DATA:
          retFuture.complete(0)
        elif errcode.int32 != ERROR_IO_PENDING:
          GC_unref(ol)
          retFuture.fail(newException(OSError, osErrorMsg(errcode)))
      return retFuture

    proc write*(pty: AsyncPty, data: pointer,
                nbytes: int): Future[int] {.async.} =
      if not pty.confuture.finished:
        await pty.confuture

      result = await writeImpl(pty, data, nbytes)

      if result == 0:
        startConnect(pty, true)

    proc close*(pty: AsyncPty) =
      if not pty.confuture.finished:
        if cancelIo(pty.fd) == 0:
          raiseOSError(osLastError())

      unregister(AsyncFD(pty.fd))

      if closeHandle(pty.fd) == 0:
        raiseOSError(osLastError())

  else:
    import posix

    proc posix_openpt(flags: cint): cint
         {.importc: "posix_openpt", header: """#include <stdlib.h>
                                               #include <fcntl.h>""".}
    proc grantpt(fildes: cint): cint
         {.importc: "grantpt", header: "<stdlib.h>".}
    proc unlockpt(fildes: cint): cint
         {.importc: "unlockpt", header: "<stdlib.h>".}
    proc ptsname(fildes: cint): cstring
         {.importc: "ptsname", header: "<stdlib.h>".}

    type
      AsyncPty* = ref object of RootRef
        name*: string
        fd: cint

    proc `$`*(pty: AsyncPty): string =
      result = "AsyncPty [name = \"" & pty.name & "\"" &
               ", handle = " & $(cast[int](pty.fd)) & "]"

    proc setNonBlocking(fd: cint) {.inline.} =
      var x = fcntl(fd, F_GETFL, 0)
      if x == -1:
        raiseOSError(osLastError())
      else:
        var mode = x or O_NONBLOCK
        if fcntl(fd, F_SETFL, mode) == -1:
          raiseOSError(osLastError())

    proc newAsyncPty*(): AsyncPty =
      let mfd = posix_openpt(posix.O_RDWR or posix.O_NOCTTY)
      if mfd == -1:
        raiseOSError(osLastError())
      if grantpt(mfd) != 0:
        raiseOSError(osLastError())
      if unlockpt(mfd) != 0:
        raiseOSError(osLastError())

      setNonBlocking(mfd)
      result = AsyncPty(name: $ptsname(mfd), fd: mfd)
      register(AsyncFD(mfd))

    proc write*(pty: AsyncPty, data: pointer, nbytes: int): Future[int] =
      var retFuture = newFuture[int]("asyncpty.write")
      var bytesWrote = 0

      proc cb(fd: AsyncFD): bool =
        result = true
        let reminder = nbytes - bytesWrote
        let pdata = cast[pointer](cast[uint](data) + bytesWrote.uint)
        let res = posix.write(pty.fd, pdata, cint(reminder))
        if res < 0:
          let err = osLastError()
          if err.int32 != EAGAIN:
            retFuture.fail(newException(OSError, osErrorMsg(err)))
          else:
            result = false # We still want this callback to be called.
        elif res == 0:
          retFuture.complete(bytesWrote)
        else:
          bytesWrote.inc(res)
          if res != reminder:
            result = false
          else:
            retFuture.complete(bytesWrote)

      if not cb(AsyncFD(pty.fd)):
        addWrite(AsyncFD(pty.fd), cb)
      return retFuture

    proc readInto*(pty: AsyncPty, data: pointer, nbytes: int): Future[int] =
      var retFuture = newFuture[int]("asyncpipe.readInto")

      proc cb(fd: AsyncFD): bool =
        result = true
        let res = posix.read(pty.fd, data, cint(nbytes))
        if res < 0:
          let err = osLastError()
          if err.int32 != EAGAIN:
            retFuture.fail(newException(OSError, osErrorMsg(err)))
          else:
            result = false # We still want this callback to be called.
        elif res == 0:
          retFuture.complete(0)
        else:
          retFuture.complete(res)

      if not cb(AsyncFD(pty.fd)):
        addRead(AsyncFD(pty.fd), cb)
      return retFuture

    proc close*(pty: AsyncPty) =
      unregister(AsyncFD(pty.fd))
      if posix.close(pty.fd) != 0:
        raiseOSError(osLastError())

when isMainModule:
  var data = "Hello World!"
  var incomingData = newString(128)
  var pty = newAsyncPty()

  when defined(windows):
    var pipeName = newWideCString(pty.name)
    var openMode = (FILE_READ_DATA or FILE_WRITE_DATA or SYNCHRONIZE)
    var ptyHandle = createFileW(pipeName, openMode, 0, nil, OPEN_EXISTING,
                                0, 0)
    if ptyHandle == INVALID_HANDLE_VALUE:
      raiseOsError(osLastError())

    if writeFile(ptyHandle, addr data[0], len(data).int32, nil, nil) == 0:
      raiseOSError(osLastError())
  else:
    var fd = posix.open(pty.name, posix.O_RDWR)
    if fd == -1:
      raiseOSError(osLastError())

    if posix.write(fd, addr data[0], len(data)) == -1:
      raiseOSError(osLastError())

  let rc = waitFor(readInto(pty, addr incomingData[0], len(incomingData)))

  incomingData.setLen(rc)
  doAssert(data == incomingData)

  close(pty)
