#
#            Chronos Asynchronous Streams
#             (c) Copyright 2019-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import ../asyncloop, ../asyncsync
import ../transports/common, ../transports/stream
export asyncloop, asyncsync, stream, common

const
  AsyncStreamDefaultBufferSize* = 4096
    ## Default reading stream internal buffer size.
  AsyncStreamDefaultQueueSize* = 0
    ## Default writing stream internal queue size.
  AsyncStreamReaderTrackerName* = "async.stream.reader"
    ## AsyncStreamReader leaks tracker name
  AsyncStreamWriterTrackerName* = "async.stream.writer"
    ## AsyncStreamWriter leaks tracker name

type
  AsyncStreamError* = object of CatchableError
  AsyncStreamIncorrectDefect* = object of Defect
  AsyncStreamIncompleteError* = object of AsyncStreamError
  AsyncStreamLimitError* = object of AsyncStreamError
  AsyncStreamUseClosedError* = object of AsyncStreamError
  AsyncStreamReadError* = object of AsyncStreamError
    par*: ref CatchableError
  AsyncStreamWriteError* = object of AsyncStreamError
    par*: ref CatchableError
  AsyncStreamWriteEOFError* = object of AsyncStreamWriteError

  AsyncBuffer* = object
    offset*: int
    buffer*: seq[byte]
    events*: array[2, AsyncEvent]

  WriteType* = enum
    Pointer, Sequence, String

  WriteItem* = object
    case kind*: WriteType
    of Pointer:
      dataPtr*: pointer
    of Sequence:
      dataSeq*: seq[byte]
    of String:
      dataStr*: string
    size*: int
    offset*: int
    future*: Future[void]

  AsyncStreamState* = enum
    Running,  ## Stream is online and working
    Error,    ## Stream has stored error
    Stopped,  ## Stream was closed while working
    Finished, ## Stream was properly finished
    Closing,  ## Stream is closing
    Closed    ## Stream was closed

  StreamReaderLoop* = proc (stream: AsyncStreamReader): Future[void] {.
                        gcsafe, raises: [Defect].}
    ## Main read loop for read streams.
  StreamWriterLoop* = proc (stream: AsyncStreamWriter): Future[void] {.
                        gcsafe, raises: [Defect].}
    ## Main write loop for write streams.

  AsyncStreamReader* = ref object of RootRef
    rsource*: AsyncStreamReader
    tsource*: StreamTransport
    readerLoop*: StreamReaderLoop
    state*: AsyncStreamState
    buffer*: AsyncBuffer
    udata: pointer
    error*: ref AsyncStreamError
    bytesCount*: uint64
    future: Future[void]

  AsyncStreamWriter* = ref object of RootRef
    wsource*: AsyncStreamWriter
    tsource*: StreamTransport
    writerLoop*: StreamWriterLoop
    state*: AsyncStreamState
    queue*: AsyncQueue[WriteItem]
    error*: ref AsyncStreamError
    udata: pointer
    bytesCount*: uint64
    future: Future[void]

  AsyncStream* = object of RootObj
    reader*: AsyncStreamReader
    writer*: AsyncStreamWriter

  AsyncStreamTracker* = ref object of TrackerBase
    opened*: int64
    closed*: int64

  AsyncStreamRW* = AsyncStreamReader | AsyncStreamWriter

proc init*(t: typedesc[AsyncBuffer], size: int): AsyncBuffer =
  AsyncBuffer(
    buffer: newSeq[byte](size),
    events: [newAsyncEvent(), newAsyncEvent()],
    offset: 0
  )

proc getBuffer*(sb: AsyncBuffer): pointer {.inline.} =
  unsafeAddr sb.buffer[sb.offset]

proc bufferLen*(sb: AsyncBuffer): int {.inline.} =
  len(sb.buffer) - sb.offset

proc getData*(sb: AsyncBuffer): pointer {.inline.} =
  unsafeAddr sb.buffer[0]

template dataLen*(sb: AsyncBuffer): int =
  sb.offset

proc `[]`*(sb: AsyncBuffer, index: int): byte {.inline.} =
  doAssert(index < sb.offset)
  sb.buffer[index]

proc update*(sb: var AsyncBuffer, size: int) {.inline.} =
  sb.offset += size

proc wait*(sb: var AsyncBuffer): Future[void] =
  sb.events[0].clear()
  sb.events[1].fire()
  sb.events[0].wait()

proc transfer*(sb: var AsyncBuffer): Future[void] =
  sb.events[1].clear()
  sb.events[0].fire()
  sb.events[1].wait()

proc forget*(sb: var AsyncBuffer) {.inline.} =
  sb.events[1].clear()
  sb.events[0].fire()

proc shift*(sb: var AsyncBuffer, size: int) {.inline.} =
  if sb.offset > size:
    moveMem(addr sb.buffer[0], addr sb.buffer[size], sb.offset - size)
    sb.offset = sb.offset - size
  else:
    sb.offset = 0

proc copyData*(sb: AsyncBuffer, dest: pointer, offset, length: int) {.inline.} =
  copyMem(cast[pointer](cast[uint](dest) + cast[uint](offset)),
          unsafeAddr sb.buffer[0], length)

proc upload*(sb: ptr AsyncBuffer, pbytes: ptr byte,
             nbytes: int): Future[void] {.async.} =
  ## You can upload any amount of bytes to the buffer. If size of internal
  ## buffer is not enough to fit all the data at once, data will be uploaded
  ## via chunks of size up to internal buffer size.
  var length = nbytes
  var srcBuffer = cast[ptr UncheckedArray[byte]](pbytes)
  var srcOffset = 0
  while length > 0:
    let size = min(length, sb[].bufferLen())
    if size == 0:
      # Internal buffer is full, we need to transfer data to consumer.
      await sb[].transfer()
    else:
      # Copy data from `pbytes` to internal buffer.
      copyMem(addr sb[].buffer[sb.offset], addr srcBuffer[srcOffset], size)
      sb[].offset = sb[].offset + size
      srcOffset = srcOffset + size
      length = length - size
  # We notify consumers that new data is available.
  sb[].forget()

template toDataOpenArray*(sb: AsyncBuffer): auto =
  toOpenArray(sb.buffer, 0, sb.offset - 1)

template toBufferOpenArray*(sb: AsyncBuffer): auto =
  toOpenArray(sb.buffer, sb.offset, len(sb.buffer) - 1)

template copyOut*(dest: pointer, item: WriteItem, length: int) =
  if item.kind == Pointer:
    let p = cast[pointer](cast[uint](item.dataPtr) + uint(item.offset))
    copyMem(dest, p, length)
  elif item.kind == Sequence:
    copyMem(dest, unsafeAddr item.dataSeq[item.offset], length)
  elif item.kind == String:
    copyMem(dest, unsafeAddr item.dataStr[item.offset], length)

proc newAsyncStreamReadError(p: ref CatchableError): ref AsyncStreamReadError {.
     noinline.} =
  var w = newException(AsyncStreamReadError, "Read stream failed")
  w.msg = w.msg & ", originated from [" & $p.name & "] " & p.msg
  w.par = p
  w

proc newAsyncStreamWriteError(p: ref CatchableError): ref AsyncStreamWriteError {.
     noinline.} =
  var w = newException(AsyncStreamWriteError, "Write stream failed")
  w.msg = w.msg & ", originated from [" & $p.name & "] " & p.msg
  w.par = p
  w

proc newAsyncStreamIncompleteError*(): ref AsyncStreamIncompleteError {.
     noinline.} =
  newException(AsyncStreamIncompleteError, "Incomplete data sent or received")

proc newAsyncStreamLimitError*(): ref AsyncStreamLimitError {.noinline.} =
  newException(AsyncStreamLimitError, "Buffer limit reached")

proc newAsyncStreamUseClosedError*(): ref AsyncStreamUseClosedError {.
     noinline.} =
  newException(AsyncStreamUseClosedError, "Stream is already closed")

proc raiseAsyncStreamUseClosedError*() {.
     noinline, noreturn, raises: [Defect, AsyncStreamUseClosedError].} =
  raise newAsyncStreamUseClosedError()

proc raiseAsyncStreamLimitError*() {.
     noinline, noreturn, raises: [Defect, AsyncStreamLimitError].} =
  raise newAsyncStreamLimitError()

proc raiseAsyncStreamIncompleteError*() {.
     noinline, noreturn, raises: [Defect, AsyncStreamIncompleteError].} =
  raise newAsyncStreamIncompleteError()

proc raiseEmptyMessageDefect*() {.noinline, noreturn.} =
  raise newException(AsyncStreamIncorrectDefect,
                     "Could not write empty message")

proc raiseAsyncStreamWriteEOFError*() {.
     noinline, noreturn, raises: [Defect, AsyncStreamWriteEOFError].} =
  raise newException(AsyncStreamWriteEOFError,
                     "Stream finished or remote side dropped connection")

proc atEof*(rstream: AsyncStreamReader): bool =
  ## Returns ``true`` is reading stream is closed or finished and internal
  ## buffer do not have any bytes left.
  if isNil(rstream.readerLoop):
    if isNil(rstream.rsource):
      rstream.tsource.atEof()
    else:
      rstream.rsource.atEof()
  else:
    (rstream.state != AsyncStreamState.Running) and
      (rstream.buffer.dataLen() == 0)

proc atEof*(wstream: AsyncStreamWriter): bool =
  ## Returns ``true`` is writing stream ``wstream`` closed or finished.
  if isNil(wstream.writerLoop):
    if isNil(wstream.wsource):
      wstream.tsource.atEof()
    else:
      wstream.wsource.atEof()
  else:
    # `wstream.future` holds `rstream.writerLoop()` call's result.
    # Return `true` if `writerLoop()` is not yet started or already stopped.
    if isNil(wstream.future) or wstream.future.finished():
      true
    else:
      wstream.state != AsyncStreamState.Running

proc closed*(rw: AsyncStreamRW): bool =
  ## Returns ``true`` is reading/writing stream is closed.
  rw.state in {AsyncStreamState.Closing, Closed}

proc finished*(rw: AsyncStreamRW): bool =
  ## Returns ``true`` if reading/writing stream is finished (completed).
  rw.atEof() and rw.state == AsyncStreamState.Finished

proc stopped*(rw: AsyncStreamRW): bool =
  ## Returns ``true`` if reading/writing stream is stopped (interrupted).
  let loopIsNil =
    when rw is AsyncStreamReader:
      isNil(rw.readerLoop)
    else:
      isNil(rw.writerLoop)

  if loopIsNil:
    when rw is AsyncStreamReader:
      if isNil(rw.rsource): false else: rw.rsource.stopped()
    else:
      if isNil(rw.wsource): false else: rw.wsource.stopped()
  else:
    if isNil(rw.future) or rw.future.finished():
      false
    else:
      rw.state == AsyncStreamState.Stopped

proc running*(rw: AsyncStreamRW): bool =
  ## Returns ``true`` if reading/writing stream is still pending.
  let loopIsNil =
    when rw is AsyncStreamReader:
      isNil(rw.readerLoop)
    else:
      isNil(rw.writerLoop)
  if loopIsNil:
    when rw is AsyncStreamReader:
      if isNil(rw.rsource): rw.tsource.running() else: rw.rsource.running()
    else:
      if isNil(rw.wsource): rw.tsource.running() else: rw.wsource.running()
  else:
    if isNil(rw.future) or rw.future.finished():
      false
    else:
      rw.state == AsyncStreamState.Running

proc failed*(rw: AsyncStreamRW): bool =
  ## Returns ``true`` if reading/writing stream is in failed state.
  let loopIsNil =
    when rw is AsyncStreamReader:
      isNil(rw.readerLoop)
    else:
      isNil(rw.writerLoop)
  if loopIsNil:
    when rw is AsyncStreamReader:
      if isNil(rw.rsource): rw.tsource.failed() else: rw.rsource.failed()
    else:
      if isNil(rw.wsource): rw.tsource.failed() else: rw.wsource.failed()
  else:
    if isNil(rw.future) or rw.future.finished():
      false
    else:
      rw.state == AsyncStreamState.Error

template checkStreamClosed*(t: untyped) =
  if t.closed(): raiseAsyncStreamUseClosedError()

template checkStreamFinished*(t: untyped) =
  if t.atEof(): raiseAsyncStreamWriteEOFError()

proc setupAsyncStreamReaderTracker(): AsyncStreamTracker {.
     gcsafe, raises: [Defect].}
proc setupAsyncStreamWriterTracker(): AsyncStreamTracker {.
     gcsafe, raises: [Defect].}

proc getAsyncStreamReaderTracker(): AsyncStreamTracker {.inline.} =
  var res = cast[AsyncStreamTracker](getTracker(AsyncStreamReaderTrackerName))
  if isNil(res):
    res = setupAsyncStreamReaderTracker()
  res

proc getAsyncStreamWriterTracker(): AsyncStreamTracker {.inline.} =
  var res = cast[AsyncStreamTracker](getTracker(AsyncStreamWriterTrackerName))
  if isNil(res):
    res = setupAsyncStreamWriterTracker()
  res

proc dumpAsyncStreamReaderTracking(): string {.gcsafe.} =
  var tracker = getAsyncStreamReaderTracker()
  let res = "Opened async stream readers: " & $tracker.opened & "\n" &
            "Closed async stream readers: " & $tracker.closed
  res

proc dumpAsyncStreamWriterTracking(): string {.gcsafe.} =
  var tracker = getAsyncStreamWriterTracker()
  let res = "Opened async stream writers: " & $tracker.opened & "\n" &
            "Closed async stream writers: " & $tracker.closed
  res

proc leakAsyncStreamReader(): bool {.gcsafe.} =
  var tracker = getAsyncStreamReaderTracker()
  tracker.opened != tracker.closed

proc leakAsyncStreamWriter(): bool {.gcsafe.} =
  var tracker = getAsyncStreamWriterTracker()
  tracker.opened != tracker.closed

proc trackAsyncStreamReader(t: AsyncStreamReader) {.inline.} =
  var tracker = getAsyncStreamReaderTracker()
  inc(tracker.opened)

proc untrackAsyncStreamReader*(t: AsyncStreamReader) {.inline.}  =
  var tracker = getAsyncStreamReaderTracker()
  inc(tracker.closed)

proc trackAsyncStreamWriter(t: AsyncStreamWriter) {.inline.} =
  var tracker = getAsyncStreamWriterTracker()
  inc(tracker.opened)

proc untrackAsyncStreamWriter*(t: AsyncStreamWriter) {.inline.}  =
  var tracker = getAsyncStreamWriterTracker()
  inc(tracker.closed)

proc setupAsyncStreamReaderTracker(): AsyncStreamTracker {.gcsafe.} =
  var res = AsyncStreamTracker(
    opened: 0,
    closed: 0,
    dump: dumpAsyncStreamReaderTracking,
    isLeaked: leakAsyncStreamReader
  )
  addTracker(AsyncStreamReaderTrackerName, res)
  res

proc setupAsyncStreamWriterTracker(): AsyncStreamTracker {.gcsafe.} =
  var res = AsyncStreamTracker(
    opened: 0,
    closed: 0,
    dump: dumpAsyncStreamWriterTracking,
    isLeaked: leakAsyncStreamWriter
  )
  addTracker(AsyncStreamWriterTrackerName, res)
  res

template readLoop(body: untyped): untyped =
  while true:
    if rstream.buffer.dataLen() == 0:
      if rstream.state == AsyncStreamState.Error:
        raise rstream.error

    let (consumed, done) = body
    rstream.buffer.shift(consumed)
    rstream.bytesCount = rstream.bytesCount + uint64(consumed)
    if done:
      break
    else:
      if not(rstream.atEof()):
        await rstream.buffer.wait()

proc readExactly*(rstream: AsyncStreamReader, pbytes: pointer,
                  nbytes: int) {.async.} =
  ## Read exactly ``nbytes`` bytes from read-only stream ``rstream`` and store
  ## it to ``pbytes``.
  ##
  ## If EOF is received and ``nbytes`` is not yet readed, the procedure
  ## will raise ``AsyncStreamIncompleteError``.
  doAssert(not(isNil(pbytes)), "pbytes must not be nil")
  doAssert(nbytes >= 0, "nbytes must be non-negative integer")

  checkStreamClosed(rstream)

  if nbytes == 0:
    return

  if isNil(rstream.rsource):
    try:
      await readExactly(rstream.tsource, pbytes, nbytes)
    except CancelledError as exc:
      raise exc
    except TransportIncompleteError:
      raise newAsyncStreamIncompleteError()
    except CatchableError as exc:
      raise newAsyncStreamReadError(exc)
  else:
    if isNil(rstream.readerLoop):
      await readExactly(rstream.rsource, pbytes, nbytes)
    else:
      var index = 0
      var pbuffer = cast[ptr UncheckedArray[byte]](pbytes)
      readLoop():
        if rstream.buffer.dataLen() == 0:
          if rstream.atEof():
            raise newAsyncStreamIncompleteError()
        let count = min(nbytes - index, rstream.buffer.dataLen())
        if count > 0:
          rstream.buffer.copyData(addr pbuffer[index], 0, count)
          index += count
        (consumed: count, done: index == nbytes)

proc readOnce*(rstream: AsyncStreamReader, pbytes: pointer,
               nbytes: int): Future[int] {.async.} =
  ## Perform one read operation on read-only stream ``rstream``.
  ##
  ## If internal buffer is not empty, ``nbytes`` bytes will be transferred from
  ## internal buffer, otherwise it will wait until some bytes will be available.
  doAssert(not(isNil(pbytes)), "pbytes must not be nil")
  # doAssert(nbytes > 0, "nbytes must be positive value")
  checkStreamClosed(rstream)

  if isNil(rstream.rsource):
    try:
      return await readOnce(rstream.tsource, pbytes, nbytes)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      raise newAsyncStreamReadError(exc)
  else:
    if isNil(rstream.readerLoop):
      return await readOnce(rstream.rsource, pbytes, nbytes)
    else:
      var count = 0
      readLoop():
        if rstream.buffer.dataLen() == 0:
          (0, rstream.atEof())
        else:
          count = min(rstream.buffer.dataLen(), nbytes)
          rstream.buffer.copyData(pbytes, 0, count)
          (count, true)
      return count

proc readUntil*(rstream: AsyncStreamReader, pbytes: pointer, nbytes: int,
                sep: seq[byte]): Future[int] {.async.} =
  ## Read data from the read-only stream ``rstream`` until separator ``sep`` is
  ## found.
  ##
  ## On success, the data and separator will be removed from the internal
  ## buffer (consumed). Returned data will include the separator at the end.
  ##
  ## If EOF is received, and `sep` was not found, procedure will raise
  ## ``AsyncStreamIncompleteError``.
  ##
  ## If ``nbytes`` bytes has been received and `sep` was not found, procedure
  ## will raise ``AsyncStreamLimitError``.
  ##
  ## Procedure returns actual number of bytes read.
  doAssert(not(isNil(pbytes)), "pbytes must not be nil")
  doAssert(len(sep) > 0, "separator must not be empty")
  doAssert(nbytes >= 0, "nbytes must be non-negative value")
  checkStreamClosed(rstream)

  if nbytes == 0:
    raise newAsyncStreamLimitError()

  if isNil(rstream.rsource):
    try:
      return await readUntil(rstream.tsource, pbytes, nbytes, sep)
    except CancelledError as exc:
      raise exc
    except TransportIncompleteError:
      raise newAsyncStreamIncompleteError()
    except TransportLimitError:
      raise newAsyncStreamLimitError()
    except CatchableError as exc:
      raise newAsyncStreamReadError(exc)
  else:
    if isNil(rstream.readerLoop):
      return await readUntil(rstream.rsource, pbytes, nbytes, sep)
    else:
      var pbuffer = cast[ptr UncheckedArray[byte]](pbytes)
      var state = 0
      var k = 0
      readLoop():
        if rstream.atEof():
          raise newAsyncStreamIncompleteError()
        var index = 0
        while index < rstream.buffer.dataLen():
          if k >= nbytes:
            raise newAsyncStreamLimitError()
          let ch = rstream.buffer[index]
          inc(index)
          pbuffer[k] = ch
          inc(k)
          if sep[state] == ch:
            inc(state)
            if state == len(sep):
              break
          else:
            state = 0
        (index, state == len(sep))
      return k

proc readLine*(rstream: AsyncStreamReader, limit = 0,
               sep = "\r\n"): Future[string] {.async.} =
  ## Read one line from read-only stream ``rstream``, where ``"line"`` is a
  ## sequence of bytes ending with ``sep`` (default is ``"\r\n"``).
  ##
  ## If EOF is received, and ``sep`` was not found, the method will return the
  ## partial read bytes.
  ##
  ## If the EOF was received and the internal buffer is empty, return an
  ## empty string.
  ##
  ## If ``limit`` more then 0, then result string will be limited to ``limit``
  ## bytes.
  checkStreamClosed(rstream)

  if isNil(rstream.rsource):
    try:
      return await readLine(rstream.tsource, limit, sep)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      raise newAsyncStreamReadError(exc)
  else:
    if isNil(rstream.readerLoop):
      return await readLine(rstream.rsource, limit, sep)
    else:
      let lim = if limit <= 0: -1 else: limit
      var state = 0
      var res = ""
      readLoop():
        if rstream.atEof():
          (0, true)
        else:
          var index = 0
          while index < rstream.buffer.dataLen():
            let ch = char(rstream.buffer[index])
            inc(index)

            if sep[state] == ch:
              inc(state)
              if state == len(sep):
                break
            else:
              if state != 0:
                if limit > 0:
                  let missing = min(state, lim - len(res) - 1)
                  res.add(sep[0 ..< missing])
                else:
                  res.add(sep[0 ..< state])
              res.add(ch)
              if len(res) == lim:
                break
          (index, (state == len(sep)) or (lim == len(res)))
      return res

proc read*(rstream: AsyncStreamReader): Future[seq[byte]] {.async.} =
  ## Read all bytes from read-only stream ``rstream``.
  ##
  ## This procedure allocates buffer seq[byte] and return it as result.
  checkStreamClosed(rstream)

  if isNil(rstream.rsource):
    try:
      return await read(rstream.tsource)
    except CancelledError as exc:
      raise exc
    except TransportLimitError:
      raise newAsyncStreamLimitError()
    except CatchableError as exc:
      raise newAsyncStreamReadError(exc)
  else:
    if isNil(rstream.readerLoop):
      return await read(rstream.rsource)
    else:
      var res = newSeq[byte]()
      readLoop():
        if rstream.atEof():
          (0, true)
        else:
          let count = rstream.buffer.dataLen()
          res.add(rstream.buffer.buffer.toOpenArray(0, count - 1))
          (count, false)
      return res

proc read*(rstream: AsyncStreamReader, n: int): Future[seq[byte]] {.async.} =
  ## Read all bytes (n <= 0) or exactly `n` bytes from read-only stream
  ## ``rstream``.
  ##
  ## This procedure allocates buffer seq[byte] and return it as result.
  checkStreamClosed(rstream)

  if isNil(rstream.rsource):
    try:
      return await read(rstream.tsource, n)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      raise newAsyncStreamReadError(exc)
  else:
    if isNil(rstream.readerLoop):
      return await read(rstream.rsource, n)
    else:
      if n <= 0:
        return await read(rstream.rsource)
      else:
        var res = newSeq[byte]()
        readLoop():
          if rstream.atEof():
            (0, true)
          else:
            let count = min(rstream.buffer.dataLen(), n - len(res))
            res.add(rstream.buffer.buffer.toOpenArray(0, count - 1))
            (count, len(res) == n)
        return res

proc consume*(rstream: AsyncStreamReader): Future[int] {.async.} =
  ## Consume (discard) all bytes from read-only stream ``rstream``.
  ##
  ## Return number of bytes actually consumed (discarded).
  checkStreamClosed(rstream)

  if isNil(rstream.rsource):
    try:
      return await consume(rstream.tsource)
    except CancelledError as exc:
      raise exc
    except TransportLimitError:
      raise newAsyncStreamLimitError()
    except CatchableError as exc:
      raise newAsyncStreamReadError(exc)
  else:
    if isNil(rstream.readerLoop):
      return await consume(rstream.rsource)
    else:
      var res = 0
      readLoop():
        if rstream.atEof():
          (0, true)
        else:
          res += rstream.buffer.dataLen()
          (rstream.buffer.dataLen(), false)
      return res

proc consume*(rstream: AsyncStreamReader, n: int): Future[int] {.async.} =
  ## Consume (discard) all bytes (n <= 0) or ``n`` bytes from read-only stream
  ## ``rstream``.
  ##
  ## Return number of bytes actually consumed (discarded).
  checkStreamClosed(rstream)

  if isNil(rstream.rsource):
    try:
      return await consume(rstream.tsource, n)
    except CancelledError as exc:
      raise exc
    except TransportLimitError:
      raise newAsyncStreamLimitError()
    except CatchableError as exc:
      raise newAsyncStreamReadError(exc)
  else:
    if isNil(rstream.readerLoop):
      return await consume(rstream.rsource, n)
    else:
      if n <= 0:
        return await rstream.consume()
      else:
        var res = 0
        readLoop():
          if rstream.atEof():
            (0, true)
          else:
            let count = min(rstream.buffer.dataLen(), n - res)
            res += count
            (count, res == n)
        return res

proc readMessage*(rstream: AsyncStreamReader, pred: ReadMessagePredicate) {.
     async.} =
  ## Read all bytes from stream ``rstream`` until ``predicate`` callback
  ## will not be satisfied.
  ##
  ## ``predicate`` callback should return tuple ``(consumed, result)``, where
  ## ``consumed`` is the number of bytes processed and ``result`` is a
  ## completion flag (``true`` if readMessage() should stop reading data,
  ## or ``false`` if readMessage() should continue to read data from stream).
  ##
  ## ``predicate`` callback must copy all the data from ``data`` array and
  ## return number of bytes it is going to consume.
  ## ``predicate`` callback will receive (zero-length) openArray, if stream
  ## is at EOF.
  doAssert(not(isNil(pred)), "`predicate` callback should not be `nil`")
  checkStreamClosed(rstream)

  if isNil(rstream.rsource):
    try:
      await readMessage(rstream.tsource, pred)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      raise newAsyncStreamReadError(exc)
  else:
    if isNil(rstream.readerLoop):
      await readMessage(rstream.rsource, pred)
    else:
      readLoop():
        let count = rstream.buffer.dataLen()
        if count == 0:
          if rstream.atEof():
            pred([])
          else:
            # Case, when transport's buffer is not yet filled with data.
            (0, false)
        else:
          pred(rstream.buffer.buffer.toOpenArray(0, count - 1))

proc write*(wstream: AsyncStreamWriter, pbytes: pointer,
            nbytes: int) {.async.} =
  ## Write sequence of bytes pointed by ``pbytes`` of length ``nbytes`` to
  ## writer stream ``wstream``.
  ##
  ## ``nbytes`` must be more then zero.
  checkStreamClosed(wstream)
  checkStreamFinished(wstream)

  if nbytes <= 0:
    raiseEmptyMessageDefect()

  if isNil(wstream.wsource):
    var res: int
    try:
      res = await write(wstream.tsource, pbytes, nbytes)
    except CancelledError as exc:
      raise exc
    except AsyncStreamError as exc:
      raise exc
    except CatchableError as exc:
      raise newAsyncStreamWriteError(exc)
    if res != nbytes:
      raise newAsyncStreamIncompleteError()
    wstream.bytesCount = wstream.bytesCount + uint64(nbytes)
  else:
    if isNil(wstream.writerLoop):
      await write(wstream.wsource, pbytes, nbytes)
      wstream.bytesCount = wstream.bytesCount + uint64(nbytes)
    else:
      var item = WriteItem(kind: Pointer)
      item.dataPtr = pbytes
      item.size = nbytes
      item.future = newFuture[void]("async.stream.write(pointer)")
      try:
        await wstream.queue.put(item)
        await item.future
        wstream.bytesCount = wstream.bytesCount + uint64(item.size)
      except CancelledError as exc:
        raise exc
      except AsyncStreamError as exc:
        raise exc
      except CatchableError as exc:
        raise newAsyncStreamWriteError(exc)

proc write*(wstream: AsyncStreamWriter, sbytes: sink seq[byte],
            msglen = -1) {.async.} =
  ## Write sequence of bytes ``sbytes`` of length ``msglen`` to writer
  ## stream ``wstream``.
  ##
  ## Sequence of bytes ``sbytes`` must not be zero-length.
  ##
  ## If ``msglen < 0`` whole sequence ``sbytes`` will be writen to stream.
  ## If ``msglen > len(sbytes)`` only ``len(sbytes)`` bytes will be written to
  ## stream.
  checkStreamClosed(wstream)
  checkStreamFinished(wstream)

  let length = if msglen <= 0: len(sbytes) else: min(msglen, len(sbytes))
  if length <= 0:
    raiseEmptyMessageDefect()

  if isNil(wstream.wsource):
    var res: int
    try:
      res = await write(wstream.tsource, sbytes, length)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      raise newAsyncStreamWriteError(exc)
    if res != length:
      raise newAsyncStreamIncompleteError()
    wstream.bytesCount = wstream.bytesCount + uint64(length)
  else:
    if isNil(wstream.writerLoop):
      await write(wstream.wsource, sbytes, length)
      wstream.bytesCount = wstream.bytesCount + uint64(length)
    else:
      var item = WriteItem(kind: Sequence)
      when declared(shallowCopy):
        if not(isLiteral(sbytes)):
          shallowCopy(item.dataSeq, sbytes)
        else:
          item.dataSeq = sbytes
      else:
        item.dataSeq = sbytes
      item.size = length
      item.future = newFuture[void]("async.stream.write(seq)")
      try:
        await wstream.queue.put(item)
        await item.future
        wstream.bytesCount = wstream.bytesCount + uint64(item.size)
      except CancelledError as exc:
        raise exc
      except AsyncStreamError as exc:
        raise exc
      except CatchableError as exc:
        raise newAsyncStreamWriteError(exc)

proc write*(wstream: AsyncStreamWriter, sbytes: sink string,
            msglen = -1) {.async.} =
  ## Write string ``sbytes`` of length ``msglen`` to writer stream ``wstream``.
  ##
  ## String ``sbytes`` must not be zero-length.
  ##
  ## If ``msglen < 0`` whole string ``sbytes`` will be writen to stream.
  ## If ``msglen > len(sbytes)`` only ``len(sbytes)`` bytes will be written to
  ## stream.
  checkStreamClosed(wstream)
  checkStreamFinished(wstream)

  let length = if msglen <= 0: len(sbytes) else: min(msglen, len(sbytes))
  if length <= 0:
    raiseEmptyMessageDefect()

  if isNil(wstream.wsource):
    var res: int
    try:
      res = await write(wstream.tsource, sbytes, length)
    except CancelledError as exc:
      raise exc
    except CatchableError as exc:
      raise newAsyncStreamWriteError(exc)
    if res != length:
      raise newAsyncStreamIncompleteError()
    wstream.bytesCount = wstream.bytesCount + uint64(length)
  else:
    if isNil(wstream.writerLoop):
      await write(wstream.wsource, sbytes, length)
      wstream.bytesCount = wstream.bytesCount + uint64(length)
    else:
      var item = WriteItem(kind: String)
      when declared(shallowCopy):
        if not(isLiteral(sbytes)):
          shallowCopy(item.dataStr, sbytes)
        else:
          item.dataStr = sbytes
      else:
        item.dataStr = sbytes
      item.size = length
      item.future = newFuture[void]("async.stream.write(string)")
      try:
        await wstream.queue.put(item)
        await item.future
        wstream.bytesCount = wstream.bytesCount + uint64(item.size)
      except CancelledError as exc:
        raise exc
      except AsyncStreamError as exc:
        raise exc
      except CatchableError as exc:
        raise newAsyncStreamWriteError(exc)

proc finish*(wstream: AsyncStreamWriter) {.async.} =
  ## Finish write stream ``wstream``.
  checkStreamClosed(wstream)
  # For AsyncStreamWriter Finished state could be set manually or by stream's
  # writeLoop, so we not going to raise exception here.
  if not(wstream.atEof()):
    if not isNil(wstream.wsource):
      if isNil(wstream.writerLoop):
        await wstream.wsource.finish()
      else:
        var item = WriteItem(kind: Pointer)
        item.size = 0
        item.future = newFuture[void]("async.stream.finish")
        try:
          await wstream.queue.put(item)
          await item.future
        except CancelledError as exc:
          raise exc
        except AsyncStreamError as exc:
          raise exc
        except CatchableError as exc:
          raise newAsyncStreamWriteError(exc)

proc join*(rw: AsyncStreamRW): Future[void] =
  ## Get Future[void] which will be completed when stream become finished or
  ## closed.
  when rw is AsyncStreamReader:
    var retFuture = newFuture[void]("async.stream.reader.join")
  else:
    var retFuture = newFuture[void]("async.stream.writer.join")

  proc continuation(udata: pointer) {.gcsafe.} =
    retFuture.complete()

  proc cancellation(udata: pointer) {.gcsafe.} =
    rw.future.removeCallback(continuation, cast[pointer](retFuture))

  if not(rw.future.finished()):
    rw.future.addCallback(continuation, cast[pointer](retFuture))
    retFuture.cancelCallback = cancellation
  else:
    retFuture.complete()

  return retFuture

proc close*(rw: AsyncStreamRW) =
  ## Close and frees resources of stream ``rw``.
  ##
  ## Note close() procedure is not completed immediately!
  if not(rw.closed()):
    rw.state = AsyncStreamState.Closing

    proc continuation(udata: pointer) {.raises: [Defect].} =
      if not isNil(rw.udata):
        GC_unref(cast[ref int](rw.udata))
      if not(rw.future.finished()):
        rw.future.complete()
      when rw is AsyncStreamReader:
        untrackAsyncStreamReader(rw)
      elif rw is AsyncStreamWriter:
        untrackAsyncStreamWriter(rw)
      rw.state = AsyncStreamState.Closed

    when rw is AsyncStreamReader:
      if isNil(rw.rsource) or isNil(rw.readerLoop) or isNil(rw.future):
        callSoon(continuation)
      else:
        if rw.future.finished():
          callSoon(continuation)
        else:
          rw.future.addCallback(continuation)
          rw.future.cancel()
    elif rw is AsyncStreamWriter:
      if isNil(rw.wsource) or isNil(rw.writerLoop) or isNil(rw.future):
        callSoon(continuation)
      else:
        if rw.future.finished():
          callSoon(continuation)
        else:
          rw.future.addCallback(continuation)
          rw.future.cancel()

proc closeWait*(rw: AsyncStreamRW): Future[void] =
  ## Close and frees resources of stream ``rw``.
  rw.close()
  rw.join()

proc startReader(rstream: AsyncStreamReader) =
  rstream.state = Running
  if not isNil(rstream.readerLoop):
    rstream.future = rstream.readerLoop(rstream)
  else:
    rstream.future = newFuture[void]("async.stream.empty.reader")

proc startWriter(wstream: AsyncStreamWriter) =
  wstream.state = Running
  if not isNil(wstream.writerLoop):
    wstream.future = wstream.writerLoop(wstream)
  else:
    wstream.future = newFuture[void]("async.stream.empty.writer")

proc init*(child, wsource: AsyncStreamWriter, loop: StreamWriterLoop,
           queueSize = AsyncStreamDefaultQueueSize) =
  ## Initialize newly allocated object ``child`` with AsyncStreamWriter
  ## parameters.
  child.writerLoop = loop
  child.wsource = wsource
  child.tsource = wsource.tsource
  child.queue = newAsyncQueue[WriteItem](queueSize)
  trackAsyncStreamWriter(child)
  child.startWriter()

proc init*[T](child, wsource: AsyncStreamWriter, loop: StreamWriterLoop,
              queueSize = AsyncStreamDefaultQueueSize, udata: ref T) =
  ## Initialize newly allocated object ``child`` with AsyncStreamWriter
  ## parameters.
  child.writerLoop = loop
  child.wsource = wsource
  child.tsource = wsource.tsource
  child.queue = newAsyncQueue[WriteItem](queueSize)
  if not isNil(udata):
    GC_ref(udata)
    child.udata = cast[pointer](udata)
  trackAsyncStreamWriter(child)
  child.startWriter()

proc init*(child, rsource: AsyncStreamReader, loop: StreamReaderLoop,
           bufferSize = AsyncStreamDefaultBufferSize) =
  ## Initialize newly allocated object ``child`` with AsyncStreamReader
  ## parameters.
  child.readerLoop = loop
  child.rsource = rsource
  child.tsource = rsource.tsource
  child.buffer = AsyncBuffer.init(bufferSize)
  trackAsyncStreamReader(child)
  child.startReader()

proc init*[T](child, rsource: AsyncStreamReader, loop: StreamReaderLoop,
              bufferSize = AsyncStreamDefaultBufferSize,
              udata: ref T) =
  ## Initialize newly allocated object ``child`` with AsyncStreamReader
  ## parameters.
  child.readerLoop = loop
  child.rsource = rsource
  child.tsource = rsource.tsource
  child.buffer = AsyncBuffer.init(bufferSize)
  if not isNil(udata):
    GC_ref(udata)
    child.udata = cast[pointer](udata)
  trackAsyncStreamReader(child)
  child.startReader()

proc init*(child: AsyncStreamWriter, tsource: StreamTransport) =
  ## Initialize newly allocated object ``child`` with AsyncStreamWriter
  ## parameters.
  child.writerLoop = nil
  child.wsource = nil
  child.tsource = tsource
  trackAsyncStreamWriter(child)
  child.startWriter()

proc init*[T](child: AsyncStreamWriter, tsource: StreamTransport,
              udata: ref T) =
  ## Initialize newly allocated object ``child`` with AsyncStreamWriter
  ## parameters.
  child.writerLoop = nil
  child.wsource = nil
  child.tsource = tsource
  trackAsyncStreamWriter(child)
  child.startWriter()

proc init*(child, wsource: AsyncStreamWriter) =
  ## Initialize newly allocated object ``child`` with AsyncStreamWriter
  ## parameters.
  child.writerLoop = nil
  child.wsource = wsource
  child.tsource = wsource.tsource
  trackAsyncStreamWriter(child)
  child.startWriter()

proc init*[T](child, wsource: AsyncStreamWriter, udata: ref T) =
  ## Initialize newly allocated object ``child`` with AsyncStreamWriter
  ## parameters.
  child.writerLoop = nil
  child.wsource = wsource
  child.tsource = wsource.tsource
  if not isNil(udata):
    GC_ref(udata)
    child.udata = cast[pointer](udata)
  trackAsyncStreamWriter(child)
  child.startWriter()

proc init*(child: AsyncStreamReader, tsource: StreamTransport) =
  ## Initialize newly allocated object ``child`` with AsyncStreamReader
  ## parameters.
  child.readerLoop = nil
  child.rsource = nil
  child.tsource = tsource
  trackAsyncStreamReader(child)
  child.startReader()

proc init*[T](child: AsyncStreamReader, tsource: StreamTransport,
              udata: ref T) =
  ## Initialize newly allocated object ``child`` with AsyncStreamReader
  ## parameters.
  child.readerLoop = nil
  child.rsource = nil
  child.tsource = tsource
  if not isNil(udata):
    GC_ref(udata)
    child.udata = cast[pointer](udata)
  trackAsyncStreamReader(child)
  child.startReader()

proc init*(child, rsource: AsyncStreamReader) =
  ## Initialize newly allocated object ``child`` with AsyncStreamReader
  ## parameters.
  child.readerLoop = nil
  child.rsource = rsource
  child.tsource = rsource.tsource
  trackAsyncStreamReader(child)
  child.startReader()

proc init*[T](child, rsource: AsyncStreamReader, udata: ref T) =
  ## Initialize newly allocated object ``child`` with AsyncStreamReader
  ## parameters.
  child.readerLoop = nil
  child.rsource = rsource
  child.tsource = rsource.tsource
  if not isNil(udata):
    GC_ref(udata)
    child.udata = cast[pointer](udata)
  trackAsyncStreamReader(child)
  child.startReader()

proc newAsyncStreamReader*[T](rsource: AsyncStreamReader,
                              loop: StreamReaderLoop,
                              bufferSize = AsyncStreamDefaultBufferSize,
                              udata: ref T): AsyncStreamReader =
  ## Create new AsyncStreamReader object, which will use other async stream
  ## reader ``rsource`` as source data channel.
  ##
  ## ``loop`` is main reading loop procedure.
  ##
  ## ``bufferSize`` is internal buffer size.
  ##
  ## ``udata`` - user object which will be associated with new AsyncStreamReader
  ## object.
  var res = AsyncStreamReader()
  res.init(rsource, loop, bufferSize, udata)
  res

proc newAsyncStreamReader*(rsource: AsyncStreamReader,
                           loop: StreamReaderLoop,
                           bufferSize = AsyncStreamDefaultBufferSize
                          ): AsyncStreamReader =
  ## Create new AsyncStreamReader object, which will use other async stream
  ## reader ``rsource`` as source data channel.
  ##
  ## ``loop`` is main reading loop procedure.
  ##
  ## ``bufferSize`` is internal buffer size.
  var res = AsyncStreamReader()
  res.init(rsource, loop, bufferSize)
  res

proc newAsyncStreamReader*[T](tsource: StreamTransport,
                              udata: ref T): AsyncStreamReader =
  ## Create new AsyncStreamReader object, which will use stream transport
  ## ``tsource`` as source data channel.
  ##
  ## ``udata`` - user object which will be associated with new AsyncStreamWriter
  ## object.
  var res = AsyncStreamReader()
  res.init(tsource, udata)
  res

proc newAsyncStreamReader*(tsource: StreamTransport): AsyncStreamReader =
  ## Create new AsyncStreamReader object, which will use stream transport
  ## ``tsource`` as source data channel.
  var res = AsyncStreamReader()
  res.init(tsource)
  res

proc newAsyncStreamWriter*[T](wsource: AsyncStreamWriter,
                              loop: StreamWriterLoop,
                              queueSize = AsyncStreamDefaultQueueSize,
                              udata: ref T): AsyncStreamWriter =
  ## Create new AsyncStreamWriter object which will use other AsyncStreamWriter
  ## object ``wsource`` as data channel.
  ##
  ## ``loop`` is main writing loop procedure.
  ##
  ## ``queueSize`` is writing queue size (default size is unlimited).
  ##
  ## ``udata`` - user object which will be associated with new AsyncStreamWriter
  ## object.
  var res = AsyncStreamWriter()
  res.init(wsource, loop, queueSize, udata)
  res

proc newAsyncStreamWriter*(wsource: AsyncStreamWriter,
                           loop: StreamWriterLoop,
                           queueSize = AsyncStreamDefaultQueueSize
                          ): AsyncStreamWriter =
  ## Create new AsyncStreamWriter object which will use other AsyncStreamWriter
  ## object ``wsource`` as data channel.
  ##
  ## ``loop`` is main writing loop procedure.
  ##
  ## ``queueSize`` is writing queue size (default size is unlimited).
  var res = AsyncStreamWriter()
  res.init(wsource, loop, queueSize)
  res

proc newAsyncStreamWriter*[T](tsource: StreamTransport,
                              udata: ref T): AsyncStreamWriter =
  ## Create new AsyncStreamWriter object which will use stream transport
  ## ``tsource`` as  data channel.
  ##
  ## ``udata`` - user object which will be associated with new AsyncStreamWriter
  ## object.
  var res = AsyncStreamWriter()
  res.init(tsource, udata)
  res

proc newAsyncStreamWriter*(tsource: StreamTransport): AsyncStreamWriter =
  ## Create new AsyncStreamWriter object which will use stream transport
  ## ``tsource`` as data channel.
  var res = AsyncStreamWriter()
  res.init(tsource)
  res

proc newAsyncStreamWriter*[T](wsource: AsyncStreamWriter,
                              udata: ref T): AsyncStreamWriter =
  ## Create copy of AsyncStreamWriter object ``wsource``.
  ##
  ## ``udata`` - user object which will be associated with new AsyncStreamWriter
  ## object.
  var res = AsyncStreamWriter()
  res.init(wsource, udata)
  res

proc newAsyncStreamWriter*(wsource: AsyncStreamWriter): AsyncStreamWriter =
  ## Create copy of AsyncStreamWriter object ``wsource``.
  var res = AsyncStreamWriter()
  res.init(wsource)
  res

proc newAsyncStreamReader*[T](rsource: AsyncStreamWriter,
                              udata: ref T): AsyncStreamWriter =
  ## Create copy of AsyncStreamReader object ``rsource``.
  ##
  ## ``udata`` - user object which will be associated with new AsyncStreamReader
  ## object.
  var res = AsyncStreamReader()
  res.init(rsource, udata)
  res

proc newAsyncStreamReader*(rsource: AsyncStreamReader): AsyncStreamReader =
  ## Create copy of AsyncStreamReader object ``rsource``.
  var res = AsyncStreamReader()
  res.init(rsource)
  res

proc getUserData*[T](rw: AsyncStreamRW): T {.inline.} =
  ## Obtain user data associated with AsyncStreamReader or AsyncStreamWriter
  ## object ``rw``.
  cast[T](rw.udata)
