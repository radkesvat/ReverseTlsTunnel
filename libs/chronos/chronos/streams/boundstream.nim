#
#         Chronos Asynchronous Bound Stream
#             (c) Copyright 2021-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

## This module implements bounded stream reading and writing.
##
## For stream reading it means that you should read exactly bounded size of
## bytes or you should read all bytes until specific boundary.
##
## For stream writing it means that you should write exactly bounded size
## of bytes.
import stew/results
import ../asyncloop, ../timer
import asyncstream, ../transports/stream, ../transports/common
export asyncloop, asyncstream, stream, timer, common

type
  BoundCmp* {.pure.} = enum
    Equal, LessOrEqual

  BoundedStreamReader* = ref object of AsyncStreamReader
    boundSize: Opt[uint64]
    boundary: seq[byte]
    offset: uint64
    cmpop: BoundCmp

  BoundedStreamWriter* = ref object of AsyncStreamWriter
    boundSize: uint64
    offset: uint64
    cmpop: BoundCmp

  BoundedStreamError* = object of AsyncStreamError
  BoundedStreamIncompleteError* = object of BoundedStreamError
  BoundedStreamOverflowError* = object of BoundedStreamError

  BoundedStreamRW* = BoundedStreamReader | BoundedStreamWriter

const
  BoundedBufferSize* = 4096
  BoundarySizeDefectMessage = "Boundary must not be empty array"

template newBoundedStreamIncompleteError(): ref BoundedStreamError =
  newException(BoundedStreamIncompleteError,
               "Stream boundary is not reached yet")

template newBoundedStreamOverflowError(): ref BoundedStreamOverflowError =
  newException(BoundedStreamOverflowError, "Stream boundary exceeded")

proc readUntilBoundary(rstream: AsyncStreamReader, pbytes: pointer,
                       nbytes: int, sep: seq[byte]): Future[int] {.async.} =
  doAssert(not(isNil(pbytes)), "pbytes must not be nil")
  doAssert(nbytes >= 0, "nbytes must be non-negative value")
  checkStreamClosed(rstream)

  if nbytes == 0:
    return 0

  var k = 0
  var state = 0
  var pbuffer = cast[ptr UncheckedArray[byte]](pbytes)

  proc predicate(data: openArray[byte]): tuple[consumed: int, done: bool] =
    if len(data) == 0:
      (0, true)
    else:
      var index = 0
      while index < len(data):
        if k >= nbytes:
          return (index, true)
        let ch = data[index]
        inc(index)
        pbuffer[k] = ch
        inc(k)
        if len(sep) > 0:
          if sep[state] == ch:
            inc(state)
            if state == len(sep):
              break
          else:
            state = 0
      (index, (state == len(sep)) or (k == nbytes))

  await rstream.readMessage(predicate)
  return k

func endsWith(s, suffix: openArray[byte]): bool =
  var i = 0
  var j = len(s) - len(suffix)
  while i + j >= 0 and i + j < len(s):
    if s[i + j] != suffix[i]: return false
    inc(i)
  if i >= len(suffix): return true

proc boundedReadLoop(stream: AsyncStreamReader) {.async.} =
  var rstream = BoundedStreamReader(stream)
  rstream.state = AsyncStreamState.Running
  var buffer = newSeq[byte](rstream.buffer.bufferLen())
  while true:
    let toRead =
      if rstream.boundSize.isNone():
        len(buffer)
      else:
        int(min(rstream.boundSize.get() - rstream.offset, uint64(len(buffer))))
    try:
      if toRead == 0:
        # When ``rstream.boundSize`` is set and we already readed
        # ``rstream.boundSize`` bytes.
        if rstream.state == AsyncStreamState.Running:
          rstream.state = AsyncStreamState.Finished
      else:
        let res = await readUntilBoundary(rstream.rsource, addr buffer[0],
                                          toRead, rstream.boundary)
        if res > 0:
          if len(rstream.boundary) > 0:
            if endsWith(buffer.toOpenArray(0, res - 1), rstream.boundary):
              let length = res - len(rstream.boundary)
              rstream.offset = rstream.offset + uint64(length)
              # There should be one step between transferring last bytes to the
              # consumer and declaring stream EOF. Otherwise could not be
              # consumed.
              await upload(addr rstream.buffer, addr buffer[0], length)
              if rstream.state == AsyncStreamState.Running:
                rstream.state = AsyncStreamState.Finished
            else:
              rstream.offset = rstream.offset + uint64(res)
              # There should be one step between transferring last bytes to the
              # consumer and declaring stream EOF. Otherwise could not be
              # consumed.
              await upload(addr rstream.buffer, addr buffer[0], res)

              if (res < toRead) and rstream.rsource.atEof():
                case rstream.cmpop
                of BoundCmp.Equal:
                  if rstream.state == AsyncStreamState.Running:
                    rstream.state = AsyncStreamState.Error
                    rstream.error = newBoundedStreamIncompleteError()
                of BoundCmp.LessOrEqual:
                  if rstream.state == AsyncStreamState.Running:
                    rstream.state = AsyncStreamState.Finished
          else:
            rstream.offset = rstream.offset + uint64(res)
            # There should be one step between transferring last bytes to the
            # consumer and declaring stream EOF. Otherwise could not be
            # consumed.
            await upload(addr rstream.buffer, addr buffer[0], res)

            if (res < toRead) and rstream.rsource.atEof():
              case rstream.cmpop
              of BoundCmp.Equal:
                if rstream.state == AsyncStreamState.Running:
                  rstream.state = AsyncStreamState.Error
                  rstream.error = newBoundedStreamIncompleteError()
              of BoundCmp.LessOrEqual:
                if rstream.state == AsyncStreamState.Running:
                  rstream.state = AsyncStreamState.Finished
        else:
          case rstream.cmpop
          of BoundCmp.Equal:
            if rstream.state == AsyncStreamState.Running:
              rstream.state = AsyncStreamState.Error
              rstream.error = newBoundedStreamIncompleteError()
          of BoundCmp.LessOrEqual:
            if rstream.state == AsyncStreamState.Running:
              rstream.state = AsyncStreamState.Finished

    except AsyncStreamError as exc:
      if rstream.state == AsyncStreamState.Running:
        rstream.state = AsyncStreamState.Error
        rstream.error = exc
    except CancelledError:
      if rstream.state == AsyncStreamState.Running:
        rstream.state = AsyncStreamState.Error
        rstream.error = newAsyncStreamUseClosedError()

    case rstream.state
    of AsyncStreamState.Running:
      discard
    of AsyncStreamState.Error, AsyncStreamState.Stopped:
      # Send `Error` or `Stopped` state to the consumer without waiting.
      rstream.buffer.forget()
      break
    of AsyncStreamState.Finished:
      # Send `EOF` state to the consumer and wait until it will be received.
      await rstream.buffer.transfer()
      break
    of AsyncStreamState.Closing, AsyncStreamState.Closed:
      break

proc boundedWriteLoop(stream: AsyncStreamWriter) {.async.} =
  var error: ref AsyncStreamError
  var wstream = BoundedStreamWriter(stream)

  wstream.state = AsyncStreamState.Running
  while true:
    var item: WriteItem
    try:
      item = await wstream.queue.get()
      if item.size > 0:
        if uint64(item.size) <= (wstream.boundSize - wstream.offset):
          # Writing chunk data.
          case item.kind
          of WriteType.Pointer:
            await wstream.wsource.write(item.dataPtr, item.size)
          of WriteType.Sequence:
            await wstream.wsource.write(addr item.dataSeq[0], item.size)
          of WriteType.String:
            await wstream.wsource.write(addr item.dataStr[0], item.size)
          wstream.offset = wstream.offset + uint64(item.size)
          item.future.complete()
        else:
          if wstream.state == AsyncStreamState.Running:
            wstream.state = AsyncStreamState.Error
            error = newBoundedStreamOverflowError()
      else:
        if wstream.offset == wstream.boundSize:
          if wstream.state == AsyncStreamState.Running:
            wstream.state = AsyncStreamState.Finished
            item.future.complete()
        else:
          case wstream.cmpop
          of BoundCmp.Equal:
            if wstream.state == AsyncStreamState.Running:
              wstream.state = AsyncStreamState.Error
              error = newBoundedStreamIncompleteError()
          of BoundCmp.LessOrEqual:
            if wstream.state == AsyncStreamState.Running:
              wstream.state = AsyncStreamState.Finished
              item.future.complete()
    except CancelledError:
      if wstream.state == AsyncStreamState.Running:
        wstream.state = AsyncStreamState.Stopped
        error = newAsyncStreamUseClosedError()
    except AsyncStreamError as exc:
      if wstream.state == AsyncStreamState.Running:
        wstream.state = AsyncStreamState.Error
        error = exc

    case wstream.state
    of AsyncStreamState.Running:
      discard
    of AsyncStreamState.Error, AsyncStreamState.Stopped:
      if not(isNil(item.future)):
        if not(item.future.finished()):
          item.future.fail(error)
      break
    of AsyncStreamState.Finished, AsyncStreamState.Closing,
       AsyncStreamState.Closed:
      error = newAsyncStreamUseClosedError()
      break

  doAssert(not(isNil(error)))
  while not(wstream.queue.empty()):
    let item = wstream.queue.popFirstNoWait()
    if not(item.future.finished()):
      item.future.fail(error)

proc bytesLeft*(stream: BoundedStreamRW): uint64 =
  ## Returns number of bytes left in stream.
  if stream.boundSize.isSome():
    stream.boundSize.get() - stream.bytesCount
  else:
    0'u64

proc init*[T](child: BoundedStreamReader, rsource: AsyncStreamReader,
              boundSize: uint64, comparison = BoundCmp.Equal,
              bufferSize = BoundedBufferSize, udata: ref T) =
  child.boundSize = some(boundSize)
  child.cmpop = comparison
  init(AsyncStreamReader(child), rsource, boundedReadLoop, bufferSize,
       udata)

proc init*[T](child: BoundedStreamReader, rsource: AsyncStreamReader,
              boundary: openArray[byte], comparison = BoundCmp.Equal,
              bufferSize = BoundedBufferSize, udata: ref T) =
  doAssert(len(boundary) > 0, BoundarySizeDefectMessage)
  child.boundary = @boundary
  child.cmpop = comparison
  init(AsyncStreamReader(child), rsource, boundedReadLoop, bufferSize,
       udata)

proc init*[T](child: BoundedStreamReader, rsource: AsyncStreamReader,
              boundSize: uint64, boundary: openArray[byte],
              comparison = BoundCmp.Equal,
              bufferSize = BoundedBufferSize, udata: ref T) =
  doAssert(len(boundary) > 0, BoundarySizeDefectMessage)
  child.boundSize = Opt.some(boundSize)
  child.boundary = @boundary
  child.cmpop = comparison
  init(AsyncStreamReader(child), rsource, boundedReadLoop, bufferSize,
       udata)

proc init*(child: BoundedStreamReader, rsource: AsyncStreamReader,
           boundSize: uint64, comparison = BoundCmp.Equal,
           bufferSize = BoundedBufferSize) =
  child.boundSize = Opt.some(boundSize)
  child.cmpop = comparison
  init(AsyncStreamReader(child), rsource, boundedReadLoop, bufferSize)

proc init*(child: BoundedStreamReader, rsource: AsyncStreamReader,
           boundary: openArray[byte], comparison = BoundCmp.Equal,
           bufferSize = BoundedBufferSize) =
  doAssert(len(boundary) > 0, BoundarySizeDefectMessage)
  child.boundary = @boundary
  child.cmpop = comparison
  init(AsyncStreamReader(child), rsource, boundedReadLoop, bufferSize)

proc init*(child: BoundedStreamReader, rsource: AsyncStreamReader,
           boundSize: uint64, boundary: openArray[byte],
           comparison = BoundCmp.Equal, bufferSize = BoundedBufferSize) =
  doAssert(len(boundary) > 0, BoundarySizeDefectMessage)
  child.boundSize = Opt.some(boundSize)
  child.boundary = @boundary
  child.cmpop = comparison
  init(AsyncStreamReader(child), rsource, boundedReadLoop, bufferSize)

proc newBoundedStreamReader*[T](rsource: AsyncStreamReader,
                                boundSize: uint64,
                                comparison = BoundCmp.Equal,
                                bufferSize = BoundedBufferSize,
                                udata: ref T): BoundedStreamReader =
  ## Create new stream reader which will be limited by size ``boundSize``. When
  ## number of bytes readed by consumer reaches ``boundSize``,
  ## BoundedStreamReader will enter EOF state (no more bytes will be returned
  ## to the consumer).
  ##
  ## If ``comparison`` operator is ``BoundCmp.Equal`` and number of bytes readed
  ## from source stream reader ``rsource`` is less than ``boundSize`` -
  ## ``BoundedStreamIncompleteError`` will be raised. But comparison operator
  ## ``BoundCmp.LessOrEqual`` allows to consume less bytes without
  ## ``BoundedStreamIncompleteError`` exception.
  var res = BoundedStreamReader()
  res.init(rsource, boundSize, comparison, bufferSize, udata)
  res

proc newBoundedStreamReader*[T](rsource: AsyncStreamReader,
                                boundary: openArray[byte],
                                comparison = BoundCmp.Equal,
                                bufferSize = BoundedBufferSize,
                                udata: ref T): BoundedStreamReader =
  ## Create new stream reader which will be limited by binary boundary
  ## ``boundary``. As soon as reader reaches ``boundary`` BoundedStreamReader
  ## will enter EOF state (no more bytes will be returned to the consumer).
  ##
  ## If ``comparison`` operator is ``BoundCmp.Equal`` and number of bytes readed
  ## from source stream reader ``rsource`` is less than ``boundSize`` -
  ## ``BoundedStreamIncompleteError`` will be raised. But comparison operator
  ## ``BoundCmp.LessOrEqual`` allows to consume less bytes without
  ## ``BoundedStreamIncompleteError`` exception.
  var res = BoundedStreamReader()
  res.init(rsource, boundary, comparison, bufferSize, udata)
  res

proc newBoundedStreamReader*[T](rsource: AsyncStreamReader,
                                boundSize: uint64,
                                boundary: openArray[byte],
                                comparison = BoundCmp.Equal,
                                bufferSize = BoundedBufferSize,
                                udata: ref T): BoundedStreamReader =
  ## Create new stream reader which will be limited by size ``boundSize`` or
  ## boundary ``boundary``. As soon as reader reaches ``boundary`` ``OR`` number
  ## of bytes readed from source stream reader ``rsource`` reaches ``boundSize``
  ## BoundStreamReader will enter EOF state (no more bytes will be returned to
  ## the consumer).
  ##
  ## If ``comparison`` operator is ``BoundCmp.Equal`` and number of bytes readed
  ## from source stream reader ``rsource`` is less than ``boundSize`` -
  ## ``BoundedStreamIncompleteError`` will be raised. But comparison operator
  ## ``BoundCmp.LessOrEqual`` allows to consume less bytes without
  ## ``BoundedStreamIncompleteError`` exception.
  var res = BoundedStreamReader()
  res.init(rsource, boundSize, boundary, comparison, bufferSize, udata)
  res

proc newBoundedStreamReader*(rsource: AsyncStreamReader,
                             boundSize: uint64,
                             comparison = BoundCmp.Equal,
                             bufferSize = BoundedBufferSize,
                            ): BoundedStreamReader =
  ## Create new stream reader which will be limited by size ``boundSize``. When
  ## number of bytes readed by consumer reaches ``boundSize``,
  ## BoundedStreamReader will enter EOF state (no more bytes will be returned
  ## to the consumer).
  ##
  ## If ``comparison`` operator is ``BoundCmp.Equal`` and number of bytes readed
  ## from source stream reader ``rsource`` is less than ``boundSize`` -
  ## ``BoundedStreamIncompleteError`` will be raised. But comparison operator
  ## ``BoundCmp.LessOrEqual`` allows to consume less bytes without
  ## ``BoundedStreamIncompleteError`` exception.
  var res = BoundedStreamReader()
  res.init(rsource, boundSize, comparison, bufferSize)
  res

proc newBoundedStreamReader*(rsource: AsyncStreamReader,
                             boundary: openArray[byte],
                             comparison = BoundCmp.Equal,
                             bufferSize = BoundedBufferSize,
                            ): BoundedStreamReader =
  ## Create new stream reader which will be limited by binary boundary
  ## ``boundary``. As soon as reader reaches ``boundary`` BoundedStreamReader
  ## will enter EOF state (no more bytes will be returned to the consumer).
  ##
  ## If ``comparison`` operator is ``BoundCmp.Equal`` and number of bytes readed
  ## from source stream reader ``rsource`` is less than ``boundSize`` -
  ## ``BoundedStreamIncompleteError`` will be raised. But comparison operator
  ## ``BoundCmp.LessOrEqual`` allows to consume less bytes without
  ## ``BoundedStreamIncompleteError`` exception.
  var res = BoundedStreamReader()
  res.init(rsource, boundary, comparison, bufferSize)
  res

proc newBoundedStreamReader*(rsource: AsyncStreamReader,
                             boundSize: uint64,
                             boundary: openArray[byte],
                             comparison = BoundCmp.Equal,
                             bufferSize = BoundedBufferSize,
                            ): BoundedStreamReader =
  ## Create new stream reader which will be limited by size ``boundSize`` or
  ## boundary ``boundary``. As soon as reader reaches ``boundary`` ``OR`` number
  ## of bytes readed from source stream reader ``rsource`` reaches ``boundSize``
  ## BoundStreamReader will enter EOF state (no more bytes will be returned to
  ## the consumer).
  ##
  ## If ``comparison`` operator is ``BoundCmp.Equal`` and number of bytes readed
  ## from source stream reader ``rsource`` is less than ``boundSize`` -
  ## ``BoundedStreamIncompleteError`` will be raised. But comparison operator
  ## ``BoundCmp.LessOrEqual`` allows to consume less bytes without
  ## ``BoundedStreamIncompleteError`` exception.
  var res = BoundedStreamReader()
  res.init(rsource, boundSize, boundary, comparison, bufferSize)
  res

proc init*[T](child: BoundedStreamWriter, wsource: AsyncStreamWriter,
              boundSize: uint64, comparison = BoundCmp.Equal,
              queueSize = AsyncStreamDefaultQueueSize, udata: ref T) =
  child.boundSize = boundSize
  child.cmpop = comparison
  init(AsyncStreamWriter(child), wsource, boundedWriteLoop, queueSize,
       udata)

proc init*(child: BoundedStreamWriter, wsource: AsyncStreamWriter,
           boundSize: uint64, comparison = BoundCmp.Equal,
           queueSize = AsyncStreamDefaultQueueSize) =
  child.boundSize = boundSize
  child.cmpop = comparison
  init(AsyncStreamWriter(child), wsource, boundedWriteLoop, queueSize)

proc newBoundedStreamWriter*[T](wsource: AsyncStreamWriter,
                                boundSize: uint64,
                                comparison = BoundCmp.Equal,
                                queueSize = AsyncStreamDefaultQueueSize,
                                udata: ref T): BoundedStreamWriter =
  ## Create new stream writer which will be limited by size ``boundSize``. As
  ## soon as number of bytes written to the destination stream ``wsource``
  ## reaches ``boundSize`` stream will enter EOF state (no more bytes will be
  ## sent to remote destination stream ``wsource``).
  ##
  ## If ``comparison`` operator is ``BoundCmp.Equal`` and number of bytes
  ## written to destination stream ``wsource`` is less than ``boundSize`` -
  ## ``BoundedStreamIncompleteError`` will be raised on stream finishing. But
  ## comparison operator ``BoundCmp.LessOrEqual`` allows to send less bytes
  ## without ``BoundedStreamIncompleteError`` exception.
  ##
  ## For both comparison operators any attempt to write more bytes than
  ## ``boundSize`` will be interrupted with ``BoundedStreamOverflowError``
  ## exception.
  var res = BoundedStreamWriter()
  res.init(wsource, boundSize, comparison, queueSize, udata)
  res

proc newBoundedStreamWriter*(wsource: AsyncStreamWriter,
                             boundSize: uint64,
                             comparison = BoundCmp.Equal,
                             queueSize = AsyncStreamDefaultQueueSize,
                             ): BoundedStreamWriter =
  ## Create new stream writer which will be limited by size ``boundSize``. As
  ## soon as number of bytes written to the destination stream ``wsource``
  ## reaches ``boundSize`` stream will enter EOF state (no more bytes will be
  ## sent to remote destination stream ``wsource``).
  ##
  ## If ``comparison`` operator is ``BoundCmp.Equal`` and number of bytes
  ## written to destination stream ``wsource`` is less than ``boundSize`` -
  ## ``BoundedStreamIncompleteError`` will be raised on stream finishing. But
  ## comparison operator ``BoundCmp.LessOrEqual`` allows to send less bytes
  ## without ``BoundedStreamIncompleteError`` exception.
  ##
  ## For both comparison operators any attempt to write more bytes than
  ## ``boundSize`` will be interrupted with ``BoundedStreamOverflowError``
  ## exception.
  var res = BoundedStreamWriter()
  res.init(wsource, boundSize, comparison, queueSize)
  res
