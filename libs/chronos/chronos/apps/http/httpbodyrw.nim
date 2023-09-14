#
#         Chronos HTTP/S body reader/writer
#             (c) Copyright 2021-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import ../../asyncloop, ../../asyncsync
import ../../streams/[asyncstream, boundstream]
import httpcommon

const
  HttpBodyReaderTrackerName* = "http.body.reader"
    ## HTTP body reader leaks tracker name
  HttpBodyWriterTrackerName* = "http.body.writer"
    ## HTTP body writer leaks tracker name

type
  HttpBodyReader* = ref object of AsyncStreamReader
    bstate*: HttpState
    streams*: seq[AsyncStreamReader]

  HttpBodyWriter* = ref object of AsyncStreamWriter
    bstate*: HttpState
    streams*: seq[AsyncStreamWriter]

  HttpBodyTracker* = ref object of TrackerBase
    opened*: int64
    closed*: int64

proc setupHttpBodyWriterTracker(): HttpBodyTracker {.gcsafe, raises: [Defect].}
proc setupHttpBodyReaderTracker(): HttpBodyTracker {.gcsafe, raises: [Defect].}

proc getHttpBodyWriterTracker(): HttpBodyTracker {.inline.} =
  var res = cast[HttpBodyTracker](getTracker(HttpBodyWriterTrackerName))
  if isNil(res):
    res = setupHttpBodyWriterTracker()
  res

proc getHttpBodyReaderTracker(): HttpBodyTracker {.inline.} =
  var res = cast[HttpBodyTracker](getTracker(HttpBodyReaderTrackerName))
  if isNil(res):
    res = setupHttpBodyReaderTracker()
  res

proc dumpHttpBodyWriterTracking(): string {.gcsafe.} =
  let tracker = getHttpBodyWriterTracker()
  "Opened HTTP body writers: " & $tracker.opened & "\n" &
  "Closed HTTP body writers: " & $tracker.closed

proc dumpHttpBodyReaderTracking(): string {.gcsafe.} =
  let tracker = getHttpBodyReaderTracker()
  "Opened HTTP body readers: " & $tracker.opened & "\n" &
  "Closed HTTP body readers: " & $tracker.closed

proc leakHttpBodyWriter(): bool {.gcsafe.} =
  var tracker = getHttpBodyWriterTracker()
  tracker.opened != tracker.closed

proc leakHttpBodyReader(): bool {.gcsafe.} =
  var tracker = getHttpBodyReaderTracker()
  tracker.opened != tracker.closed

proc trackHttpBodyWriter(t: HttpBodyWriter) {.inline.} =
  inc(getHttpBodyWriterTracker().opened)

proc untrackHttpBodyWriter*(t: HttpBodyWriter) {.inline.}  =
  inc(getHttpBodyWriterTracker().closed)

proc trackHttpBodyReader(t: HttpBodyReader) {.inline.} =
  inc(getHttpBodyReaderTracker().opened)

proc untrackHttpBodyReader*(t: HttpBodyReader) {.inline.}  =
  inc(getHttpBodyReaderTracker().closed)

proc setupHttpBodyWriterTracker(): HttpBodyTracker {.gcsafe.} =
  var res = HttpBodyTracker(opened: 0, closed: 0,
    dump: dumpHttpBodyWriterTracking,
    isLeaked: leakHttpBodyWriter
  )
  addTracker(HttpBodyWriterTrackerName, res)
  res

proc setupHttpBodyReaderTracker(): HttpBodyTracker {.gcsafe.} =
  var res = HttpBodyTracker(opened: 0, closed: 0,
    dump: dumpHttpBodyReaderTracking,
    isLeaked: leakHttpBodyReader
  )
  addTracker(HttpBodyReaderTrackerName, res)
  res

proc newHttpBodyReader*(streams: varargs[AsyncStreamReader]): HttpBodyReader =
  ## HttpBodyReader is AsyncStreamReader which holds references to all the
  ## ``streams``. Also on close it will close all the ``streams``.
  ##
  ## First stream in sequence will be used as a source.
  doAssert(len(streams) > 0, "At least one stream must be added")
  var res = HttpBodyReader(bstate: HttpState.Alive, streams: @streams)
  res.init(streams[0])
  trackHttpBodyReader(res)
  res

proc closeWait*(bstream: HttpBodyReader) {.async.} =
  ## Close and free resource allocated by body reader.
  if bstream.bstate == HttpState.Alive:
    bstream.bstate = HttpState.Closing
    var res = newSeq[Future[void]]()
    # We closing streams in reversed order because stream at position [0], uses
    # data from stream at position [1].
    for index in countdown((len(bstream.streams) - 1), 0):
      res.add(bstream.streams[index].closeWait())
    await allFutures(res)
    await procCall(closeWait(AsyncStreamReader(bstream)))
    bstream.bstate = HttpState.Closed
    untrackHttpBodyReader(bstream)

proc newHttpBodyWriter*(streams: varargs[AsyncStreamWriter]): HttpBodyWriter =
  ## HttpBodyWriter is AsyncStreamWriter which holds references to all the
  ## ``streams``. Also on close it will close all the ``streams``.
  ##
  ## First stream in sequence will be used as a destination.
  doAssert(len(streams) > 0, "At least one stream must be added")
  var res = HttpBodyWriter(bstate: HttpState.Alive, streams: @streams)
  res.init(streams[0])
  trackHttpBodyWriter(res)
  res

proc closeWait*(bstream: HttpBodyWriter) {.async.} =
  ## Close and free all the resources allocated by body writer.
  if bstream.bstate == HttpState.Alive:
    bstream.bstate = HttpState.Closing
    var res = newSeq[Future[void]]()
    for index in countdown(len(bstream.streams) - 1, 0):
      res.add(bstream.streams[index].closeWait())
    await allFutures(res)
    await procCall(closeWait(AsyncStreamWriter(bstream)))
    bstream.bstate = HttpState.Closed
    untrackHttpBodyWriter(bstream)

proc hasOverflow*(bstream: HttpBodyReader): bool {.raises: [Defect].} =
  if len(bstream.streams) == 1:
    # If HttpBodyReader has only one stream it has ``BoundedStreamReader``, in
    # such case its impossible to get more bytes then expected amount.
    false
  else:
    # If HttpBodyReader has two or more streams, we check if
    # ``BoundedStreamReader`` at EOF.
    if bstream.streams[0].atEof():
      for i in 1 ..< len(bstream.streams):
        if not(bstream.streams[i].atEof()):
          return true
      false
    else:
      false

proc closed*(bstream: HttpBodyReader | HttpBodyWriter): bool {.
     raises: [Defect].} =
  bstream.bstate != HttpState.Alive
