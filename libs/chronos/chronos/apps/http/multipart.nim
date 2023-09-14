#
#           Chronos HTTP/S multipart/form
#      encoding and decoding helper procedures
#             (c) Copyright 2021-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[monotimes, strutils]
import stew/results, httputils
import ../../asyncloop
import ../../streams/[asyncstream, boundstream, chunkstream]
import httptable, httpcommon, httpbodyrw
export asyncloop, httptable, httpcommon, httpbodyrw, asyncstream, httputils

const
  UnableToReadMultipartBody = "Unable to read multipart message body"

type
  MultiPartSource* {.pure.} = enum
    Stream, Buffer

  MultiPartWriterState* {.pure.} = enum
    MessagePreparing, MessageStarted, PartStarted, PartFinished,
    MessageFinished, MessageFailure

  MultiPartReader* = object
    case kind*: MultiPartSource
    of MultiPartSource.Stream:
      stream*: HttpBodyReader
    of MultiPartSource.Buffer:
      discard
    firstTime: bool
    buffer: seq[byte]
    offset: int
    boundary: seq[byte]
    counter: int

  MultiPartReaderRef* = ref MultiPartReader

  MultiPartWriter* = object
    case kind*: MultiPartSource
    of MultiPartSource.Stream:
      stream*: HttpBodyWriter
    of MultiPartSource.Buffer:
      buffer*: seq[byte]
    beginMark: seq[byte]
    finishMark: seq[byte]
    beginPartMark: seq[byte]
    finishPartMark: seq[byte]
    state*: MultiPartWriterState

  MultiPartWriterRef* = ref MultiPartWriter

  MultiPart* = object
    case kind: MultiPartSource
    of MultiPartSource.Stream:
      breader: HttpBodyReader
      stream: BoundedStreamReader
    of MultiPartSource.Buffer:
      discard
    buffer: seq[byte]
    headers: HttpTable
    counter: int
    name*: string
    filename*: string

  MultipartError* = object of HttpCriticalError
  MultipartEOMError* = object of MultipartError

  BChar* = byte | char

proc startsWith(s, prefix: openArray[byte]): bool {.
     raises: [Defect].} =
  # This procedure is copy of strutils.startsWith() procedure, however,
  # it is intended to work with arrays of bytes, but not with strings.
  var i = 0
  while true:
    if i >= len(prefix): return true
    if i >= len(s) or s[i] != prefix[i]: return false
    inc(i)

proc parseUntil(s, until: openArray[byte]): int {.
     raises: [Defect].} =
  # This procedure is copy of parseutils.parseUntil() procedure, however,
  # it is intended to work with arrays of bytes, but not with strings.
  var i = 0
  while i < len(s):
    if len(until) > 0 and s[i] == until[0]:
      var u = 1
      while i + u < len(s) and u < len(until) and s[i + u] == until[u]:
        inc u
      if u >= len(until): return i
    inc(i)
  -1

func setPartNames(part: var MultiPart): HttpResult[void] {.
     raises: [Defect].} =
  if part.headers.count("content-disposition") != 1:
    return err("Content-Disposition header is incorrect")
  var header = part.headers.getString("content-disposition")
  let disp = parseDisposition(header, false)
  if disp.failed():
    return err("Content-Disposition header value is incorrect")
  let dtype = disp.dispositionType(header.toOpenArrayByte(0, len(header) - 1))
  if dtype.toLowerAscii() != "form-data":
    return err("Content-Disposition type is incorrect")
  for k, v in disp.fields(header.toOpenArrayByte(0, len(header) - 1)):
    case k.toLowerAscii()
    of "name":
      part.name = v
    of "filename":
      part.filename = v
    else:
      discard
  if len(part.name) == 0:
    part.name = $part.counter
  ok()

proc init*[A: BChar, B: BChar](mpt: typedesc[MultiPartReader],
                               buffer: openArray[A],
                               boundary: openArray[B]): MultiPartReader {.
     raises: [Defect].} =
  ## Create new MultiPartReader instance with `buffer` interface.
  ##
  ## ``buffer`` - is buffer which will be used to read data.
  ## ``boundary`` - is multipart boundary, this value must not be empty.
  doAssert(len(boundary) > 0)
  # Our internal boundary has format `<CR><LF><-><-><boundary>`, so we can
  # reuse different parts of this sequence for processing.
  var fboundary = newSeq[byte](len(boundary) + 4)
  fboundary[0] = 0x0D'u8
  fboundary[1] = 0x0A'u8
  fboundary[2] = byte('-')
  fboundary[3] = byte('-')
  copyMem(addr fboundary[4], unsafeAddr boundary[0], len(boundary))
  # Make copy of buffer, because all the returned parts depending on it.
  var buf = newSeq[byte](len(buffer))
  if len(buf) > 0:
    copyMem(addr buf[0], unsafeAddr buffer[0], len(buffer))
  MultiPartReader(kind: MultiPartSource.Buffer,
                  buffer: buf, offset: 0, boundary: fboundary)

proc new*[B: BChar](mpt: typedesc[MultiPartReaderRef],
                    stream: HttpBodyReader,
                    boundary: openArray[B],
                    partHeadersMaxSize = 4096): MultiPartReaderRef {.
     raises: [Defect].} =
  ## Create new MultiPartReader instance with `stream` interface.
  ##
  ## ``stream`` is stream used to read data.
  ## ``boundary`` is multipart boundary, this value must not be empty.
  ## ``partHeadersMaxSize`` is maximum size of multipart's headers.
  # According to specification length of boundary must be bigger then `0` and
  # less or equal to `70`.
  doAssert(len(boundary) > 0 and len(boundary) <= 70)
  # 256 bytes is minimum value because we going to use single buffer for
  # reading boundaries and for reading headers.
  # Minimal buffer value for boundary is 5 bytes, maximum is 74 bytes. But at
  # least one header should be present "Content-Disposition", so minimum value
  # of multipart headers will be near 150 bytes.
  doAssert(partHeadersMaxSize >= 256)
  # Our internal boundary has format `<CR><LF><-><-><boundary>`, so we can
  # reuse different parts of this sequence for processing.
  var fboundary = newSeq[byte](len(boundary) + 4)
  fboundary[0] = 0x0D'u8
  fboundary[1] = 0x0A'u8
  fboundary[2] = byte('-')
  fboundary[3] = byte('-')
  copyMem(addr fboundary[4], unsafeAddr boundary[0], len(boundary))
  MultiPartReaderRef(kind: MultiPartSource.Stream, firstTime: true,
                     stream: stream, offset: 0, boundary: fboundary,
                     buffer: newSeq[byte](partHeadersMaxSize))

proc readPart*(mpr: MultiPartReaderRef): Future[MultiPart] {.async.} =
  doAssert(mpr.kind == MultiPartSource.Stream)
  if mpr.firstTime:
    try:
      # Read and verify initial <-><-><boundary>
      await mpr.stream.readExactly(addr mpr.buffer[0], len(mpr.boundary) - 2)
      mpr.firstTime = false
      if not(startsWith(mpr.buffer.toOpenArray(0, len(mpr.boundary) - 3),
                        mpr.boundary.toOpenArray(2, len(mpr.boundary) - 1))):
        raiseHttpCriticalError("Unexpected boundary encountered")
    except CancelledError as exc:
      raise exc
    except AsyncStreamError:
      if mpr.stream.hasOverflow():
        raiseHttpCriticalError(MaximumBodySizeError, Http413)
      else:
        raiseHttpCriticalError(UnableToReadMultipartBody)

  # Reading part's headers
  try:
    # Read 2 bytes more
    await mpr.stream.readExactly(addr mpr.buffer[0], 2)
    if mpr.buffer[0] == byte('-') and mpr.buffer[1] == byte('-'):
      # If two bytes are "--" we are at the end
      await mpr.stream.readExactly(addr mpr.buffer[0], 2)
      if mpr.buffer[0] == 0x0D'u8 and mpr.buffer[1] == 0x0A'u8:
        # If 3rd and 4th bytes are CRLF we are exactly at the end of message.
        raise newException(MultipartEOMError,
                           "End of multipart message")
      else:
        raiseHttpCriticalError("Incorrect multipart header found")
    if mpr.buffer[0] != 0x0D'u8 or mpr.buffer[1] != 0x0A'u8:
      raiseHttpCriticalError("Incorrect multipart boundary found")

    # If two bytes are CRLF we are at the part beginning.
    # Reading part's headers
    let res = await mpr.stream.readUntil(addr mpr.buffer[0], len(mpr.buffer),
                                         HeadersMark)
    var headersList = parseHeaders(mpr.buffer.toOpenArray(0, res - 1), false)
    if headersList.failed():
      raiseHttpCriticalError("Incorrect multipart's headers found")
    inc(mpr.counter)

    var part = MultiPart(
      kind: MultiPartSource.Stream,
      headers: HttpTable.init(),
      breader: mpr.stream,
      stream: newBoundedStreamReader(mpr.stream, mpr.boundary),
      counter: mpr.counter
    )

    for k, v in headersList.headers(mpr.buffer.toOpenArray(0, res - 1)):
      part.headers.add(k, v)

    let sres = part.setPartNames()
    if sres.isErr():
      raiseHttpCriticalError($sres.error)
    return part

  except CancelledError as exc:
    raise exc
  except AsyncStreamError:
    if mpr.stream.hasOverflow():
      raiseHttpCriticalError(MaximumBodySizeError, Http413)
    else:
      raiseHttpCriticalError(UnableToReadMultipartBody)

proc getBody*(mp: MultiPart): Future[seq[byte]] {.async.} =
  ## Get multipart's ``mp`` value as sequence of bytes.
  case mp.kind
  of MultiPartSource.Stream:
    try:
      let res = await mp.stream.read()
      return res
    except AsyncStreamError:
      if mp.breader.hasOverflow():
        raiseHttpCriticalError(MaximumBodySizeError, Http413)
      else:
        raiseHttpCriticalError(UnableToReadMultipartBody)
  of MultiPartSource.Buffer:
    return mp.buffer

proc consumeBody*(mp: MultiPart) {.async.} =
  ## Discard multipart's ``mp`` value.
  case mp.kind
  of MultiPartSource.Stream:
    try:
      discard await mp.stream.consume()
    except AsyncStreamError:
      if mp.breader.hasOverflow():
        raiseHttpCriticalError(MaximumBodySizeError, Http413)
      else:
        raiseHttpCriticalError(UnableToReadMultipartBody)
  of MultiPartSource.Buffer:
    discard

proc getBodyStream*(mp: MultiPart): HttpResult[AsyncStreamReader] {.
     raises: [Defect].} =
  ## Get multipart's ``mp`` stream, which can be used to obtain value of the
  ## part.
  case mp.kind
  of MultiPartSource.Stream:
    ok(mp.stream)
  else:
    err("Could not obtain stream from buffer-like part")

proc closeWait*(mp: MultiPart) {.async.} =
  ## Close and release MultiPart's ``mp`` stream and resources.
  case mp.kind
  of MultiPartSource.Stream:
    await closeWait(mp.stream)
  else:
    discard

proc closeWait*(mpr: MultiPartReaderRef) {.async.} =
  ## Close and release MultiPartReader's ``mpr`` stream and resources.
  case mpr.kind
  of MultiPartSource.Stream:
    await mpr.stream.closeWait()
  else:
    discard

proc getBytes*(mp: MultiPart): seq[byte] {.raises: [Defect].} =
  ## Returns value for MultiPart ``mp`` as sequence of bytes.
  case mp.kind
  of MultiPartSource.Buffer:
    mp.buffer
  of MultiPartSource.Stream:
    doAssert(not(mp.stream.atEof()), "Value is not obtained yet")
    mp.buffer

proc getString*(mp: MultiPart): string {.raises: [Defect].} =
  ## Returns value for MultiPart ``mp`` as string.
  case mp.kind
  of MultiPartSource.Buffer:
    bytesToString(mp.buffer)
  of MultiPartSource.Stream:
    doAssert(not(mp.stream.atEof()), "Value is not obtained yet")
    bytesToString(mp.buffer)

proc atEoM*(mpr: var MultiPartReader): bool {.raises: [Defect].} =
  ## Procedure returns ``true`` if MultiPartReader has reached the end of
  ## multipart message.
  case mpr.kind
  of MultiPartSource.Buffer:
    mpr.offset >= len(mpr.buffer)
  of MultiPartSource.Stream:
    mpr.stream.atEof()

proc atEoM*(mpr: MultiPartReaderRef): bool {.raises: [Defect].} =
  ## Procedure returns ``true`` if MultiPartReader has reached the end of
  ## multipart message.
  case mpr.kind
  of MultiPartSource.Buffer:
    mpr.offset >= len(mpr.buffer)
  of MultiPartSource.Stream:
    mpr.stream.atEof()

proc getPart*(mpr: var MultiPartReader): Result[MultiPart, string] {.
     raises: [Defect].} =
  ## Get multipart part from MultiPartReader instance.
  ##
  ## This procedure will work only for MultiPartReader with buffer source.
  doAssert(mpr.kind == MultiPartSource.Buffer)
  if mpr.offset >= len(mpr.buffer):
    return err("End of multipart form encountered")

  if startsWith(mpr.buffer.toOpenArray(mpr.offset, len(mpr.buffer) - 1),
                mpr.boundary.toOpenArray(2, len(mpr.boundary) - 1)):
    # Buffer must start at <-><-><boundary>
    mpr.offset += (len(mpr.boundary) - 2)

    # After boundary there should be at least 2 symbols <-><-> or <CR><LF>.
    if len(mpr.buffer) <= mpr.offset + 1:
      return err("Incomplete multipart form")

    if mpr.buffer[mpr.offset] == byte('-') and
       mpr.buffer[mpr.offset + 1] == byte('-'):
      # If we have <-><-><boundary><-><-> it means we have found last boundary
      # of multipart message.
      mpr.offset += 2
      if len(mpr.buffer) <= mpr.offset + 1:
        if mpr.buffer[mpr.offset] == 0x0D'u8 and
           mpr.buffer[mpr.offset + 1] == 0x0A'u8:
          mpr.offset += 2
          return err("End of multipart form encountered")
        else:
          return err("Incorrect multipart last boundary")
      else:
        return err("Incomplete multipart form")

    if mpr.buffer[mpr.offset] == 0x0D'u8 and
       mpr.buffer[mpr.offset + 1] == 0x0A'u8:
      # If we have <-><-><boundary><CR><LF> it means that we have found another
      # part of multipart message.
      mpr.offset += 2
      # Multipart form must always have at least single Content-Disposition
      # header, so we searching position where all the headers should be
      # finished <CR><LF><CR><LF>.
      let pos1 = parseUntil(
        mpr.buffer.toOpenArray(mpr.offset, len(mpr.buffer) - 1),
        [0x0D'u8, 0x0A'u8, 0x0D'u8, 0x0A'u8]
      )

      if pos1 < 0:
        return err("Incomplete multipart form")

      # parseUntil returns 0-based position without `until` sequence.
      let start = mpr.offset + pos1 + 4

      # Multipart headers position
      let hstart = mpr.offset
      let hfinish = mpr.offset + pos1 + 4 - 1

      let headersList = parseHeaders(mpr.buffer.toOpenArray(hstart, hfinish),
                                     false)
      if headersList.failed():
        return err("Incorrect or incomplete multipart headers received")

      # Searching for value's boundary <CR><LF><-><-><boundary>.
      let pos2 = parseUntil(
        mpr.buffer.toOpenArray(start, len(mpr.buffer) - 1),
        mpr.boundary.toOpenArray(0, len(mpr.boundary) - 1)
      )

      if pos2 < 0:
        return err("Incomplete multipart form")

      # We set reader's offset to the place right after <CR><LF>
      mpr.offset = start + pos2 + 2
      inc(mpr.counter)
      var part = MultiPart(
        kind: MultiPartSource.Buffer,
        headers: HttpTable.init(),
        buffer: @(mpr.buffer.toOpenArray(start, start + pos2 - 1)),
        counter: mpr.counter
      )

      for k, v in headersList.headers(mpr.buffer.toOpenArray(hstart, hfinish)):
        part.headers.add(k, v)

      ? part.setPartNames()

      ok(part)
    else:
      err("Incorrect multipart form")
  else:
    err("Incorrect multipart form")

func isEmpty*(mp: MultiPart): bool {.
     raises: [Defect].} =
  ## Returns ``true`` is multipart ``mp`` is not initialized/filled yet.
  mp.counter == 0

func validateBoundary[B: BChar](boundary: openArray[B]): HttpResult[void] =
  if len(boundary) == 0:
    err("Content-Type boundary must be at least 1 character size")
  elif len(boundary) > 70:
    err("Content-Type boundary must be less then 70 characters")
  else:
    for ch in boundary:
      if chr(ord(ch)) notin {'a' .. 'z', 'A' .. 'Z', '0' .. '9',
                             '\'' .. ')', '+' .. '/', ':', '=', '?', '_'}:
        return err("Content-Type boundary alphabet incorrect")
    ok()

func getMultipartBoundary*(contentData: ContentTypeData): HttpResult[string] {.
     raises: [Defect].} =
  ## Returns ``multipart/form-data`` boundary value from ``Content-Type``
  ## header.
  ##
  ## The procedure carries out all the necessary checks:
  ##   1) `boundary` value must be present.
  ##   2) `boundary` value must be less then 70 characters length and
  ##      all characters should be part of specific alphabet.
  let candidate =
    block:
      var res: string
      for item in contentData.params:
        if cmpIgnoreCase(item.name, "boundary") == 0:
          res = item.value
          break
      res
  ? validateBoundary(candidate)
  ok(candidate)

proc quoteCheck(name: string): HttpResult[string] =
  if len(name) > 0:
    var res = newStringOfCap(len(name))
    for ch in name:
      case ch
      of '\x00' .. '\x08', '\x0a' .. '\x1f':
        return err("Incorrect character encountered")
      of '\x09', '\x20', '\x21':
        res.add(ch)
      of '\x22':
        res.add('\\')
        res.add('"')
      of '\x23' .. '\x7f':
        res.add(ch)
      else:
        return err("Incorrect character encountered")
    ok(res)
  else:
    ok(name)

proc init*[B: BChar](mpt: typedesc[MultiPartWriter],
                     boundary: openArray[B]): MultiPartWriter {.
     raises: [Defect].} =
  ## Create new MultiPartWriter instance with `buffer` interface.
  ##
  ## ``boundary`` - is multipart boundary, this value must not be empty.
  doAssert(validateBoundary(boundary).isOk())

  let sboundary =
    when B is char:
      @(boundary.toOpenArrayByte(0, len(boundary) - 1))
    else:
      @boundary

  var finishMark = sboundary
  finishMark.add([0x2d'u8, 0x2d'u8, 0x0d'u8, 0x0a'u8])
  var beginPartMark = sboundary
  beginPartMark.add([0x0d'u8, 0x0a'u8])

  MultiPartWriter(
    kind: MultiPartSource.Buffer,
    buffer: newSeq[byte](),
    beginMark: @[0x2d'u8, 0x2d'u8],
    finishMark: finishMark,
    beginPartMark: beginPartMark,
    finishPartMark: @[0x0d'u8, 0x0a'u8, 0x2d'u8, 0x2d'u8],
    state: MultiPartWriterState.MessagePreparing
  )

proc new*[B: BChar](mpt: typedesc[MultiPartWriterRef],
                    stream: HttpBodyWriter,
                    boundary: openArray[B]): MultiPartWriterRef {.
     raises: [Defect].} =
  doAssert(validateBoundary(boundary).isOk())
  doAssert(not(isNil(stream)))

  let sboundary =
    when B is char:
      @(boundary.toOpenArrayByte(0, len(boundary) - 1))
    else:
      @boundary

  var finishMark = sboundary
  finishMark.add([0x2d'u8, 0x2d'u8, 0x0d'u8, 0x0a'u8])
  var beginPartMark = sboundary
  beginPartMark.add([0x0d'u8, 0x0a'u8])

  MultiPartWriterRef(
    kind: MultiPartSource.Stream,
    stream: stream,
    beginMark: @[0x2d'u8, 0x2d'u8],
    finishMark: finishMark,
    beginPartMark: beginPartMark,
    finishPartMark: @[0x0d'u8, 0x0a'u8, 0x2d'u8, 0x2d'u8],
    state: MultiPartWriterState.MessagePreparing
  )

proc prepareHeaders(partMark: openArray[byte], name: string, filename: string,
                    headers: HttpTable): string =
  const ContentDisposition = "Content-Disposition"
  let qname =
    block:
      let res = quoteCheck(name)
      doAssert(res.isOk())
      res.get()
  let qfilename =
    block:
      let res = quoteCheck(filename)
      doAssert(res.isOk())
      res.get()
  var buffer = newString(len(partMark))
  copyMem(addr buffer[0], unsafeAddr partMark[0], len(partMark))
  buffer.add(ContentDisposition)
  buffer.add(": ")
  if ContentDisposition in headers:
    buffer.add(headers.getString(ContentDisposition))
    buffer.add("\r\n")
  else:
    buffer.add("form-data; name=\"")
    buffer.add(qname)
    buffer.add("\"")
    if len(qfilename) > 0:
      buffer.add("; filename=\"")
      buffer.add(qfilename)
      buffer.add("\"")
    buffer.add("\r\n")

  for k, v in headers.stringItems():
    if k != toLowerAscii(ContentDisposition):
      if len(v) > 0:
        buffer.add(k)
        buffer.add(": ")
        buffer.add(v)
        buffer.add("\r\n")
  buffer.add("\r\n")
  buffer

proc begin*(mpw: MultiPartWriterRef) {.async.} =
  ## Starts multipart message form and write approprate markers to output
  ## stream.
  doAssert(mpw.kind == MultiPartSource.Stream)
  doAssert(mpw.state == MultiPartWriterState.MessagePreparing)
  # write "--"
  try:
    await mpw.stream.write(mpw.beginMark)
  except AsyncStreamError:
    mpw.state = MultiPartWriterState.MessageFailure
    raiseHttpCriticalError("Unable to start multipart message")
  mpw.state = MultiPartWriterState.MessageStarted

proc begin*(mpw: var MultiPartWriter) =
  ## Starts multipart message form and write approprate markers to output
  ## buffer.
  doAssert(mpw.kind == MultiPartSource.Buffer)
  doAssert(mpw.state == MultiPartWriterState.MessagePreparing)
  # write "--"
  mpw.buffer.add(mpw.beginMark)
  mpw.state = MultiPartWriterState.MessageStarted

proc beginPart*(mpw: MultiPartWriterRef, name: string,
                filename: string, headers: HttpTable) {.async.} =
  ## Starts part of multipart message and write appropriate ``headers`` to the
  ## output stream.
  ##
  ## Note: `filename` and `name` arguments could be only ASCII strings.
  doAssert(mpw.kind == MultiPartSource.Stream)
  doAssert(mpw.state in {MultiPartWriterState.MessageStarted,
                         MultiPartWriterState.PartFinished})
  # write "<boundary><CR><LF>"
  # write "<part headers><CR><LF>"
  # write "<CR><LF>"
  let buffer = prepareHeaders(mpw.beginPartMark, name, filename, headers)
  try:
    await mpw.stream.write(buffer)
    mpw.state = MultiPartWriterState.PartStarted
  except AsyncStreamError:
    mpw.state = MultiPartWriterState.MessageFailure
    raiseHttpCriticalError("Unable to start multipart part")

proc beginPart*(mpw: var MultiPartWriter, name: string,
                filename: string, headers: HttpTable) =
  ## Starts part of multipart message and write appropriate ``headers`` to the
  ## output stream.
  ##
  ## Note: `filename` and `name` arguments could be only ASCII strings.
  doAssert(mpw.kind == MultiPartSource.Buffer)
  doAssert(mpw.state in {MultiPartWriterState.MessageStarted,
                         MultiPartWriterState.PartFinished})
  let buffer = prepareHeaders(mpw.beginPartMark, name, filename, headers)
  # write "<boundary><CR><LF>"
  # write "<part headers><CR><LF>"
  # write "<CR><LF>"
  mpw.buffer.add(buffer.toOpenArrayByte(0, len(buffer) - 1))
  mpw.state = MultiPartWriterState.PartStarted

proc write*(mpw: MultiPartWriterRef, pbytes: pointer, nbytes: int) {.async.} =
  ## Write part's data ``data`` to the output stream.
  doAssert(mpw.kind == MultiPartSource.Stream)
  doAssert(mpw.state == MultiPartWriterState.PartStarted)
  try:
    # write <chunk> of data
    await mpw.stream.write(pbytes, nbytes)
  except AsyncStreamError:
    mpw.state = MultiPartWriterState.MessageFailure
    raiseHttpCriticalError("Unable to write multipart data")

proc write*(mpw: MultiPartWriterRef, data: seq[byte]) {.async.} =
  ## Write part's data ``data`` to the output stream.
  doAssert(mpw.kind == MultiPartSource.Stream)
  doAssert(mpw.state == MultiPartWriterState.PartStarted)
  try:
    # write <chunk> of data
    await mpw.stream.write(data)
  except AsyncStreamError:
    mpw.state = MultiPartWriterState.MessageFailure
    raiseHttpCriticalError("Unable to write multipart data")

proc write*(mpw: MultiPartWriterRef, data: string) {.async.} =
  ## Write part's data ``data`` to the output stream.
  doAssert(mpw.kind == MultiPartSource.Stream)
  doAssert(mpw.state == MultiPartWriterState.PartStarted)
  try:
    # write <chunk> of data
    await mpw.stream.write(data)
  except AsyncStreamError:
    mpw.state = MultiPartWriterState.MessageFailure
    raiseHttpCriticalError("Unable to write multipart data")

proc write*(mpw: var MultiPartWriter, pbytes: pointer, nbytes: int) =
  ## Write part's data ``data`` to the output stream.
  doAssert(mpw.kind == MultiPartSource.Buffer)
  doAssert(mpw.state == MultiPartWriterState.PartStarted)
  let index = len(mpw.buffer)
  if nbytes > 0:
    mpw.buffer.setLen(index + nbytes)
    copyMem(addr mpw.buffer[0], pbytes, nbytes)

proc write*(mpw: var MultiPartWriter, data: openArray[byte]) =
  ## Write part's data ``data`` to the output stream.
  doAssert(mpw.kind == MultiPartSource.Buffer)
  doAssert(mpw.state == MultiPartWriterState.PartStarted)
  mpw.buffer.add(data)

proc write*(mpw: var MultiPartWriter, data: openArray[char]) =
  ## Write part's data ``data`` to the output stream.
  doAssert(mpw.kind == MultiPartSource.Buffer)
  doAssert(mpw.state == MultiPartWriterState.PartStarted)
  mpw.buffer.add(data.toOpenArrayByte(0, len(data) - 1))

proc finishPart*(mpw: MultiPartWriterRef) {.async.} =
  ## Finish multipart's message part and send proper markers to output stream.
  doAssert(mpw.state == MultiPartWriterState.PartStarted)
  try:
    # write "<CR><LF>--"
    await mpw.stream.write(mpw.finishPartMark)
    mpw.state = MultiPartWriterState.PartFinished
  except AsyncStreamError:
    mpw.state = MultiPartWriterState.MessageFailure
    raiseHttpCriticalError("Unable to finish multipart message part")

proc finishPart*(mpw: var MultiPartWriter) =
  ## Finish multipart's message part and send proper markers to output stream.
  doAssert(mpw.kind == MultiPartSource.Buffer)
  doAssert(mpw.state == MultiPartWriterState.PartStarted)
  # write "<CR><LF>--"
  mpw.buffer.add(mpw.finishPartMark)
  mpw.state = MultiPartWriterState.PartFinished

proc finish*(mpw: MultiPartWriterRef) {.async.} =
  ## Finish multipart's message form and send finishing markers to the output
  ## stream.
  doAssert(mpw.kind == MultiPartSource.Stream)
  doAssert(mpw.state == MultiPartWriterState.PartFinished)
  try:
    # write "<boundary>--"
    await mpw.stream.write(mpw.finishMark)
    mpw.state = MultiPartWriterState.MessageFinished
  except AsyncStreamError:
    mpw.state = MultiPartWriterState.MessageFailure
    raiseHttpCriticalError("Unable to finish multipart message")

proc finish*(mpw: var MultiPartWriter): seq[byte] =
  ## Finish multipart's message form and send finishing markers to the output
  ## stream.
  doAssert(mpw.kind == MultiPartSource.Buffer)
  doAssert(mpw.state == MultiPartWriterState.PartFinished)
  # write "<boundary>--"
  mpw.buffer.add(mpw.finishMark)
  mpw.state = MultiPartWriterState.MessageFinished
  mpw.buffer
