 #
#        Chronos HTTP/S server implementation
#             (c) Copyright 2021-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[tables, uri, strutils]
import stew/[results, base10], httputils
import ../../asyncloop, ../../asyncsync
import ../../streams/[asyncstream, boundstream, chunkstream]
import httptable, httpcommon, multipart
export asyncloop, asyncsync, httptable, httpcommon, httputils, multipart,
       asyncstream, boundstream, chunkstream, uri, tables, results

type
  HttpServerFlags* {.pure.} = enum
    Secure,
      ## Internal flag which indicates that server working in secure TLS mode
    NoExpectHandler,
      ## Do not handle `Expect` header automatically
    NotifyDisconnect,
      ## Notify user-callback when remote client disconnects.
    QueryCommaSeparatedArray
      ## Enable usage of comma as an array item delimiter in url-encoded
      ## entities (e.g. query string or POST body).

  HttpServerError* {.pure.} = enum
    TimeoutError, CatchableError, RecoverableError, CriticalError,
    DisconnectError

  HttpServerState* {.pure.} = enum
    ServerRunning, ServerStopped, ServerClosed

  HttpProcessError* = object
    error*: HttpServerError
    code*: HttpCode
    exc*: ref CatchableError
    remote*: TransportAddress

  RequestFence* = Result[HttpRequestRef, HttpProcessError]

  HttpRequestFlags* {.pure.} = enum
    BoundBody, UnboundBody, MultipartForm, UrlencodedForm, ClientExpect

  HttpResponseFlags* {.pure.} = enum
    KeepAlive, Stream

  HttpResponseStreamType* {.pure.} = enum
    Plain, SSE, Chunked

  HttpResponseState* {.pure.} = enum
    Empty, Prepared, Sending, Finished, Failed, Cancelled, Dumb

  HttpProcessCallback* =
    proc(req: RequestFence): Future[HttpResponseRef] {.
      gcsafe, raises: [Defect, CatchableError].}

  HttpConnectionCallback* =
    proc(server: HttpServerRef,
         transp: StreamTransport): Future[HttpConnectionRef] {.
      gcsafe, raises: [Defect].}

  HttpServer* = object of RootObj
    instance*: StreamServer
    address*: TransportAddress
    # semaphore*: AsyncSemaphore
    maxConnections*: int
    backlogSize*: int
    baseUri*: Uri
    serverIdent*: string
    flags*: set[HttpServerFlags]
    socketFlags*: set[ServerFlags]
    connections*: Table[string, Future[void]]
    acceptLoop*: Future[void]
    lifetime*: Future[void]
    headersTimeout*: Duration
    bufferSize*: int
    maxHeadersSize*: int
    maxRequestBodySize*: int
    processCallback*: HttpProcessCallback
    createConnCallback*: HttpConnectionCallback

  HttpServerRef* = ref HttpServer

  HttpRequest* = object of RootObj
    state*: HttpState
    headers*: HttpTable
    query*: HttpTable
    postTable: Opt[HttpTable]
    rawPath*: string
    uri*: Uri
    scheme*: string
    version*: HttpVersion
    meth*: HttpMethod
    contentEncoding*: set[ContentEncodingFlags]
    transferEncoding*: set[TransferEncodingFlags]
    requestFlags*: set[HttpRequestFlags]
    contentLength*: int
    contentTypeData*: Opt[ContentTypeData]
    connection*: HttpConnectionRef
    response*: Opt[HttpResponseRef]

  HttpRequestRef* = ref HttpRequest

  HttpResponse* = object of RootObj
    status*: HttpCode
    version*: HttpVersion
    headersTable: HttpTable
    body: seq[byte]
    flags: set[HttpResponseFlags]
    state*: HttpResponseState
    connection*: HttpConnectionRef
    streamType*: HttpResponseStreamType
    writer: AsyncStreamWriter

  HttpResponseRef* = ref HttpResponse

  HttpConnection* = object of RootObj
    state*: HttpState
    server*: HttpServerRef
    transp: StreamTransport
    mainReader*: AsyncStreamReader
    mainWriter*: AsyncStreamWriter
    reader*: AsyncStreamReader
    writer*: AsyncStreamWriter
    buffer: seq[byte]

  HttpConnectionRef* = ref HttpConnection

  ByteChar* = string | seq[byte]

proc init(htype: typedesc[HttpProcessError], error: HttpServerError,
          exc: ref CatchableError, remote: TransportAddress,
          code: HttpCode): HttpProcessError {.raises: [Defect].} =
  HttpProcessError(error: error, exc: exc, remote: remote, code: code)

proc createConnection(server: HttpServerRef,
                     transp: StreamTransport): Future[HttpConnectionRef] {.
     gcsafe.}

proc new*(htype: typedesc[HttpServerRef],
          address: TransportAddress,
          processCallback: HttpProcessCallback,
          serverFlags: set[HttpServerFlags] = {},
          socketFlags: set[ServerFlags] = {ReuseAddr},
          serverUri = Uri(),
          serverIdent = "",
          maxConnections: int = -1,
          bufferSize: int = 4096,
          backlogSize: int = 100,
          httpHeadersTimeout = 10.seconds,
          maxHeadersSize: int = 8192,
          maxRequestBodySize: int = 1_048_576): HttpResult[HttpServerRef] {.
     raises: [Defect].} =

  let serverUri =
    if len(serverUri.hostname) > 0:
      serverUri
    else:
      try:
        parseUri("http://" & $address & "/")
      except TransportAddressError as exc:
        return err(exc.msg)

  let serverInstance =
    try:
      createStreamServer(address, flags = socketFlags, bufferSize = bufferSize,
                         backlog = backlogSize)
    except TransportOsError as exc:
      return err(exc.msg)
    except CatchableError as exc:
      return err(exc.msg)

  var res = HttpServerRef(
    address: address,peq
    instance: serverInstance,
    processCallback: processCallback,
    createConnCallback: createConnection,
    baseUri: serverUri,
    serverIdent: serverIdent,
    flags: serverFlags,
    socketFlags: socketFlags,
    maxConnections: maxConnections,
    bufferSize: bufferSize,
    backlogSize: backlogSize,
    headersTimeout: httpHeadersTimeout,
    maxHeadersSize: maxHeadersSize,
    maxRequestBodySize: maxRequestBodySize,
    # semaphore:
    #   if maxConnections > 0:
    #     newAsyncSemaphore(maxConnections)
    #   else:
    #     nil
    lifetime: newFuture[void]("http.server.lifetime"),
    connections: initTable[string, Future[void]]()
  )
  ok(res)

proc getResponse*(req: HttpRequestRef): HttpResponseRef {.raises: [Defect].} =
  if req.response.isNone():
    var resp = HttpResponseRef(
      status: Http200,
      state: HttpResponseState.Empty,
      version: req.version,
      headersTable: HttpTable.init(),
      connection: req.connection,
      flags: if req.version == HttpVersion11:
               {HttpResponseFlags.KeepAlive}
             else:
               {}
    )
    req.response = Opt.some(resp)
    resp
  else:
    req.response.get()

proc getHostname*(server: HttpServerRef): string =
  if len(server.baseUri.port) > 0:
    server.baseUri.hostname & ":" & server.baseUri.port
  else:
    server.baseUri.hostname

proc dumbResponse*(): HttpResponseRef {.raises: [Defect].} =
  ## Create an empty response to return when request processor got no request.
  HttpResponseRef(state: HttpResponseState.Dumb, version: HttpVersion11)

proc getId(transp: StreamTransport): Result[string, string]  {.inline.} =
  ## Returns string unique transport's identifier as string.
  try:
    ok($transp.remoteAddress() & "_" & $transp.localAddress())
  except TransportOsError as exc:
    err($exc.msg)

proc hasBody*(request: HttpRequestRef): bool {.raises: [Defect].} =
  ## Returns ``true`` if request has body.
  request.requestFlags * {HttpRequestFlags.BoundBody,
                          HttpRequestFlags.UnboundBody} != {}

proc prepareRequest(conn: HttpConnectionRef,
                    req: HttpRequestHeader): HttpResultCode[HttpRequestRef] {.
     raises: [Defect].}=
  var request = HttpRequestRef(connection: conn, state: HttpState.Alive)

  if req.version notin {HttpVersion10, HttpVersion11}:
    return err(Http505)

  request.scheme =
    if HttpServerFlags.Secure in conn.server.flags:
      "https"
    else:
      "http"

  request.version = req.version
  request.meth = req.meth

  request.rawPath =
    block:
      let res = req.uri()
      if len(res) == 0:
        return err(Http400)
      res

  request.uri =
    if request.rawPath != "*":
      let uri = parseUri(request.rawPath)
      if uri.scheme notin ["http", "https", ""]:
        return err(Http400)
      uri
    else:
      var uri = initUri()
      uri.path = "*"
      uri

  request.query =
    block:
      let queryFlags =
        if QueryCommaSeparatedArray in conn.server.flags:
          {QueryParamsFlag.CommaSeparatedArray}
        else:
          {}
      var table = HttpTable.init()
      for key, value in queryParams(request.uri.query, queryFlags):
        table.add(key, value)
      table

  request.headers =
    block:
      var table = HttpTable.init()
      # Retrieve headers and values
      for key, value in req.headers():
        table.add(key, value)
      # Validating HTTP request headers
      # Some of the headers must be present only once.
      if table.count(ContentTypeHeader) > 1:
        return err(Http400)
      if table.count(ContentLengthHeader) > 1:
        return err(Http400)
      if table.count(TransferEncodingHeader) > 1:
        return err(Http400)
      table

  # Preprocessing "Content-Encoding" header.
  request.contentEncoding =
    block:
      let res = getContentEncoding(
        request.headers.getList(ContentEncodingHeader))
      if res.isErr():
        return err(Http400)
      else:
        res.get()

  # Preprocessing "Transfer-Encoding" header.
  request.transferEncoding =
    block:
      let res = getTransferEncoding(
        request.headers.getList(TransferEncodingHeader))
      if res.isErr():
        return err(Http400)
      else:
        res.get()

  # Almost all HTTP requests could have body (except TRACE), we perform some
  # steps to reveal information about body.
  if ContentLengthHeader in request.headers:
    let length = request.headers.getInt(ContentLengthHeader)
    if length >= 0:
      if request.meth == MethodTrace:
        return err(Http400)
      # Because of coversion to `int` we should avoid unexpected OverflowError.
      if length > uint64(high(int)):
        return err(Http413)
      if length > uint64(conn.server.maxRequestBodySize):
        return err(Http413)
      request.contentLength = int(length)
      request.requestFlags.incl(HttpRequestFlags.BoundBody)
  else:
    if TransferEncodingFlags.Chunked in request.transferEncoding:
      if request.meth == MethodTrace:
        return err(Http400)
      request.requestFlags.incl(HttpRequestFlags.UnboundBody)

  if request.hasBody():
    # If request has body, we going to understand how its encoded.
    if ContentTypeHeader in request.headers:
      let contentType =
        getContentType(request.headers.getList(ContentTypeHeader)).valueOr:
          return err(Http415)
      if contentType == UrlEncodedContentType:
        request.requestFlags.incl(HttpRequestFlags.UrlencodedForm)
      elif contentType == MultipartContentType:
        request.requestFlags.incl(HttpRequestFlags.MultipartForm)
      request.contentTypeData = Opt.some(contentType)

    if ExpectHeader in request.headers:
      let expectHeader = request.headers.getString(ExpectHeader)
      if strip(expectHeader).toLowerAscii() == "100-continue":
        request.requestFlags.incl(HttpRequestFlags.ClientExpect)

  ok(request)

proc getBodyReader*(request: HttpRequestRef): HttpResult[HttpBodyReader] =
  ## Returns stream's reader instance which can be used to read request's body.
  ##
  ## Please be sure to handle ``Expect`` header properly.
  ##
  ## Streams which was obtained using this procedure must be closed to avoid
  ## leaks.
  if HttpRequestFlags.BoundBody in request.requestFlags:
    let bstream = newBoundedStreamReader(request.connection.reader,
                                         uint64(request.contentLength))
    ok(newHttpBodyReader(bstream))
  elif HttpRequestFlags.UnboundBody in request.requestFlags:
    let maxBodySize = request.connection.server.maxRequestBodySize
    let cstream = newChunkedStreamReader(request.connection.reader)
    let bstream = newBoundedStreamReader(cstream, uint64(maxBodySize),
                                         comparison = BoundCmp.LessOrEqual)
    ok(newHttpBodyReader(bstream, cstream))
  else:
    err("Request do not have body available")

proc handleExpect*(request: HttpRequestRef) {.async.} =
  ## Handle expectation for ``Expect`` header.
  ## https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Expect
  if HttpServerFlags.NoExpectHandler notin request.connection.server.flags:
    if HttpRequestFlags.ClientExpect in request.requestFlags:
      if request.version == HttpVersion11:
        try:
          let message = $request.version & " " & $Http100 & "\r\n\r\n"
          await request.connection.writer.write(message)
        except CancelledError as exc:
          raise exc
        except AsyncStreamWriteError, AsyncStreamIncompleteError:
          raiseHttpCriticalError("Unable to send `100-continue` response")

proc getBody*(request: HttpRequestRef): Future[seq[byte]] {.async.} =
  ## Obtain request's body as sequence of bytes.
  let bodyReader = request.getBodyReader()
  if bodyReader.isErr():
    return @[]
  else:
    var reader = bodyReader.get()
    try:
      await request.handleExpect()
      let res = await reader.read()
      if reader.hasOverflow():
        await reader.closeWait()
        reader = nil
        raiseHttpCriticalError(MaximumBodySizeError, Http413)
      else:
        await reader.closeWait()
        reader = nil
        return res
    except CancelledError as exc:
      if not(isNil(reader)):
        await reader.closeWait()
      raise exc
    except AsyncStreamError:
      if not(isNil(reader)):
        await reader.closeWait()
      raiseHttpCriticalError("Unable to read request's body")

proc consumeBody*(request: HttpRequestRef): Future[void] {.async.} =
  ## Consume/discard request's body.
  let bodyReader = request.getBodyReader()
  if bodyReader.isErr():
    return
  else:
    var reader = bodyReader.get()
    try:
      await request.handleExpect()
      discard await reader.consume()
      if reader.hasOverflow():
        await reader.closeWait()
        reader = nil
        raiseHttpCriticalError(MaximumBodySizeError, Http413)
      else:
        await reader.closeWait()
        reader = nil
        return
    except CancelledError as exc:
      if not(isNil(reader)):
        await reader.closeWait()
      raise exc
    except AsyncStreamError:
      if not(isNil(reader)):
        await reader.closeWait()
      raiseHttpCriticalError("Unable to read request's body")

proc getAcceptInfo*(request: HttpRequestRef): Result[AcceptInfo, cstring] =
  ## Returns value of `Accept` header as `AcceptInfo` object.
  ##
  ## If ``Accept`` header is missing in request headers, ``*/*`` content
  ## type will be returned.
  let acceptHeader = request.headers.getString(AcceptHeaderName)
  getAcceptInfo(acceptHeader)

proc preferredContentMediaType*(acceptHeader: string): MediaType =
  ## Returns preferred content-type using ``Accept`` header value specified by
  ## string ``acceptHeader``.
  let res = getAcceptInfo(acceptHeader)
  if res.isErr():
    # If `Accept` header is incorrect, client accepts any type of content.
    MediaType.init("*", "*")
  else:
    let mediaTypes = res.get().data
    if len(mediaTypes) > 0:
      mediaTypes[0].mediaType
    else:
      MediaType.init("*", "*")

proc preferredContentType*(acceptHeader: string,
                           types: varargs[MediaType]
                          ): Result[MediaType, cstring] =
  ## Match or obtain preferred content type using ``Accept`` header specified by
  ## string ``acceptHeader`` and server preferred content types ``types``.
  ##
  ## If ``Accept`` header is missing in client's request - ``types[0]`` or
  ## ``*/*`` value will be returned as result.
  ##
  ## If ``Accept`` header has incorrect format in client's request -
  ## ``types[0]`` or ``*/*`` value will be returned as result.
  ##
  ## If ``Accept`` header is present in request to server and it has one or more
  ## content types supported by client, the best value will be selected from
  ## ``types`` using position and quality value (weight) reported in ``Accept``
  ## header. If client do not support any methods in ``types`` error
  ## will be returned.
  ##
  ## Note: Quality value (weight) for content type has priority over server's
  ## preferred content-type.
  if len(types) == 0:
    if len(acceptHeader) == 0:
      # If `Accept` header is missing, return `*/*`.
      ok(wildCardMediaType)
    else:
      let res = getAcceptInfo(acceptHeader)
      if res.isErr():
        # If `Accept` header is incorrect, client accepts any type of content.
        ok(wildCardMediaType)
      else:
        let mediaTypes = res.get().data
        var
          currentType = MediaType()
          currentWeight = 0.0
        # `Accept` header values array is not sorted, so we need to find value
        # with the biggest ``q-value``.
        for item in mediaTypes:
          if currentWeight < item.qvalue:
            currentType = item.mediaType
            currentWeight = item.qvalue
        if len(currentType.media) == 0 and len(currentType.subtype) == 0:
          ok(wildCardMediaType)
        else:
          ok(currentType)
  else:
    if len(acceptHeader) == 0:
      # If `Accept` header is missing, client accepts any type of content.
      ok(types[0])
    else:
      let ares = getAcceptInfo(acceptHeader)
      if ares.isErr():
        # If `Accept` header is incorrect, client accepts any type of content.
        ok(types[0])
      else:
        # ``maxWeight`` represents maximum possible weight value which can be
        # obtained.
        let maxWeight = (1.0, 0)
        var
          currentType = MediaType()
          currentIndex = -1
          currentWeight = (-1.0, 0)

        for itemType in ares.get().data:
          let preferredIndex = types.find(itemType.mediaType)
          if preferredIndex != -1:
            let weight = (itemType.qvalue, -preferredIndex)
            if currentWeight < weight:
              currentType = types[preferredIndex]
              currentWeight = weight
              currentIndex = preferredIndex

          if currentWeight == maxWeight:
            # There is no reason to continue search, because maximum possible
            # weight is already achieved, so this is the best match.
            break

        if currentIndex == -1:
          err("Preferred content type not found")
        else:
          ok(currentType)

proc preferredContentMediaType*(request: HttpRequestRef): MediaType =
  ## Returns preferred content-type using ``Accept`` header specified by
  ## client in request ``request``.
  preferredContentMediaType(request.headers.getString(AcceptHeaderName))

proc preferredContentType*(request: HttpRequestRef,
                           types: varargs[MediaType]
                          ): Result[MediaType, cstring] =
  ## Match or obtain preferred content-type using ``Accept`` header specified by
  ## client in request ``request``.
  preferredContentType(request.headers.getString(AcceptHeaderName), types)

proc sendErrorResponse(conn: HttpConnectionRef, version: HttpVersion,
                       code: HttpCode, keepAlive = true,
                       datatype = "text/text",
                       databody = ""): Future[bool] {.async.} =
  var answer = $version & " " & $code & "\r\n"
  answer.add(DateHeader)
  answer.add(": ")
  answer.add(httpDate())
  answer.add("\r\n")
  if len(datatype) > 0:
    answer.add(ContentTypeHeader)
    answer.add(": ")
    answer.add(datatype)
    answer.add("\r\n")
  answer.add(ContentLengthHeader)
  answer.add(": ")
  answer.add(Base10.toString(uint64(len(databody))))
  answer.add("\r\n")
  if keepAlive:
    answer.add(ConnectionHeader)
    answer.add(": keep-alive\r\n")
  else:
    answer.add(ConnectionHeader)
    answer.add(": close\r\n")
  answer.add("\r\n")
  if len(databody) > 0:
    answer.add(databody)
  try:
    await conn.writer.write(answer)
    return true
  except CancelledError:
    return false
  except AsyncStreamWriteError:
    return false
  except AsyncStreamIncompleteError:
    return false

proc getRequest(conn: HttpConnectionRef): Future[HttpRequestRef] {.async.} =
  try:
    conn.buffer.setLen(conn.server.maxHeadersSize)
    let res = await conn.reader.readUntil(addr conn.buffer[0], len(conn.buffer),
                                          HeadersMark)
    conn.buffer.setLen(res)
    let header = parseRequest(conn.buffer)
    if header.failed():
      raiseHttpCriticalError("Malformed request recieved")
    else:
      let res = prepareRequest(conn, header)
      if res.isErr():
        raiseHttpCriticalError("Invalid request received", res.error)
      else:
        return res.get()
  except AsyncStreamIncompleteError, AsyncStreamReadError:
    raiseHttpDisconnectError()
  except AsyncStreamLimitError:
    raiseHttpCriticalError("Maximum size of request headers reached", Http431)

proc init*(value: var HttpConnection, server: HttpServerRef,
           transp: StreamTransport) =
  value = HttpConnection(
    state: HttpState.Alive,
    server: server,
    transp: transp,
    buffer: newSeq[byte](server.maxHeadersSize),
    mainReader: newAsyncStreamReader(transp),
    mainWriter: newAsyncStreamWriter(transp)
  )

proc new(ht: typedesc[HttpConnectionRef], server: HttpServerRef,
         transp: StreamTransport): HttpConnectionRef =
  var res = HttpConnectionRef()
  res[].init(server, transp)
  res.reader = res.mainReader
  res.writer = res.mainWriter
  res

proc closeWait*(conn: HttpConnectionRef) {.async.} =
  if conn.state == HttpState.Alive:
    conn.state = HttpState.Closing
    var pending: seq[Future[void]]
    if conn.reader != conn.mainReader:
      pending.add(conn.reader.closeWait())
    if conn.writer != conn.mainWriter:
      pending.add(conn.writer.closeWait())
    if len(pending) > 0:
      await allFutures(pending)
    # After we going to close everything else.
    pending.setLen(3)
    pending[0] = conn.mainReader.closeWait()
    pending[1] = conn.mainWriter.closeWait()
    pending[2] = conn.transp.closeWait()
    await allFutures(pending)
    conn.state = HttpState.Closed

proc closeWait*(req: HttpRequestRef) {.async.} =
  if req.state == HttpState.Alive:
    if req.response.isSome():
      req.state = HttpState.Closing
      let resp = req.response.get()
      if (HttpResponseFlags.Stream in resp.flags) and not(isNil(resp.writer)):
        await resp.writer.closeWait()
    req.state = HttpState.Closed

proc createConnection(server: HttpServerRef,
                      transp: StreamTransport): Future[HttpConnectionRef] {.
     async.} =
  return HttpConnectionRef.new(server, transp)

proc `keepalive=`*(resp: HttpResponseRef, value: bool) =
  doAssert(resp.state == HttpResponseState.Empty)
  if value:
    resp.flags.incl(HttpResponseFlags.KeepAlive)
  else:
    resp.flags.excl(HttpResponseFlags.KeepAlive)

proc keepalive*(resp: HttpResponseRef): bool {.raises: [Defect].} =
  HttpResponseFlags.KeepAlive in resp.flags

proc processLoop(server: HttpServerRef, transp: StreamTransport,
                 connId: string) {.async.} =
  var
    conn: HttpConnectionRef
    connArg: RequestFence
    runLoop = false

  try:
    conn = await server.createConnCallback(server, transp)
    runLoop = true
  except CancelledError:
    server.connections.del(connId)
    await transp.closeWait()
    return
  except HttpCriticalError as exc:
    let error = HttpProcessError.init(HttpServerError.CriticalError, exc,
                                      transp.remoteAddress(), exc.code)
    connArg = RequestFence.err(error)
    runLoop = false

  if not(runLoop):
    try:
      # We still want to notify process callback about failure, but we ignore
      # result.
      discard await server.processCallback(connArg)
    except CancelledError:
      runLoop = false
    except CatchableError as exc:
      # There should be no exceptions, so we will raise `Defect`.
      raiseHttpDefect("Unexpected exception catched [" & $exc.name & "]")

  var breakLoop = false
  while runLoop:
    var
      arg: RequestFence
      resp: HttpResponseRef

    try:
      let request =
        if server.headersTimeout.isInfinite():
          await conn.getRequest()
        else:
          await conn.getRequest().wait(server.headersTimeout)
      arg = RequestFence.ok(request)
    except CancelledError:
      breakLoop = true
    except AsyncTimeoutError as exc:
      let error = HttpProcessError.init(HttpServerError.TimeoutError, exc,
                                        transp.remoteAddress(), Http408)
      arg = RequestFence.err(error)
    except HttpRecoverableError as exc:
      let error = HttpProcessError.init(HttpServerError.RecoverableError, exc,
                                        transp.remoteAddress(), exc.code)
      arg = RequestFence.err(error)
    except HttpCriticalError as exc:
      let error = HttpProcessError.init(HttpServerError.CriticalError, exc,
                                        transp.remoteAddress(), exc.code)
      arg = RequestFence.err(error)
    except HttpDisconnectError as exc:
      if HttpServerFlags.NotifyDisconnect in server.flags:
        let error = HttpProcessError.init(HttpServerError.DisconnectError, exc,
                                          transp.remoteAddress(), Http400)
        arg = RequestFence.err(error)
      else:
        breakLoop = true
    except CatchableError as exc:
      let error = HttpProcessError.init(HttpServerError.CatchableError, exc,
                                        transp.remoteAddress(), Http500)
      arg = RequestFence.err(error)

    if breakLoop:
      break

    breakLoop = false
    var lastErrorCode: Opt[HttpCode]

    try:
      resp = await conn.server.processCallback(arg)
    except CancelledError:
      breakLoop = true
    except HttpCriticalError as exc:
      lastErrorCode = Opt.some(exc.code)
    except HttpRecoverableError as exc:
      lastErrorCode = Opt.some(exc.code)
    except CatchableError:
      lastErrorCode = Opt.some(Http503)

    if breakLoop:
      break

    if arg.isErr():
      let code = arg.error().code
      try:
        case arg.error().error
        of HttpServerError.TimeoutError:
          discard await conn.sendErrorResponse(HttpVersion11, code, false)
        of HttpServerError.RecoverableError:
          discard await conn.sendErrorResponse(HttpVersion11, code, false)
        of HttpServerError.CriticalError:
          discard await conn.sendErrorResponse(HttpVersion11, code, false)
        of HttpServerError.CatchableError:
          discard await conn.sendErrorResponse(HttpVersion11, code, false)
        of HttpServerError.DisconnectError:
          discard
      except CancelledError:
        # We swallowing `CancelledError` in a loop, but we going to exit
        # loop ASAP.
        discard
      break
    else:
      let request = arg.get()
      var keepConn = if request.version == HttpVersion11: true else: false
      if lastErrorCode.isNone():
        if isNil(resp):
          # Response was `nil`.
          try:
            discard await conn.sendErrorResponse(HttpVersion11, Http404, false)
          except CancelledError:
            keepConn = false
        else:
          try:
            case resp.state
            of HttpResponseState.Empty:
              # Response was ignored
              discard await conn.sendErrorResponse(HttpVersion11, Http404,
                                                   keepConn)
            of HttpResponseState.Prepared:
              # Response was prepared but not sent.
              discard await conn.sendErrorResponse(HttpVersion11, Http409,
                                                   keepConn)
            else:
              # some data was already sent to the client.
              keepConn = resp.keepalive()
          except CancelledError:
            keepConn = false
      else:
        try:
          discard await conn.sendErrorResponse(HttpVersion11,
                                               lastErrorCode.get(), false)
        except CancelledError:
          keepConn = false

      # Closing and releasing all the request resources.
      try:
        await request.closeWait()
      except CancelledError:
        # We swallowing `CancelledError` in a loop, but we still need to close
        # `request` before exiting.
        await request.closeWait()

      if not(keepConn):
        break

  # Connection could be `nil` only when secure handshake is failed.
  if not(isNil(conn)):
    try:
      await conn.closeWait()
    except CancelledError:
      # Cancellation could be happened while we closing `conn`. But we still
      # need to close it.
      await conn.closeWait()

  server.connections.del(connId)
  # if server.maxConnections > 0:
  #   server.semaphore.release()

proc acceptClientLoop(server: HttpServerRef) {.async.} =
  var breakLoop = false
  while true:
    try:
      # if server.maxConnections > 0:
      #   await server.semaphore.acquire()
      let transp = await server.instance.accept()
      let resId = transp.getId()
      if resId.isErr():
        # We are unable to identify remote peer, it means that remote peer
        # disconnected before identification.
        await transp.closeWait()
        breakLoop = false
      else:
        let connId = resId.get()
        server.connections[connId] = processLoop(server, transp, connId)
    except CancelledError:
      # Server was stopped
      breakLoop = true
    except TransportOsError:
      # This is some critical unrecoverable error.
      breakLoop = true
    except TransportTooManyError:
      # Non critical error
      breakLoop = false
    except TransportAbortedError:
      # Non critical error
      breakLoop = false
    except CatchableError:
      # Unexpected error
      breakLoop = true

    if breakLoop:
      break

proc state*(server: HttpServerRef): HttpServerState {.raises: [Defect].} =
  ## Returns current HTTP server's state.
  if server.lifetime.finished():
    ServerClosed
  else:
    if isNil(server.acceptLoop):
      ServerStopped
    else:
      if server.acceptLoop.finished():
        ServerStopped
      else:
        ServerRunning

proc start*(server: HttpServerRef) =
  ## Starts HTTP server.
  if server.state == ServerStopped:
    server.acceptLoop = acceptClientLoop(server)

proc stop*(server: HttpServerRef) {.async.} =
  ## Stop HTTP server from accepting new connections.
  if server.state == ServerRunning:
    await server.acceptLoop.cancelAndWait()

proc drop*(server: HttpServerRef) {.async.} =
  ## Drop all pending HTTP connections.
  var pending: seq[Future[void]]
  if server.state in {ServerStopped, ServerRunning}:
    for fut in server.connections.values():
      if not(fut.finished()):
        fut.cancel()
        pending.add(fut)
    await allFutures(pending)

proc closeWait*(server: HttpServerRef) {.async.} =
  ## Stop HTTP server and drop all the pending connections.
  if server.state != ServerClosed:
    await server.stop()
    await server.drop()
    await server.instance.closeWait()
    server.lifetime.complete()

proc join*(server: HttpServerRef): Future[void] =
  ## Wait until HTTP server will not be closed.
  var retFuture = newFuture[void]("http.server.join")

  proc continuation(udata: pointer) {.gcsafe.} =
    if not(retFuture.finished()):
      retFuture.complete()

  proc cancellation(udata: pointer) {.gcsafe.} =
    if not(retFuture.finished()):
      server.lifetime.removeCallback(continuation, cast[pointer](retFuture))

  if server.state == ServerClosed:
    retFuture.complete()
  else:
    server.lifetime.addCallback(continuation, cast[pointer](retFuture))
    retFuture.cancelCallback = cancellation

  retFuture

proc getMultipartReader*(req: HttpRequestRef): HttpResult[MultiPartReaderRef] {.
     raises: [Defect].} =
  ## Create new MultiPartReader interface for specific request.
  if req.meth in PostMethods:
    if MultipartForm in req.requestFlags:
      if req.contentTypeData.isSome():
        let boundary = ? getMultipartBoundary(req.contentTypeData.get())
        var stream = ? req.getBodyReader()
        ok(MultiPartReaderRef.new(stream, boundary))
      else:
        err("Content type is missing or invalid")
    else:
      err("Request's data is not multipart encoded")
  else:
    err("Request's method do not supports multipart")

proc post*(req: HttpRequestRef): Future[HttpTable] {.async.} =
  ## Return POST parameters
  if req.postTable.isSome():
    return req.postTable.get()
  else:
    if req.meth notin PostMethods:
      return HttpTable.init()

    if UrlencodedForm in req.requestFlags:
      let queryFlags =
        if QueryCommaSeparatedArray in req.connection.server.flags:
          {QueryParamsFlag.CommaSeparatedArray}
        else:
          {}
      var table = HttpTable.init()
      # getBody() will handle `Expect`.
      var body = await req.getBody()
      # TODO (cheatfate) double copy here, because of `byte` to `char`
      # conversion.
      var strbody = newString(len(body))
      if len(body) > 0:
        copyMem(addr strbody[0], addr body[0], len(body))
      for key, value in queryParams(strbody, queryFlags):
        table.add(key, value)
      req.postTable = Opt.some(table)
      return table
    elif MultipartForm in req.requestFlags:
      var table = HttpTable.init()
      let res = getMultipartReader(req)
      if res.isErr():
        raiseHttpCriticalError("Unable to retrieve multipart form data")
      var mpreader = res.get()

      # We must handle `Expect` first.
      try:
        await req.handleExpect()
      except CancelledError as exc:
        await mpreader.closeWait()
        raise exc
      except HttpCriticalError as exc:
        await mpreader.closeWait()
        raise exc

      # Reading multipart/form-data parts.
      var runLoop = true
      while runLoop:
        var part: MultiPart
        try:
          part = await mpreader.readPart()
          var value = await part.getBody()
          # TODO (cheatfate) double copy here, because of `byte` to `char`
          # conversion.
          var strvalue = newString(len(value))
          if len(value) > 0:
            copyMem(addr strvalue[0], addr value[0], len(value))
          table.add(part.name, strvalue)
          await part.closeWait()
        except MultipartEOMError:
          runLoop = false
        except HttpCriticalError as exc:
          if not(part.isEmpty()):
            await part.closeWait()
          await mpreader.closeWait()
          raise exc
        except CancelledError as exc:
          if not(part.isEmpty()):
            await part.closeWait()
          await mpreader.closeWait()
          raise exc
      await mpreader.closeWait()
      req.postTable = Opt.some(table)
      return table
    else:
      if HttpRequestFlags.BoundBody in req.requestFlags:
        if req.contentLength != 0:
          raiseHttpCriticalError("Unsupported request body")
        return HttpTable.init()
      elif HttpRequestFlags.UnboundBody in req.requestFlags:
        raiseHttpCriticalError("Unsupported request body")

proc setHeader*(resp: HttpResponseRef, key, value: string) {.
     raises: [Defect].} =
  ## Sets value of header ``key`` to ``value``.
  doAssert(resp.state == HttpResponseState.Empty)
  resp.headersTable.set(key, value)

proc setHeaderDefault*(resp: HttpResponseRef, key, value: string) {.
     raises: [Defect].} =
  ## Sets value of header ``key`` to ``value``, only if header ``key`` is not
  ## present in the headers table.
  discard resp.headersTable.hasKeyOrPut(key, value)

proc addHeader*(resp: HttpResponseRef, key, value: string) {.
     raises: [Defect].} =
  ## Adds value ``value`` to header's ``key`` value.
  doAssert(resp.state == HttpResponseState.Empty)
  resp.headersTable.add(key, value)

proc getHeader*(resp: HttpResponseRef, key: string,
                default: string = ""): string {.raises: [Defect].} =
  ## Returns value of header with name ``name`` or ``default``, if header is
  ## not present in the table.
  resp.headersTable.getString(key, default)

proc hasHeader*(resp: HttpResponseRef, key: string): bool {.raises: [Defect].} =
  ## Returns ``true`` if header with name ``key`` present in the headers table.
  key in resp.headersTable

template checkPending(t: untyped) =
  if t.state != HttpResponseState.Empty:
    raiseHttpCriticalError("Response body was already sent")

func createHeaders(resp: HttpResponseRef): string =
  var answer = $(resp.version) & " " & $(resp.status) & "\r\n"
  for k, v in resp.headersTable.stringItems():
    if len(v) > 0:
      answer.add(normalizeHeaderName(k))
      answer.add(": ")
      answer.add(v)
      answer.add("\r\n")
  answer.add("\r\n")
  answer

proc prepareLengthHeaders(resp: HttpResponseRef, length: int): string {.
     raises: [Defect].}=
  if not(resp.hasHeader(DateHeader)):
    resp.setHeader(DateHeader, httpDate())
  if length > 0:
    if not(resp.hasHeader(ContentTypeHeader)):
      resp.setHeader(ContentTypeHeader, "text/html; charset=utf-8")
  if not(resp.hasHeader(ContentLengthHeader)):
    resp.setHeader(ContentLengthHeader, Base10.toString(uint64(length)))
  if not(resp.hasHeader(ServerHeader)):
    resp.setHeader(ServerHeader, resp.connection.server.serverIdent)
  if not(resp.hasHeader(ConnectionHeader)):
    if HttpResponseFlags.KeepAlive in resp.flags:
      resp.setHeader(ConnectionHeader, "keep-alive")
    else:
      resp.setHeader(ConnectionHeader, "close")
  resp.createHeaders()

proc prepareChunkedHeaders(resp: HttpResponseRef): string {.
     raises: [Defect].} =
  if not(resp.hasHeader(DateHeader)):
    resp.setHeader(DateHeader, httpDate())
  if not(resp.hasHeader(ContentTypeHeader)):
    resp.setHeader(ContentTypeHeader, "text/html; charset=utf-8")
  if not(resp.hasHeader(TransferEncodingHeader)):
    resp.setHeader(TransferEncodingHeader, "chunked")
  if not(resp.hasHeader(ServerHeader)):
    resp.setHeader(ServerHeader, resp.connection.server.serverIdent)
  if not(resp.hasHeader(ConnectionHeader)):
    if HttpResponseFlags.KeepAlive in resp.flags:
      resp.setHeader(ConnectionHeader, "keep-alive")
    else:
      resp.setHeader(ConnectionHeader, "close")
  resp.createHeaders()

proc prepareServerSideEventHeaders(resp: HttpResponseRef): string {.
     raises: [Defect].} =
  if not(resp.hasHeader(DateHeader)):
    resp.setHeader(DateHeader, httpDate())
  if not(resp.hasHeader(ContentTypeHeader)):
    resp.setHeader(ContentTypeHeader, "text/event-stream")
  if not(resp.hasHeader(ServerHeader)):
    resp.setHeader(ServerHeader, resp.connection.server.serverIdent)
  if not(resp.hasHeader(ConnectionHeader)):
    resp.flags.excl(HttpResponseFlags.KeepAlive)
    resp.setHeader(ConnectionHeader, "close")
  resp.createHeaders()

proc preparePlainHeaders(resp: HttpResponseRef): string {.
     raises: [Defect].} =
  if not(resp.hasHeader(DateHeader)):
    resp.setHeader(DateHeader, httpDate())
  if not(resp.hasHeader(ServerHeader)):
    resp.setHeader(ServerHeader, resp.connection.server.serverIdent)
  if not(resp.hasHeader(ConnectionHeader)):
    resp.flags.excl(HttpResponseFlags.KeepAlive)
    resp.setHeader(ConnectionHeader, "close")
  resp.createHeaders()

proc sendBody*(resp: HttpResponseRef, pbytes: pointer, nbytes: int) {.async.} =
  ## Send HTTP response at once by using bytes pointer ``pbytes`` and length
  ## ``nbytes``.
  doAssert(not(isNil(pbytes)), "pbytes must not be nil")
  doAssert(nbytes >= 0, "nbytes should be bigger or equal to zero")
  checkPending(resp)
  let responseHeaders = resp.prepareLengthHeaders(nbytes)
  resp.state = HttpResponseState.Prepared
  try:
    resp.state = HttpResponseState.Sending
    await resp.connection.writer.write(responseHeaders)
    if nbytes > 0:
      await resp.connection.writer.write(pbytes, nbytes)
    resp.state = HttpResponseState.Finished
  except CancelledError as exc:
    resp.state = HttpResponseState.Cancelled
    raise exc
  except AsyncStreamWriteError, AsyncStreamIncompleteError:
    resp.state = HttpResponseState.Failed
    raiseHttpCriticalError("Unable to send response")

proc sendBody*(resp: HttpResponseRef, data: ByteChar) {.async.} =
  ## Send HTTP response at once by using data ``data``.
  checkPending(resp)
  let responseHeaders = resp.prepareLengthHeaders(len(data))
  resp.state = HttpResponseState.Prepared
  try:
    resp.state = HttpResponseState.Sending
    await resp.connection.writer.write(responseHeaders)
    if len(data) > 0:
      await resp.connection.writer.write(data)
    resp.state = HttpResponseState.Finished
  except CancelledError as exc:
    resp.state = HttpResponseState.Cancelled
    raise exc
  except AsyncStreamWriteError, AsyncStreamIncompleteError:
    resp.state = HttpResponseState.Failed
    raiseHttpCriticalError("Unable to send response")

proc sendError*(resp: HttpResponseRef, code: HttpCode, body = "") {.async.} =
  ## Send HTTP error status response.
  checkPending(resp)
  resp.status = code
  let responseHeaders = resp.prepareLengthHeaders(len(body))
  resp.state = HttpResponseState.Prepared
  try:
    resp.state = HttpResponseState.Sending
    await resp.connection.writer.write(responseHeaders)
    if len(body) > 0:
      await resp.connection.writer.write(body)
    resp.state = HttpResponseState.Finished
  except CancelledError as exc:
    resp.state = HttpResponseState.Cancelled
    raise exc
  except AsyncStreamWriteError, AsyncStreamIncompleteError:
    resp.state = HttpResponseState.Failed
    raiseHttpCriticalError("Unable to send response")

proc prepare*(resp: HttpResponseRef,
              streamType = HttpResponseStreamType.Chunked) {.async.} =
  ## Prepare for HTTP stream response.
  ##
  ## Such responses will be sent chunk by chunk using ``chunked`` encoding.
  resp.checkPending()
  let responseHeaders =
    case streamType
    of HttpResponseStreamType.Plain:
      resp.preparePlainHeaders()
    of HttpResponseStreamType.SSE:
      resp.prepareServerSideEventHeaders()
    of HttpResponseStreamType.Chunked:
      resp.prepareChunkedHeaders()
  resp.streamType = streamType
  resp.state = HttpResponseState.Prepared
  try:
    resp.state = HttpResponseState.Sending
    await resp.connection.writer.write(responseHeaders)
    case streamType
    of HttpResponseStreamType.Plain, HttpResponseStreamType.SSE:
      resp.writer = newAsyncStreamWriter(resp.connection.writer)
    of HttpResponseStreamType.Chunked:
      resp.writer = newChunkedStreamWriter(resp.connection.writer)
    resp.flags.incl(HttpResponseFlags.Stream)
  except CancelledError as exc:
    resp.state = HttpResponseState.Cancelled
    raise exc
  except AsyncStreamWriteError, AsyncStreamIncompleteError:
    resp.state = HttpResponseState.Failed
    raiseHttpCriticalError("Unable to send response")

proc prepareChunked*(resp: HttpResponseRef): Future[void] =
  ## Prepare for HTTP chunked stream response.
  ##
  ## Such responses will be sent chunk by chunk using ``chunked`` encoding.
  resp.prepare(HttpResponseStreamType.Chunked)

proc preparePlain*(resp: HttpResponseRef): Future[void] =
  ## Prepare for HTTP plain stream response.
  ##
  ## Such responses will be sent without any encoding.
  resp.prepare(HttpResponseStreamType.Plain)

proc prepareSSE*(resp: HttpResponseRef): Future[void] =
  ## Prepare for HTTP server-side event stream response.
  resp.prepare(HttpResponseStreamType.SSE)

proc send*(resp: HttpResponseRef, pbytes: pointer, nbytes: int) {.async.} =
  ## Send single chunk of data pointed by ``pbytes`` and ``nbytes``.
  doAssert(not(isNil(pbytes)), "pbytes must not be nil")
  doAssert(nbytes >= 0, "nbytes should be bigger or equal to zero")
  if HttpResponseFlags.Stream notin resp.flags:
    raiseHttpCriticalError("Response was not prepared")
  if resp.state notin {HttpResponseState.Prepared, HttpResponseState.Sending}:
    raiseHttpCriticalError("Response in incorrect state")
  try:
    resp.state = HttpResponseState.Sending
    await resp.writer.write(pbytes, nbytes)
    resp.state = HttpResponseState.Sending
  except CancelledError as exc:
    resp.state = HttpResponseState.Cancelled
    raise exc
  except AsyncStreamWriteError, AsyncStreamIncompleteError:
    resp.state = HttpResponseState.Failed
    raiseHttpCriticalError("Unable to send response")

proc send*(resp: HttpResponseRef, data: ByteChar) {.async.} =
  ## Send single chunk of data ``data``.
  if HttpResponseFlags.Stream notin resp.flags:
    raiseHttpCriticalError("Response was not prepared")
  if resp.state notin {HttpResponseState.Prepared, HttpResponseState.Sending}:
    raiseHttpCriticalError("Response in incorrect state")
  try:
    resp.state = HttpResponseState.Sending
    await resp.writer.write(data)
    resp.state = HttpResponseState.Sending
  except CancelledError as exc:
    resp.state = HttpResponseState.Cancelled
    raise exc
  except AsyncStreamWriteError, AsyncStreamIncompleteError:
    resp.state = HttpResponseState.Failed
    raiseHttpCriticalError("Unable to send response")

proc sendChunk*(resp: HttpResponseRef, pbytes: pointer,
                nbytes: int): Future[void] =
  resp.send(pbytes, nbytes)

proc sendChunk*(resp: HttpResponseRef, data: ByteChar): Future[void] =
  resp.send(data)

proc sendEvent*(resp: HttpResponseRef, eventName: string,
                data: string): Future[void] =
  ## Send server-side event with name ``eventName`` and payload ``data`` to
  ## remote peer.
  let data =
    block:
      var res = ""
      if len(eventName) > 0:
        res.add("event: ")
        res.add(eventName)
        res.add("\r\n")
      res.add("data: ")
      res.add(data)
      res.add("\r\n\r\n")
      res
  resp.send(data)

proc finish*(resp: HttpResponseRef) {.async.} =
  ## Sending last chunk of data, so it will indicate end of HTTP response.
  if HttpResponseFlags.Stream notin resp.flags:
    raiseHttpCriticalError("Response was not prepared")
  if resp.state notin {HttpResponseState.Prepared, HttpResponseState.Sending}:
    raiseHttpCriticalError("Response in incorrect state")
  try:
    resp.state = HttpResponseState.Sending
    await resp.writer.finish()
    resp.state = HttpResponseState.Finished
  except CancelledError as exc:
    resp.state = HttpResponseState.Cancelled
    raise exc
  except AsyncStreamWriteError, AsyncStreamIncompleteError:
    resp.state = HttpResponseState.Failed
    raiseHttpCriticalError("Unable to send response")

proc respond*(req: HttpRequestRef, code: HttpCode, content: ByteChar,
              headers: HttpTable): Future[HttpResponseRef] {.async.} =
  ## Responds to the request with the specified ``HttpCode``, HTTP ``headers``
  ## and ``content``.
  let response = req.getResponse()
  response.status = code
  for k, v in headers.stringItems():
    response.addHeader(k, v)
  await response.sendBody(content)
  return response

proc respond*(req: HttpRequestRef, code: HttpCode,
              content: ByteChar): Future[HttpResponseRef] =
  ## Responds to the request with specified ``HttpCode`` and ``content``.
  respond(req, code, content, HttpTable.init())

proc respond*(req: HttpRequestRef, code: HttpCode): Future[HttpResponseRef] =
  ## Responds to the request with specified ``HttpCode`` only.
  respond(req, code, "", HttpTable.init())

proc redirect*(req: HttpRequestRef, code: HttpCode,
               location: string, headers: HttpTable): Future[HttpResponseRef] =
  ## Responds to the request with redirection to location ``location`` and
  ## additional headers ``headers``.
  ##
  ## Note, ``location`` argument's value has priority over "Location" header's
  ## value in ``headers`` argument.
  var mheaders = headers
  mheaders.set("location", location)
  respond(req, code, "", mheaders)

proc redirect*(req: HttpRequestRef, code: HttpCode,
               location: Uri, headers: HttpTable): Future[HttpResponseRef] =
  ## Responds to the request with redirection to location ``location`` and
  ## additional headers ``headers``.
  ##
  ## Note, ``location`` argument's value has priority over "Location" header's
  ## value in ``headers`` argument.
  redirect(req, code, $location, headers)

proc redirect*(req: HttpRequestRef, code: HttpCode,
               location: Uri): Future[HttpResponseRef] =
  ## Responds to the request with redirection to location ``location``.
  redirect(req, code, location, HttpTable.init())

proc redirect*(req: HttpRequestRef, code: HttpCode,
               location: string): Future[HttpResponseRef] =
  ## Responds to the request with redirection to location ``location``.
  redirect(req, code, location, HttpTable.init())

proc responded*(req: HttpRequestRef): bool =
  ## Returns ``true`` if request ``req`` has been responded or responding.
  if isSome(req.response):
    if req.response.get().state == HttpResponseState.Empty:
      false
    else:
      true
  else:
    false

proc remoteAddress*(conn: HttpConnectionRef): TransportAddress =
  ## Returns address of the remote host that established connection ``conn``.
  conn.transp.remoteAddress()

proc remoteAddress*(request: HttpRequestRef): TransportAddress =
  ## Returns address of the remote host that made request ``request``.
  request.connection.remoteAddress()

proc requestInfo*(req: HttpRequestRef, contentType = "text/text"): string {.
     raises: [Defect].} =
  ## Returns comprehensive information about request for specific content
  ## type.
  ##
  ## Only two content-types are supported: "text/text" and "text/html".
  proc h(t: string): string =
    case contentType
    of "text/text":
      "\r\n" & t & " ===\r\n"
    of "text/html":
      "<h3>" & t & "</h3>"
    else:
      t
  proc kv(k, v: string): string =
    case contentType
    of "text/text":
      k & ": " & v & "\r\n"
    of "text/html":
      "<div><code><b>" & k & "</b></code><code>" & v & "</code></div>"
    else:
      k & ": " & v

  let header =
    case contentType
    of "text/html":
      "<html><head><title>Request Information</title>" &
      "<style>code {padding-left: 30px;}</style>" &
      "</head><body>"
    else:
      ""

  let footer =
    case contentType
    of "text/html":
      "</body></html>"
    else:
      ""

  var res = h("Request information")
  res.add(kv("request.scheme", $req.scheme))
  res.add(kv("request.method", $req.meth))
  res.add(kv("request.version", $req.version))
  res.add(kv("request.uri", $req.uri))
  res.add(kv("request.flags", $req.requestFlags))
  res.add(kv("request.TransferEncoding", $req.transferEncoding))
  res.add(kv("request.ContentEncoding", $req.contentEncoding))

  let body =
    if req.hasBody():
      if req.contentLength == 0:
        "present, size not available"
      else:
        "present, size = " & $req.contentLength
    else:
      "not available"
  res.add(kv("request.body", body))

  if not(req.query.isEmpty()):
    res.add(h("Query arguments"))
    for k, v in req.query.stringItems():
      res.add(kv(k, v))

  if not(req.headers.isEmpty()):
    res.add(h("HTTP headers"))
    for k, v in req.headers.stringItems(true):
      res.add(kv(k, v))

  if req.meth in PostMethods:
    if req.postTable.isSome():
      let postTable = req.postTable.get()
      if not(postTable.isEmpty()):
        res.add(h("POST arguments"))
        for k, v in postTable.stringItems():
          res.add(kv(k, v))

  res.add(h("Connection information"))
  let localAddress =
    try:
      $req.connection.transp.localAddress()
    except TransportError:
      "incorrect address"
  let remoteAddress =
    try:
      $req.connection.transp.remoteAddress()
    except TransportError:
      "incorrect address"

  res.add(kv("local.address", localAddress))
  res.add(kv("remote.address", remoteAddress))

  res.add(h("Server configuration"))
  let maxConn =
    if req.connection.server.maxConnections < 0:
      "unlimited"
    else:
      $req.connection.server.maxConnections
  res.add(kv("server.maxConnections", $maxConn))
  res.add(kv("server.maxHeadersSize", $req.connection.server.maxHeadersSize))
  res.add(kv("server.maxRequestBodySize",
             $req.connection.server.maxRequestBodySize))
  res.add(kv("server.backlog", $req.connection.server.backlogSize))
  res.add(kv("server.headersTimeout", $req.connection.server.headersTimeout))
  res.add(kv("server.baseUri", $req.connection.server.baseUri))
  res.add(kv("server.flags", $req.connection.server.flags))
  res.add(kv("server.socket.flags", $req.connection.server.socketFlags))
  header & res & footer
