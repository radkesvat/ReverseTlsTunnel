#
#          Chronos Asynchronous TLS Stream
#             (c) Copyright 2019-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

## This module implements Transport Layer Security (TLS) stream. This module
## uses sources of BearSSL <https://www.bearssl.org> by Thomas Pornin.
import
  bearssl/[brssl, ec, errors, pem, rsa, ssl, x509],
  bearssl/certs/cacert
import ../asyncloop, ../timer, ../asyncsync
import asyncstream, ../transports/stream, ../transports/common
export asyncloop, asyncsync, timer, asyncstream

type
  TLSStreamKind {.pure.} = enum
    Client, Server

  TLSVersion* {.pure.} = enum
    TLS10 = 0x0301, TLS11 = 0x0302, TLS12 = 0x0303

  TLSFlags* {.pure.} = enum
    NoVerifyHost,         # Client: Skip remote certificate check
    NoVerifyServerName,   # Client: Skip Server Name Indication (SNI) check
    EnforceServerPref,    # Server: Enforce server preferences
    NoRenegotiation,      # Server: Reject renegotiations requests
    TolerateNoClientAuth, # Server: Disable strict client authentication
    FailOnAlpnMismatch    # Server: Fail on application protocol mismatch

  TLSKeyType {.pure.} = enum
    RSA, EC

  TLSResult {.pure.} = enum
    Success, Error, Stopped, WriteEof, ReadEof

  TLSPrivateKey* = ref object
    case kind: TLSKeyType
    of RSA:
      rsakey: RsaPrivateKey
    of EC:
      eckey: EcPrivateKey
    storage: seq[byte]

  TLSCertificate* = ref object
    certs: seq[X509Certificate]
    storage: seq[byte]

  TLSSessionCache* = ref object
    storage: seq[byte]
    context: SslSessionCacheLru

  PEMElement* = object
    name*: string
    data*: seq[byte]

  PEMContext = ref object
    data: seq[byte]
  
  TrustAnchorStore* = ref object
    anchors: seq[X509TrustAnchor]

  TLSStreamWriter* = ref object of AsyncStreamWriter
    case kind: TLSStreamKind
    of TLSStreamKind.Client:
      ccontext: ptr SslClientContext
    of TLSStreamKind.Server:
      scontext: ptr SslServerContext
    stream*: TLSAsyncStream
    handshaked*: bool
    handshakeFut*: Future[void]

  TLSStreamReader* = ref object of AsyncStreamReader
    case kind: TLSStreamKind
    of TLSStreamKind.Client:
      ccontext: ptr SslClientContext
    of TLSStreamKind.Server:
      scontext: ptr SslServerContext
    stream*: TLSAsyncStream
    handshaked*: bool
    handshakeFut*: Future[void]

  TLSAsyncStream* = ref object of RootRef
    xwc*: X509NoanchorContext
    ccontext*: SslClientContext
    scontext*: SslServerContext
    sbuffer*: seq[byte]
    x509*: X509MinimalContext
    reader*: TLSStreamReader
    writer*: TLSStreamWriter
    mainLoop*: Future[void]
    trustAnchors: TrustAnchorStore

  SomeTLSStreamType* = TLSStreamReader|TLSStreamWriter|TLSAsyncStream

  TLSStreamError* = object of AsyncStreamError
  TLSStreamHandshakeError* = object of TLSStreamError
  TLSStreamInitError* = object of TLSStreamError
  TLSStreamReadError* = object of TLSStreamError
    par*: ref AsyncStreamError
  TLSStreamWriteError* = object of TLSStreamError
    par*: ref AsyncStreamError
  TLSStreamProtocolError* = object of TLSStreamError
    errCode*: int

proc newTLSStreamWriteError(p: ref AsyncStreamError): ref TLSStreamWriteError {.
     noinline.} =
  var w = newException(TLSStreamWriteError, "Write stream failed")
  w.msg = w.msg & ", originated from [" & $p.name & "] " & p.msg
  w.par = p
  w

template newTLSStreamProtocolImpl[T](message: T): ref TLSStreamProtocolError =
  var msg = ""
  var code = 0
  when T is string:
    msg.add(message)
  elif T is cint:
    msg.add(sslErrorMsg(message) & " (code: " & $int(message) & ")")
    code = int(message)
  elif T is int:
    msg.add(sslErrorMsg(message) & " (code: " & $message & ")")
    code = message
  else:
    msg.add("Internal Error")
  var err = newException(TLSStreamProtocolError, msg)
  err.errCode = code
  err

template newTLSUnexpectedProtocolError(): ref TLSStreamProtocolError =
  newException(TLSStreamProtocolError, "Unexpected internal error")

proc newTLSStreamProtocolError[T](message: T): ref TLSStreamProtocolError =
  newTLSStreamProtocolImpl(message)

proc raiseTLSStreamProtocolError[T](message: T) {.noreturn, noinline.} =
  raise newTLSStreamProtocolImpl(message)

proc new*(T: typedesc[TrustAnchorStore], anchors: openArray[X509TrustAnchor]): TrustAnchorStore =
  var res: seq[X509TrustAnchor]
  for anchor in anchors:
    res.add(anchor)
    doAssert(unsafeAddr(anchor) != unsafeAddr(res[^1]), "Anchors should be copied")
  return TrustAnchorStore(anchors: res)

proc tlsWriteRec(engine: ptr SslEngineContext,
                 writer: TLSStreamWriter): Future[TLSResult] {.async.} =
  try:
    var length = 0'u
    var buf = sslEngineSendrecBuf(engine[], length)
    doAssert(length != 0 and not isNil(buf))
    await writer.wsource.write(buf, int(length))
    sslEngineSendrecAck(engine[], length)
    return TLSResult.Success
  except AsyncStreamError as exc:
    writer.state = AsyncStreamState.Error
    writer.error = exc
    return TLSResult.Error
  except CancelledError:
    if writer.state == AsyncStreamState.Running:
      writer.state = AsyncStreamState.Stopped
    return TLSResult.Stopped

  return TLSResult.Error

proc tlsWriteApp(engine: ptr SslEngineContext,
                 writer: TLSStreamWriter): Future[TLSResult] {.async.} =
  try:
    var item = await writer.queue.get()
    if item.size > 0:
      var length = 0'u
      var buf = sslEngineSendappBuf(engine[], length)
      if isNil(buf) or (length == 0):
        # This situation could happen when connection is closing, no
        # application data can be sent, but some can still be received
        # (and discarded).
        writer.state = AsyncStreamState.Finished
        return TLSResult.WriteEof

      let toWrite = min(int(length), item.size)
      copyOut(buf, item, toWrite)
      if int(length) >= item.size:
        # BearSSL is ready to accept whole item size.
        sslEngineSendappAck(engine[], uint(item.size))
        sslEngineFlush(engine[], 0)
        item.future.complete()
        return TLSResult.Success
      else:
        # BearSSL is not ready to accept whole item, so we will send
        # only part of item and adjust offset.
        item.offset = item.offset + int(length)
        item.size = item.size - int(length)
        writer.queue.addFirstNoWait(item)
        sslEngineSendappAck(engine[], length)
        return TLSResult.Success
    else:
      sslEngineClose(engine[])
      item.future.complete()
      return TLSResult.Success
  except CancelledError:
    if writer.state == AsyncStreamState.Running:
      writer.state = AsyncStreamState.Stopped
    return TLSResult.Stopped

  return TLSResult.Error

proc tlsReadRec(engine: ptr SslEngineContext,
                reader: TLSStreamReader): Future[TLSResult] {.async.} =
  try:
    var length = 0'u
    var buf = sslEngineRecvrecBuf(engine[], length)
    let res = await reader.rsource.readOnce(buf, int(length))
    sslEngineRecvrecAck(engine[], uint(res))
    if res == 0:
      sslEngineClose(engine[])
      return TLSResult.ReadEof
    else:
      return TLSResult.Success
  except AsyncStreamError as exc:
    reader.state = AsyncStreamState.Error
    reader.error = exc
    return TLSResult.Error
  except CancelledError:
    if reader.state == AsyncStreamState.Running:
      reader.state = AsyncStreamState.Stopped
    return TLSResult.Stopped

  return TLSResult.Error

proc tlsReadApp(engine: ptr SslEngineContext,
                reader: TLSStreamReader): Future[TLSResult] {.async.} =
  try:
    var length = 0'u
    var buf = sslEngineRecvappBuf(engine[], length)
    await upload(addr reader.buffer, buf, int(length))
    sslEngineRecvappAck(engine[], length)
    return TLSResult.Success
  except CancelledError:
    if reader.state == AsyncStreamState.Running:
      reader.state = AsyncStreamState.Stopped
    return TLSResult.Stopped

  return TLSResult.Error

template readAndReset(fut: untyped) =
  if fut.finished():
    let res = fut.read()
    case res
    of TLSResult.Success, TLSResult.WriteEof, TLSResult.Stopped:
      fut = nil
      continue
    of TLSResult.Error:
      fut = nil
      if loopState == AsyncStreamState.Running:
        loopState = AsyncStreamState.Error
      break
    of TLSResult.ReadEof:
      fut = nil
      if loopState == AsyncStreamState.Running:
        loopState = AsyncStreamState.Finished
      break

proc cancelAndWait*(a, b, c, d: Future[TLSResult]): Future[void] =
  var waiting: seq[Future[TLSResult]]
  if not(isNil(a)) and not(a.finished()):
    a.cancel()
    waiting.add(a)
  if not(isNil(b)) and not(b.finished()):
    b.cancel()
    waiting.add(b)
  if not(isNil(c)) and not(c.finished()):
    c.cancel()
    waiting.add(c)
  if not(isNil(d)) and not(d.finished()):
    d.cancel()
    waiting.add(d)
  allFutures(waiting)

proc dumpState*(state: cuint): string =
  var res = ""
  if (state and SSL_CLOSED) == SSL_CLOSED:
    if len(res) > 0: res.add(", ")
    res.add("SSL_CLOSED")
  if (state and SSL_SENDREC) == SSL_SENDREC:
    if len(res) > 0: res.add(", ")
    res.add("SSL_SENDREC")
  if (state and SSL_SENDAPP) == SSL_SENDAPP:
    if len(res) > 0: res.add(", ")
    res.add("SSL_SENDAPP")
  if (state and SSL_RECVREC) == SSL_RECVREC:
    if len(res) > 0: res.add(", ")
    res.add("SSL_RECVREC")
  if (state and SSL_RECVAPP) == SSL_RECVAPP:
    if len(res) > 0: res.add(", ")
    res.add("SSL_RECVAPP")
  "{" & res & "}"

proc tlsLoop*(stream: TLSAsyncStream) {.async.} =
  var
    sendRecFut, sendAppFut: Future[TLSResult]
    recvRecFut, recvAppFut: Future[TLSResult]

  let engine =
    case stream.reader.kind
    of TLSStreamKind.Server:
      addr stream.scontext.eng
    of TLSStreamKind.Client:
      addr stream.ccontext.eng

  var loopState = AsyncStreamState.Running

  while true:
    var waiting: seq[Future[TLSResult]]
    var state = sslEngineCurrentState(engine[])

    if (state and SSL_CLOSED) == SSL_CLOSED:
      if loopState == AsyncStreamState.Running:
        loopState = AsyncStreamState.Finished
      break

    if isNil(sendRecFut):
      if (state and SSL_SENDREC) == SSL_SENDREC:
        sendRecFut = tlsWriteRec(engine, stream.writer)
    else:
      sendRecFut.readAndReset()

    if isNil(sendAppFut):
      if (state and SSL_SENDAPP) == SSL_SENDAPP:
        if stream.writer.state == AsyncStreamState.Running:
          # Application data can be sent over stream.
          if not(stream.writer.handshaked):
            stream.reader.handshaked = true
            stream.writer.handshaked = true
            if not(isNil(stream.writer.handshakeFut)):
              stream.writer.handshakeFut.complete()
          sendAppFut = tlsWriteApp(engine, stream.writer)
    else:
      sendAppFut.readAndReset()

    if isNil(recvRecFut):
      if (state and SSL_RECVREC) == SSL_RECVREC:
        recvRecFut = tlsReadRec(engine, stream.reader)
    else:
      recvRecFut.readAndReset()

    if isNil(recvAppFut):
      if (state and SSL_RECVAPP) == SSL_RECVAPP:
        recvAppFut = tlsReadApp(engine, stream.reader)
    else:
      recvAppFut.readAndReset()

    if not(isNil(sendRecFut)):
      waiting.add(sendRecFut)
    if not(isNil(sendAppFut)):
      waiting.add(sendAppFut)
    if not(isNil(recvRecFut)):
      waiting.add(recvRecFut)
    if not(isNil(recvAppFut)):
      waiting.add(recvAppFut)

    if len(waiting) > 0:
      try:
        discard await one(waiting)
      except CancelledError:
        if loopState == AsyncStreamState.Running:
          loopState = AsyncStreamState.Stopped

    if loopState != AsyncStreamState.Running:
      break

  # Cancelling and waiting all the pending operations
  await cancelAndWait(sendRecFut, sendAppFut, recvRecFut, recvAppFut)
  # Calculating error
  let error =
    case loopState
    of AsyncStreamState.Stopped:
      newAsyncStreamUseClosedError()
    of AsyncStreamState.Error:
      if not(isNil(stream.writer.error)):
        stream.writer.error
      elif not(isNil(stream.reader.error)):
        newTLSStreamWriteError(stream.reader.error)
      else:
        newTLSUnexpectedProtocolError()
    of AsyncStreamState.Finished:
      let err = engine[].sslEngineLastError()
      if err != 0:
        newTLSStreamProtocolError(err)
      else:
        nil
    of AsyncStreamState.Running:
      nil
    else:
      nil

  # Syncing state for reader and writer
  stream.writer.state = loopState
  stream.reader.state = loopState
  if loopState == AsyncStreamState.Error:
    if isNil(stream.reader.error):
      stream.reader.state = AsyncStreamState.Finished

  if not(isNil(error)):
    # Completing all pending writes
    while(not(stream.writer.queue.empty())):
      let item = stream.writer.queue.popFirstNoWait()
      if not(item.future.finished()):
        item.future.fail(error)
    # Completing handshake
    if not(stream.writer.handshaked):
      if not(isNil(stream.writer.handshakeFut)):
        if not(stream.writer.handshakeFut.finished()):
          stream.writer.handshakeFut.fail(error)
  else:
    if not(stream.writer.handshaked):
      if not(isNil(stream.writer.handshakeFut)):
        if not(stream.writer.handshakeFut.finished()):
          stream.writer.handshakeFut.fail(
            newTLSStreamProtocolError(
              "Connection to the remote peer has been lost")
          )

  # Completing readers
  stream.reader.buffer.forget()

proc tlsWriteLoop(stream: AsyncStreamWriter) {.async.} =
  var wstream = TLSStreamWriter(stream)
  wstream.state = AsyncStreamState.Running
  await stepsAsync(1)
  if isNil(wstream.stream.mainLoop):
    wstream.stream.mainLoop = tlsLoop(wstream.stream)
  await wstream.stream.mainLoop

proc tlsReadLoop(stream: AsyncStreamReader) {.async.} =
  var rstream = TLSStreamReader(stream)
  rstream.state = AsyncStreamState.Running
  await stepsAsync(1)
  if isNil(rstream.stream.mainLoop):
    rstream.stream.mainLoop = tlsLoop(rstream.stream)
  await rstream.stream.mainLoop

proc getSignerAlgo(xc: X509Certificate): int =
  ## Get certificate's signing algorithm.
  var dc: X509DecoderContext
  x509DecoderInit(dc, nil, nil)
  x509DecoderPush(dc, xc.data, xc.dataLen)
  let err = x509DecoderLastError(dc)
  if err != 0:
    -1
  else:
    int(x509DecoderGetSignerKeyType(dc))

proc newTLSClientAsyncStream*(rsource: AsyncStreamReader,
                              wsource: AsyncStreamWriter,
                              serverName: string,
                              bufferSize = SSL_BUFSIZE_BIDI,
                              minVersion = TLSVersion.TLS12,
                              maxVersion = TLSVersion.TLS12,
                              flags: set[TLSFlags] = {},
                              trustAnchors: TrustAnchorStore | openArray[X509TrustAnchor] = MozillaTrustAnchors
                              ): TLSAsyncStream =
  ## Create new TLS asynchronous stream for outbound (client) connections
  ## using reading stream ``rsource`` and writing stream ``wsource``.
  ##
  ## You can specify remote server name using ``serverName``, if while
  ## handshake server reports different name you will get an error. If
  ## ``serverName`` is empty string, remote server name checking will be
  ## disabled.
  ##
  ## ``bufferSize`` - is SSL/TLS buffer which is used for encoding/decoding
  ## incoming data.
  ##
  ## ``minVersion`` and ``maxVersion`` are TLS versions which will be used
  ## for handshake with remote server. If server's version will be lower then
  ## ``minVersion`` of bigger then ``maxVersion`` you will get an error.
  ##
  ## ``flags`` - custom TLS connection flags.
  ## 
  ## ``trustAnchors`` - use this if you want to use certificate trust
  ## anchors other than the default Mozilla trust anchors. If you pass
  ## a ``TrustAnchorStore`` you should reuse the same instance for
  ## every call to avoid making a copy of the trust anchors per call.
  when trustAnchors is TrustAnchorStore:
    doAssert(len(trustAnchors.anchors) > 0, "Empty trust anchor list is invalid")
  else:
    doAssert(len(trustAnchors) > 0, "Empty trust anchor list is invalid")
  var res = TLSAsyncStream()
  var reader = TLSStreamReader(
    kind: TLSStreamKind.Client,
    stream: res,
    ccontext: addr res.ccontext
  )
  var writer = TLSStreamWriter(
    kind: TLSStreamKind.Client,
    stream: res,
    ccontext: addr res.ccontext
  )
  res.reader = reader
  res.writer = writer

  if TLSFlags.NoVerifyHost in flags:
    sslClientInitFull(res.ccontext, addr res.x509, nil, 0)
    x509NoanchorInit(res.xwc, addr res.x509.vtable)
    sslEngineSetX509(res.ccontext.eng, addr res.xwc.vtable)
  else:
    when trustAnchors is TrustAnchorStore:
      res.trustAnchors = trustAnchors
      sslClientInitFull(res.ccontext, addr res.x509,
                        unsafeAddr trustAnchors.anchors[0],
                        uint(len(trustAnchors.anchors)))
    else:
      sslClientInitFull(res.ccontext, addr res.x509,
                        unsafeAddr trustAnchors[0],
                        uint(len(trustAnchors)))

  let size = max(SSL_BUFSIZE_BIDI, bufferSize)
  res.sbuffer = newSeq[byte](size)
  sslEngineSetBuffer(res.ccontext.eng, addr res.sbuffer[0],
                     uint(len(res.sbuffer)), 1)
  sslEngineSetVersions(res.ccontext.eng, uint16(minVersion),
                       uint16(maxVersion))

  if TLSFlags.NoVerifyServerName in flags:
    let err = sslClientReset(res.ccontext, "", 0)
    if err == 0:
      raise newException(TLSStreamInitError, "Could not initialize TLS layer")
  else:
    if len(serverName) == 0:
      raise newException(TLSStreamInitError,
                         "serverName must not be empty string")

    let err = sslClientReset(res.ccontext, serverName, 0)
    if err == 0:
      raise newException(TLSStreamInitError, "Could not initialize TLS layer")

  init(AsyncStreamWriter(res.writer), wsource, tlsWriteLoop,
       bufferSize)
  init(AsyncStreamReader(res.reader), rsource, tlsReadLoop,
       bufferSize)
  res

proc newTLSServerAsyncStream*(rsource: AsyncStreamReader,
                              wsource: AsyncStreamWriter,
                              privateKey: TLSPrivateKey,
                              certificate: TLSCertificate,
                              bufferSize = SSL_BUFSIZE_BIDI,
                              minVersion = TLSVersion.TLS11,
                              maxVersion = TLSVersion.TLS12,
                              cache: TLSSessionCache = nil,
                              flags: set[TLSFlags] = {}): TLSAsyncStream =
  ## Create new TLS asynchronous stream for inbound (server) connections
  ## using reading stream ``rsource`` and writing stream ``wsource``.
  ##
  ## You need to specify local private key ``privateKey`` and certificate
  ## ``certificate``.
  ##
  ## ``bufferSize`` - is SSL/TLS buffer which is used for encoding/decoding
  ## incoming data.
  ##
  ## ``minVersion`` and ``maxVersion`` are TLS versions which will be used
  ## for handshake with remote server. If server's version will be lower then
  ## ``minVersion`` of bigger then ``maxVersion`` you will get an error.
  ##
  ## ``flags`` - custom TLS connection flags.
  if isNil(privateKey) or privateKey.kind notin {TLSKeyType.RSA, TLSKeyType.EC}:
    raiseTLSStreamProtocolError("Incorrect private key")
  if isNil(certificate) or len(certificate.certs) == 0:
    raiseTLSStreamProtocolError("Incorrect certificate")

  var res = TLSAsyncStream()
  var reader = TLSStreamReader(
    kind: TLSStreamKind.Server,
    stream: res,
    scontext: addr res.scontext
  )
  var writer = TLSStreamWriter(
    kind: TLSStreamKind.Server,
    stream: res,
    scontext: addr res.scontext
  )
  res.reader = reader
  res.writer = writer

  if privateKey.kind == TLSKeyType.EC:
    let algo = getSignerAlgo(certificate.certs[0])
    if algo == -1:
      raiseTLSStreamProtocolError("Could not decode certificate")
    sslServerInitFullEc(res.scontext, addr certificate.certs[0],
                        uint(len(certificate.certs)), cuint(algo),
                        addr privateKey.eckey)
  elif privateKey.kind == TLSKeyType.RSA:
    sslServerInitFullRsa(res.scontext, addr certificate.certs[0],
                         uint(len(certificate.certs)), addr privateKey.rsakey)

  let size = max(SSL_BUFSIZE_BIDI, bufferSize)
  res.sbuffer = newSeq[byte](size)
  sslEngineSetBuffer(res.scontext.eng, addr res.sbuffer[0],
                     uint(len(res.sbuffer)), 1)
  sslEngineSetVersions(res.scontext.eng, uint16(minVersion),
                       uint16(maxVersion))

  if not isNil(cache):
    sslServerSetCache(res.scontext, addr cache.context.vtable)

  if TLSFlags.EnforceServerPref in flags:
    sslEngineAddFlags(res.scontext.eng, OPT_ENFORCE_SERVER_PREFERENCES)
  if TLSFlags.NoRenegotiation in flags:
    sslEngineAddFlags(res.scontext.eng, OPT_NO_RENEGOTIATION)
  if TLSFlags.TolerateNoClientAuth in flags:
    sslEngineAddFlags(res.scontext.eng, OPT_TOLERATE_NO_CLIENT_AUTH)
  if TLSFlags.FailOnAlpnMismatch in flags:
    sslEngineAddFlags(res.scontext.eng, OPT_FAIL_ON_ALPN_MISMATCH)

  let err = sslServerReset(res.scontext)
  if err == 0:
    raise newException(TLSStreamInitError, "Could not initialize TLS layer")

  init(AsyncStreamWriter(res.writer), wsource, tlsWriteLoop,
       bufferSize)
  init(AsyncStreamReader(res.reader), rsource, tlsReadLoop,
       bufferSize)
  res

proc copyKey(src: RsaPrivateKey): TLSPrivateKey =
  ## Creates copy of RsaPrivateKey ``src``.
  var offset = 0'u
  let keySize = src.plen + src.qlen + src.dplen + src.dqlen + src.iqlen
  var res = TLSPrivateKey(kind: TLSKeyType.RSA, storage: newSeq[byte](keySize))
  copyMem(addr res.storage[offset], src.p, src.plen)
  res.rsakey.p = addr res.storage[offset]
  res.rsakey.plen = src.plen
  offset = offset + src.plen
  copyMem(addr res.storage[offset], src.q, src.qlen)
  res.rsakey.q = addr res.storage[offset]
  res.rsakey.qlen = src.qlen
  offset = offset + src.qlen
  copyMem(addr res.storage[offset], src.dp, src.dplen)
  res.rsakey.dp = addr res.storage[offset]
  res.rsakey.dplen = src.dplen
  offset = offset + src.dplen
  copyMem(addr res.storage[offset], src.dq, src.dqlen)
  res.rsakey.dq = addr res.storage[offset]
  res.rsakey.dqlen = src.dqlen
  offset = offset + src.dqlen
  copyMem(addr res.storage[offset], src.iq, src.iqlen)
  res.rsakey.iq = addr res.storage[offset]
  res.rsakey.iqlen = src.iqlen
  res.rsakey.nBitlen = src.nBitlen
  res

proc copyKey(src: EcPrivateKey): TLSPrivateKey =
  ## Creates copy of EcPrivateKey ``src``.
  var offset = 0
  let keySize = src.xlen
  var res = TLSPrivateKey(kind: TLSKeyType.EC, storage: newSeq[byte](keySize))
  copyMem(addr res.storage[offset], src.x, src.xlen)
  res.eckey.x = addr res.storage[offset]
  res.eckey.xlen = src.xlen
  res.eckey.curve = src.curve
  res

proc init*(tt: typedesc[TLSPrivateKey], data: openArray[byte]): TLSPrivateKey =
  ## Initialize TLS private key from array of bytes ``data``.
  ##
  ## This procedure initializes private key using raw, DER-encoded format,
  ## or wrapped in an unencrypted PKCS#8 archive (again DER-encoded).
  var ctx: SkeyDecoderContext
  if len(data) == 0:
    raiseTLSStreamProtocolError("Incorrect private key")
  skeyDecoderInit(ctx)
  skeyDecoderPush(ctx, cast[pointer](unsafeAddr data[0]), uint(len(data)))
  let err = skeyDecoderLastError(ctx)
  if err != 0:
    raiseTLSStreamProtocolError(err)
  let keyType = skeyDecoderKeyType(ctx)
  let res =
    if keyType == KEYTYPE_RSA:
      copyKey(ctx.key.rsa)
    elif keyType == KEYTYPE_EC:
      copyKey(ctx.key.ec)
    else:
      raiseTLSStreamProtocolError("Unknown key type (" & $keyType & ")")
  res

proc pemDecode*(data: openArray[char]): seq[PEMElement] =
  ## Decode PEM encoded string and get array of binary blobs.
  if len(data) == 0:
    raiseTLSStreamProtocolError("Empty PEM message")
  var pctx = new PEMContext
  var res = newSeq[PEMElement]()

  proc itemAppend(ctx: pointer, pbytes: pointer, nbytes: uint) {.cdecl.} =
    var p = cast[PEMContext](ctx)
    var o = uint(len(p.data))
    p.data.setLen(o + nbytes)
    copyMem(addr p.data[o], pbytes, nbytes)

  var offset = 0
  var inobj = false
  var elem: PEMElement

  var ctx: PemDecoderContext
  ctx.init()
  ctx.setdest(itemAppend, cast[pointer](pctx))

  while offset < data.len:
    let tlen = ctx.push(data.toOpenArray(offset, data.high))
    offset = offset + tlen

    let event = ctx.lastEvent()
    if event == PEM_BEGIN_OBJ:
      inobj = true
      elem.name = ctx.banner()
      pctx.data.setLen(0)
    elif event == PEM_END_OBJ:
      if inobj:
        elem.data = pctx.data
        res.add(elem)
        inobj = false
      else:
        break
    else:
      raiseTLSStreamProtocolError("Invalid PEM encoding")
  res

proc init*(tt: typedesc[TLSPrivateKey], data: openArray[char]): TLSPrivateKey =
  ## Initialize TLS private key from string ``data``.
  ##
  ## This procedure initializes private key using unencrypted PKCS#8 PEM
  ## encoded string.
  ##
  ## Note that PKCS#1 PEM encoded objects are not supported.
  var res: TLSPrivateKey
  var items = pemDecode(data)
  for item in items:
    if item.name == "PRIVATE KEY":
      res = TLSPrivateKey.init(item.data)
      break
  if isNil(res):
    raiseTLSStreamProtocolError("Could not find private key")
  res

proc init*(tt: typedesc[TLSCertificate],
           data: openArray[char]): TLSCertificate =
  ## Initialize TLS certificates from string ``data``.
  ##
  ## This procedure initializes array of certificates from PEM encoded string.
  var items = pemDecode(data)
  # storage needs to be big enough for input data
  var res = TLSCertificate(storage: newSeqOfCap[byte](data.len))
  for item in items:
    if item.name == "CERTIFICATE" and len(item.data) > 0:
      let offset = len(res.storage)
      res.storage.add(item.data)
      let cert = X509Certificate(
        data: addr res.storage[offset],
        dataLen: uint(len(item.data))
      )
      let ares = getSignerAlgo(cert)
      if ares == -1:
        raiseTLSStreamProtocolError("Could not decode certificate")
      elif ares != KEYTYPE_RSA and ares != KEYTYPE_EC:
        raiseTLSStreamProtocolError(
          "Unsupported signing key type in certificate")
      res.certs.add(cert)
  if len(res.storage) == 0:
    raiseTLSStreamProtocolError("Could not find any certificates")
  res

proc init*(tt: typedesc[TLSSessionCache], size: int = 4096): TLSSessionCache =
  ## Create new TLS session cache with size ``size``.
  ##
  ## One cached item is near 100 bytes size.
  var rsize = min(size, 4096)
  var res = TLSSessionCache(storage: newSeq[byte](rsize))
  sslSessionCacheLruInit(addr res.context, addr res.storage[0], rsize)
  res

proc handshake*(rws: SomeTLSStreamType): Future[void] =
  ## Wait until initial TLS handshake will be successfully performed.
  var retFuture = newFuture[void]("tlsstream.handshake")
  when rws is TLSStreamReader:
    if rws.handshaked:
      retFuture.complete()
    else:
      rws.handshakeFut = retFuture
      rws.stream.writer.handshakeFut = retFuture
  elif rws is TLSStreamWriter:
    if rws.handshaked:
      retFuture.complete()
    else:
      rws.handshakeFut = retFuture
      rws.stream.reader.handshakeFut = retFuture
  elif rws is TLSAsyncStream:
    if rws.reader.handshaked:
      retFuture.complete()
    else:
      rws.reader.handshakeFut = retFuture
      rws.writer.handshakeFut = retFuture
  retFuture
