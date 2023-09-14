#
#            Chronos HTTP/S common types
#             (c) Copyright 2021-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[strutils, uri]
import stew/results, httputils
import ../../asyncloop, ../../asyncsync
import ../../streams/[asyncstream, boundstream]
export asyncloop, asyncsync, results, httputils, strutils

const
  HeadersMark* = @[0x0d'u8, 0x0a'u8, 0x0d'u8, 0x0a'u8]
  PostMethods* = {MethodPost, MethodPatch, MethodPut, MethodDelete}

  MaximumBodySizeError* = "Maximum size of request's body reached"

  UserAgentHeader* = "user-agent"
  DateHeader* = "date"
  HostHeader* = "host"
  ConnectionHeader* = "connection"
  AcceptHeaderName* = "accept"
  ContentLengthHeader* = "content-length"
  TransferEncodingHeader* = "transfer-encoding"
  ContentEncodingHeader* = "content-encoding"
  ContentTypeHeader* = "content-type"
  ExpectHeader* = "expect"
  ServerHeader* = "server"
  LocationHeader* = "location"
  AuthorizationHeader* = "authorization"

  UrlEncodedContentType* = MediaType.init("application/x-www-form-urlencoded")
  MultipartContentType* = MediaType.init("multipart/form-data")

type
  HttpResult*[T] = Result[T, string]
  HttpResultCode*[T] = Result[T, HttpCode]

  HttpDefect* = object of Defect
  HttpError* = object of CatchableError
  HttpCriticalError* = object of HttpError
    code*: HttpCode
  HttpRecoverableError* = object of HttpError
    code*: HttpCode
  HttpDisconnectError* = object of HttpError
  HttpConnectionError* = object of HttpError
  HttpInterruptError* = object of HttpError
  HttpReadError* = object of HttpError
  HttpWriteError* = object of HttpError
  HttpProtocolError* = object of HttpError
  HttpRedirectError* = object of HttpError
  HttpAddressError* = object of HttpError
  HttpUseClosedError* = object of HttpError
  HttpReadLimitError* = object of HttpReadError

  KeyValueTuple* = tuple
    key: string
    value: string

  TransferEncodingFlags* {.pure.} = enum
    Identity, Chunked, Compress, Deflate, Gzip

  ContentEncodingFlags* {.pure.} = enum
    Identity, Br, Compress, Deflate, Gzip

  QueryParamsFlag* {.pure.} = enum
    CommaSeparatedArray ## Enable usage of comma symbol as separator of array
                        ## items

  HttpState* {.pure.} = enum
    Alive, Closing, Closed

proc raiseHttpCriticalError*(msg: string,
                             code = Http400) {.noinline, noreturn.} =
  raise (ref HttpCriticalError)(code: code, msg: msg)

proc raiseHttpDisconnectError*() {.noinline, noreturn.} =
  raise (ref HttpDisconnectError)(msg: "Remote peer disconnected")

proc raiseHttpDefect*(msg: string) {.noinline, noreturn.} =
  raise (ref HttpDefect)(msg: msg)

proc raiseHttpConnectionError*(msg: string) {.noinline, noreturn.} =
  raise (ref HttpConnectionError)(msg: msg)

proc raiseHttpInterruptError*() {.noinline, noreturn.} =
  raise (ref HttpInterruptError)(msg: "Connection was interrupted")

proc raiseHttpReadError*(msg: string) {.noinline, noreturn.} =
  raise (ref HttpReadError)(msg: msg)

proc raiseHttpProtocolError*(msg: string) {.noinline, noreturn.} =
  raise (ref HttpProtocolError)(msg: msg)

proc raiseHttpWriteError*(msg: string) {.noinline, noreturn.} =
  raise (ref HttpWriteError)(msg: msg)

proc raiseHttpRedirectError*(msg: string) {.noinline, noreturn.} =
  raise (ref HttpRedirectError)(msg: msg)

proc raiseHttpAddressError*(msg: string) {.noinline, noreturn.} =
  raise (ref HttpAddressError)(msg: msg)

template newHttpInterruptError*(): ref HttpInterruptError =
  newException(HttpInterruptError, "Connection was interrupted")

template newHttpReadError*(message: string): ref HttpReadError =
  newException(HttpReadError, message)

template newHttpWriteError*(message: string): ref HttpWriteError =
  newException(HttpWriteError, message)

template newHttpUseClosedError*(): ref HttpUseClosedError =
  newException(HttpUseClosedError, "Connection was already closed")

iterator queryParams*(query: string,
                      flags: set[QueryParamsFlag] = {}): KeyValueTuple {.
         raises: [Defect].} =
  ## Iterate over url-encoded query string.
  for pair in query.split('&'):
    let items = pair.split('=', maxsplit = 1)
    let k = items[0]
    if len(k) > 0:
      let v = if len(items) > 1: items[1] else: ""
      if CommaSeparatedArray in flags:
        for av in decodeUrl(v).split(','):
          yield (decodeUrl(k), av)
      else:
        yield (decodeUrl(k), decodeUrl(v))

func getTransferEncoding*(ch: openArray[string]): HttpResult[
                                                  set[TransferEncodingFlags]] {.
     raises: [Defect].} =
  ## Parse value of multiple HTTP headers ``Transfer-Encoding`` and return
  ## it as set of ``TransferEncodingFlags``.
  var res: set[TransferEncodingFlags] = {}
  if len(ch) == 0:
    res.incl(TransferEncodingFlags.Identity)
    ok(res)
  else:
    for header in ch:
      for item in header.split(","):
        case strip(item.toLowerAscii())
        of "identity":
          res.incl(TransferEncodingFlags.Identity)
        of "chunked":
          res.incl(TransferEncodingFlags.Chunked)
        of "compress":
          res.incl(TransferEncodingFlags.Compress)
        of "deflate":
          res.incl(TransferEncodingFlags.Deflate)
        of "gzip":
          res.incl(TransferEncodingFlags.Gzip)
        of "x-gzip":
          res.incl(TransferEncodingFlags.Gzip)
        of "":
          res.incl(TransferEncodingFlags.Identity)
        else:
          return err("Incorrect Transfer-Encoding value")
    ok(res)

func getContentEncoding*(ch: openArray[string]): HttpResult[
                                                   set[ContentEncodingFlags]] {.
     raises: [Defect].} =
  ## Parse value of multiple HTTP headers ``Content-Encoding`` and return
  ## it as set of ``ContentEncodingFlags``.
  var res: set[ContentEncodingFlags] = {}
  if len(ch) == 0:
    res.incl(ContentEncodingFlags.Identity)
    ok(res)
  else:
    for header in ch:
      for item in header.split(","):
        case strip(item.toLowerAscii()):
        of "identity":
          res.incl(ContentEncodingFlags.Identity)
        of "br":
          res.incl(ContentEncodingFlags.Br)
        of "compress":
          res.incl(ContentEncodingFlags.Compress)
        of "deflate":
          res.incl(ContentEncodingFlags.Deflate)
        of "gzip":
          res.incl(ContentEncodingFlags.Gzip)
        of "x-gzip":
          res.incl(ContentEncodingFlags.Gzip)
        of "":
          res.incl(ContentEncodingFlags.Identity)
        else:
          return err("Incorrect Content-Encoding value")
    ok(res)

func getContentType*(ch: openArray[string]): HttpResult[ContentTypeData]  {.
     raises: [Defect].} =
  ## Check and prepare value of ``Content-Type`` header.
  if len(ch) == 0:
    err("No Content-Type values found")
  elif len(ch) > 1:
    err("Multiple Content-Type values found")
  else:
    let res = getContentType(ch[0])
    if res.isErr():
      return err($res.error())
    ok(res.get())

proc bytesToString*(src: openArray[byte], dst: var openArray[char]) =
  ## Convert array of bytes to array of characters.
  ##
  ## Note, that this procedure assume that `sizeof(byte) == sizeof(char) == 1`.
  ## If this equation is not correct this procedures MUST not be used.
  doAssert(len(src) == len(dst))
  if len(src) > 0:
    copyMem(addr dst[0], unsafeAddr src[0], len(src))

proc stringToBytes*(src: openArray[char], dst: var openArray[byte]) =
  ## Convert array of characters to array of bytes.
  ##
  ## Note, that this procedure assume that `sizeof(byte) == sizeof(char) == 1`.
  ## If this equation is not correct this procedures MUST not be used.
  doAssert(len(src) == len(dst))
  if len(src) > 0:
    copyMem(addr dst[0], unsafeAddr src[0], len(src))

func bytesToString*(src: openArray[byte]): string =
  ## Convert array of bytes to a string.
  ##
  ## Note, that this procedure assume that `sizeof(byte) == sizeof(char) == 1`.
  ## If this equation is not correct this procedures MUST not be used.
  var default: string
  if len(src) > 0:
    var dst = newString(len(src))
    bytesToString(src, dst)
    dst
  else:
    default

func stringToBytes*(src: openArray[char]): seq[byte] =
  ## Convert string to sequence of bytes.
  ##
  ## Note, that this procedure assume that `sizeof(byte) == sizeof(char) == 1`.
  ## If this equation is not correct this procedures MUST not be used.
  var default: seq[byte]
  if len(src) > 0:
    var dst = newSeq[byte](len(src))
    stringToBytes(src, dst)
    dst
  else:
    default
