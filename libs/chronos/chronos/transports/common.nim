#
#            Chronos Transport Common Types
#             (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import std/[strutils]
import stew/[base10, byteutils]
import ".."/[asyncloop, osdefs, oserrno]

from std/net import Domain, `==`, IpAddress, IpAddressFamily, parseIpAddress,
                    SockType, Protocol, Port, `$`
from std/nativesockets import toInt, `$`

export Domain, `==`, IpAddress, IpAddressFamily, parseIpAddress, SockType,
       Protocol, Port, toInt, `$`

const
  DefaultStreamBufferSize* = 4096    ## Default buffer size for stream
                                     ## transports
  DefaultDatagramBufferSize* = 65536 ## Default buffer size for datagram
                                     ## transports
type
  ServerFlags* = enum
    ## Server's flags
    ReuseAddr, ReusePort, TcpNoDelay, NoAutoRead, GCUserData, FirstPipe,
    NoPipeFlash, Broadcast

  AddressFamily* {.pure.} = enum
    None, IPv4, IPv6, Unix

  TransportAddress* = object
    ## Transport network address
    case family*: AddressFamily
    of AddressFamily.None:
      discard
    of AddressFamily.IPv4:
      address_v4*: array[4, uint8]
    of AddressFamily.IPv6:
      address_v6*: array[16, uint8]
    of AddressFamily.Unix:
      address_un*: array[108, uint8]
    port*: Port                   # Port number

  ServerCommand* = enum
    ## Server's commands
    Start,                        # Start server
    Pause,                        # Pause server
    Stop                          # Stop server

  ServerStatus* = enum
    ## Server's statuses
    Starting,                     # Server created
    Stopped,                      # Server stopped
    Running,                      # Server running
    Closed                        # Server closed

when defined(windows) or defined(nimdoc):
  type
    SocketServer* = ref object of RootRef
      ## Socket server object
      sock*: AsyncFD                # Socket
      local*: TransportAddress      # Address
      status*: ServerStatus         # Current server status
      udata*: pointer               # User-defined pointer
      flags*: set[ServerFlags]      # Flags
      bufferSize*: int              # Size of internal transports' buffer
      loopFuture*: Future[void]     # Server's main Future
      domain*: Domain               # Current server domain (IPv4 or IPv6)
      apending*: bool
      asock*: AsyncFD               # Current AcceptEx() socket
      errorCode*: OSErrorCode       # Current error code
      abuffer*: array[128, byte]    # Windows AcceptEx() buffer
      when defined(windows):
        aovl*: CustomOverlapped     # AcceptEx OVERLAPPED structure
else:
  type
    SocketServer* = ref object of RootRef
      ## Socket server object
      sock*: AsyncFD                # Socket
      local*: TransportAddress      # Address
      status*: ServerStatus         # Current server status
      udata*: pointer               # User-defined pointer
      flags*: set[ServerFlags]      # Flags
      bufferSize*: int              # Size of internal transports' buffer
      loopFuture*: Future[void]     # Server's main Future
      errorCode*: OSErrorCode       # Current error code

type
  TransportError* = object of AsyncError
    ## Transport's specific exception
  TransportOsError* = object of TransportError
    ## Transport's OS specific exception
    code*: OSErrorCode
  TransportIncompleteError* = object of TransportError
    ## Transport's `incomplete data received` exception
  TransportLimitError* = object of TransportError
    ## Transport's `data limit reached` exception
  TransportAddressError* = object of TransportError
    ## Transport's address specific exception
    code*: OSErrorCode
  TransportNoSupport* = object of TransportError
    ## Transport's capability not supported exception
  TransportUseClosedError* = object of TransportError
    ## Usage after transport close exception
  TransportTooManyError* = object of TransportError
    ## Too many open file descriptors exception
  TransportAbortedError* = object of TransportError
    ## Remote client disconnected before server accepts connection

  TransportState* = enum
    ## Transport's state
    ReadPending,                  # Read operation pending (Windows)
    ReadPaused,                   # Read operations paused
    ReadClosed,                   # Read operations closed
    ReadEof,                      # Read at EOF
    ReadError,                    # Read error
    WritePending,                 # Writer operation pending (Windows)
    WritePaused,                  # Writer operations paused
    WriteClosed,                  # Writer operations closed
    WriteEof,                     # Remote peer disconnected
    WriteError                    # Write error

var
  AnyAddress* = TransportAddress(family: AddressFamily.IPv4, port: Port(0))
    ## Default INADDR_ANY address for IPv4
  AnyAddress6* = TransportAddress(family: AddressFamily.IPv6, port: Port(0))
    ## Default INADDR_ANY address for IPv6

proc `==`*(lhs, rhs: TransportAddress): bool =
  ## Compare two transport addresses ``lhs`` and ``rhs``. Return ``true`` if
  ## addresses are equal.
  if (lhs.family != rhs.family): return false
  case lhs.family
  of AddressFamily.None:
    true
  of AddressFamily.IPv4:
    if lhs.port != rhs.port: return false
    lhs.address_v4 == rhs.address_v4
  of AddressFamily.IPv6:
    if lhs.port != rhs.port: return false
    lhs.address_v6 == rhs.address_v6
  of AddressFamily.Unix:
    equalMem(unsafeAddr lhs.address_un[0],
             unsafeAddr rhs.address_un[0], sizeof(lhs.address_un))

proc getDomain*(address: TransportAddress): Domain =
  ## Returns OS specific Domain from TransportAddress.
  case address.family
  of AddressFamily.IPv4:
    Domain.AF_INET
  of AddressFamily.IPv6:
    Domain.AF_INET6
  of AddressFamily.Unix:
    when defined(windows):
      cast[Domain](1)
    else:
      Domain.AF_UNIX
  else:
    cast[Domain](0)

proc `$`*(address: TransportAddress): string =
  ## Returns string representation of ``address``.
  case address.family
  of AddressFamily.IPv4:
    var a = IpAddress(family: IpAddressFamily.IPv4,
                      address_v4: address.address_v4)
    var res = $a
    res.add(":")
    res.add(Base10.toString(uint16(address.port)))
    res
  of AddressFamily.IPv6:
    var a = IpAddress(family: IpAddressFamily.IPv6,
                      address_v6: address.address_v6)
    var res = "[" & $a & "]:"
    res.add(Base10.toString(uint16(address.port)))
    res
  of AddressFamily.Unix:
    const length = sizeof(address.address_un) + 1
    var buffer: array[length, char]
    if not equalMem(addr buffer[0], unsafeAddr address.address_un[0],
                    sizeof(address.address_un)):
      copyMem(addr buffer[0], unsafeAddr address.address_un[0],
              sizeof(address.address_un))
      $cast[cstring](addr buffer)
    else:
      "/"
  of AddressFamily.None:
    "None"

proc toHex*(address: TransportAddress): string =
  ## Returns hexadecimal representation of ``address`.
  case address.family
  of AddressFamily.IPv4:
    "0x" & address.address_v4.toHex()
  of AddressFamily.IPv6:
    "0x" & address.address_v6.toHex()
  of AddressFamily.Unix:
    "0x" & address.address_un.toHex()
  of AddressFamily.None:
    "None"

proc initTAddress*(address: string): TransportAddress {.
    raises: [Defect, TransportAddressError].} =
  ## Parses string representation of ``address``. ``address`` can be IPv4, IPv6
  ## or Unix domain address.
  ##
  ## IPv4 transport address format is ``a.b.c.d:port``.
  ## IPv6 transport address format is ``[::]:port``.
  ## Unix transport address format is ``/address``.
  if len(address) > 0:
    if address[0] == '/':
      var res = TransportAddress(family: AddressFamily.Unix, port: Port(1))
      let size = if len(address) < (sizeof(res.address_un) - 1): len(address)
                   else: (sizeof(res.address_un) - 1)
      copyMem(addr res.address_un[0], unsafeAddr address[0], size)
      res
    else:
      let parts =
        block:
          let res = address.rsplit(":", maxsplit = 1)
          if len(res) != 2:
            raise newException(TransportAddressError,
                               "Format is <address>:<port>!")
          res
      let port =
        block:
          let res = Base10.decode(uint16, parts[1])
          if res.isErr():
            raise newException(TransportAddressError,
                               "Invalid port number!")
          res.get()

      let ipaddr =
        try:
          if parts[0][0] == '[' and parts[0][^1] == ']':
            parseIpAddress(parts[0][1..^2])
          else:
            parseIpAddress(parts[0])
        except CatchableError as exc:
          raise newException(TransportAddressError, exc.msg)

      case ipaddr.family
      of IpAddressFamily.IPv4:
        TransportAddress(family: AddressFamily.IPv4,
                         address_v4: ipaddr.address_v4, port: Port(port))
      of IpAddressFamily.IPv6:
        TransportAddress(family: AddressFamily.IPv6,
                         address_v6: ipaddr.address_v6, port: Port(port))
  else:
    TransportAddress(family: AddressFamily.Unix)

proc initTAddress*(address: string, port: Port): TransportAddress {.
    raises: [Defect, TransportAddressError].} =
  ## Initialize ``TransportAddress`` with IP (IPv4 or IPv6) address ``address``
  ## and port number ``port``.
  let ipaddr =
    try:
      parseIpAddress(address)
    except CatchableError as exc:
      raise newException(TransportAddressError, exc.msg)

  case ipaddr.family
  of IpAddressFamily.IPv4:
    TransportAddress(family: AddressFamily.IPv4,
                     address_v4: ipaddr.address_v4, port: port)
  of IpAddressFamily.IPv6:
    TransportAddress(family: AddressFamily.IPv6,
                     address_v6: ipaddr.address_v6, port: port)

proc initTAddress*(address: string, port: int): TransportAddress {.
    raises: [Defect, TransportAddressError].} =
  ## Initialize ``TransportAddress`` with IP (IPv4 or IPv6) address ``address``
  ## and port number ``port``.
  if port < 0 or port > 65535:
    raise newException(TransportAddressError, "Illegal port number!")
  initTAddress(address, Port(port))

proc initTAddress*(address: IpAddress, port: Port): TransportAddress =
  ## Initialize ``TransportAddress`` with net.nim ``IpAddress`` and
  ## port number ``port``.
  case address.family
  of IpAddressFamily.IPv4:
    TransportAddress(family: AddressFamily.IPv4,
                     address_v4: address.address_v4, port: port)
  of IpAddressFamily.IPv6:
    TransportAddress(family: AddressFamily.IPv6,
                     address_v6: address.address_v6, port: port)

proc getAddrInfo(address: string, port: Port, domain: Domain,
                 sockType: SockType = SockType.SOCK_STREAM,
                 protocol: Protocol = Protocol.IPPROTO_TCP): ptr AddrInfo {.
    raises: [Defect, TransportAddressError].} =
  ## We have this one copy of ``getAddrInfo()`` because of AI_V4MAPPED in
  ## ``net.nim:getAddrInfo()``, which is not cross-platform.
  var hints: AddrInfo
  var res: ptr AddrInfo = nil
  hints.ai_family = toInt(domain)
  hints.ai_socktype = toInt(sockType)
  hints.ai_protocol = toInt(protocol)
  var gaiRes = getaddrinfo(address, cstring(Base10.toString(uint16(port))),
                           addr(hints), res)
  if gaiRes != 0'i32:
    when defined(windows) or defined(nimdoc):
      raise newException(TransportAddressError, osErrorMsg(osLastError()))
    else:
      raise newException(TransportAddressError, $gai_strerror(gaiRes))
  res

proc fromSAddr*(sa: ptr Sockaddr_storage, sl: SockLen,
                address: var TransportAddress) =
  ## Set transport address ``address`` with value from OS specific socket
  ## address storage.
  if int(sa.ss_family) == toInt(Domain.AF_INET) and
     int(sl) == sizeof(Sockaddr_in):
    address = TransportAddress(family: AddressFamily.IPv4)
    let s = cast[ptr Sockaddr_in](sa)
    copyMem(addr address.address_v4[0], addr s.sin_addr,
            sizeof(address.address_v4))
    address.port = Port(nativesockets.ntohs(s.sin_port))
  elif int(sa.ss_family) == toInt(Domain.AF_INET6) and
       int(sl) == sizeof(Sockaddr_in6):
    address = TransportAddress(family: AddressFamily.IPv6)
    let s = cast[ptr Sockaddr_in6](sa)
    copyMem(addr address.address_v6[0], addr s.sin6_addr,
            sizeof(address.address_v6))
    address.port = Port(nativesockets.ntohs(s.sin6_port))
  elif int(sa.ss_family) == toInt(Domain.AF_UNIX):
    when not defined(windows) and not defined(nimdoc):
      address = TransportAddress(family: AddressFamily.Unix)
      if int(sl) > sizeof(sa.ss_family):
        var length = int(sl) - sizeof(sa.ss_family)
        if length > (sizeof(address.address_un) - 1):
          length = sizeof(address.address_un) - 1
        let s = cast[ptr Sockaddr_un](sa)
        copyMem(addr address.address_un[0], addr s.sun_path[0], length)
        address.port = Port(1)
    else:
      discard

proc toSAddr*(address: TransportAddress, sa: var Sockaddr_storage,
             sl: var SockLen) =
  ## Set socket OS specific socket address storage with address from transport
  ## address ``address``.
  case address.family
  of AddressFamily.IPv4:
    sl = SockLen(sizeof(Sockaddr_in))
    let s = cast[ptr Sockaddr_in](addr sa)
    s.sin_family = type(s.sin_family)(toInt(Domain.AF_INET))
    s.sin_port = nativesockets.htons(uint16(address.port))
    copyMem(addr s.sin_addr, unsafeAddr address.address_v4[0],
            sizeof(s.sin_addr))
  of AddressFamily.IPv6:
    sl = SockLen(sizeof(Sockaddr_in6))
    let s = cast[ptr Sockaddr_in6](addr sa)
    s.sin6_family = type(s.sin6_family)(toInt(Domain.AF_INET6))
    s.sin6_port = nativesockets.htons(uint16(address.port))
    copyMem(addr s.sin6_addr, unsafeAddr address.address_v6[0],
            sizeof(s.sin6_addr))
  of AddressFamily.Unix:
    when not defined(windows) and not defined(nimdoc):
      if address.port == Port(0):
        sl = SockLen(sizeof(sa.ss_family))
      else:
        let s = cast[ptr Sockaddr_un](addr sa)
        var name = cast[cstring](unsafeAddr address.address_un[0])
        sl = SockLen(sizeof(sa.ss_family) + len(name) + 1)
        s.sun_family = type(s.sun_family)(toInt(Domain.AF_UNIX))
        copyMem(addr s.sun_path, unsafeAddr address.address_un[0],
                len(name) + 1)
  else:
    discard

proc address*(ta: TransportAddress): IpAddress {.
     raises: [Defect, ValueError].} =
  ## Converts ``TransportAddress`` to ``net.IpAddress`` object.
  ##
  ## Note its impossible to convert ``TransportAddress`` of ``Unix`` family,
  ## because ``IpAddress`` supports only IPv4, IPv6 addresses.
  case ta.family
  of AddressFamily.IPv4:
    IpAddress(family: IpAddressFamily.IPv4, address_v4: ta.address_v4)
  of AddressFamily.IPv6:
    IpAddress(family: IpAddressFamily.IPv6, address_v6: ta.address_v6)
  else:
    raise newException(ValueError, "IpAddress supports only IPv4/IPv6!")

proc host*(ta: TransportAddress): string {.raises: [Defect].} =
  ## Returns ``host`` of TransportAddress ``ta``.
  ##
  ## For IPv4 and IPv6 addresses it will return IP address as string, or empty
  ## string for Unix address.
  case ta.family
  of AddressFamily.IPv4:
    $IpAddress(family: IpAddressFamily.IPv4, address_v4: ta.address_v4)
  of AddressFamily.IPv6:
    let a = $IpAddress(family: IpAddressFamily.IPv6,
                       address_v6: ta.address_v6)
    "[" & a & "]"
  else:
    ""

proc resolveTAddress*(address: string, port: Port,
                      domain: Domain): seq[TransportAddress] {.
     raises: [Defect, TransportAddressError].} =
  var res: seq[TransportAddress]
  let aiList = getAddrInfo(address, port, domain)
  var it = aiList
  while not(isNil(it)):
    var ta: TransportAddress
    fromSAddr(cast[ptr Sockaddr_storage](it.ai_addr),
              SockLen(it.ai_addrlen), ta)
    # For some reason getAddrInfo() sometimes returns duplicate addresses,
    # for example getAddrInfo(`localhost`) returns `127.0.0.1` twice.
    if ta notin res:
      res.add(ta)
    it = it.ai_next
  res

proc resolveTAddress*(address: string, domain: Domain): seq[TransportAddress] {.
     raises: [Defect, TransportAddressError].} =
  let parts =
    block:
      let res = address.rsplit(":", maxsplit = 1)
      if len(res) != 2:
        raise newException(TransportAddressError, "Format is <address>:<port>!")
      res
  let port =
    block:
      let res = Base10.decode(uint16, parts[1])
      if res.isErr():
        raise newException(TransportAddressError, "Invalid port number!")
      res.get()
  let hostname =
    if parts[0][0] == '[' and parts[0][^1] == ']':
      # IPv6 numeric addresses must be enclosed with `[]`.
      parts[0][1..^2]
    else:
      parts[0]
  resolveTAddress(hostname, Port(port), domain)

proc resolveTAddress*(address: string): seq[TransportAddress] {.
     raises: [Defect, TransportAddressError].} =
  ## Resolve string representation of ``address``.
  ##
  ## Supported formats are:
  ## IPv4 numeric address ``a.b.c.d:port``
  ## IPv6 numeric address ``[::]:port``
  ## Hostname address ``hostname:port``
  ##
  ## If hostname address is detected, then network address translation via DNS
  ## will be performed.
  resolveTAddress(address, Domain.AF_UNSPEC)

proc resolveTAddress*(address: string, port: Port): seq[TransportAddress] {.
     raises: [Defect, TransportAddressError].} =
  ## Resolve string representation of ``address``.
  ##
  ## Supported formats are:
  ## IPv4 numeric address ``a.b.c.d:port``
  ## IPv6 numeric address ``[::]:port``
  ## Hostname address ``hostname:port``
  ##
  ## If hostname address is detected, then network address translation via DNS
  ## will be performed.
  resolveTAddress(address, port, Domain.AF_UNSPEC)

proc resolveTAddress*(address: string,
                      family: AddressFamily): seq[TransportAddress] {.
    raises: [Defect, TransportAddressError].} =
  ## Resolve string representation of ``address``.
  ##
  ## Supported formats are:
  ## IPv4 numeric address ``a.b.c.d:port``
  ## IPv6 numeric address ``[::]:port``
  ## Hostname address ``hostname:port``
  ##
  ## If hostname address is detected, then network address translation via DNS
  ## will be performed.
  case family
  of AddressFamily.IPv4:
    resolveTAddress(address, Domain.AF_INET)
  of AddressFamily.IPv6:
    resolveTAddress(address, Domain.AF_INET6)
  else:
    raiseAssert("Unable to resolve non-internet address")

proc resolveTAddress*(address: string, port: Port,
                      family: AddressFamily): seq[TransportAddress] {.
    raises: [Defect, TransportAddressError].} =
  ## Resolve string representation of ``address``.
  ##
  ## ``address`` could be dot IPv4/IPv6 address or hostname.
  ##
  ## If hostname address is detected, then network address translation via DNS
  ## will be performed.
  case family
  of AddressFamily.IPv4:
    resolveTAddress(address, port, Domain.AF_INET)
  of AddressFamily.IPv6:
    resolveTAddress(address, port, Domain.AF_INET6)
  else:
    raiseAssert("Unable to resolve non-internet address")

proc resolveTAddress*(address: string,
                      family: IpAddressFamily): seq[TransportAddress] {.
     deprecated, raises: [Defect, TransportAddressError].} =
  case family
  of IpAddressFamily.IPv4:
    resolveTAddress(address, AddressFamily.IPv4)
  of IpAddressFamily.IPv6:
    resolveTAddress(address, AddressFamily.IPv6)

proc resolveTAddress*(address: string, port: Port,
                      family: IpAddressFamily): seq[TransportAddress] {.
     deprecated, raises: [Defect, TransportAddressError].} =
  case family
  of IpAddressFamily.IPv4:
    resolveTAddress(address, port, AddressFamily.IPv4)
  of IpAddressFamily.IPv6:
    resolveTAddress(address, port, AddressFamily.IPv6)

proc windowsAnyAddressFix*(a: TransportAddress): TransportAddress =
  ## BSD Sockets on \*nix systems are able to perform connections to
  ## `0.0.0.0` or `::0` which are equal to `127.0.0.1` or `::1`.
  when defined(windows):
    if (a.family == AddressFamily.IPv4 and
        a.address_v4 == AnyAddress.address_v4):
      try:
        initTAddress("127.0.0.1", a.port)
      except TransportAddressError as exc:
        raiseAssert exc.msg
    elif (a.family == AddressFamily.IPv6 and
          a.address_v6 == AnyAddress6.address_v6):
      try:
        initTAddress("::1", a.port)
      except TransportAddressError as exc:
        raiseAssert exc.msg
    else:
      a
  else:
    a

template checkClosed*(t: untyped) =
  if (ReadClosed in (t).state) or (WriteClosed in (t).state):
    raise newException(TransportUseClosedError, "Transport is already closed!")

template checkClosed*(t: untyped, future: untyped) =
  if (ReadClosed in (t).state) or (WriteClosed in (t).state):
    future.fail(newException(TransportUseClosedError,
                             "Transport is already closed!"))
    return future

template checkWriteEof*(t: untyped, future: untyped) =
  if (WriteEof in (t).state):
    future.fail(newException(TransportError,
                             "Transport connection is already dropped!"))
    return future

template getError*(t: untyped): ref CatchableError =
  var err = (t).error
  (t).error = nil
  err

template getServerUseClosedError*(): ref TransportUseClosedError =
  newException(TransportUseClosedError, "Server is already closed!")

template getTransportUseClosedError*(): ref TransportUseClosedError =
  newException(TransportUseClosedError, "Transport is already closed!")

template getTransportOsError*(err: OSErrorCode): ref TransportOsError =
  var msg = "(" & $int(err) & ") " & osErrorMsg(err)
  var tre = newException(TransportOsError, msg)
  tre.code = err
  tre

template getTransportOsError*(err: cint): ref TransportOsError =
  getTransportOsError(OSErrorCode(err))

proc raiseTransportOsError*(err: OSErrorCode) {.
    raises: [Defect, TransportOsError].} =
  ## Raises transport specific OS error.
  raise getTransportOsError(err)

type
  SeqHeader = object
    length, reserved: int

proc isLiteral*(s: string): bool {.inline.} =
  when defined(gcOrc) or defined(gcArc):
    false
  else:
    (cast[ptr SeqHeader](s).reserved and (1 shl (sizeof(int) * 8 - 2))) != 0

proc isLiteral*[T](s: seq[T]): bool {.inline.} =
  when defined(gcOrc) or defined(gcArc):
    false
  else:
    (cast[ptr SeqHeader](s).reserved and (1 shl (sizeof(int) * 8 - 2))) != 0

template getTransportTooManyError*(
           code = OSErrorCode(0)
         ): ref TransportTooManyError =
  let msg =
    when defined(posix):
      if code == OSErrorCode(0):
        "Too many open transports"
      elif code == oserrno.EMFILE:
        "[EMFILE] Too many open files in the process"
      elif code == oserrno.ENFILE:
        "[ENFILE] Too many open files in system"
      elif code == oserrno.ENOBUFS:
        "[ENOBUFS] No buffer space available"
      elif code == oserrno.ENOMEM:
        "[ENOMEM] Not enough memory availble"
      else:
        "[" & $int(code) & "] Too many open transports"
    elif defined(windows):
      case code
      of OSErrorCode(0):
        "Too many open transports"
      of ERROR_TOO_MANY_OPEN_FILES:
        "[ERROR_TOO_MANY_OPEN_FILES] Too many open files"
      of WSAENOBUFS:
        "[WSAENOBUFS] No buffer space available"
      of WSAEMFILE:
        "[WSAEMFILE] Too many open sockets"
      else:
        "[" & $int(code) & "] Too many open transports"
    else:
      "[" & $int(code) & "] Too many open transports"
  newException(TransportTooManyError, msg)

template getConnectionAbortedError*(m: string = ""): ref TransportAbortedError =
  let msg =
    if len(m) == 0:
      "[ECONNABORTED] Connection has been aborted before being accepted"
    else:
      "[ECONNABORTED] " & m
  newException(TransportAbortedError, msg)

template getConnectionAbortedError*(
           code: OSErrorCode
         ): ref TransportAbortedError =
  let msg =
    when defined(posix):
      if code == OSErrorCode(0):
        "[ECONNABORTED] Connection has been aborted before being accepted"
      elif code == oserrno.EPERM:
        "[EPERM] Firewall rules forbid connection"
      elif code == oserrno.ETIMEDOUT:
        "[ETIMEDOUT] Operation has been timed out"
      else:
        "[" & $int(code) & "] Connection has been aborted"
    elif defined(windows):
      case code
      of OSErrorCode(0), oserrno.WSAECONNABORTED:
        "[ECONNABORTED] Connection has been aborted before being accepted"
      of WSAENETDOWN:
        "[ENETDOWN] Network is down"
      of oserrno.WSAENETRESET:
        "[ENETRESET] Network dropped connection on reset"
      of oserrno.WSAECONNRESET:
        "[ECONNRESET] Connection reset by peer"
      of WSAETIMEDOUT:
        "[ETIMEDOUT] Connection timed out"
      else:
        "[" & $int(code) & "] Connection has been aborted"
    else:
      "[" & $int(code) & "] Connection has been aborted"

  newException(TransportAbortedError, msg)
