#
#
#       Asynchronous tools for Nim Language
#        (c) Copyright 2016 Eugene Kabanov
#
#      See the file "LICENSE", included in this
#    distribution, for details about the copyright.
#

## This module implements asynchronous DNS resolve mechanism.
##
## asyncGetAddrInfo() don't have support for `flags` argument.
##
## Supported platforms: Linux, Windows, MacOS, FreeBSD, NetBSD, OpenBSD(*),
## Solaris.
##
## * OpenBSD requires `libbind` package.

import asyncdispatch, os, nativesockets, strutils

const
  PACKETSZ = 512

type
  uncheckedArray [T] = UncheckedArray[T]
  AsyncAddrInfo* = distinct AddrInfo

when defined(windows):
  import winlean
else:
  import posix

proc `$`*(aip: ptr AddrInfo|ptr AsyncAddrInfo): string =
  result = ""
  var ai = cast[ptr AddrInfo](aip)
  var address = newString(128)
  var nport = 0'u16
  var hport = 0'u16
  if ai.ai_family == toInt(Domain.AF_INET6):
    let p = cast[ptr Sockaddr_in6](ai.ai_addr)
    nport = p.sin6_port
    hport = nativesockets.ntohs(nport)
    discard inet_ntop(ai.ai_family, cast[pointer](addr p.sin6_addr),
                      cstring(address), len(address).int32)
  else:
    let p = cast[ptr Sockaddr_in](ai.ai_addr)
    nport = p.sin_port
    hport = nativesockets.ntohs(nport)
    discard inet_ntop(ai.ai_family, cast[pointer](addr p.sin_addr),
                      cstring(address), len(address).int32)
  result &= "ai_flags = 0x" & toHex(cast[int32](ai.ai_flags)) & "\n"
  result &= "ai_family = 0x" & toHex(cast[int32](ai.ai_family)) & "\n"
  result &= "ai_socktype = 0x" & toHex(cast[int32](ai.ai_socktype)) & "\n"
  result &= "ai_protocol = 0x" & toHex(cast[int32](ai.ai_protocol)) & "\n"
  result &= "ai_canonname = 0x" & toHex(cast[int](ai.ai_canonname)) & "\n"
  result &= "ai_addrlen = " & $ai.ai_addrlen & "\n"
  result &= "ai_addr = 0x" & toHex(cast[int](ai.ai_addr)) & "\n"
  result &= "  sin_family = 0x" & toHex(cast[int16](ai.ai_addr.sa_family)) &
                                  "\n"
  result &= "  sin_port = 0x" & toHex(cast[int16](nport)) & " (" &
                                $hport & ")" & "\n"
  result &= "  sin_addr = " & address & "\n"
  result &= "ai_next = 0x" & toHex(cast[int](ai.ai_next))

proc `==`*(ai1: ptr AddrInfo|ptr AsyncAddrInfo,
           ai2: ptr AddrInfo|ptr AsyncAddrInfo): bool =
  result = false
  var sai = cast[ptr AddrInfo](ai1)
  var dai = cast[ptr AddrInfo](ai2)

  var saiLength = 0
  var daiLength = 0
  var rec = sai
  while not rec.isNil:
    inc(saiLength)
    rec = rec.ai_next
  rec = dai
  while not rec.isNil:
    inc(daiLength)
    rec = rec.ai_next

  if saiLength == daiLength:
    var srec = sai
    while not srec.isNil:
      result = false
      var drec = dai
      while not drec.isNil:
        if srec.ai_family == drec.ai_family and
           srec.ai_socktype == drec.ai_socktype and
           srec.ai_protocol == drec.ai_protocol and
           srec.ai_addrlen == drec.ai_addrlen:
          if equalMem(cast[pointer](srec.ai_addr), cast[pointer](drec.ai_addr),
                      srec.ai_addrlen):
            result = true
            break
        drec = drec.ai_next
      if not result:
        break
      srec = srec.ai_next

when defined(windows):

  const
    DnsConfigDnsServerList = 6
    DnsTypeA = 1
    DnsTypeAAAA = 28
    DnsFreeRecordList = 1
    DnsSectionAnswer = 1
    DNS_ERROR_NO_DNS_SERVERS = 9852
    DNS_INFO_NO_RECORDS = 9501
    DNS_ERROR_WRONG_XID = 100
  type
    WORD = uint16

    DNS_RECORD = object
      pNext: ptr DNS_RECORD
      pName: pointer
      wType: Word
      wDataLength: Word
      flags: Dword
      ttl: Dword
      reserved: Dword
      data: byte
    PDNS_RECORD = ptr DNS_RECORD

    DNS_HEADER {.packed.} = object
      Xid: Word
      Flags: Word
      QuestionCount: Word
      AnswerCount: Word
      NameServerCount: Word
      AdditionalCount: Word

  proc dnsQueryConfig(config: Dword, flag: Dword, adapterName: pointer,
                      reserved: pointer, buffer: pointer,
                      buflen: ptr Dword): LONG
       {.importc: "DnsQueryConfig", stdcall, dynlib: "dnsapi.dll".}
  proc dnsWriteQuestionToBuffer(buffer: pointer, buflen: ptr Dword,
                                name: WideCSTring, wtype: Word,
                                xid: Word, recursion: Winbool): Winbool
       {.importc: "DnsWriteQuestionToBuffer_W", stdcall,
         dynlib: "dnsapi.dll".}
  proc dnsExtractRecordsFromMessage(message: pointer, buflen: Word,
                                    buffer: ptr PDNS_RECORD): LONG
       {.importc: "DnsExtractRecordsFromMessage_W", stdcall,
         dynlib: "dnsapi.dll".}
  proc dnsFree(buffer: pointer, ftype: Dword)
       {.importc: "DnsFree", stdcall, dynlib: "dnsapi.dll".}

  proc QueryPerformanceCounter(res: var int64)
       {.importc: "QueryPerformanceCounter", stdcall, dynlib: "kernel32".}

  proc getDnsServersList(): ptr uncheckedArray[int32] =
    var buffer: pointer = nil
    var buflen = 0.Dword
    let res = dnsQueryConfig(DnsConfigDnsServerList, 0, nil, nil, buffer,
                             addr buflen)
    if res == 0 and buflen > 4:
      buffer = alloc0(buflen)
      let sres = dnsQueryConfig(DnsConfigDnsServerList, 0, nil, nil, buffer,
                               addr buflen)
      if sres == 0:
        result = cast[ptr uncheckedArray[int32]](buffer)
      else:
        raiseOsError(osLastError())
    else:
      raiseOsError(osLastError())

  proc freeDnsServersList(arr: ptr uncheckedArray[int32]) =
    dealloc(cast[pointer](arr))

  proc getXid(): Word =
    var number = 0'i64
    QueryPerformanceCounter(number)
    result = ((number shr 48) and 0xFFFF).Word xor
             ((number shr 32) and 0xFFFF).Word xor
             ((number shr 16) and 0xFFFF).Word xor
             (number and 0xFFFF).Word

  when declared(system.csize_t):
    type SizeAlias = system.csize_t
  else:
    type SizeAlias = system.int

  proc asyncGetAddrInfo*(address: string, port: Port,
                         domain: Domain = nativesockets.AF_INET,
                         sockType: SockType = nativesockets.SOCK_STREAM,
                         protocol: Protocol = nativesockets.IPPROTO_TCP):
                         Future[ptr AsyncAddrInfo] {.async.} =
    var blob: pointer = nil
    var ai = 0
    var request = newString(PACKETSZ)
    var response = newString(PACKETSZ)
    var reqLength = 0
    var nsLastError = 0

    var qt = if domain == Domain.AF_INET6: Word(DnsTypeAAAA) else:
             Word(DnsTypeA)
    var nsList = getDnsServersList()
    if nsList[0] <= 0:
      raiseOsError(OSErrorCode(DNS_ERROR_NO_DNS_SERVERS))

    var xid = getXid()
    var buflen = 0.Dword
    var buffer: pointer = nil
    while true:
      let res = dnsWriteQuestionToBuffer(buffer, addr buflen,
                                         newWideCString(address), qt,
                                         xid, 0)
      if res == 0:
        if buflen > 0 and isNil(buffer):
          buffer = alloc0(buflen)
        else:
          if not isNil(buffer):
            dealloc(buffer)
          raiseOsError(osLastError())
      elif res == 1:
        if buflen > PACKETSZ:
          if not isNil(buffer):
            dealloc(buffer)
          raise newException(ValueError, "Packet size is too big!")
        else:
          copyMem(cast[pointer](addr request[0]), buffer, buflen)
          reqLength = buflen
          dealloc(buffer)
          break

    let sock = createAsyncNativeSocket(nativesockets.AF_INET,
                                    nativesockets.SOCK_DGRAM,
                                    Protocol.IPPROTO_UDP)

    for i in 1..nsList[0]:
      var dnsAddr = Sockaddr_in()
      var recvAddr = Sockaddr_in()
      var recvALen = sizeof(Sockaddr_in)
      dnsAddr.sin_family = winlean.AF_INET
      dnsAddr.sin_port = nativesockets.htons(53.uint16)
      dnsAddr.sin_addr.s_addr = nsList[i].uint32

      await sendTo(sock, addr request[0], reqLength,
                   cast[ptr SockAddr](addr dnsAddr),
                   sizeof(Sockaddr_in).SockLen)

      var respLength = await recvFromInto(sock, addr(response[0]),
                                          PACKETSZ,
                                          cast[ptr SockAddr](addr recvAddr),
                                          cast[ptr SockLen](addr recvALen))
      var records: PDNS_RECORD = nil

      # This is emulation of windns.h DNS_BYTE_FLIP_HEADER_COUNTS macro.
      var header = cast[ptr DNS_HEADER](addr response[0])
      header.Xid = nativesockets.ntohs(header.Xid)
      header.QuestionCount = nativesockets.ntohs(header.QuestionCount)
      header.AnswerCount = nativesockets.ntohs(header.AnswerCount)
      header.NameServerCount = nativesockets.ntohs(header.NameServerCount)
      header.AdditionalCount = nativesockets.ntohs(header.AdditionalCount)

      if header.Xid != xid:
        nsLastError = DNS_ERROR_WRONG_XID
        continue

      let res = dnsExtractRecordsFromMessage(cast[pointer](addr response[0]),
                                             respLength.Word, addr records)
      if res != 0:
        nsLastError = res.int
        continue

      # lets count answer records
      var count = 0
      var rec = records
      while rec != nil:
        let section = rec.flags and 3
        if (section == DnsSectionAnswer) and
           ((rec.wType == DnsTypeA) or (rec.wType == DnsTypeAAAA)):
          inc(count)
        rec = rec.pNext

      if count == 0:
        nsLastError = DNS_INFO_NO_RECORDS
        continue

      let blobsize = sizeof(AddrInfo) * count + sizeof(SockAddr) * count
      if isNil(blob):
        blob = alloc0(blobsize)

      let p0 = blob
      let p1 = cast[pointer](cast[uint](blob) +
                             cast[uint](sizeof(AddrInfo) * count))
      var addrArr = cast[ptr uncheckedArray[AddrInfo]](p0)
      var sockArr = cast[ptr uncheckedArray[SockAddr]](p1)

      var k = 0
      rec = records
      while rec != nil:
        let section = rec.flags and 3

        if section == DnsSectionAnswer:
          if rec.wType == DnsTypeA:
            addrArr[ai].ai_family = toInt(domain)
            addrArr[ai].ai_socktype = toInt(sockType)
            addrArr[ai].ai_protocol = toInt(protocol)
            addrArr[ai].ai_addrlen = sizeof(Sockaddr_in).SizeAlias
            addrArr[ai].ai_addr = addr sockArr[ai]
            var addrp = cast[ptr Sockaddr_in](addr sockArr[ai])
            addrp.sin_family = toInt(domain).uint16
            addrp.sin_port = nativesockets.ntohs(cast[uint16](port))
            copyMem(addr addrp.sin_addr, addr rec.data, 4)
            if k + 1 < count:
              addrArr[ai].ai_next = cast[ptr AddrInfo](addr addrarr[ai + 1])
            inc(ai)
          elif rec.wType == DnsTypeAAAA:
            addrArr[ai].ai_family = toInt(domain)
            addrArr[ai].ai_socktype = toInt(sockType)
            addrArr[ai].ai_protocol = toInt(protocol)
            addrArr[ai].ai_addrlen = sizeof(Sockaddr_in6).SizeAlias
            addrArr[ai].ai_addr = addr sockArr[ai]
            var addrp = cast[ptr Sockaddr_in6](addr sockArr[ai])
            addrp.sin6_family = toInt(domain).uint16
            addrp.sin6_port = nativesockets.ntohs(cast[uint16](port))
            copyMem(addr addrp.sin6_addr, addr rec.data, 4 * 4)
            if k + 1 < count:
              addrArr[ai].ai_next = cast[ptr AddrInfo](addr addrarr[ai + 1])
            inc(ai)
        inc(k)
        rec = rec.pNext

      dnsFree(cast[pointer](records), DnsFreeRecordList)

      if ai > 0 and nsLastError == 0:
        result = cast[ptr AsyncAddrInfo](blob)
        break
      else:
        ai = 0
        zeroMem(blob, blobsize)
        continue

    freeDnsServersList(nsList)
    if nsLastError == 0:
      discard
    elif nsLastError == DNS_ERROR_WRONG_XID:
      raise newException(ValueError, "Wrong packet id recieved!")
    else:
      raiseOsError(OSErrorCode(nsLastError))

else:
  when defined(linux) or defined(macosx):
    {.passL: "-lresolv".}

  when defined(freebsd) or defined(linux) or defined(macosx):
    const headers = """#include <sys/types.h>
                       #include <netinet/in.h>
                       #include <arpa/nameser.h>
                       #include <resolv.h>"""
  elif defined(solaris):
    const headers = """#include <sys/types.h>
                       #include <netinet/in.h>
                       #include <arpa/nameser.h>
                       #include <resolv.h>
                       #include <netdb.h>"""
  elif defined(netbsd):
    const headers = """#include <resolv.h>
                       #include <res_update.h>"""
  elif defined(openbsd):
    {.hint: "*** OpenBSD requires `libbind` package to be installed".}
    const headers = """#include <sys/types.h>
                       #include <netinet/in.h>
                       #include <arpa/nameser.h>
                       #include <resolv.h>"""
    {.passC: "-I/usr/local/include/bind".}
    {.passL: "-L/usr/local/lib/libbind -R/usr/local/lib/libbind -lbind".}
  else:
    {.error: "Unsupported operation system!".}

  const
    QUERY = 0
    C_IN = 1
    NS_MAXDNAME = 1025

  type
    adnsStatus = enum
      noError, formatError, serverFailError, nxDomainError,
      notimplError, refusedError, badDataError, parseError,
      recordError, unknownError, zeroError, rtypeError

    ResolverState {.importc: "struct __res_state",
                    header: headers, pure, final.} = object
      retrans {.importc: "retrans".}: cint
      retry {.importc: "retry".}: cint
      options {.importc: "options".}: culong
      nscount {.importc: "nscount".}: cint
      nsaddrList {.importc: "nsaddr_list".}: array[3, Sockaddr_in]
      # id {.importc: "id".}: cushort
      # dnsrch {.importc: "dnsrch".}: array[7, ptr char]
      # defdname {.importc: "defdname".}: array[256, char]
      # pfcode {.importc: "pfcode".}: culong
      # somethings: array[4, char]
      # sortList {.importc: "sort_list".}: array[10, SortList]
      # qhook {.importc: "qhook".}: pointer
      # rhook {.importc: "rhook".}: pointer
      # resErrno {.importc: "res_h_errno".}: cint
      # vcsock {.importc: "_vcsock".}: cint
      # flags {.importc: "_flags".}: cuint

    PResolver = ref ResolverState

    nsFlag {.importc: "enum __ns_flag", header: headers.} = enum
      # ns_f_qr,                # Question/Response.
      # ns_f_opcode,            # Operation code.
      # ns_f_aa,                # Authoritative Answer.
      # ns_f_tc,                # Truncation occurred.
      # ns_f_rd,                # Recursion Desired.
      # ns_f_ra,                # Recursion Available.
      # ns_f_z,                 # MBZ.
      # ns_f_ad,                # Authentic Data (DNSSEC).
      # ns_f_cd,                # Checking Disabled (DNSSEC).
      ns_f_rcode = 9,             # Response code.
      # ns_f_max

    nsRcode {.importc: "enum __ns_rcode", header: headers.} = enum
      ns_r_noerror = 0,       # No error occurred.
      ns_r_formerr = 1,       # Format error.
      ns_r_servfail = 2,      # Server failure.
      ns_r_nxdomain = 3,      # Name error.
      ns_r_notimpl = 4,       # Unimplemented.
      ns_r_refused = 5,       # Operation refused.
      # these are for BIND_UPDATE
      # ns_r_yxdomain = 6,      # Name exists
      # ns_r_yxrrset = 7,       # RRset exists
      # ns_r_nxrrset = 8,       # RRset does not exist
      # ns_r_notauth = 9,       # Not authoritative for zone
      # ns_r_notzone = 10,      # Zone of record different from zone section
      # ns_r_max = 11,
      # # The following are EDNS extended rcodes
      # # ns_r_badvers = 16,
      # # The following are TSIG errors
      # ns_r_badsig = 16,
      # ns_r_badkey = 17,
      # ns_r_badtime = 18

    nsSect {.importc: "enum __ns_sect", header: headers.} = enum
      # ns_s_qd = 0,            # Query: Question.
      ns_s_an = 1,            # Query: Answer.
      # ns_s_ns = 2,            # Query: Name servers.
      # ns_s_ar = 3,            # Query|Update: Additional records.
      # ns_s_max = 4

    nsType {.importc: "enum __ns_type", header: headers.} = enum
      # ns_t_invalid = 0,       #  Cookie.
      ns_t_a = 1,             #  Host address.
      # ns_t_ns = 2,            #  Authoritative server.
      # ns_t_md = 3,            #  Mail destination.
      # ns_t_mf = 4,            #  Mail forwarder.
      ns_t_cname = 5,         #  Canonical name.
      # ns_t_soa = 6,           #  Start of authority zone.
      # ns_t_mb = 7,            #  Mailbox domain name.
      # ns_t_mg = 8,            #  Mail group member.
      # ns_t_mr = 9,            #  Mail rename name.
      # ns_t_null = 10,         #  Null resource record.
      # ns_t_wks = 11,          #  Well known service.
      # ns_t_ptr = 12,          #  Domain name pointer.
      # ns_t_hinfo = 13,        #  Host information.
      # ns_t_minfo = 14,        #  Mailbox information.
      # ns_t_mx = 15,           #  Mail routing information.
      # ns_t_txt = 16,          #  Text strings.
      # ns_t_rp = 17,           #  Responsible person.
      # ns_t_afsdb = 18,        #  AFS cell database.
      # ns_t_x25 = 19,          #  X_25 calling address.
      # ns_t_isdn = 20,         #  ISDN calling address.
      # ns_t_rt = 21,           #  Router.
      # ns_t_nsap = 22,         #  NSAP address.
      # ns_t_nsap_ptr = 23,     #  Reverse NSAP lookup (deprecated).
      # ns_t_sig = 24,          #  Security signature.
      # ns_t_key = 25,          #  Security key.
      # ns_t_px = 26,           #  X.400 mail mapping.
      # ns_t_gpos = 27,         #  Geographical position (withdrawn).
      ns_t_aaaa = 28,         #  IPv6 Address.
      # ns_t_loc = 29,          #  Location Information.
      # ns_t_nxt = 30,          #  Next domain (security).
      # ns_t_eid = 31,          #  Endpoint identifier.
      # ns_t_nimloc = 32,       #  Nimrod Locator.
      # ns_t_srv = 33,          #  Server Selection.
      # ns_t_atma = 34,         #  ATM Address
      # ns_t_naptr = 35,        #  Naming Authority PoinTeR
      # ns_t_kx = 36,           #  Key Exchange
      # ns_t_cert = 37,         #  Certification record
      # ns_t_a6 = 38,           #  IPv6 address (experimental)
      # ns_t_dname = 39,        #  Non-terminal DNAME
      # ns_t_sink = 40,         #  Kitchen sink (experimentatl)
      # ns_t_opt = 41,          #  EDNS0 option (meta-RR)
      # ns_t_apl = 42,          #  Address prefix list (RFC3123)
      # ns_t_ds = 43,           #  Delegation Signer
      # ns_t_sshfp = 44,        #  SSH Fingerprint
      # ns_t_ipseckey = 45,     #  IPSEC Key
      # ns_t_rrsig = 46,        #  RRset Signature
      # ns_t_nsec = 47,         #  Negative security
      # ns_t_dnskey = 48,       #  DNS Key
      # ns_t_dhcid = 49,        #  Dynamic host configuratin identifier
      # ns_t_nsec3 = 50,        #  Negative security type 3
      # ns_t_nsec3param = 51,   #  Negative security type 3 parameters
      # ns_t_hip = 55,          #  Host Identity Protocol
      # ns_t_spf = 99,          #  Sender Policy Framework
      # ns_t_tkey = 249,        #  Transaction key
      # ns_t_tsig = 250,        #  Transaction signature.
      # ns_t_ixfr = 251,        #  Incremental zone transfer.
      # ns_t_axfr = 252,        #  Transfer zone of authority.
      # ns_t_mailb = 253,       #  Transfer mailbox records.
      # ns_t_maila = 254,       #  Transfer mail agent records.
      # ns_t_any = 255,         #  Wildcard match.
      # ns_t_zxfr = 256,        #  BIND-specific, nonstandard.
      # ns_t_dlv = 32769,       #  DNSSEC look-aside validatation.
      # ns_t_max = 65536

    nsRr {.importc: "struct __ns_rr",
           header: headers, pure, bycopy, final.} = object
      name {.importc: "name".}: array[NS_MAXDNAME, char]
      rr_type {.importc: "type".}: uint16
      rr_class {.importc: "rr_class".}: uint16
      ttl {.importc: "ttl".}: uint16
      rdlength {.importc: "rdlength".}: uint16
      rdata {.importc: "rdata".}: pointer

    nsMsg {.importc: "struct __ns_msg",
            header: headers, pure, bycopy, final.} = object
      msg {.importc: "_msg".}: pointer
      eom {.importc: "_eom".}: pointer
      id {.importc: "_id".}: uint16
      flags {.importc: "_flags".}: uint16
      counts {.importc: "_counts".}: array[4, uint16]
      sections {.importc: "_sections".}: array[4, ptr byte]
      sect {.importc: "_sect".}: cint
      rrnum {.importc: "_rrnum".}: cint
      msgptr {.importc: "_msg_ptr".}: pointer

  proc resInit(state: PResolver): cint
       {.importc: "res_ninit", header: headers.}
  proc resMakeQuery(state: PResolver, op: cint, dname: cstring,
                    class: cint, typ: cint, data: pointer, datalen: cint,
                    newrr: pointer, buf: pointer, buflen: cint): cint
       {.importc: "res_nmkquery", header: headers.}
  proc nsInitParse(buf: pointer, buflen: cint, pmsg: ptr nsMsg): cint
       {.importc: "ns_initparse", header: headers.}
  proc nsMsgGetFlag(msg: nsMsg, flag: cint): cint
       {.importc: "ns_msg_getflag", header: headers.}
  proc nsParseRr(pmsg: ptr nsMsg, section: nsSect, index: cint,
                 rr: ptr nsRr): cint
       {.importc: "ns_parserr", header: headers.}
  template nsMsgCount(msg: nsMsg, section: nsSect): uint16 =
    msg.counts[cast[int](section)]
  template nsRrType(rr: nsRr): nsType =
    cast[nsType](rr.rr_type)

  var gResolver {.threadvar.}: PResolver # Global resolver state

  proc newResolver*(): PResolver =
    result = PResolver()
    discard resInit(result)

  proc getGlobalResolver*(): PResolver =
    ## Retrieves the global thread-local DNS resolver.
    if gResolver.isNil: gResolver = newResolver()
    result = gResolver

  proc asyncGetAddrInfo*(address: string, port: Port,
                    domain: Domain = nativesockets.AF_INET,
                    sockType: SockType = nativesockets.SOCK_STREAM,
                    protocol: Protocol = nativesockets.IPPROTO_TCP):
                    Future[ptr AsyncAddrInfo] {.async.} =
    var blob: pointer = nil
    var ai = 0
    var nsLastError = noError
    var request = newString(PACKETSZ)
    var response = newString(PACKETSZ)

    let r = getGlobalResolver()
    var qt = if domain == Domain.AF_INET6:
               cint(ns_t_aaaa)
             else:
               cint(ns_t_a)

    let reqLength = resMakeQuery(r, QUERY, address, C_IN, qt, nil, 0, nil,
                                 addr request[0], PACKETSZ)
    if reqLength <= 0:
      raise newException(ValueError, "Could not create DNS query!")

    let sock = createAsyncNativeSocket(nativesockets.AF_INET,
                                    nativesockets.SOCK_DGRAM,
                                    Protocol.IPPROTO_UDP)

    for i in 0..<3:
      if r.nsaddrList[i].sin_family == 0:
        break

      var recvAddr = Sockaddr_in()
      var recvALen = sizeof(Sockaddr_in).SockLen

      await sendTo(sock, addr request[0], reqLength,
                   cast[ptr SockAddr](addr r.nsaddrList[i]),
                   sizeof(Sockaddr_in).SockLen)
      var respLength = await recvFromInto(sock, addr response[0],
                                          PACKETSZ,
                                          cast[ptr SockAddr](addr recvAddr),
                                          cast[ptr SockLen](addr recvALen))
      if respLength <= 0:
        nsLastError = badDataError
        continue

      var msg = nsMsg()
      let pres = nsInitParse(cast[pointer](addr response[0]), cint(respLength),
                            addr msg)
      if pres != 0:
        nsLastError = parseError
        continue

      let gres = cast[nsRcode](nsMsgGetFlag(msg, cast[cint](ns_f_rcode)))

      if gres != ns_r_noerror:
        case gres
        of ns_r_formerr: nsLastError = formatError
        of ns_r_servfail: nsLastError = serverFailError
        of ns_r_nxdomain: nsLastError = nxDomainError
        of ns_r_notimpl: nsLastError = notimplError
        of ns_r_refused: nsLastError = refusedError
        else: nsLastError = unknownError
        continue

      var count = nsMsgCount(msg, ns_s_an).int
      if count <= 0:
        nsLastError = zeroError
        continue

      let blobsize = sizeof(AddrInfo) * count + sizeof(SockAddr) * count
      if isNil(blob):
        blob = alloc0(blobsize)

      let p0 = blob
      let p1 = cast[pointer](cast[uint](blob) +
                             cast[uint](sizeof(AddrInfo) * count))
      var addrArr = cast[ptr uncheckedArray[AddrInfo]](p0)
      var sockArr = cast[ptr uncheckedArray[SockAddr]](p1)

      for k in 0..<count:
        var record = nsRr()

        if nsParseRr(addr msg, ns_s_an, cint(k), addr record) != 0:
          nsLastError = recordError
          break

        let rrtype = nsRrType(record)
        if rrtype == ns_t_cname:
          # we don't need CNAME records
          discard
        elif rrtype == ns_t_a:
          addrArr[ai].ai_family = toInt(domain)
          addrArr[ai].ai_socktype = toInt(sockType)
          addrArr[ai].ai_protocol = toInt(protocol)
          addrArr[ai].ai_addrlen = sizeof(Sockaddr_in).SockLen
          addrArr[ai].ai_addr = addr sockArr[ai]

          when defined(freebsd) or defined(macosx) or defined(netbsd) or
               defined(openbsd):
            # BSD has one more field in sockaddr_inX.sin_len
            let psin_len = cast[ptr uint8](addr sockArr[ai])
            psin_len[] = cast[uint8](sizeof(Sockaddr_in))

          var addrp = cast[ptr Sockaddr_in](addr sockArr[ai])
          addrp.sin_family = TSa_Family(toInt(domain))
          addrp.sin_port = nativesockets.ntohs(cast[uint16](port))
          copyMem(addr addrp.sin_addr, record.rdata, 4)
          if k + 1 < count:
            addrArr[ai].ai_next = cast[ptr AddrInfo](addr addrarr[ai + 1])
          inc(ai)
        elif rrtype == ns_t_aaaa:
          addrArr[ai].ai_family = toInt(domain)
          addrArr[ai].ai_socktype = toInt(sockType)
          addrArr[ai].ai_protocol = toInt(protocol)
          addrArr[ai].ai_addrlen = sizeof(Sockaddr_in6).SockLen
          addrArr[ai].ai_addr = addr sockArr[ai]

          when defined(freebsd) or defined(macosx) or defined(netbsd) or
               defined(openbsd):
            # BSD has one more field in sockaddr_inX.sin_len
            let psin_len = cast[ptr uint8](addr sockArr[ai])
            psin_len[] = cast[uint8](sizeof(Sockaddr_in6))

          var addrp = cast[ptr Sockaddr_in6](addr sockArr[ai])
          addrp.sin6_family = TSa_Family(toInt(domain))
          addrp.sin6_port = nativesockets.ntohs(cast[uint16](port))
          copyMem(addr addrp.sin6_addr, record.rdata, 4 * 4)
          if k + 1 < count:
            addrArr[ai].ai_next = cast[ptr AddrInfo](addr addrarr[ai + 1])
          inc(ai)
        else:
          nsLastError = rtypeError
          break

      if ai > 0 and nsLastError == noError:
        result = cast[ptr AsyncAddrInfo](blob)
        break
      else:
        ai = 0
        zeroMem(blob, blobsize)
        continue

    case nsLastError
      of noError:
        discard
      of formatError:
        raise newException(ValueError, "Request format error!")
      of serverFailError:
        raise newException(ValueError, "DNS Server failure error!")
      of nxDomainError:
        raise newException(ValueError, "Non existent internet domain error!")
      of notimplError:
        raise newException(ValueError, "Not implemented error!")
      of refusedError:
        raise newException(ValueError, "Connection refused error!")
      of badDataError:
        raise newException(ValueError, "Empty response received!")
      of parseError:
        raise newException(ValueError, "Response parser error!")
      of recordError:
        raise newException(ValueError, "Record parser error!")
      of unknownError:
        raise newException(ValueError, "Unknown error!")
      of zeroError:
        raise newException(ValueError, "No address records for domain!")
      of rtypeError:
        raise newException(ValueError, "Wrong record type in response!")

proc free*(aip: ptr AsyncAddrInfo) =
  dealloc(cast[pointer](aip))

when isMainModule:
  echo "=== synchronous variant"
  var saiList = getAddrInfo("www.google.com", Port(80), domain = Domain.AF_INET)
  var it = saiList
  while not it.isNil:
    echo $it
    it = it.ai_next

  echo "=== asynchronous variant"

  var aiList = waitFor(asyncGetAddrInfo("www.google.com", Port(80), domain = Domain.AF_INET))
  var ait = aiList
  while not ait.isNil:
    echo $ait
    ait = cast[ptr AsyncAddrInfo](cast[ptr AddrInfo](ait).ai_next)

  if saiList == aiList:
    echo "RESULTS EQUAL"
  else:
    echo "RESULTS NOT EQUAL"

  free(aiList)
  freeaddrinfo(saiList)
