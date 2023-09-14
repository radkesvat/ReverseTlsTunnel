#
#                  Chronos IP Network
#              (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)

## This module implements various IP network utility procedures.

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

import std/strutils
import stew/endians2
import ./common
export common

type
  IpMask* = object
    case family*: AddressFamily
    of AddressFamily.None, AddressFamily.Unix:
      discard
    of AddressFamily.IPv4:
      mask4*: uint32
    of AddressFamily.IPv6:
      mask6*: array[2, uint64]

  IpNet* = object
    host*: TransportAddress
    mask*: IpMask

proc `==`*(m1, m2: IpMask): bool {.inline.} =
  ## Returns ``true`` if masks ``m1`` and ``m2`` are equal in IP family and
  ## by value.
  if m1.family == m2.family:
    case m1.family
    of AddressFamily.IPv4:
      (m1.mask4 == m2.mask4)
    of AddressFamily.IPv6:
      ((m1.mask6[0] == m2.mask6[0]) and (m1.mask6[1] == m2.mask6[1]))
    else:
      true
  else:
    false

proc init*(t: typedesc[IpMask], family: AddressFamily, prefix: int): IpMask =
  ## Initialize mask of IP family ``family`` from prefix length ``prefix``.
  case family
  of AddressFamily.IPv4:
    if prefix <= 0:
      IpMask(family: AddressFamily.IPv4, mask4: 0'u32)
    elif prefix < 32:
      let mask = 0xFFFF_FFFF'u32 shl (32 - prefix)
      IpMask(family: AddressFamily.IPv4, mask4: mask.toBE())
    else:
      IpMask(family: AddressFamily.IPv4, mask4: 0xFFFF_FFFF'u32)
  of AddressFamily.IPv6:
    if prefix <= 0:
      IpMask(family: AddressFamily.IPv6, mask6: [0'u64, 0'u64])
    elif prefix >= 128:
      IpMask(family: AddressFamily.IPv6,
             mask6: [0xFFFF_FFFF_FFFF_FFFF'u64, 0xFFFF_FFFF_FFFF_FFFF'u64])
    else:
      if prefix > 64:
        let mask = 0xFFFF_FFFF_FFFF_FFFF'u64 shl (128 - prefix)
        IpMask(family: AddressFamily.IPv6,
               mask6: [0xFFFF_FFFF_FFFF_FFFF'u64, mask.toBE()])
      elif prefix == 64:
        IpMask(family: AddressFamily.IPv6,
               mask6: [0xFFFF_FFFF_FFFF_FFFF'u64, 0'u64])
      else:
        let mask = 0xFFFF_FFFF_FFFF_FFFF'u64 shl (64 - prefix)
        IpMask(family: AddressFamily.IPv6, mask6: [mask.toBE(), 0'u64])
  else:
    IpMask(family: family)

proc init*(t: typedesc[IpMask], netmask: TransportAddress): IpMask =
  ## Initialize network mask using address ``netmask``.
  case netmask.family
  of AddressFamily.IPv4:
    IpMask(family: AddressFamily.IPv4,
           mask4: uint32.fromBytes(netmask.address_v4))
  of AddressFamily.IPv6:
    IpMask(family: AddressFamily.IPv6,
           mask6: [uint64.fromBytes(netmask.address_v6.toOpenArray(0, 7)),
                   uint64.fromBytes(netmask.address_v6.toOpenArray(8, 15))])
  else:
    IpMask(family: netmask.family)

proc initIp*(t: typedesc[IpMask], netmask: string): IpMask =
  ## Initialize network mask using IPv4 or IPv6 address in text representation
  ## ``netmask``.
  ##
  ## If ``netmask`` address string is invalid, result IpMask.family will be
  ## set to ``AddressFamily.None``.
  try:
    var ip = parseIpAddress(netmask)
    var tip = initTAddress(ip, Port(0))
    t.init(tip)
  except ValueError:
    IpMask(family: AddressFamily.None)

proc init*(t: typedesc[IpMask], netmask: string): IpMask =
  ## Initialize network mask using hexadecimal string representation
  ## ``netmask``.
  ##
  ## If ``netmask`` mask is invalid, result IpMask.family will be set to
  ## ``AddressFamily.None``.
  const
    hexNumbers = {'0'..'9'}
    hexCapitals = {'A'..'F'}
    hexLowers = {'a'..'f'}
  let length = len(netmask)
  if length == 8 or length == (2 + 8):
    ## IPv4 mask
    var offset = 0
    if length == 2 + 8:
      offset = 2
    var res = IpMask(family: AddressFamily.IPv4)
    var r, v: uint32
    for i in 0 ..< 8:
      if netmask[offset + i] in hexNumbers:
        v = uint32(ord(netmask[offset + i]) - ord('0'))
      elif netmask[offset + i] in hexCapitals:
        v = uint32(ord(netmask[offset + i]) - ord('A') + 10)
      elif netmask[offset + i] in hexLowers:
        v = uint32(ord(netmask[offset + i]) - ord('a') + 10)
      else:
        return
      r = (r shl 4) or v
    res.mask4 = r.toBE()
    res
  elif length == 32 or length == (2 + 32):
    ## IPv6 mask
    var offset = 0
    if length == 2 + 32:
      offset = 2
    var res = IpMask(family: AddressFamily.IPv6)
    for i in 0..1:
      var r, v: uint64
      for i in 0 ..< 16:
        if netmask[offset + i] in hexNumbers:
          v = uint64(ord(netmask[offset + i]) - ord('0'))
        elif netmask[offset + i] in hexCapitals:
          v = uint64(ord(netmask[offset + i]) - ord('A') + 10)
        elif netmask[offset + i] in hexLowers:
          v = uint64(ord(netmask[offset + i]) - ord('a') + 10)
        else:
          return
        r = (r shl 4) or v
      offset += 16
      res.mask6[i] = r.toBE()
    res
  else:
    IpMask(family: AddressFamily.None)

proc toIPv6*(address: TransportAddress): TransportAddress =
  ## Map IPv4 ``address`` to IPv6 address.
  ##
  ## If ``address`` is IPv4 address then it will be mapped as:
  ## <80 bits of zeros> + <16 bits of ones> + <32-bit IPv4 address>.
  ##
  ## If ``address`` is IPv6 address it will be returned without any changes.
  case address.family
  of AddressFamily.IPv4:
    var address6: array[16, uint8]
    address6[10] = 0xFF'u8
    address6[11] = 0xFF'u8
    let ip4 = uint32.fromBytes(address.address_v4)
    address6[12 .. 15] = ip4.toBytes()
    TransportAddress(family: AddressFamily.IPv6, port: address.port,
                     address_v6: address6)
  of AddressFamily.IPv6:
    address
  else:
    raiseAssert "Invalid address family type"

proc isV4Mapped*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is (IPv4 to IPv6) mapped address, e.g.
  ## 0000:0000:0000:0000:0000:FFFF:xxxx:xxxx
  ##
  ## Procedure returns ``false`` if ``address`` family is IPv4.
  case address.family
  of AddressFamily.IPv6:
    let data0 = uint64.fromBytes(address.address_v6.toOpenArray(0, 7))
    let data1 = uint16.fromBytes(address.address_v6.toOpenArray(8, 9))
    let data2 = uint16.fromBytes(address.address_v6.toOpenArray(10, 11))
    (data0 == 0x00'u64) and (data1 == 0x00'u16) and (data2 == 0xFFFF'u16)
  else:
    false

proc toIPv4*(address: TransportAddress): TransportAddress =
  ## Get IPv4 from (IPv4 to IPv6) mapped address.
  ##
  ## If ``address`` is IPv4 address it will be returned without any changes.
  ##
  ## If ``address`` is not IPv4 to IPv6 mapped address, then result family will
  ## be set to AddressFamily.None.
  case address.family
  of AddressFamily.IPv4:
    address
  of AddressFamily.IPv6:
    if isV4Mapped(address):
      let data = uint32.fromBytes(address.address_v6.toOpenArray(12, 15))
      TransportAddress(family: AddressFamily.IPv4, port: address.port,
                       address_v4: data.toBytes())
    else:
      TransportAddress(family: AddressFamily.None)
  else:
    TransportAddress(family: AddressFamily.None)

proc mask*(a: TransportAddress, m: IpMask): TransportAddress =
  ## Apply IP mask ``m`` to address ``a`` and return result address.
  ##
  ## If ``a`` family is IPv4 and ``m`` family is IPv6, masking is still
  ## possible when ``m`` has ``FFFF:FFFF:FFFF:FFFF:FFFF:FFFF`` prefix. Returned
  ## value will be IPv4 address.
  ##
  ## If ``a`` family is IPv6 and ``m`` family is IPv4, masking is still
  ## possible when ``a`` holds (IPv4 to IPv6) mapped address. Returned value
  ## will be IPv6 address.
  ##
  ## If ``a`` family is IPv4 and ``m`` family is IPv4, returned value will be
  ## IPv4 address.
  ##
  ## If ``a`` family is IPv6 and ``m`` family is IPv6, returned value will be
  ## IPv6 address.
  ##
  ## In all other cases returned address will have ``AddressFamily.None``.
  if (a.family == AddressFamily.IPv4) and (m.family == AddressFamily.IPv6):
    if (m.mask6[0] == 0xFFFF_FFFF_FFFF_FFFF'u64) and
       (m.mask6[1] and 0xFFFF_FFFF'u64) == 0xFFFF_FFFF'u64:
      let
        mask = uint32((m.mask6[1] shr 32) and 0xFFFF_FFFF'u64)
        data = uint32.fromBytes(a.address_v4)
      TransportAddress(family: AddressFamily.IPv4, port: a.port,
                       address_v4: (data and mask).toBytes())
    else:
      TransportAddress(family: AddressFamily.None)
  elif (a.family == AddressFamily.IPv6) and (m.family == AddressFamily.IPv4):
    var ip = a.toIPv4()
    if ip.family != AddressFamily.IPv4:
      return TransportAddress(family: AddressFamily.None)
    let data = uint32.fromBytes(ip.address_v4)
    ip.address_v4[0 .. 3] = (data and m.mask4).toBytes()
    var res = ip.toIPv6()
    res.port = a.port
    res
  elif a.family == AddressFamily.IPv4 and m.family == AddressFamily.IPv4:
    let data = uint32.fromBytes(a.address_v4)
    TransportAddress(family: AddressFamily.IPv4, port: a.port,
                     address_v4: (data and m.mask4).toBytes())
  elif a.family == AddressFamily.IPv6 and m.family == AddressFamily.IPv6:
    var address6: array[16, uint8]
    let
      data0 = uint64.fromBytes(a.address_v6.toOpenArray(0, 7))
      data1 = uint64.fromBytes(a.address_v6.toOpenArray(8, 15))
    address6[0 .. 7] = (data0 and m.mask6[0]).toBytes()
    address6[8 .. 15] = (data1 and m.mask6[1]).toBytes()
    TransportAddress(family: AddressFamily.IPv6, port: a.port,
                     address_v6: address6)
  else:
    TransportAddress(family: AddressFamily.None)

proc prefix*(mask: IpMask): int =
  ## Returns number of bits set `1` in IP mask ``mask``.
  ##
  ## Procedure returns ``-1`` if mask is not canonical, e.g. has holes with
  ## ``0`` bits between ``1`` bits.
  case mask.family
  of AddressFamily.IPv4:
    var
      res = 0
      n = mask.mask4.fromBE()
    while n != 0:
      if (n and 0x8000_0000'u32) == 0'u32: return -1
      n = n shl 1
      inc(res)
    res
  of AddressFamily.IPv6:
    let mask6 = [mask.mask6[0].fromBE(), mask.mask6[1].fromBE()]
    var res = 0
    if mask6[0] == 0xFFFF_FFFF_FFFF_FFFF'u64:
      res += 64
      if mask6[1] == 0xFFFF_FFFF_FFFF_FFFF'u64:
        res + 64
      else:
        var n = mask6[1]
        while n != 0:
          if (n and 0x8000_0000_0000_0000'u64) == 0'u64: return -1
          n = n shl 1
          inc(res)
        res
    else:
      var n = mask6[0]
      while n != 0:
        if (n and 0x8000_0000_0000_0000'u64) == 0'u64: return -1
        n = n shl 1
        inc(res)
      if mask6[1] != 0x00'u64: return -1
      res
  else:
    -1

proc subnetMask*(mask: IpMask): TransportAddress =
  ## Returns TransportAddress representation of IP mask ``mask``.
  case mask.family
  of AddressFamily.IPv4:
    TransportAddress(family: AddressFamily.IPv4,
                     address_v4: mask.mask4.toBytes())
  of AddressFamily.IPv6:
    var address6: array[16, uint8]
    address6[0 .. 7] = mask.mask6[0].toBytes()
    address6[8 .. 15] = mask.mask6[1].toBytes()
    TransportAddress(family: AddressFamily.IPv6, address_v6: address6)
  else:
    TransportAddress(family: mask.family)

proc `$`*(mask: IpMask, include0x = false): string =
  ## Returns hexadecimal string representation of IP mask ``mask``.
  case mask.family
  of AddressFamily.IPv4:
    var res = if include0x: "0x" else: ""
    var n = 32
    var m = mask.mask4.fromBE()
    while n > 0:
      n -= 4
      var c = int((m shr n) and 0x0F)
      if c < 10:
        res.add(chr(ord('0') + c))
      else:
        res.add(chr(ord('A') + (c - 10)))
    res
  of AddressFamily.IPv6:
    let mask6 = [mask.mask6[0].fromBE(), mask.mask6[1].fromBE()]
    var res = if include0x: "0x" else: ""
    for i in 0 .. 1:
      var n = 64
      var m = mask6[i]
      while n > 0:
        n -= 4
        var c = int((m shr n) and 0x0F)
        if c < 10:
          res.add(chr(ord('0') + c))
        else:
          res.add(chr(ord('A') + (c - 10)))
    res
  else:
    "Unknown mask family: " & $mask.family

proc ip*(mask: IpMask): string {.raises: [Defect, ValueError].} =
  ## Returns IP address text representation of IP mask ``mask``.
  case mask.family
  of AddressFamily.IPv4:
    var address4: array[4, uint8]
    copyMem(addr address4[0], unsafeAddr mask.mask4, sizeof(uint32))
    $IpAddress(family: IpAddressFamily.IPv4, address_v4: address4)
  of AddressFamily.Ipv6:
    var address6: array[16, uint8]
    copyMem(addr address6[0], unsafeAddr mask.mask6[0], 16)
    $IpAddress(family: IpAddressFamily.IPv6, address_v6: address6)
  else:
    raise newException(ValueError, "Invalid mask family type")

proc init*(t: typedesc[IpNet], host: TransportAddress,
           prefix: int): IpNet {.inline.} =
  ## Initialize IP Network using host address ``host`` and prefix length
  ## ``prefix``.
  IpNet(mask: IpMask.init(host.family, prefix), host: host)

proc init*(t: typedesc[IpNet], host, mask: TransportAddress): IpNet {.inline.} =
  ## Initialize IP Network using host address ``host`` and network mask
  ## address ``mask``.
  ##
  ## Note that ``host`` and ``mask`` must be from the same IP family.
  doAssert(host.family == mask.family)
  IpNet(mask: IpMask.init(mask), host: host)

proc init*(t: typedesc[IpNet], host: TransportAddress,
           mask: IpMask): IpNet {.inline.} =
  ## Initialize IP Network using host address ``host`` and network mask
  ## ``mask``.
  IpNet(mask: mask, host: host)

proc init*(t: typedesc[IpNet], network: string): IpNet {.
    raises: [Defect, TransportAddressError].} =
  ## Initialize IP Network from string representation in format
  ## <address>/<prefix length> or <address>/<netmask address>.
  var parts = network.rsplit("/", maxsplit = 1)
  var host, mhost: TransportAddress
  var ipaddr: IpAddress
  var mask: IpMask
  var prefix: int
  try:
    ipaddr = parseIpAddress(parts[0])
    if ipaddr.family == IpAddressFamily.IPv4:
      host = TransportAddress(family: AddressFamily.IPv4)
      host.address_v4 = ipaddr.address_v4
      prefix = 32
    elif ipaddr.family == IpAddressFamily.IPv6:
      host = TransportAddress(family: AddressFamily.IPv6)
      host.address_v6 = ipaddr.address_v6
      prefix = 128
    if len(parts) > 1:
      try:
        prefix = parseInt(parts[1])
      except:
        prefix = -1
      if prefix == -1:
        ipaddr = parseIpAddress(parts[1])
        if ipaddr.family == IpAddressFamily.IPv4:
          mhost = TransportAddress(family: AddressFamily.IPv4)
          mhost.address_v4 = ipaddr.address_v4
        elif ipaddr.family == IpAddressFamily.IPv6:
          mhost = TransportAddress(family: AddressFamily.IPv6)
          mhost.address_v6 = ipaddr.address_v6
        mask = IpMask.init(mhost)
        if mask.family != host.family:
          raise newException(TransportAddressError,
                             "Incorrect network address!")
      else:
        if (ipaddr.family == IpAddressFamily.IPv4 and
           (prefix < 0 or prefix > 32)) or
           (ipaddr.family == IpAddressFamily.IPv6 and
           (prefix < 0 or prefix > 128)) or
           (prefix == 0 and parts[1][0] notin {'0'..'9'}): # /-0 case
          raise newException(TransportAddressError,
                             "Incorrect network address!")
    if prefix == -1:
      result = t.init(host, mask)
    else:
      result = t.init(host, prefix)
  except:
    raise newException(TransportAddressError, "Incorrect network address!")

proc `==`*(n1, n2: IpNet): bool {.inline.} =
  ## Returns ``true`` if networks ``n1`` and ``n2`` are equal in IP family and
  ## by value.
  if n1.host.family != n2.host.family:
    return false
  case n1.host.family
  of AddressFamily.IPv4:
    (n1.host.address_v4 == n2.host.address_v4) and (n1.mask == n2.mask)
  of AddressFamily.IPv6:
    (n1.host.address_v6 == n2.host.address_v6) and (n1.mask == n2.mask)
  else:
    false

proc contains*(net: IpNet, address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` belongs to IP Network ``net``
  if net.host.family != address.family:
    return false
  var host1 = mask(address, net.mask)
  var host2 = mask(net.host, net.mask)
  host2.port = host1.port
  host1 == host2

proc broadcast*(net: IpNet): TransportAddress =
  ## Returns broadcast address for IP Network ``net``.
  case net.host.family
  of AddressFamily.IPv4:
    let
      host = uint32.fromBytes(net.host.address_v4)
      mask = net.mask.mask4
    TransportAddress(family: AddressFamily.IPv4,
                     address_v4: (host or (not(mask))).toBytes())
  of AddressFamily.IPv6:
    var address6: array[16, uint8]
    let
      host0 = uint64.fromBytes(net.host.address_v6.toOpenArray(0, 7))
      host1 = uint64.fromBytes(net.host.address_v6.toOpenArray(8, 15))
      data0 = net.mask.mask6[0]
      data1 = net.mask.mask6[1]
    address6[0 .. 7] = (host0 or (not(data0))).toBytes()
    address6[8 .. 15] = (host1 or (not(data1))).toBytes()
    TransportAddress(family: AddressFamily.IPv6, address_v6: address6)
  else:
    TransportAddress(family: AddressFamily.None)

proc subnetMask*(net: IpNet): TransportAddress =
  ## Returns netmask address for IP Network ``net``.
  subnetMask(net.mask)

proc network*(net: IpNet): TransportAddress {.inline.} =
  ## Returns network address (host address masked with network mask) for
  ## IP Network ``net``.
  mask(net.host, net.mask)

proc `and`*(address1, address2: TransportAddress): TransportAddress =
  ## Bitwise ``and`` operation for ``address1 and address2``.
  ##
  ## Note only IPv4 and IPv6 addresses are supported. ``address1`` and
  ## ``address2`` must be in equal IP family
  doAssert(address1.family == address2.family)
  case address1.family
  of AddressFamily.IPv4:
    let
      data1 = uint32.fromBytes(address1.address_v4)
      data2 = uint32.fromBytes(address2.address_v4)
    TransportAddress(family: AddressFamily.IPv4,
                     address_v4: (data1 and data2).toBytes())
  of AddressFamily.IPv6:
    var address6: array[16, uint8]
    let
      data1 = uint64.fromBytes(address1.address_v6.toOpenArray(0, 7))
      data2 = uint64.fromBytes(address1.address_v6.toOpenArray(8, 15))
      data3 = uint64.fromBytes(address2.address_v6.toOpenArray(0, 7))
      data4 = uint64.fromBytes(address2.address_v6.toOpenArray(8, 15))
    address6[0 .. 7] = (data1 and data3).toBytes()
    address6[8 .. 15] = (data2 and data4).toBytes()
    TransportAddress(family: AddressFamily.IPv6, address_v6: address6)
  else:
    raiseAssert "Invalid address family type"

proc `or`*(address1, address2: TransportAddress): TransportAddress =
  ## Bitwise ``or`` operation for ``address1 or address2``.
  ##
  ## Note only IPv4 and IPv6 addresses are supported. ``address1`` and
  ## ``address2`` must be in equal IP family
  doAssert(address1.family == address2.family)
  case address1.family
  of AddressFamily.IPv4:
    let
      data1 = uint32.fromBytes(address1.address_v4)
      data2 = uint32.fromBytes(address2.address_v4)
    TransportAddress(family: AddressFamily.IPv4,
                     address_v4: (data1 or data2).toBytes())
  of AddressFamily.IPv6:
    var address6: array[16, uint8]
    let
      data1 = uint64.fromBytes(address1.address_v6.toOpenArray(0, 7))
      data2 = uint64.fromBytes(address1.address_v6.toOpenArray(8, 15))
      data3 = uint64.fromBytes(address2.address_v6.toOpenArray(0, 7))
      data4 = uint64.fromBytes(address2.address_v6.toOpenArray(8, 15))
    address6[0 .. 7] = (data1 or data3).toBytes()
    address6[8 .. 15] = (data2 or data4).toBytes()
    TransportAddress(family: AddressFamily.IPv6, address_v6: address6)
  else:
    raiseAssert "Invalid address family type"

proc `not`*(address: TransportAddress): TransportAddress =
  ## Bitwise ``not`` operation for ``address``.
  case address.family
  of AddressFamily.IPv4:
    let data = not(uint32.fromBytes(address.address_v4))
    TransportAddress(family: AddressFamily.IPv4, address_v4: data.toBytes())
  of AddressFamily.IPv6:
    var address6: array[16, uint8]
    let
      data1 = not(uint64.fromBytes(address.address_v6.toOpenArray(0, 7)))
      data2 = not(uint64.fromBytes(address.address_v6.toOpenArray(8, 15)))
    address6[0 .. 7] = data1.toBytes()
    address6[8 .. 15] = data2.toBytes()
    TransportAddress(family: AddressFamily.IPv6, address_v6: address6)
  else:
    address

proc `+`*(address: TransportAddress, v: int|uint): TransportAddress =
  ## Add to IPv4/IPv6 transport ``address`` integer ``v``.
  if v == 0: return address
  case address.family
  of AddressFamily.IPv4:
    let
      av = uint32.fromBytesBE(address.address_v4)
      address4 =
        when v is int:
          if v <= 0:
            # Case when v == 0 is already covered.
            let v32 = uint32(uint64(not(v) + 1) and 0xFFFF_FFFF'u64)
            (av - v32).toBytesBE()
          else:
            let v32 = uint32(uint64(v) and 0xFFFF_FFFF'u64)
            (av + v32).toBytesBE()
        else:
          let v32 = uint32(uint64(v) and 0xFFFF_FFFF'u64)
          (av + v32).toBytesBE()
    TransportAddress(family: AddressFamily.IPv4, port: address.port,
                     address_v4: address4)
  of AddressFamily.IPv6:
    let a2 = uint64.fromBytesBE(address.address_v6.toOpenArray(8, 15))
    var
      a1 = uint64.fromBytesBE(address.address_v6.toOpenArray(0, 7))
      address6: array[16, uint8]
    when v is int:
      if v <= 0:
        # Case when v == 0 is already covered
        let a3 = a2 - uint64(not(int64(v)) + 1)
        if a3 > a2: a1 = a1 - 1'u64
        address6[0 .. 7] = a1.toBytesBE()
        address6[8 .. 15] = a3.toBytesBE()
      else:
        let a3 = a2 + uint64(v)
        if a3 < a2: a1 = a1 + 1'u64
        address6[0 .. 7] = a1.toBytesBE()
        address6[8 .. 15] = a3.toBytesBE()
    else:
      # v is unsigned so it is always bigger than zero.
      let a3 = a2 + uint64(v)
      if a3 < a2: a1 = a1 + 1'u64
      address6[0 .. 7] = a1.toBytesBE()
      address6[8 .. 15] = a3.toBytesBE()

    TransportAddress(family: AddressFamily.IPv6, port: address.port,
                     address_v6: address6)
  else:
    address

proc `-`*(address: TransportAddress, v: int|uint): TransportAddress =
  ## Sub from IPv4/IPv6 transport ``address`` integer ``v``.
  if v == 0: return address
  case address.family
  of AddressFamily.IPv4:
    let
      av = uint32.fromBytesBE(address.address_v4)
      address4 =
        when v is int:
          if v <= 0:
            # Case when v == 0 is already covered.
            let v32 = uint32(uint64(not(v) + 1) and 0xFFFF_FFFF'u64)
            (av + v32).toBytesBE()
          else:
            let v32 = uint32(uint64(v) and 0xFFFF_FFFF'u64)
            (av - v32).toBytesBE()
        else:
          let v32 = uint32(uint64(v) and 0xFFFF_FFFF'u64)
          (av - v32).toBytesBE()
    TransportAddress(family: AddressFamily.IPv4, port: address.port,
                     address_v4: address4)
  of AddressFamily.IPv6:
    let a2 = uint64.fromBytesBE(address.address_v6.toOpenArray(8, 15))
    var
      a1 = uint64.fromBytesBE(address.address_v6.toOpenArray(0, 7))
      address6: array[16, uint8]
    when v is int:
      if v <= 0:
        # Case when v == 0 is already covered
        let a3 = a2 + uint64(not(int64(v)) + 1)
        if a3 < a2: a1 = a1 + 1'u64
        address6[0 .. 7] = a1.toBytesBE()
        address6[8 .. 15] = a3.toBytesBE()
      else:
        let a3 = a2 - uint64(v)
        if a3 > a2: a1 = a1 - 1'u64
        address6[0 .. 7] = a1.toBytesBE()
        address6[8 .. 15] = a3.toBytesBE()
    else:
      # v is unsigned so it is always bigger than zero.
      let a3 = a2 - uint64(v)
      if a3 > a2: a1 = a1 - 1'u64
      address6[0 .. 7] = a1.toBytesBE()
      address6[8 .. 15] = a3.toBytesBE()

    TransportAddress(family: AddressFamily.IPv6, port: address.port,
                     address_v6: address6)
  else:
    address

proc inc*(address: var TransportAddress, v: int = 1) =
  ## Increment IPv4/IPv6 transport ``address`` by integer ``v``.
  address = address + v

proc dec*(address: var TransportAddress, v: int = 1) =
  ## Decrement IPv4/IPv6 transport ``address`` by integer ``v``.
  address = address - v

proc `$`*(net: IpNet): string =
  ## Return string representation of IP network in format:
  ## <IPv4 or IPv6 address>/<prefix length>.
  var res =
    case net.host.family
    of AddressFamily.IPv4:
      $IpAddress(family: IpAddressFamily.IPv4, address_v4: net.host.address_v4)
    of AddressFamily.IPv6:
      $IpAddress(family: IpAddressFamily.IPv6, address_v6: net.host.address_v6)
    else:
      return "Invalid network address family"

  res.add("/")
  let prefix = net.mask.prefix()
  if prefix == -1:
    try:
      res.add(net.mask.ip())
    except ValueError:
      return "Invalid network mask address"
  else:
    res.add($prefix)
  res

template a4(): untyped {.dirty.} =
  address.address_v4
template a6(): untyped {.dirty.} =
  address.address_v6

proc isNone*(address: TransportAddress): bool {.inline.} =
  ## Returns ``true`` if ``address`` is not initialized yet, e.g. its ``family``
  ## field is not set or equal to ``AddressFamily.None``.
  address.family == AddressFamily.None

proc isZero*(address: TransportAddress): bool {.inline.} =
  ## Returns ``true`` if ``address`` is full of zeros, but its ``family`` is
  ## not ``AddressFamily.None``.
  case address.family
  of AddressFamily.IPv4:
    uint32.fromBytes(a4()) == 0'u32
  of AddressFamily.IPv6:
    (uint64.fromBytes(a6.toOpenArray(0, 7)) == 0'u64) and
    (uint64.fromBytes(a6.toOpenArray(8, 15)) == 0'u64)
  of AddressFamily.Unix:
    len($cast[cstring](unsafeAddr address.address_un[0])) == 0
  else:
    false

proc isUnspecified*(address: TransportAddress): bool {.inline.} =
  ## Alias for isZero().
  isZero(address)

proc isMulticast*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is a multicast address.
  ##
  ## ``IPv4``: 224.0.0.0 - 239.255.255.255
  ##
  ## ``IPv6``: FF00:: - FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
  case address.family
  of AddressFamily.IPv4:
    (a4[0] and 0xF0'u8) == 0xE0'u8
  of AddressFamily.IPv6:
    a6[0] == 0xFF'u8
  else:
    false

proc isUnicast*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is unicast, as defined by [IETF RFC 4291].
  ## Any address that is not a IPv6 multicast address `FF00::/8` is unicast.
  case address.family
  of AddressFamily.IPv4:
    not(isZero(address) and not isMulticast(address))
  of AddressFamily.IPv6:
    not(isMulticast(address))
  else:
    false

proc isInterfaceLocalMulticast*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is interface local multicast address.
  ##
  ## ``IPv4``:  N/A (always returns ``false``)
  case address.family
  of AddressFamily.IPv4:
    false
  of AddressFamily.IPv6:
    (a6[0] == 0xFF'u8) and ((a6[1] and 0x0F'u8) == 0x01'u8)
  else:
    false

proc isLinkLocalMulticast*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is link local multicast address.
  ##
  ## ``IPv4``: 224.0.0.0 - 224.0.0.255
  case address.family
  of AddressFamily.IPv4:
    (a4[0] == 224'u8) and (a4[1] == 0'u8) and (a4[2] == 0'u8)
  of AddressFamily.IPv6:
    (a6[0] == 0xFF'u8) and ((a6[1] and 0x0F'u8) == 0x02'u8)
  else:
    false

proc isUniqueLocal*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is a unique local IPv6 unicast address.
  ##
  ## ``IPv6``: FC00::/7
  case address.family
  of AddressFamily.IPv4:
    false
  of AddressFamily.IPv6:
    (a6[0] and 0xFE'u8) == 0xFC'u8
  else:
    false

proc isUnicastLinkLocal*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is a IPv6 unicast address with link-local
  ## scope.
  ##
  ## NOTE: While [RFC 4291 section 2.5.3] mentions about the [loopback address]
  ## `::1` that "it is treated as having Link-Local scope", this does not mean
  ## that the loopback address actually has link-local scope and procedure
  ## will return `false` on it.
  ##
  ## ``IPv6``: FE80::/10
  case address.family
  of AddressFamily.IPv4:
    false
  of AddressFamily.IPv6:
    ((a6[0] and 0xFF'u8) == 0xFE'u8) and ((a6[1] and 0xC0'u8) == 0x80'u8)
  else:
    false

proc isLoopback*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is loopback address.
  ##
  ## ``IPv4``: 127.0.0.0 - 127.255.255.255
  ##
  ## ``IPv6``: ::1
  case address.family
  of AddressFamily.IPv4:
    a4[0] == 127'u8
  of AddressFamily.IPv6:
    (uint64.fromBytes(a6.toOpenArray(0, 7)) == 0x00'u64) and
    (uint64.fromBytesBE(a6.toOpenArray(8, 15)) == 0x01'u64)
  else:
    false

proc isAnyLocal*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is a wildcard address.
  ##
  ## ``IPv4``: 0.0.0.0
  ##
  ## ``IPv6``: ::
  case address.family
  of AddressFamily.IPv4:
    uint32.fromBytes(a4) == 0'u32
  of AddressFamily.IPv6:
    (uint64.fromBytes(a6.toOpenArray(0, 7)) == 0x00'u64) and
    (uint64.fromBytes(a6.toOpenArray(8, 15)) == 0x00'u64)
  else:
    false

proc isLinkLocal*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is link local address.
  ##
  ## ``IPv4``: 169.254.0.0 - 169.254.255.255
  ##
  ## ``IPv6``: FE80:: - FEBF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
  case address.family
  of AddressFamily.IPv4:
    (a4[0] == 169'u8) and (a4[1] == 254'u8)
  of AddressFamily.IPv6:
    (a6[0] == 0xFE'u8) and ((a6[1] and 0xC0'u8) == 0x80'u8)
  else:
    false

proc isLinkLocalUnicast*(address: TransportAddress): bool {.inline.} =
  isLinkLocal(address)

proc isSiteLocal*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is site local address.
  ##
  ## ``IPv4``: 10.0.0.0 - 10.255.255.255, 172.16.0.0 - 172.31.255.255,
  ##           192.168.0.0 - 192.168.255.255
  ##
  ## ``IPv6``: FEC0:: - FEFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
  case address.family
  of AddressFamily.IPv4:
    (a4[0] == 10'u8) or ((a4[0] == 172'u8) and ((a4[1] and 0xF0) == 16)) or
    ((a4[0] == 192'u8) and ((a4[1] == 168'u8)))
  of AddressFamily.IPv6:
    (a6[0] == 0xFE'u8) and ((a6[1] and 0xC0'u8) == 0xC0'u8)
  else:
    false

proc isPrivate*(address: TransportAddress): bool =
  ## Alias for ``isSiteLocal()``.
  isSiteLocal(address)

proc isGlobalMulticast*(address: TransportAddress): bool =
  ## Returns ``true`` if the multicast address has global scope.
  ##
  ## ``IPv4``: 224.0.1.0 - 238.255.255.255
  ##
  ## ``IPv6``: FF0E:: - FFFE:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF
  case address.family
  of AddressFamily.IPv4:
    (a4[0] >= 224'u8) and (a4[0] <= 238'u8) and
    not((a4[0] == 224'u8) and (a4[1] == 0'u8) and (a4[2] == 0'u8))
  of AddressFamily.IPv6:
    (a6[0] == 0xFF'u8) and ((a6[1] and 0x0F'u8) == 0x0E'u8)
  else:
    false

proc isShared*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is part of the Shared Address Space
  ## defined in [IETF RFC 6598]
  ##
  ## ``IPv4``: 100.64.0.0/10
  case address.family
  of AddressFamily.IPv4:
    (a4[0] == 100'u8) and ((a4[1] and 0xC0'u8) == 0x40'u8)
  of AddressFamily.IPv6:
    false
  else:
    false

proc isBroadcast*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is a broadcast address.
  ##
  ## ``IPv4``: 255.255.255.255
  case address.family
  of AddressFamily.IPv4:
    uint32.fromBytes(a4) == 0xFFFF_FFFF'u32
  of AddressFamily.IPv6:
    false
  else:
    false

proc isBenchmarking*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is part of the `198.18.0.0/15` range,
  ## which is reserved for network devices benchmarking. This range is defined
  ## in [IETF RFC 2544] as `198.18.0.0` through `198.19.255.255` but
  ## [errata 423] corrects it to `198.18.0.0/15`.
  ##
  ## ``IPv4``: 198.18.0.0/15
  ##
  ## ``IPv6``: 2001:2::/48
  case address.family
  of AddressFamily.IPv4:
    (a4[0] == 198'u8) and ((a4[1] and 0xFE'u8) == 18'u8)
  of AddressFamily.IPv6:
    (uint16.fromBytesBE(a6.toOpenArray(0, 1)) == 0x2001'u16) and
    (uint16.fromBytesBE(a6.toOpenArray(2, 3)) == 0x02'u16) and
    (uint16.fromBytes(a6.toOpenArray(4, 5)) == 0x00'u16)
  else:
    false

proc isDocumentation*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is in a range designated for documentation.
  ##
  ## ``IPv4``: 192.0.2.0/24 (TEST-NET-1)
  ##           198.51.100.0/24 (TEST-NET-2)
  ##           203.0.113.0/24 (TEST-NET-3)
  ##
  ## ``IPv6``: 2001:DB8::/32
  case address.family
  of AddressFamily.IPv4:
    ((a4[0] == 192'u8) and (a4[1] == 0'u8) and (a4[2] == 2'u8)) or
    ((a4[0] == 198'u8) and (a4[1] == 51'u8) and (a4[2] == 100'u8)) or
    ((a4[0] == 203'u8) and (a4[1] == 0'u8) and (a4[2] == 113'u8))
  of AddressFamily.IPv6:
    (uint16.fromBytesBE(a6.toOpenArray(0, 1)) == 0x2001'u16) and
    (uint16.fromBytesBE(a6.toOpenArray(2, 3)) == 0xDB8'u16)
  else:
    false

proc isReserved*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` is reserved by IANA for future use.
  ## [IETF RFC 1112] defines the block of reserved addresses as `240.0.0.0/4`.
  ##
  ## NOTE: As IANA assigns new addresses, this procedure will be updated. This
  ## may result in non-reserved addresses being treated as reserved in code
  ## that relies on an outdated version of this procedure.
  ##
  ## ``IPv4``: 240.0.0.0/4
  case address.family
  of AddressFamily.IPv4:
    (a4[0] and 240'u8) == 240'u8
  of AddressFamily.IPv6:
    false
  else:
    false

proc isGlobal*(address: TransportAddress): bool =
  ## Returns ``true`` if ``address`` appears to be globally reachable as
  ## specified by the [IANA IPv4 Special-Purpose Address Registry].
  case address.family
  of AddressFamily.IPv4:
    not(
      (a4[0] == 0) or
      address.isPrivate() or
      address.isShared() or
      address.isLoopback() or
      address.isLinkLocal() or
      # address reserver for future protocols `192.0.0.0/24`.
      ((a4[0] == 192'u8) and (a4[1] == 0'u8) and (a4[2] == 0'u8)) or
      address.isDocumentation() or
      address.isBenchmarking() or
      address.isReserved() or
      address.isBroadcast()
    )
  of AddressFamily.IPv6:
    not(
      address.isUnspecified() or
      address.isLoopback() or
      (
        # IPv4-Mapped `::FFFF:0:0/96`
        (uint64.fromBytes(a6.toOpenArray(0, 7)) == 0x00'u64) and
        (uint16.fromBytes(a6.toOpenArray(8, 9)) == 0x00'u16) and
        (uint16.fromBytes(a6.toOpenArray(10, 11)) == 0xFFFF'u16)
      ) or
      (
        # IPv4-IPv6 Translation `64:FF9B:1::/48`
        (uint16.fromBytesBE(a6.toOpenArray(0, 1)) == 0x64'u16) and
        (uint16.fromBytesBE(a6.toOpenArray(2, 3)) == 0xFF9B'u16) and
        (uint16.fromBytesBE(a6.toOpenArray(4, 5)) == 0x01'u16)
      ) or
      (
        # Discard-Only Address Block `100::/64`
        (uint16.fromBytesBE(a6.toOpenArray(0, 1)) == 0x100'u16) and
        (uint32.fromBytes(a6.toOpenArray(2, 5)) == 0x00'u32) and
        (uint16.fromBytes(a6.toOpenArray(6, 7)) == 0x00'u16)
      ) or
      (
        # IETF Protocol Assignments `2001::/23`
        (uint16.fromBytesBE(a6.toOpenArray(0, 1)) == 0x2001'u16) and
        (uint16.fromBytesBE(a6.toOpenArray(2, 3)) < 0x200'u16) and
        not(
          (
            # Port Control Protocol Anycast `2001:1::1`
            (uint32.fromBytesBE(a6.toOpenArray(0, 3)) == 0x20010001'u32) and
            (uint32.fromBytes(a6.toOpenArray(4, 7)) == 0x00'u32) and
            (uint32.fromBytes(a6.toOpenArray(8, 11)) == 0x00'u32) and
            (uint32.fromBytesBE(a6.toOpenArray(12, 15)) == 0x01'u32)
          ) or
          (
            # Traversal Using Relays around NAT Anycast `2001:1::2`
            (uint32.fromBytesBE(a6.toOpenArray(0, 3)) == 0x20010001'u32) and
            (uint32.fromBytes(a6.toOpenArray(4, 7)) == 0x00'u32) and
            (uint32.fromBytes(a6.toOpenArray(8, 11)) == 0x00'u32) and
            (uint32.fromBytesBE(a6.toOpenArray(12, 15)) == 0x02'u32)
          ) or
          (
            # AMT `2001:3::/32`
            (uint16.fromBytesBE(a6.toOpenArray(0, 1)) == 0x2001'u16) and
            (uint16.fromBytesBE(a6.toOpenArray(2, 3)) == 0x03'u16)
          ) or
          (
            # AS112-v6 `2001:4:112::/48`
            (uint16.fromBytesBE(a6.toOpenArray(0, 1)) == 0x2001'u16) and
            (uint16.fromBytesBE(a6.toOpenArray(2, 3)) == 0x04'u16) and
            (uint16.fromBytesBE(a6.toOpenArray(4, 5)) == 0x112'u16) and
            (uint16.fromBytes(a6.toOpenArray(6, 7)) == 0x00'u16)
          ) or
          (
            # ORCHIDv2 `2001:20::/28`
            (uint16.fromBytesBE(a6.toOpenArray(0, 1)) == 0x2001'u16) and
            (uint16.fromBytesBE(a6.toOpenArray(2, 3)) >= 0x20'u16) and
            (uint16.fromBytesBE(a6.toOpenArray(2, 3)) <= 0x2F'u16)
          )
        )
      ) or
      address.isDocumentation() or
      address.isUniqueLocal() or
      address.isUnicastLinkLocal()
    )
  else:
    false
