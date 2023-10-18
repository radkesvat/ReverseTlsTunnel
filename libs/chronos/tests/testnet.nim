#                Chronos Test Suite
#            (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import unittest2
import ../chronos/transports/[osnet, ipnet]

{.used.}

suite "Network utilities test suite":

  const MaskVectors = [
    ["192.168.1.127:1024", "255.255.255.128", "192.168.1.0:1024"],
    ["192.168.1.127:1024", "255.255.255.192", "192.168.1.64:1024"],
    ["192.168.1.127:1024", "255.255.255.224", "192.168.1.96:1024"],
    ["192.168.1.127:1024", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ff80",
     "192.168.1.0:1024"],
    ["192.168.1.127:1024", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffc0",
     "192.168.1.64:1024"],
    ["192.168.1.127:1024", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffe0",
     "192.168.1.96:1024"],
    ["192.168.1.127:1024", "255.0.255.0", "192.0.1.0:1024"],
    ["[2001:db8::1]:1024", "ffff:ff80::", "[2001:d80::]:1024"],
    ["[2001:db8::1]:1024", "f0f0:0f0f::", "[2000:d08::]:1024"]
  ]

  const NonCanonicalMasks = [
    ["ip", "0.255.255.255", "-1"],
    ["ip", "255.0.255.255", "-1"],
    ["ip", "255.255.0.255", "-1"],
    ["ip", "255.255.255.0", "24"],
    ["ms", "0FFFFFFF", "-1"],
    ["ms", "F0FFFFFF", "-1"],
    ["ms", "FF0FFFFF", "-1"],
    ["ms", "FFF0FFFF", "-1"],
    ["ms", "FFFF0FFF", "-1"],
    ["ms", "FFFFF0FF", "-1"],
    ["ms", "FFFFFF0F", "-1"],
    ["ms", "FFFFFFF0", "28"],
    ["ip", "00FF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FF00:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:00FF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FF00:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:00FF:FFFF:FFFF:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FF00:FFFF:FFFF:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:00FF:FFFF:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:FF00:FFFF:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:FFFF:00FF:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:FFFF:FF00:FFFF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:FFFF:FFFF:00FF:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:FFFF:FFFF:FF00:FFFF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:00FF:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FF00:FFFF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:00FF", "-1"],
    ["ip", "FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FF00", "120"],
    ["ms", "0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "F0FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FF0FFFFFFFFFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFF0FFFFFFFFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFF0FFFFFFFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFF0FFFFFFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFF0FFFFFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFF0FFFFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFF0FFFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFF0FFFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFF0FFFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFF0FFFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFF0FFFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFF0FFFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFF0FFFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFF0FFFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFF0FFFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFF0FFFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFF0FFFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFF0FFFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFF0FFFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFF0FFFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFF0FFFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFFF0FFFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFFFF0FFFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFFFFF0FFFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFFFFFF0FFFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFFFFFFF0FFFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFFFFFFFF0FFF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFF0FF", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0F", "-1"],
    ["ms", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF0", "124"],
  ]

  const NetworkVectors = [
    ["135.104.0.0/32", "true", "135.104.0.0:0", "FFFFFFFF"],
    ["0.0.0.0/24", "true", "0.0.0.0:0", "FFFFFF00"],
    ["135.104.0.0/24", "true", "135.104.0.0:0", "FFFFFF00"],
    ["135.104.0.1/32", "true", "135.104.0.1:0", "FFFFFFFF"],
    ["135.104.0.1/24", "true", "135.104.0.1:0", "FFFFFF00"],
    ["::1/128", "true", "[::1]:0", "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF"],
    ["abcd:2345::/127", "true", "[abcd:2345::]:0",
     "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFE"],
    ["abcd:2345::/65", "true", "[abcd:2345::]:0",
     "FFFFFFFFFFFFFFFF8000000000000000"],
    ["abcd:2345::/64", "true", "[abcd:2345::]:0",
     "FFFFFFFFFFFFFFFF0000000000000000"],
    ["abcd:2345::/63", "true", "[abcd:2345::]:0",
     "FFFFFFFFFFFFFFFE0000000000000000"],
    ["abcd:2345::/33", "true", "[abcd:2345::]:0",
     "FFFFFFFF800000000000000000000000"],
    ["abcd:2345::/32", "true", "[abcd:2345::]:0",
     "FFFFFFFF000000000000000000000000"],
    ["abcd:2344::/31", "true", "[abcd:2344::]:0",
     "FFFFFFFE000000000000000000000000"],
    ["abcd:2300::/24", "true", "[abcd:2300::]:0",
     "FFFFFF00000000000000000000000000"],
    ["abcd:2345::/24", "true", "[abcd:2345::]:0",
     "FFFFFF00000000000000000000000000"],
    ["2001:db8::/48", "true", "[2001:db8::]:0",
     "FFFFFFFFFFFF00000000000000000000"],
    ["2001:db8::1/48", "true", "[2001:db8::1]:0",
     "FFFFFFFFFFFF00000000000000000000"],
    ["192.168.1.1/255.255.255.0", "true", "192.168.1.1:0", "FFFFFF00"],
    ["192.168.1.1/35", "false", "", ""],
    ["2001:db8::1/-1", "false", "", ""],
    ["2001:db8::1/-0", "false", "", ""],
    ["-0.0.0.0/32", "false", "", ""],
    ["0.-1.0.0/32", "false", "", ""],
    ["0.0.-2.0/32", "false", "", ""],
    ["0.0.0.-3/32", "false", "", ""],
    ["0.0.0.0/-0", "false", "", ""],
    ["", "false", "", ""]
  ]

  const NetworkContainsVectors = [
    ["172.16.1.1:1024", "172.16.0.0/12", "true"],
    ["172.24.0.1:1024", "172.16.0.0/13", "false"],
    ["192.168.0.3:1024", "192.168.0.0/0.0.255.252", "true"],
    ["192.168.0.4:1024", "192.168.0.0/0.255.0.252", "false"],
    ["[2001:db8:1:2::1]:1024", "2001:db8:1::/47", "true"],
    ["[2001:db8:1:2::1]:1024", "2001:db8:2::/47", "false"],
    ["[2001:db8:1:2::1]:1024", "2001:db8:1::/ffff:0:ffff::", "true"],
    ["[2001:db8:1:2::1]:1024", "2001:db8:1::/0:0:0:ffff::", "false"]
  ]

  test "IPv4 networks test":
    var a: TransportAddress
    check:
      a.isNone() == true
      initTAddress("0.0.0.0:0").isUnspecified() == true
      initTAddress("0.0.0.0:0").isNone() == false

      initTAddress("0.0.0.0:0").isZero() == true
      initTAddress("1.0.0.0:0").isZero() == false
      initTAddress("1.0.0.0:0").isUnspecified() == false

      initTAddress("127.0.0.0:0").isLoopback() == true
      initTAddress("127.255.255.255:0").isLoopback() == true
      initTAddress("128.0.0.0:0").isLoopback() == false
      initTAddress("126.0.0.0:0").isLoopback() == false

      initTAddress("224.0.0.0:0").isMulticast() == true
      initTAddress("230.0.0.0:0").isMulticast() == true
      initTAddress("239.255.255.255:0").isMulticast() == true
      initTAddress("240.0.0.0:0").isMulticast() == false
      initTAddress("223.0.0.0:0").isMulticast() == false

      initTAddress("224.0.0.0:0").isLinkLocalMulticast() == true
      initTAddress("224.0.0.255:0").isLinkLocalMulticast() == true
      initTAddress("225.0.0.0:0").isLinkLocalMulticast() == false
      initTAddress("224.0.1.0:0").isLinkLocalMulticast() == false

      initTAddress("0.0.0.0:0").isAnyLocal() == true
      initTAddress("1.0.0.0:0").isAnyLocal() == false

      initTAddress("169.254.0.0:0").isLinkLocal() == true
      initTAddress("169.254.255.255:0").isLinkLocal() == true
      initTAddress("169.255.0.0:0").isLinkLocal() == false
      initTAddress("169.253.0.0:0").isLinkLocal() == false

      initTAddress("10.0.0.0:0").isSiteLocal() == true
      initTAddress("10.255.255.255:0").isSiteLocal() == true
      initTAddress("11.0.0.0:0").isSiteLocal() == false
      initTAddress("9.0.0.0:0").isSiteLocal() == false
      initTAddress("172.16.0.0:0").isSiteLocal() == true
      initTAddress("172.31.255.255:0").isSiteLocal() == true
      initTAddress("172.15.0.0:0").isSiteLocal() == false
      initTAddress("172.32.0.0:0").isSiteLocal() == false
      initTAddress("192.168.0.0:0").isSiteLocal() == true
      initTAddress("192.168.255.255:0").isSiteLocal() == true
      initTAddress("192.167.0.0:0").isSiteLocal() == false
      initTAddress("192.169.0.0:0").isSiteLocal() == false

      initTAddress("224.0.1.0:0").isGlobalMulticast() == true
      initTAddress("238.255.255.255:0").isGlobalMulticast() == true
      initTAddress("224.0.0.0:0").isGlobalMulticast() == false
      initTAddress("239.0.0.0:0").isGlobalMulticast() == false

      initTAddress("239.255.255.255:0").isReserved() == false
      initTAddress("240.0.0.0:0").isReserved() == true
      initTAddress("250.0.0.0:0").isReserved() == true
      initTAddress("255.254.254.254:0").isReserved() == true

      initTAddress("198.17.255.255:0").isBenchmarking() == false
      initTAddress("198.18.0.0:0").isBenchmarking() == true
      initTAddress("198.18.0.1:0").isBenchmarking() == true
      initTAddress("198.19.0.1:0").isBenchmarking() == true
      initTAddress("198.19.255.255:0").isBenchmarking() == true
      initTAddress("198.20.0.0:0").isBenchmarking() == false

      initTAddress("192.0.1.255:0").isDocumentation() == false
      initTAddress("192.0.2.0:0").isDocumentation() == true
      initTAddress("192.0.2.255:0").isDocumentation() == true
      initTAddress("192.0.3.0:0").isDocumentation() == false

      initTAddress("198.51.99.255:0").isDocumentation() == false
      initTAddress("198.51.100.0:0").isDocumentation() == true
      initTAddress("198.51.100.255:0").isDocumentation() == true
      initTAddress("198.51.101.0:0").isDocumentation() == false

      initTAddress("203.0.112.255:0").isDocumentation() == false
      initTAddress("203.0.113.0:0").isDocumentation() == true
      initTAddress("203.0.113.255:0").isDocumentation() == true
      initTAddress("203.0.114.0:0").isDocumentation() == false

      initTAddress("0.0.0.0:0").isBroadcast() == false
      initTAddress("127.0.0.255:0").isBroadcast() == false
      initTAddress("127.0.255.255:0").isBroadcast() == false
      initTAddress("127.255.255.255:0").isBroadcast() == false
      initTAddress("255.255.255.255:0").isBroadcast() == true

      initTAddress("100.63.255.255:0").isShared() == false
      initTAddress("100.64.0.0:0").isShared() == true
      initTAddress("100.64.0.1:0").isShared() == true
      initTAddress("100.127.255.255:0").isShared() == true
      initTAddress("100.128.0.0:0").isShared() == false

      a.isGlobal() == false
      initTAddress("0.0.0.0:0").isGlobal() == false
      initTAddress("127.0.0.0:0").isGlobal() == false
      initTAddress("10.0.0.0:0").isGlobal() == false
      initTAddress("10.255.255.255:0").isGlobal() == false
      initTAddress("172.16.0.0:0").isGlobal() == false
      initTAddress("172.31.255.255:0").isGlobal() == false
      initTAddress("192.168.0.0:0").isGlobal() == false
      initTAddress("192.168.255.255:0").isGlobal() == false
      initTAddress("100.64.0.0:0").isGlobal() == false
      initTAddress("100.64.0.1:0").isGlobal() == false
      initTAddress("100.127.255.255:0").isGlobal() == false
      initTAddress("169.254.0.0:0").isGlobal() == false
      initTAddress("169.254.255.255:0").isGlobal() == false
      initTAddress("192.0.0.0:0").isGlobal() == false
      initTAddress("192.0.0.255:0").isGlobal() == false
      initTAddress("192.0.2.0:0").isGlobal() == false
      initTAddress("192.0.2.255:0").isGlobal() == false
      initTAddress("198.51.100.0:0").isGlobal() == false
      initTAddress("198.51.100.255:0").isGlobal() == false
      initTAddress("203.0.113.0:0").isGlobal() == false
      initTAddress("203.0.113.255:0").isGlobal() == false
      initTAddress("198.18.0.0:0").isGlobal() == false
      initTAddress("198.18.0.1:0").isGlobal() == false
      initTAddress("198.19.0.1:0").isGlobal() == false
      initTAddress("198.19.255.255:0").isGlobal() == false
      initTAddress("240.0.0.0:0").isGlobal() == false
      initTAddress("250.0.0.0:0").isGlobal() == false
      initTAddress("255.254.254.254:0").isGlobal() == false
      initTAddress("255.255.255.255:0").isGlobal() == false

      initTAddress("1.1.1.1:0").isGlobal() == true
      initTAddress("8.8.8.8:0").isGlobal() == true

  test "IPv6 networks test":
    var a: TransportAddress
    check:
      initTAddress("[::]:0").isNone() == false
      initTAddress("[::]:0").isUnspecified() == true

      initTAddress("[::]:0").isZero() == true
      initTAddress("[::1]:0").isZero() == false
      initTAddress("[::1]:0").isUnspecified() == false

      initTAddress("[::1]:0").isLoopback() == true
      initTAddress("[::2]:0").isLoopback() == false

      initTAddress("[FF00::]:0").isMulticast() == true
      initTAddress(
        "[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isMulticast() == true
      initTAddress("[F000::]:0").isMulticast() == false

      initTAddress("[::]:0").isAnyLocal() == true
      initTAddress("[::1]:0").isAnyLocal() == false

      initTAddress("[FE80::]:0").isLinkLocal() == true
      initTAddress(
        "[FEBF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isLinkLocal() == true
      initTAddress("[FE7F::]:0").isLinkLocal() == false
      initTAddress("[FEC0::]:0").isLinkLocal() == false

      initTAddress("[FEC0::]:0").isSiteLocal() == true
      initTAddress(
        "[FEFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isSiteLocal() == true
      initTAddress("[FEBF::]:0").isSiteLocal() == false
      initTAddress("[FF00::]:0").isSiteLocal() == false

      initTAddress("[FF0E::]:0").isGlobalMulticast() == true
      initTAddress(
        "[FFFE:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isGlobalMulticast() == true
      initTAddress("[FF0D::]:0").isGlobalMulticast() == false
      initTAddress("[FFFF::]:0").isGlobalMulticast() == false

      initTAddress(
        "[FBFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isUniqueLocal() == false
      initTAddress("[FC00::]:0").isUniqueLocal() == true
      initTAddress(
        "[FDFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isUniqueLocal() == true
      initTAddress("[FE00::]:0").isUniqueLocal() == false

      initTAddress(
        "[FE7F:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isUnicastLinkLocal() == false
      initTAddress("[FE80::]:0").isUnicastLinkLocal() == true
      initTAddress(
        "[FEBF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isUnicastLinkLocal() == true
      initTAddress("[FEC0::]:0").isUnicastLinkLocal() == false

      initTAddress(
        "[2001:0001:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isBenchmarking() == false
      initTAddress("[2001:0002::]:0").isBenchmarking() == true
      initTAddress(
        "[2001:0002:0000:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isBenchmarking() == true
      initTAddress("[2001:0002:0001::]:0").isBenchmarking() == false

      initTAddress(
        "[2001:0DB7:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isDocumentation() == false
      initTAddress("[2001:0DB8::]:0").isDocumentation() == true
      initTAddress(
        "[2001:0DB8:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isDocumentation() == true
      initTAddress("[2001:0DB9::]:0").isDocumentation() == false

      a.isGlobal() == false
      initTAddress("[::]:0").isGlobal() == false
      initTAddress("[::1]:0").isGlobal() == false
      initTAddress("[::FFFF:0000:0000]:0").isGlobal() == false
      initTAddress("[::FFFF:FFFF:FFFF]:0").isGlobal() == false
      initTAddress("[0064:FF9B:0001::]:0").isGlobal() == false
      initTAddress(
        "[0064:FF9B:0001:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isGlobal() == false
      initTAddress("[0100::]:0").isGlobal() == false
      initTAddress(
        "[0100:0000:0000:0000:FFFF:FFFF:FFFF:FFFF]:0"
      ).isGlobal() == false
      initTAddress("[2001::]:0").isGlobal() == false
      initTAddress(
        "[2001:01FF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isGlobal() == false
      initTAddress("[2001:1::1]:0").isGlobal() == true
      initTAddress("[2001:1::2]:0").isGlobal() == true
      initTAddress("[2001:3::]:0").isGlobal() == true
      initTAddress("[2001:4:112::]:0").isGlobal() == true
      initTAddress("[2001:20::]:0").isGlobal() == true
      initTAddress("[2001:0db8::]:0").isGlobal() == false
      initTAddress(
        "[2001:0DB8:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isGlobal() == false
      initTAddress("[FC00::]:0").isGlobal() == false
      initTAddress(
        "[FDFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isGlobal() == false
      initTAddress("[FE80::]:0").isGlobal() == false
      initTAddress(
        "[FEBF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0"
      ).isGlobal() == false

      initTAddress("[2606:4700:4700::1111]:0").isGlobal() == true
      initTAddress("[2606:4700:4700::1001]:0").isGlobal() == true

  test "IP masks test":
    check:
      $IpMask.init(AddressFamily.IPv4, -1) == "00000000"
      $IpMask.init(AddressFamily.IPv4, 0) == "00000000"
      $IpMask.init(AddressFamily.IPv4, 4) == "F0000000"
      $IpMask.init(AddressFamily.IPv4, 8) == "FF000000"
      $IpMask.init(AddressFamily.IPv4, 12) == "FFF00000"
      $IpMask.init(AddressFamily.IPv4, 16) == "FFFF0000"
      $IpMask.init(AddressFamily.IPv4, 20) == "FFFFF000"
      $IpMask.init(AddressFamily.IPv4, 24) == "FFFFFF00"
      $IpMask.init(AddressFamily.IPv4, 28) == "FFFFFFF0"
      $IpMask.init(AddressFamily.IPv4, 32) == "FFFFFFFF"
      $IpMask.init(AddressFamily.IPv4, 33) == "FFFFFFFF"

      IpMask.init(AddressFamily.IPv4, -1) == IpMask.init("00000000")
      IpMask.init(AddressFamily.IPv4, 0) == IpMask.init("00000000")
      IpMask.init(AddressFamily.IPv4, 4) == IpMask.init("F0000000")
      IpMask.init(AddressFamily.IPv4, 8) == IpMask.init("FF000000")
      IpMask.init(AddressFamily.IPv4, 12) == IpMask.init("FFF00000")
      IpMask.init(AddressFamily.IPv4, 16) == IpMask.init("FFFF0000")
      IpMask.init(AddressFamily.IPv4, 20) == IpMask.init("FFFFF000")
      IpMask.init(AddressFamily.IPv4, 24) == IpMask.init("FFFFFF00")
      IpMask.init(AddressFamily.IPv4, 28) == IpMask.init("FFFFFFF0")
      IpMask.init(AddressFamily.IPv4, 32) == IpMask.init("FFFFFFFF")
      IpMask.init(AddressFamily.IPv4, 33) == IpMask.init("FFFFFFFF")

      IpMask.init(initTAddress("255.0.0.0:0")) == IpMask.initIp("255.0.0.0")
      IpMask.init(initTAddress("255.255.0.0:0")) == IpMask.initIp("255.255.0.0")
      IpMask.init(initTAddress("255.255.255.0:0")) ==
        IpMask.initIp("255.255.255.0")
      IpMask.init(initTAddress("255.255.255.255:0")) ==
        IpMask.initIp("255.255.255.255")

      IpMask.init("00000000").prefix() == 0
      IpMask.init("F0000000").prefix() == 4
      IpMask.init("FF000000").prefix() == 8
      IpMask.init("FFF00000").prefix() == 12
      IpMask.init("FFFF0000").prefix() == 16
      IpMask.init("FFFFF000").prefix() == 20
      IpMask.init("FFFFFF00").prefix() == 24
      IpMask.init("FFFFFFF0").prefix() == 28
      IpMask.init("FFFFFFFF").prefix() == 32

      IpMask.init("00000000").subnetMask() == initTAddress("0.0.0.0:0")
      IpMask.init("F0000000").subnetMask() == initTAddress("240.0.0.0:0")
      IpMask.init("FF000000").subnetMask() == initTAddress("255.0.0.0:0")
      IpMask.init("FFF00000").subnetMask() == initTAddress("255.240.0.0:0")
      IpMask.init("FFFF0000").subnetMask() == initTAddress("255.255.0.0:0")
      IpMask.init("FFFFF000").subnetMask() == initTAddress("255.255.240.0:0")
      IpMask.init("FFFFFF00").subnetMask() == initTAddress("255.255.255.0:0")
      IpMask.init("FFFFFFF0").subnetMask() == initTAddress("255.255.255.240:0")
      IpMask.init("FFFFFFFF").subnetMask() == initTAddress("255.255.255.255:0")

      IpMask.init("00000000").ip() == "0.0.0.0"
      IpMask.init("F0000000").ip() == "240.0.0.0"
      IpMask.init("FF000000").ip() == "255.0.0.0"
      IpMask.init("FFF00000").ip() == "255.240.0.0"
      IpMask.init("FFFF0000").ip() == "255.255.0.0"
      IpMask.init("FFFFF000").ip() == "255.255.240.0"
      IpMask.init("FFFFFF00").ip() == "255.255.255.0"
      IpMask.init("FFFFFFF0").ip() == "255.255.255.240"
      IpMask.init("FFFFFFFF").ip() == "255.255.255.255"

      initTAddress("241.241.241.241:0").mask(IpMask.init("00000000")) ==
        initTAddress("0.0.0.0:0")
      initTAddress("241.241.241.241:0").mask(IpMask.init("F0000000")) ==
        initTAddress("240.0.0.0:0")
      initTAddress("241.241.241.241:0").mask(IpMask.init("FF000000")) ==
        initTAddress("241.0.0.0:0")
      initTAddress("241.241.241.241:0").mask(IpMask.init("FFF00000")) ==
        initTAddress("241.240.0.0:0")
      initTAddress("241.241.241.241:0").mask(IpMask.init("FFFF0000")) ==
        initTAddress("241.241.0.0:0")
      initTAddress("241.241.241.241:0").mask(IpMask.init("FFFFF000")) ==
        initTAddress("241.241.240.0:0")
      initTAddress("241.241.241.241:0").mask(IpMask.init("FFFFFF00")) ==
        initTAddress("241.241.241.0:0")
      initTAddress("241.241.241.241:0").mask(IpMask.init("FFFFFFF0")) ==
        initTAddress("241.241.241.240:0")
      initTAddress("241.241.241.241:0").mask(IpMask.init("FFFFFFFF")) ==
        initTAddress("241.241.241.241:0")

  test "IP networks test":
    check:
      IpNet.init(initTAddress("192.168.0.1:0"), 0) ==
        IpNet.init("192.168.0.1/0.0.0.0")
      IpNet.init(initTAddress("192.168.0.1:0"), 4) ==
        IpNet.init("192.168.0.1/240.0.0.0")
      IpNet.init(initTAddress("192.168.0.1:0"), 8) ==
        IpNet.init("192.168.0.1/255.0.0.0")
      IpNet.init(initTAddress("192.168.0.1:0"), 12) ==
        IpNet.init("192.168.0.1/255.240.0.0")
      IpNet.init(initTAddress("192.168.0.1:0"), 16) ==
        IpNet.init("192.168.0.1/255.255.0.0")
      IpNet.init(initTAddress("192.168.0.1:0"), 20) ==
        IpNet.init("192.168.0.1/255.255.240.0")
      IpNet.init(initTAddress("192.168.0.1:0"), 24) ==
        IpNet.init("192.168.0.1/255.255.255.0")
      IpNet.init(initTAddress("192.168.0.1:0"), 28) ==
        IpNet.init("192.168.0.1/255.255.255.240")
      IpNet.init(initTAddress("192.168.0.1:0"), 32) ==
        IpNet.init("192.168.0.1/255.255.255.255")

      IpNet.init(initTAddress("192.168.0.1:0"), 0) ==
        IpNet.init("192.168.0.1/0")
      IpNet.init(initTAddress("192.168.0.1:0"), 4) ==
        IpNet.init("192.168.0.1/4")
      IpNet.init(initTAddress("192.168.0.1:0"), 8) ==
        IpNet.init("192.168.0.1/8")
      IpNet.init(initTAddress("192.168.0.1:0"), 12) ==
        IpNet.init("192.168.0.1/12")
      IpNet.init(initTAddress("192.168.0.1:0"), 16) ==
        IpNet.init("192.168.0.1/16")
      IpNet.init(initTAddress("192.168.0.1:0"), 20) ==
        IpNet.init("192.168.0.1/20")
      IpNet.init(initTAddress("192.168.0.1:0"), 24) ==
        IpNet.init("192.168.0.1/24")
      IpNet.init(initTAddress("192.168.0.1:0"), 28) ==
        IpNet.init("192.168.0.1/28")
      IpNet.init(initTAddress("192.168.0.1:0"), 32) ==
        IpNet.init("192.168.0.1/32")

      IpNet.init("192.168.0.1/24").contains(initTAddress("192.168.0.1:0")) ==
        true
      IpNet.init("192.168.0.1/24").contains(initTAddress("192.168.0.128:0")) ==
        true
      IpNet.init("192.168.0.1/24").contains(initTAddress("192.168.0.255:0")) ==
        true
      IpNet.init("192.168.0.1/24").contains(initTAddress("192.168.1.0:0")) ==
        false
      IpNet.init("192.168.0.1/0").contains(initTAddress("1.1.1.1:0")) ==
        true
      IpNet.init("192.168.0.1/32").contains(initTAddress("192.168.0.1:0")) ==
        true
      IpNet.init("192.168.0.1/32").contains(initTAddress("192.168.0.2:0")) ==
        false

  test "IpMask test vectors":
    for item in MaskVectors:
      var a = initTAddress(item[0])
      var m = IpMask.initIp(item[1])
      var r = a.mask(m)
      check $r == item[2]

  test "IpMask serialization/deserialization test":
    for i in 1..32:
      var m = IpMask.init(AddressFamily.IPv4, i)
      check m.prefix() == i
      var s0x = `$`(m, true)
      var s = $m
      var sip = m.ip()
      var m1 = IpMask.init(s0x)
      var m2 = IpMask.init(s)
      var m3 = IpMask.initIp(sip)
      check:
        m == m1
        m == m2
        m == m3
    for i in 1..128:
      var m = IpMask.init(AddressFamily.IPv6, i)
      check m.prefix() == i
      var s0x = `$`(m, true)
      var s = $m
      var sip = m.ip()
      var m1 = IpMask.init(s0x)
      var m2 = IpMask.init(s)
      var m3 = IpMask.initIp(sip)
      check:
        m == m1
        m == m2
        m == m3

  test "IpMask non-canonical masks":
    for item in NonCanonicalMasks:
      var m: IpMask
      if item[0] == "ip":
        m = IpMask.initIp(item[1])
      elif item[0] == "ms":
        m = IpMask.init(item[1])
      var c = $(m.prefix())
      check:
        c == item[2]

  test "IpNet test vectors":
    for item in NetworkVectors:
      var res: bool
      var inet: IpNet
      try:
        inet = IpNet.init(item[0])
        res = true
      except TransportAddressError:
        res = false
      check:
        $res == item[1]
      if res:
        check:
          $inet.host == item[2]
          $inet.mask == $item[3]

  test "IpNet contains test vectors":
    for item in NetworkContainsVectors:
      var a = initTAddress(item[0])
      var n = IpNet.init(item[1])
      var res = a in n
      check:
        $res == item[2]

  test "IpNet serialization/deserialization test":
    var ip4 = initTAddress("192.168.1.0:1024")
    for i in 1..32:
      var net = IpNet.init(ip4, i)
      var s1 = $net
      var net2 = IpNet.init(s1)
      check net == net2

    var ip6 = initTAddress("[8000:f123:f456:cafe::]:1024")
    for i in 1..128:
      var net = IpNet.init(ip6, i)
      var s1 = $net
      var net2 = IpNet.init(s1)
      check net == net2

  test "IPv4 <-> IPv6 mapping test":
    check:
      initTAddress("255.255.255.255:0").toIPv6() ==
        initTAddress("[::FFFF:FFFF:FFFF]:0")
      initTAddress("128.128.128.128:0").toIPv6() ==
        initTAddress("[::FFFF:8080:8080]:0")
      initTAddress("1.1.1.1:0").toIPv6() == initTAddress("[::FFFF:0101:0101]:0")
      initTAddress("0.0.0.0:0").toIPv6() == initTAddress("[::FFFF:0000:0000]:0")
      initTAddress("[::FFFF:FFFF:FFFF]:0").isV4Mapped() == true
      initTAddress("[::FFFF:8080:8080]:0").isV4Mapped() == true
      initTAddress("[::FFFF:0101:0101]:0").isV4Mapped() == true
      initTAddress("[::FFFF:0000:0000]:0").isV4Mapped() == true
      initTAddress("[::FFFF:FFFF:FFFF]:0").toIPv4() ==
        initTAddress("255.255.255.255:0")
      initTAddress("[::FFFF:8080:8080]:0").toIPv4() ==
        initTAddress("128.128.128.128:0")
      initTAddress("[::FFFF:0101:0101]:0").toIPv4() == initTAddress("1.1.1.1:0")
      initTAddress("[::FFFF:0000:0000]:0").toIPv4() == initTAddress("0.0.0.0:0")

  test "getInterfaces() test":
    var ifaces = getInterfaces()
    check:
      len(ifaces) > 0
    for item in ifaces:
      echo item

  test "getBestRoute() test":
    var route = getBestRoute(initTAddress("8.8.8.8:0"))
    check:
      route.source.isUnspecified() == false
      route.dest.isUnspecified() == false
      route.ifIndex != 0
    echo route

  test "TransportAddress arithmetic operations test (add)":
    block:
      var ip4 = initTAddress("192.168.1.0:1024")
      var ip6 = initTAddress("[::1]:1024")
      when sizeof(int) == 8:
        ip4 = ip4 + uint(0xFFFF_FFFF_FFFF_FFFF'u64)
        ip6 = ip6 + uint(0xFFFF_FFFF_FFFF_FFFF'u64)
        var ip6e = initTAddress("[::1:0000:0000:0000:1]:1024")
      else:
        ip4 = ip4 + uint(0xFFFF_FFFF'u32)
        ip6 = ip6 + uint(0xFFFF_FFFF'u32)
        var ip6e = initTAddress("[::1:0000:1]:1024")
      inc(ip4)
      inc(ip6)
      check:
        ip4 == initTAddress("192.168.1.0:1024")
        ip6 == ip6e
      ip4 = initTAddress("255.255.255.255:0")
      ip6 = initTAddress("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0")
      inc(ip4)
      inc(ip6)
      check:
        ip4 == initTAddress("0.0.0.0:0")
        ip6 == initTAddress("[::]:0")

  test "TransportAddress arithmetic operations test (sub)":
    var ip4 = initTAddress("192.168.1.0:1024")
    when sizeof(int) == 8:
      var ip6 = initTAddress("[::1:0000:0000:0000:0000]:1024")
      ip4 = ip4 - uint(0xFFFF_FFFF_FFFF_FFFF'u64)
      ip6 = ip6 - uint(0xFFFF_FFFF_FFFF_FFFF'u64)
    else:
      var ip6 = initTAddress("[::1:0000:0000]:1024")
      ip4 = ip4 - uint(0xFFFF_FFFF'u32)
      ip6 = ip6 - uint(0xFFFF_FFFF'u32)
    dec(ip4)
    dec(ip6)
    check:
      ip4 == initTAddress("192.168.1.0:1024")
      ip6 == initTAddress("[::]:1024")
    ip4 = initTAddress("0.0.0.0:0")
    ip6 = initTAddress("[::]:0")
    dec(ip4)
    dec(ip6)
    check:
      ip4 == initTAddress("255.255.255.255:0")
      ip6 == initTAddress("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:0")
