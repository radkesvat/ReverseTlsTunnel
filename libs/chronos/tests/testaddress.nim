#                Chronos Test Suite
#            (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import unittest2
import ../chronos

{.used.}

suite "TransportAddress test suite":
  test "initTAddress(string)":
    check $initTAddress("0.0.0.0:1") == "0.0.0.0:1"
    check $initTAddress("255.255.255.255:65535") == "255.255.255.255:65535"
    check $initTAddress("[::]:1") == "[::]:1"
    check $initTAddress("[FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF]:65535") ==
      "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"

  test "initTAddress(string, Port)":
    check $initTAddress("0.0.0.0", Port(0)) == "0.0.0.0:0"
    check $initTAddress("255.255.255.255", Port(65535)) ==
      "255.255.255.255:65535"
    check $initTAddress("::", Port(0)) == "[::]:0"
    check $initTAddress("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF",
                        Port(65535)) ==
      "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"

  test "initTAddress(string, int)":
    check $initTAddress("0.0.0.0", 1) == "0.0.0.0:1"
    check $initTAddress("255.255.255.255", 65535) ==
      "255.255.255.255:65535"
    check $initTAddress("::", 0) == "[::]:0"
    check $initTAddress("FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF", 65535) ==
      "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535"

  test "resolveTAddress(string, IPv4)":
    var numeric = ["0.0.0.0:1", "255.0.0.255:54321", "128.128.128.128:12345",
                   "255.255.255.255:65535"]
    var hostnames = ["www.google.com:443", "www.github.com:443"]

    for item in numeric:
      var taseq = resolveTAddress(item)
      check len(taseq) == 1
      check $taseq[0] == item

    for item in hostnames:
      var taseq = resolveTAddress(item)
      check len(taseq) >= 1

  # test "resolveTAddress(string, IPv6)":
  #   var numeric = [
  #     "[::]:1",
  #     "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
  #     "[aaaa:bbbb:cccc:dddd:eeee:ffff::1111]:12345",
  #     "[aaaa:bbbb:cccc:dddd:eeee:ffff::]:12345",
  #     "[a:b:c:d:e:f::]:12345",
  #     "[2222:3333:4444:5555:6666:7777:8888:9999]:56789"
  #   ]
  #   var hostnames = ["localhost:443"]

  #   for item in numeric:
  #     var taseq = resolveTAddress(item, IpAddressFamily.IPv6)
  #     check len(taseq) == 1
  #     check $taseq[0] == item

  #   for item in hostnames:
  #     var taseq = resolveTAddress(item, IpAddressFamily.IPv6)
  #     check len(taseq) >= 1

  test "resolveTAddress(string, Port, IPv4)":
    var numeric = ["0.0.0.0", "255.0.0.255", "128.128.128.128",
                   "255.255.255.255"]
    var hostnames = ["www.google.com", "www.github.com", "localhost"]

    for item in numeric:
      var taseq = resolveTAddress(item, Port(443))
      check len(taseq) == 1
      check $taseq[0] == item & ":443"

    for item in hostnames:
      var taseq = resolveTAddress(item, Port(443))
      check len(taseq) >= 1

  # test "resolveTAddress(string, Port, IPv6)":
  #   var numeric = [
  #     "::",
  #     "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
  #     "aaaa:bbbb:cccc:dddd:eeee:ffff::1111",
  #     "aaaa:bbbb:cccc:dddd:eeee:ffff::",
  #     "a:b:c:d:e:f::",
  #     "2222:3333:4444:5555:6666:7777:8888:9999"
  #   ]
  #   var hostnames = ["localhost"]
  #   for item in numeric:
  #     var taseq = resolveTAddress(item, Port(443), IpAddressFamily.IPv6)
  #     check len(taseq) == 1
  #     check $taseq[0] == "[" & item & "]:443"

  #   for item in hostnames:
  #     var taseq = resolveTAddress(item, Port(443), IpAddressFamily.IPv6)
  #     check len(taseq) >= 1

  test "Faulty initTAddress(string)":
    var tests = [
      "z:1",
      "256.256.256.256:65534",
      "127.0.0.1:65536"
    ]
    var errcounter = 0
    for item in tests:
      try:
        discard initTAddress(item)
      except TransportAddressError:
        inc(errcounter)
    check errcounter == len(tests)

  test "Faulty initTAddress(string, Port)":
    var tests = [
      ":::",
      "999.999.999.999",
      "gggg:aaaa:bbbb:gggg:aaaa:bbbb:gggg:aaaa",
      "hostname"
    ]
    var errcounter = 0
    for item in tests:
      try:
        discard initTAddress(item, Port(443))
      except TransportAddressError:
        inc(errcounter)
    check errcounter == len(tests)

  test "Faulty initTAddress(string, Port)":
    var errcounter = 0
    try:
      discard initTAddress("127.0.0.1", 100000)
    except TransportAddressError:
      inc(errcounter)
    check errcounter == 1

  test "Faulty resolveTAddress(string, IPv4) for IPv6 address":
    var numeric = [
      "[::]:1",
      "[ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff]:65535",
      "[aaaa:bbbb:cccc:dddd:eeee:ffff::1111]:12345",
      "[aaaa:bbbb:cccc:dddd:eeee:ffff::]:12345",
      "[a:b:c:d:e:f::]:12345",
      "[2222:3333:4444:5555:6666:7777:8888:9999]:56789"
    ]
    var errcounter = 0
    for item in numeric:
      try:
        discard resolveTAddress(item, AddressFamily.IPv4)
      except TransportAddressError:
        inc(errcounter)
    check errcounter == len(numeric)

  test "Faulty resolveTAddress(string, Port, IPv4) for IPv6 address":
    var numeric = [
      "::",
      "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
      "aaaa:bbbb:cccc:dddd:eeee:ffff::1111",
      "aaaa:bbbb:cccc:dddd:eeee:ffff::",
      "a:b:c:d:e:f::",
      "2222:3333:4444:5555:6666:7777:8888:9999"
    ]
    var errcounter = 0
    for item in numeric:
      try:
        discard resolveTAddress(item, Port(443), AddressFamily.IPv4)
      except TransportAddressError:
        inc(errcounter)
    check errcounter == len(numeric)

  # test "Faulty resolveTAddress(string, IPv6) for IPv4 address":
  #   var numeric = ["0.0.0.0:0", "255.0.0.255:54321", "128.128.128.128:12345",
  #                  "255.255.255.255:65535"]
  #   var errcounter = 0
  #   for item in numeric:
  #     try:
  #       var taseq = resolveTAddress(item, IpAddressFamily.IPv6)
  #     except TransportAddressError:
  #       inc(errcounter)
  #   check errcounter == len(numeric)

  # test "Faulty resolveTAddress(string, Port, IPv6) for IPv4 address":
  #   var numeric = ["0.0.0.0", "255.0.0.255", "128.128.128.128",
  #                  "255.255.255.255"]
  #   var errcounter = 0
  #   for item in numeric:
  #     try:
  #       var taseq = resolveTAddress(item, Port(443), IpAddressFamily.IPv6)
  #     except TransportAddressError:
  #       inc(errcounter)
  #   check errcounter == len(numeric)
