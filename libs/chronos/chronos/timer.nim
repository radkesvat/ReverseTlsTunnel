#
#                 Chronos Timer
#
#           (c) Copyright 2017 Eugene Kabanov
#  (c) Copyright 2018-Present Status Research & Development GmbH
#
#                Licensed under either of
#    Apache License, version 2.0, (LICENSE-APACHEv2)
#                MIT license (LICENSE-MIT)

## This module implements cross-platform system timer with
## milliseconds resolution.
##
## Timer supports two types of clocks:
## ``system`` uses the most fast OS primitive to obtain wall clock time.
## ``mono`` uses monotonic clock time (default).
##
## ``system`` clock is affected by discontinuous jumps in the system time. This
## clock is significantly faster then ``mono`` clock in most of the cases.
##
## ``mono`` clock is not affected by discontinuous jumps in the system time.
## This clock is slower then ``system`` clock.
##
## You can specify which timer you want to use ``-d:asyncTimer=<system/mono>``.
import stew/base10
import "."/osdefs

const asyncTimer* {.strdefine.} = "mono"

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

when defined(windows):
  when asyncTimer == "system":
    proc fastEpochTime*(): uint64 {.
         inline, deprecated: "Use Moment.now()".} =
      ## Timer resolution is millisecond.
      var t: FILETIME
      getSystemTimeAsFileTime(t)
      ((uint64(t.dwHighDateTime) shl 32) or uint64(t.dwLowDateTime)) div 10_000

    proc fastEpochTimeNano(): uint64 {.inline.} =
      ## Timer resolution is nanosecond.
      var t: FILETIME
      getSystemTimeAsFileTime(t)
      ((uint64(t.dwHighDateTime) shl 32) or uint64(t.dwLowDateTime)) * 100

  else:
    var queryFrequencyM: uint64
    var queryFrequencyN: uint64

    proc fastEpochTimeNano(): uint64 {.inline.} =
      ## Procedure's resolution is nanosecond.
      var res: uint64
      queryPerformanceCounter(res)
      res * queryFrequencyN

    proc fastEpochTime*(): uint64 {.inline, deprecated: "Use Moment.now()".} =
      ## Procedure's resolution is millisecond.
      var res: uint64
      queryPerformanceCounter(res)
      res div queryFrequencyM

    proc setupQueryFrequence() =
      var freq: uint64
      queryPerformanceFrequency(freq)
      if freq < 1000:
        queryFrequencyM = freq
      else:
        queryFrequencyM = freq div 1_000
      queryFrequencyN = 1_000_000_000'u64 div freq

    setupQueryFrequence()

elif defined(macosx):

  when asyncTimer == "system":

    proc fastEpochTime*(): uint64 {.inline, deprecated: "Use Moment.now()".} =
      ## Procedure's resolution is millisecond.
      var t: Timeval
      posix_gettimeofday(t)
      uint64(t.tv_sec) * 1_000 + uint64(t.tv_usec) div 1_000

    proc fastEpochTimeNano(): uint64 {.inline.} =
      ## Procedure's resolution is nanosecond.
      var t: Timeval
      posix_gettimeofday(t)
      uint64(t.tv_sec) * 1_000_000_000 + uint64(t.tv_usec) * 1_000
  else:
    var queryFrequencyN: uint64
    var queryFrequencyD: uint64

    proc setupQueryFrequence() =
      var info: MachTimebaseInfo
      mach_timebase_info(info)
      queryFrequencyN = info.numer
      queryFrequencyD = info.denom

    proc fastEpochTime*(): uint64 {.inline, deprecated: "Use Moment.now()".} =
      ## Procedure's resolution is millisecond.
      let res = (mach_absolute_time() * queryFrequencyN) div queryFrequencyD
      res div 1_000_000

    proc fastEpochTimeNano(): uint64 {.inline.} =
      ## Procedure's resolution is nanosecond.
      (mach_absolute_time() * queryFrequencyN) div queryFrequencyD

    setupQueryFrequence()

elif defined(posix):
  when asyncTimer == "system":
    proc fastEpochTime*(): uint64 {.inline, deprecated: "Use Moment.now()".} =
      ## Procedure's resolution is millisecond.
      var t: Timespec
      discard clock_gettime(CLOCK_REALTIME, t)
      uint64(t.tv_sec) * 1_000 + (uint64(t.tv_nsec) div 1_000_000)

    proc fastEpochTimeNano(): uint64 {.inline.} =
      ## Procedure's resolution is nanosecond.
      var t: Timespec
      discard clock_gettime(CLOCK_REALTIME, t)
      uint64(t.tv_sec) * 1_000_000_000'u64 + uint64(t.tv_nsec)

  else:
    proc fastEpochTime*(): uint64 {.inline, deprecated: "Use Moment.now()".} =
      ## Procedure's resolution is millisecond.
      var t: Timespec
      discard clock_gettime(CLOCK_MONOTONIC, t)
      uint64(t.tv_sec) * 1_000 + (uint64(t.tv_nsec) div 1_000_000)

    proc fastEpochTimeNano(): uint64 {.inline.} =
      ## Procedure's resolution is nanosecond.
      var t: Timespec
      discard clock_gettime(CLOCK_MONOTONIC, t)
      uint64(t.tv_sec) * 1_000_000_000'u64 + uint64(t.tv_nsec)

elif defined(nimdoc):
  discard
else:
  error("Sorry, your operation system is not yet supported!")

type
  Moment* = object
    ## A Moment in time. Its value has no direct meaning, but can be compared
    ## with other Moments. Moments are captured using a monotonically
    ## non-decreasing clock (by default).
    value: int64

  Duration* = object
    ## A Duration is the interval between to points in time.
    value: int64

when sizeof(int) == 4:
  type SomeIntegerI64* = SomeSignedInt|uint|uint8|uint16|uint32
else:
  type SomeIntegerI64* = SomeSignedInt|uint8|uint16|uint32

func `+`*(a: Duration, b: Duration): Duration {.inline.} =
  ## Duration + Duration = Duration
  Duration(value: a.value + b.value)

func `+`*(a: Duration, b: Moment): Moment {.inline.} =
  ## Duration + Moment = Moment
  Moment(value: a.value + b.value)

func `+`*(a: Moment, b: Duration): Moment {.inline.} =
  ## Moment + Duration = Moment
  Moment(value: a.value + b.value)

func `+=`*(a: var Moment, b: Duration) {.inline.} =
  ## Moment += Duration
  a.value += b.value

func `+=`*(a: var Duration, b: Duration) {.inline.} =
  ## Duration += Duration
  a.value += b.value

func `-`*(a, b: Moment): Duration {.inline.} =
  ## Moment - Moment = Duration
  ##
  ## Note: Duration can't be negative.
  Duration(value: if a.value >= b.value: a.value - b.value else: 0'i64)

func `-`*(a: Moment, b: Duration): Moment {.inline.} =
  ## Moment - Duration = Moment
  ##
  ## Note: Moment can be negative
  Moment(value: a.value - b.value)

func `-`*(a: Duration, b: Duration): Duration {.inline.} =
  ## Duration - Duration = Duration
  ##
  ## Note: Duration can't be negative.
  Duration(value: if a.value >= b.value: a.value - b.value else: 0'i64)

func `-=`*(a: var Duration, b: Duration) {.inline.} =
  ## Duration -= Duration
  a.value = if a.value >= b.value: a.value - b.value else: 0'i64

func `-=`*(a: var Moment, b: Duration) {.inline.} =
  ## Moment -= Duration
  a.value -= b.value

func `==`*(a, b: Duration): bool {.inline.} =
  ## Returns ``true`` if ``a`` equal to ``b``.
  a.value == b.value

func `==`*(a, b: Moment): bool {.inline.} =
  ## Returns ``true`` if ``a`` equal to ``b``.
  a.value == b.value

func `<`*(a, b: Duration): bool {.inline.} =
  ## Returns ``true`` if ``a`` less then ``b``.
  a.value < b.value

func `<`*(a, b: Moment): bool {.inline.} =
  ## Returns ``true`` if ``a`` less then ``b``.
  a.value < b.value

func `<=`*(a, b: Duration): bool {.inline.} =
  ## Returns ``true`` if ``a`` less or equal ``b``.
  a.value <= b.value

func `<=`*(a, b: Moment): bool {.inline.} =
  ## Returns ``true`` if ``a`` less or equal ``b``.
  a.value <= b.value

func `>`*(a, b: Duration): bool {.inline.} =
  ## Returns ``true`` if ``a`` bigger then ``b``.
  a.value > b.value

func `>`*(a, b: Moment): bool {.inline.} =
  ## Returns ``true`` if ``a`` bigger then ``b``.
  a.value > b.value

func `>=`*(a, b: Duration): bool {.inline.} =
  ## Returns ``true`` if ``a`` bigger or equal ``b``.
  a.value >= b.value

func `>=`*(a, b: Moment): bool {.inline.} =
  ## Returns ``true`` if ``a`` bigger or equal ``b``.
  a.value >= b.value

func `*`*(a: Duration, b: SomeIntegerI64): Duration {.inline.} =
  ## Returns Duration multiplied by scalar integer.
  Duration(value: a.value * int64(b))

func `*`*(a: SomeIntegerI64, b: Duration): Duration {.inline.} =
  ## Returns Duration multiplied by scalar integer.
  Duration(value: int64(a) * b.value)

func `div`*(a: Duration, b: SomeIntegerI64): Duration {.inline.} =
  ## Returns Duration which is result of dividing a Duration by scalar integer.
  Duration(value: a.value div int64(b))

const
  Nanosecond* = Duration(value: 1'i64)
  Microsecond* = Nanosecond * 1_000'i64
  Millisecond* = Microsecond * 1_000'i64
  Second* = Millisecond * 1_000'i64
  Minute* = Second * 60'i64
  Hour* = Minute * 60'i64
  Day* = Hour * 24'i64
  Week* = Day * 7'i64

  ZeroDuration* = Duration(value: 0'i64)
  InfiniteDuration* = Duration(value: high(int64))

template high*(T: typedesc[Moment]): Moment =
  Moment(value: high(int64))

template low*(T: typedesc[Moment]): Moment =
  Moment(value: 0)

template high*(T: typedesc[Duration]): Duration =
  Duration(value: high(int64))

template low*(T: typedesc[Duration]): Duration =
  Duration(value: 0)

func nanoseconds*(v: SomeIntegerI64): Duration {.inline.} =
  ## Initialize Duration with nanoseconds value ``v``.
  Duration(value: int64(v))

func microseconds*(v: SomeIntegerI64): Duration {.inline.} =
  ## Initialize Duration with microseconds value ``v``.
  Duration(value: int64(v) * Microsecond.value)

func milliseconds*(v: SomeIntegerI64): Duration {.inline.} =
  ## Initialize Duration with milliseconds value ``v``.
  Duration(value: int64(v) * Millisecond.value)

func seconds*(v: SomeIntegerI64): Duration {.inline.} =
  ## Initialize Duration with seconds value ``v``.
  Duration(value: int64(v) * Second.value)

func minutes*(v: SomeIntegerI64): Duration {.inline.} =
  ## Initialize Duration with minutes value ``v``.
  Duration(value: int64(v) * Minute.value)

func hours*(v: SomeIntegerI64): Duration {.inline.} =
  ## Initialize Duration with hours value ``v``.
  Duration(value: int64(v) * Hour.value)

func days*(v: SomeIntegerI64): Duration {.inline.} =
  ## Initialize Duration with days value ``v``.
  Duration(value: int64(v) * Day.value)

func weeks*(v: SomeIntegerI64): Duration {.inline.} =
  ## Initialize Duration with weeks value ``v``.
  Duration(value: int64(v) * Week.value)

func nanoseconds*(v: Duration): int64 {.inline.} =
  ## Round Duration ``v`` to nanoseconds.
  v.value

func microseconds*(v: Duration): int64 {.inline.} =
  ## Round Duration ``v`` to microseconds.
  v.value div Microsecond.value

func milliseconds*(v: Duration): int64 {.inline.} =
  ## Round Duration ``v`` to milliseconds.
  v.value div Millisecond.value

func seconds*(v: Duration): int64 {.inline.} =
  ## Round Duration ``v`` to seconds.
  v.value div Second.value

func minutes*(v: Duration): int64 {.inline.} =
  ## Round Duration ``v`` to minutes.
  v.value div Minute.value

func hours*(v: Duration): int64 {.inline.} =
  ## Round Duration ``v`` to hours.
  v.value div Hour.value

func days*(v: Duration): int64 {.inline.} =
  ## Round Duration ``v`` to days.
  v.value div Day.value

func weeks*(v: Duration): int64 {.inline.} =
  ## Round Duration ``v`` to weeks.
  v.value div Week.value

func nanos*(v: SomeIntegerI64): Duration {.inline.} =
  nanoseconds(v)

func micros*(v: SomeIntegerI64): Duration {.inline.} =
  microseconds(v)

func millis*(v: SomeIntegerI64): Duration {.inline.} =
  milliseconds(v)

func secs*(v: SomeIntegerI64): Duration {.inline.} =
  seconds(v)

func nanos*(v: Duration): int64 {.inline.} =
  nanoseconds(v)

func micros*(v: Duration): int64 {.inline.} =
  microseconds(v)

func millis*(v: Duration): int64 {.inline.} =
  milliseconds(v)

func secs*(v: Duration): int64 {.inline.} =
  seconds(v)

template add(a: var string, b: Base10Buf[uint64]) =
  for index in 0 ..< b.len:
    a.add(char(b.data[index]))

func `$`*(a: Duration): string {.inline.} =
  ## Returns string representation of Duration ``a`` as nanoseconds value.
  var res = ""
  var v = a.value

  if v >= Week.value:
    res.add(Base10.toBytes(uint64(v div Week.value)))
    res.add('w')
    v = v mod Week.value
  if v == 0: return res
  if v >= Day.value:
    res.add(Base10.toBytes(uint64(v div Day.value)))
    res.add('d')
    v = v mod Day.value
  if v == 0: return res
  if v >= Hour.value:
    res.add(Base10.toBytes(uint64(v div Hour.value)))
    res.add('h')
    v = v mod Hour.value
  if v == 0: return res
  if v >= Minute.value:
    res.add(Base10.toBytes(uint64(v div Minute.value)))
    res.add('m')
    v = v mod Minute.value
  if v == 0: return res
  if v >= Second.value:
    res.add(Base10.toBytes(uint64(v div Second.value)))
    res.add('s')
    v = v mod Second.value
  if v == 0: return res
  if v >= Millisecond.value:
    res.add(Base10.toBytes(uint64(v div Millisecond.value)))
    res.add('m')
    res.add('s')
    v = v mod Millisecond.value
  if v == 0: return res
  if v >= Microsecond.value:
    res.add(Base10.toBytes(uint64(v div Microsecond.value)))
    res.add('u')
    res.add('s')
    v = v mod Microsecond.value
  if v == 0: return res
  res.add(Base10.toBytes(uint64(v div Nanosecond.value)))
  res.add('n')
  res.add('s')
  res

func `$`*(a: Moment): string {.inline.} =
  ## Returns string representation of Moment ``a`` as nanoseconds value.
  var res = ""
  res.add(Base10.toBytes(uint64(a.value)))
  res.add('n')
  res.add('s')
  res

func isZero*(a: Duration): bool {.inline.} =
  ## Returns ``true`` if Duration ``a`` is ``0``.
  a.value == 0

func isInfinite*(a: Duration): bool {.inline.} =
  ## Returns ``true`` if Duration ``a`` is infinite.
  a.value == InfiniteDuration.value

proc now*(t: typedesc[Moment]): Moment {.inline.} =
  ## Returns current moment in time as Moment.
  Moment(value: int64(fastEpochTimeNano()))

func init*(t: typedesc[Moment], value: int64, precision: Duration): Moment =
  ## Initialize Moment with absolute time value ``value`` with precision
  ## ``precision``.
  Moment(value: value * precision.value)

func epochSeconds*(moment: Moment): int64 =
  moment.value div Second.value

func epochNanoSeconds*(moment: Moment): int64 =
  moment.value

proc fromNow*(t: typedesc[Moment], a: Duration): Moment {.inline.} =
  ## Returns moment in time which is equal to current moment + Duration.
  Moment.now() + a
