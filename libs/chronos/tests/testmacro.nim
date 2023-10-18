#                Chronos Test Suite
#            (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[macros, strutils]
import unittest2
import ../chronos

{.used.}

type
  RetValueType = proc(n: int): Future[int] {.async.}
  RetImplicitVoidType = proc(n: int) {.async.}
  RetVoidType = proc(n: int): Future[void] {.async.}

proc asyncRetValue(n: int): Future[int] {.async.} =
  await sleepAsync(n.milliseconds)
  result = n * 10

proc asyncRetVoid(n: int) {.async.} =
  await sleepAsync(n.milliseconds)

proc asyncRetExceptionValue(n: int): Future[int] {.async.} =
  await sleepAsync(n.milliseconds)
  result = n * 10
  if true:
    raise newException(ValueError, "Test exception")

proc asyncRetExceptionVoid(n: int) {.async.} =
  await sleepAsync(n.milliseconds)
  if true:
    raise newException(ValueError, "Test exception")

proc testAwait(): Future[bool] {.async.} =
  var res: int

  await asyncRetVoid(100)
  res = await asyncRetValue(100)
  if res != 1000:
    return false
  if (await asyncRetValue(100)) != 1000:
    return false
  try:
    await asyncRetExceptionVoid(100)
    return false
  except ValueError:
    discard
  res = 0
  try:
    discard await asyncRetExceptionValue(100)
    return false
  except ValueError:
    discard
  if res != 0:
    return false

  block:
    let fn: RetVoidType = asyncRetVoid
    await fn(100)
  block:
    let fn: RetImplicitVoidType = asyncRetVoid
    await fn(100)
  block:
    let fn: RetValueType = asyncRetValue
    if (await fn(100)) != 1000:
      return false

  return true

proc testAwaitne(): Future[bool] {.async.} =
  var res1: Future[void]
  var res2: Future[int]

  res1 = awaitne asyncRetVoid(100)
  res2 = awaitne asyncRetValue(100)
  if res1.failed():
    return false
  if res2.read() != 1000:
    return false

  res1 = awaitne asyncRetExceptionVoid(100)
  if not(res1.failed()):
    return false

  res2 = awaitne asyncRetExceptionValue(100)
  try:
    discard res2.read()
    return false
  except ValueError:
    discard

  return true

template returner =
  # can't use `return 5`
  result = 5
  return

suite "Macro transformations test suite":
  test "`await` command test":
    check waitFor(testAwait()) == true
  test "`awaitne` command test":
    check waitFor(testAwaitne()) == true


  test "template async macro transformation":
    template templatedAsync(name, restype: untyped): untyped =
      proc name(): Future[restype] {.async.} = return @[4]

    templatedAsync(testTemplate, seq[int])
    check waitFor(testTemplate()) == @[4]

    macro macroAsync(name, restype, innerrestype: untyped): untyped =
      quote do:
        proc `name`(): Future[`restype`[`innerrestype`]] {.async.} = return

    type OpenObject = object
    macroAsync(testMacro, seq, OpenObject)
    check waitFor(testMacro()).len == 0

    macro macroAsync2(name, restype, inner1, inner2, inner3, inner4: untyped): untyped =
      quote do:
        proc `name`(): Future[`restype`[`inner1`[`inner2`[`inner3`, `inner4`]]]] {.async.} = return

    macroAsync2(testMacro2, seq, Opt, Result, OpenObject, cstring)
    check waitFor(testMacro2()).len == 0

  test "Future with generics":
    proc gen(T: typedesc): Future[T] {.async.} =
      proc testproc(): Future[T] {.async.} =
        when T is void:
          return
        else:
          return default(T)
      await testproc()

    waitFor gen(void)
    check:
      waitFor(gen(int)) == default(int)

  test "Nested return":
    proc nr: Future[int] {.async.} =
      return
        if 1 == 1:
          return 42
        else:
          33

    check waitFor(nr()) == 42

# There are a few unreacheable statements to ensure that we don't regress in
# generated code
{.push warning[UnreachableCode]: off.}

suite "Macro transformations - completions":
  test "Run closure to completion on return": # issue #415
    var x = 0
    proc test415 {.async.} =
      try:
        return
      finally:
        await sleepAsync(1.milliseconds)
        x = 5
    waitFor(test415())
    check: x == 5

  test "Run closure to completion on defer":
    var x = 0
    proc testDefer {.async.} =
      defer:
        await sleepAsync(1.milliseconds)
        x = 5
      return
    waitFor(testDefer())
    check: x == 5

  test "Run closure to completion with exceptions":
    var x = 0
    proc testExceptionHandling {.async.} =
      try:
        return
      finally:
        try:
          await sleepAsync(1.milliseconds)
          raise newException(ValueError, "")
        except ValueError:
          await sleepAsync(1.milliseconds)
        await sleepAsync(1.milliseconds)
        x = 5
    waitFor(testExceptionHandling())
    check: x == 5

  test "Correct return value when updating result after return":
    proc testWeirdCase: int =
      try: return 33
      finally: result = 55
    proc testWeirdCaseAsync: Future[int] {.async.} =
      try:
        await sleepAsync(1.milliseconds)
        return 33
      finally: result = 55

    check:
        testWeirdCase() == waitFor(testWeirdCaseAsync())
        testWeirdCase() == 55

  test "Correct return value with result assignment in defer":
    proc testWeirdCase: int =
      defer:
        result = 55
      result = 33
    proc testWeirdCaseAsync: Future[int] {.async.} =
      defer:
        result = 55
      await sleepAsync(1.milliseconds)
      return 33

    check:
        testWeirdCase() == waitFor(testWeirdCaseAsync())
        testWeirdCase() == 55

  test "Generic & finally calling async":
    proc testGeneric(T: type): Future[T] {.async.} =
      try:
        try:
          await sleepAsync(1.milliseconds)
          return
        finally:
          await sleepAsync(1.milliseconds)
          await sleepAsync(1.milliseconds)
          result = 11
      finally:
        await sleepAsync(1.milliseconds)
        await sleepAsync(1.milliseconds)
        result = 12
    check waitFor(testGeneric(int)) == 12

    proc testFinallyCallsAsync(T: type): Future[T] {.async.} =
      try:
        await sleepAsync(1.milliseconds)
        return
      finally:
        result = await testGeneric(T)
    check waitFor(testFinallyCallsAsync(int)) == 12

  test "templates returning":
    proc testReturner: Future[int] {.async.} =
      returner
      doAssert false
    check waitFor(testReturner()) == 5

    proc testReturner2: Future[int] {.async.} =
      template returner2 =
        return 6
      returner2
      doAssert false
    check waitFor(testReturner2()) == 6

  test "raising defects":
    proc raiser {.async.} =
      # sleeping to make sure our caller is the poll loop
      await sleepAsync(0.milliseconds)
      raise newException(Defect, "uh-oh")

    let fut = raiser()
    expect(Defect): waitFor(fut)
    check not fut.completed()
    fut.complete()

  test "return result":
    proc returnResult: Future[int] {.async.} =
      var result: int
      result = 12
      return result
    check waitFor(returnResult()) == 12

  test "async in async":
    proc asyncInAsync: Future[int] {.async.} =
      proc a2: Future[int] {.async.} =
        result = 12
      result = await a2()
    check waitFor(asyncInAsync()) == 12
{.pop.}

suite "Macro transformations - implicit returns":
  test "Implicit return":
    proc implicit(): Future[int] {.async.} =
      42

    proc implicit2(): Future[int] {.async.} =
      block:
        42

    proc implicit3(): Future[int] {.async.} =
      try:
        parseInt("error")
      except ValueError:
        42

    proc implicit4(v: bool): Future[int] {.async.} =
      case v
      of false: 5
      of true: 42

    proc implicit5(v: bool): Future[int] {.async.} =
      if v: 42
      else: 5

    proc implicit6(v: ref int): Future[int] {.async.} =
      try:
        parseInt("error")
      except ValueError:
        42
      finally:
        v[] = 42

    proc implicit7(v: bool): Future[int] {.async.} =
      case v
      of false: return 33
      of true: 42

    proc implicit8(v: bool): Future[int] {.async.} =
      case v
      of false: await implicit7(v)
      of true: 42

    proc implicit9(): Future[int] {.async.} =
      result = 42
      result

    let fin = new int
    check:
      waitFor(implicit()) == 42
      waitFor(implicit2()) == 42
      waitFor(implicit3()) == 42
      waitFor(implicit4(true)) == 42
      waitFor(implicit5(true)) == 42
      waitFor(implicit5(false)) == 5
      waitFor(implicit6(fin)) == 42
      fin[] == 42
      waitFor(implicit7(true)) == 42
      waitFor(implicit7(false)) == 33

      waitFor(implicit8(true)) == 42
      waitFor(implicit8(false)) == 33

      waitFor(implicit9()) == 42

suite "Closure iterator's exception transformation issues":
  test "Nested defer/finally not called on return":
    # issue #288
    # fixed by https://github.com/nim-lang/Nim/pull/19933
    var answer = 0
    proc a {.async.} =
      try:
        try:
          await sleepAsync(0.milliseconds)
          return
        finally:
          answer = 32
      finally:
        answer.inc(10)
    waitFor(a())
    check answer == 42

  test "raise-only":
    # https://github.com/status-im/nim-chronos/issues/56
    proc trySync() {.async.} =
      return

    proc x() {.async.} =
      try:
        await trySync()
        return
      except ValueError:
        discard

      raiseAssert "shouldn't reach"

    waitFor(x())

suite "Exceptions tracking":
  template checkNotCompiles(body: untyped) =
    check (not compiles(body))
  test "Can raise valid exception":
    proc test1 {.async.} = raise newException(ValueError, "hey")
    proc test2 {.async, asyncraises: [ValueError].} = raise newException(ValueError, "hey")
    proc test3 {.async, asyncraises: [IOError, ValueError].} =
      if 1 == 2:
        raise newException(ValueError, "hey")
      else:
        raise newException(IOError, "hey")

    proc test4 {.async, asyncraises: [], used.} = raise newException(Defect, "hey")
    proc test5 {.async, asyncraises: [].} = discard
    proc test6 {.async, asyncraises: [].} = await test5()

    expect(ValueError): waitFor test1()
    expect(ValueError): waitFor test2()
    expect(IOError): waitFor test3()
    waitFor test6()

  test "Cannot raise invalid exception":
    checkNotCompiles:
      proc test3 {.async, asyncraises: [IOError].} = raise newException(ValueError, "hey")

  test "Explicit return in non-raising proc":
    proc test(): Future[int] {.async, asyncraises: [].} = return 12
    check:
      waitFor(test()) == 12

  test "Non-raising compatibility":
    proc test1 {.async, asyncraises: [ValueError].} = raise newException(ValueError, "hey")
    let testVar: Future[void] = test1()

    proc test2 {.async.} = raise newException(ValueError, "hey")
    let testVar2: proc: Future[void] = test2

    # Doesn't work unfortunately
    #let testVar3: proc: Future[void] = test1

  test "Cannot store invalid future types":
    proc test1 {.async, asyncraises: [ValueError].} = raise newException(ValueError, "hey")
    proc test2 {.async, asyncraises: [IOError].} = raise newException(IOError, "hey")

    var a = test1()
    checkNotCompiles:
      a = test2()

  test "Await raises the correct types":
    proc test1 {.async, asyncraises: [ValueError].} = raise newException(ValueError, "hey")
    proc test2 {.async, asyncraises: [ValueError, CancelledError].} = await test1()
    checkNotCompiles:
      proc test3 {.async, asyncraises: [CancelledError].} = await test1()

  test "Can create callbacks":
    proc test1 {.async, asyncraises: [ValueError].} = raise newException(ValueError, "hey")
    let callback: proc() {.async, asyncraises: [ValueError].} = test1

  test "Can return values":
    proc test1: Future[int] {.async, asyncraises: [ValueError].} =
      if 1 == 0: raise newException(ValueError, "hey")
      return 12
    proc test2: Future[int] {.async, asyncraises: [ValueError, IOError, CancelledError].} =
      return await test1()

    checkNotCompiles:
      proc test3: Future[int] {.async, asyncraises: [CancelledError].} = await test1()

    check waitFor(test2()) == 12

  test "Manual tracking":
    proc test1: Future[int] {.asyncraises: [ValueError].} =
      result = newFuture[int]()
      result.complete(12)
    check waitFor(test1()) == 12

    proc test2: Future[int] {.asyncraises: [IOError, OSError].} =
      result = newFuture[int]()
      result.fail(newException(IOError, "fail"))
      result.fail(newException(OSError, "fail"))
      checkNotCompiles:
        result.fail(newException(ValueError, "fail"))

    proc test3: Future[void] {.asyncraises: [].} =
      checkNotCompiles:
        result.fail(newException(ValueError, "fail"))

    # Inheritance
    proc test4: Future[void] {.asyncraises: [CatchableError].} =
      result.fail(newException(IOError, "fail"))

  test "Reversed async, asyncraises":
    proc test44 {.asyncraises: [ValueError], async.} = raise newException(ValueError, "hey")
    checkNotCompiles:
      proc test33 {.asyncraises: [IOError], async.} = raise newException(ValueError, "hey")
