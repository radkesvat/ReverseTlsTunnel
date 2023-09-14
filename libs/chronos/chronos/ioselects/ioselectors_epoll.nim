#
#
#            Nim's Runtime Library
#        (c) Copyright 2016 Eugene Kabanov
#
#    See the file "copying.txt", included in this
#    distribution, for details about the copyright.
#

# This module implements Linux epoll().
import std/[deques, tables]
import stew/base10

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

type
  SelectorImpl[T] = object
    epollFd: cint
    sigFd: Opt[cint]
    pidFd: Opt[cint]
    fds: Table[int32, SelectorKey[T]]
    signals: Table[int32, SelectorKey[T]]
    processes: Table[int32, SelectorKey[T]]
    signalMask: Sigset
    virtualHoles: Deque[int32]
    virtualId: int32
    childrenExited: bool
    pendingEvents: Deque[ReadyKey]

  Selector*[T] = ref SelectorImpl[T]

  SelectEventImpl = object
    efd: cint

  SelectEvent* = ptr SelectEventImpl

proc getVirtualId[T](s: Selector[T]): SelectResult[int32] =
  if len(s.virtualHoles) > 0:
    ok(s.virtualHoles.popLast())
  else:
    if s.virtualId == low(int32):
      err(oserrno.EMFILE)
    else:
      dec(s.virtualId)
      ok(s.virtualId)

proc isVirtualId(ident: int32): bool =
  ident < 0'i32

proc toString(key: int32|cint|SocketHandle|int): string =
  let fdi32 = when key is int32: key else: int32(key)
  if isVirtualId(fdi32):
    if fdi32 == -1:
      "InvalidIdent"
    else:
      "V" & Base10.toString(uint32(-fdi32))
  else:
    Base10.toString(uint32(fdi32))

template addKey[T](s: Selector[T], key: int32, skey: SelectorKey[T]) =
  if s.fds.hasKeyOrPut(key, skey):
    raiseAssert "Descriptor [" & key.toString() &
                "] is already registered in the selector!"

template getKey[T](s: Selector[T], key: int32): SelectorKey[T] =
  let
    defaultKey = SelectorKey[T](ident: InvalidIdent)
    pkey = s.fds.getOrDefault(key, defaultKey)
  doAssert(pkey.ident != InvalidIdent,
           "Descriptor [" & key.toString() &
           "] is not registered in the selector!")
  pkey

template checkKey[T](s: Selector[T], key: int32): bool =
  s.fds.contains(key)

proc addSignal[T](s: Selector[T], signal: int, skey: SelectorKey[T]) =
  if s.signals.hasKeyOrPut(int32(signal), skey):
    raiseAssert "Signal [" & $signal & "] is already registered in the selector"

template addProcess[T](s: Selector[T], pid: int, skey: SelectorKey[T]) =
  if s.processes.hasKeyOrPut(int32(pid), skey):
    raiseAssert "Process [" & $pid & "] is already registered in the selector"

proc freeKey[T](s: Selector[T], key: int32) =
  s.fds.del(key)
  if isVirtualId(key):
    s.virtualHoles.addFirst(key)

proc freeSignal[T](s: Selector[T], ident: int32) =
  s.signals.del(ident)

proc freeProcess[T](s: Selector[T], ident: int32) =
  s.processes.del(ident)

proc new*(t: typedesc[Selector], T: typedesc): SelectResult[Selector[T]] =
  var nmask: Sigset
  if sigemptyset(nmask) < 0:
    return err(osLastError())
  let epollFd = epoll_create(asyncEventsCount)
  if epollFd < 0:
    return err(osLastError())
  let selector = Selector[T](
    epollFd: epollFd,
    fds: initTable[int32, SelectorKey[T]](asyncInitialSize),
    signalMask: nmask,
    virtualId: -1'i32, # Should start with -1, because `InvalidIdent` == -1
    childrenExited: false,
    virtualHoles: initDeque[int32](),
    pendingEvents: initDeque[ReadyKey]()
  )
  ok(selector)

proc close2*[T](s: Selector[T]): SelectResult[void] =
  s.fds.clear()
  s.signals.clear()
  s.processes.clear()
  s.virtualHoles.clear()
  s.virtualId = -1'i32
  if handleEintr(osdefs.close(s.epollFd)) != 0:
    err(osLastError())
  else:
    ok()

proc new*(t: typedesc[SelectEvent]): SelectResult[SelectEvent] =
  let eFd = eventfd(0, EFD_CLOEXEC or EFD_NONBLOCK)
  if eFd == -1:
    return err(osLastError())
  var res = cast[SelectEvent](allocShared0(sizeof(SelectEventImpl)))
  res.efd = eFd
  ok(res)

proc trigger2*(event: SelectEvent): SelectResult[void] =
  var data: uint64 = 1
  let res = handleEintr(osdefs.write(event.efd, addr data, sizeof(uint64)))
  if res == -1:
    err(osLastError())
  elif res != sizeof(uint64):
    err(oserrno.EINVAL)
  else:
    ok()

proc close2*(event: SelectEvent): SelectResult[void] =
  let evFd = event.efd
  deallocShared(cast[pointer](event))
  let res = handleEintr(osdefs.close(evFd))
  if res == -1:
    err(osLastError())
  else:
    ok()

proc init(t: typedesc[EpollEvent], fdi: cint, events: set[Event]): EpollEvent =
  var res = uint32(EPOLLRDHUP)
  if Event.Read in events: res = res or uint32(EPOLLIN)
  if Event.Write in events: res = res or uint32(EPOLLOUT)
  if Event.Oneshot in events: res = res or uint32(EPOLLONESHOT)
  # We need this double conversion of type because otherwise in x64 environment
  # negative cint could be converted to big uint64.
  EpollEvent(events: res, data: EpollData(u64: uint64(uint32(fdi))))

proc registerHandle2*[T](s: Selector[T], fd: cint, events: set[Event],
                         data: T): SelectResult[void] =
  let skey = SelectorKey[T](ident: fd, events: events, param: 0, data: data)

  s.addKey(fd, skey)

  if events != {}:
    let epollEvents = EpollEvent.init(fd, events)
    if epoll_ctl(s.epollFd, EPOLL_CTL_ADD, fd, unsafeAddr(epollEvents)) != 0:
      s.freeKey(fd)
      return err(osLastError())
  ok()

proc updateHandle2*[T](s: Selector[T], fd: cint,
                       events: set[Event]): SelectResult[void] =
  const EventsMask = {Event.Timer, Event.Signal, Event.Process, Event.Vnode,
                      Event.User, Event.Oneshot, Event.Error}
  s.fds.withValue(int32(fd), pkey):
    doAssert(pkey[].events * EventsMask == {},
             "Descriptor [" & fd.toString() & "] could not be updated!")
    if pkey[].events != events:
      let epollEvents = EpollEvent.init(fd, events)
      if pkey[].events == {}:
        if epoll_ctl(s.epollFd, EPOLL_CTL_ADD, fd,
                     unsafeAddr(epollEvents)) != 0:
          return err(osLastError())
      else:
        if events != {}:
          if epoll_ctl(s.epollFd, EPOLL_CTL_MOD, fd,
                       unsafeAddr(epollEvents)) != 0:
            return err(osLastError())
        else:
          if epoll_ctl(s.epollFd, EPOLL_CTL_DEL, fd,
                       unsafeAddr epollEvents) != 0:
            return err(osLastError())
      pkey.events = events
  do:
    raiseAssert "Descriptor [" & fd.toString() &
                "] is not registered in the selector!"
  ok()

proc blockSignal[T](s: Selector[T], signal: int): SelectResult[bool] =
  let isMember = sigismember(s.signalMask, cint(signal))
  if isMember < 0:
    err(osLastError())
  elif isMember > 0:
    ok(false)
  else:
    var omask, nmask: Sigset
    if sigemptyset(nmask) < 0:
      return err(osLastError())
    if sigemptyset(omask) < 0:
      return err(osLastError())
    if sigaddset(nmask, cint(signal)) < 0:
      return err(osLastError())
    ? blockSignals(nmask, omask)
    if sigaddset(s.signalMask, cint(signal)) < 0:
      # Try to restore previous state of signals mask
      let errorCode = osLastError()
      discard unblockSignals(nmask, omask)
      return err(errorCode)
    ok(true)

proc unblockSignal[T](s: Selector[T], signal: int): SelectResult[bool] =
  let isMember = sigismember(s.signalMask, cint(signal))
  if isMember < 0:
    err(osLastError())
  elif isMember == 0:
    ok(false)
  else:
    var omask, nmask: Sigset
    if sigemptyset(nmask) < 0:
      return err(osLastError())
    if sigemptyset(omask) < 0:
      return err(osLastError())
    if sigaddset(nmask, cint(signal)) < 0:
      return err(osLastError())
    ? unblockSignals(nmask, omask)
    if sigdelset(s.signalMask, cint(signal)) < 0:
      # Try to restore previous state of signals mask
      let errorCode = osLastError()
      discard blockSignals(nmask, omask)
      return err(errorCode)
    ok(true)

template checkSignal(signal: int) =
  doAssert((signal >= 0) and (signal <= int(high(int32))),
           "Invalid signal value [" & $signal & "]")

proc registerSignalEvent[T](s: Selector[T], signal: int,
                            events: set[Event], param: int,
                            data: T): SelectResult[cint] =
  checkSignal(signal)

  let
    fdi32 = ? s.getVirtualId()
    selectorKey = SelectorKey[T](ident: signal, events: events,
                                param: param, data: data)
    signalKey = SelectorKey[T](ident: fdi32, events: events,
                               param: param, data: data)

  s.addKey(fdi32, selectorKey)
  s.addSignal(signal, signalKey)

  let mres =
    block:
      let res = s.blockSignal(signal)
      if res.isErr():
        s.freeKey(fdi32)
        s.freeSignal(int32(signal))
        return err(res.error())
      res.get()

  if not(mres):
    raiseAssert "Signal [" & $signal & "] could have only one handler at " &
                "the same time!"

  if s.sigFd.isSome():
    let res = signalfd(s.sigFd.get(), s.signalMask,
                       SFD_NONBLOCK or SFD_CLOEXEC)
    if res == -1:
      let errorCode = osLastError()
      s.freeKey(fdi32)
      s.freeSignal(int32(signal))
      discard s.unblockSignal(signal)
      return err(errorCode)
  else:
    let sigFd = signalfd(-1, s.signalMask, SFD_NONBLOCK or SFD_CLOEXEC)
    if sigFd == -1:
      let errorCode = osLastError()
      s.freeKey(fdi32)
      s.freeSignal(int32(signal))
      discard s.unblockSignal(signal)
      return err(errorCode)

    let fdKey = SelectorKey[T](ident: sigFd, events: {Event.Signal})
    s.addKey(sigFd, fdKey)

    let event = EpollEvent.init(sigFd, {Event.Read})
    if epoll_ctl(s.epollFd, EPOLL_CTL_ADD, sigFd, unsafeAddr(event)) != 0:
      let errorCode = osLastError()
      s.freeKey(fdi32)
      s.freeSignal(int32(signal))
      s.freeKey(sigFd)
      discard s.unblockSignal(signal)
      discard handleEintr(osdefs.close(sigFd))
      return err(errorCode)

    s.sigFd = Opt.some(sigFd)

  ok(cint(fdi32))

proc registerSignal*[T](s: Selector[T], signal: int,
                       data: T): SelectResult[cint] =
  registerSignalEvent(s, signal, {Event.Signal}, 0, data)

proc registerTimer2*[T](s: Selector[T], timeout: int, oneshot: bool,
                        data: T): SelectResult[cint] =
  let timerFd = timerfd_create(CLOCK_MONOTONIC, TFD_CLOEXEC or TFD_NONBLOCK)
  if timerFd == -1:
    return err(osLastError())

  let
    fdi32 = int32(timerFd)
    (key, event) =
      if oneshot:
        (
          SelectorKey[T](ident: timerFd, events: {Event.Timer, Event.Oneshot},
                         param: 0, data: data),
          EpollEvent.init(timerFd, {Event.Read, Event.Oneshot})
        )
      else:
        (
          SelectorKey[T](ident: timerFd, events: {Event.Timer},
                         param: 0, data: data),
          EpollEvent.init(timerFd, {Event.Read})
        )
  var timeStruct =
    if oneshot:
      Itimerspec(
        it_interval: Timespec(tv_sec: osdefs.Time(0), tv_nsec: 0),
        it_value: Timespec(tv_sec: osdefs.Time(timeout div 1_000),
                           tv_nsec: (timeout %% 1000) * 1_000_000)
      )
    else:
      Itimerspec(
        it_interval: Timespec(tv_sec: osdefs.Time(timeout div 1_000),
                              tv_nsec: 0),
        it_value: Timespec(tv_sec: osdefs.Time(timeout div 1_000),
                           tv_nsec: 0),
      )

  s.addKey(fdi32, key)

  var oldTs = Itimerspec()
  if timerfd_settime(timerFd, cint(0), timeStruct, oldTs) != 0:
    let errorCode = osLastError()
    s.freeKey(fdi32)
    discard handleEintr(osdefs.close(timerFd))
    return err(errorCode)

  if epoll_ctl(s.epollFd, EPOLL_CTL_ADD, timerFd, unsafeAddr(event)) != 0:
    let errorCode = osLastError()
    s.freeKey(fdi32)
    discard handleEintr(osdefs.close(timerFd))
    return err(errorCode)

  ok(cint(fdi32))

proc registerEvent2*[T](s: Selector[T], ev: SelectEvent,
                        data: T): SelectResult[cint] =
  doAssert(not(isNil(ev)))
  let
    key = SelectorKey[T](ident: ev.efd, events: {Event.User},
                         param: 0, data: data)
    event = EpollEvent.init(ev.efd, {Event.Read})

  s.addKey(ev.efd, key)

  if epoll_ctl(s.epollFd, EPOLL_CTL_ADD, ev.efd, unsafeAddr(event)) != 0:
    s.freeKey(ev.efd)
    return err(osLastError())

  ok(ev.efd)

template checkPid(pid: int) =
  when sizeof(int) == 8:
    doAssert(pid >= 0 and pid <= int(high(uint32)),
             "Invalid process idientified (pid) value")
  else:
    doAssert(pid >= 0 and pid <= high(int32),
             "Invalid process idientified (pid) value")

proc registerProcess*[T](s: Selector, pid: int, data: T): SelectResult[cint] =
  checkPid(pid)

  let
    fdi32 = ? s.getVirtualId()
    events = {Event.Process, Event.Oneshot}
    selectorKey = SelectorKey[T](ident: pid, events: events, param: 0,
                                 data: data)
    processKey = SelectorKey[T](ident: fdi32, events: events, param: 0,
                                data: data)

  s.addProcess(pid, processKey)
  s.addKey(fdi32, selectorKey)

  if s.pidFd.isNone():
    let res = registerSignalEvent(s, int(SIGCHLD), {Event.Signal}, 0, data)
    if res.isErr():
      s.freeKey(fdi32)
      s.freeProcess(int32(pid))
      return err(res.error())
    s.pidFd = Opt.some(cast[cint](res.get()))

  ok(cint(fdi32))

proc unregister2*[T](s: Selector[T], fd: cint): SelectResult[void] =
  let
    fdi32 = int32(fd)
    pkey = s.getKey(fdi32)

  if pkey.events != {}:
    if {Event.Read, Event.Write, Event.User} * pkey.events != {}:
      if epoll_ctl(s.epollFd, EPOLL_CTL_DEL, cint(pkey.ident), nil) != 0:
        return err(osLastError())

    elif Event.Timer in pkey.events:
      if Event.Finished notin pkey.events:
        if epoll_ctl(s.epollFd, EPOLL_CTL_DEL, fd, nil) != 0:
          let errorCode = osLastError()
          discard handleEintr(osdefs.close(fd))
          return err(errorCode)
      if handleEintr(osdefs.close(fd)) == -1:
        return err(osLastError())

    elif Event.Signal in pkey.events:
      if not(s.signals.hasKey(int32(pkey.ident))):
        raiseAssert "Signal " & pkey.ident.toString() &
                    " is not registered in the selector!"
      let sigFd =
        block:
          doAssert(s.sigFd.isSome(), "signalfd descriptor is missing")
          s.sigFd.get()

      s.freeSignal(int32(pkey.ident))

      if len(s.signals) > 0:
        let res = signalfd(sigFd, s.signalMask, SFD_NONBLOCK or SFD_CLOEXEC)
        if res == -1:
          let errorCode = osLastError()
          discard s.unblockSignal(pkey.ident)
          return err(errorCode)
      else:
        s.freeKey(sigFd)
        s.sigFd = Opt.none(cint)

        if epoll_ctl(s.epollFd, EPOLL_CTL_DEL, sigFd, nil) != 0:
          let errorCode = osLastError()
          discard handleEintr(osdefs.close(sigFd))
          discard s.unblockSignal(pkey.ident)
          return err(errorCode)

        if handleEintr(osdefs.close(sigFd)) != 0:
          let errorCode = osLastError()
          discard s.unblockSignal(pkey.ident)
          return err(errorCode)

      let mres = ? s.unblockSignal(pkey.ident)
      doAssert(mres, "Signal is not present in stored mask!")

    elif Event.Process in pkey.events:
      if not(s.processes.hasKey(int32(pkey.ident))):
        raiseAssert "Process " & pkey.ident.toString() &
                    " is not registered in the selector!"

      let pidFd =
        block:
          doAssert(s.pidFd.isSome(), "process descriptor is missing")
          s.pidFd.get()

      s.freeProcess(int32(pkey.ident))

      # We need to filter pending events queue for just unregistered process.
      if len(s.pendingEvents) > 0:
        s.pendingEvents =
          block:
            var res = initDeque[ReadyKey](len(s.pendingEvents))
            for item in s.pendingEvents.items():
              if item.fd != fdi32:
                res.addLast(item)
            res

      if len(s.processes) == 0:
        s.pidFd = Opt.none(cint)
        let res = s.unregister2(pidFd)
        if res.isErr():
          return err(res.error())

  s.freeKey(fdi32)
  ok()

proc unregister2*[T](s: Selector[T], event: SelectEvent): SelectResult[void] =
  s.unregister2(event.efd)

proc prepareKey[T](s: Selector[T], event: EpollEvent): Opt[ReadyKey] =
  let
    defaultKey = SelectorKey[T](ident: InvalidIdent)
    fdi32 =
      block:
        doAssert(event.data.u64 <= uint64(high(uint32)),
                 "Invalid user data value in epoll event object")
        cast[int32](event.data.u64)

  var
    pkey = s.getKey(fdi32)
    rkey = ReadyKey(fd: fdi32)

  if (event.events and EPOLLERR) != 0:
    rkey.events.incl(Event.Error)
    rkey.errorCode = oserrno.ECONNRESET

  if (event.events and EPOLLHUP) != 0 or (event.events and EPOLLRDHUP) != 0:
    rkey.events.incl(Event.Error)
    rkey.errorCode = oserrno.ECONNRESET

  if (event.events and EPOLLOUT) != 0:
    rkey.events.incl(Event.Write)

  if (event.events and EPOLLIN) != 0:
    if Event.Read in pkey.events:
      rkey.events.incl(Event.Read)

    elif Event.Timer in pkey.events:
      var data: uint64
      rkey.events.incl(Event.Timer)
      let res = handleEintr(osdefs.read(fdi32, addr data, sizeof(uint64)))
      if res != sizeof(uint64):
        rkey.events.incl(Event.Error)
        rkey.errorCode = osLastError()

    elif Event.Signal in pkey.events:
      var data: SignalFdInfo
      let res = handleEintr(osdefs.read(fdi32, addr data, sizeof(SignalFdInfo)))
      if res != sizeof(SignalFdInfo):
        # We could not obtain `signal` number so we can't report an error to
        # proper handler.
        return Opt.none(ReadyKey)
      if data.ssi_signo != uint32(SIGCHLD) or len(s.processes) == 0:
        let skey = s.signals.getOrDefault(cast[int32](data.ssi_signo),
                                          defaultKey)
        if skey.ident == InvalidIdent:
          # We do not have any handlers for received event so we can't report
          # an error to proper handler.
          return Opt.none(ReadyKey)
        rkey.events.incl(Event.Signal)
        rkey.fd = skey.ident
      else:
        # Indicate that SIGCHLD has been seen.
        s.childrenExited = true
        # Current signal processing.
        let pidKey = s.processes.getOrDefault(cast[int32](data.ssi_pid),
                                              defaultKey)
        if pidKey.ident == InvalidIdent:
          # We do not have any handlers with signal's pid.
          return Opt.none(ReadyKey)
        rkey.events.incl({Event.Process, Event.Oneshot, Event.Finished})
        rkey.fd = pidKey.ident
        # Mark process descriptor inside fds table as finished.
        var fdKey = s.fds.getOrDefault(int32(pidKey.ident), defaultKey)
        if fdKey.ident != InvalidIdent:
          fdKey.events.incl(Event.Finished)
          s.fds[int32(pidKey.ident)] = fdKey

    elif Event.User in pkey.events:
      var data: uint64
      let res = handleEintr(osdefs.read(fdi32, addr data, sizeof(uint64)))
      if res != sizeof(uint64):
        let errorCode = osLastError()
        case errorCode
        of oserrno.EAGAIN:
          return Opt.none(ReadyKey)
        else:
          rkey.events.incl({Event.User, Event.Error})
          rkey.errorCode = errorCode
      else:
        rkey.events.incl(Event.User)

  if Event.Oneshot in rkey.events:
    if Event.Timer in rkey.events:
      if epoll_ctl(s.epollFd, EPOLL_CTL_DEL, fdi32, nil) != 0:
        rkey.events.incl(Event.Error)
        rkey.errorCode = osLastError()
      # we are marking key with `Finished` event, to avoid double decrease.
      rkey.events.incl(Event.Finished)
      pkey.events.incl(Event.Finished)
      s.fds[fdi32] = pkey

  ok(rkey)

proc checkProcesses[T](s: Selector[T]) =
  # If SIGCHLD has been seen we need to check all processes we are monitoring
  # for completion, because in Linux SIGCHLD could be masked.
  # You can get more information in article "Signalfd is useless" -
  # https://ldpreload.com/blog/signalfd-is-useless?reposted-on-request
  if not(s.childrenExited):
    return

  let
    defaultKey = SelectorKey[T](ident: InvalidIdent)
    flags = WNOHANG or WNOWAIT or WSTOPPED or WEXITED
  s.childrenExited = false
  for pid, pidKey in s.processes.pairs():
    var fdKey = s.fds.getOrDefault(int32(pidKey.ident), defaultKey)
    if fdKey.ident != InvalidIdent:
      if Event.Finished notin fdKey.events:
        var sigInfo = SigInfo()
        let res = handleEintr(osdefs.waitid(P_PID, cast[Id](pid),
                                            sigInfo, flags))
        if (res == 0) and (cint(sigInfo.si_pid) == cint(pid)):
          fdKey.events.incl(Event.Finished)
          let rkey = ReadyKey(fd: pidKey.ident, events: fdKey.events)
          s.pendingEvents.addLast(rkey)
          s.fds[int32(pidKey.ident)] = fdKey

proc selectInto2*[T](s: Selector[T], timeout: int,
                     readyKeys: var openArray[ReadyKey]
                    ): SelectResult[int] =
  var
    queueEvents: array[asyncEventsCount, EpollEvent]
    k: int = 0

  verifySelectParams(timeout, -1, int(high(cint)))

  let
    maxEventsCount = min(len(queueEvents), len(readyKeys))
    maxPendingEventsCount = min(maxEventsCount, len(s.pendingEvents))
    maxNewEventsCount = max(maxEventsCount - maxPendingEventsCount, 0)

  let
    eventsCount =
      if maxNewEventsCount > 0:
        let res = handleEintr(epoll_wait(s.epollFd, addr(queueEvents[0]),
                                         cint(maxNewEventsCount),
                                         cint(timeout)))
        if res < 0:
          return err(osLastError())
        res
      else:
        0

  s.childrenExited = false

  for i in 0 ..< eventsCount:
    let rkey = s.prepareKey(queueEvents[i]).valueOr: continue
    readyKeys[k] = rkey
    inc(k)

  s.checkProcesses()

  let pendingEventsCount = min(len(readyKeys) - eventsCount,
                               len(s.pendingEvents))

  for i in 0 ..< pendingEventsCount:
    readyKeys[k] = s.pendingEvents.popFirst()
    inc(k)

  ok(k)

proc select2*[T](s: Selector[T], timeout: int): SelectResult[seq[ReadyKey]] =
  var res = newSeq[ReadyKey](asyncEventsCount)
  let count = ? selectInto2(s, timeout, res)
  res.setLen(count)
  ok(res)

proc newSelector*[T](): Selector[T] {.
     raises: [Defect, OSError].} =
  let res = Selector.new(T)
  if res.isErr(): raiseOSError(res.error())
  res.get()

proc close*[T](s: Selector[T]) {.
     raises: [Defect, IOSelectorsException].} =
  let res = s.close2()
  if res.isErr(): raiseIOSelectorsError(res.error())

proc newSelectEvent*(): SelectEvent {.
     raises: [Defect, IOSelectorsException].} =
  let res = SelectEvent.new()
  if res.isErr(): raiseIOSelectorsError(res.error())
  res.get()

proc trigger*(event: SelectEvent) {.
     raises: [Defect, IOSelectorsException].} =
  let res = event.trigger2()
  if res.isErr(): raiseIOSelectorsError(res.error())

proc close*(event: SelectEvent) {.
     raises: [Defect, IOSelectorsException].} =
  let res = event.close2()
  if res.isErr(): raiseIOSelectorsError(res.error())

proc registerHandle*[T](s: Selector[T], fd: cint | SocketHandle,
                        events: set[Event], data: T) {.
    raises: [Defect, IOSelectorsException].} =
  let res = registerHandle2(s, fd, events, data)
  if res.isErr(): raiseIOSelectorsError(res.error())

proc updateHandle*[T](s: Selector[T], fd: cint | SocketHandle,
                      events: set[Event]) {.
    raises: [Defect, IOSelectorsException].} =
  let res = updateHandle2(s, fd, events)
  if res.isErr(): raiseIOSelectorsError(res.error())

proc unregister*[T](s: Selector[T], fd: cint | SocketHandle) {.
     raises: [Defect, IOSelectorsException].} =
  let res = unregister2(s, fd)
  if res.isErr(): raiseIOSelectorsError(res.error())

proc unregister*[T](s: Selector[T], event: SelectEvent) {.
    raises: [Defect, IOSelectorsException].} =
  let res = unregister2(s, event)
  if res.isErr(): raiseIOSelectorsError(res.error())

proc registerTimer*[T](s: Selector[T], timeout: int, oneshot: bool,
                       data: T): cint {.
    discardable, raises: [Defect, IOSelectorsException].} =
  let res = registerTimer2(s, timeout, oneshot, data)
  if res.isErr(): raiseIOSelectorsError(res.error())
  res.get()

proc registerEvent*[T](s: Selector[T], event: SelectEvent,
                       data: T) {.
     raises: [Defect, IOSelectorsException].} =
  let res = registerEvent2(s, event, data)
  if res.isErr(): raiseIOSelectorsError(res.error())

proc selectInto*[T](s: Selector[T], timeout: int,
                    readyKeys: var openArray[ReadyKey]): int {.
     raises: [Defect, IOSelectorsException].} =
  let res = selectInto2(s, timeout, readyKeys)
  if res.isErr(): raiseIOSelectorsError(res.error())
  res.get()

proc select*[T](s: Selector[T], timeout: int): seq[ReadyKey] =
  let res = select2(s, timeout)
  if res.isErr(): raiseIOSelectorsError(res.error())
  res.get()

proc contains*[T](s: Selector[T], fd: SocketHandle|cint): bool {.inline.} =
  s.checkKey(int32(fd))

proc setData*[T](s: Selector[T], fd: SocketHandle|cint, data: T): bool =
  s.fds.withValue(int32(fd), skey):
    skey[].data = data
    return true
  do:
    return false

template withData*[T](s: Selector[T], fd: SocketHandle|cint, value,
                      body: untyped) =
  s.fds.withValue(int32(fd), skey):
    var value = addr(skey[].data)
    body

template withData*[T](s: Selector[T], fd: SocketHandle|cint, value, body1,
                      body2: untyped) =
  s.fds.withValue(int32(fd), skey):
    var value = addr(skey[].data)
    body1
  do:
    body2

proc getFd*[T](s: Selector[T]): cint = s.epollFd
