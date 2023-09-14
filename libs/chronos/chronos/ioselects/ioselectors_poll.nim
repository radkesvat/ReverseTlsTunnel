#
#
#            Nim's Runtime Library
#        (c) Copyright 2016 Eugene Kabanov
#
#    See the file "copying.txt", included in this
#    distribution, for details about the copyright.
#

# This module implements Posix poll().
import std/tables
import stew/base10

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

type
  SelectorImpl[T] = object
    fds: Table[int32, SelectorKey[T]]
    pollfds: seq[TPollFd]
  Selector*[T] = ref SelectorImpl[T]

type
  SelectEventImpl = object
    rfd: cint
    wfd: cint
  SelectEvent* = ptr SelectEventImpl

proc toString(key: int32): string =
  Base10.toString(uint32(key))

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

proc freeKey[T](s: Selector[T], key: int32) =
  s.fds.del(key)

proc new*(t: typedesc[Selector], T: typedesc): SelectResult[Selector[T]] =
  let selector = Selector[T](
    fds: initTable[int32, SelectorKey[T]](asyncInitialSize)
  )
  ok(selector)

proc close2*[T](s: Selector[T]): SelectResult[void] =
  s.fds.clear()
  s.pollfds.clear()

proc new*(t: typedesc[SelectEvent]): SelectResult[SelectEvent] =
  let flags = {DescriptorFlag.NonBlock, DescriptorFlag.CloseOnExec}
  let pipes = ? createOsPipe(flags, flags)
  var res = cast[SelectEvent](allocShared0(sizeof(SelectEventImpl)))
  res.rfd = pipes.read
  res.wfd = pipes.write
  ok(res)

proc trigger2*(event: SelectEvent): SelectResult[void] =
  var data: uint64 = 1
  let res = handleEintr(osdefs.write(event.wfd, addr data, sizeof(uint64)))
  if res == -1:
    err(osLastError())
  elif res != sizeof(uint64):
    err(OSErrorCode(osdefs.EINVAL))
  else:
    ok()

proc close2*(event: SelectEvent): SelectResult[void] =
  let
    rfd = event.rfd
    wfd = event.wfd
  deallocShared(cast[pointer](event))
  let rres = handleEintr(osdefs.close(rfd))
  if rres == -1:
    discard osdefs.close(wfd)
    return err(osLastError())
  let wres = handleEintr(osdefs.close(wfd))
  if wres == -1:
    err(osLastError())
  else:
    ok()

template toPollEvents(events: set[Event]): cshort =
  var res = cshort(0)
  if Event.Read in events: res = res or POLLIN
  if Event.Write in events: res = res or POLLOUT
  res

template pollAdd[T](s: Selector[T], sock: cint, events: set[Event]) =
  s.pollfds.add(TPollFd(fd: sock, events: toPollEvents(events), revents: 0))

template pollUpdate[T](s: Selector[T], sock: cint, events: set[Event]) =
  var updated = false
  for mitem in s.pollfds.mitems():
    if mitem.fd == sock:
      mitem.events = toPollEvents(events)
      break
  if not(updated):
    raiseAssert "Descriptor [" & $sock & "] is not registered in the queue!"

template pollRemove[T](s: Selector[T], sock: cint) =
  let index =
    block:
      var res = -1
      for key, item in s.pollfds.pairs():
        if item.fd == sock:
          res = key
          break
      res
  if index < 0:
    raiseAssert "Descriptor [" & $sock & "] is not registered in the queue!"
  else:
    s.pollfds.del(index)

proc registerHandle2*[T](s: Selector[T], fd: cint, events: set[Event],
                         data: T): SelectResult[void] =
  let skey = SelectorKey[T](ident: fd, events: events, param: 0, data: data)

  s.addKey(fd, skey)
  if events != {}:
    s.pollAdd(fd, events)
  ok()

proc updateHandle2*[T](s: Selector[T], fd: cint,
                       events: set[Event]): SelectResult[void] =
  const EventsMask = {Event.Timer, Event.Signal, Event.Process, Event.Vnode,
                      Event.User, Event.Oneshot, Event.Error}
  s.fds.withValue(int32(fd), pkey):
    doAssert(pkey[].events * EventsMask == {},
             "Descriptor [" & fd.toString() & "] could not be updated!")
    if pkey[].events != events:
      if pkey[].events == {}:
        s.pollAdd(fd, events)
      else:
        if events != {}:
          s.pollUpdate(fd, events)
        else:
          s.pollRemove(fd)
      pkey.events = events
  do:
    raiseAssert "Descriptor [" & fd.toString() &
                "] is not registered in the selector!"
  ok()

proc registerEvent2*[T](s: Selector[T], ev: SelectEvent,
                        data: T): SelectResult[cint] =
  doAssert(not(isNil(ev)))
  let
    key = SelectorKey[T](ident: ev.rfd, events: {Event.User},
                         param: 0, data: data)

  s.addKey(ev.rfd, key)
  s.pollAdd(ev.rfd, {Event.Read}.toPollEvents())
  ok(ev.rfd)

proc unregister2*[T](s: Selector[T], fd: cint): SelectResult[void] =
  let pkey = s.getKey(fd)
  if pkey.events != {}:
    if {Event.Read, Event.Write, Event.User} * pkey.events != {}:
      s.pollRemove(fd)
  s.freeKey(fd)
  ok()

proc unregister2*[T](s: Selector[T], event: SelectEvent): SelectResult[void] =
  s.unregister2(event.rfd)

proc prepareKey[T](s: Selector[T], event: var TPollfd): Opt[ReadyKey] =
  let
    defaultKey = SelectorKey[T](ident: InvalidIdent)
    fdi32 = int32(event.fd)
    revents = event.revents

  var
    pkey = s.getKey(fdi32)
    rkey = ReadyKey(fd: event.fd)

  # Cleanup all the received events.
  event.revents = 0

  if (revents and POLLIN) != 0:
    if Event.User in pkey.events:
      var data: uint64 = 0
      let res = handleEintr(osdefs.read(event.fd, addr data, sizeof(uint64)))
      if res != sizeof(uint64):
        let errorCode = osLastError()
        if errorCode == EAGAIN:
          return Opt.none(ReadyKey)
        else:
          rkey.events.incl({Event.User, Event.Error})
          rkey.errorCode = errorCode
      else:
        rkey.events.incl(Event.User)
    else:
      rkey.events.incl(Event.Read)

  if (revents and POLLOUT) != 0:
    rkey.events.incl(Event.Write)

  if (revents and POLLERR) != 0 or (revents and POLLHUP) != 0 or
     (revents and POLLNVAL) != 0:
    rkey.events.incl(Event.Error)

  ok(rkey)

proc selectInto2*[T](s: Selector[T], timeout: int,
                     readyKeys: var openArray[ReadyKey]): SelectResult[int] =
  var k = 0

  verifySelectParams(timeout, -1, int(high(cint)))

  let
    maxEventsCount = min(len(s.pollfds), len(readyKeys))
    eventsCount =
      if maxEventsCount > 0:
        let res = handleEintr(poll(addr(s.pollfds[0]), Tnfds(maxEventsCount),
                              timeout))
        if res < 0:
          return err(osLastError())
        res
      else:
        0

  for i in 0 ..< len(s.pollfds):
    if s.pollfds[i].revents != 0:
      let rkey = s.prepareKey(s.pollfds[i]).valueOr: continue
      readyKeys[k] = rkey
      inc(k)
      if k == eventsCount: break

  ok(k)

proc select2*[T](s: Selector[T], timeout: int): SelectResult[seq[ReadyKey]] =
  var res = newSeq[ReadyKey](asyncEventsCount)
  let count = ? selectInto2(s, timeout, res)
  res.setLen(count)
  ok(res)

proc newSelector*[T](): Selector[T] {.
     raises: [Defect, OSError].} =
  let res = Selector.new(T)
  if res.isErr(): raiseOSError(res.error)
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
  let res = registerHandle2(s, cint(fd), events, data)
  if res.isErr(): raiseIOSelectorsError(res.error())

proc updateHandle*[T](s: Selector[T], fd: cint | SocketHandle,
                      events: set[Event]) {.
    raises: [Defect, IOSelectorsException].} =
  let res = updateHandle2(s, cint(fd), events)
  if res.isErr(): raiseIOSelectorsError(res.error())

proc unregister*[T](s: Selector[T], fd: cint | SocketHandle) {.
     raises: [Defect, IOSelectorsException].} =
  let res = unregister2(s, cint(fd))
  if res.isErr(): raiseIOSelectorsError(res.error())

proc unregister*[T](s: Selector[T], event: SelectEvent) {.
    raises: [Defect, IOSelectorsException].} =
  let res = unregister2(s, event)
  if res.isErr(): raiseIOSelectorsError(res.error())

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

proc getFd*[T](s: Selector[T]): int = -1
