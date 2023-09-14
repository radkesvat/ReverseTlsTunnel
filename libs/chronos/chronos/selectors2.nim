#
#
#            Nim's Runtime Library
#        (c) Copyright 2016 Eugene Kabanov
#
#    See the file "copying.txt", included in this
#    distribution, for details about the copyright.
#

## This module allows high-level and efficient I/O multiplexing.
##
## Supported OS primitives: ``epoll``, ``kqueue``, ``poll`` and
## Windows ``select``.
##
## To use threadsafe version of this module, it needs to be compiled
## with both ``-d:threadsafe`` and ``--threads:on`` options.
##
## Supported features: files, sockets, pipes, timers, processes, signals
## and user events.
##
## Fully supported OS: MacOSX, FreeBSD, OpenBSD, NetBSD, Linux (except
## for Android).
##
## Partially supported OS: Windows (only sockets and user events),
## Solaris (files, sockets, handles and user events).
## Android (files, sockets, handles and user events).
##
## TODO: ``/dev/poll``, ``event ports`` and filesystem events.

# Based on std/selectors, but with stricter exception handling and effect
# support - changes could potentially be backported to nim but are not
# backwards-compatible.

import stew/results
import osdefs, osutils, oserrno
export results, oserrno

const
  asyncEventsCount* {.intdefine.} = 64
    ## Number of epoll events retrieved by syscall.
  asyncInitialSize* {.intdefine.} = 64
    ## Initial size of Selector[T]'s array of file descriptors.
  asyncEventEngine* {.strdefine.} =
    when defined(linux):
      "epoll"
    elif defined(macosx) or defined(macos) or defined(ios) or
         defined(freebsd) or defined(netbsd) or defined(openbsd) or
         defined(dragonfly):
      "kqueue"
    elif defined(posix):
      "poll"
    else:
      ""
    ## Engine type which is going to be used by module.

  hasThreadSupport = compileOption("threads")

when defined(nimdoc):

  type
    Selector*[T] = ref object
      ## An object which holds descriptors to be checked for read/write status

    Event* {.pure.} = enum
      ## An enum which hold event types
      Read,        ## Descriptor is available for read
      Write,       ## Descriptor is available for write
      Timer,       ## Timer descriptor is completed
      Signal,      ## Signal is raised
      Process,     ## Process is finished
      Vnode,       ## BSD specific file change
      User,        ## User event is raised
      Error,       ## Error occurred while waiting for descriptor
      VnodeWrite,  ## NOTE_WRITE (BSD specific, write to file occurred)
      VnodeDelete, ## NOTE_DELETE (BSD specific, unlink of file occurred)
      VnodeExtend, ## NOTE_EXTEND (BSD specific, file extended)
      VnodeAttrib, ## NOTE_ATTRIB (BSD specific, file attributes changed)
      VnodeLink,   ## NOTE_LINK (BSD specific, file link count changed)
      VnodeRename, ## NOTE_RENAME (BSD specific, file renamed)
      VnodeRevoke  ## NOTE_REVOKE (BSD specific, file revoke occurred)

    IOSelectorsException* = object of CatchableError

    ReadyKey* = object
      ## An object which holds result for descriptor
      fd* : int ## file/socket descriptor
      events*: set[Event] ## set of events
      errorCode*: OSErrorCode ## additional error code information for
                              ## Error events

    SelectEvent* = object
      ## An object which holds user defined event

  proc newSelector*[T](): Selector[T] =
    ## Creates a new selector

  proc close*[T](s: Selector[T]) =
    ## Closes the selector.

  proc registerHandle*[T](s: Selector[T], fd: int | SocketHandle,
                          events: set[Event], data: T) =
    ## Registers file/socket descriptor ``fd`` to selector ``s``
    ## with events set in ``events``. The ``data`` is application-defined
    ## data, which will be passed when an event is triggered.

  proc updateHandle*[T](s: Selector[T], fd: int | SocketHandle,
                        events: set[Event]) =
    ## Update file/socket descriptor ``fd``, registered in selector
    ## ``s`` with new events set ``event``.

  proc registerTimer*[T](s: Selector[T], timeout: int, oneshot: bool,
                         data: T): int {.discardable.} =
    ## Registers timer notification with ``timeout`` (in milliseconds)
    ## to selector ``s``.
    ##
    ## If ``oneshot`` is ``true``, timer will be notified only once.
    ##
    ## Set ``oneshot`` to ``false`` if you want periodic notifications.
    ##
    ## The ``data`` is application-defined data, which will be passed, when
    ## the timer is triggered.
    ##
    ## Returns the file descriptor for the registered timer.

  proc registerSignal*[T](s: Selector[T], signal: int,
                          data: T): int {.discardable.} =
    ## Registers Unix signal notification with ``signal`` to selector
    ## ``s``.
    ##
    ## The ``data`` is application-defined data, which will be
    ## passed when signal raises.
    ##
    ## Returns the file descriptor for the registered signal.
    ##
    ## **Note:** This function is not supported on ``Windows``.

  proc registerProcess*[T](s: Selector[T], pid: int,
                           data: T): int {.discardable.} =
    ## Registers a process id (pid) notification (when process has
    ## exited) in selector ``s``.
    ##
    ## The ``data`` is application-defined data, which will be passed when
    ## process with ``pid`` has exited.
    ##
    ## Returns the file descriptor for the registered signal.

  proc registerEvent*[T](s: Selector[T], ev: SelectEvent, data: T) =
    ## Registers selector event ``ev`` in selector ``s``.
    ##
    ## The ``data`` is application-defined data, which will be passed when
    ## ``ev`` happens.

  proc registerVnode*[T](s: Selector[T], fd: cint, events: set[Event],
                         data: T) =
    ## Registers selector BSD/MacOSX specific vnode events for file
    ## descriptor ``fd`` and events ``events``.
    ## ``data`` application-defined data, which to be passed, when
    ## vnode event happens.
    ##
    ## **Note:** This function is supported only by BSD and MacOSX.

  proc newSelectEvent*(): SelectEvent =
    ## Creates a new user-defined event.

  proc trigger*(ev: SelectEvent) =
    ## Trigger event ``ev``.

  proc close*(ev: SelectEvent) =
    ## Closes user-defined event ``ev``.

  proc unregister*[T](s: Selector[T], ev: SelectEvent) =
    ## Unregisters user-defined event ``ev`` from selector ``s``.

  proc unregister*[T](s: Selector[T], fd: int|SocketHandle|cint) =
    ## Unregisters file/socket descriptor ``fd`` from selector ``s``.

  proc selectInto*[T](s: Selector[T], timeout: int,
                      results: var openArray[ReadyKey]): int =
    ## Waits for events registered in selector ``s``.
    ##
    ## The ``timeout`` argument specifies the maximum number of milliseconds
    ## the function will be blocked for if no events are ready. Specifying a
    ## timeout of ``-1`` causes the function to block indefinitely.
    ## All available events will be stored in ``results`` array.
    ##
    ## Returns number of triggered events.

  proc select*[T](s: Selector[T], timeout: int): seq[ReadyKey] =
    ## Waits for events registered in selector ``s``.
    ##
    ## The ``timeout`` argument specifies the maximum number of milliseconds
    ## the function will be blocked for if no events are ready. Specifying a
    ## timeout of ``-1`` causes the function to block indefinitely.
    ##
    ## Returns a list of triggered events.

  proc getData*[T](s: Selector[T], fd: SocketHandle|int): var T =
    ## Retrieves application-defined ``data`` associated with descriptor ``fd``.
    ## If specified descriptor ``fd`` is not registered, empty/default value
    ## will be returned.

  proc setData*[T](s: Selector[T], fd: SocketHandle|int, data: var T): bool =
    ## Associate application-defined ``data`` with descriptor ``fd``.
    ##
    ## Returns ``true``, if data was successfully updated, ``false`` otherwise.

  template isEmpty*[T](s: Selector[T]): bool = # TODO: Why is this a template?
    ## Returns ``true``, if there are no registered events or descriptors
    ## in selector.

  template withData*[T](s: Selector[T], fd: SocketHandle|int, value,
                        body: untyped) =
    ## Retrieves the application-data assigned with descriptor ``fd``
    ## to ``value``. This ``value`` can be modified in the scope of
    ## the ``withData`` call.
    ##
    ## .. code-block:: nim
    ##
    ##   s.withData(fd, value) do:
    ##     # block is executed only if ``fd`` registered in selector ``s``
    ##     value.uid = 1000
    ##

  template withData*[T](s: Selector[T], fd: SocketHandle|int, value,
                        body1, body2: untyped) =
    ## Retrieves the application-data assigned with descriptor ``fd``
    ## to ``value``. This ``value`` can be modified in the scope of
    ## the ``withData`` call.
    ##
    ## .. code-block:: nim
    ##
    ##   s.withData(fd, value) do:
    ##     # block is executed only if ``fd`` registered in selector ``s``.
    ##     value.uid = 1000
    ##   do:
    ##     # block is executed if ``fd`` not registered in selector ``s``.
    ##     raise
    ##

  proc contains*[T](s: Selector[T], fd: SocketHandle|int): bool {.inline.} =
    ## Determines whether selector contains a file descriptor.

  proc getFd*[T](s: Selector[T]): int =
    ## Retrieves the underlying selector's file descriptor.
    ##
    ## For *poll* and *select* selectors ``-1`` is returned.

else:
  type
    IOSelectorsException* = object of CatchableError

    SelectResult*[T] = Result[T, OSErrorCode]

    Event* {.pure.} = enum
      Read, Write, Timer, Signal, Process, Vnode, User, Error, Oneshot,
      Finished, VnodeWrite, VnodeDelete, VnodeExtend, VnodeAttrib, VnodeLink,
      VnodeRename, VnodeRevoke

    ReadyKey* = object
      fd* : int
      events*: set[Event]
      errorCode*: OSErrorCode

    SelectorKey[T] = object
      ident: int
      events: set[Event]
      param: int
      data: T

  const
    InvalidIdent = -1

  proc raiseIOSelectorsError[T](message: T) =
    var msg = ""
    when T is string:
      msg.add(message)
    elif T is OSErrorCode:
      msg.add(osErrorMsg(message) & " (code: " & $int(message) & ")")
    else:
      msg.add("Internal Error\n")
    var err = newException(IOSelectorsException, msg)
    raise err

  when asyncEventEngine in ["epoll", "kqueue"]:
    proc blockSignals(newmask: Sigset,
                      oldmask: var Sigset): Result[void, OSErrorCode] =
      var nmask = newmask
      # We do this trick just because Nim's posix.nim has declaration like
      # this:
      # proc pthread_sigmask(a1: cint; a2, a3: var Sigset): cint
      # proc sigprocmask*(a1: cint, a2, a3: var Sigset): cint
      when hasThreadSupport:
        if pthread_sigmask(SIG_BLOCK, nmask, oldmask) == -1:
          err(osLastError())
        else:
          ok()
      else:
        if sigprocmask(SIG_BLOCK, nmask, oldmask) == -1:
          err(osLastError())
        else:
          ok()

    proc unblockSignals(newmask: Sigset,
                        oldmask: var Sigset): Result[void, OSErrorCode] =
      # We do this trick just because Nim's posix.nim has declaration like
      # this:
      # proc pthread_sigmask(a1: cint; a2, a3: var Sigset): cint
      # proc sigprocmask*(a1: cint, a2, a3: var Sigset): cint
      var nmask = newmask
      when hasThreadSupport:
        if pthread_sigmask(SIG_UNBLOCK, nmask, oldmask) == -1:
          err(osLastError())
        else:
          ok()
      else:
        if sigprocmask(SIG_UNBLOCK, nmask, oldmask) == -1:
          err(osLastError())
        else:
          ok()

  template verifySelectParams(timeout, min, max: int) =
    # Timeout of -1 means: wait forever
    # Anything higher is the time to wait in milliseconds.
    doAssert((timeout >= min) and (timeout <= max),
             "Cannot select with incorrect timeout value, got " & $timeout)

when asyncEventEngine == "epoll":
  include ./ioselects/ioselectors_epoll
elif asyncEventEngine == "kqueue":
  include ./ioselects/ioselectors_kqueue
elif asyncEventEngine == "poll":
  include ./ioselects/ioselectors_poll
else:
  {.fatal: "Event engine `" & asyncEventEngine & "` is not supported!".}
