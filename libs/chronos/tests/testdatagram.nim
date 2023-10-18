#                Chronos Test Suite
#            (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[strutils, net]
import ".."/chronos/unittest2/asynctests
import ".."/chronos

{.used.}

suite "Datagram Transport test suite":
  const
    TestsCount = 2000
    ClientsCount = 20
    MessagesCount = 20

    m1 = "sendTo(pointer) test (" & $TestsCount & " messages)"
    m2 = "send(pointer) test (" & $TestsCount & " messages)"
    m3 = "sendTo(string) test (" & $TestsCount & " messages)"
    m4 = "send(string) test (" & $TestsCount & " messages)"
    m5 = "sendTo(seq[byte]) test (" & $TestsCount & " messages)"
    m6 = "send(seq[byte]) test (" & $TestsCount & " messages)"
    m7 = "Unbounded multiple clients with messages (" & $ClientsCount &
         " clients x " & $MessagesCount & " messages)"
    m8 = "Bounded multiple clients with messages (" & $ClientsCount &
         " clients x " & $MessagesCount & " messages)"

  proc client1(transp: DatagramTransport,
               raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("REQUEST"):
        var numstr = data[7..^1]
        var num = parseInt(numstr)
        var ans = "ANSWER" & $num
        await transp.sendTo(raddr, addr ans[0], len(ans))
      else:
        var err = "ERROR"
        await transp.sendTo(raddr, addr err[0], len(err))
    else:
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client2(transp: DatagramTransport,
               raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("ANSWER"):
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = counterPtr[] + 1
        if counterPtr[] == TestsCount:
          transp.close()
        else:
          var ta = initTAddress("127.0.0.1:33336")
          var req = "REQUEST" & $counterPtr[]
          await transp.sendTo(ta, addr req[0], len(req))
      else:
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = -1
        transp.close()
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client3(transp: DatagramTransport,
               raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("ANSWER"):
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = counterPtr[] + 1
        if counterPtr[] == TestsCount:
          transp.close()
        else:
          var req = "REQUEST" & $counterPtr[]
          await transp.send(addr req[0], len(req))
      else:
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = -1
        transp.close()
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client4(transp: DatagramTransport,
               raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("ANSWER"):
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = counterPtr[] + 1
        if counterPtr[] == MessagesCount:
          transp.close()
        else:
          var req = "REQUEST" & $counterPtr[]
          await transp.send(addr req[0], len(req))
      else:
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = -1
        transp.close()
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client5(transp: DatagramTransport,
               raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("ANSWER"):
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = counterPtr[] + 1
        if counterPtr[] == MessagesCount:
          transp.close()
        else:
          var req = "REQUEST" & $counterPtr[]
          await transp.sendTo(raddr, addr req[0], len(req))
      else:
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = -1
        transp.close()
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client6(transp: DatagramTransport,
               raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("REQUEST"):
        var numstr = data[7..^1]
        var num = parseInt(numstr)
        var ans = "ANSWER" & $num
        await transp.sendTo(raddr, ans)
      else:
        var err = "ERROR"
        await transp.sendTo(raddr, err)
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client7(transp: DatagramTransport,
               raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("ANSWER"):
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = counterPtr[] + 1
        if counterPtr[] == TestsCount:
          transp.close()
        else:
          var req = "REQUEST" & $counterPtr[]
          await transp.sendTo(raddr, req)
      else:
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = -1
        transp.close()
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client8(transp: DatagramTransport,
               raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("ANSWER"):
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = counterPtr[] + 1
        if counterPtr[] == TestsCount:
          transp.close()
        else:
          var req = "REQUEST" & $counterPtr[]
          await transp.send(req)
      else:
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = -1
        transp.close()
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client9(transp: DatagramTransport,
               raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("REQUEST"):
        var numstr = data[7..^1]
        var num = parseInt(numstr)
        var ans = "ANSWER" & $num
        var ansseq = newSeq[byte](len(ans))
        copyMem(addr ansseq[0], addr ans[0], len(ans))
        await transp.sendTo(raddr, ansseq)
      else:
        var err = "ERROR"
        var errseq = newSeq[byte](len(err))
        copyMem(addr errseq[0], addr err[0], len(err))
        await transp.sendTo(raddr, errseq)
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client10(transp: DatagramTransport,
                raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("ANSWER"):
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = counterPtr[] + 1
        if counterPtr[] == TestsCount:
          transp.close()
        else:
          var req = "REQUEST" & $counterPtr[]
          var reqseq = newSeq[byte](len(req))
          copyMem(addr reqseq[0], addr req[0], len(req))
          await transp.sendTo(raddr, reqseq)
      else:
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = -1
        transp.close()
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc client11(transp: DatagramTransport,
                raddr: TransportAddress): Future[void] {.async.} =
    var pbytes = transp.getMessage()
    var nbytes = len(pbytes)
    if nbytes > 0:
      var data = newString(nbytes + 1)
      copyMem(addr data[0], addr pbytes[0], nbytes)
      data.setLen(nbytes)
      if data.startsWith("ANSWER"):
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = counterPtr[] + 1
        if counterPtr[] == TestsCount:
          transp.close()
        else:
          var req = "REQUEST" & $counterPtr[]
          var reqseq = newSeq[byte](len(req))
          copyMem(addr reqseq[0], addr req[0], len(req))
          await transp.send(reqseq)
      else:
        var counterPtr = cast[ptr int](transp.udata)
        counterPtr[] = -1
        transp.close()
    else:
      ## Read operation failed with error
      var counterPtr = cast[ptr int](transp.udata)
      counterPtr[] = -1
      transp.close()

  proc testPointerSendTo(): Future[int] {.async.} =
    ## sendTo(pointer) test
    var ta = initTAddress("127.0.0.1:33336")
    var counter = 0
    var dgram1 = newDatagramTransport(client1, udata = addr counter, local = ta)
    var dgram2 = newDatagramTransport(client2, udata = addr counter)
    var data = "REQUEST0"
    await dgram2.sendTo(ta, addr data[0], len(data))
    await dgram2.join()
    dgram1.close()
    await dgram1.join()
    result = counter

  proc testPointerSend(): Future[int] {.async.} =
    ## send(pointer) test
    var ta = initTAddress("127.0.0.1:33337")
    var counter = 0
    var dgram1 = newDatagramTransport(client1, udata = addr counter, local = ta)
    var dgram2 = newDatagramTransport(client3, udata = addr counter, remote = ta)
    var data = "REQUEST0"
    await dgram2.send(addr data[0], len(data))
    await dgram2.join()
    dgram1.close()
    await dgram1.join()
    result = counter

  proc testStringSendTo(): Future[int] {.async.} =
    ## sendTo(string) test
    var ta = initTAddress("127.0.0.1:33338")
    var counter = 0
    var dgram1 = newDatagramTransport(client6, udata = addr counter, local = ta)
    var dgram2 = newDatagramTransport(client7, udata = addr counter)
    var data = "REQUEST0"
    await dgram2.sendTo(ta, data)
    await dgram2.join()
    dgram1.close()
    await dgram1.join()
    result = counter

  proc testStringSend(): Future[int] {.async.} =
    ## send(string) test
    var ta = initTAddress("127.0.0.1:33339")
    var counter = 0
    var dgram1 = newDatagramTransport(client6, udata = addr counter, local = ta)
    var dgram2 = newDatagramTransport(client8, udata = addr counter, remote = ta)
    var data = "REQUEST0"
    await dgram2.send(data)
    await dgram2.join()
    dgram1.close()
    await dgram1.join()
    result = counter

  proc testSeqSendTo(): Future[int] {.async.} =
    ## sendTo(string) test
    var ta = initTAddress("127.0.0.1:33340")
    var counter = 0
    var dgram1 = newDatagramTransport(client9, udata = addr counter, local = ta)
    var dgram2 = newDatagramTransport(client10, udata = addr counter)
    var data = "REQUEST0"
    var dataseq = newSeq[byte](len(data))
    copyMem(addr dataseq[0], addr data[0], len(data))
    await dgram2.sendTo(ta, dataseq)
    await dgram2.join()
    dgram1.close()
    await dgram1.join()
    result = counter

  proc testSeqSend(): Future[int] {.async.} =
    ## send(seq) test
    var ta = initTAddress("127.0.0.1:33341")
    var counter = 0
    var dgram1 = newDatagramTransport(client9, udata = addr counter, local = ta)
    var dgram2 = newDatagramTransport(client11, udata = addr counter, remote = ta)
    var data = "REQUEST0"
    var dataseq = newSeq[byte](len(data))
    copyMem(addr dataseq[0], addr data[0], len(data))
    await dgram2.send(data)
    await dgram2.join()
    dgram1.close()
    await dgram1.join()
    result = counter

  #

  proc waitAll(futs: seq[Future[void]]): Future[void] =
    var counter = len(futs)
    var retFuture = newFuture[void]("waitAll")
    proc cb(udata: pointer) =
      dec(counter)
      if counter == 0:
        retFuture.complete()
    for fut in futs:
      fut.addCallback(cb)
    return retFuture

  proc test3(bounded: bool): Future[int] {.async.} =
    var ta: TransportAddress
    if bounded:
      ta = initTAddress("127.0.0.1:33240")
    else:
      ta = initTAddress("127.0.0.1:33241")
    var counter = 0
    var dgram1 = newDatagramTransport(client1, udata = addr counter, local = ta)
    var clients = newSeq[Future[void]](ClientsCount)
    var grams = newSeq[DatagramTransport](ClientsCount)
    var counters = newSeq[int](ClientsCount)
    for i in 0..<ClientsCount:
      var data = "REQUEST0"
      if bounded:
        grams[i] = newDatagramTransport(client4, udata = addr counters[i],
                                        remote = ta)
        await grams[i].send(addr data[0], len(data))
      else:
        grams[i] = newDatagramTransport(client5, udata = addr counters[i])
        await grams[i].sendTo(ta, addr data[0], len(data))
      clients[i] = grams[i].join()

    await waitAll(clients)
    dgram1.close()
    await dgram1.join()
    result = 0
    for i in 0..<ClientsCount:
      result += counters[i]

  proc testConnReset(): Future[bool] {.async.} =
    var ta = initTAddress("127.0.0.1:0")
    var counter = 0
    proc clientMark(transp: DatagramTransport,
                    raddr: TransportAddress): Future[void] {.async.} =
      counter = 1
      transp.close()
    var dgram1 = newDatagramTransport(client1, local = ta)
    var localta = dgram1.localAddress()
    dgram1.close()
    await dgram1.join()
    var dgram2 = newDatagramTransport(clientMark)
    var data = "MESSAGE"
    asyncSpawn dgram2.sendTo(localta, data)
    await sleepAsync(2000.milliseconds)
    result = (counter == 0)
    dgram2.close()
    await dgram2.join()

  proc testTransportClose(): Future[bool] {.async.} =
    var ta = initTAddress("127.0.0.1:45000")
    proc clientMark(transp: DatagramTransport,
                    raddr: TransportAddress): Future[void] {.async.} =
      discard
    var dgram = newDatagramTransport(clientMark, local = ta)
    dgram.close()
    try:
      await wait(dgram.join(), 1.seconds)
      result = true
    except CatchableError:
      discard

  proc testBroadcast(): Future[int] {.async.} =
    const expectMessage = "BROADCAST MESSAGE"
    var ta1 = initTAddress("0.0.0.0:45010")
    var bta = initTAddress("255.255.255.255:45010")
    var res = 0
    proc clientMark(transp: DatagramTransport,
                     raddr: TransportAddress): Future[void] {.async.} =
      var bmsg = transp.getMessage()
      var smsg = cast[string](bmsg)
      if smsg == expectMessage:
        inc(res)
      transp.close()
    var dgram1 = newDatagramTransport(clientMark, local = ta1,
                                      flags = {Broadcast}, ttl = 2)
    await dgram1.sendTo(bta, expectMessage)
    await wait(dgram1.join(), 5.seconds)
    result = res

  proc testAnyAddress(): Future[int] {.async.} =
    var expectStr = "ANYADDRESS MESSAGE"
    var expectSeq = cast[seq[byte]](expectStr)
    let ta = initTAddress("0.0.0.0:0")
    var res = 0
    var event = newAsyncEvent()

    proc clientMark1(transp: DatagramTransport,
                     raddr: TransportAddress): Future[void] {.async.} =
      var bmsg = transp.getMessage()
      var smsg = cast[string](bmsg)
      if smsg == expectStr:
        inc(res)
      event.fire()

    proc clientMark2(transp: DatagramTransport,
                     raddr: TransportAddress): Future[void] {.async.} =
      discard

    var dgram1 = newDatagramTransport(clientMark1, local = ta)
    let la = dgram1.localAddress()
    var dgram2 = newDatagramTransport(clientMark2)
    var dgram3 = newDatagramTransport(clientMark2,
                                      remote = la)
    await dgram2.sendTo(la, addr expectStr[0], len(expectStr))
    await event.wait()
    event.clear()
    await dgram2.sendTo(la, expectStr)
    await event.wait()
    event.clear()
    await dgram2.sendTo(la, expectSeq)
    await event.wait()
    event.clear()
    await dgram3.send(addr expectStr[0], len(expectStr))
    await event.wait()
    event.clear()
    await dgram3.send(expectStr)
    await event.wait()
    event.clear()
    await dgram3.send(expectSeq)
    await event.wait()
    event.clear()

    await dgram1.closeWait()
    await dgram2.closeWait()
    await dgram3.closeWait()

    result = res

  test "close(transport) test":
    check waitFor(testTransportClose()) == true
  test m1:
    check waitFor(testPointerSendTo()) == TestsCount
  test m2:
    check waitFor(testPointerSend()) == TestsCount
  test m3:
    check waitFor(testStringSendTo()) == TestsCount
  test m4:
    check waitFor(testStringSend()) == TestsCount
  test m5:
    check waitFor(testSeqSendTo()) == TestsCount
  test m6:
    check waitFor(testSeqSend()) == TestsCount
  test m7:
    check waitFor(test3(false)) == ClientsCount * MessagesCount
  test m8:
    check waitFor(test3(true)) == ClientsCount * MessagesCount
  test "Datagram connection reset test":
    check waitFor(testConnReset()) == true
  test "Broadcast test":
    check waitFor(testBroadcast()) == 1
  test "0.0.0.0/::0 (INADDR_ANY) test":
    check waitFor(testAnyAddress()) == 6
  test "Transports leak test":
    checkLeaks()
