# import overrides/[asyncnet]
import chronos, chronos/asyncsync, chronos/transports/datagram
import chronos/streams/[asyncstream, tlsstream, boundstream]
import std/[tables, sequtils, times, strutils, net, random,hashes]
import globals
export asyncsync

type
    TrustStatus*{.pure.} = enum
        no, pending, yes
    SocketScheme* {.pure.} = enum
        NonSecure, ## Non-secure connection
        Secure     ## Secure TLS connection

    SimpleAddress* = object
        id*: string
        hostname*: string
        port*: uint16

    SocketState* {.pure.} = enum
        Closed      ## Connection has been closed
        Closing,    ## Connection is closing
        Resolving,  ## Resolving remote hostname
        Connecting, ## Connecting to remote server
        Ready,      ## Connected to remote server
        Acquired,   ## Connection is acquired for use
        Error       ## Error happens


    Connection* = ref object
        creation_time*: uint      #creation epochtime
        id*: uint16               #global incremental id
        case kind*: SocketScheme
        of SocketScheme.NonSecure:
            discard
        of SocketScheme.Secure:
            treader*: AsyncStreamReader
            twriter*: AsyncStreamWriter
            tls*: TLSAsyncStream
        transp*: StreamTransport
        reader*: AsyncStreamReader
        writer*: AsyncStreamWriter
        remoteHostname*: string   # sni
        state*: SocketState
        trusted*: TrustStatus     #when fake handshake perfromed
        estabilished*: AsyncEvent #connection has started
        port*: Port               #the port the socket points to
        counter*: uint
        exhausted*: bool
        udp_packets*: uint32

    UdpConnection* = ref object
        creation_time*: uint #creation epochtime
        last_action*:uint    #last action epochtime
        id*: uint16   
        transp*: DatagramTransport
        raddr*: TransportAddress
        port*: Port               #the port the socket points to
        mark*:bool
        bound*:Connection

    Connections* = seq[Connection]
    UdpConnections* = seq[UdpConnection]



var et: uint = 0 #last epoch time
var lgid: uint16 = 1 #last incremental global id

proc new_uid: uint16 =
    result = lgid
    inc lgid

template assignId*(con: Connection or UdpConnection) = con.id = new_uid()



template hit*(conn: UdpConnection)= conn.last_action = et

proc findUdp*(conns:UdpConnections, raddr: TransportAddress): tuple[result: bool, connection: UdpConnection] =
    for el in conns:
        if el.raddr == raddr:
            el.hit()
            return (true,el)
    return (false,nil)


proc findUdp*(conns:UdpConnections, filedesc: AsyncFD): tuple[result: bool, connection: UdpConnection] =
    for el in conns:
        if el.transp.fd == filedesc:
            el.hit()
            return (true,el)
    return (false,nil)



# proc id*(x: UdpConnection): int =
#     ## Computes a Hash from `x`.
#     var h: Hash = 0
#     case x.raddr.family
#         of AddressFamily.IPv4:
#             h = h !& hash(x.raddr.address_v4)
#         of AddressFamily.IPv6:
#             h = h !& hash(x.raddr.address_v6)
#         of AddressFamily.Unix:
#             h = h !& hash(x.raddr.address_un)
#         of AddressFamily.None:
#             h = h !& hash("None")
        
#     h = h !& hash(x.raddr.port)
#     result = int(!$h)


proc isTrusted*(con: Connection): bool = con.trusted == TrustStatus.yes

proc hasID*(cons: Connections or UdpConnections, cid: uint16): bool =
    for el in cons:
        if cid == el.id:
            return true
    return false

template with*(cons: Connections or UdpConnections, cid: uint16, name: untyped, action: untyped) =
    block withconnection:
        for el in cons:
            var `name` {.inject.} = el
            if `name`.id == cid:
                action
                break withconnection

proc remove*(cons: var (Connections or UdpConnections), con: Connection or  UdpConnection or uint16) =
    var index = -1
    when con is Connection or con is UdpConnection:
        for i, el in cons:
            if el == con:
                index = i
                
    when con is uint16:
        for i, el in cons:
            if el.id == con:
                index = i
    
    if index != -1:
        cons.delete(index)

# proc remove*(cons: var seq[uint32], id: uint16) =
#     let i = cons.find(id)
#     if i != -1:
#         cons.del(i)


proc grab*(cons: var Connections ): Connection =
    if cons.len() == 0: return nil
    result = cons[0]
    cons.del(0)
    # result.register_start_time = 0

proc randomPick*(cons: var Connections): Connection =
    if cons.len() == 0: return nil
    let index = rand(cons.high)
    result = cons[index]

    # cons.del(index)
    # result.register_start_time = 0


proc register*(cons: var (Connections or UdpConnections), con: Connection or var UdpConnection) =
    # con.register_start_time = et
    cons.add con



template close*(conn: UdpConnection)= conn.transp.close()
template closeWait*(conn: UdpConnection):untyped = conn.transp.closeWait()
template join*(conn: UdpConnection)= conn.transp.join()
template closed*(conn: UdpConnection): bool = conn.transp.closed()

proc closed*(conn: Connection): bool =
    case conn.kind
    of SocketScheme.NonSecure:
        return conn.reader.closed and conn.writer.closed
    of SocketScheme.Secure:
        return conn.reader.closed and conn.writer.closed and
            conn.treader.closed and conn.twriter.closed


proc close*(conn: Connection) =
    if not(isNil(conn.reader)) and not(conn.reader.closed()):
        conn.reader.close()
    if not(isNil(conn.writer)) and not(conn.writer.closed()):
        conn.writer.close()

    case conn.kind
    of SocketScheme.NonSecure: discard
    of SocketScheme.Secure:
        conn.treader.close()
        conn.twriter.close()
    conn.transp.close()
    conn.state = SocketState.Closing




proc closeWait*(conn: Connection) {.async.} =
    ## Close HttpClientConnectionRef instance ``conn`` and free all the resources.
    if conn.isNil(): return
    if conn.state notin {SocketState.Closing,
                         SocketState.Closed}:
        conn.state = SocketState.Closing
        let pending =
            block:
                var res: seq[Future[void]]
                if not(isNil(conn.reader)) and not(conn.reader.closed()):
                    res.add(conn.reader.closeWait())
                if not(isNil(conn.writer)) and not(conn.writer.closed()):
                    res.add(conn.writer.closeWait())
                res
        if len(pending) > 0: await allFutures(pending)
        case conn.kind
        of SocketScheme.Secure:
            await allFutures(conn.treader.closeWait(), conn.twriter.closeWait())
        of SocketScheme.NonSecure:
            discard
        await conn.transp.closeWait()
        conn.state = SocketState.Closed


proc new*(ctype: typedesc[UdpConnection], transp: DatagramTransport, raddr: TransportAddress,no_id = false): UdpConnection =
    result = UdpConnection(
        id: if no_id: 0 else: new_uid(),
        creation_time: et,
        last_action: et,
        transp: transp,
        raddr: raddr
    )


proc new*(ctype: typedesc[Connection], transp: StreamTransport, scheme: SocketScheme = SocketScheme.NonSecure,
 hostname: string = "",no_id = false): Future[
        Connection] {.async.} =
    if scheme == SocketScheme.Secure:
        assert not hostname.isEmptyOrWhitespace(), "hostname was empty for secure socket!"
    let conn =
        block:
            let res =
                case scheme
                of SocketScheme.NonSecure:
                    let res = Connection(
                    id:  if no_id: 0 else: new_uid(),
                    kind: SocketScheme.NonSecure,
                    transp: transp,
                    reader: newAsyncStreamReader(transp),
                    writer: newAsyncStreamWriter(transp),
                    state: SocketState.Connecting,
                    remoteHostname: hostname,
                    estabilished: newAsyncEvent()
                    )
                    res
                of SocketScheme.Secure:
                    let treader = newAsyncStreamReader(transp)
                    let twriter = newAsyncStreamWriter(transp)
                    # let flags:set[TLSFlags] =  {TLSFlags.NoVerifyHost,TLSFlags.NoVerifyServerName}
                    let flags: set[TLSFlags] = {TLSFlags.CustomStopAfterHandShake}

                    let tls = newTLSClientAsyncStream(treader, twriter, hostname, flags = flags)
                    let res = Connection(
                    id: if no_id: 0 else: new_uid(),
                    kind: SocketScheme.Secure,
                    transp: transp,
                    treader: treader,
                    twriter: twriter,
                    reader: tls.reader,
                    writer: tls.writer,
                    tls: tls,
                    state: SocketState.Connecting,
                    remoteHostname: hostname,
                    estabilished: newAsyncEvent()

                    )
                    res

            case res.kind
            of SocketScheme.Secure:
                try:
                    await res.tls.handshake()
                    res.state = SocketState.Ready
                except TLSStreamProtocolError as exc:
                    await res.closeWait()
                    res.state = SocketState.Error
                    raise exc
                except CatchableError as exc:
                    await res.closeWait()
                    res.state = SocketState.Error
                    raise exc

            of SocketScheme.Nonsecure:
                res.state = SocketState.Ready
            res

    conn.creation_time = et
    conn.trusted = TrustStatus.pending
    conn.estabilished.fire()

    return conn

proc connect*(address: TransportAddress, scheme: SocketScheme = SocketScheme.NonSecure,
    hostname: string = "",no_id = false): Future[Connection] {.async.} =
    let transp =
        try:
            var flags = {SocketFlags.TcpNoDelay, SocketFlags.ReuseAddr}
            if globals.keep_system_limit:
                flags.excl SocketFlags.TcpNoDelay
            await connect(address, flags = flags)
        except CancelledError as exc:
            raise exc
        except CatchableError as exc:
            raise exc

    let con = await Connection.new(transp, scheme, hostname,no_id)
    con.port = address.port
    return con



template trackIdleConnections*(cons: var Connections, age: uint) =
    block:
        proc checkAndRemove() =
            cons.keepIf(proc(x: Connection): bool =
                if x.creation_time != 0:
                    if et - x.creation_time > age:
                        x.close()
                        if globals.log_conn_destory: echo "[Controller] closed a idle connection, ", et - x.creation_time
                        return false
                return true
            )
        proc tracker(){.async.} =
            while true:
                await sleepAsync(timer.seconds(age.int))
                checkAndRemove()
        asyncSpawn tracker()

template trackDeadUdpConnections*(cons: var UdpConnections, age: uint,close :bool) =
    block:
        proc checkAndRemove() =
            cons.keepIf(proc(x: UdpConnection): bool =
                if x.last_action != 0:
                    if et - x.last_action > age:
                        if close:
                            x.close()
                            if not isNil x.bound:
                                x.bound.close()
                                
                        if globals.log_conn_destory: echo "[Controller] closed a dead udp connection, ", et - x.last_action
                        return false
                return true
            )
        proc tracker() {.async.} =
            while true:
                await sleepAsync(timer.seconds(age.int))
                checkAndRemove()
        asyncSpawn tracker()

proc startController*() {.async.} =
    while true:
        et = epochTime().uint
        await sleepAsync(1000)

        # echo GC_getStatistics()
        # allConnections.keepIf(
        #     proc(x: Connection): bool =
        #     if x.action_start_time != 0:
        #         if et - x.action_start_time > globals.max_idle_time:
        #             if x.socket != nil: x.socket.close()
        #             if globals.log_conn_destory: echo "[Controller] closed a idle connection"
        #             return false

        #     if x.register_start_time != 0:
        #         if et - x.register_start_time > globals.max_pool_unused_time:
        #             if x.socket != nil: x.socket.close()
        #             if globals.log_conn_destory: echo "[Controller] closed a unused connection"
        #             return false
        #     return true
        # )

        # when not defined release:
        #     if globals.debug_info:
        #         echo "futures in list : ", getFuturesInProgress().len()
