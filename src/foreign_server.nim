import chronos
import chronos/streams/[tlsstream], chronos/transports/datagram
import std/[strformat, net, openssl, random]
import overrides/[asyncnet]
import print, connection, pipe
from globals import nil

type
    ServerConnectionPoolContext = object
        free_peer_outbounds: Connections
        pending_free_outbounds:int
        used_peer_outbounds: Connections
        outbounds: Connections
        outbounds_udp:UdpConnections

var context = ServerConnectionPoolContext()

# [FWD]
proc poolFrame(create_count: uint = 0)


proc generateFinishHandShakeData(): string =
    #AES default chunk size is 16 so use a multple of 16
    let rlen: uint16 = uint16(16*(6+rand(4)))
    var random_trust_data: string = newStringOfCap(rlen)
    random_trust_data.setLen(rlen)

    copyMem(addr random_trust_data[0], addr(globals.random_str[rand(250)]), rlen)
    copyMem(addr random_trust_data[0], addr globals.tls13_record_layer[0], 3) #tls header
    copyMem(addr random_trust_data[3], addr rlen, 2) #tls len

    let base = 5 + 7 + `mod`(globals.sh5, 7.uint8)
    copyMem(unsafeAddr random_trust_data[base+0], unsafeAddr globals.sh1.uint32, 4)
    copyMem(unsafeAddr random_trust_data[base+4], unsafeAddr globals.sh2.uint32, 4)

    return random_trust_data

proc monitorData(data: string): bool =
    try:
        if len(data) < 16: return false
        let base = 5 + 7 + `mod`(globals.sh5, 7.uint8)

        var sh3_c: uint32
        var sh4_c: uint32

        copyMem(unsafeAddr sh3_c, unsafeAddr data[base+0], 4)
        copyMem(unsafeAddr sh4_c, unsafeAddr data[base+4], 4)


        let chk1 = sh3_c == globals.sh3
        let chk2 = sh4_c == globals.sh4

        return chk1 and chk2
    except:
        return false


proc remoteTrusted(port: Port): Future[Connection] {.async.} =
    var con = await connection.connect(initTAddress(globals.next_route_addr, port))
    con.trusted = TrustStatus.yes
    return con

proc acquireClientConnection(): Future[Connection] {.async.} =
    var found: Connection = nil
    for i in 0..<50:
        found = context.used_peer_outbounds.randomPick()
        if found != nil:
            if not found.closed:
                return found
            else:
                context.used_peer_outbounds.remove(found)

    return nil



proc processConnection(client: Connection) {.async.} =


    proc closeLine(client: Connection, remote: Connection) {.async.} =
        if globals.log_conn_destory: echo "closed client & remote"
        if remote != nil:
            await allFutures(remote.closeWait(), client.closeWait())
        else:
            await client.closeWait()


    proc processUdpRemote(remote: UdpConnection) {.async.} =
        var client = client
      
        let width = globals.full_tls_record_len.int + globals.mux_record_len.int

        try:
            #read
            var pbytes = remote.transp.getMessage()
            var nbytes = len(pbytes)
            if nbytes > 0:
                var data = newStringOfCap(cap = nbytes + width); data.setlen(nbytes + width)
                copyMem(addr data[0 + width], addr pbytes[0], data.len - width)
                if globals.log_data_len: echo &"[processUdpRemote] {data.len()} bytes from remote {client.id} (udp)"

                #write
                if client.closed:
                    client = await acquireClientConnection()
                    if client == nil:
                        echo "[Error] no client for udp ! "
                        return

                packForSend(data, remote.id, remote.port.uint16,flags = {DataFlags.udp})        
                await client.twriter.write(data)
                if globals.log_data_len: echo &"[processUdpRemote] Sent {data.len()} bytes ->  client (udp)"
            else:
                quit "0 byte udp income"
        except:
            if globals.log_conn_error: echo getCurrentExceptionMsg()


    proc processRemote(remote: Connection) {.async.} =
        var client = client
        var data = newStringOfCap(4200)
        try:
            while not remote.closed:
                #read
                data.setlen remote.reader.tsource.offset
                if data.len() == 0:
                    if remote.reader.atEof():
                        break
                    else:
                        discard await remote.reader.readOnce(addr data, 0)
                        continue
                let width = globals.full_tls_record_len.int + globals.mux_record_len.int
                data.setLen(data.len() + width)
                await remote.reader.readExactly(addr data[0 + width], data.len - width)
                if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from remote"

                if client.closed:
                    client = await acquireClientConnection()
                    if client == nil: break

                packForSend(data, remote.id, remote.port.uint16)
                await client.twriter.write(data)
                if globals.log_data_len: echo &"[processRemote] Sent {data.len()} bytes ->  client"

        except:
            if globals.log_conn_error: echo getCurrentExceptionMsg()

        #close
        try:
            if client == nil or client.closed:
                client = await acquireClientConnection()
            if client != nil:   
                await client.twriter.write(closeSignalData(remote.id))
        except:
             if globals.log_conn_error: echo getCurrentExceptionMsg()

        context.outbounds.remove(remote)
        remote.close()

    proc proccessClient() {.async.} =

        var data = newStringOfCap(4200)
        var boundary: uint16 = 0
        var cid: uint16
        var port: uint16
        var flag: uint8
        var moved:bool = false
        try:
            while not client.closed:
                #read
                data.setlen client.treader.tsource.offset
                if data.len() == 0:
                    if client.treader.atEof():
                        break
                    else:
                        discard await client.treader.readOnce(addr data, 0); continue

                
                if not moved and context.free_peer_outbounds.hasID(client.id):
                    moved = true
                    context.free_peer_outbounds.remove(client)
                    context.used_peer_outbounds.register(client)
                    poolFrame()


                if boundary == 0:
                    let width = int(globals.full_tls_record_len + globals.mux_record_len)
                    data.setLen width
                    await client.treader.readExactly(addr data[0], width)
                    copyMem(addr boundary, addr data[3], sizeof(boundary))
                    if boundary == 0: break
                    copyMem(addr cid, addr data[globals.full_tls_record_len], sizeof(cid))
                    copyMem(addr port, addr data[globals.full_tls_record_len.int + sizeof(cid)], sizeof(port))
                    copyMem(addr flag, addr data[globals.full_tls_record_len.int + sizeof(cid) + sizeof(port)], sizeof(flag))
                    cid = cid xor boundary
                    port = port xor boundary
                    flag = flag xor boundary.uint8
                    boundary -= globals.mux_record_len.uint16
                    if boundary == 0:
                        context.outbounds.with(cid, child_remote):
                            context.outbounds.remove(child_remote)
                            child_remote.close()
                            if globals.log_conn_destory: echo "close mux client"

                    continue
                let readable = min(boundary, data.len().uint16)
                boundary -= readable; data.setlen readable
                await client.treader.readExactly(addr data[0], readable.int)
                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes from client"


                if DataFlags.junk in cast[TransferFlags](flag):
                    if globals.log_data_len: echo &"[proccessClient] {data.len()} discarded from client"
                    continue

                #write
                unPackForRead(data)

                if DataFlags.udp in cast[TransferFlags](flag):
                    proc handleDatagram(transp: DatagramTransport,
                        raddr: TransportAddress): Future[void] {.async.} =
                            var (found,connection) = findUdp(context.outbounds_udp,transp.fd)
                            if found:
                                await processUdpRemote(connection)
                            
                    if context.outbounds_udp.hasID(cid):
                        context.outbounds_udp.with(cid,udp_remote):
                            udp_remote.hit()
                            await udp_remote.transp.send(data)
                            if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote (presist udp)"

                    else:
                        let ta = initTAddress(globals.next_route_addr, if globals.multi_port: port.Port else: globals.next_route_port)
                        var transp = newDatagramTransport(handleDatagram, remote = ta)
                        
                        var connection = UdpConnection.new(transp,ta)
                        connection.id = cid
                        context.outbounds_udp.register connection
                        await connection.transp.send(data)
                        if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote (udp)"
                        

                else:
                    if context.outbounds.hasID(cid):
                        context.outbounds.with(cid, child_remote):
                            if not isSet(child_remote.estabilished): await child_remote.estabilished.wait()
                            if not child_remote.closed():
                                await child_remote.writer.write(data)
                                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote"
                    else:
                        var remote = await remoteTrusted(if globals.multi_port: port.Port else: globals.next_route_port)
                        remote.id = cid
                        context.outbounds.register(remote)
                        asyncCheck processRemote(remote)
                        await remote.writer.write(data)
                        if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote"

        except:
            if globals.log_conn_error: echo getCurrentExceptionMsg()

        #close
        context.used_peer_outbounds.remove(client)
        context.free_peer_outbounds.remove(client)
        poolFrame()

        await client.closeWait()


        # await closeLine(client, remote)


    try:
        asyncCheck proccessClient()
    except:
        print getCurrentExceptionMsg()

proc poolFrame(create_count: uint = 0) =
    var count = create_count

    proc create() {.async.} =
        inc context.pending_free_outbounds

        try:
            var con_fut =  connect(initTAddress(globals.iran_addr, globals.iran_port), SocketScheme.Secure, globals.final_target_domain)
            var notimeout = await withTimeout(con_fut,3.secs)
            if notimeout :
                var conn = con_fut.read()
                if globals.log_conn_create: echo "TlsHandsahke complete."
                conn.trusted = TrustStatus.yes


                context.free_peer_outbounds.add conn                
                asyncCheck processConnection(conn)
                await conn.twriter.write(generateFinishHandShakeData())

            else:
                if globals.log_conn_create: echo "Connecting to iran Timed-out!"
                


        except TLSStreamProtocolError as exc:
            if globals.log_conn_create: echo "Tls error, handshake failed because:"
            echo exc.msg

        except CatchableError as exc:
            if globals.log_conn_create: echo "Connection failed because:"
            echo exc.name, ": ", exc.msg
        
        dec context.pending_free_outbounds


    if count == 0:
        var i = uint(context.free_peer_outbounds.len() + context.pending_free_outbounds)

        if i < globals.pool_size div 2:
            count = 2 
        elif i < globals.pool_size:
            count = 1

    if count > 0: #yea yea yea yea but for testing, compiler knows what to do here :)
        for _ in 0..<count:
            asyncCheck create()

proc start*(){.async.} =
    echo &"Mode Foreign Server:  {globals.self_ip} <-> {globals.iran_addr} ({globals.final_target_domain} with ip {globals.final_target_ip})"
    trackIdleConnections(context.free_peer_outbounds, globals.pool_age)
    # just to make sure we always willing to connect to the peer
    while true:
        poolFrame()
        await sleepAsync(5.secs)
        echo "free: ",context.free_peer_outbounds.len,
             "  iran: ", context.used_peer_outbounds.len, " core: ", context.outbounds.len


    trackDeadUdpConnections(context.outbounds_udp,globals.udp_max_idle_time)

    # await sleepAsync(2.secs)
    # poolFrame()

