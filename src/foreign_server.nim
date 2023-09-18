import chronos
import chronos/streams/[tlsstream]
import std/[strformat, net, openssl, random]
import overrides/[asyncnet]
import print, connection, pipe
from globals import nil

type
    ServerConnectionPoolContext = object
        free_peer_outbounds: Connections
        used_peer_outbounds: Connections
        outbound: Connections

var context = ServerConnectionPoolContext()
var mux = false

# [FWD]
proc poolFrame(create_count: uint = 0)


proc generateFinishHandShakeData(): string =
    #AES default chunk size is 16 so use a multple of 16
    let rlen: uint16 = uint16(16*(6+rand(4)))
    var random_trust_data: string
    random_trust_data.setLen(rlen)

    copyMem(addr random_trust_data[0], addr(globals.random_str[rand(250)]), rlen)
    copyMem(addr random_trust_data[0], addr globals.tls13_record_layer[0], 3) #tls header
    copyMem(addr random_trust_data[3], addr rlen, 2) #tls len

    let base = 5 + 7 + `mod`(globals.sh5, 7.uint8)
    copyMem(unsafeAddr random_trust_data[base+0], unsafeAddr globals.sh1.uint32, 4)
    copyMem(unsafeAddr random_trust_data[base+4], unsafeAddr globals.sh2.uint32, 4)

    return random_trust_data

proc monitorData(data: string): tuple[trust: bool, port: uint32] =
    var port: uint32
    try:
        if len(data) < 16: return (false, port)
        let base = 5 + 7 + `mod`(globals.sh5, 7.uint8)

        var sh3_c: uint32
        var sh4_c: uint32

        copyMem(unsafeAddr sh3_c, unsafeAddr data[base+0], 4)
        copyMem(unsafeAddr sh4_c, unsafeAddr data[base+4], 4)
        copyMem(unsafeAddr port, unsafeAddr data[base+8], 4)


        let chk1 = sh3_c == globals.sh3
        let chk2 = sh4_c == globals.sh4

        return (chk1 and chk2, port)
    except:
        return (false, port)


proc remoteTrusted(port: Port): Future[Connection] {.async.} =
    var con = await connection.connect(initTAddress(globals.next_route_addr, port))
    con.trusted = TrustStatus.yes
    return con

proc processConnection(client: Connection) {.async.} =


    proc closeLine(client: Connection, remote: Connection) {.async.} =
        if globals.log_conn_destory: echo "closed client & remote"
        if remote != nil:
            await allFutures(remote.closeWait(), client.closeWait())
        else:
            await client.closeWait()

    proc processRemote(remote: Connection) {.async.} =
        var data = newString(len = 0)
        try:
            while not remote.closed:
                block read:   
                    data.setlen remote.reader.tsource.offset
                    if data.len() == 0:
                        if remote.reader.atEof():
                            break
                        else:
                            discard await remote.reader.readOnce(addr data, 0)
                            continue
                    let width = globals.full_tls_record_len.int
                    data.setLen(data.len() + width)
                    await remote.reader.readExactly(addr data[0 + width], data.len - width)
                    if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from remote"

                block write:
                    if not client.closed:
                        if mux: packForSendMux(remote.id, remote.port.uint16, data) else: packForSend(data)

                        await client.twriter.write(data)
                        if globals.log_data_len: echo &"[processRemote] Sent {data.len()} bytes ->  client"

        except:
            if globals.log_conn_error: echo getCurrentExceptionMsg()
        block close:
            if mux:
                await remote.closeWait()
                context.outbound.remove(remote)

                if not client.closed and client.mux_holds.contains(remote.id):
                    client.mux_holds.remove(remote.id)
                    inc client.mux_closes
                    var data = ""
                    echo "sending mux client close .... ", remote.id
                    packForSendMux(remote.id, remote.port.uint16, data)
                    await client.twriter.write(data)

                if client.mux_closes >= client.mux_capacity:
                    await client.closeWait() #end full connection
            else:
                await closeLine(client, remote)

    proc proccessClient() {.async.} =
        var remote: Connection = nil
        var data = newString(len = 0)
        var boundary: uint16 = 0
        try:
            while not client.closed:
                block read:  
                    data.setlen client.treader.tsource.offset
                    if data.len() == 0:
                        if client.treader.atEof():
                            break
                        else:
                            discard await client.treader.readOnce(addr data, 0)
                            continue

                    if client.isTrusted:
                        if boundary == 0:
                            let width = globals.full_tls_record_len.int
                            data.setLen width
                            await client.treader.readExactly(addr data[0],width)
                            copyMem(addr boundary, addr data[3], sizeof(boundary))
                            if boundary == 0: break
                            continue

                        let readable = min(boundary, data.len().uint16)
                        boundary -= readable; data.setlen readable
                        await client.treader.readExactly(addr data[0], readable.int)

                    else:
                        await client.treader.readExactly(addr data[0], data.len)

                    if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes from client"


                block process:
                    if mux:
                        discard
                    else:
                        if (client.isTrusted()) and (remote.isNil()):
                            remote = await remoteTrusted(client.port.Port)
                            asyncCheck processRemote(remote)
                            context.free_peer_outbounds.remove(client)
                            poolFrame()

                        if client.trusted == TrustStatus.pending:
                            var (trust, port) = monitorData(data)
                            if trust:
                                if globals.multi_port:
                                    echo "multi-port target:", port
                                    client.port = port.Port
                                else:
                                    client.port = globals.next_route_port.Port
                                client.trusted = TrustStatus.yes
                                print "Fake Reverse Handshake Complete !"
                                continue
                            else:
                                echo "[proccessClient] Target server was not a trusted tunnel client, closing..."
                                client.trusted = TrustStatus.no
                                break
                            # asyncCheck processRemote()
                    
                block write:          
                    if mux:
                        discard #who cares
                        # if client.isTrusted:
                        #     var (cid, port) = unPackForReadMux(data)
                        #     if not globals.multi_port: port = globals.next_route_port.uint16
                        #     print cid, port
                        #     if not context.outbound.hasID(cid):
                        #         let new_remote = remoteTrusted()
                        #         new_remote.id = cid
                        #         new_remote.port = port
                        #         client.mux_holds.add(new_remote.id)
                        #         if client.mux_holds.len.uint32 > client.mux_capacity:
                        #             echo "[ERROR] this mux connection is taking more than capacity"
                        #         context.outbound.register new_remote
                        #         new_remote.estabilished = new_remote.socket.connect(globals.next_route_addr, port.Port)
                        #         await new_remote.estabilished
                        #         echo "connected to the remote core"
                        #         asyncCheck processRemote(new_remote)

                        #     context.outbound.with(cid, name = con):
                        #         if not con.estabilished.finished:
                        #             await con.estabilished

                        #         if data.len() == 0: #mux remote close
                        #             echo "[processRemote] closed Mux remote"
                        #             con.close()
                        #             context.outbound.remove cid
                        #             client.mux_holds.remove cid
                        #             inc client.mux_closes
                        #         elif not con.closed():
                        #             await con.send(data)
                        #             echo &"[proccessClient] {data.len()} bytes -> remote "

                        # if client.trusted == TrustStatus.pending:
                        #     var (trust, _) = monitorData(data)
                        #     if trust:
                        #         client.trusted = TrustStatus.yes
                        #         print "Fake Reverse Handshake Complete !"
                        #         client.setBuffered()

                        #     else:
                        #         echo "[proccessClient] Target server was not a trusted tunnel client, closing..."
                        #         client.trusted = TrustStatus.no
                        #         break
                    else:
                        unPackForRead(data)
                        if not remote.closed():
                            await remote.writer.write(data)
                            if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote "

        except:
            if globals.log_conn_error: echo getCurrentExceptionMsg()

        block close:
            context.free_peer_outbounds.remove(client)
            if mux:
                await client.closeWait()
                for cid in client.mux_holds:
                    context.outbound.with(cid, name = con):
                        await con.closeWait()
            else:
                await closeLine(client, remote)


    try:
        asyncCheck proccessClient()
    except:
        echo "[Server] root level exception"
        print getCurrentExceptionMsg()

proc poolFrame(create_count: uint = 0) =
    var count = create_count

    proc create() {.async.} =
        try:
            var conn = await connect(initTAddress(globals.iran_addr, globals.iran_port), SocketScheme.Secure, globals.final_target_domain)
            echo "TlsHandsahke complete."
            context.free_peer_outbounds.add conn

            conn.transp.reader.cancel()
            await stepsAsync(1)
            conn.transp.reader = nil

            asyncCheck processConnection(conn)
            await conn.twriter.write(generateFinishHandShakeData())





        except TLSStreamProtocolError as exc:
            echo "Tls error, handshake failed because:"
            echo exc.msg

        except CatchableError as exc:
            echo "Connection failed because:"
            echo exc.name, ": ", exc.msg


    if count == 0:
        var i = context.free_peer_outbounds.len().uint

        if i < globals.pool_size div 2:
            count = 2
        elif i < globals.pool_size:
            count = 1


    for i in 0..<count:
        asyncCheck create()

proc start*(){.async.} =
    mux = globals.mux

    echo &"Mode Foreign Server:  {globals.listen_addr} <-> ({globals.final_target_domain} with ip {globals.final_target_ip})"
    trackIdleConnections(context.free_peer_outbounds,10)# only save for 10 secs
    #just to make sure we always willing to connect to the peer
    while true:
        poolFrame()
        await sleepAsync(5.secs)
