import std/[asyncdispatch, strformat, net, openssl, random]
import overrides/[asyncnet]
import print, connection, pipe
from globals import nil

type
    ServerConnectionPoolContext = object
        free_peer_outbounds: Connections
        used_peer_outbounds: Connections
        outbound: Connections

var context = ServerConnectionPoolContext()
var ssl_ctx = newContext(verifyMode = CVerifyPeer)
var mux = false

# [FWD]
proc poolFrame(create_count: uint = 0)

proc sslConnect(con: Connection, ip: string, sni: string){.async.} =
    # con.socket.close()
    var fc = 0
    echo &"connecting to {ip}:{$con.port} (sni: {sni}) ..."

    while true:
        if fc > 3:
            con.close()
            raise newException(ValueError, "[SslConnect] could not connect, all retires failed")

        # var fut = con.socket.connect(ip, con.port.Port, sni = sni)
        var fut = asyncnet.dial(ip, Port(con.port), buffered = false)

        var timeout = withTimeout(fut, 3000)
        yield timeout
        if timeout.failed():
            inc fc
            if globals.log_conn_error: echo timeout.error.msg
            if globals.log_conn_error: echo &"[SslConnect] retry in {min(1000,fc*200)} ms"
            await sleepAsync(min(1000, fc*200))
            continue
        if timeout.read() == true:
            con.socket = fut.read()
            break
        if timeout.read() == false:
            con.close()
            raise newException(ValueError, "[SslConnect] dial timed-out")

    try:
        if not globals.keep_system_limit: con.socket.setSockOpt(OptNoDelay, true)

        ssl_ctx.wrapConnectedSocket(
            con.socket, handshakeAsClient, sni)
        let flags = {SocketFlag.SafeDisconn}

        block handshake:
            sslLoop(con.socket, flags, sslDoHandshake(con.socket.sslHandle))

    except:
        echo "[SslConnect] handshake error!"
        con.close()
        raise getCurrentException()

    if globals.log_conn_create: print "[SslConnect] conencted !"


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

    case globals.self_ip.family: # the type of the IP address (IPv4 or IPv6)
        of IpAddressFamily.IPv6:
            random_trust_data[base+9] = 6.char
            copyMem(unsafeAddr random_trust_data[base+10], unsafeAddr globals.self_ip.address_v6[0], globals.self_ip.address_v6.len)

        of IpAddressFamily.IPv4:
            random_trust_data[base+9] = 4.char
            copyMem(unsafeAddr random_trust_data[base+10], unsafeAddr globals.self_ip.address_v4[0], globals.self_ip.address_v4.len)


    # if globals.multi_port:
    #     copyMem(unsafeAddr random_trust_data[8], unsafeAddr client_origin_port, 4)
    await con.unEncryptedSend(random_trust_data)

    con.trusted = TrustStatus.pending


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



proc processConnection(client: Connection) {.async.} =
    # var remote: Connection = nil
    var data = ""

    # var remoteEstabilishment: Future[void] = nil

    proc remoteTrusted(): Connection =
        var new_remote = newConnection()
        new_remote.trusted = TrustStatus.yes
        new_remote.estabilished = nil
        return new_remote

    var closed = false
    proc close(client: Connection, remote: Connection) =
        if not closed:
            closed = true
            if globals.log_conn_destory: echo "[processRemote] closed client & remote"
            client.close()
            if remote != nil:
                remote.close()

    proc proccessRemote(remote: Connection) {.async.} =
        try:
            while not remote.isClosed:
                data = await remote.recv(if mux: globals.mux_payload_size else: globals.chunk_size)
                if globals.log_data_len: echo &"[proccessRemote] {data.len()} bytes from remote"


                if data.len() == 0:
                    break

                if not client.isClosed():
                    if mux: packForSendMux(remote.id, remote.port.uint16, data) else: packForSend(data)

                    await client.unEncryptedSend(data)
                    if globals.log_data_len: echo &"[proccessRemote] Sent {data.len()} bytes ->  client"

        except: discard
        if mux:
            remote.close()
            context.outbound.remove(remote)

            if not client.isClosed and client.mux_holds.contains(remote.id):
                client.mux_holds.remove(remote.id)
                inc client.mux_closes
                var data = ""
                packForSendMux(client.id, client.port.uint16, data)
                await client.send(data)

            if client.mux_closes >= client.mux_capacity:
                client.close() #end full connection
        else:
            close(client, remote)

    proc proccessClient() {.async.} =
        var remote: Connection = nil

        try:
            while not client.isClosed:

                data = await client.unEncryptedrecv(if mux: globals.mux_chunk_size else: globals.chunk_size)
                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes from client"


                if data.len() == 0:
                    break


                if mux:
                    if client.isTrusted:
                        let (cid, port) = unPackForReadMux(data)
                        if not context.outbound.hasID(cid):
                            let new_remote = remoteTrusted()
                            new_remote.id = cid
                            new_remote.port = port
                            client.mux_holds.add(new_remote.id)
                            context.outbound.register new_remote
                            new_remote.estabilished = new_remote.socket.connect(globals.next_route_addr, port.Port)
                            await new_remote.estabilished
                            asyncCheck proccessRemote(new_remote)

                        context.outbound.with(cid, name = con):
                            if not con.estabilished.finished:
                                await con.estabilished

                            if not con.isClosed():
                                await con.send(data)
                                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote "

                    if client.trusted == TrustStatus.pending:
                        var (trust, _) = monitorData(data)
                        if trust:
                            client.trusted = TrustStatus.yes
                            print "Fake Reverse Handshake Complete !"
                            client.setBuffered()

                        else:
                            echo "[proccessClient] Target server was not a trusted tunnel client, closing..."
                            client.trusted = TrustStatus.no
                            break


                else:

                    if (client.isTrusted()) and (not remote.isNil()):
                        if remote.estabilished.isNil:
                            remote.estabilished = remote.socket.connect(globals.next_route_addr, client.port.Port)
                            await remote.estabilished
                            asyncCheck proccessRemote(remote)
                            
                            let i = context.free_peer_outbounds.find(client)
                            if i != -1: context.free_peer_outbounds.del(i)
                            echo "established to remote, calling pool frame"
                            poolFrame()

                        elif not remote.estabilished.finished:
                            await remote.estabilished


                    if client.trusted == TrustStatus.pending:
                        var (trust, port) = monitorData(data)
                        if trust:
                            if globals.multi_port:
                                echo "multi-port target:", port
                                client.port = port
                            else:
                                client.port = globals.next_route_port.uint32
                            client.trusted = TrustStatus.yes
                            print "Fake Reverse Handshake Complete !"
                            # remote.close()
                            # asyncdispatch.poll()
                            try:
                                remote = remoteTrusted()

                            except:
                                echo &"[Error] Failed to connect to the Target {globals.next_route_addr}:{globals.next_route_port}"
                                raise

                            continue
                        else:
                            echo "[proccessClient] Target server was not a trusted tunnel client, closing..."
                            client.trusted = TrustStatus.no
                            break
                        # asyncCheck proccessRemote()


                    unPackForRead(data)

                    if not remote.isClosed():
                        await remote.send(data)
                        if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote "

        except: discard
        if mux:
            client.close()
            for cid in client.mux_holds:
                context.outbound.with(cid, name = con):
                    con.close()
        else:
            close(client, remote)


    try:
        asyncCheck proccessClient()
    except:
        echo "[Server] root level exception"
        print getCurrentExceptionMsg()

proc poolFrame(create_count: uint = 0) =
    var count = create_count

    proc create() =
        var con = newConnection(create_socket = false)
        con.port = globals.iran_port.uint32
        var fut = sslConnect(con, globals.iran_addr, globals.final_target_domain)

        fut.addCallback(
            proc() =
            {.gcsafe.}:
                if fut.failed:
                    if globals.log_conn_error: echo fut.error.msg
                else:
                    if globals.log_conn_create: echo &"[createNewCon] registered a new connection to the pool"
                    asyncCheck processConnection(con)

        )

    if count == 0:
        var i = context.free_peer_outbounds.len().uint

        if i < globals.pool_size div 2:
            count = 2
        elif i < globals.pool_size:
            count = 1

    for i in 0..<count:
        create()

proc start*(){.async.} =
    mux = globals.mux

    echo &"Mode Foreign Server:  {globals.listen_addr} <-> ({globals.final_target_domain} with ip {globals.final_target_ip})"
    #just to make sure we always willing to connect to the peer
    while true:
        poolFrame()
        await sleepAsync(5000)
