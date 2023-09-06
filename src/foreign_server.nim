import std/[asyncdispatch, strformat, net, openssl, tables, random, times]
import overrides/[asyncnet]
import print, connection, pipe
from globals import nil

import os
type
    ServerConnectionPoolContext = object
        free_outbounds: Connections
        outbound: Connections

var context = ServerConnectionPoolContext()
var ssl_ctx = newContext(verifyMode = CVerifyPeer)

# [FWD]
proc poolFrame(create_count: uint = 0) 

proc sslConnect(con: Connection, ip: string, sni: string){.async.} =
    con.socket.close()
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
    let rlen = 16*(6+rand(4))
    var random_trust_data: string
    random_trust_data.setLen(rlen)

    copyMem(unsafeAddr random_trust_data[0], unsafeAddr globals.sh1.uint32, 4)
    copyMem(unsafeAddr random_trust_data[4], unsafeAddr globals.sh2.uint32, 4)

    case globals.self_ip.family:   # the type of the IP address (IPv4 or IPv6)
        of IpAddressFamily.IPv6:
            random_trust_data[9] = 6.char
            copyMem(unsafeAddr random_trust_data[10], unsafeAddr globals.self_ip.address_v6[0],globals.self_ip.address_v6.len)
            copyMem(unsafeAddr random_trust_data[10+globals.self_ip.address_v6.len], unsafeAddr(globals.random_600[rand(250)]), rlen-8)

        of IpAddressFamily.IPv4:
            random_trust_data[9] = 4.char
            copyMem(unsafeAddr random_trust_data[10], unsafeAddr globals.self_ip.address_v4[0],globals.self_ip.address_v4.len)
            copyMem(unsafeAddr random_trust_data[10+globals.self_ip.address_v4.len], unsafeAddr(globals.random_600[rand(250)]), rlen-8)


    # if globals.multi_port:
    #     copyMem(unsafeAddr random_trust_data[8], unsafeAddr client_origin_port, 4)

    await con.unEncryptedSend(random_trust_data)

    con.trusted = TrustStatus.pending


proc monitorData(data: string): tuple[trust: bool, port: uint32] =
    var port: uint32
    try:
        if len(data) < 16: return (false, port)
        var sh3_c: uint32
        var sh4_c: uint32

        copyMem(unsafeAddr sh3_c, unsafeAddr data[0], 4)
        copyMem(unsafeAddr sh4_c, unsafeAddr data[4], 4)
        copyMem(unsafeAddr port, unsafeAddr data[8], 4)


        let chk1 = sh3_c == globals.sh3
        let chk2 = sh4_c == globals.sh4

        return (chk1 and chk2, port)
    except:
        return (false, port)



proc processConnection(client: Connection) {.async.} =
    var remote: Connection = nil
    var data = ""

    var remoteEstabilishment: Future[void] = nil

    proc proccessRemote() {.async.}
    proc proccessClient() {.async.}

    proc remoteTrusted(): Future[Connection]{.async.} =
        var new_remote = newConnection()
        new_remote.trusted = TrustStatus.yes
        new_remote.estabilished = false
        return new_remote

    var closed = false
    proc close() =
        if not closed:
            closed = true
            if globals.log_conn_destory: echo "[processRemote] closed client & remote"
            client.close()
            if remote != nil:
                remote.close()

    proc proccessRemote() {.async.} =
        try:
            while not remote.isClosed:
                data = await remote.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[proccessRemote] {data.len()} bytes from remote"
              

                if data.len() == 0:
                    break 

                if not client.isClosed():
                    if client.isTrusted():
                        packForSend(data)
                    await client.unEncryptedSend(data)
                    if globals.log_data_len: echo &"[proccessRemote] Sent {data.len()} bytes ->  client"

        except: discard
        close()

    proc proccessClient() {.async.} =
        try:
            while not client.isClosed:

                data = await client.unEncryptedrecv(globals.chunk_size)
                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes from client"


                if data.len() == 0:
                    break

                if (client.isTrusted()) and (not remote.isNil() and not remote.estabilished):
                    if remoteEstabilishment.isNil:
                        remoteEstabilishment = remote.socket.connect(globals.next_route_addr, client.port.Port)
                        await remoteEstabilishment
                        asyncCheck proccessRemote()
                        remote.estabilished = true
                        let i = context.free_outbounds.connections.find(client)
                        if i != -1: context.free_outbounds.connections.del(i)
                        echo "established to remote, calling pool frame"
                        poolFrame()

                    elif not remoteEstabilishment.finished:
                        await remoteEstabilishment


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
                            remote = await remoteTrusted()

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
        close()


    try:
        asyncCheck proccessClient()
    except:
        echo "[Server] root level exception"
        print getCurrentExceptionMsg()

proc poolFrame(create_count: uint = 0) =
    var count = create_count

    proc create() =
        var con = newConnection()
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
        var i = context.free_outbounds.connections.len().uint

        if i < globals.pool_size div 2:
            count = 2
        elif i < globals.pool_size:
            count = 1
    
    for i in 0..<count:
        create()
            
proc start*(){.async.} =

    echo &"Mode Foreign Server:  {globals.listen_addr} <-> ({globals.final_target_domain} with ip {globals.final_target_ip})"
    #just to make sure we always willing to connect to the peer
    while true:
        poolFrame()
        await sleepAsync(5000)
