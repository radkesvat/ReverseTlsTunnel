import std/[asyncdispatch, strformat, net, openssl, tables, random, times]
import overrides/[asyncnet]
import print, connection, pipe
from globals import nil


type
    ServerConnectionPoolContext = object
        free_outbounds: Connections
        outbound: Connections



var context = ServerConnectionPoolContext()
var ssl_ctx = newContext(verifyMode = CVerifyPeer)

proc poolFrame(count: uint = 0){.gcsafe.}

proc sslConnect(con: Connection, ip: string,  sni: string){.async.} =
    con.socket.close()
    var fc = 0
    echo "connecting..."

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
    let rlen = 16*(4+rand(4))
    var random_trust_data: string
    random_trust_data.setLen(rlen)

    copyMem(unsafeAddr random_trust_data[0], unsafeAddr globals.sh1.uint32, 4)
    copyMem(unsafeAddr random_trust_data[4], unsafeAddr globals.sh2.uint32, 4)
    # if globals.multi_port:
    #     copyMem(unsafeAddr random_trust_data[8], unsafeAddr client_origin_port, 4)
    copyMem(unsafeAddr random_trust_data[8], unsafeAddr(globals.random_600[rand(250)]), rlen-8)


    await con.pureSend(random_trust_data)

    con.trusted = TrustStatus.yes






proc monitorData(data: string): tuple[trust: bool, port: uint32] =
    var port: uint32
    try:
        if len(data) < 16: return (false, port)
        var sh1_c: uint32
        var sh2_c: uint32

        copyMem(unsafeAddr sh1_c, unsafeAddr data[0], 4)
        copyMem(unsafeAddr sh2_c, unsafeAddr data[4], 4)
        copyMem(unsafeAddr port, unsafeAddr data[8], 4)

        let chk1 = sh1_c == globals.sh1
        let chk2 = sh2_c == globals.sh2

        return (chk1 and chk2, port)
    except:
        return (false, port)



proc processConnection(client_a: Connection) {.async.} =
    # var remote: Connection
    var client: Connection = client_a
    var remote: Connection = nil

    proc proccessRemote() {.async.}
    proc proccessClient() {.async.}

    proc remoteTrusted(): Future[Connection]{.async.} =
        var new_remote = newConnection()
        new_remote.trusted = TrustStatus.yes
        new_remote.estabilished = false
        return new_remote


    proc remoteUnTrusted(): Future[Connection]{.async.} =
        var new_remote = newConnection()
        new_remote.trusted = TrustStatus.no
        await new_remote.socket.connect(globals.final_target_ip, globals.final_target_port.Port)
        if globals.log_conn_create: echo "connected to ", globals.final_target_ip, ":", $globals.final_target_port
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
        var data = ""
        while not remote.isClosed:
            try:
                data = await remote.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[proccessRemote] {data.len()} bytes from remote"
            except:
                if client.isTrusted():
                    if remote.estabilished:
                        close()
                        break
                    else:
                        if globals.log_conn_destory: echo "[processRemote] closed remote"
                        break
                else:
                    close()
                    break

            if data.len() == 0:
                close()
                break
            try:
                if not client.isClosed():
                    if client.isTrusted():
                        normalSend(data)
                    await client.send(data)
                    if globals.log_data_len: echo &"[proccessRemote] Sent {data.len()} bytes ->  client"
            except:
                close()
                break







    proc proccessClient() {.async.} =
        var data = ""
        while not client.isClosed:
            try:
                data = await client.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes from client"
            except:
                break

            if data == "":
                break
            if (client.isTrusted()) and (not remote.estabilished):
                remote.estabilished = true
                try:
                    await remote.socket.connect(globals.next_route_addr, client.port.Port)
                    asyncCheck proccessRemote()
                    let i = context.free_outbounds.connections.find(client)
                    if i != -1: context.free_outbounds.connections.del(i)
                    poolFrame()
                except:
                    break


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
                        break

                    continue
                else:
                    echo "[proccessClient] non-client connection detected! forwarding to real website."
                    client.trusted = TrustStatus.no
                    try:
                        remote = await remoteUnTrusted()
                    except:
                        echo &"[Error] Failed to connect to the Target {globals.final_target_ip}:{globals.final_target_port}"
                        break
                asyncCheck proccessRemote()

            try:
                if client.isTrusted():
                    normalRead(data)

                if not remote.isClosed():
                    await remote.send(data)
                    if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote "


            except: break
        close()




    try:
        # asyncCheck proccessRemote()

        asyncCheck proccessClient()
    except:
        echo "[Server] root level exception"
        print getCurrentExceptionMsg()

proc poolFrame(count: uint = 0){.gcsafe.} =
    proc create() =
        var con = newConnection()
        con.port = globals.next_route_port.uint32
        var fut = sslConnect(con, globals.next_route_addr, globals.final_target_domain)

        fut.addCallback(
            proc() {.gcsafe.} =
            if fut.failed:
                if globals.log_conn_error: echo fut.error.msg
            else:
                if globals.log_conn_create: echo &"[createNewCon] registered a new connection to the pool"
                asyncCheck processConnection(con)

        )

    if count == 0:
        var i = context.free_outbounds.connections.len().uint

        if i < globals.pool_size div 2:
            create()
            create()
        elif i < globals.pool_size:
            create()

    else:
        for i in 0..<count:
            create()
proc start*(){.async.} =
    # proc start_server(){.async.} =

    #     context.listener = newConnection()
    #     context.listener.socket.setSockOpt(OptReuseAddr, true)
    #     context.listener.socket.bindAddr(globals.listen_port.Port, globals.listen_addr)
    #     echo &"Started tcp server... {globals.listen_addr}:{globals.listen_port}"
    #     context.listener.socket.listen()
    #     if globals.multi_port:
    #         echo "Multi port mode!"
    #     while true:
    #         let (address, client) = await context.listener.socket.acceptAddr()
    #         let con = newConnection(client)
    #         if globals.log_conn_create: print "Connected client: ", address
    #         asyncCheck processConnection(con)




    echo &"Mode Server:   {globals.listen_addr} <-> ({globals.final_target_domain} with ip {globals.final_target_ip})"
    #just to make sure we always willing to connect to the peer
    while true:
        poolFrame()
        await sleepAsync(5000)
    # asyncCheck start_server()
