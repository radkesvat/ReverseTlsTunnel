import std/[asyncdispatch, strformat]
import overrides/[asyncnet]
import times, print, connection, pipe
from globals import nil


type
    ServerConnectionPoolContext = object
        listener: Connection
        inbound: Table[uint32,Connections]
        outbound: Connections


let ssl_ctx = newContext(verifyMode = CVerifyPeer)

var context = ServerConnectionPoolContext()


proc ssl_connect(con: Connection, ip: string, client_origin_port: uint32, sni: string){.async.} =
    wrapSocket(ssl_ctx, con.socket)
    con.isfakessl = true
    var fc = 0
    while true:
        if fc > 6:
            raise newException(ValueError, "Request Timed Out!")
        try:
            await con.socket.connect(ip, con.port.Port, sni = sni)
            break
        except:
            echo &"ssl connect error ! retry in {min(1000,fc*50)} ms"
            await sleepAsync(min(1000, fc*200))
            inc fc

    print "ssl socket conencted"

    # let to_send = &"GET / HTTP/1.1\nHost: {sni}\nAccept: */*\n\n"
    # await socket.send(to_send)  [not required ...]

    #now we use this socket as a normal tcp data transfer socket
    con.socket.isSsl = false 

    #AES default chunk size is 16 so use a multple of 16 
    let rlen = 16*(4+rand(4))
    var random_trust_data: string
    random_trust_data.setLen(rlen)

    prepareMutation(random_trust_data)
    copyMem(unsafeAddr random_trust_data[0], unsafeAddr globals.sh1.uint32, 4)
    copyMem(unsafeAddr random_trust_data[4], unsafeAddr globals.sh2.uint32, 4)
    if globals.multi_port:
        copyMem(unsafeAddr random_trust_data[8], unsafeAddr client_origin_port, 4)
    # copyMem(unsafeAddr random_trust_data[12], unsafeAddr con.id, 4)
    copyMem(unsafeAddr random_trust_data[12], unsafeAddr(globals.random_600[rand(250)]), rlen-12)

    await con.socket.send(random_trust_data)
    con.trusted = TrustStatus.yes

proc poolFrame(client_port:uint32 , count: uint = 0){.gcsafe.} =
    proc create() =
        var con = newConnection(address = globals.next_route_addr)
        con.port = globals.next_route_port.uint32
        var fut = ssl_connect(con, globals.next_route_addr, client_port, globals.final_target_domain)
        fut.addCallback(
            proc() {.gcsafe.} =
            if fut.failed:
                echo fut.error.msg
            else:
                if globals.log_conn_create: echo &"[createNewCon] registered a new connection to the pool"
                context.outbound[client_port].register con
        )


    if count == 0:
        var i = context.outbound[client_port].connections.len().uint

        if i < globals.pool_size div 2:
            create()
            create()
        else:
            create()

    else:
        for i in 0..<count:
            create()


proc processConnection(client_a: Connection) {.async.} =
    # var remote: Connection
    var client: Connection = client_a
    var remote: Connection

    proc proccessRemote() {.async.}
    proc proccessClient() {.async.}

    proc remoteTrusted(): Future[Connection]{.async.} =
        var new_remote = newConnection(address = globals.next_route_addr)
        new_remote.trusted = TrustStatus.yes
        new_remote.estabilished = false
        return new_remote

    proc remoteUnTrusted(): Future[Connection]{.async.} =
        var new_remote = newConnection(address = globals.final_target_ip)
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
        

    try:
        remote = await remoteUnTrusted()
        asyncCheck proccessRemote()
    except:
        echo &"[Error] Failed to connect to the Target {globals.final_target_ip}:{globals.final_target_port}"
        client.close()
        return



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
            if (remote.isTrusted()) and (not remote.estabilished):
                remote.estabilished = true
                try:
                    await remote.socket.connect(globals.next_route_addr, client.port.Port)
                    asyncCheck proccessRemote()
                except:
                    break


            if client.trusted == TrustStatus.pending:
                var (trust, port) = monitorData(data)
                if trust:
                    if globals.multi_port:
                        echo "multi-port target:" , port
                        client.port = port
                    else:
                        client.port = globals.next_route_port.uint32
                    client.trusted = TrustStatus.yes
                    print "Fake Handshake Complete !"
                    remote.close()
                    asyncdispatch.poll()

                    try:
                        remote = await remoteTrusted()
                    except:
                        echo &"[Error] Failed to connect to the Target {globals.next_route_addr}:{globals.next_route_port}"
                        break

                    continue
                elif (epochTime().uint - client.creation_time) > globals.trust_time:
                    echo "[proccessClient] non-client connection detected !  forwarding to real website."
                    client.trusted = TrustStatus.no


            try:
                if client.isTrusted():
                    normalRead(data)

                if not remote.isClosed():
                    await remote.send(data)
                    if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote "


            except: break
        close()




    try:
        asyncCheck proccessClient()
    except:
        echo "[Server] root level exception"
        print getCurrentExceptionMsg()


proc start*(){.async.} =
    # proc start_server(){.async.} =

    #     context.listener = newConnection(address = "This Server")
    #     context.listener.socket.setSockOpt(OptReuseAddr, true)
    #     context.listener.socket.bindAddr(globals.listen_port.Port, globals.listen_addr)
    #     echo &"Started tcp server... {globals.listen_addr}:{globals.listen_port}"
    #     context.listener.socket.listen()
    #     if globals.multi_port:
    #         echo "Multi port mode!"
    #     while true:
    #         let (address, client) = await context.listener.socket.acceptAddr()
    #         let con = newConnection(client, address)
    #         if globals.log_conn_create: print "Connected client: ", address
    #         asyncCheck processConnection(con)



    if not globals.multi_port:
        context.outbound[globals.port] = Connections()
        poolFrame(globals.listen_port,globals.pool_size)
        
    await sleepAsync(1200)

    echo &"Mode Server:   {globals.listen_addr} <-> ({globals.final_target_domain} with ip {globals.final_target_ip})"
    asyncCheck start_server()
