import std/[asyncdispatch, strformat]
import overrides/[asyncnet]
import times, print, connection, pipe
from globals import nil


type
    ServerConnectionPoolContext = object
        listener: Connection
        inbound: Connections
        outbound: Connections



var context = ServerConnectionPoolContext()



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
    proc start_server(){.async.} =

        context.listener = newConnection(address = "This Server")
        context.listener.socket.setSockOpt(OptReuseAddr, true)
        context.listener.socket.bindAddr(globals.listen_port.Port, globals.listen_addr)
        echo &"Started tcp server... {globals.listen_addr}:{globals.listen_port}"
        context.listener.socket.listen()
        if globals.multi_port:
            echo "Multi port mode!"
        while true:
            let (address, client) = await context.listener.socket.acceptAddr()
            let con = newConnection(client, address)
            if globals.log_conn_create: print "Connected client: ", address
            asyncCheck processConnection(con)




    echo &"Mode Server:   {globals.listen_addr} <-> ({globals.final_target_domain} with ip {globals.final_target_ip})"
    asyncCheck start_server()
