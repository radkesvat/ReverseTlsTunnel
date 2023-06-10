import std/[ asyncdispatch, strformat]
import overrides/[asyncnet]
import times, print, connection, pipe
from globals import nil


type
    ServerConnectionPoolContext = object
        listener: Connection
        inbound: Connections
        outbound: Connections



var context = ServerConnectionPoolContext()



proc monitorData(data: string): tuple[trust: bool,id:uint32] =
    var id:uint32
    try:
        if len(data) < 12: return (false,id)
        var sh1_c: uint32
        var sh2_c: uint32

        copyMem(unsafeAddr sh1_c, unsafeAddr data[0], 4)
        copyMem(unsafeAddr sh2_c, unsafeAddr data[4], 4)
        copyMem(unsafeAddr id, unsafeAddr data[8], 4)

        let chk1 = sh1_c == globals.sh1
        let chk2 = sh2_c == globals.sh2

        return (chk1 and chk2,id)
    except:
        return (false,id)



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
    proc close()=
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
                if  client.isTrusted():
                    if globals.log_conn_destory: echo "[processRemote] closed remote"

                    continue
                else:
                    close()
                    break
                    
            if data.len() == 0:
                close()
                break

            try:
                if not client.isClosed():
                    if  client.isTrusted():
                        normalSend(data)
                    await client.send(data)
                    if globals.log_data_len: echo &"[proccessRemote] Sent {data.len()} bytes ->  client"
            except:continue


    try:
        remote = await remoteUnTrusted()
        asyncCheck proccessRemote()
    except:
        echo &"[Error] Failed to connect to the Target {globals.final_target_ip}:{globals.final_target_port}"
        client.close()
        return



    proc proccessClient() {.async.} =
        while not client.isClosed:

            var data = ""
            try:
                data = await client.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes from client"
            except:
                close()
                break

            if data == "":
                close()
                break
            if (remote.isTrusted()) and (not remote.estabilished):
                remote.estabilished = true
                try:
                    await remote.socket.connect(globals.next_route_addr, globals.next_route_port.Port)
                    asyncCheck proccessRemote()  
                except:
                    close()
                    break
                        

            if client.trusted == TrustStatus.pending:
                var (trust,id) = monitorData(data)
                if trust:
                    client.trusted = TrustStatus.yes
                    print "Fake Handshake Complete !"
                    remote.close()
                    asyncdispatch.poll()

                    try:
                        remote = await remoteTrusted()
                    except :
                        echo &"[Error] Failed to connect to the Target {globals.next_route_addr}:{globals.next_route_port}"
                        close()
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
                               
              
            except:
                printEx()
                continue




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

        while true:
            let (address, client) = await context.listener.socket.acceptAddr()
            let con = newConnection(client, address)
            if globals.log_conn_create: print "Connected client: ", address
            asyncCheck processConnection(con)




    echo &"Mode Server:   {globals.listen_addr} <-> ({globals.final_target_domain} with ip {globals.final_target_ip})"
    asyncCheck start_server()
