import std/[asyncdispatch, nativesockets, strformat, strutils, net, tables, random, endians]
import overrides/[asyncnet]
import times, print, connection, pipe, openssl
from globals import nil

when defined(windows):
    from winlean import getSockOpt
else:
    from posix import getSockOpt

type
    TunnelConnectionPoolContext = object
        listener: Connection
        user_inbound: Connections
        peer_inbound: Connections

var context = TunnelConnectionPoolContext()

proc monitorData(data: string): bool =
    var port: uint32
    try:
        if len(data) < 8: return false
        var sh1_c: uint32
        var sh2_c: uint32

        copyMem(unsafeAddr sh1_c, unsafeAddr data[0], 4)
        copyMem(unsafeAddr sh2_c, unsafeAddr data[4], 4)
        # copyMem(unsafeAddr port, unsafeAddr data[8], 4)

        let chk1 = sh1_c == globals.sh1
        let chk2 = sh2_c == globals.sh2

        return (chk1 and chk2)
    except:
        return false



proc processConnection(client_a: Connection) {.async.} =
    var client: Connection = client_a
    var remote: Connection = nil
    var data = ""


    var closed = false
    proc close() =
        if not closed:
            closed = true
            if globals.log_conn_destory: echo "[processRemote] closed client & remote"
            if remote != nil:
                remote.close()

            client.close()

    proc remoteUnTrusted(): Future[Connection]{.async.} =
        var new_remote = newConnection()
        new_remote.trusted = TrustStatus.no
        await new_remote.socket.connect(globals.final_target_ip, globals.final_target_port.Port)
        if globals.log_conn_create: echo "connected to ", globals.final_target_ip, ":", $globals.final_target_port
        return new_remote


    proc processRemote() {.async.} =
        while (not remote.isClosed) and (not client.isClosed):
            try:
                data = await remote.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from remote"

                if data.len() == 0:
                    break
               
                if not client.isClosed:
                    if client.isTrusted:
                        normalRead(data)
                    await client.send(data)
                    if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> client "

            except: break
        close()

    proc chooseRemote() {.async.} =
        proc introduce() {.async.} =
            let rlen = 16*(4+rand(4))
            var random_trust_data: string
            random_trust_data.setLen(rlen)
            copyMem(unsafeAddr random_trust_data[0], unsafeAddr globals.sh1.uint32, 4)
            copyMem(unsafeAddr random_trust_data[4], unsafeAddr globals.sh2.uint32, 4)
            if globals.multi_port:
                copyMem(unsafeAddr random_trust_data[8], unsafeAddr client.port, 4)
            # copyMem(unsafeAddr random_trust_data[12], unsafeAddr con.id, 4)
            copyMem(unsafeAddr random_trust_data[12], unsafeAddr(globals.random_600[rand(250)]), rlen-12)
            await remote.pureSend(random_trust_data)

        for i in 0..<16:
            remote = context.peer_inbound.grab()
            if remote != nil: break
            await sleepAsync(100)

        if remote != nil:
            if globals.log_conn_create: echo &"[createNewCon][Succ] grabbed a connection"
            await introduce()
            asyncCheck processRemote()
        else:
            if globals.log_conn_destory: echo &"[createNewCon][Error] left without connection, closes forcefully."
            client.close()

    proc processClient() {.async.} =
        while not client.isClosed:
            try:
                data = await client.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[processClient] {data.len()} bytes from client {client.id}"

                if data.len() == 0:
                    break


                if client.trusted == TrustStatus.pending:
                    let trust = monitorData(data)
                    if trust:
                        client.trusted = TrustStatus.yes
                        print "Peer Fake Handshake Complete !"
                        context.peer_inbound.register(client)
                        return # will have you as a client
                    elif (epochTime().uint - client.creation_time) > globals.trust_time:
                        #user connection
                        client.trusted = TrustStatus.no
                        await chooseRemote()
                        if remote == nil: break

                if not remote.isClosed:
                    if client.isTrusted:
                        normalSend(data)
                    await remote.send(data)
                    if globals.log_data_len: echo &"{data.len} bytes -> Remote"

            except: break
        close()

    try:
        remote = await remoteUnTrusted()
        asyncCheck processClient()
    except:
        printEx()

proc start*(){.async.} =
    var pbuf = newString(len = 16)

    proc start_server(){.async.} =

        context.listener = newConnection()
        context.listener.socket.setSockOpt(OptReuseAddr, true)
        context.listener.socket.bindAddr(globals.listen_port.Port, globals.listen_addr)
        if globals.multi_port:
            globals.listen_port = getSockName(context.listener.socket.getFd().SocketHandle).uint32
            globals.createIptablesRules()

        echo &"Started tcp server... {globals.listen_addr}:{globals.listen_port}"
        context.listener.socket.listen()

        while true:
            let (address, client) = await context.listener.socket.acceptAddr()
            var con = newConnection(client)
            if globals.multi_port:
                var origin_port: cushort
                var size = 16.SockLen
                if getSockOpt(con.socket.getFd().SocketHandle, cint(globals.SOL_IP), cint(globals.SO_ORIGINAL_DST),
                addr(pbuf[0]), addr(size)) < 0'i32:
                    echo "multiport failure getting origin port. !"
                    continue
                bigEndian16(addr origin_port, addr pbuf[2])

                con.port = origin_port
                if globals.log_conn_create: print "Connected client: ", address, " : ", con.port
            else:
                con.port = globals.listen_port

                if globals.log_conn_create: print "Connected client: ", address

            asyncCheck processConnection(con)


    await sleepAsync(2500)
    echo &"Mode Tunnel:  {globals.self_ip} <->  {globals.next_route_addr}  => {globals.final_target_domain}"
    asyncCheck start_server()





