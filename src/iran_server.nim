import std/[strformat, strutils, random, endians]
import chronos
import chronos/osdefs

# import overrides/[asyncnet]
import times, print, connection, pipe
from globals import nil

# when defined(windows):
#     from winlean import getSockOpt
# else:
#     from posix import getSockOpt

type
    TunnelConnectionPoolContext = object
        # listener_server: Connection # for testing on local pc
        listener: Connection
        user_inbounds: Connections
        peer_inbounds: Connections
        peer_ip: TransportAddress


var context = TunnelConnectionPoolContext()
var mux = false

proc monitorData(data: var string): bool =
    try:
        let base = 5 + 7 + `mod`(globals.sh5, 7.uint8)
        if data.high.uint8 < base + 4: return false
        var sh1_c: uint32
        var sh2_c: uint32

        copyMem(addr sh1_c, addr data[base+0], 4)
        copyMem(addr sh2_c, addr data[base+4], 4)

        let chk1 = sh1_c == globals.sh1
        let chk2 = sh2_c == globals.sh2

        if (chk1 and chk2):


            return true
        else:
            return false

    except:
        return false

proc generateFinishHandShakeData(client_port: Port): string =
    let rlen: uint16 = uint16(16*(6+rand(4)))
    var port = client_port.uint32
    var random_trust_data: string
    random_trust_data.setLen(rlen)

    copyMem(addr random_trust_data[0], addr(globals.random_str[rand(250)]), rlen)
    copyMem(addr random_trust_data[0], addr globals.tls13_record_layer[0], 3) #tls header
    copyMem(addr random_trust_data[3], addr rlen, 2) #tls len

    let base = 5 + 7 + `mod`(globals.sh5, 7.uint8)
    copyMem(addr random_trust_data[base+0], addr globals.sh3.uint32, 4)
    copyMem(addr random_trust_data[base+4], addr globals.sh4.uint32, 4)
    if globals.multi_port:
        copyMem(addr random_trust_data[base+8], addr client_port, 4)

    return random_trust_data

proc close(client: Connection, remote: Connection) {.async.} =
    if remote != nil:
        await (remote.closeWait() and client.closeWait())
        if globals.log_conn_destory: echo "[processRemote] closed client & remote"
    else:
        if globals.log_conn_destory: echo "[processRemote] closed client "
        await client.closeWait()

proc remoteUnTrusted(): Future[Connection] {.async.} =
    let address = initTAddress(globals.final_target_ip, globals.final_target_port)
    var new_remote: Connection = await connection.connect(address)
    new_remote.trusted = TrustStatus.no
    if globals.log_conn_create: echo "connected to ", globals.final_target_domain, ":", $globals.final_target_port
    return new_remote


proc processRemote(client: Connection, remote: Connection) {.async.} =
    var data = newString(len = globals.chunk_size)
    try:
        while not remote.isNil and not remote.closed:
            # data = await remote.recv(if mux: globals.mux_chunk_size else: globals.chunk_size)
            data.setlen await remote.reader.readOnce(addr data[0], globals.chunk_size)
            if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from remote"
            if data.len() == 0:
                await close(client,remote) #end full connection

                return
            if mux:
                if remote.isTrusted:
                    let (cid, port) = unPackForReadMux(data)
                    echo &"[processRemote] {data.len()} bytes from mux remote"
                    if data.len() == 0: #mux client close
                        echo "Wanted to close: ", cid
                    context.user_inbounds.with(cid, name = con):
                        if data.len() == 0: #mux client close
                            echo "[processRemote] closed Mux client"
                            await con.closeWait()
                            context.user_inbounds.remove cid
                            remote.mux_holds.remove cid
                            inc remote.mux_closes
                        else:
                            if not con.closed:
                                await con.writer.write(data)
                                if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> Mux client "
                else:
                    if not client.closed:
                        await client.writer.write(data)
                        if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> client "
            else:
                if remote.isTrusted:
                    unPackForRead(data)
                if not client.closed:
                    await client.writer.write(data)
                    if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> client "
    except: discard
    if mux:
        for cid in remote.mux_holds:
            context.user_inbounds.with(cid, name = con):
                await con.closeWait()
            context.user_inbounds.remove(cid)
            echo "[1] removed user_inbound: ", cid
    else:
        if remote.isTrusted:
            await client.closeWait()
        if not remote.isNil(): await remote.closeWait()



proc chooseRemote(): Future[Connection] {.async.} =
    var remote: Connection= nil
    if mux:
        for i in 0..<16:
            remote = context.peer_inbounds.randomPick()
            if remote != nil:
                if remote.mux_holds.len().uint32 >= remote.mux_capacity:
                    context.peer_inbounds.remove(remote) # old connection
                    continue
                # remote.mux_holds.add client.id
                break
            await sleepAsync(100)
    else:
        for i in 0..<16:
            remote = context.peer_inbounds.grab()
            if remote != nil:
                if remote.closed: continue
                break
            await sleepAsync(100)
    return remote

proc processClient(client: Connection, remote: Connection, processRemoteFuture: Future[void]) {.async.} =
    var data = newString(len = globals.chunk_size)
    try:
        while not client.closed:
            echo "read try"
            # data = await client.recv(if mux: globals.mux_payload_size else: globals.chunk_size)
            data.setlen await client.reader.readOnce(addr data[0], globals.chunk_size)
            if globals.log_data_len: echo "[processClient] "&($data.len())&" bytes from client {client.id}"
            if data.len() == 0: #user closed the connection
                break
            # if client.trusted == TrustStatus.pending:
            #     var trust = monitorData(data)
            #     if trust:
            #         echo "Trusted the connection !"
            #         #peer connection
            #         client.trusted = TrustStatus.yes
            #         print "Peer Fake Handshake Complete ! ", ip
            #         if mux: context.user_inbounds.remove(client)
            #         context.peer_inbounds.register(client)
            #         context.peer_ip = client.transp.remoteAddress
            #         await remote.closeWait() # close untrusted remote
            #         await processRemoteFuture
            #         if mux:
            #             discard
            #             # remote = client
            #             # remote.setBuffered()
            #             # asyncCheck processRemote()
            #         if not globals.multi_port and not client.closed:
            #             await client.writer.write(generateFinishHandShakeData(client.port))
            #         return
                # else:
                #     if (epochTime().uint - client.creation_time) > globals.trust_time:
                #         #user connection but no peer connected yet
                #         #peer connection but couldnt finish handshake in time
                #         client.trusted = TrustStatus.no
                #         if mux:
                #             await close(client,remote)
                #             return
                #         else:
                #             break

            # await client.writer.write(data)
            continue
            if not remote.closed:
                if remote.isTrusted:
                    if mux: packForSendMux(client.id, client.port.uint16, data) else: packForSend(data)
                await remote.writer.write(data)
                if globals.log_data_len: echo &"{data.len} bytes -> Remote"
 
    except:
        echo getCurrentExceptionMsg()
    echo "loop broke"
    if mux:
        await client.closeWait()
        context.user_inbounds.remove(client)
        echo "[2] removed user_inbound: ", client.id
        if not remote.closed and remote.mux_holds.contains(client.id):
            var data = ""
            packForSendMux(client.id, client.port.uint16, data)
            await remote.writer.write(data)
        if remote.mux_holds.contains(client.id):
            remote.mux_holds.remove client.id
            inc remote.mux_closes
        if remote.mux_closes >= remote.mux_capacity:
            await close(client,remote) #end full connection
    else:
        await close(client,remote)


proc processConnection(client: Connection) {.async.} =
    var remote: Connection = nil
    var processRemoteFuture: Future[void]

    var closed = false

    try:
        if context.peer_ip != TransportAddress() and
            context.peer_ip.address != client.transp.remoteAddress.address:
            echo "Real User connected !"
            client.trusted = TrustStatus.no
            remote = await chooseRemote() #associate peer
            if remote != nil:
                if mux: context.user_inbounds.register(client)
                if globals.log_conn_create: echo &"[createNewCon][Succ] Associated a peer connection"
                if globals.multi_port:
                    await remote.writer.write(generateFinishHandShakeData(client.port))

                if not mux: asyncCheck processRemote(client,remote) # mux already called this
            else:
                if globals.log_conn_destory: echo &"[createNewCon][Error] left without connection, closes forcefully."
                await client.closeWait()
                return
        else:
            discard
            # remote = await remoteUnTrusted()
            # processRemoteFuture = processRemote(client,remote)
        await processClient(client, remote, processRemoteFuture)

    except:
        printEx()

proc start*(){.async.} =
    var pbuf = newString(len = 16)

    # [to test on local pc]
    # proc start_server_listener(){.async.} =
    #     context.listener_server = newConnection()
    #     context.listener_server.socket.setSockOpt(OptReuseAddr, true)
    #     context.listener_server.socket.bindAddr(8093.Port, globals.listen_addr)
    #     echo &"Started tcp server... {globals.listen_addr}:{globals.listen_port}"
    #     context.listener_server.socket.listen()
    #     while true:
    #         let (address, client) = await context.listener_server.socket.acceptAddr()
    #         var con = newConnection(client,"192.168.1.130")
    #         con.port = globals.listen_port
    #         if globals.log_conn_create: print "Connected reverse host: ", address
    #         asyncCheck processConnection(con)

    proc start_listener(){.async.} =

        proc serveStreamClient(server: StreamServer,
                         transp: StreamTransport) {.async.} =

            let con = await Connection.new(transp)
            if globals.multi_port:
                var origin_port: int
                var size = 16.SockLen
                if not getSockOpt(transp.fd, int(globals.SOL_IP), int(globals.SO_ORIGINAL_DST),
                origin_port):
                    echo "multiport failure getting origin port. !"
                    await con.closeWait()
                    return
                # bigEndian16(addr origin_port, addr pbuf[2])

                con.port = origin_port.Port
                if globals.log_conn_create: print "Connected client: ", transp.remoteAddress, " multiport: ", con.port
            else:
                con.port = server.local.port.Port
                if globals.log_conn_create: print "Connected client: ", transp.remoteAddress

            asyncCheck processConnection(con)


        var address = initTAddress(globals.listen_addr, globals.listen_port.Port)

        let server: StreamServer =
            try:
                createStreamServer(address, serveStreamClient, {ReuseAddr})
            except TransportOsError as exc:
                print exc
                quit(-1)
            except CatchableError as exc:
                print exc
                quit(-1)

        if globals.multi_port:
            globals.listen_port = server.localAddress().port
            globals.createIptablesForwardRules()

        server.start()
        echo &"Started tcp server... {globals.listen_addr}:{globals.listen_port}"


        # context.listener = newConnection()
        # context.listener.socket.setSockOpt(OptReuseAddr, true)
        # context.listener.socket.bindAddr(globals.listen_port.Port, globals.listen_addr)
        # if globals.multi_port:
        #     globals.listen_port = getSockName(context.listener.socket.getFd()).uint32
        #     globals.createIptablesForwardRules()

        # echo &"Started tcp server... {globals.listen_addr}:{globals.listen_port}"
        # context.listener.socket.listen()

        # while true:
        #     let (address, client) = await context.listener.socket.acceptAddr()

        #     var con = newConnection(client, address)
        #     if globals.multi_port:
        #         var origin_port: cushort
        #         var size = 16.SockLen
        #         if getSockOpt(con.socket.getFd(), cint(globals.SOL_IP), cint(globals.SO_ORIGINAL_DST),
        #         addr(pbuf[0]), addr(size)) < 0'i32:
        #             echo "multiport failure getting origin port. !"
        #             continue
        #         bigEndian16(addr origin_port, addr pbuf[2])

        #         con.port = origin_port
        #         if globals.log_conn_create: print "Connected client: ", address, " : ", con.port
        #     else:
        #         con.port = globals.listen_port

        #         if globals.log_conn_create: print "Connected client: ", address

        #     asyncCheck processConnection(con)

    mux = globals.mux
    await sleepAsync(2500)
    echo &"Mode Iran : {globals.self_ip}  handshake: {globals.final_target_domain}"
    asyncCheck start_listener()
    # asyncCheck start_server_listener()





