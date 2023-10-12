import std/[strformat, strutils, random, endians]
import chronos, chronos/transports/[datagram, ipnet], chronos/osdefs
import times, print, connection, pipe, bitops
from globals import nil

type
    TunnelConnectionPoolContext = object
        # listener_server: Connection for testing on local pc
        listener: StreamServer
        listener_udp: DatagramTransport
        user_inbounds: Connections
        user_inbounds_udp: UdpConnections

        up_bounds: Connections
        dw_bounds: Connections
        available_peer_inbounds: Connections
        peer_ip: IpAddress

var context = TunnelConnectionPoolContext()



proc monitorData(data: var string): tuple[trust: bool, upload: bool] =
    let base = 5 + 7 + `mod`(globals.sh5, 7.uint8)
    if data.high.uint8 < base + 1: return (false, false)
    var sh1_c: uint32
    var sh2_c: uint32
    var up_c: uint8

    copyMem(addr sh1_c, addr data[base+0], 4)
    copyMem(addr sh2_c, addr data[base+4], 4)
    copyMem(addr up_c, addr data[base+8], 1)

    let chk1 = sh1_c == globals.sh1
    let chk2 = sh2_c == globals.sh2
    let up = (up_c xor globals.sh5) == 0x0

    if (chk1 and chk2):
        return (true, up)
    else:
        return (false, up)


proc acquireRemoteConnection(upload: bool, mark = true): Future[Connection] {.async.} =
    var remote: Connection = nil
    var source: Connections = if upload: context.up_bounds else: context.dw_bounds
    for i in 0..<100:
        if source.len != 0:
            remote = source.roundPick()
            if remote != nil:
                if remote.closed or remote.isClosing:
                    source.remove(remote)
                    continue

                if mark:
                    inc remote.counter

                return remote
        await sleepAsync(20)
    return nil

proc connectTargetSNI(): Future[Connection] {.async.} =
    let address = initTAddress(globals.final_target_ip, globals.final_target_port)
    var new_remote: Connection = await connection.connect(address, no_id = true)
    new_remote.trusted = TrustStatus.no
    if globals.log_conn_create: echo "connected to ", globals.final_target_domain, ":", $globals.final_target_port
    return new_remote

template fupload: bool = globals.noise_ratio != 0

proc sendJunkData(len: int) {.async.} =
    var target: Connection = await acquireRemoteConnection(upload = true)

    if target.isNil:
        if globals.log_data_len: echo "could not acquire a connection to send fake traffic."
        return

    let random_start = rand(1500)
    let full_len = min((len+random_start) + `mod`((len+random_start), 16), globals.random_str.len())
    var data = globals.random_str[random_start ..< full_len]
    let size: uint16 = data.len().uint16 - globals.full_tls_record_len.uint16
    copyMem(addr data[0], addr globals.tls13_record_layer[0], globals.tls13_record_layer.len())
    copyMem(addr data[0 + globals.tls13_record_layer.len()], addr size, sizeof(size))
    data.flagForSend(flags = {DataFlags.junk})
    await target.writer.write(data)
    if globals.log_data_len: echo &"{data.len} Junk bytes -> Remote"

proc handleUpRemote(remote: Connection){.async.} =
    try:
        let bytes = await remote.reader.consume()
        when not defined release:
            echo "discarded ", bytes, " bytes form up-bound."
    except:
        if globals.log_conn_error: echo "[Error] [handleUpRemote] [loopEx]: ", getCurrentExceptionMsg()

    if globals.log_conn_destory: echo "[Closed] [poolController] [End]:", "a up-bound"
    context.up_bounds.remove(remote)
    remote.close



proc processDownBoundRemote(remote: Connection) {.async.} =
    var data = newStringOfCap(4200)
    var boundary: uint16 = 0
    var cid: uint16
    var port: uint16
    var flag: uint8
    var dec_bytes_left: uint
    var fake_bytes: uint8 = 0
    var client: Connection = nil
    try:
        while not remote.isNil and not remote.closed:
            #read
            data.setlen remote.reader.tsource.offset
            if data.len() == 0:
                if remote.reader.atEof():
                    break
                else:
                    discard await remote.reader.readOnce(addr data, 0)
                    continue

            if boundary == 0:
                let width = int(globals.full_tls_record_len + globals.mux_record_len)
                data.setLen width
                await remote.reader.readExactly(addr data[0], width)
                copyMem(addr boundary, addr data[3], sizeof(boundary))
                if boundary == 0: break

                copyMem(addr cid, addr data[globals.full_tls_record_len], sizeof(cid))
                copyMem(addr flag, addr data[globals.full_tls_record_len.int + sizeof(cid) + sizeof(port)], sizeof(flag))

                cid = cid xor boundary
                flag = (flag xor boundary.uint8)
                fake_bytes = bitand((flag shr 4), 0xF)
                flag = bitand(flag, 0xF)

                boundary -= globals.mux_record_len.uint16 + fake_bytes
                if boundary == 0:
                    context.user_inbounds.with(cid, child_client):
                        echo "Remote wanted to close ", cid
                        child_client.close()
                        context.user_inbounds.remove(child_client)
                    if fake_bytes > 0:
                        print fake_bytes, cid
                        discard await remote.reader.consume(fake_bytes.int)
                else:
                    dec_bytes_left = min(globals.fast_encrypt_width, boundary)

                continue

            # let readable = min(boundary, data.len().uint16)
            # boundary -= readable; data.setlen readable
            # await remote.reader.readExactly(addr data[0], readable.int)
            data.setLen(max(4200,boundary.int))
            await remote.reader.readExactly(addr data[0], boundary.int)
            if  fake_bytes > 0: discard await  remote.reader.consume(fake_bytes.int)
            # if boundary == 0 and fake_bytes > 0: discard await remote.reader.consume(fake_bytes.int)
            if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from remote"

            if dec_bytes_left > 0:
                let consumed = min(data.len(), dec_bytes_left.int)
                dec_bytes_left -= consumed.uint
                unPackForRead(data, consumed)

            if DataFlags.udp in cast[TransferFlags](flag):
                context.user_inbounds_udp.with(cid, udp_up_bound):
                    await udp_up_bound.transp.sendTo(udp_up_bound.raddr, data)
                    if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> client"

            else:
                try:
                    if client == nil or client.id != cid:
                        client = context.user_inbounds.find(cid)
                    if client != nil and not client.closed:
                        await client.writer.write(data)
                        if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> client"
                        if fupload: await sendJunkData(globals.noise_ratio.int * data.len())
                    else:
                        let temp_up_bound = await acquireRemoteConnection(true)
                        if temp_up_bound != nil:
                            await temp_up_bound.writer.write(closeSignalData(cid))
                            echo "here x2"

                except:
                    if globals.log_conn_error: echo "[Error] [processDownBoundRemote] [writeCl]: ", getCurrentExceptionMsg()


    except:
        if globals.log_conn_error: echo "[Error] [processDownBoundRemote] [loopEx]: ", getCurrentExceptionMsg()
    #close
    context.dw_bounds.remove(remote)
    await remote.closeWait()

proc processTcpConnection(client: Connection) {.async.} =

    proc closeLine(remote, client: Connection) {.async.} =
        if globals.log_conn_destory: echo "closed client & remote"
        if remote != nil:
            await allFutures(remote.closeWait(), client.closeWait())
        else:
            await client.closeWait()

    proc processSNIRemote(remote: Connection) {.async.} =
        var data = newStringOfCap(4200)
        try:
            while not remote.isNil and not remote.closed:
                #read
                data.setlen remote.reader.tsource.offset
                if data.len() == 0:
                    if remote.reader.atEof():
                        await closeLine(client, remote)
                        return
                    else:
                        discard await remote.reader.readOnce(addr data, 0)
                        continue

                await remote.reader.readExactly(addr data[0], data.len)
                if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from target Sni"

                # write
                if not client.closed:
                    await client.writer.write(data)
                    if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> client "
        except:
            if globals.log_conn_error: echo "[Error] [processSNIRemote] [loopEx]: ", getCurrentExceptionMsg()
        #close
        # await remote.closeWait()
        if not client.isTrusted():
            await client.closeWait()


    proc processClient(ub: Connection) {.async.} =
        var up_bound = ub
        var data = newStringOfCap(4200)
        var first_packet = true
        try:
            while not client.closed:
                #read
                data.setlen client.reader.tsource.offset
                if data.len() == 0:
                    if client.reader.atEof():
                        break
                    else:
                        discard await client.reader.readOnce(addr data, 0)
                        continue
                if client.trusted == TrustStatus.no:
                    let width = globals.full_tls_record_len.int + globals.mux_record_len.int
                    data.setLen(data.len() + width)
                    await client.reader.readExactly(addr data[0 + width], data.len - width)
                else:
                    await client.reader.readExactly(addr data[0], data.len)

                if globals.log_data_len: echo &"[processClient] {data.len()} bytes from client {client.id}"

                #trust based route
                if client.trusted == TrustStatus.pending:

                    var (trust, up) = monitorData(data)
                    if trust:
                        #peer connection
                        client.trusted = TrustStatus.yes
                        up_bound.close() # close SNI remote
                        up_bound = nil
                        let address = client.transp.remoteAddress()
                        print "Peer Fake Handshake Complete !", up
                        # context.available_peer_inbounds.register(client)
                        context.peer_ip = client.transp.remoteAddress.address
                        if up:
                            context.up_bounds.register(client)
                            asyncSpawn handleUpRemote(client)

                        else:
                            context.dw_bounds.register(client)
                            asyncSpawn processDownBoundRemote(client)

                        return # no need to close this client
                    else:
                        if first_packet:
                            if not data.contains(globals.final_target_domain):
                                #user connection but no peer connected yet
                                client.trusted = TrustStatus.no
                                echo "[Error] user connection but no peer connected yet."
                                await closeLine(client, up_bound)
                                return
                        if (epochTime().uint - client.creation_time) > globals.trust_time:
                            #user connection but no peer connected yet
                            #peer connection but couldnt finish handshake in time
                            client.trusted = TrustStatus.no
                            await closeLine(client, up_bound)
                            return

                    first_packet = false

                #write
                if up_bound.closed or up_bound.isClosing:
                    up_bound = await acquireRemoteConnection(upload = true)
                    if up_bound == nil:
                        if globals.log_conn_error: echo "[Error] [processClient] [loop]: ", "left without connection, closes forcefully."
                        await closeLine(client, up_bound); return

                if up_bound.isTrusted:
                    data.packForSend(client.id, client.port.uint16)

                try:
                    await up_bound.writer.write(data)
                except:
                    echo "[Error] [processClient] [writeUp]: ", getCurrentExceptionMsg()

                if globals.log_data_len: echo &"{data.len} bytes -> Remote"

                if fupload and up_bound.isTrusted: await sendJunkData(globals.noise_ratio.int * data.len())


        except:
            if globals.log_conn_error: echo "[Error] [processClient] [loopEx]: ", getCurrentExceptionMsg()

        #close
        client.close()
        context.user_inbounds.remove(client)

        try:
            let temp_up_bound = await acquireRemoteConnection(true)
            if temp_up_bound != nil:
                await temp_up_bound.writer.write(closeSignalData(client.id))
                echo "here x1"
        except:
            if globals.log_conn_error: echo "[Error] [processClient] [closeSig]: ", getCurrentExceptionMsg()


    #Initialize remote
    var client_up_bound: Connection = nil
    try:
        if globals.trusted_foreign_peers.len != 0:

            if isV4Mapped(client.transp.remoteAddress):
                let ipv4 = toIPv4(client.transp.remoteAddress).address
                if ipv4 in globals.trusted_foreign_peers:
                    #load balancer connection
                    client_up_bound = await connectTargetSNI()
                    asyncSpawn processSNIRemote(client_up_bound)
            else:
                if client.transp.remoteAddress.address in globals.trusted_foreign_peers:
                    #load balancer connection
                    client_up_bound = await connectTargetSNI()
                    asyncSpawn processSNIRemote(client_up_bound)

        if client_up_bound == nil:
            if context.peer_ip != IpAddress() and
                context.peer_ip != client.transp.remoteAddress.address:
                if globals.log_conn_create: echo "Real User connected !"
                client.trusted = TrustStatus.no
                client.assignId()
                client_up_bound = await acquireRemoteConnection(upload = true) #associate peer

                if client_up_bound != nil:
                    if globals.log_conn_create: echo "Associated a peer connection."
                    context.user_inbounds.register(client)

                else:
                    echo &"[AssociatedCon][Error] left without connection, closes forcefully."
                    await client.closeWait()
                    return
            else:
                client_up_bound = await connectTargetSNI()
                asyncSpawn processSNIRemote(client_up_bound)

        asyncSpawn processClient(client_up_bound)

    except:
        printEx()

proc processUdpPacket(client: UdpConnection) {.async.} =

    proc processClient(remote: Connection) {.async.} =
        try:
            var remote = remote
            var pbytes = client.transp.getMessage()
            var nbytes = len(pbytes)
            let width = globals.full_tls_record_len.int + globals.mux_record_len.int

            if nbytes > 0:
                var data = newStringOfCap(cap = nbytes + width); data.setlen(nbytes + width)
                copyMem(addr data[0 + width], addr pbytes[0], data.len - width)
                if globals.log_data_len: echo &"[processClient] {data.len()} bytes from client {client.id}"

                #write
                if remote.closed:
                    if globals.log_conn_error: echo "[Error] [UDP-processClient] [loop]: ", " Tcp remote was just closed!"
                    return

                data.packForSend(client.id, client.port.uint16, flags = {DataFlags.udp})
                await remote.writer.write(data)
                if globals.log_data_len: echo &"{data.len} bytes -> Remote"

                inc remote.udp_packets; if remote.udp_packets > globals.udp_max_ppc: remote.close()

                if fupload: await sendJunkData(globals.noise_ratio.int * data.len())

        except:
            if globals.log_conn_error: echo "[Error] [UDP-processClient] [loopEx]: ", getCurrentExceptionMsg()


    #Initialize remote
    try:
        if globals.log_conn_create: echo "Real User connected (UDP) !"
        # var remote = await acquireRemoteConnection(not client.mark) #associate peer
        if client.bound == nil or client.bound.closed:
            client.bound = await acquireRemoteConnection(upload = true)

        if client.bound != nil:
            if globals.log_conn_create: echo "Associated a peer connection"
        else:
            echo &"[AssociatedCon][Error] left without connection, closes forcefully."
            return
        await processClient(client.bound)

    except:
        printEx()


proc start*(){.async.} =
    var pbuf = newString(len = 28)
    context.user_inbounds.new()
    context.user_inbounds_udp.new()
    context.available_peer_inbounds.new()
    context.up_bounds.new()
    context.dw_bounds.new()
    proc startTcpListener(){.async.} =

        proc serveStreamClient(server: StreamServer,
                        transp: StreamTransport) {.async.} =
            try:
                let con = await Connection.new(transp, no_id = true)
                let address = con.transp.remoteAddress()
                if globals.multi_port:
                    var origin_port: int
                    var size = int(if isV4Mapped(con.transp.remoteAddress): 16 else: 28)


                    let sol = int(if isV4Mapped(con.transp.remoteAddress): globals.SOL_IP else: globals.SOL_IPV6)
                    if not getSockOpt(transp.fd, sol, int(globals.SO_ORIGINAL_DST), addr pbuf[0], size):
                        echo "multiport failure getting origin port. !"
                        await con.closeWait()
                        return

                    bigEndian16(addr origin_port, addr pbuf[2])

                    con.port = origin_port.Port

                    if globals.log_conn_create: print "Connected client: ", address, con.port
                else:
                    con.port = server.local.port.Port
                    if globals.log_conn_create: print "Connected client: ", address

                asyncSpawn processTcpConnection(con)
            except:
                echo "handle client connection error:"
                echo getCurrentExceptionMsg()


        var address = initTAddress(globals.listen_addr, globals.listen_port.Port)

        let server: StreamServer =
            try:
                var flags = {ServerFlags.TcpNoDelay, ServerFlags.ReuseAddr}
                if globals.keep_system_limit:
                    flags.excl ServerFlags.TcpNoDelay
                createStreamServer(address, serveStreamClient, flags = flags)
            except TransportOsError as exc:
                raise exc
            except CatchableError as exc:
                raise exc

        context.listener = server

        if globals.multi_port:
            assert globals.listen_port == server.localAddress().port
            # globals.listen_port = server.localAddress().port # its must be same as listen port

            globals.createIptablesForwardRules()

        server.start()
        echo &"Started tcp server  {globals.listen_addr}:{globals.listen_port}"


    proc startUdpListener() {.async.} =

        proc handleDatagram(transp: DatagramTransport,
                    raddr: TransportAddress): Future[void] {.async.} =

            var (found, connection) = findUdp(context.user_inbounds_udp, raddr)
            if not found:
                connection = UdpConnection.new(transp, raddr)
                context.user_inbounds_udp.register connection

            let address = raddr
            if globals.log_conn_create: print "Connected client: ", address

            if globals.multi_port:
                var origin_port: int
                var size = int(if isV4Mapped(connection.transp.remoteAddress): 16 else: 28)
                let sol = int(if isV4Mapped(connection.transp.remoteAddress): globals.SOL_IP else: globals.SOL_IPV6)
                if not getSockOpt(connection.transp.fd, sol, int(globals.SO_ORIGINAL_DST),
                addr pbuf[0], size):
                    echo "multiport failure getting origin port. !"
                    return
                bigEndian16(addr origin_port, addr pbuf[2])

                connection.port = origin_port.Port

                if globals.log_conn_create: print "Connected client: ", address, connection.port
            else:
                # connection.port = transp.localAddress.port.Port
                connection.port = globals.listen_port
                if globals.log_conn_create: print "Connected client: ", address


            asyncSpawn processUdpPacket(connection)

        # var address4 = initTAddress(globals.listen_addr4, globals.listen_port.Port)
        var address = initTAddress(globals.listen_addr, globals.listen_port.Port)

        # var dgramServer4 = newDatagramTransport(handleDatagram, local = address4,flags = {ReuseAddr})
        # echo &"Started udp server  {globals.listen_addr4}:{globals.listen_port}"

        context.listener_udp = newDatagramTransport6(handleDatagram, local = address, flags = {ServerFlags.ReuseAddr})

        echo &"Started udp server  {globals.listen_addr}:{globals.listen_port}"

        await context.listener_udp.join()
        echo "Udp server ended."

    trackOldConnections(context.up_bounds, globals.connection_age)
    trackOldConnections(context.dw_bounds, globals.connection_age)

    await sleepAsync(200)
    if globals.accept_udp:
        echo &"Mode Iran (Tcp + Udp): {globals.self_ip}  handshake: {globals.final_target_domain}"
    else:
        echo &"Mode Iran: {globals.self_ip}  handshake: {globals.final_target_domain}"


    asyncSpawn startTcpListener()
    if globals.accept_udp:
        trackDeadUdpConnections(context.user_inbounds_udp, globals.udp_max_idle_time, false)
        asyncSpawn startUdpListener()




    # asyncSpawn start_server_listener()





