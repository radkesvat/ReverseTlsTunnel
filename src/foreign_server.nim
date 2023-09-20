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
        outbounds: Connections

var context = ServerConnectionPoolContext()

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

proc monitorData(data: string): bool =
    try:
        if len(data) < 16: return false
        let base = 5 + 7 + `mod`(globals.sh5, 7.uint8)

        var sh3_c: uint32
        var sh4_c: uint32

        copyMem(unsafeAddr sh3_c, unsafeAddr data[base+0], 4)
        copyMem(unsafeAddr sh4_c, unsafeAddr data[base+4], 4)


        let chk1 = sh3_c == globals.sh3
        let chk2 = sh4_c == globals.sh4

        return chk1 and chk2
    except:
        return false


proc remoteTrusted(port: Port): Future[Connection] {.async.} =
    var con = await connection.connect(initTAddress(globals.next_route_addr, port))
    con.trusted = TrustStatus.yes
    return con

proc acquireClientConnection(): Future[Connection] {.async.} =
    var found: Connection = nil
    for i in 0..<50:
        found = context.used_peer_outbounds.randomPick()
        if found != nil and not found.closed:
            return found
        else:
            context.used_peer_outbounds.remove(found)

    return nil


proc processConnection(client: Connection) {.async.} =


    proc closeLine(client: Connection, remote: Connection) {.async.} =
        if globals.log_conn_destory: echo "closed client & remote"
        if remote != nil:
            await allFutures(remote.closeWait(), client.closeWait())
        else:
            await client.closeWait()

    proc processRemote(remote: Connection) {.async.} =
        var client = client
        var data = newString(len = 0)
        try:
            while not remote.closed:
                #read
                data.setlen remote.reader.tsource.offset
                if data.len() == 0:
                    if remote.reader.atEof():
                        break
                    else:
                        discard await remote.reader.readOnce(addr data, 0)
                        continue
                let width = globals.full_tls_record_len.int + globals.mux_record_len.int
                data.setLen(data.len() + width)
                await remote.reader.readExactly(addr data[0 + width], data.len - width)
                if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from remote"



                #write

                # context.used_peer_outbounds.with(remote.id, child_client):
                #     unPackForRead(data)
                #     if not child_client.closed:
                #         await child_client.writer.write(data)
                #         if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> client "
                #     else:
                #         context.used_peer_outbounds.remove(child_client)
                #         break

                if client.closed:
                    client = await acquireClientConnection()
                    if client == nil: await closeLine(client, remote); return

                packForSend(data, remote.id, remote.port.uint16)
                await client.twriter.write(data)
                if globals.log_data_len: echo &"[processRemote] Sent {data.len()} bytes ->  client"

        except:
            if globals.log_conn_error: echo getCurrentExceptionMsg()
        #close
        try:
            if not client.closed:
                await client.twriter.write(closeSignalData(remote.id))
        except:
            if globals.log_conn_error: echo getCurrentExceptionMsg()


        await remote.closeWait()

    proc proccessClient() {.async.} =
        var remote: Connection = nil
        var data = newString(len = 0)
        var boundary: uint16 = 0
        var cid: uint16
        var port: uint16

        try:
            while not client.closed:
                #read
                data.setlen client.treader.tsource.offset
                if data.len() == 0:
                    if client.treader.atEof():
                        if client.isTrusted:
                            break
                        else:
                            await closeLine(client, remote)
                            return
                    else:
                        discard await client.treader.readOnce(addr data, 0); continue

                if client.isTrusted:
                    if boundary == 0:
                        let width = int(globals.full_tls_record_len + globals.mux_record_len)
                        data.setLen width
                        await client.treader.readExactly(addr data[0], width)
                        copyMem(addr boundary, addr data[3], sizeof(boundary))
                        if boundary == 0: break
                        boundary-=globals.mux_record_len.uint16

                        copyMem(addr cid, addr data[globals.full_tls_record_len], sizeof(cid))
                        copyMem(addr port, addr data[globals.full_tls_record_len.int + sizeof(cid)], sizeof(port))
                        cid = cid xor boundary
                        port = port xor boundary
                        if boundary == globals.mux_width:
                            boundary = 0
                            context.outbounds.with(cid, child_remote):
                                child_remote.close()
                                context.outbounds.remove(child_remote)
                        continue

                    let readable = min(boundary, data.len().uint16)
                    boundary -= readable; data.setlen readable
                    await client.treader.readExactly(addr data[0], readable.int)
                else:
                    await client.treader.readExactly(addr data[0], data.len)
                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes from client"



                #write
                if client.isTrusted():
                    unPackForRead(data)

                    if context.outbounds.hasID(cid):
                        context.outbounds.with(cid, child_remote):
                            if not isSet(child_remote.estabilished): await child_remote.estabilished.wait()
                            #write
                            if not child_remote.closed():
                                await child_remote.writer.write(data)
                                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote"
                            else:
                                await client.writer.write(closeSignalData(cid))
                                context.outbounds.remove cid

                    else:
                        let new_remote = await remoteTrusted(if globals.multi_port: port.Port else: globals.next_route_port)
                        new_remote.id = cid
                        context.outbounds.register(new_remote)
                        asyncCheck processRemote(new_remote)
                        await new_remote.writer.write(data)
                        if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote"
                        poolFrame()
                        context.free_peer_outbounds.remove(client)
                        context.used_peer_outbounds.register(client)

                if client.trusted == TrustStatus.pending:
                    var trust = monitorData(data)
                    if trust:
                        client.trusted = TrustStatus.yes
                        print "Fake Reverse Handshake Complete !"

                    else:
                        echo "[proccessClient] Target server was not a trusted tunnel client, closing..."
                        client.trusted = TrustStatus.no
                        break

        except:
            if globals.log_conn_error: echo getCurrentExceptionMsg()

        #close
        poolFrame()
        context.free_peer_outbounds.remove(client)
        await client.closeWait()


        # await closeLine(client, remote)


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
    echo &"Mode Foreign Server:  {globals.listen_addr} <-> ({globals.final_target_domain} with ip {globals.final_target_ip})"
    trackIdleConnections(context.free_peer_outbounds, globals.pool_age)
    #just to make sure we always willing to connect to the peer
    while true:
        poolFrame()
        await sleepAsync(5.secs)
