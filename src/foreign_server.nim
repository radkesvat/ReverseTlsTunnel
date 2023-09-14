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
        outbound: Connections

var context = ServerConnectionPoolContext()
var mux = false

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

    # case globals.self_ip.family: # the type of the IP address (IPv4 or IPv6)
    #     of IpAddressFamily.IPv6:
    #         random_trust_data[base+9] = 6.char
    #         copyMem(unsafeAddr random_trust_data[base+10], unsafeAddr globals.self_ip.address_v6[0], globals.self_ip.address_v6.len)

    #     of IpAddressFamily.IPv4:
    #         random_trust_data[base+9] = 4.char
    #         copyMem(unsafeAddr random_trust_data[base+10], unsafeAddr globals.self_ip.address_v4[0], globals.self_ip.address_v4.len)

    return random_trust_data

# proc sslConnect(con: Connection, ip: string, sni: string){.async.} =
#     # con.socket.close()
#     var fc = 0
#     echo &"connecting to {ip}:{$con.port} (sni: {sni}) ..."

#     while true:
#         if fc > 3:
#             con.close()
#             raise newException(ValueError, "[SslConnect] could not connect, all retires failed")

#         # var fut = con.socket.connect(ip, con.port.Port, sni = sni)
#         var fut = asyncnet.dial(ip, Port(con.port), buffered = false)

#         var timeout = withTimeout(fut, 3000)
#         yield timeout
#         if timeout.failed():
#             inc fc
#             if globals.log_conn_error: echo timeout.error.msg
#             if globals.log_conn_error: echo &"[SslConnect] retry in {min(1000,fc*200)} ms"
#             await sleepAsync(min(1000, fc*200))
#             continue
#         if timeout.read() == true:
#             con.socket = fut.read()
#             break
#         if timeout.read() == false:
#             con.close()
#             raise newException(ValueError, "[SslConnect] dial timed-out")

#     try:
#         if not globals.keep_system_limit: con.socket.setSockOpt(OptNoDelay, true)

#         ssl_ctx.wrapConnectedSocket(
#             con.socket, handshakeAsClient, sni)
#         let flags = {SocketFlag.SafeDisconn}

#         block handshake:
#             sslLoop(con.socket, flags, sslDoHandshake(con.socket.sslHandle))

#     except:
#         echo "[SslConnect] handshake error!"
#         con.close()
#         raise getCurrentException()

#     if globals.log_conn_create: print "[SslConnect] conencted !"

    
#     SSL_free(con.socket.sslHandle)
#     con.socket.isSsl = false

#     #AES default chunk size is 16 so use a multple of 16
#     let rlen: uint16 = uint16(16*(6+rand(4)))
#     var random_trust_data: string
#     random_trust_data.setLen(rlen)


#     copyMem(addr random_trust_data[0], addr(globals.random_str[rand(250)]), rlen)
#     copyMem(addr random_trust_data[0], addr globals.tls13_record_layer[0], 3) #tls header
#     copyMem(addr random_trust_data[3], addr rlen, 2) #tls len



#     let base = 5 + 7 + `mod`(globals.sh5, 7.uint8)
#     copyMem(unsafeAddr random_trust_data[base+0], unsafeAddr globals.sh1.uint32, 4)
#     copyMem(unsafeAddr random_trust_data[base+4], unsafeAddr globals.sh2.uint32, 4)

#     # case globals.self_ip.family: # the type of the IP address (IPv4 or IPv6)
#     #     of IpAddressFamily.IPv6:
#     #         random_trust_data[base+9] = 6.char
#     #         copyMem(unsafeAddr random_trust_data[base+10], unsafeAddr globals.self_ip.address_v6[0], globals.self_ip.address_v6.len)

#     #     of IpAddressFamily.IPv4:
#     #         random_trust_data[base+9] = 4.char
#     #         copyMem(unsafeAddr random_trust_data[base+10], unsafeAddr globals.self_ip.address_v4[0], globals.self_ip.address_v4.len)


#     # if globals.multi_port:
#     #     copyMem(unsafeAddr random_trust_data[8], unsafeAddr client_origin_port, 4)
#     await con.unEncryptedSend(random_trust_data)

#     con.trusted = TrustStatus.pending


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
    # var remoteEstabilishment: Future[void] = nil

    proc remoteTrusted(port:Port): Future[Connection] {.async.} =
        var con = await connection.connect(initTAddress(globals.next_route_addr,port))
        con.trusted = TrustStatus.yes
        return con


    var closed = false
    proc close(client: Connection,remote:Connection) {.async.} =
        if not closed:
            closed = true
            if globals.log_conn_destory: echo "closed client & remote"
            if remote != nil:
                await (remote.closeWait() and client.closeWait())
            else:
                await client.closeWait()

    proc processRemote(remote: Connection) {.async.} =
        var data = newString(len = globals.chunk_size)
        try:
            while not remote.closed:

                # data = await remote.recv(if mux: globals.mux_payload_size else: globals.chunk_size)
                data.setlen await remote.reader.readOnce(addr data[0], globals.chunk_size)

                if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from remote"


                if data.len() == 0:
                    break
                
                if not client.closed:
                    if mux: packForSendMux(remote.id, remote.port.uint16, data) else: packForSend(data)

                    await client.twriter.write(data)
                    if globals.log_data_len: echo &"[processRemote] Sent {data.len()} bytes ->  client"

        except: 
            if globals.log_conn_error: echo getCurrentExceptionMsg()
        if mux:
            await remote.closeWait()
            context.outbound.remove(remote)

            if not client.closed and client.mux_holds.contains(remote.id):
                client.mux_holds.remove(remote.id)
                inc client.mux_closes
                var data = ""
                echo "sending mux client close .... ", remote.id
                packForSendMux(remote.id, remote.port.uint16, data)
                await client.twriter.write(data)

            if client.mux_closes >= client.mux_capacity:
                await client.closeWait() #end full connection
        else:
            await close(client,remote)

    proc proccessClient() {.async.} =
        var remote: Connection = nil
        var data = newString(len = globals.chunk_size)

        try:
            while not client.closed:
                data.setlen await client.treader.readOnce(addr data[0], globals.chunk_size)

                # data = await client.recv(if mux: globals.mux_chunk_size else: globals.chunk_size)
                if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes from client"


                if data.len() == 0:
                    break


                if mux:
                    discard #who cares
                    # if client.isTrusted:
                    #     var (cid, port) = unPackForReadMux(data)
                    #     if not globals.multi_port: port = globals.next_route_port.uint16
                    #     print cid, port
                    #     if not context.outbound.hasID(cid):
                    #         let new_remote = remoteTrusted()
                    #         new_remote.id = cid
                    #         new_remote.port = port
                    #         client.mux_holds.add(new_remote.id)
                    #         if client.mux_holds.len.uint32 > client.mux_capacity:
                    #             echo "[ERROR] this mux connection is taking more than capacity"
                    #         context.outbound.register new_remote
                    #         new_remote.estabilished = new_remote.socket.connect(globals.next_route_addr, port.Port)
                    #         await new_remote.estabilished
                    #         echo "connected to the remote core"
                    #         asyncCheck processRemote(new_remote)

                    #     context.outbound.with(cid, name = con):
                    #         if not con.estabilished.finished:
                    #             await con.estabilished

                    #         if data.len() == 0: #mux remote close
                    #             echo "[processRemote] closed Mux remote"
                    #             con.close()
                    #             context.outbound.remove cid
                    #             client.mux_holds.remove cid
                    #             inc client.mux_closes
                    #         elif not con.closed():
                    #             await con.send(data)
                    #             echo &"[proccessClient] {data.len()} bytes -> remote "

                    # if client.trusted == TrustStatus.pending:
                    #     var (trust, _) = monitorData(data)
                    #     if trust:
                    #         client.trusted = TrustStatus.yes
                    #         print "Fake Reverse Handshake Complete !"
                    #         client.setBuffered()

                    #     else:
                    #         echo "[proccessClient] Target server was not a trusted tunnel client, closing..."
                    #         client.trusted = TrustStatus.no
                    #         break


                else:
                    if (client.isTrusted()) and (remote.isNil()):
                        remote = await remoteTrusted(client.port.Port)
                        asyncCheck processRemote(remote)
                        let i = context.free_peer_outbounds.find(client)
                        if i != -1: context.free_peer_outbounds.del(i)
                        # echo "established to remote, calling pool frame"
                        poolFrame()

    

                    if client.trusted == TrustStatus.pending:
                        var (trust, port) = monitorData(data)
                        if trust:
                            if globals.multi_port:
                                echo "multi-port target:", port
                                client.port = port.Port
                            else:
                                client.port = globals.next_route_port.Port
                            client.trusted = TrustStatus.yes
                            print "Fake Reverse Handshake Complete !"

                            continue
                        else:
                            echo "[proccessClient] Target server was not a trusted tunnel client, closing..."
                            client.trusted = TrustStatus.no
                            break
                        # asyncCheck processRemote()


                    unPackForRead(data)

                    if not remote.closed():
                        await remote.writer.write(data)
                        if globals.log_data_len: echo &"[proccessClient] {data.len()} bytes -> remote "

        except: 
            if globals.log_conn_error: echo getCurrentExceptionMsg()
        if mux:
            await client.closeWait()
            for cid in client.mux_holds:
                context.outbound.with(cid, name = con):
                    await con.closeWait()
        else:
            await close(client,remote)


    try:
        asyncCheck proccessClient()
    except:
        echo "[Server] root level exception"
        print getCurrentExceptionMsg()

proc poolFrame(create_count: uint = 0) =
    var count = create_count

    proc create() {.async.} =
        try:
            var conn = await connect(initTAddress(globals.iran_addr,globals.iran_port),SocketScheme.Secure,globals.final_target_domain)
            echo "TlsHandsahke complete."
            # let pending =
            #     block:
            #         var res: seq[Future[void]]
            #         if not(isNil(conn.reader)) and not(conn.reader.closed()):
            #             res.add(conn.reader.closeWait())
            #         if not(isNil(conn.writer)) and not(conn.writer.closed()):
            #             res.add(conn.writer.closeWait())
            #         res
            # if len(pending) > 0: await allFutures(pending)
            # await allFutures(conn.treader.closeWait(), conn.twriter.closeWait())
            # await stepsAsync(1)

            conn.transp.reader.cancel()
            await stepsAsync(1)
            conn.transp.reader = nil

            # conn.treader = newAsyncStreamReader(transp)
            # conn.twriter = newAsyncStreamWriter(transp)
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
    mux = globals.mux

    echo &"Mode Foreign Server:  {globals.listen_addr} <-> ({globals.final_target_domain} with ip {globals.final_target_ip})"
    #just to make sure we always willing to connect to the peer
    while true:
        poolFrame()
        await sleepAsync(5.secs)
