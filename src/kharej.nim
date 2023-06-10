import std/[asyncdispatch, strformat, strutils, net, tables, random]
import overrides/[asyncnet]
import times, print, connection, pipe
from globals import nil



type
    KharejServerConnectionPoolContext = object
        listener: Connection
        inbound: Connections
        outbound: Connections

var context = KharejServerConnectionPoolContext()
let ssl_ctx = newContext(verifyMode = CVerifyPeer)


proc ssl_connect(con: Connection, ip: string, port: int, sni: string){.async.} =
    wrapSocket(ssl_ctx, con.socket)
    var fc = 0
    while true:
        if fc > 6:
            raise newException(ValueError, "Request Timed Out!")
        try:
            await con.socket.connect(ip, port.Port, sni = sni)
            break
        except:
            echo &"ssl connect error ! retry in {min(1000,fc*50)} ms"
            await sleepAsync(min(1000, fc*200))
            inc fc

    print "ssl socket conencted"

    # let to_send = &"GET / HTTP/1.1\nHost: {sni}\nAccept: */*\n\n"
    # await socket.send(to_send)  [not required ...]

    con.socket.isSsl = false #now break it

    let rlen = 16*(4+rand(4))
    var random_trust_data: string
    random_trust_data.setLen(rlen)

    for i in 0..<rlen:
        random_trust_data[i] = rand(char.low .. char.high).char

    prepareMutation(random_trust_data)
    copyMem(unsafeAddr random_trust_data[0], unsafeAddr globals.sh1.uint32, 4)
    copyMem(unsafeAddr random_trust_data[4], unsafeAddr globals.sh2.uint32, 4)
    copyMem(unsafeAddr random_trust_data[8], unsafeAddr con.id, 4)

    await con.socket.send(random_trust_data)
    con.trusted = TrustStatus.yes


proc poolFrame() =
    proc create() =
        var con = newConnection(address = globals.next_route_addr)
        var fut = ssl_connect(con, globals.next_route_addr, globals.next_route_port, globals.final_target_domain)
        fut.addCallback(
            proc() {.gcsafe.} =
                if fut.failed:
                    echo fut.error.msg
                else:
                    if globals.log_conn_create: echo &"[createNewCon] registered a new connection to the pool"
                    context.outbound.register con
        )

    var i = context.outbound.connections.len()
    while i.uint32 < globals.pool_size:
        try:
            create()
            inc i
        except:
            discard
            



proc processConnection(client: Connection) {.async.} =
    var client: Connection = client
    var remote: Connection

    var closed = false
    proc close() =
        if not closed:
            closed = true
            if globals.log_conn_destory: echo "[processRemote] closed client & remote"
            client.close()
            if remote.isTrusted:
                remote.socket.isSsl = true
            remote.close()


    proc processRemote() {.async.} =
        var data = ""
        while not remote.isClosed:

            try:
                data = await remote.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from remote"
            except:
                close()
                break

            if data.len() == 0:
                close()
                break

            try:
                normalRead(data)
                if not client.isClosed:
                    await client.send(data)
                    if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> client "


            except: continue

    proc chooseRemote() {.async.} =
        remote = context.outbound.grab()
        if remote != nil:
            if globals.log_conn_create: echo &"[createNewCon][Succ] grabbed a connection"
            poolFrame()
            asyncCheck processRemote()
            return

        await sleepAsync(600)
        remote = context.outbound.grab()

        if remote != nil:
            if globals.log_conn_create: echo &"[createNewCon][Succ] grabbed a connection"
            poolFrame()
            asyncCheck processRemote()
        else:
            if globals.log_conn_destory: echo &"[createNewCon][Error] left without connection, closes forcefully."
            client.close()


    await chooseRemote()


    proc processClient() {.async.} =
        var data = ""

        while not client.isClosed:
            try:
                data = await client.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[processClient] {data.len()} bytes from client {client.id}"
            except:
                close()
                break

            if data.len() == 0:
                close()
                break
            try:
                if not remote.isClosed:
                    normalSend(data)
                    await remote.send(data)
                    if globals.log_data_len: echo &"{data.len} bytes -> Remote"

            except: continue
    try:
        asyncCheck processClient()
    except:
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
            var con = newConnection(client, address)
            if globals.log_conn_create: print "Connected client: ", address

            asyncCheck processConnection(con)

    poolFrame()
    await sleepAsync(1200)
    echo &"Mode Tunnel:  {globals.self_ip}  <->  {globals.next_route_addr}  => {globals.final_target_domain}"
    asyncCheck start_server()



