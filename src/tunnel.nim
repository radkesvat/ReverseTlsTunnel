import std/[asyncdispatch, nativesockets, strformat, strutils, net, tables, random, endians]
import overrides/[asyncnet]
import times, print, connection, pipe
from globals import nil

when defined(windows):
    from winlean import getSockOpt
else:
    from posix import getSockOpt

type
    TunnelConnectionPoolContext = object
        listener: Connection
        inbound: Connections
        outbound: Connections

var context = TunnelConnectionPoolContext()

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


proc processConnection(client: Connection) {.async.} =
    var client: Connection = client
    var remote: Connection

    var closed = false
    proc close() =
        if not closed:
            closed = true
            if globals.log_conn_destory: echo "[processRemote] closed client & remote"
            client.close()
            if not remote.isNil():
                remote.close()


    proc processRemote() {.async.} =
        var data = ""
        while not remote.isClosed:
            try:
                data = await remote.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[processRemote] {data.len()} bytes from remote"
            except:
                break

            if data.len() == 0:
                break

            try:
                normalRead(data)
                if not client.isClosed:
                    await client.send(data)
                    if globals.log_data_len: echo &"[processRemote] {data.len} bytes -> client "

            except: break
        close()

    proc chooseRemote() {.async.} =
        if not context.outbound.hasKeyOrPut(client.port,Connections()):
            poolFrame(client.port,globals.pool_size)
            await sleepAsync(250)

        remote = context.outbound[client.port].grab()
        if remote != nil:
            if globals.log_conn_create: echo &"[createNewCon][Succ] grabbed a connection"
            callSoon do: poolFrame(client.port)

            asyncCheck processRemote()
            return

        await sleepAsync(300)
        remote = context.outbound[client.port].grab()

        if remote != nil:
            if globals.log_conn_create: echo &"[createNewCon][Succ] grabbed a connection"
            callSoon do: poolFrame(client.port)
            asyncCheck processRemote()
        else:

            if globals.log_conn_destory: echo &"[createNewCon][Error] left without connection, closes forcefully."
            callSoon do: poolFrame(client.port)
            client.close()


    await chooseRemote()


    proc processClient() {.async.} =
        var data = ""

        while not client.isClosed:
            try:
                data = await client.recv(globals.chunk_size)
                if globals.log_data_len: echo &"[processClient] {data.len()} bytes from client {client.id}"
            except:
                break

            if data.len() == 0:
                break
            try:
                if not remote.isClosed:
                    normalSend(data)
                    await remote.send(data)
                    if globals.log_data_len: echo &"{data.len} bytes -> Remote"

            except: break
        close()
    try:
        asyncCheck processClient()
    except:
        print getCurrentExceptionMsg()




proc start*(){.async.} =
    var pbuf = newString(len = 16)

    proc start_server(){.async.} =

        context.listener = newConnection(address = "This Server")
        context.listener.socket.setSockOpt(OptReuseAddr, true)
        context.listener.socket.bindAddr(globals.listen_port.Port, globals.listen_addr)
        if globals.multi_port:
            globals.listen_port = getSockName(context.listener.socket.getFd().SocketHandle).uint32
            echo "Multi port mode !"
            globals.createIptablesRules()

        echo &"Started tcp server... {globals.listen_addr}:{globals.listen_port}"
        context.listener.socket.listen()

        while true:
            let (address, client) = await context.listener.socket.acceptAddr()
            var con = newConnection(client, address)
            if globals.multi_port:
                var origin_port:cushort
                var size = 16.SockLen
                if getSockOpt(con.socket.getFd().SocketHandle, cint(globals.SOL_IP), cint(globals.SO_ORIGINAL_DST),
                addr(pbuf[0]), addr(size)) < 0'i32:
                    echo "multiport failure getting origin port. !"
                    continue
                bigEndian16(addr origin_port,addr pbuf[2])

                con.port = origin_port
                if globals.log_conn_create: print "Connected client: ", address , " : ",  con.port
            else:
                con.port = globals.listen_port

                if globals.log_conn_create: print "Connected client: ", address

            asyncCheck processConnection(con)

    if not globals.multi_port:
        context.outbound[globals.listen_port] = Connections()
        poolFrame(globals.listen_port,globals.pool_size)
        
    await sleepAsync(1200)
    echo &"Mode Tunnel:  {globals.self_ip} <->  {globals.next_route_addr}  => {globals.final_target_domain}"
    asyncCheck start_server()



