import overrides/[asyncnet]
import std/[tables, times,os , random, asyncdispatch, strutils, net, random]
import globals


var lgid: uint32 = 1
proc new_uid: uint32 =
    result = lgid
    inc lgid


type
    TrustStatus*{.pure.} = enum
        no, pending, yes

    Connection* = ref object
        recv_buffer*: string
        id*: uint32
        creation_time*: uint
        trusted*: TrustStatus
        address*: string
        socket*: AsyncSocket
        estabilished*: bool

    Connections* = object
        connections*: Table[uint32, Connection]

# proc has(cons:Connections,con:Connection):bool =cons.connections.hasKey(con.id)

template send*(con: Connection, data: string): untyped = con.socket.send(data)
template recv*(con: Connection, data: SomeInteger): untyped = con.socket.recv(data)




proc isClosed*(con: Connection): bool = con.socket.isClosed()
template close*(con: Connection) = con.socket.close()

proc close*(cons: var Connections, con: Connection) =
    con.socket.close()
    if cons.connections.hasKey(con.id):
        cons.connections.del(con.id)

proc isTrusted*(con: Connection): bool = con.trusted == TrustStatus.yes

proc takeRandom*(cons: Connections): Connection =
    var chosen = rand(cons.connections.len()-1)
    for k in cons.connections.keys:
        if chosen == 0:
            return cons.connections[k]
        dec chosen

    raise newException(ValueError, "could not take random conn")




proc newConnection*(socket: AsyncSocket = nil, address: string, buffered: bool = globals.socket_buffered): Connection =
    new(result)
    # result.recv_buffer =  newStringOfCap(globals.connection_buf_cap)
    # if id == 0 : result.id = new_uid()
    result.id = 0
    result.creation_time = epochTime().uint32
    result.trusted = TrustStatus.pending
    result.address = address

    if socket == nil: result.socket = newAsyncSocket(buffered = buffered)
    else: result.socket = socket

    when not defined(android):
        result.socket.setSockOpt(OptNoDelay, true)


# proc attachID*(con : var Connection)=
#     if con.id == 0:
#         con.id = new_uid()

proc grab*(cons: var Connections):Connection=
    if cons.connections.len() == 0: return nil
    for k in cons.connections.keys:
        assert cons.connections.pop(k,result)
        return result

proc register*(cons: var Connections, con: Connection) =
    if con.id == 0:
        con.id = new_uid()
    assert not cons.connections.hasKey con.id

    cons.connections[con.id] = con

