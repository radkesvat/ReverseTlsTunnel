import overrides/[asyncnet]
import std/[tables,sequtils, times,os , random, asyncdispatch, strutils, net, random]
import globals

type
    TrustStatus*{.pure.} = enum
        no, pending, yes

    Connection* = ref object
        creation_time*: uint
        action_start_time*: uint
        id*: uint32
        trusted*: TrustStatus
        address*: string
        socket*: AsyncSocket
        estabilished*: bool
        isfakessl*:bool
        port*:uint32
        
    Connections* = object
        connections*: Table[uint32, Connection]

var allConnections:seq[Connection]


var lgid: uint32 = 1
proc new_uid: uint32 =
    result = lgid
    inc lgid
var et:uint = 0

proc isTrusted*(con: Connection): bool = con.trusted == TrustStatus.yes

template send*(con: Connection, data: string): untyped = 
    con.action_start_time = et
    var result = con.socket.send(data)
    result.addCallback(proc()=
        con.action_start_time = 0
    )
    result

template recv*(con: Connection, data: SomeInteger): untyped = 
    con.action_start_time = et
    var result = con.socket.recv(data)
    result.addCallback(proc()=
        con.action_start_time = 0
    )
    result

proc isClosed*(con: Connection): bool = con.socket.isClosed()


proc prepairClose(con: Connection) = 
    if con.isfakessl:
        if con.isTrusted:
            con.socket.isSsl = true
template close*(con: Connection) = 
    prepairClose(con)
    con.socket.close()
    let i = allConnections.find(con)
    if i != -1:
        allConnections.del(i)

# proc close*(cons: var Connections, con: Connection) =
#     con.socket.close()
#     if cons.connections.hasKey(con.id):
#         cons.connections.del(con.id)


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
    result.action_start_time = 0

    if socket == nil: result.socket = newAsyncSocket(buffered = buffered)
    else: result.socket = socket

    when not defined(android):
        result.socket.setSockOpt(OptNoDelay, true)
    allConnections.add result

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




proc startController*(){.async.}=
    while true:
        et = epochTime().uint
        await sleepAsync(1000)
        allConnections.keepIf(
            proc(x: Connection):bool =
                if x.action_start_time == 0: return true
                if et - x.action_start_time > globals.max_idle_time :
                    prepairClose(x)
                    x.socket.close()
                    return false
                return true
        )
