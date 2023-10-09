from globals import nil
import Connection
# import std/[strutils]

type
    Record* = ref object
        sent*: seq[string]
        received*: seq[string]
        handshaked:bool

let allrecords* = newSeq[Record](len = globals.tls_records)


proc recrdSends(rec: Record, sent: string) =
    let index = rec.sent.high
    rec.sent[index].add sent
    if rec.sent.len > rec.received.len: rec.received.setLen rec.received.high+1

proc recrdRecvs(rec: Record, received: string) =
    rec.sent.setLen rec.sent.high + 1
    let index = rec.received.high
    rec.received[index].add received

proc finishRecord(rec: Record)=rec.handshaked = true

proc find(sent:string)=
    for rec in allrecords:
        if rec.handshaked:
            if 



proc create(): Record =
    result.new()
    result.sent.setLen 1
    result.received.setLen 1

proc newRecord(): uint =
    var lid {.global.}: uint = 0
    result = lid
    allrecords[lid] = create()
    inc lid
