from globals import nil
import random, strutils, bitops

type
    DataFlags* {.size: sizeof(uint8), pure.} = enum
        junk,
        udp


    TransferFlags* = set[DataFlags]

# proc `+`*(x: ptr[uint32],y:uint): ptr[uint32] =
#   return cast[ptr[uint32]](cast[uint](x) + y)

# proc `+`(a:pointer,p:pointer): pointer =
#   result = cast[pointer](cast[int](a) + 1 * sizeof(p))

# proc encrypt(data_pure: var string, start = 0) =
#     let len = (data.len() - start) div 4
#     var data = cast[seq[uint32]](data_pure)
#     for i in 0..<len:
#         data[i] = `xor`(data[i], globals.sh4)


# proc decrypt(data: var string) =
#     var address =cast[ptr[uint32]](addr data[0])
#     for i in 0 ..< (data.len() div 4):
#         (address+i.uint)[] = `xor`((address+i.uint)[], globals.sh4)

# proc encrypt(data: var string, start:int = 0, nbytes: int = data.len()) =
#     var i: int = start
#     let loopmax = min(data.len(), start + nbytes)
#     while i < loopmax:
#         data[i] = chr(uint8(data[i]) xor cast[uint8](globals.sh5))
#         i += 1

# proc decrypt(data: var string, nbytes: int = data.len()) =

#     var i: int = 0
#     let loopmax = min(data.len(), nbytes)
#     while i < loopmax:
#         data[i] = chr(uint8(data[i]) xor cast[uint8](globals.sh5))
#         i += 1

proc encrypt(data: var string, start: int = 0, nbytes: int = data.len()) =
    var i: int = start
    let loopmax = min(data.len(), start + nbytes)
    while i < loopmax:
        data[i] = chr(uint8(data[i]) xor cast[uint8](globals.sh5))
        i += 2

proc decrypt(data: var string, nbytes: int = data.len()) =

    var i: int = 0
    let loopmax = min(data.len(), nbytes)
    while i < loopmax:
        data[i] = chr(uint8(data[i]) xor cast[uint8](globals.sh5))
        i += 2



proc unPackForRead*(data: var string, bytes: int) =
    decrypt data, bytes


proc flagForSend*(data: var string, flags: TransferFlags) =
    let width = globals.full_tls_record_len.int+sizeof(uint16)+sizeof(uint16) + sizeof(uint8)
    if data.len < width: data.setLen(width)

    var size: uint16 = (data.len - globals.full_tls_record_len.int).uint16

    var dif: uint8 = 16 - (size mod 16).uint8

    if dif == 16: dif = 0
    data.setLen data.len + dif.int
    size += dif

    copyMem(addr data[0], addr globals.tls13_record_layer[0], globals.tls13_record_layer.len())
    copyMem(addr data[0 + globals.tls13_record_layer.len()],addr size,  sizeof(size))


    var e_flags: uint8 = bitand(cast[uint8](flags), 0xF)
    e_flags = bitor((dif shl 4), e_flags)
    e_flags = e_flags xor size.uint8

    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(uint16)+sizeof(uint16)], addr e_flags, sizeof(e_flags))

proc packForSend*(data: var string, cid: uint16, port: uint16, flags: TransferFlags = {}) =
    let width = globals.full_tls_record_len.int+sizeof(port)+sizeof(cid) + sizeof(uint8)
    if data.len < width: data.setLen(width)

    var size: uint16 = data.len().uint16 - globals.full_tls_record_len.uint16


    var dif: uint8 = 16 - (size mod 16).uint8
    if dif == 16: dif = 0
    data.setLen data.len + dif.int
    size += dif


    copyMem(addr data[0], addr globals.tls13_record_layer[0], globals.tls13_record_layer.len())
    copyMem(addr data[0 + globals.tls13_record_layer.len()], addr size, sizeof(size))

    let e_cid: uint16 = cid xor size
    let e_port: uint16 = port xor size


    var e_flags: uint8 = bitand(cast[uint8](flags), 0xF)
    e_flags = bitor((dif shl 4), e_flags)
    e_flags = e_flags xor size.uint8

    copyMem(addr data[0 + globals.full_tls_record_len.int], addr e_cid, sizeof(e_cid))
    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(e_cid)], addr e_port, sizeof(e_port))
    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(e_cid)+sizeof(e_port)], addr e_flags, sizeof(e_flags))

    encrypt(data, width, globals.fast_encrypt_width.int)



proc closeSignalData*(cid: uint16): string =
    let port: uint16 = rand(uint16.high.int).uint16
    let flags: TransferFlags = {}

    let width = globals.full_tls_record_len.int+sizeof(port)+sizeof(cid) + sizeof(uint8)
    var data = newStringOfCap(16); data.setLen(width)


    var size: uint16 = data.len().uint16 - globals.full_tls_record_len.uint16

    var dif: uint8 = 16 - (size mod 16).uint8
    if dif == 16: dif = 0
    data.setLen data.len + dif.int
    size += dif


    # let size: uint16 = sizeof(port)+sizeof(cid) + sizeof(uint8)
    let e_cid: uint16 = cid xor size
    var e_flags: uint8 = bitand(cast[uint8](flags), 0xF)
    e_flags = bitor((dif shl 4), e_flags)
    e_flags = e_flags xor size.uint8

    copyMem(addr data[0], addr globals.tls13_record_layer[0], globals.tls13_record_layer.len())
    copyMem(addr data[0 + globals.tls13_record_layer.len()], addr size, sizeof(size))


    copyMem(addr data[0 + globals.full_tls_record_len.int], addr e_cid, sizeof(e_cid))
    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(e_cid)], addr port, sizeof(port))
    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(e_cid)+sizeof(port)], addr e_flags, sizeof(uint8))
    return data



