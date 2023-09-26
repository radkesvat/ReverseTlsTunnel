from globals import nil
import random, strutils

type
    DataFlags* {.size: sizeof(uint8), pure.} = enum
        junk


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

proc encrypt(data: var string, start = 0) =
    var i: int = start
    while i < data.len():
        data[i] = chr(uint8(data[i]) xor cast[uint8](globals.sh5))

proc decrypt(data: var string) =
    var i: int = 0
    while i < data.len():
        data[i] = chr(uint8(data[i]) xor cast[uint8](globals.sh5))
    

# proc muxPack(cid: uint32, port: uint16, data: string): string =
#     result = newString(len = globals.mux_chunk_size)
#     # copyMem(addr result[0], addr(globals.random_str[rand(250)]), result.len)

#     var totake: uint16 = min(globals.mux_payload_size.uint16, data.len.uint16)

#     copyMem(addr result[0], addr globals.tls13_record_layer[0], 3) #tls header
#     copyMem(addr result[3], addr totake, 2) #tls len
#     copyMem(addr result[5], addr port, 2)
#     copyMem(addr result[7], addr cid, 4)

#     result[11] = rand(char.low .. char.high).char

#     if totake != 0:
#         copyMem(addr result[12], addr data[0], totake)
#     else:
#         discard

#     let diff = globals.mux_payload_size - totake
#     if diff > 0:
#         copyMem(addr result[totake+12], addr(globals.random_str[rand(250)]), diff)

# proc muxRead(data: var string): tuple[cid: uint32, port: uint16, data: string] =
#     var buffer = newString(len = globals.mux_payload_size)
#     var cid: uint32
#     var dlen: uint16
#     var port: uint16
#     copyMem(addr dlen, addr data[3], 2)
#     copyMem(addr port, addr data[5], 2)

#     copyMem(addr cid, addr data[7], 4)

#     if dlen != 0:
#         if dlen > globals.mux_payload_size.uint16 or dlen > data.len.uint16:
#             return (0.uint32,0, "")
#         copyMem(addr buffer[0], addr data[12], dlen)
#         buffer.setLen(dlen)
#     else:
#         buffer.setLen(0)


#     return (cid,port, buffer)




proc unPackForRead*(data: var string) =
    decrypt data


proc flagForSend*(data: var string, flags: TransferFlags) =
    let width = globals.full_tls_record_len.int+sizeof(uint16)+sizeof(uint16) + sizeof(flags)
    if data.len < width: data.setLen(width)

    let size: uint16 = 0
    copyMem(addr size, addr data[0 + globals.tls13_record_layer.len()], sizeof(size))

    let e_flags: uint8 = cast[uint8](flags) xor size.uint8
    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(uint16)+sizeof(uint16)], addr e_flags, sizeof(e_flags))

proc packForSend*(data: var string, cid: uint16, port: uint16, flags: TransferFlags = {}) =
    let width = globals.full_tls_record_len.int+sizeof(port)+sizeof(cid) + sizeof(flags)
    if data.len < width: data.setLen(width)

    let size: uint16 = data.len().uint16 - globals.full_tls_record_len.uint16
    copyMem(addr data[0], addr globals.tls13_record_layer[0], globals.tls13_record_layer.len())
    copyMem(addr data[0 + globals.tls13_record_layer.len()], addr size, sizeof(size))

    let e_cid: uint16 = cid xor size
    let e_port: uint16 = port xor size
    let e_flags: uint8 = cast[uint8](flags) xor size.uint8


    copyMem(addr data[0 + globals.full_tls_record_len.int], addr e_cid, sizeof(e_cid))
    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(e_cid)], addr e_port, sizeof(e_port))
    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(e_cid)+sizeof(e_port)], addr e_flags, sizeof(e_flags))

    encrypt(data, width)



proc closeSignalData*(cid: uint16): string =
    let port: uint16 = rand(uint16.high.int).uint16
    let flags: uint8 = rand(uint8.high.int).uint8

    let width = globals.full_tls_record_len.int+sizeof(port)+sizeof(cid) + sizeof(flags)

    var data = newString(len = width)

    let size: uint16 = sizeof(port)+sizeof(cid) + sizeof(flags)
    let e_cid: uint16 = cid xor size

    copyMem(addr data[0], addr globals.tls13_record_layer[0], globals.tls13_record_layer.len())
    copyMem(addr data[0 + globals.tls13_record_layer.len()], addr size, sizeof(size))


    copyMem(addr data[0 + globals.full_tls_record_len.int], addr e_cid, sizeof(e_cid))
    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(e_cid)], addr port, sizeof(port))
    copyMem(addr data[0 + globals.full_tls_record_len.int+sizeof(e_cid)+sizeof(port)], addr flags, sizeof(flags))
    return data
#returns connection id
# proc unPackForReadMux*(data: var string): tuple[cid: uint32, port: uint16] =
#     decrypt data
#     var (result_cid, port, result_data) = muxRead(data)
#     data = result_data
#     return (result_cid, port)

# proc packForSendMux*(cid: uint32, port: uint16, data: var string) =
#     var muxres = muxPack(cid, port, data)
#     encrypt muxres
#     data = muxres


