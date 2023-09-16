from globals import nil
import random


# proc encrypt(data:var string) =
#     for i in 0..< data.len() div 4:
#         (cast[ptr[uint32]](addr data[i]))[] = uint32(rotateRightBits((cast[ptr[uint32]](addr data[i]))[], globals.sh5))

# proc decrypt(data:var string) =
#     for i in 0..< data.len() div 4:
#         (cast[ptr[uint32]](addr data[i]))[] = uint32(rotateLeftBits((cast[ptr[uint32]](addr data[i]))[], globals.sh5))

# per byte = consume more cpu (testing)
proc encrypt(data: var string,start = 0) =
    for i in start..<data.len():
        # data[i] = chr(rotateRightBits(uint8(data[i]), globals.sh5))
        data[i] = chr(uint8(data[i]) xor cast[uint8](globals.sh5))

proc decrypt(data: var string) =
    for i in 0..<data.len():
        # data[i] = chr(rotateLeftBits(uint8(data[i]), globals.sh5))
        data[i] = chr(uint8(data[i]) xor cast[uint8](globals.sh5))


proc muxPack(cid: uint32, port: uint16, data: string): string =

    result = newString(len = globals.mux_chunk_size)
    # copyMem(addr result[0], addr(globals.random_str[rand(250)]), result.len)

    var totake: uint16 = min(globals.mux_payload_size.uint16, data.len.uint16)

    copyMem(addr result[0], addr globals.tls13_record_layer[0], 3) #tls header
    copyMem(addr result[3], addr totake, 2) #tls len
    copyMem(addr result[5], addr port, 2)
    copyMem(addr result[7], addr cid, 4)

    result[11] = rand(char.low .. char.high).char

    if totake != 0:
        copyMem(addr result[12], addr data[0], totake)
    else:
        discard

    let diff = globals.mux_payload_size - totake
    if diff > 0:
        copyMem(addr result[totake+12], addr(globals.random_str[rand(250)]), diff)




proc muxRead(data: var string): tuple[cid: uint32, port: uint16, data: string] =
    var buffer = newString(len = globals.mux_payload_size)
    var cid: uint32
    var dlen: uint16
    var port: uint16
    copyMem(addr dlen, addr data[3], 2)
    copyMem(addr port, addr data[5], 2)

    copyMem(addr cid, addr data[7], 4)

    if dlen != 0:
        if dlen > globals.mux_payload_size.uint16 or dlen > data.len.uint16:
            return (0.uint32,0, "")
        copyMem(addr buffer[0], addr data[12], dlen)
        buffer.setLen(dlen)
    else:
        buffer.setLen(0)


    return (cid,port, buffer)




proc unPackForRead*(data: var string) =
    decrypt data

proc packForSend*(data: var string) =
    let size:uint16 = data.len().uint16 - globals.full_tls_record_len.uint
    copyMem(addr data[0], addr globals.tls13_record_layer[0], globals.tls13_record_layer.len())
    copyMem(addr data[0 + globals.tls13_record_layer.len()], addr size, sizeof(uint16))

    encrypt(data,globals.full_tls_record_len.int)





#returns connection id
proc unPackForReadMux*(data: var string): tuple[cid: uint32, port: uint16] =
    decrypt data
    var (result_cid,port, result_data) = muxRead(data)
    data = result_data
    return (result_cid,port)

proc packForSendMux*(cid: uint32, port: uint16, data: var string) =
    var muxres = muxPack(cid, port, data)
    encrypt muxres
    data = muxres


