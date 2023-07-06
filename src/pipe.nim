from globals import nil
import math,bitops,random

const hsize = 8

proc encrypt(data:var string) =
    for i in 0..<data.len():
        data[i] = chr(rotateRightBits(uint8(data[i]), globals.sh3))

proc decrypt(data:var string) =
    for i in 0..<data.len():
        data[i] = chr(rotateLeftBits(uint8(data[i]), globals.sh3))

proc muxPack(cid: uint32,data: string): string =
    var datalen = len(data)
    result = newString(len= globals.chunk_size+8)
    var totake:uint32 = min(globals.chunk_size,data.len).uint32
    copyMem(unsafeAddr result[0], unsafeAddr cid, 4)
    copyMem(unsafeAddr result[4], unsafeAddr totake, 4)
    if totake != 0:
        copyMem(unsafeAddr result[8], unsafeAddr data[0], totake)
    else:
        discard
    
    var check:uint32 = 0
    copyMem(unsafeAddr check, unsafeAddr result[0], 4)
    let diff = (globals.chunk_size) - totake 
    if diff > 0 : 
        copyMem(unsafeAddr result[totake+hsize], unsafeAddr(globals.random_600[rand(250)]), diff)
    
proc prepairTrustedSend*(cid: uint32, data: var string) = 
   
    var muxres = muxPack(cid,data)
    encrypt muxres
    data = muxres
  

proc prepairUnTrustedSend(data: var string) = discard

proc muxRead*(data:var string):  tuple[cid:uint32,data:string] =
    decrypt data
    var datalen = len(data)
    var buffer = newString(len=globals.chunk_size)
    var cid:uint32
    var dlen:uint32
    copyMem(unsafeAddr cid, unsafeAddr data[0],4)
    copyMem(unsafeAddr dlen, unsafeAddr data[4], 4)
    if dlen != 0:
        if dlen > globals.chunk_size:
            return (0.uint32,"")
        copyMem(unsafeAddr buffer[0], unsafeAddr data[8], dlen)
        buffer.setLen(dlen)
    else:
        buffer.setLen(0)


    return (cid,buffer)


proc normalRead*(data:var string) = 
    decrypt data

proc normalSend*(data:var string) = 
    encrypt data


proc prepairUnTrustedRecv(data:string) = discard

 


