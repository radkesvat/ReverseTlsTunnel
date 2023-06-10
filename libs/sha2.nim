# SHA-2 implementation written in nim
#
# Copyright (c) 2015 Andri Lim
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.
#
#
#-------------------------------------

import endians, strutils

const
  SHA256_K = [
    0x428A2F98'u32, 0x71374491'u32, 0xB5C0FBCF'u32, 0xE9B5DBA5'u32,
    0x3956C25B'u32, 0x59F111F1'u32, 0x923F82A4'u32, 0xAB1C5ED5'u32,
    0xD807AA98'u32, 0x12835B01'u32, 0x243185BE'u32, 0x550C7DC3'u32,
    0x72BE5D74'u32, 0x80DEB1FE'u32, 0x9BDC06A7'u32, 0xC19BF174'u32,
    0xE49B69C1'u32, 0xEFBE4786'u32, 0x0FC19DC6'u32, 0x240CA1CC'u32,
    0x2DE92C6F'u32, 0x4A7484AA'u32, 0x5CB0A9DC'u32, 0x76F988DA'u32,
    0x983E5152'u32, 0xA831C66D'u32, 0xB00327C8'u32, 0xBF597FC7'u32,
    0xC6E00BF3'u32, 0xD5A79147'u32, 0x06CA6351'u32, 0x14292967'u32,
    0x27B70A85'u32, 0x2E1B2138'u32, 0x4D2C6DFC'u32, 0x53380D13'u32,
    0x650A7354'u32, 0x766A0ABB'u32, 0x81C2C92E'u32, 0x92722C85'u32,
    0xA2BFE8A1'u32, 0xA81A664B'u32, 0xC24B8B70'u32, 0xC76C51A3'u32,
    0xD192E819'u32, 0xD6990624'u32, 0xF40E3585'u32, 0x106AA070'u32,
    0x19A4C116'u32, 0x1E376C08'u32, 0x2748774C'u32, 0x34B0BCB5'u32,
    0x391C0CB3'u32, 0x4ED8AA4A'u32, 0x5B9CCA4F'u32, 0x682E6FF3'u32,
    0x748F82EE'u32, 0x78A5636F'u32, 0x84C87814'u32, 0x8CC70208'u32,
    0x90BEFFFA'u32, 0xA4506CEB'u32, 0xBEF9A3F7'u32, 0xC67178F2'u32]

  SHA512_K = [
    0x428A2F98D728AE22'u64, 0x7137449123EF65CD'u64,
    0xB5C0FBCFEC4D3B2F'u64, 0xE9B5DBA58189DBBC'u64,
    0x3956C25BF348B538'u64, 0x59F111F1B605D019'u64,
    0x923F82A4AF194F9B'u64, 0xAB1C5ED5DA6D8118'u64,
    0xD807AA98A3030242'u64, 0x12835B0145706FBE'u64,
    0x243185BE4EE4B28C'u64, 0x550C7DC3D5FFB4E2'u64,
    0x72BE5D74F27B896F'u64, 0x80DEB1FE3B1696B1'u64,
    0x9BDC06A725C71235'u64, 0xC19BF174CF692694'u64,
    0xE49B69C19EF14AD2'u64, 0xEFBE4786384F25E3'u64,
    0x0FC19DC68B8CD5B5'u64, 0x240CA1CC77AC9C65'u64,
    0x2DE92C6F592B0275'u64, 0x4A7484AA6EA6E483'u64,
    0x5CB0A9DCBD41FBD4'u64, 0x76F988DA831153B5'u64,
    0x983E5152EE66DFAB'u64, 0xA831C66D2DB43210'u64,
    0xB00327C898FB213F'u64, 0xBF597FC7BEEF0EE4'u64,
    0xC6E00BF33DA88FC2'u64, 0xD5A79147930AA725'u64,
    0x06CA6351E003826F'u64, 0x142929670A0E6E70'u64,
    0x27B70A8546D22FFC'u64, 0x2E1B21385C26C926'u64,
    0x4D2C6DFC5AC42AED'u64, 0x53380D139D95B3DF'u64,
    0x650A73548BAF63DE'u64, 0x766A0ABB3C77B2A8'u64,
    0x81C2C92E47EDAEE6'u64, 0x92722C851482353B'u64,
    0xA2BFE8A14CF10364'u64, 0xA81A664BBC423001'u64,
    0xC24B8B70D0F89791'u64, 0xC76C51A30654BE30'u64,
    0xD192E819D6EF5218'u64, 0xD69906245565A910'u64,
    0xF40E35855771202A'u64, 0x106AA07032BBD1B8'u64,
    0x19A4C116B8D2D0C8'u64, 0x1E376C085141AB53'u64,
    0x2748774CDF8EEB99'u64, 0x34B0BCB5E19B48A8'u64,
    0x391C0CB3C5C95A63'u64, 0x4ED8AA4AE3418ACB'u64,
    0x5B9CCA4F7763E373'u64, 0x682E6FF3D6B2B8A3'u64,
    0x748F82EE5DEFB2FC'u64, 0x78A5636F43172F60'u64,
    0x84C87814A1F0AB72'u64, 0x8CC702081A6439EC'u64,
    0x90BEFFFA23631E28'u64, 0xA4506CEBDE82BDE9'u64,
    0xBEF9A3F7B2C67915'u64, 0xC67178F2E372532B'u64,
    0xCA273ECEEA26619C'u64, 0xD186B8C721C0C207'u64,
    0xEADA7DD6CDE0EB1E'u64, 0xF57D4F7FEE6ED178'u64,
    0x06F067AA72176FBA'u64, 0x0A637DC5A2C898A6'u64,
    0x113F9804BEF90DAE'u64, 0x1B710B35131C471B'u64,
    0x28DB77F523047D84'u64, 0x32CAAB7B40C72493'u64,
    0x3C9EBE0A15C9BEBC'u64, 0x431D67C49C100D4C'u64,
    0x4CC5D4BECB3E42B6'u64, 0x597F299CFC657E2A'u64,
    0x5FCB6FAB3AD6FAEC'u64, 0x6C44198C4A475817'u64]

type
  SHA2Ctx = object of RootObj
    count: array[0..1, uint32]

  SHA224* = object of SHA2Ctx
    state: array[0..7, uint32]
    buffer: array[0..63, uint8]

  SHA256* = object of SHA224

  SHA384* = object of SHA2Ctx
    state: array[0..7, uint64]
    buffer: array[0..127, uint8]

  SHA512* = object of SHA384

  SHA224Digest* = array[0..27, uint8]
  SHA256Digest* = array[0..31, uint8]
  SHA384Digest* = array[0..47, uint8]
  SHA512Digest* = array[0..63, uint8]

proc initSHA*(ctx: var SHA224) =
  ctx.count[0] = 0
  ctx.count[1] = 0
  ctx.state[0] = 0xC1059ED8'u32
  ctx.state[1] = 0x367CD507'u32
  ctx.state[2] = 0x3070DD17'u32
  ctx.state[3] = 0xF70E5939'u32
  ctx.state[4] = 0xFFC00B31'u32
  ctx.state[5] = 0x68581511'u32
  ctx.state[6] = 0x64F98FA7'u32
  ctx.state[7] = 0xBEFA4FA4'u32

proc initSHA*(ctx: var SHA256) =
  ctx.count[0] = 0
  ctx.count[1] = 0
  ctx.state[0] = 0x6A09E667'u32
  ctx.state[1] = 0xBB67AE85'u32
  ctx.state[2] = 0x3C6EF372'u32
  ctx.state[3] = 0xA54FF53A'u32
  ctx.state[4] = 0x510E527F'u32
  ctx.state[5] = 0x9B05688C'u32
  ctx.state[6] = 0x1F83D9AB'u32
  ctx.state[7] = 0x5BE0CD19'u32

proc initSHA*(ctx: var SHA384) =
  ctx.count[0] = 0
  ctx.count[1] = 0
  ctx.state[0] = 0xCBBB9D5DC1059ED8'u64
  ctx.state[1] = 0x629A292A367CD507'u64
  ctx.state[2] = 0x9159015A3070DD17'u64
  ctx.state[3] = 0x152FECD8F70E5939'u64
  ctx.state[4] = 0x67332667FFC00B31'u64
  ctx.state[5] = 0x8EB44A8768581511'u64
  ctx.state[6] = 0xDB0C2E0D64F98FA7'u64
  ctx.state[7] = 0x47B5481DBEFA4FA4'u64

proc initSHA*(ctx: var SHA512) =
  ctx.count[0] = 0
  ctx.count[1] = 0
  ctx.state[0] = 0x6A09E667F3BCC908'u64
  ctx.state[1] = 0xBB67AE8584CAA73B'u64
  ctx.state[2] = 0x3C6EF372FE94F82B'u64
  ctx.state[3] = 0xA54FF53A5F1D36F1'u64
  ctx.state[4] = 0x510E527FADE682D1'u64
  ctx.state[5] = 0x9B05688C2B3E6C1F'u64
  ctx.state[6] = 0x1F83D9ABFB41BD6B'u64
  ctx.state[7] = 0x5BE0CD19137E2179'u64

proc initSHA*[T](): T =
  result.initSHA()

proc GET_UINT32_BE(b: cstring, i: int): uint32 =
  var val = b
  bigEndian32(addr(result), addr(val[i]))

proc PUT_UINT32_BE(n: uint32, b: var cstring, i: int) =
  var val = n
  bigEndian32(addr(b[i]), addr(val))

proc GET_UINT64_BE(b: cstring, i: int): uint64 =
  var val = b
  bigEndian64(addr(result), addr(val[i]))

proc PUT_UINT64_BE(n: uint64, b: var cstring, i: int) =
  var val = n
  bigEndian64(addr(b[i]), addr(val))

template a(i:int):untyped = T[(0 - i) and 7]
template b(i:int):untyped = T[(1 - i) and 7]
template c(i:int):untyped = T[(2 - i) and 7]
template d(i:int):untyped = T[(3 - i) and 7]
template e(i:int):untyped = T[(4 - i) and 7]
template f(i:int):untyped = T[(5 - i) and 7]
template g(i:int):untyped = T[(6 - i) and 7]
template h(i:int):untyped = T[(7 - i) and 7]

proc Ch[T: uint32|uint64](x, y, z: T): T {.inline.} = (z xor (x and (y xor z)))
proc Maj[T: uint32|uint64](x, y, z: T): T {.inline.} = ((x and y) or (z and (x or y)))
proc rotr[T: uint32|uint64](num: T, amount: int): T {.inline.} =
  result = (num shr T(amount)) or (num shl T(8 * sizeof(num) - amount))

template R(i: int): untyped =
  h(i) += S1(e(i)) + Ch(e(i), f(i), g(i)) + K[i + j]

  if j != 0:
   W[i and 15] += S3(W[(i - 2) and 15]) + W[(i - 7) and 15] + S2(W[(i - 15) and 15])
   h(i) += W[i and 15]
  else:
   W[i] = data[i]
   h(i) += W[i]

  d(i) += h(i)
  h(i) += S0(a(i)) + Maj(a(i), b(i), c(i))

proc transform256(state: var array[0..7, uint32], input: cstring) =
  let K = SHA256_K
  var W, data: array[0..15, uint32]
  for i in countup(0, 15): data[i] = GET_UINT32_BE(input, i * 4)

  var T: array[0..7, uint32]
  for i in 0..7: T[i] = state[i]

  proc S0(x:uint32): uint32 {.inline.} = (rotr(x, 2) xor rotr(x, 13) xor rotr(x, 22))
  proc S1(x:uint32): uint32 {.inline.} = (rotr(x, 6) xor rotr(x, 11) xor rotr(x, 25))
  proc S2(x:uint32): uint32 {.inline.} = (rotr(x, 7) xor rotr(x, 18) xor (x shr 3))
  proc S3(x:uint32): uint32 {.inline.} = (rotr(x, 17) xor rotr(x, 19) xor (x shr 10))

  for j in countup(0, 63, 16):
    R( 0); R( 1); R( 2); R( 3)
    R( 4); R( 5); R( 6); R( 7)
    R( 8); R( 9); R(10); R(11)
    R(12); R(13); R(14); R(15)

  state[0] += a(0)
  state[1] += b(0)
  state[2] += c(0)
  state[3] += d(0)
  state[4] += e(0)
  state[5] += f(0)
  state[6] += g(0)
  state[7] += h(0)

func update*[T:char|byte](ctx: var (SHA224|SHA256), data: openarray[T]) =
  var len = data.len
  var pos = 0
  while len > 0:
    let copy_start = int(ctx.count[0] and 0x3F)
    let copy_size = min(64 - copy_start, len)
    copyMem(addr(ctx.buffer[copy_start]), unsafeAddr(data[pos]), copy_size)

    inc(pos, copy_size)
    dec(len, copy_size)

    ctx.count[0] += uint32(copy_size)
    # carry overflow from low to high
    if ctx.count[0] < uint32(copy_size): ctx.count[1] += 1'u32

    if (ctx.count[0] and 0x3F) == 0:
      transform256(ctx.state, cast[cstring](addr(ctx.buffer[0])))

proc transform512(state: var array[0..7, uint64], input: cstring) =
  let K = SHA512_K
  var W, data: array[0..15, uint64]
  for i in countup(0, 15):  data[i] = GET_UINT64_BE(input, i * 8)

  var T: array[0..7, uint64]
  for i in 0..7: T[i] = state[i]

  proc S0(x:uint64):uint64 {.inline.} = (rotr(x, 28) xor rotr(x, 34) xor rotr(x, 39))
  proc S1(x:uint64):uint64 {.inline.} = (rotr(x, 14) xor rotr(x, 18) xor rotr(x, 41))
  proc S2(x:uint64):uint64 {.inline.} = (rotr(x, 1) xor rotr(x, 8) xor (x shr 7))
  proc S3(x:uint64):uint64 {.inline.} = (rotr(x, 19) xor rotr(x, 61) xor (x shr 6))

  # 80 operations, partially loop unrolled
  for j in countup(0, 79, 16):
    R( 0); R( 1); R( 2); R( 3)
    R( 4); R( 5); R( 6); R( 7)
    R( 8); R( 9); R(10); R(11)
    R(12); R(13); R(14); R(15)

  # Add the working vars back into state[].
  state[0] += a(0)
  state[1] += b(0)
  state[2] += c(0)
  state[3] += d(0)
  state[4] += e(0)
  state[5] += f(0)
  state[6] += g(0)
  state[7] += h(0)

func update*[T:char|byte](ctx: var (SHA384|SHA512), data: openarray[T]) =
  var len = data.len
  var pos = 0
  while len > 0:
    let copy_start = int(ctx.count[0] and 0x7F)
    let copy_size = min(128 - copy_start, len)
    copyMem(addr(ctx.buffer[copy_start]), unsafeAddr(data[pos]), copy_size)

    inc(pos, copy_size)
    dec(len, copy_size)

    ctx.count[0] += uint32(copy_size)
    # carry overflow from low to high
    if ctx.count[0] < uint32(copy_size): ctx.count[1] += 1'u32

    if (ctx.count[0] and 0x7F) == 0:
      transform512(ctx.state, cast[cstring](addr(ctx.buffer[0])))

proc final224_256(ctx: var SHA224) =
  var buffer = cast[cstring](addr(ctx.buffer[0]))
  # Add padding as described in RFC 3174 (it describes SHA-1 but
  # the same padding style is used for SHA-256 too).
  var j = int(ctx.count[0] and 0x3F)
  ctx.buffer[j] = 0x80
  inc j

  while j != 56:
    if j == 64:
      transform256(ctx.state, buffer)
      j = 0
    ctx.buffer[j] = 0x00
    inc j

  # Convert the message size from bytes to bits.
  ctx.count[1] = (ctx.count[1] shl 3) + (ctx.count[0] shr 29)
  ctx.count[0] = ctx.count[0] shl 3

  PUT_UINT32_BE(ctx.count[1], buffer, 14 * 4)
  PUT_UINT32_BE(ctx.count[0], buffer, 15 * 4)
  transform256(ctx.state, buffer)

proc final*(ctx: var SHA224): SHA224Digest =
  ctx.final224_256()
  var output = cast[cstring](addr(result[0]))
  for i in 0..6:
    PUT_UINT32_BE(ctx.state[i], output, i * 4)

proc final*(ctx: var SHA256): SHA256Digest =
  SHA224(ctx).final224_256()
  var output = cast[cstring](addr(result[0]))
  for i in 0..7:
    PUT_UINT32_BE(ctx.state[i], output, i * 4)

proc final384_512(ctx: var SHA384) =
  var buffer = cast[cstring](addr(ctx.buffer[0]))

  # Add padding as described in RFC 3174 (it describes SHA-1 but
  # the same padding style is used for SHA-512 too).
  var j = int(ctx.count[0] and 0x7F)
  ctx.buffer[j] = 0x80
  inc j

  while j != 112:
    if j == 128:
      transform512(ctx.state, buffer)
      j = 0
    ctx.buffer[j] = 0x00
    inc j

  # Convert the message size from bytes to bits.
  ctx.count[1] = (ctx.count[1] shl 3) + (ctx.count[0] shr 29)
  ctx.count[0] = ctx.count[0] shl 3

  PUT_UINT64_BE(ctx.count[1], buffer, 14 * 8)
  PUT_UINT64_BE(ctx.count[0], buffer, 15 * 8)
  transform512(ctx.state, buffer)

proc final*(ctx: var SHA384): SHA384Digest =
  ctx.final384_512()
  var output = cast[cstring](addr(result[0]))
  for i in 0..5:
    PUT_UINT64_BE(ctx.state[i], output, i * 8)

proc final*(ctx: var SHA512): SHA512Digest =
  ctx.final384_512()
  var output = cast[cstring](addr(result[0]))
  for i in 0..7:
    PUT_UINT64_BE(ctx.state[i], output, i * 8)

proc computeSHA[T, R](input: string, rep: int): R =
  var ctx: T
  ctx.initSHA()
  for i in 0..rep-1: ctx.update(input)
  result = ctx.final()

proc computeSHA224*(input: string, rep: int = 1): SHA224Digest = computeSHA[SHA224, SHA224Digest](input, rep)
proc computeSHA256*(input: string, rep: int = 1): SHA256Digest = computeSHA[SHA256, SHA256Digest](input, rep)
proc computeSHA384*(input: string, rep: int = 1): SHA384Digest = computeSHA[SHA384, SHA384Digest](input, rep)
proc computeSHA512*(input: string, rep: int = 1): SHA512Digest = computeSHA[SHA512, SHA512Digest](input, rep)

proc toString[T](input: T): string =
  result = newString(input.len)
  for i in 0..input.len-1: result[i] = input[i].char

proc `$`*(sha: SHA224Digest): string = toString(sha)
proc `$`*(sha: SHA256Digest): string = toString(sha)
proc `$`*(sha: SHA384Digest): string = toString(sha)
proc `$`*(sha: SHA512Digest): string = toString(sha)  

proc toHexImpl[T](input: T): string =
  result = ""
  for c in input:
    result.add toHex(ord(c), 2)
    
proc hex*(sha: SHA224Digest): string = toHexImpl(sha)
proc hex*(sha: SHA256Digest): string = toHexImpl(sha)
proc hex*(sha: SHA384Digest): string = toHexImpl(sha)
proc hex*(sha: SHA512Digest): string = toHexImpl(sha)

proc toHex*(sha: SHA224Digest): string = toHexImpl(sha)
proc toHex*(sha: SHA256Digest): string = toHexImpl(sha)
proc toHex*(sha: SHA384Digest): string = toHexImpl(sha)
proc toHex*(sha: SHA512Digest): string = toHexImpl(sha)  