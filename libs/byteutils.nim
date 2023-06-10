# byteutils
# Copyright (c) 2018 Status Research & Development GmbH
# Licensed and distributed under either of
#   * MIT license (license terms in the root directory or at http://opensource.org/licenses/MIT).
#   * Apache v2 license (license terms in the root directory or at http://www.apache.org/licenses/LICENSE-2.0).
# at your option. This file may not be copied, modified, or distributed except according to those terms.


########################################################################################################
####################################   Array utilities   ###############################################

import algorithm

func initArrayWith*[N: static[int], T](value: T): array[N, T] {.noInit, inline.}=
  result.fill(value)

func `&`*[N1, N2: static[int], T](
    a: array[N1, T],
    b: array[N2, T]
    ): array[N1 + N2, T] {.inline, noInit.}=
  ## Array concatenation
  result[0 ..< N1] = a
  result[N1 ..< result.len] = b

########################################################################################################
#####################################   Hex utilities   ################################################

proc readHexChar*(c: char): byte {.noSideEffect, inline.}=
  ## Converts an hex char to a byte
  case c
  of '0'..'9': result = byte(ord(c) - ord('0'))
  of 'a'..'f': result = byte(ord(c) - ord('a') + 10)
  of 'A'..'F': result = byte(ord(c) - ord('A') + 10)
  else:
    raise newException(ValueError, $c & "is not a hexademical character")

template skip0xPrefix(hexStr: string): int =
  ## Returns the index of the first meaningful char in `hexStr` by skipping
  ## "0x" prefix
  if hexStr[0] == '0' and hexStr[1] in {'x', 'X'}: 2
  else: 0

func hexToByteArray*(hexStr: string, output: var openArray[byte], fromIdx, toIdx: int) =
  ## Read a hex string and store it in a byte array `output`. No "endianness" reordering is done.
  ## Allows specifying the byte range to process into the array
  var sIdx = skip0xPrefix(hexStr)

  doAssert(fromIdx >= 0 and toIdx >= fromIdx and fromIdx < output.len and toIdx < output.len)
  let sz = toIdx - fromIdx + 1

  doAssert hexStr.len - sIdx >= 2*sz

  sIdx += fromIdx * 2
  for bIdx in fromIdx ..< sz + fromIdx:
    output[bIdx] = hexStr[sIdx].readHexChar shl 4 or hexStr[sIdx + 1].readHexChar
    inc(sIdx, 2)

func hexToByteArray*(hexStr: string, output: var openArray[byte]) {.inline.} =
  ## Read a hex string and store it in a byte array `output`. No "endianness" reordering is done.
  hexToByteArray(hexStr, output, 0, output.high)

func hexToByteArray*[N: static[int]](hexStr: string): array[N, byte] {.noInit, inline.}=
  ## Read an hex string and store it in a byte array. No "endianness" reordering is done.
  hexToByteArray(hexStr, result)

func hexToPaddedByteArray*[N: static[int]](hexStr: string): array[N, byte] =
  ## Read a hex string and store it in a byte array `output`.
  ## The string may be shorter than the byte array.
  ## No "endianness" reordering is done.
  let
    p = skip0xPrefix(hexStr)
    sz = hexStr.len - p
    maxStrSize = result.len * 2
  var
    bIdx: int
    shift = 4

  doAssert hexStr.len - p <= maxStrSize
  
  if sz < maxStrSize:
    # include extra byte if odd length
    bIdx = result.len - (sz + 1) div 2   
    # start with shl of 4 if length is even
    shift = 4 - sz mod 2 * 4

  for sIdx in p ..< hexStr.len:
    let nibble = hexStr[sIdx].readHexChar shl shift
    result[bIdx] = result[bIdx] or nibble
    shift = shift + 4 and 4
    bIdx += shift shr 2

func hexToSeqByte*(hexStr: string): seq[byte] =
  ## Read an hex string and store it in a sequence of bytes. No "endianness" reordering is done.
  doAssert (hexStr.len and 1) == 0

  let skip = skip0xPrefix(hexStr)
  let N = (hexStr.len - skip) div 2

  result = newSeq[byte](N)
  for i in 0 ..< N:
    result[i] = hexStr[2*i + skip].readHexChar shl 4 or hexStr[2*i + 1 + skip].readHexChar

func toHexAux(ba: openarray[byte]): string =
  ## Convert a byte-array to its hex representation
  ## Output is in lowercase
  ## No "endianness" reordering is done.
  const hexChars = "0123456789abcdef"

  let sz = ba.len
  result = newString(2 * sz)
  for i in 0 ..< sz:
    result[2*i] = hexChars[int ba[i] shr 4 and 0xF]
    result[2*i+1] = hexChars[int ba[i] and 0xF]

func toHex*(ba: openarray[byte]): string {.inline.} =
  ## Convert a byte-array to its hex representation
  ## Output is in lowercase
  ## No "endianness" reordering is done.
  toHexAux(ba)

func toHex*[N: static[int]](ba: array[N, byte]): string {.inline.} =
  ## Convert a big endian byte-array to its hex representation
  ## Output is in lowercase
  ## No "endianness" reordering is done.
  toHexAux(ba)