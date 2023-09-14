#
#          Chronos source location utilities
#              (c) Copyright 2018-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}
import stew/base10

type
  SrcLoc* = object
    procedure*: cstring
    file*: cstring
    line*: int

proc `$`*(loc: ptr SrcLoc): string =
  var res = $loc.file
  res.add("(")
  res.add(Base10.toString(uint64(loc.line)))
  res.add(")")
  res.add("    ")
  if len(loc.procedure) == 0:
    res.add("[unspecified]")
  else:
    res.add($loc.procedure)
  res

proc srcLocImpl(procedure: static string,
                file: static string, line: static int): ptr SrcLoc =
  var loc {.global.} = SrcLoc(
    file: cstring(file), line: line, procedure: procedure
  )
  return addr(loc)

template getSrcLocation*(procedure: static string = ""): ptr SrcLoc =
  srcLocImpl(procedure,
             instantiationInfo(-2).filename, instantiationInfo(-2).line)
