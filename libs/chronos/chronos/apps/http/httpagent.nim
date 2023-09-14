#
#        Chronos HTTP/S client implementation
#             (c) Copyright 2021-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import strutils

const
  ChronosName* = "nim-chronos"
    ## Project name string
  ChronosMajor* {.intdefine.}: int = 3
    ## Major number of Chronos' version.
  ChronosMinor* {.intdefine.}: int = 0
    ## Minor number of Chronos' version.
  ChronosPatch* {.intdefine.}: int = 2
    ## Patch number of Chronos' version.
  ChronosVersion* = $ChronosMajor & "." & $ChronosMinor & "." & $ChronosPatch
    ## Version of Chronos as a string.
  ChronosIdent* = "$1/$2 ($3/$4)" % [ChronosName, ChronosVersion, hostCPU,
                                     hostOS]
    ## Project ident name for networking services
