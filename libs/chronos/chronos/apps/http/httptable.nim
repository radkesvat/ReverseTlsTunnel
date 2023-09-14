#
#        Chronos HTTP/S case-insensitive non-unique
#              key-value memory storage
#             (c) Copyright 2021-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
import std/[tables, strutils]
import stew/base10

when (NimMajor, NimMinor) < (1, 4):
  {.push raises: [Defect].}
else:
  {.push raises: [].}

type
  HttpTable* = object
    table: Table[string, seq[string]]

  HttpTableRef* = ref HttpTable

  HttpTables* = HttpTable | HttpTableRef

proc add*(ht: var HttpTables, key: string, value: string) =
  ## Add string ``value`` to header with key ``key``.
  var default: seq[string]
  ht.table.mgetOrPut(key.toLowerAscii(), default).add(value)

proc add*(ht: var HttpTables, key: string, value: SomeInteger) =
  ## Add integer ``value`` to header with key ``key``.
  ht.add(key, $value)

proc set*(ht: var HttpTables, key: string, value: string) =
  ## Set/replace value of header with key ``key`` to value ``value``.
  let lowkey = key.toLowerAscii()
  ht.table[lowkey] = @[value]

proc hasKeyOrPut*(ht: var HttpTables, key: string, value: string): bool =
  ## Returns true if ``key`` is in the table ``ht``,
  ## otherwise inserts ``value``.
  ht.table.hasKeyOrPut(key, @[value])

proc contains*(ht: HttpTables, key: string): bool =
  ## Returns ``true`` if header with name ``key`` is present in HttpTable/Ref.
  ht.table.contains(key.toLowerAscii())

proc getList*(ht: HttpTables, key: string,
              default: openArray[string] = []): seq[string] =
  ## Returns sequence of headers with key ``key``.
  var defseq = @default
  ht.table.getOrDefault(key.toLowerAscii(), defseq)

proc getString*(ht: HttpTables, key: string,
                default: string = ""): string =
  ## Returns concatenated value of headers with key ``key``.
  ##
  ## If there multiple headers with the same name ``key`` the result value will
  ## be concatenation using `,`.
  var defseq: seq[string]
  let res = ht.table.getOrDefault(key.toLowerAscii(), defseq)
  if len(res) == 0:
    return default
  else:
    res.join(",")

proc count*(ht: HttpTables, key: string): int =
  ## Returns number of headers with key ``key``.
  var default: seq[string]
  len(ht.table.getOrDefault(key.toLowerAscii(), default))

proc getInt*(ht: HttpTables, key: string): uint64 =
  ## Parse header with key ``key`` as unsigned integer.
  ##
  ## Integers are parsed in safe way, there no exceptions or errors will be
  ## raised.
  ##
  ## Procedure returns `0` value in next cases:
  ## 1. The value is empty.
  ## 2. Non-decimal character encountered during the parsing of the value.
  ## 3. Result exceeds `uint64` maximum allowed value.
  let res = Base10.decode(uint64, ht.getString(key))
  if res.isOk():
    res.get()
  else:
    0'u64

proc getLastString*(ht: HttpTables, key: string): string =
  ## Returns "last" value of header ``key``.
  ##
  ## If there multiple headers with the same name ``key`` the value of last
  ## encountered header will be returned.
  var default: seq[string]
  let item = ht.table.getOrDefault(key.toLowerAscii(), default)
  if len(item) == 0:
    ""
  else:
    item[^1]

proc getLastInt*(ht: HttpTables, key: string): uint64 =
  ## Returns "last" value of header ``key`` as unsigned integer.
  ##
  ## If there multiple headers with the same name ``key`` the value of last
  ## encountered header will be returned.
  ##
  ## Unsigned integer will be parsed using rules of getInt() procedure.
  let res = Base10.decode(uint64, ht.getLastString(key))
  if res.isOk():
    res.get()
  else:
    0'u64

proc init*(htt: typedesc[HttpTable]): HttpTable =
  ## Create empty HttpTable.
  HttpTable(table: initTable[string, seq[string]]())

proc new*(htt: typedesc[HttpTableRef]): HttpTableRef =
  ## Create empty HttpTableRef.
  HttpTableRef(table: initTable[string, seq[string]]())

proc init*(htt: typedesc[HttpTable],
           data: openArray[tuple[key: string, value: string]]): HttpTable =
  ## Create HttpTable using array of tuples with header names and values.
  var res = HttpTable.init()
  for item in data:
    res.add(item.key, item.value)
  res

proc new*(htt: typedesc[HttpTableRef],
          data: openArray[tuple[key: string, value: string]]): HttpTableRef =
  ## Create HttpTableRef using array of tuples with header names and values.
  var res = HttpTableRef.new()
  for item in data:
    res.add(item.key, item.value)
  res

proc isEmpty*(ht: HttpTables): bool =
  ## Returns ``true`` if HttpTable ``ht`` is empty (do not have any values).
  len(ht.table) == 0

proc normalizeHeaderName*(value: string): string =
  ## Set any header name to have first capital letters in their name
  ##
  ## For example:
  ## "content-length" become "<C>ontent-<L>ength"
  ## "expect" become "<E>xpect"
  var res = value.toLowerAscii()
  var k = 0
  while k < len(res):
    if k == 0:
      res[k] = toUpperAscii(res[k])
      inc(k, 1)
    else:
      if res[k] == '-':
        if k + 1 < len(res):
          res[k + 1] = toUpperAscii(res[k + 1])
          inc(k, 2)
        else:
          break
      else:
        inc(k, 1)
  res

iterator stringItems*(ht: HttpTables,
                      normKey = false): tuple[key: string, value: string] =
  ## Iterate over HttpTable/Ref values.
  ##
  ## If ``normKey`` is true, key name value will be normalized using
  ## normalizeHeaderName() procedure.
  for k, v in ht.table.pairs():
    let key = if normKey: normalizeHeaderName(k) else: k
    for item in v:
      yield (key, item)

iterator items*(ht: HttpTables,
                normKey = false): tuple[key: string, value: seq[string]] =
  ## Iterate over HttpTable/Ref values.
  ##
  ## If ``normKey`` is true, key name value will be normalized using
  ## normalizeHeaderName() procedure.
  for k, v in ht.table.pairs():
    let key = if normKey: normalizeHeaderName(k) else: k
    yield (key, v)

proc `$`*(ht: HttpTables): string =
  ## Returns string representation of HttpTable/Ref.
  var res = ""
  for key, value in ht.table.pairs():
    for item in value:
      res.add(key.normalizeHeaderName())
      res.add(": ")
      res.add(item)
      res.add("\p")
  res

proc toList*(ht: HttpTables, normKey = false): auto =
  ## Returns sequence of (key, value) pairs.
  var res: seq[tuple[key: string, value: string]]
  for key, value in ht.stringItems(normKey):
    res.add((key, value))
  res
