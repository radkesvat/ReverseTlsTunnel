import json, macros, strutils, tables, sets, math, unicode, typetraits

when defined(js):
  var
    printWidth* = 120
    printColors* = false
    haveSeen: HashSet[uint64]
    line: string
  type
    ForegroundColor = enum  ## terminal's foreground colors
      fgBlack = 30,         ## black
      fgRed,                ## red
      fgGreen,              ## green
      fgYellow,             ## yellow
      fgBlue,               ## blue
      fgMagenta,            ## magenta
      fgCyan,               ## cyan
      fgWhite,              ## white
      fg8Bit,               ## 256-color (not supported, see ``enableTrueColors`` instead.)
      fgDefault             ## default terminal foreground color
else:
  import terminal
  var
    printWidth* = terminalWidth()
    printColors* = stdout.isatty()
    haveSeen: HashSet[uint64]

type
  NodeKind = enum
    nkSupport
    nkTopLevel
    nkName
    nkNumber
    nkProc
    nkType
    nkString
    nkChar
    nkBool
    nkPointer
    nkSeq
    nkArray
    nkTuple
    nkTable
    nkObject
    nkTopPair
    nkFieldPair
    nkNil
    nkRepeat

  Node = ref object
    kind: NodeKind
    value: string
    nodes: seq[Node]

# Work around for both jsony and print needs this.
template fieldPairs2*(x: untyped): untyped =
  when compiles(x[]):
    x[].fieldPairs
  else:
    x.fieldPairs

template justAddr(x): uint64 =
  cast[uint64](x.unsafeAddr)

macro `$`(a: proc): untyped =
  let procDef = a.getTypeInst
  procDef.insert 0, ident($a)
  newLit(procDef.repr)

proc escapeString*(v: string, q = "\""): string =
  result.add q
  for c in v:
    case c:
    of '\0': result.add r"\0"
    of '\\': result.add r"\\"
    of '\b': result.add r"\b"
    of '\f': result.add r"\f"
    of '\n': result.add r"\n"
    of '\r': result.add r"\r"
    of '\t': result.add r"\t"
    else:
      if ord(c) > 128:
        result.add "\\x" & toHex(ord(c), 2).toLowerAscii()
      result.add c
  result.add q

proc escapeChar(v: string): string =
  escapeString(v, "'")

proc newSupportNode*(value: string): Node =
  Node(kind: nkSupport, value: value)

proc newNameNode*(name: string): Node =
  Node(kind: nkName, value: name)

proc newTopPairNode*(k, v: Node): Node =
  Node(kind: nkTopPair, nodes: @[k, v])

proc newFieldPairNode*(k, v: Node): Node =
  Node(kind: nkFieldPair, nodes: @[k, v])

#proc newNode[K, V](t: Table[K, V]): Node
proc newNode*[T](x: seq[T]): Node
proc newNode*[N, T](x: array[N, T]): Node
proc newNode*(x: SomeNumber): Node
proc newNode*(x: string): Node
proc newNode*(x: char): Node
proc newNodeFromBaseType*[T](x: T): Node
#proc newNode[T: object](s: T): Node

proc newNode*(x: SomeNumber): Node =
  Node(kind: nkNumber, value: $x)

proc newNode*(x: bool): Node =
  Node(kind: nkBool, value: $x)

proc newNode*(x: string): Node =
  Node(kind: nkString, value: x)

proc newNode*(x: cstring): Node =
  Node(kind: nkString, value: $x)

proc newNode*(x: char): Node =
  Node(kind: nkChar, value: $x)

proc newNode*(x: Rune): Node =
  Node(kind: nkChar, value: $x)

proc newNode*(x: proc): Node =
  when compiles($x):
    Node(kind: nkProc, value: $x)
  else:
    Node(kind: nkProc, value: x.type.name)

proc newNode*(x: type): Node =
  Node(kind: nkType, value: $x)

proc newNode*[T](x: seq[T]): Node =
  var nodes: seq[Node]
  for e in x:
    nodes.add(newNodeFromBaseType(e))
  Node(kind: nkSeq, nodes:nodes)

proc newNode*[N, T](x: array[N, T]): Node =
  var nodes: seq[Node]
  for e in x:
    nodes.add(newNodeFromBaseType(e))
  Node(kind: nkArray, nodes:nodes)

proc newNode*[K, V](x: Table[K, V]): Node =
  var nodes: seq[Node]
  for k, v in x.pairs():
   nodes.add(newFieldPairNode(newNodeFromBaseType(k), newNodeFromBaseType(v)))
  Node(kind: nkTable, nodes:nodes)

proc newNode*[T](x: HashSet[T] | set[T]): Node =
  var nodes: seq[Node]
  for e in x:
    nodes.add(newNodeFromBaseType(e))
  Node(kind: nkArray, nodes:nodes)

proc newNode*[T: tuple](x: T): Node =
  var nodes: seq[Node]
  for _, e in x.fieldPairs2:
    nodes.add(newNodeFromBaseType(e))
  Node(kind: nkTuple, nodes:nodes)

proc newNode*[T: object](x: T): Node =
  var nodes: seq[Node]
  for n, e in x.fieldPairs2:
    nodes.add(newFieldPairNode(newNameNode(n), newNodeFromBaseType(e)))
  Node(kind: nkObject, value: $type(x), nodes:nodes)

proc newNode*[T](x: ref T): Node =
  if x != nil:
    when not defined(js):
      if x[].justAddr in haveSeen:
        Node(kind: nkRepeat, value:"...")
      else:
        if x[].justAddr != 0:
          haveSeen.incl x[].justAddr
        newNodeFromBaseType(x[])
    else:
      newNodeFromBaseType(x[])
  else:
    Node(kind: nkNil, value:"nil")

proc newNode*[T](x: ptr T): Node =
  if x != nil:
    newNodeFromBaseType(x[])
  else:
    Node(kind: nkNil, value:"nil")

proc newNode*(x: pointer): Node =
  if x != nil:
    Node(kind: nkPointer, value:"0x" & toHex(cast[uint64](x)))
  else:
    Node(kind: nkNil, value:"nil")

proc newNode*[T](x: ptr UncheckedArray[T]): Node =
  newNodeFromBaseType(cast[pointer](x))

proc newNode*(x: enum): Node =
  newNode($x)

proc newNodeFromBaseType*[T](x: T): Node =
  newNode(x.distinctBase(recursive = true))

proc newNodeFromBaseType*(x: type): Node =
  newNode(x)

proc textLine(node: Node): string =
  case node.kind:
    of nkNumber, nkNil, nkRepeat, nkPointer, nkProc, nkBool, nkType:
      result.add node.value
    of nkString, nkChar:
      result.add node.value.escapeString()
    of nkSeq, nkArray:
      if node.kind == nkSeq:
        result.add "@"
      result.add "["
      for i, e in node.nodes:
        if i != 0:
          result.add ", "
        result.add textLine(e)
      result.add "]"
    of nkTable:
      result.add "{"
      for i, e in node.nodes:
        if i != 0:
          result.add ", "
        result.add textLine(e)
      result.add "}"
    of nkObject, nkTuple:
      result.add node.value
      result.add "("
      for i, e in node.nodes:
        if i != 0:
          result.add ", "
        result.add textLine(e)
      result.add ")"
    of nkTopLevel:
      result.add node.value
      for i, e in node.nodes:
        if i != 0:
          result.add " "
        result.add textLine(e)
    of nkTopPair:
      result.add textLine(node.nodes[0])
      result.add "="
      result.add textLine(node.nodes[1])
    of nkFieldPair:
      result.add textLine(node.nodes[0])
      result.add ": "
      result.add textLine(node.nodes[1])
    else:
      result.add node.value

proc printStr(s: string) =
  when defined(js):
    line.add(s)
  else:
    stdout.write(s)

proc printStr(c: ForeGroundColor, s: string) =
  when defined(js):
    line.add(s)
  else:
    if printColors:
      stdout.styledWrite(c, s)
    else:
      stdout.write(s)

proc printNode*(node: Node, indent: int) =

  let wrap = textLine(node).len + indent >= printWidth

  case node.kind:
    of nkNumber, nkBool:
      printStr(fgBlue, node.value)
    of nkRepeat, nkNil, nkPointer:
      printStr(fgRed, node.value)
    of nkProc, nkType:
      printStr(fgMagenta, node.value)
    of nkString:
      printStr(fgGreen, node.value.escapeString())
    of nkChar:
      printStr(fgGreen, "'" & node.value.escapeString()[1..^2] & "'")
    of nkSeq, nkArray:
      if node.kind == nkSeq:
        printStr "@"
      if wrap:
        printStr "[\n"
        for i, e in node.nodes:
          printStr "  ".repeat(indent + 1)
          printNode(e, indent + 1)
          if i != node.nodes.len - 1:
            printStr ",\n"
        printStr "\n"
        printStr "  ".repeat(indent)
        printStr "]"
      else:
        printStr "["
        for i, e in node.nodes:
          if i != 0:
            printStr ", "
          printNode(e, 0)
        printStr "]"
    of nkTable, nkObject, nkTuple:
      if node.kind in [nkObject, nkTuple]:
        printStr(fgCyan, node.value)
        printStr "("
      else:
        printStr "{"
      if wrap:
        printStr "\n"
        for i, e in node.nodes:
          printNode(e, indent + 1)
          if i != node.nodes.len - 1:
            printStr ",\n"
        printStr "\n"
        printStr "  ".repeat(indent)
      else:
        for i, e in node.nodes:
          if i != 0:
            printStr ", "
          printNode(e, 0)
      if node.kind in [nkObject, nkTuple]:
        printStr ")"
      else:
        printStr "}"

    of nkTopLevel:
      if wrap:
        for i, e in node.nodes:
          printNode(e, 0)
          if i != node.nodes.len - 1:
            printStr "\n"
      else:
        for i, e in node.nodes:
          if i != 0:
            printStr " "
          printNode(e, 0)
      printStr "\n"

    of nkTopPair:
      printNode(node.nodes[0], 0)
      printStr "="
      printNode(node.nodes[1], 0)

    of nkFieldPair:
      printStr "  ".repeat(indent)
      printNode(node.nodes[0], indent)
      printStr ": "
      printNode(node.nodes[1], indent)

    else:
      printStr(node.value)

proc printNodes*(s: varargs[Node]) =
  haveSeen.clear()
  var nodes: seq[Node]
  for e in s:
    nodes.add(e)
  var node = Node(kind: nkTopLevel, nodes: nodes)
  printNode(node, 0)
  when defined(js):
    echo line[0 .. ^2]
    line = ""

macro print*(n: varargs[untyped]): untyped =
  var command = nnkCommand.newTree(
    newIdentNode("printNodes")
  )
  for i in 0..n.len-1:
    if n[i].kind == nnkStrLit:
      command.add nnkCommand.newTree(
        newIdentNode("newSupportNode"),
        n[i]
      )
    else:
      command.add nnkCommand.newTree(
        newIdentNode("newTopPairNode"),
        nnkCommand.newTree(
          newIdentNode("newNameNode"),
          newStrLitNode(n[i].repr)
        ),
        nnkCommand.newTree(
          newIdentNode("newNodeFromBaseType"),
          n[i]
        )
      )

  var s = nnkStmtList.newTree(command)
  return s

template debugPrint*(n: varargs[untyped]): untyped =
  {.cast(gcSafe), cast(noSideEffect).}:
    print(n)


type TableStyle* = enum
  Fancy
  Plain

proc printTable*[T](arr: seq[T], style = Fancy) =
  ## Given a list of items prints them as a table.

  # Turns items into table props.
  var
    header: seq[string]
    widths: seq[int]
    number: seq[bool]
    table: seq[seq[string]]

  var headerItem: T
  for k, v in headerItem.fieldPairs2:
    header.add(k)
    widths.add(len(k))
    number.add(type(v) is SomeNumber)

  for i, item in arr:
    var
      row: seq[string]
      col = 0
    for k, v in item.fieldPairs2:
      let text =
        when type(v) is char:
          escapeChar($v)
        elif type(v) is string:
          v.escapeString("")
        else:
          $v
      row.add(text)
      widths[col] = max(text.len, widths[col])
      inc col
    table.add(row)

  case style:
  of Fancy:
    # Print header.
    printStr("╭─")
    for col in 0 ..< header.len:
      for j in 0 ..< widths[col]:
        printStr("─")
      if col != header.len - 1:
        printStr("─┬─")
      else:
        printStr("─╮")
    printStr("\n")

    # Print header.
    printStr("│ ")
    for col in 0 ..< header.len:
      if number[col]:
        for j in header[col].len ..< widths[col]:
          printStr(" ")
        printStr(header[col])
      else:
        printStr(header[col])
        for j in header[col].len ..< widths[col]:
          printStr(" ")
      printStr(" │ ")
    printStr("\n")

    # Print header divider.
    printStr("├─")
    for col in 0 ..< header.len:
      for j in 0 ..< widths[col]:
        printStr("─")
      if col != header.len - 1:
        printStr("─┼─")
      else:
        printStr("─┤")
    printStr("\n")

    # Print the values
    for i, item in arr:
      var col = 0
      printStr("│ ")
      for k, v in item.fieldPairs2:
        let text = table[i][col]
        if number[col]:
          printStr(" ".repeat(widths[col] - text.len))
          printStr(fgBlue, text)
        else:
          printStr(fgGreen, text)
          printStr(" ".repeat(widths[col] - text.len))
        printStr(" │ ")
        inc col
      printStr("\n")

    # Print footer.
    printStr("╰─")
    for col in 0 ..< header.len:
      for j in 0 ..< widths[col]:
        printStr("─")
      if col != header.len - 1:
        printStr("─┴─")
      else:
        printStr("─╯")
    printStr("\n")

  of Plain:
     # Print header.
    for col in 0 ..< header.len:
      printStr(header[col])
      for j in header[col].len ..< widths[col]:
        printStr(" ")
      printStr("   ")
    printStr("\n")

    # Print the values
    for i, item in arr:
      var col = 0
      for k, v in item.fieldPairs2:
        let text = table[i][col]
        if number[col]:
          for j in text.len ..< widths[col]:
            printStr(" ")
          printStr(fgBlue, text)
        else:
          printStr(fgGreen, text)
          if not number[col]:
            for j in text.len ..< widths[col]:
              printStr(" ")
        printStr("   ")
        inc col
      printStr("\n")

proc printBarChart*[N:SomeNumber](data: seq[(string, N)]) =
  ## prints a bar chart like this:
  ## zpu: ######### 20.45
  ## cpu: ################################################# 70.00
  ## gpu: ########################### 45.56
  const fillChar = "#"
  proc maximize(a: var SomeNumber, v: SomeNumber) = a = max(a, v)
  proc minimize(a: var SomeNumber, v: SomeNumber) = a = min(a, v)
  proc frac(a: SomeFloat): SomeFloat = a - floor(a)
  var
    maxKeyWidth = 0
    minNumber: N = 0
    maxNumber: N = 0
    maxLabel = 0

  for (k, v) in data:
    maximize(maxKeyWidth, k.len)
    maximize(maxLabel, ($v).len)
    minimize(minNumber, v)
    maximize(maxNumber, v)

  var
    chartWidth = printWidth - maxKeyWidth - 3 - maxLabel - 2
  if minNumber != 0:
    chartWidth -= maxLabel + 1
  var
    barScale = chartWidth.float / (maxNumber.float - minNumber.float)
    preZero = (-minNumber.float * barScale).ceil.int

  for (k, v) in data:
    var line = ""
    printStr " ".repeat(maxKeyWidth - k.len)
    printStr fgGreen, k
    printStr ": "

    let barWidth = v.float * barScale
    if minNumber == 0:
      printStr fillChar.repeat(floor(barWidth).int)
      printStr " "
      printStr fgBlue, $v
    else:
      if barWidth >= 0:
        printStr " ".repeat(preZero + maxLabel)
        printStr fillChar.repeat(floor(barWidth).int)
        printStr " "
        printStr fgBlue, $v
      else:
        printStr " ".repeat(preZero + barWidth.int + maxLabel - ($v).len)
        printStr fgBlue, $v
        printStr " "
        printStr fillChar.repeat(floor(-barWidth).int - 1)
    printStr "\n"

template printEx*()=
  let current_ex = getCurrentException()
  print "Exception Type: " & $current_ex.name
  print "Exception Message: " & $current_ex.msg