#
#
#            Nim's Runtime Library
#        (c) Copyright 2015 Dominik Picheta
#
#    See the file "copying.txt", included in this
#    distribution, for details about the copyright.
#

import std/[macros]

proc skipUntilStmtList(node: NimNode): NimNode {.compileTime.} =
  # Skips a nest of StmtList's.
  if node[0].kind == nnkStmtList:
    skipUntilStmtList(node[0])
  else:
    node

proc processBody(node, retFutureSym: NimNode,
                 baseTypeIsVoid: bool): NimNode {.compileTime.} =
  #echo(node.treeRepr)
  result = node
  case node.kind
  of nnkReturnStmt:
    result = newNimNode(nnkStmtList, node)

    # As I've painfully found out, the order here really DOES matter.
    if node[0].kind == nnkEmpty:
      if not baseTypeIsVoid:
        result.add newCall(newIdentNode("complete"), retFutureSym,
            newIdentNode("result"))
      else:
        result.add newCall(newIdentNode("complete"), retFutureSym)
    else:
      let x = node[0].processBody(retFutureSym, baseTypeIsVoid)
      if x.kind == nnkYieldStmt: result.add x
      else:
        result.add newCall(newIdentNode("complete"), retFutureSym, x)

    result.add newNimNode(nnkReturnStmt, node).add(newNilLit())
    return # Don't process the children of this return stmt
  of RoutineNodes-{nnkTemplateDef}:
    # skip all the nested procedure definitions
    return node
  else: discard

  for i in 0 ..< result.len:
    # We must not transform nested procedures of any form, otherwise
    # `retFutureSym` will be used for all nested procedures as their own
    # `retFuture`.
    result[i] = processBody(result[i], retFutureSym, baseTypeIsVoid)

proc getName(node: NimNode): string {.compileTime.} =
  case node.kind
  of nnkSym:
    return node.strVal
  of nnkPostfix:
    return node[1].strVal
  of nnkIdent:
    return node.strVal
  of nnkEmpty:
    return "anonymous"
  else:
    error("Unknown name.")

proc verifyReturnType(typeName: string) {.compileTime.} =
  if typeName != "Future":
    error("Expected return type of 'Future' got '" & typeName & "'")

macro unsupported(s: static[string]): untyped =
  error s

proc params2(someProc: NimNode): NimNode =
  # until https://github.com/nim-lang/Nim/pull/19563 is available
  if someProc.kind == nnkProcTy:
    someProc[0]
  else:
    params(someProc)

proc cleanupOpenSymChoice(node: NimNode): NimNode {.compileTime.} =
  # Replace every Call -> OpenSymChoice by a Bracket expr
  # ref https://github.com/nim-lang/Nim/issues/11091
  if node.kind in nnkCallKinds and
    node[0].kind == nnkOpenSymChoice and node[0].eqIdent("[]"):
    result = newNimNode(nnkBracketExpr)
    for child in node[1..^1]:
      result.add(cleanupOpenSymChoice(child))
  else:
    result = node.copyNimNode()
    for child in node:
      result.add(cleanupOpenSymChoice(child))

proc asyncSingleProc(prc: NimNode): NimNode {.compileTime.} =
  ## This macro transforms a single procedure into a closure iterator.
  ## The ``async`` macro supports a stmtList holding multiple async procedures.
  if prc.kind notin {nnkProcTy, nnkProcDef, nnkLambda, nnkMethodDef, nnkDo}:
      error("Cannot transform " & $prc.kind & " into an async proc." &
            " proc/method definition or lambda node expected.")

  let returnType = cleanupOpenSymChoice(prc.params2[0])

  # Verify that the return type is a Future[T]
  let baseType =
    if returnType.kind == nnkBracketExpr:
      let fut = repr(returnType[0])
      verifyReturnType(fut)
      returnType[1]
    elif returnType.kind == nnkEmpty:
      ident("void")
    else:
      raiseAssert("Unhandled async return type: " & $prc.kind)

  let baseTypeIsVoid = baseType.eqIdent("void")

  if prc.kind in {nnkProcDef, nnkLambda, nnkMethodDef, nnkDo}:
    let
      prcName = prc.name.getName
      outerProcBody = newNimNode(nnkStmtList, prc.body)

    # Copy comment for nimdoc
    if prc.body.len > 0 and prc.body[0].kind == nnkCommentStmt:
      outerProcBody.add(prc.body[0])

    let
      internalFutureSym = ident "chronosInternalRetFuture"
      internalFutureType =
        if baseTypeIsVoid:
          newNimNode(nnkBracketExpr, prc).add(newIdentNode("Future")).add(newIdentNode("void"))
        else: returnType
      castFutureSym = quote do:
        cast[`internalFutureType`](`internalFutureSym`)
      procBody = prc.body.processBody(castFutureSym, baseTypeIsVoid)

    # don't do anything with forward bodies (empty)
    if procBody.kind != nnkEmpty:
      # fix #13899, `defer` should not escape its original scope
      let procBodyBlck =
        newStmtList(newTree(nnkBlockStmt, newEmptyNode(), procBody))

      # Avoid too much quote do to not lose original line numbers
      let closureBody = if baseTypeIsVoid:
        let resultTemplate = quote do:
          template result: auto {.used.} =
            {.fatal: "You should not reference the `result` variable inside" &
                    " a void async proc".}
        # -> complete(chronosInternalRetFuture)
        let complete =
          newCall(newIdentNode("complete"), castFutureSym)

        newStmtList(resultTemplate, procBodyBlck, complete)
      else:
        # -> iterator nameIter(chronosInternalRetFuture: Future[T]): FutureBase {.closure.} =
        # ->   {.push warning[resultshadowed]: off.}
        # ->   var result: T
        # ->   {.pop.}
        # ->   <proc_body>
        # ->   complete(chronosInternalRetFuture, result)
        newStmtList(
           # -> {.push warning[resultshadowed]: off.}
          newNimNode(nnkPragma).add(newIdentNode("push"),
            newNimNode(nnkExprColonExpr).add(newNimNode(nnkBracketExpr).add(
              newIdentNode("warning"), newIdentNode("resultshadowed")),
            newIdentNode("off"))),

          # -> var result: T
          newNimNode(nnkVarSection, prc.body).add(
            newIdentDefs(newIdentNode("result"), baseType)),

          # -> {.pop.})
          newNimNode(nnkPragma).add(
            newIdentNode("pop")),

          procBodyBlck,

          # -> complete(chronosInternalRetFuture, result)
          newCall(newIdentNode("complete"),
            castFutureSym, newIdentNode("result")))

      let
        internalFutureParameter = nnkIdentDefs.newTree(internalFutureSym, newIdentNode("FutureBase"), newEmptyNode())
        iteratorNameSym = genSym(nskIterator, $prcName)
        closureIterator = newProc(iteratorNameSym, [newIdentNode("FutureBase"), internalFutureParameter],
                                  closureBody, nnkIteratorDef)

      iteratorNameSym.copyLineInfo(prc)

      closureIterator.pragma = newNimNode(nnkPragma, lineInfoFrom=prc.body)
      closureIterator.addPragma(newIdentNode("closure"))

      # `async` code must be gcsafe
      closureIterator.addPragma(newIdentNode("gcsafe"))

      # TODO when push raises is active in a module, the iterator here inherits
      #      that annotation - here we explicitly disable it again which goes
      #      against the spirit of the raises annotation - one should investigate
      #      here the possibility of transporting more specific error types here
      #      for example by casting exceptions coming out of `await`..
      let raises = nnkBracket.newTree()
      when chronosStrictException:
        raises.add(newIdentNode("CatchableError"))
        when (NimMajor, NimMinor) < (1, 4):
          raises.add(newIdentNode("Defect"))
      else:
        raises.add(newIdentNode("Exception"))

      closureIterator.addPragma(nnkExprColonExpr.newTree(
        newIdentNode("raises"),
        raises
      ))

      # If proc has an explicit gcsafe pragma, we add it to iterator as well.
      # TODO if these lines are not here, srcloc tests fail (!)
      if prc.pragma.findChild(it.kind in {nnkSym, nnkIdent} and
                              it.strVal == "gcsafe") != nil:
        closureIterator.addPragma(newIdentNode("gcsafe"))

      outerProcBody.add(closureIterator)

      # -> let resultFuture = newFuture[T]()
      # declared at the end to be sure that the closure
      # doesn't reference it, avoid cyclic ref (#203)
      let
        retFutureSym = ident "resultFuture"
      # Do not change this code to `quote do` version because `instantiationInfo`
      # will be broken for `newFuture()` call.
      outerProcBody.add(
        newLetStmt(
          retFutureSym,
          newCall(newTree(nnkBracketExpr, ident "newFuture", baseType),
                  newLit(prcName))
        )
      )

      # -> resultFuture.closure = iterator
      outerProcBody.add(
        newAssignment(
          newDotExpr(retFutureSym, newIdentNode("closure")),
          iteratorNameSym)
      )

      # -> futureContinue(resultFuture))
      outerProcBody.add(
          newCall(newIdentNode("futureContinue"), retFutureSym)
      )

      # -> return resultFuture
      outerProcBody.add newNimNode(nnkReturnStmt, prc.body[^1]).add(retFutureSym)

      prc.body = outerProcBody

  if prc.kind notin {nnkProcTy, nnkLambda}: # TODO: Nim bug?
    prc.addPragma(newColonExpr(ident "stackTrace", ident "off"))

  # See **Remark 435** in this file.
  # https://github.com/nim-lang/RFCs/issues/435
  prc.addPragma(newIdentNode("gcsafe"))

  let raises = nnkBracket.newTree()
  when (NimMajor, NimMinor) < (1, 4):
    raises.add(newIdentNode("Defect"))
  prc.addPragma(nnkExprColonExpr.newTree(
    newIdentNode("raises"),
    raises
  ))

  if baseTypeIsVoid:
    if returnType.kind == nnkEmpty:
      # Add Future[void]
      prc.params2[0] =
        newNimNode(nnkBracketExpr, prc)
        .add(newIdentNode("Future"))
        .add(newIdentNode("void"))

  prc

template await*[T](f: Future[T]): untyped =
  when declared(chronosInternalRetFuture):
    chronosInternalRetFuture.child = f
    # `futureContinue` calls the iterator generated by the `async`
    # transformation - `yield` gives control back to `futureContinue` which is
    # responsible for resuming execution once the yielded future is finished
    yield chronosInternalRetFuture.child

    # `child` is guaranteed to have been `finished` after the yield
    if chronosInternalRetFuture.mustCancel:
      raise newCancelledError()

    # `child` released by `futureContinue`
    chronosInternalRetFuture.child.internalCheckComplete()
    when T isnot void:
      cast[type(f)](chronosInternalRetFuture.child).internalRead()
  else:
    unsupported "await is only available within {.async.}"

template awaitne*[T](f: Future[T]): Future[T] =
  when declared(chronosInternalRetFuture):
    chronosInternalRetFuture.child = f
    yield chronosInternalRetFuture.child
    if chronosInternalRetFuture.mustCancel:
      raise newCancelledError()
    cast[type(f)](chronosInternalRetFuture.child)
  else:
    unsupported "awaitne is only available within {.async.}"

macro async*(prc: untyped): untyped =
  ## Macro which processes async procedures into the appropriate
  ## iterators and yield statements.
  if prc.kind == nnkStmtList:
    result = newStmtList()
    for oneProc in prc:
      result.add asyncSingleProc(oneProc)
  else:
    result = asyncSingleProc(prc)
  when chronosDumpAsync:
    echo repr result
