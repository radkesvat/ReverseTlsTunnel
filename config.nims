import std/[strformat,macros,strutils,ospaths]

const Release = true


const libs_dir = "libs"
const output_dir = "dist"
const src_dir = "src"
const nimble_path = libs_dir&"/nimble"

template require(package: untyped) =
    block:
        var pack_to_install {.inject.} = astToStr(package)
        if (astToStr(package))[0] == '\"':
            pack_to_install[0] = ' '
            pack_to_install[pack_to_install.high()] = ' '
            pack_to_install = pack_to_install.replace("\\\"", "\"")
        exec fmt"nimble -l install --nimbleDir:{nimble_path} {pack_to_install} -y"

task install, "install deps":
    require zippy
    require checksums
    require stew
    require bearssl
    require httputils
    require unittest2
    # require chronos
    # require stew
    # require jsony
    # require secp256k1
    # require ndns

task build_server, "builds server":
    let backend = "c"
    let output_dir_target = output_dir
    const output_file_name = "RTT"&(when defined(windows): ".exe" else: "")

    setCommand("c", src_dir&"/main.nim")
    switch("nimblePath", nimble_path&"/pkgs2")

    var output = output_dir_target /  output_file_name
    # switch("mm", "orc") not for chronos
    switch("mm", "refc")
    switch("threads", "off")
    # switch("exceptions", "setjmp")
    switch("warning", "HoleEnumConv:off")
    switch("warning", "BareExcept:off")
    
    
    # switch("d", "useMalloc")

    switch("d", "asyncBackend:chronos")
 
    # switch("cc", "clang")

    switch("path", src_dir)
    switch("path", libs_dir)
    switch("path", libs_dir&"/chronos/")
    switch("passC", "-I "&libs_dir&"/hwinfo/include/")

    switch("nimcache", "build"/hostOS/hostCPU)
    # switch("define", "logGC")
    # switch("define", "ssl")

    when Release:
        switch("opt", "speed")
        switch("debugger", "off")
        switch("d", "release")
        # switch("d", "danger") #disables assertions therfore won't work!

        switch("passL", " -s")
        switch("debuginfo", "off")
        switch("passC", "-DNDEBUG")
        switch("passC", "-flto")
        switch("passL", "-flto")

        switch("obj_checks","off")
        switch("field_checks","off")
        switch("range_checks","off")
        switch("bound_checks","off")
        switch("overflow_checks","off")
        # switch("assertions","off")
        switch("stacktrace","off")
        switch("linetrace","off")
        switch("debugger","off")
        switch("line_dir","off")


        # switch("passL", " -static")
        # switch("passL", " -static-libgcc")
        # switch("passL", " -static-libstdc++")
 


    switch("backend", backend)
    switch("outdir", output_dir_target)
    switch("out", output)



task build, "builds all":

    # echo staticExec "pkill RTT"
    # echo staticExec "taskkill /IM RTT.exe /F"
    
    exec "nim build_server"
    # withDir(output_dir):
        # exec "chmod +x RTT"
        # echo staticExec "./RTT >> output.log 2>&1"
        
