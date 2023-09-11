import dns_resolve, hashes, print, parseopt, asyncdispatch, strutils, random, net, osproc, strformat
import checksums/sha1

export IpAddress

const version = "2"

type RunMode*{.pure.} = enum
    iran, kharej

var mode*: RunMode = RunMode.iran

# [Log Options]
const log_data_len* = false
const log_conn_create* = true
const log_conn_destory* = false
const log_conn_error* = true


# [Connection]
var trust_time*: uint = 3 #secs
var pool_size*: uint = 16
var max_idle_time*: uint = 600 #secs (default TCP RFC is 3600)
var max_pool_unused_time*: uint = 60 #secs
const chunk_size* = 8192

var mux*: bool = false
let tls13_record_layer* = "\x17\x03\x03" 
let mux_header_size*:uint32 = tls13_record_layer.len().uint32 + 2 +2 + 4 # followed by 2 bytes len +2 port+and 4 bytes cid
let mux_payload_size*:uint32 = 1024 
let mux_chunk_size*:uint32 = mux_payload_size + mux_header_size

let socket_buffered* = false # when using mux, it depends
var mux_capacity*:uint32 = 4

# [Routes]
const listen_addr* = "0.0.0.0"
var listen_port*: uint32 = 0
var next_route_addr* = ""
var next_route_port*: uint32 = 0
var iran_addr* = ""
var iran_port*: uint32 = 0
var final_target_domain* = ""
var final_target_ip*: string
const final_target_port* = 443 # port of the sni host (443 for tls handshake)
var self_ip*: IpAddress


# [passwords and hashes]
var password* = ""
var password_hash*: string
var sh1*: uint32
var sh2*: uint32
var sh3*: uint32
var sh4*: uint32
var sh5*: uint8
var random_str* = newString(len = 2000)

# [settings]
var disable_ufw* = true
var reset_iptable* = true
var keep_system_limit* = false
var terminate_secs* = 0
var debug_info* = false

# [multiport]
var multi_port* = false
var multi_port_min: int
var multi_port_max: int
var multi_port_additions: seq[uint32]

# [posix constants]
const SO_ORIGINAL_DST* = 80
const SOL_IP* = 0
proc iptablesInstalled(): bool {.used.} =
    execCmdEx("""dpkg-query -W --showformat='${Status}\n' iptables|grep "install ok install"""").output != ""

proc resetIptables*() =
    echo "reseting iptable nat"
    assert 0 == execCmdEx("iptables -t nat -F").exitCode
    assert 0 == execCmdEx("iptables -t nat -X").exitCode



proc createIptablesForwardRules*() =
    if reset_iptable: resetIptables()
    if not (multi_port_min == 0 or multi_port_max == 0):
        assert 0 == execCmdEx(&"""iptables -t nat -A PREROUTING -p tcp --dport {multi_port_min}:{multi_port_max} -j REDIRECT --to-port {listen_port}""").exitCode

    for port in multi_port_additions:
        assert 0 == execCmdEx(&"""iptables -t nat -A PREROUTING -p tcp --dport {port} -j REDIRECT --to-port {listen_port}""").exitCode


proc multiportSupported(): bool =
    when defined(windows) or defined(android):
        echo "multi listen port unsupported for windows."
        return false
    else:
        if not iptablesInstalled():
            echo "multi listen port requires iptables to be installed."
            return false
        return true


proc init*() =
    print version

    for i in 0..<random_str.len():
        random_str[i] = rand(char.low .. char.high).char

    var p = initOptParser(longNoVal = @["kharej", "iran", "multiport", "keep-ufw", "keep-iptables", "keep-os-limit", "mux", "debug"])
    while true:
        p.next()
        case p.kind
        of cmdEnd: break
        of cmdShortOption, cmdLongOption:
            if p.val == "":
                case p.key:
                    of "kharej":
                        mode = RunMode.kharej
                        print mode
                    of "iran":
                        mode = RunMode.iran
                        print mode
                    of "keep-ufw":
                        disable_ufw = false
                    of "keep-iptables":
                        reset_iptable = false
                    of "multiport":
                        multiport = true
                    of "keep-os-limit":
                        keep_system_limit = true
                    of "debug":
                        debug_info = true
                    of "mux":
                        mux = true

                    else:
                        echo "invalid option"
                        quit(-1)
            else:
                case p.key:

                    of "lport":
                        try:
                            listen_port = parseInt(p.val).uint32
                        except: #multi port
                            if not multiportSupported(): quit(-1)
                            try:
                                let port_range_string = p.val
                                multi_port = true
                                listen_port = 0 # will take a random port
                                pool_size = max(2.uint, pool_size div 2.uint)
                                let port_range = port_range_string.split('-')
                                assert port_range.len == 2, "Invalid listen port range. !"
                                multi_port_min = max(1, port_range[0].parseInt)
                                multi_port_max = min(65535, port_range[1].parseInt)
                                assert multi_port_max-multi_port_min >= 0, "port range is invalid!  use --lport:min-max"
                            except:
                                quit("could not parse lport.")

                        print listen_port
                    of "add-port":
                        if not multiportSupported(): quit(-1)
                        multi_port = true
                        if listen_port != 0:
                            multi_port_additions.add listen_port
                            listen_port = 0
                        multi_port_additions.add p.val.parseInt().uint32

                    of "toip":
                        next_route_addr = (p.val)
                        print next_route_addr

                    of "toport":
                        try:
                            next_route_port = parseInt(p.val).uint32
                            print next_route_port

                        except: #multi port
                            try:
                                assert(p.val == "multiport")

                                multi_port = true
                                print multi_port
                            except:
                                quit("could not parse toport.")

                    of "iran-ip":
                        iran_addr = (p.val)
                        print iran_addr

                    of "iran-port":
                        iran_port = parseInt(p.val).uint32
                        print iran_port

                    of "sni":
                        final_target_domain = (p.val)
                        print final_target_domain

                    of "password":
                        password = (p.val)
                        print password

                    of "terminate":
                        terminate_secs = parseInt(p.val) * 60*60
                        print terminate_secs

                    of "pool":
                        pool_size = parseInt(p.val).uint
                        print pool_size

                    of "trust_time":
                        trust_time = parseInt(p.val).uint
                        print trust_time
                    else:
                        echo "Unkown argument ", p.key
                        quit(-1)


        of cmdArgument:
            # echo "Argument: ", p.key
            echo "invalid argument style: ", p.key
            quit(-1)


    var exit = false

    case mode:
        of RunMode.kharej:
            if iran_addr.isEmptyOrWhitespace():
                echo "specify the ip address of the iran server --iran-addr:{ip}"
                exit = true
            if iran_port == 0 and not multi_port:
                echo "specify the iran server prot --iran-port:{port}"
                exit = true

            if next_route_addr.isEmptyOrWhitespace():
                echo "specify the next ip for routing --toip:{ip} (usually 127.0.0.1)"
                exit = true
            if next_route_port == 0 and not multi_port:
                echo "specify the port of the next ip for routing --toport:{port} (the port of the config that panel shows you)"
                exit = true

        of RunMode.iran:
            if listen_port == 0 and not multi_port:
                echo "specify the listen prot --lport:{port}  (usually 443)"
                exit = true


    if final_target_domain.isEmptyOrWhitespace():
        echo "specify the sni for routing --sni:{domain}"
        exit = true
    if password.isEmptyOrWhitespace():
        echo "specify the password  --password:{something}"
        exit = true

    if exit: quit("Application did not start due to above logs.")

    if terminate_secs != 0:
        sleepAsync(terminate_secs*1000).addCallback(
            proc() =
            echo "Exiting due to termination timeout. (--terminate)"
            quit(0)
        )

    final_target_ip = resolveIPv4(final_target_domain)
    print "\n"
    self_ip = getPrimaryIPAddr(dest = parseIpAddress("8.8.8.8"))
    password_hash = $(secureHash(password))
    sh1 = hash(password_hash).uint32
    sh2 = hash(sh1).uint32
    sh3 = hash(sh2).uint32
    sh4 = hash(sh3).uint32
    # sh5 = (3 + (hash(sh2).uint32 mod 5)).uint8
    sh5 = hash(sh4).uint8
    while sh5 <= 2.uint32 or sh5 >= 223.uint32:
        sh5 = hash(sh5).uint8


    print password, password_hash, sh1, sh2, sh3, pool_size
    print "\n"
