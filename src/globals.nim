import chronos
import dns_resolve, hashes, print, parseopt,strutils, random, net, osproc, strformat
import checksums/sha1

# export IpAddress

const version = "4.0"

type RunMode*{.pure.} = enum
    iran, kharej

var mode*: RunMode = RunMode.iran

# [Log Options]true
const log_conn_create* = true
const log_data_len* = true
const log_conn_destory* = true
const log_conn_error* = true

# [TLS]
let tls13_record_layer* = "\x17\x03\x03" 
let tls13_record_layer_data_len_size*:uint = 2
let full_tls_record_len*:uint = tls13_record_layer.len().uint + tls13_record_layer_data_len_size
# var tls_records*:uint = 50

# [Connection]
var trust_time*: uint = 3 #secs
var pool_size*: uint = 16
var pool_age*: uint = 10
var max_idle_time*: uint = 600 #secs (default TCP RFC is 3600)
var max_pool_unused_time*: uint = 60 #secs
let mux_record_len*:uint32 = 5 #2bytes port 2bytes id 1byte reserved
var mux_width*:uint32 = 2

# [Noise]
var noise_ratio*:uint = 0


# [Routes]
var listen_addr* = "0.0.0.0"
var listen_port*: Port = 0.Port
var next_route_addr* = ""
var next_route_port*: Port = 0.Port
var iran_addr* = ""
var iran_port*: Port = 0.Port
var final_target_domain* = ""
var final_target_ip*: string
var trusted_foreign_peers*:seq[IpAddress]
const final_target_port*:Port = 443.Port # port of the sni host (443 for tls handshake)
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
var multi_port_min: Port = 0.Port
var multi_port_max: Port = 0.Port
var multi_port_additions: seq[Port]

# [posix constants]
const SO_ORIGINAL_DST* = 80
const SOL_IP* = 0

proc isPortFree*(port:Port):bool = 
    execCmdEx(&"""lsof -i:{port}""").output.len < 3

proc chooseRandomLPort():Port =
    result = block:
        if multi_port_min == 0.Port and multi_port_max == 0.Port:
            multi_port_additions[rand(multi_port_additions.high).int]
        elif (multi_port_min != 0.Port and multi_port_max != 0.Port):
            (multi_port_min.int + rand(multi_port_max.int - multi_port_min.int)).Port
        else:
            quit("multi port range may not include port 0!")

    if not isPortFree(result):return chooseRandomLPort()
    
proc iptablesInstalled(): bool {.used.} =
    execCmdEx("""dpkg-query -W --showformat='${Status}\n' iptables|grep "install ok install"""").output != ""

proc resetIptables*() =
    echo "reseting iptable nat"
    assert 0 == execCmdEx("iptables -t nat -F").exitCode
    assert 0 == execCmdEx("iptables -t nat -X").exitCode



proc createIptablesForwardRules*() =
    if reset_iptable: resetIptables()
    if not (multi_port_min == 0.Port or multi_port_max == 0.Port):
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

    var p = initOptParser(longNoVal = @["kharej", "iran", "multiport", "keep-ufw", "keep-iptables", "keep-os-limit",  "debug"])
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


                    else:
                        echo "invalid option"
                        quit(-1)
            else:
                case p.key:

                    of "lport":
                        try:
                            listen_port = parseInt(p.val).Port
                        except: #multi port
                            if not multiportSupported(): quit(-1)
                            try:
                                let port_range_string = p.val
                                multi_port = true
                                listen_port = 0.Port # will take a random port
                                # pool_size = max(2.uint, pool_size div 2.uint)
                                let port_range = port_range_string.split('-')
                                assert port_range.len == 2, "Invalid listen port range. !"
                                multi_port_min = max(1.uint16, port_range[0].parseInt.uint16).Port
                                multi_port_max = min(65535.uint16, port_range[1].parseInt.uint16).Port
                                assert multi_port_max.uint16 - multi_port_min.uint16 >= 0, "port range is invalid!  use --lport:min-max"
                            except:
                                quit("could not parse lport.")

                        print listen_port
                    of "add-port":
                        if not multiportSupported(): quit(-1)
                        multi_port = true
                        if listen_port != 0.Port:
                            multi_port_additions.add listen_port.Port
                            listen_port = 0.Port
                        multi_port_additions.add p.val.parseInt().Port

                    of "peer":
                        
                        trusted_foreign_peers.add parseIpAddress(p.val)


                    of "toip":
                        next_route_addr = (p.val)
                        print next_route_addr

                    of "toport":
                        try:
                            next_route_port = parseInt(p.val).Port
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
                        iran_port = parseInt(p.val).Port
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

                    of "pool-age":
                        pool_age = parseInt(p.val).uint
                        print pool_age

                    of "mux-width":
                        mux_width = parseInt(p.val).uint32
                        print mux_width

                    of "noise":
                        noise_ratio = parseInt(p.val).uint32
                        print noise_ratio

                    of "trust_time":
                        trust_time = parseInt(p.val).uint
                        print trust_time
                    
                    of "listen":
                        listen_addr = (p.val)
                        print listen_addr
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
            if iran_port == 0.Port and not multi_port:
                echo "specify the iran server prot --iran-port:{port}"
                exit = true

            if next_route_addr.isEmptyOrWhitespace():
                echo "specify the next ip for routing --toip:{ip} (usually 127.0.0.1)"
                exit = true
            if next_route_port == 0.Port and not multi_port:
                echo "specify the port of the next ip for routing --toport:{port} (the port of the config that panel shows you)"
                exit = true

        of RunMode.iran:
            if listen_port == 0.Port and not multi_port:
                echo "specify the listen prot --lport:{port}  (usually 443)"
                exit = true
            if listen_port == 0.Port and multi_port:
                listen_port = chooseRandomLPort()
                    

    if final_target_domain.isEmptyOrWhitespace():
        echo "specify the sni for routing --sni:{domain}"
        exit = true
    if password.isEmptyOrWhitespace():
        echo "specify the password  --password:{something}"
        exit = true

    if exit: quit("Application did not start due to above logs.")

    if terminate_secs != 0:
        sleepAsync(terminate_secs*1000).addCallback(
            proc(arg: pointer) =
            echo "Exiting due to termination timeout. (--terminate)"
            quit(0)
        )

    # if multi_port and listen_addr == "0.0.0.0":
        # listen_addr = "127.0.0.1"

    final_target_ip = resolveIPv4(final_target_domain)
    print "\n"
    self_ip =  getPrimaryIPAddr(dest = parseIpAddress("8.8.8.8"))
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
