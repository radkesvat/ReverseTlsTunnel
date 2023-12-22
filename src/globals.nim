import chronos
import dns_resolve, hashes, print, parseopt, strutils, random, net, osproc, strformat
import checksums/sha1


const version = "7.1"

type RunMode*{.pure.} = enum
    unspecified, iran, kharej

var mode*: RunMode = RunMode.unspecified

# [Log Options]
var log_conn_create* = true
var log_data_len* = false
var log_conn_destory* = false
var log_conn_error* = false

# [TLS]
let tls13_record_layer* = "\x17\x03\x03"
let tls13_record_layer_data_len_size*: uint = 2
let full_tls_record_len*: uint = tls13_record_layer.len().uint + tls13_record_layer_data_len_size


# [Connection]
var trust_time*: uint = 3 #secs
var upload_cons*: uint = 8
var download_cons*: uint = 8
var connection_age*: uint = 180 # secs
var connection_rewind*: uint = 4 # secs
# var pool_size*: uint = 24
# var pool_age*: uint = 15
var fakeupload_con_age*: uint = 60 #secs
var max_pool_unused_time*: uint = 60 #secs
let mux_record_len*: uint32 = 5 #2bytes port 2bytes id 1byte reserved
var max_idle_timeout*:int = 500 #secs

# var udp_max_ppc*: uint32 = 500
var udp_max_idle_time*: uint = 12000 #secs


# [Noise]
var noise_ratio*: uint = 0


# [Routes]
var listen_addr* = "::"

var listen_port*: Port = 0.Port
var next_route_addr* = ""
var next_route_port*: Port = 0.Port
var iran_addr* = ""
var iran_port*: Port = 0.Port
var final_target_domain* = ""
var final_target_ip*: string
var trusted_foreign_peers*: seq[IpAddress]
const final_target_port*: Port = 443.Port # port of the sni host (443 for tls handshake)
var self_ip*: IpAddress


# [passwords and hashes]
var password* = ""
var password_hash*: string
var sh1*: uint32
var sh2*: uint32
var sh3*: uint32
var sh4*: uint32
var sh5*: uint8
var random_str* = newString(len = 0)
var fast_encrypt_width*: uint = 600

# [settings]
var disable_ufw* = true
var reset_iptable* = true
var keep_system_limit* = false
var accept_udp* = false
var terminate_secs* = 0
var debug_info* = false

# [multiport]
var multi_port* = false
var multi_port_min: Port = 0.Port
var multi_port_max: Port = 0.Port
var multi_port_additions: seq[Port]

# [posix constants]
const SO_ORIGINAL_DST* = 80
const IP6T_SO_ORIGINAL_DST* = 80

const SOL_IP* = 0
const SOL_IPV6* = 41


proc isPortFree*(port: Port): bool =
    execCmdEx(&"""lsof -i:{port}""").output.len < 3

proc chooseRandomLPort(): Port =
    result = block:
        if multi_port_min == 0.Port and multi_port_max == 0.Port:
            multi_port_additions[rand(multi_port_additions.high).int]
        elif (multi_port_min != 0.Port and multi_port_max != 0.Port):
            (multi_port_min.int + rand(multi_port_max.int - multi_port_min.int)).Port
        else:
            quit("multi port range may not include port 0!")

    if not isPortFree(result): return chooseRandomLPort()

proc iptablesInstalled(): bool {.used.} =
    execCmdEx("""dpkg-query -W --showformat='${Status}\n' iptables|grep "install ok install"""").output != ""

proc ip6tablesInstalled(): bool {.used.} =
    execCmdEx("""dpkg-query -W --showformat='${Status}\n' ip6tables|grep "install ok install"""").output != ""

proc lsofInstalled(): bool {.used.} =
    execCmdEx("""dpkg-query -W --showformat='${Status}\n' lsof|grep "install ok install"""").output != ""

proc resetIptables*() =
    echo "reseting iptable nat"
    assert 0 == execCmdEx("iptables -t nat -F").exitCode
    assert 0 == execCmdEx("iptables -t nat -X").exitCode
    if ip6tablesInstalled():
        assert 0 == execCmdEx("ip6tables -t nat -F").exitCode
        assert 0 == execCmdEx("ip6tables -t nat -X").exitCode


#ip6tables -t nat -A PREROUTING -p tcp --dport 443:2083 -j REDIRECT --to-port
proc createIptablesForwardRules*() =
    if reset_iptable: resetIptables()
    proc rule(protocal : string)=
        if not (multi_port_min == 0.Port or multi_port_max == 0.Port):
            assert 0 == execCmdEx(&"""iptables -t nat -A PREROUTING -p {protocal} --dport {multi_port_min}:{multi_port_max} -j REDIRECT --to-port {listen_port}""").exitCode
            assert 0 == execCmdEx(&"""ip6tables -t nat -A PREROUTING -p {protocal} --dport {multi_port_min}:{multi_port_max} -j REDIRECT --to-port {listen_port}""").exitCode

        for port in multi_port_additions:
            assert 0 == execCmdEx(&"""iptables -t nat -A PREROUTING -p {protocal} --dport {port} -j REDIRECT --to-port {listen_port}""").exitCode
            assert 0 == execCmdEx(&"""ip6tables -t nat -A PREROUTING -p {protocal} --dport {port} -j REDIRECT --to-port {listen_port}""").exitCode

    rule("tcp")
    if accept_udp: rule("udp")

proc multiportSupported(): bool =
    when defined(windows) or defined(android):
        echo "multi listen port unsupported for windows."
        return false
    else:
        if not iptablesInstalled():
            echo "multi listen port requires iptables to be installed.  \"apt-get install iptables\""
            return false
        if not ip6tablesInstalled():
            echo "multi listen port requires ip6tables to be installed. (ip6tables not iptables !)  \"apt-get install ip6tables\""
            return false

        if not lsofInstalled():
            echo "multi listen port requires lsof to be installed.  install with \"apt-get install lsof\""
            return false

        return true


proc init*() =
    print version

    var p = initOptParser(longNoVal = @["kharej", "iran", "multiport", "keep-ufw", "keep-iptables", "keep-os-limit", "accept-udp", "debug"])
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

                    of "accept-udp":
                        accept_udp = true
                        print accept_udp

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
                            multi_port_additions.add listen_port
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
                        echo "[Deprecated] option \'pool\' may not be set after v6.0, the calculation is done automatically."

                        # pool_size = parseInt(p.val).uint
                        # print pool_size

                    of "pool-age":
                        echo "[Deprecated] option \'pool-age\' may not be set after v6.0, the calculation is done automatically."

                        # pool_age = parseInt(p.val).uint
                        # print pool_age

                    of "mux-width":
                        echo "[Deprecated] option \'mux-width\' may not be set after v6.0, the calculation is done automatically."
                        # mux_width = parseInt(p.val).uint32
                        # print mux_width

                    of "parallel-cons":
                        upload_cons = parseInt(p.val).uint32
                        download_cons = parseInt(p.val).uint32
                        print upload_cons,download_cons
                            
                    of "connection-age":
                        connection_age = parseInt(p.val).uint32
                        print connection_age

                    of "noise":
                        noise_ratio = parseInt(p.val).uint32
                        print noise_ratio

                    of "trust_time":
                        trust_time = parseInt(p.val).uint
                        print trust_time

                    of "emax":
                        fast_encrypt_width = parseInt(p.val).uint
                        print fast_encrypt_width


                    of "listen":
                        listen_addr = (p.val)
                        print listen_addr

                    of "log":
                        case (p.val).parseInt:
                            of 0:
                                log_conn_create = false
                            of 1:
                                discard

                            of 2:
                                log_conn_error = true
                            of 3:
                                log_conn_error = true
                                log_conn_destory = true
                            of 4:
                                log_conn_error = true
                                log_conn_destory = true
                                log_data_len = true
                            else:
                                quit &"Incorrect value {p.val} for option \"log\" "

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
        of RunMode.unspecified:
            quit "specify the mode!. iran or kharej?  --iran or --kharej"



    if final_target_domain.isEmptyOrWhitespace():
        echo "specify the sni for routing --sni:{domain}"
        exit = true
    if password.isEmptyOrWhitespace():
        echo "specify the password  --password:{something}"
        exit = true


    if exit: quit("Application did not start due to above logs.")

    if terminate_secs != 0:
        sleepAsync(terminate_secs.secs).addCallback(
            proc(arg: pointer) =
            echo "Exiting due to termination timeout. (--terminate)"
            quit(0)
        )

    let rs_capacity = 4400 + (noise_ratio * 4400)
    random_str = newStringOfCap(rs_capacity); random_str.setLen(rs_capacity)
    for i in 0..<random_str.len():
        random_str[i] = rand(char.low .. char.high).char

    final_target_ip = resolveIPv4(final_target_domain)
    print "\n"

    try:
        self_ip = getPrimaryIPAddr(dest = parseIpAddress("8.8.8.8"))
    except:
        try:
            self_ip = getPrimaryIPAddr(dest = parseIpAddress("2001:4860:4860::8888"))
        except CatchableError as e:
            raise e

    password_hash = $(secureHash(password))
    sh1 = hash(password_hash).uint32
    sh2 = hash(sh1).uint32
    sh3 = hash(sh2).uint32
    sh4 = hash(sh3).uint32
    # sh5 = (3 + (hash(sh2).uint32 mod 5)).uint8
    sh5 = hash(sh4).uint8
    while sh5 <= 2.uint32 or sh5 >= 223.uint32:
        sh5 = hash(sh5).uint8


    print password, password_hash, sh1, sh2, sh3, download_cons,upload_cons,connection_age
    print "\n"
