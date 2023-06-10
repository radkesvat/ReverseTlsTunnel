import dns_resolve, hashes, print, parseopt, strutils, random, net
import std/sha1

const socket_buffered* = false

const log_data_len* = false
const log_conn_create* = true
const log_conn_destory* = true

var trust_time*: uint = 3 #secs
var pool_size*: uint = 16 #secs

const chunk_size* = 4000

const mux*: bool = false

type RunMode*{.pure.} = enum
    dakhel, kharej


var mode*: RunMode = RunMode.dakhel
const listen_addr* = "0.0.0.0"
var listen_port* = -1
var next_route_addr* = ""
var next_route_port* = -1
var final_target_domain* = ""
var final_target_ip*: string
const final_target_port* = 443


var self_ip*: string



var password* = ""
var password_hash*: string
var sh1*: uint32
var sh2*: uint32
var sh3*: uint8

var random_600* = newString(len = 600)

proc init*() =

    for i in 0..<random_600.len():
        random_600[i] = rand(char.low .. char.high).char

    var p = initOptParser(longNoVal = @["server", "tunnel"])
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
                    of "dakhel":
                        mode = RunMode.dakhel
                        print mode
                    else:
                        echo "specify mode (--tunnel or --server)"
                        quit(-1)
            else:
                case p.key:
                    of "lport":
                        listen_port = parseInt(p.val)
                        print listen_port
                    of "toip":
                        next_route_addr = (p.val)
                        print next_route_addr
                    of "toport":
                        next_route_port = parseInt(p.val)
                        print next_route_port
                    of "sni":
                        final_target_domain = (p.val)
                        print final_target_domain
                    of "password":
                        password = (p.val)
                        print password
                    of "pool":
                        pool_size = parseInt(p.val).uint
                        print pool_size
                    of "trust_time":
                        trust_time = parseInt(p.val).uint
                        print trust_time


        of cmdArgument:
            echo "Argument: ", p.key

    var exit = false

    if listen_port == -1:
        echo "specify the listen prot --lport:{port}"
        exit = true

    if next_route_addr.isEmptyOrWhitespace():
        echo "specify the next ip for routing --toip:{ip}"
        exit = true
    if next_route_port == -1:
        echo "specify the port of the next ip for routing --toport:{port}"
        exit = true

    if next_route_addr.isEmptyOrWhitespace():
        echo "specify the sni for routing --sni:{domain}"
        exit = true
    if password.isEmptyOrWhitespace():
        echo "specify the password  --password:{something}"
        exit = true

    if exit: quit(-1)

    print "\n"
    final_target_ip = resolveIPv4(final_target_domain)
    print "\n"
    self_ip = $(getPrimaryIPAddr(dest = parseIpAddress("8.8.8.8")))
    password_hash = $(secureHash(password))
    sh1 = hash(password_hash).uint32
    sh2 = hash(sh1).uint32
    sh3 = (3 + (hash(sh2).uint32 mod 5)).uint8
    print password, password_hash, sh1, sh2, sh3, pool_size
    print "\n"
