
import std/[random,os,osproc,asyncdispatch]
from globals import nil
import tunnel,server,print


when defined(linux) and not defined(android):
    import std/posix
    if not isAdmin():
        echo "Please run as root."
        quit(-1)
    discard 0 == execShellCmd("sudo ufw disable")
    discard 0 == execShellCmd("sysctl -w fs.file-max=100000")
    var limit = RLimit(rlim_cur:65000,rlim_max:66000)
    assert 0 == setrlimit(RLIMIT_NOFILE,limit)

randomize()
globals.init()


if globals.mode == globals.RunMode.tunnel:
    asyncCheck tunnel.start()
else:
    asyncCheck server.start()

runForever()