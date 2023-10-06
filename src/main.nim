
import chronos
import std/[random, exitprocs]
import system/ansi_c except SIGTERM
from globals import nil
import connection, iran_server, foreign_server

randomize()
globals.init()

#full reset iptables at exit (if the user allowed)
if globals.multi_port and globals.reset_iptable and globals.mode == globals.RunMode.iran:
    addExitProc do():
        globals.resetIptables()
    setControlCHook do(){.noconv.}:
        quit()
    c_signal(SIGTERM, proc(a: cint){.noconv.} =
        quit()
    )

#increase systam maximum fds to be able to handle more than 1024 cons (650000 for now)
when defined(linux) and not defined(android):
    import std/[posix, os, osproc]

    if not globals.keep_system_limit:
        if not isAdmin():
            echo "Please run as root. or start with --keep-os-limit "
            quit(-1)

        try:
            discard 0 == execShellCmd("sysctl -w fs.file-max=1000000")
            var limit = RLimit(rlim_cur: 650000, rlim_max: 660000)
            assert 0 == setrlimit(RLIMIT_NOFILE, limit)
        except: # try may not be able to catch above exception, anyways
            echo getCurrentExceptionMsg()
            echo "Could not increase system max connection (file descriptors) limit."
            echo "Please run as root. or start with --keep-os-limit "
            quit(-1)

    if globals.disable_ufw:
        if not isAdmin():
            echo "Disabling ufw requires root. !"
            echo "Please run as root. or start with --keep-ufw "
            quit(-1)
        discard 0 == execShellCmd("sudo ufw disable")



#idle connection removal controller and general timer
asyncSpawn startController()


if globals.mode == globals.RunMode.iran:
    asyncSpawn iran_server.start()
else:
    asyncSpawn foreign_server.start()


runForever()
