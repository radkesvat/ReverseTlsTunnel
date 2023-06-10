import nativesockets,print


proc resolveIPv4*(address : string):string=
    let host =  getHostByName(address)
    
    print host

    return host.addrList[0]