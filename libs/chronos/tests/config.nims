switch("threads", "on")
# switch("hints", "off")
# switch("verbosity", "0")

# This is workaround for `mingw64-gcc-12.1.0` issue.
# https://github.com/nim-lang/Nim/pull/19197
# Should be removed when https://github.com/status-im/nim-chronos/issues/284
# will be implemented.
switch("define", "nimRawSetjmp")
