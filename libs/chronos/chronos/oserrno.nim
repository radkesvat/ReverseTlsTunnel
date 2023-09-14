#
#             Chronos Posix OS error codes
#              (c) Copyright 2023-Present
#         Status Research & Development GmbH
#
#              Licensed under either of
#  Apache License, version 2.0, (LICENSE-APACHEv2)
#              MIT license (LICENSE-MIT)
from std/os import osLastError, osErrorMsg, OSErrorCode, raiseOSError,
                   newOSError, `==`
export osLastError, osErrorMsg, OSError, OSErrorCode, raiseOSError, newOSError,
       `==`

when defined(netbsd):
  ## Source: https://github.com/NetBSD/src/blob/trunk/sys/sys/errno.h
  const
    EPERM* = OSErrorCode(1)
      # Operation not permitted
    ENOENT* = OSErrorCode(2)
      # No such file or directory
    ESRCH* = OSErrorCode(3)
      # No such process
    EINTR* = OSErrorCode(4)
      # Interrupted system call
    EIO* = OSErrorCode(5)
      # Input/output error
    ENXIO* = OSErrorCode(6)
      # Device not configured
    E2BIG* = OSErrorCode(7)
      # Argument list too long
    ENOEXEC* = OSErrorCode(8)
      # Exec format error
    EBADF* = OSErrorCode(9)
      # Bad file descriptor
    ECHILD* = OSErrorCode(10)
      # No child processes
    EDEADLK* = OSErrorCode(11)
      # Resource deadlock avoided
    ENOMEM* = OSErrorCode(12)
      # Cannot allocate memory
    EACCES* = OSErrorCode(13)
      # Permission denied
    EFAULT* = OSErrorCode(14)
      # Bad address
    ENOTBLK* = OSErrorCode(15)
      # Block device required
    EBUSY* = OSErrorCode(16)
      # Device busy
    EEXIST* = OSErrorCode(17)
      # File exists
    EXDEV* = OSErrorCode(18)
      # Cross-device link
    ENODEV* = OSErrorCode(19)
      # Operation not supported by device
    ENOTDIR* = OSErrorCode(20)
      # Not a directory
    EISDIR* = OSErrorCode(21)
      # Is a directory
    EINVAL* = OSErrorCode(22)
      # Invalid argument
    ENFILE* = OSErrorCode(23)
      # Too many open files in system
    EMFILE* = OSErrorCode(24)
      # Too many open files
    ENOTTY* = OSErrorCode(25)
      # Inappropriate ioctl for device
    ETXTBSY* = OSErrorCode(26)
      # Text file busy
    EFBIG* = OSErrorCode(27)
      # File too large
    ENOSPC* = OSErrorCode(28)
      # No space left on device
    ESPIPE* = OSErrorCode(29)
      # Illegal seek
    EROFS* = OSErrorCode(30)
      # Read-only file system
    EMLINK* = OSErrorCode(31)
      # Too many links
    EPIPE* = OSErrorCode(32)
      # Broken pipe
    EDOM* = OSErrorCode(33)
      # Numerical argument out of domain
    ERANGE* = OSErrorCode(34)
      # Result too large or too small
    EAGAIN* = OSErrorCode(35)
      # Resource temporarily unavailable
    EWOULDBLOCK* = EAGAIN
      # Operation would block
    EINPROGRESS* = OSErrorCode(36)
      # Operation now in progress
    EALREADY* = OSErrorCode(37)
      # Operation already in progress
    ENOTSOCK* = OSErrorCode(38)
      # Socket operation on non-socket
    EDESTADDRREQ* = OSErrorCode(39)
      # Destination address required
    EMSGSIZE* = OSErrorCode(40)
      # Message too long
    EPROTOTYPE* = OSErrorCode(41)
      # Protocol wrong type for socket
    ENOPROTOOPT* = OSErrorCode(42)
      # Protocol option not available
    EPROTONOSUPPORT* = OSErrorCode(43)
      # Protocol not supported
    ESOCKTNOSUPPORT* = OSErrorCode(44)
      # Socket type not supported
    EOPNOTSUPP* = OSErrorCode(45)
      # Operation not supported
    EPFNOSUPPORT* = OSErrorCode(46)
      # Protocol family not supported
    EAFNOSUPPORT* = OSErrorCode(47)
      # Address family not supported by protocol family
    EADDRINUSE* = OSErrorCode(48)
      # Address already in use
    EADDRNOTAVAIL* = OSErrorCode(49)
      # Can't assign requested address
    ENETDOWN* = OSErrorCode(50)
      # Network is down
    ENETUNREACH* = OSErrorCode(51)
      # Network is unreachable
    ENETRESET* = OSErrorCode(52)
      # Network dropped connection on reset
    ECONNABORTED* = OSErrorCode(53)
      # Software caused connection abort
    ECONNRESET* = OSErrorCode(54)
      # Connection reset by peer
    ENOBUFS* = OSErrorCode(55)
      # No buffer space available
    EISCONN* = OSErrorCode(56)
      # Socket is already connected
    ENOTCONN* = OSErrorCode(57)
      # Socket is not connected
    ESHUTDOWN* = OSErrorCode(58)
      # Can't send after socket shutdown
    ETOOMANYREFS* = OSErrorCode(59)
      # Too many references: can't splice
    ETIMEDOUT* = OSErrorCode(60)
      # Operation timed out
    ECONNREFUSED* = OSErrorCode(61)
      # Connection refused
    ELOOP* = OSErrorCode(62)
      # Too many levels of symbolic links
    ENAMETOOLONG* = OSErrorCode(63)
      # File name too long
    EHOSTDOWN* = OSErrorCode(64)
      # Host is down
    EHOSTUNREACH* = OSErrorCode(65)
      # No route to host
    ENOTEMPTY* = OSErrorCode(66)
      # Directory not empty
    EPROCLIM* = OSErrorCode(67)
      # Too many processes
    EUSERS* = OSErrorCode(68)
      # Too many users
    EDQUOT* = OSErrorCode(69)
      # Disc quota exceeded
    ESTALE* = OSErrorCode(70)
      # Stale NFS file handle
    EREMOTE* = OSErrorCode(71)
      # Too many levels of remote in path
    EBADRPC* = OSErrorCode(72)
      # RPC struct is bad
    ERPCMISMATCH* = OSErrorCode(73)
      # RPC version wrong
    EPROGUNAVAIL* = OSErrorCode(74)
      # RPC prog. not avail
    EPROGMISMATCH* = OSErrorCode(75)
      # Program version wrong
    EPROCUNAVAIL* = OSErrorCode(76)
      # Bad procedure for program
    ENOLCK* = OSErrorCode(77)
      # No locks available
    ENOSYS* = OSErrorCode(78)
      # Function not implemented
    EFTYPE* = OSErrorCode(79)
      # Inappropriate file type or format
    EAUTH* = OSErrorCode(80)
      # Authentication error
    ENEEDAUTH* = OSErrorCode(81)
      # Need authenticator
    EIDRM* = OSErrorCode(82)
      # Identifier removed
    ENOMSG* = OSErrorCode(83)
      # No message of desired type
    EOVERFLOW* = OSErrorCode(84)
      # Value too large to be stored in data type
    EILSEQ* = OSErrorCode(85)
      # Illegal byte sequence
    ENOTSUP* = OSErrorCode(86)
      # Not supported
    ECANCELED* = OSErrorCode(87)
      # Operation canceled
    EBADMSG* = OSErrorCode(88)
      # Bad or Corrupt message
    ENODATA* = OSErrorCode(89)
      # No message available
    ENOSR* = OSErrorCode(90)
      # No STREAM resources
    ENOSTR* = OSErrorCode(91)
      # Not a STREAM
    ETIME* = OSErrorCode(92)
      # STREAM ioctl timeout
    ENOATTR* = OSErrorCode(93)
      # Attribute not found
    EMULTIHOP* = OSErrorCode(94)
      # Multihop attempted
    ENOLINK* = OSErrorCode(95)
      # Link has been severed
    EPROTO* = OSErrorCode(96)
      # Protocol error
    EOWNERDEAD* = OSErrorCode(97)
      # Previous owner died
    ENOTRECOVERABLE* = OSErrorCode(98)
      # State not recoverable
    ELAST* = OSErrorCode(98)
      # Must equal largest errno

elif defined(openbsd):
  ## Source: https://github.com/openbsd/src/blob/master/sys/sys/errno.h
  const
    EPERM* = OSErrorCode(1)
      # Operation not permitted
    ENOENT* = OSErrorCode(2)
      # No such file or directory
    ESRCH* = OSErrorCode(3)
      # No such process
    EINTR* = OSErrorCode(4)
      # Interrupted system call
    EIO* = OSErrorCode(5)
      # Input/output error
    ENXIO* = OSErrorCode(6)
      # Device not configured
    E2BIG* = OSErrorCode(7)
      # Argument list too long
    ENOEXEC* = OSErrorCode(8)
      # Exec format error
    EBADF* = OSErrorCode(9)
      # Bad file descriptor
    ECHILD* = OSErrorCode(10)
      # No child processes
    EDEADLK* = OSErrorCode(11)
      # Resource deadlock avoided
    ENOMEM* = OSErrorCode(12)
      # Cannot allocate memory
    EACCES* = OSErrorCode(13)
      # Permission denied
    EFAULT* = OSErrorCode(14)
      # Bad address
    ENOTBLK* = OSErrorCode(15)
      # Block device required
    EBUSY* = OSErrorCode(16)
      # Device busy
    EEXIST* = OSErrorCode(17)
      # File exists
    EXDEV* = OSErrorCode(18)
      # Cross-device link
    ENODEV* = OSErrorCode(19)
      # Operation not supported by device
    ENOTDIR* = OSErrorCode(20)
      # Not a directory
    EISDIR* = OSErrorCode(21)
      # Is a directory
    EINVAL* = OSErrorCode(22)
      # Invalid argument
    ENFILE* = OSErrorCode(23)
      # Too many open files in system
    EMFILE* = OSErrorCode(24)
      # Too many open files
    ENOTTY* = OSErrorCode(25)
      # Inappropriate ioctl for device
    ETXTBSY* = OSErrorCode(26)
      # Text file busy
    EFBIG* = OSErrorCode(27)
      # File too large
    ENOSPC* = OSErrorCode(28)
      # No space left on device
    ESPIPE* = OSErrorCode(29)
      # Illegal seek
    EROFS* = OSErrorCode(30)
      # Read-only file system
    EMLINK* = OSErrorCode(31)
      # Too many links
    EPIPE* = OSErrorCode(32)
      # Broken pipe
    EDOM* = OSErrorCode(33)
      # Numerical argument out of domain
    ERANGE* = OSErrorCode(34)
      # Result too large
    EAGAIN* = OSErrorCode(35)
      # Resource temporarily unavailable
    EWOULDBLOCK* = EAGAIN
      # Operation would block
    EINPROGRESS* = OSErrorCode(36)
      # Operation now in progress
    EALREADY* = OSErrorCode(37)
      # Operation already in progress
    ENOTSOCK* = OSErrorCode(38)
      # Socket operation on non-socket
    EDESTADDRREQ* = OSErrorCode(39)
      # Destination address required
    EMSGSIZE* = OSErrorCode(40)
      # Message too long
    EPROTOTYPE* = OSErrorCode(41)
      # Protocol wrong type for socket
    ENOPROTOOPT* = OSErrorCode(42)
      # Protocol not available
    EPROTONOSUPPORT* = OSErrorCode(43)
      # Protocol not supported
    ESOCKTNOSUPPORT* = OSErrorCode(44)
      # Socket type not supported
    EOPNOTSUPP* = OSErrorCode(45)
      # Operation not supported
    EPFNOSUPPORT* = OSErrorCode(46)
      # Protocol family not supported
    EAFNOSUPPORT* = OSErrorCode(47)
      # Address family not supported by protocol family
    EADDRINUSE* = OSErrorCode(48)
      # Address already in use
    EADDRNOTAVAIL* = OSErrorCode(49)
      # Can't assign requested address
    ENETDOWN* = OSErrorCode(50)
      # Network is down
    ENETUNREACH* = OSErrorCode(51)
      # Network is unreachable
    ENETRESET* = OSErrorCode(52)
      # Network dropped connection on reset
    ECONNABORTED* = OSErrorCode(53)
      # Software caused connection abort
    ECONNRESET* = OSErrorCode(54)
      # Connection reset by peer
    ENOBUFS* = OSErrorCode(55)
      # No buffer space available
    EISCONN* = OSErrorCode(56)
      # Socket is already connected
    ENOTCONN* = OSErrorCode(57)
      # Socket is not connected
    ESHUTDOWN* = OSErrorCode(58)
      # Can't send after socket shutdown
    ETOOMANYREFS* = OSErrorCode(59)
      # Too many references: can't splice
    ETIMEDOUT* = OSErrorCode(60)
      # Operation timed out
    ECONNREFUSED* = OSErrorCode(61)
      # Connection refused
    ELOOP* = OSErrorCode(62)
      # Too many levels of symbolic links
    ENAMETOOLONG* = OSErrorCode(63)
      # File name too long
    EHOSTDOWN* = OSErrorCode(64)
      # Host is down
    EHOSTUNREACH* = OSErrorCode(65)
      # No route to host
    ENOTEMPTY* = OSErrorCode(66)
      # Directory not empty
    EPROCLIM* = OSErrorCode(67)
      # Too many processes
    EUSERS* = OSErrorCode(68)
      # Too many users
    EDQUOT* = OSErrorCode(69)
      # Disk quota exceeded
    ESTALE* = OSErrorCode(70)
      # Stale NFS file handle
    EREMOTE* = OSErrorCode(71)
      # Too many levels of remote in path
    EBADRPC* = OSErrorCode(72)
      # RPC struct is bad
    ERPCMISMATCH* = OSErrorCode(73)
      # RPC version wrong
    EPROGUNAVAIL* = OSErrorCode(74)
      # RPC program not available
    EPROGMISMATCH* = OSErrorCode(75)
      # Program version wrong
    EPROCUNAVAIL* = OSErrorCode(76)
      # Bad procedure for program
    ENOLCK* = OSErrorCode(77)
      # No locks available
    ENOSYS* = OSErrorCode(78)
      # Function not implemented
    EFTYPE* = OSErrorCode(79)
      # Inappropriate file type or format
    EAUTH* = OSErrorCode(80)
      # Authentication error
    ENEEDAUTH* = OSErrorCode(81)
      # Need authenticator
    EIPSEC* = OSErrorCode(82)
      # IPsec processing failure
    ENOATTR* = OSErrorCode(83)
      # Attribute not found
    EILSEQ* = OSErrorCode(84)
      # Illegal byte sequence
    ENOMEDIUM* = OSErrorCode(85)
      # No medium found
    EMEDIUMTYPE* = OSErrorCode(86)
      # Wrong medium type
    EOVERFLOW* = OSErrorCode(87)
      # Value too large to be stored in data type
    ECANCELED* = OSErrorCode(88)
      # Operation canceled
    EIDRM* = OSErrorCode(89)
      # Identifier removed
    ENOMSG* = OSErrorCode(90)
      # No message of desired type
    ENOTSUP* = OSErrorCode(91)
      # Not supported
    EBADMSG* = OSErrorCode(92)
      # Bad message
    ENOTRECOVERABLE* = OSErrorCode(93)
      # State not recoverable
    EOWNERDEAD* = OSErrorCode(94)
      # Previous owner died
    EPROTO* = OSErrorCode(95)
      # Protocol error
    ELAST* = OSErrorCode(95)
      # Must be equal largest errno

elif defined(freebsd):
  ## Source: https://github.com/freebsd/freebsd-src/blob/main/sys/sys/errno.h
  const
    EPERM* = OSErrorCode(1)
      # Operation not permitted
    ENOENT* = OSErrorCode(2)
      # No such file or directory
    ESRCH* = OSErrorCode(3)
      # No such process
    EINTR* = OSErrorCode(4)
      # Interrupted system call
    EIO* = OSErrorCode(5)
      # Input/output error
    ENXIO* = OSErrorCode(6)
      # Device not configured
    E2BIG* = OSErrorCode(7)
      # Argument list too long
    ENOEXEC* = OSErrorCode(8)
      # Exec format error
    EBADF* = OSErrorCode(9)
      # Bad file descriptor
    ECHILD* = OSErrorCode(10)
      # No child processes
    EDEADLK* = OSErrorCode(11)
      # Resource deadlock avoided
    ENOMEM* = OSErrorCode(12)
      # Cannot allocate memory
    EACCES* = OSErrorCode(13)
      # Permission denied
    EFAULT* = OSErrorCode(14)
      # Bad address
    ENOTBLK* = OSErrorCode(15)
      # Block device required
    EBUSY* = OSErrorCode(16)
      # Device busy
    EEXIST* = OSErrorCode(17)
      # File exists
    EXDEV* = OSErrorCode(18)
      # Cross-device link
    ENODEV* = OSErrorCode(19)
      # Operation not supported by device
    ENOTDIR* = OSErrorCode(20)
      # Not a directory
    EISDIR* = OSErrorCode(21)
      # Is a directory
    EINVAL* = OSErrorCode(22)
      # Invalid argument
    ENFILE* = OSErrorCode(23)
      # Too many open files in system
    EMFILE* = OSErrorCode(24)
      # Too many open files
    ENOTTY* = OSErrorCode(25)
      # Inappropriate ioctl for device
    ETXTBSY* = OSErrorCode(26)
      # Text file busy
    EFBIG* = OSErrorCode(27)
      # File too large
    ENOSPC* = OSErrorCode(28)
      # No space left on device
    ESPIPE* = OSErrorCode(29)
      # Illegal seek
    EROFS* = OSErrorCode(30)
      # Read-only filesystem
    EMLINK* = OSErrorCode(31)
      # Too many links
    EPIPE* = OSErrorCode(32)
      # Broken pipe
    EDOM* = OSErrorCode(33)
      # Numerical argument out of domain
    ERANGE* = OSErrorCode(34)
      # Result too large
    EAGAIN* = OSErrorCode(35)
      # Resource temporarily unavailable
    EWOULDBLOCK* = EAGAIN
      # Operation would block
    EINPROGRESS* = OSErrorCode(36)
      # Operation now in progress
    EALREADY* = OSErrorCode(37)
      # Operation already in progress
    ENOTSOCK* = OSErrorCode(38)
      # Socket operation on non-socket
    EDESTADDRREQ* = OSErrorCode(39)
      # Destination address required
    EMSGSIZE* = OSErrorCode(40)
      # Message too long
    EPROTOTYPE* = OSErrorCode(41)
      # Protocol wrong type for socket
    ENOPROTOOPT* = OSErrorCode(42)
      # Protocol not available
    EPROTONOSUPPORT* = OSErrorCode(43)
      # Protocol not supported
    ESOCKTNOSUPPORT* = OSErrorCode(44)
      # Socket type not supported
    EOPNOTSUPP* = OSErrorCode(45)
      # Operation not supported
    ENOTSUP* = EOPNOTSUPP
      # Operation not supported
    EPFNOSUPPORT* = OSErrorCode(46)
      # Protocol family not supported
    EAFNOSUPPORT* = OSErrorCode(47)
      # Address family not supported by protocol family
    EADDRINUSE* = OSErrorCode(48)
      # Address already in use
    EADDRNOTAVAIL* = OSErrorCode(49)
      # Can't assign requested address
    ENETDOWN* = OSErrorCode(50)
      # Network is down
    ENETUNREACH* = OSErrorCode(51)
      # Network is unreachable
    ENETRESET* = OSErrorCode(52)
      # Network dropped connection on reset
    ECONNABORTED* = OSErrorCode(53)
      # Software caused connection abort
    ECONNRESET* = OSErrorCode(54)
      # Connection reset by peer
    ENOBUFS* = OSErrorCode(55)
      # No buffer space available
    EISCONN* = OSErrorCode(56)
      # Socket is already connected
    ENOTCONN* = OSErrorCode(57)
      # Socket is not connected
    ESHUTDOWN* = OSErrorCode(58)
      # Can't send after socket shutdown
    ETOOMANYREFS* = OSErrorCode(59)
      # Too many references: can't splice
    ETIMEDOUT* = OSErrorCode(60)
      # Operation timed out
    ECONNREFUSED* = OSErrorCode(61)
      # Connection refused
    ELOOP* = OSErrorCode(62)
      # Too many levels of symbolic links
    ENAMETOOLONG* = OSErrorCode(63)
      # File name too long
    EHOSTDOWN* = OSErrorCode(64)
      # Host is down
    EHOSTUNREACH* = OSErrorCode(65)
      # No route to host
    ENOTEMPTY* = OSErrorCode(66)
      # Directory not empty
    EPROCLIM* = OSErrorCode(67)
      # Too many processes
    EUSERS* = OSErrorCode(68)
      # Too many users
    EDQUOT* = OSErrorCode(69)
      # Disc quota exceeded
    ESTALE* = OSErrorCode(70)
      # Stale NFS file handle
    EREMOTE* = OSErrorCode(71)
      # Too many levels of remote in path
    EBADRPC* = OSErrorCode(72)
      # RPC struct is bad
    ERPCMISMATCH* = OSErrorCode(73)
      # RPC version wrong
    EPROGUNAVAIL* = OSErrorCode(74)
      # RPC prog. not avail
    EPROGMISMATCH* = OSErrorCode(75)
      # Program version wrong
    EPROCUNAVAIL* = OSErrorCode(76)
      # Bad procedure for program
    ENOLCK* = OSErrorCode(77)
      # No locks available
    ENOSYS* = OSErrorCode(78)
      # Function not implemented
    EFTYPE* = OSErrorCode(79)
      # Inappropriate file type or format
    EAUTH* = OSErrorCode(80)
      # Authentication error
    ENEEDAUTH* = OSErrorCode(81)
      # Need authenticator
    EIDRM* = OSErrorCode(82)
      # Identifier removed
    ENOMSG* = OSErrorCode(83)
      # No message of desired type
    EOVERFLOW* = OSErrorCode(84)
      # Value too large to be stored in data type
    ECANCELED* = OSErrorCode(85)
      # Operation canceled
    EILSEQ* = OSErrorCode(86)
      # Illegal byte sequence
    ENOATTR* = OSErrorCode(87)
      # Attribute not found
    EDOOFUS* = OSErrorCode(88)
      # Programming error
    EBADMSG* = OSErrorCode(89)
      # Bad message
    EMULTIHOP* = OSErrorCode(90)
      # Multihop attempted
    ENOLINK* = OSErrorCode(91)
      # Link has been severed
    EPROTO* = OSErrorCode(92)
      # Protocol error
    ENOTCAPABLE* = OSErrorCode(93)
      # Capabilities insufficient
    ECAPMODE* = OSErrorCode(94)
      # Not permitted in capability mode
    ENOTRECOVERABLE* = OSErrorCode(95)
      # State not recoverable
    EOWNERDEAD* = OSErrorCode(96)
      # Previous owner died
    EINTEGRITY* = OSErrorCode(97)
      # Integrity check failed
    ELAST* = OSErrorCode(97)
      # Must be equal largest errno

elif defined(dragonfly) or defined(dragonflybsd):
  ## Source: https://github.com/DragonFlyBSD/DragonFlyBSD/blob/master/sys/sys/errno.h
  const
    EPERM* = OSErrorCode(1)
      # Operation not permitted
    ENOENT* = OSErrorCode(2)
      # No such file or directory
    ESRCH* = OSErrorCode(3)
      # No such process
    EINTR* = OSErrorCode(4)
      # Interrupted system call
    EIO* = OSErrorCode(5)
      # Input/output error
    ENXIO* = OSErrorCode(6)
      # Device not configured
    E2BIG* = OSErrorCode(7)
      # Argument list too long
    ENOEXEC* = OSErrorCode(8)
      # Exec format error
    EBADF* = OSErrorCode(9)
      # Bad file descriptor
    ECHILD* = OSErrorCode(10)
      # No child processes
    EDEADLK* = OSErrorCode(11)
      # Resource deadlock avoided
    ENOMEM* = OSErrorCode(12)
      # Cannot allocate memory
    EACCES* = OSErrorCode(13)
      # Permission denied
    EFAULT* = OSErrorCode(14)
      # Bad address
    ENOTBLK* = OSErrorCode(15)
      # Block device required
    EBUSY* = OSErrorCode(16)
      # Device busy
    EEXIST* = OSErrorCode(17)
      # File exists
    EXDEV* = OSErrorCode(18)
      # Cross-device link
    ENODEV* = OSErrorCode(19)
      # Operation not supported by device
    ENOTDIR* = OSErrorCode(20)
      # Not a directory
    EISDIR* = OSErrorCode(21)
      # Is a directory
    EINVAL* = OSErrorCode(22)
      # Invalid argument
    ENFILE* = OSErrorCode(23)
      # Too many open files in system
    EMFILE* = OSErrorCode(24)
      # Too many open files
    ENOTTY* = OSErrorCode(25)
      # Inappropriate ioctl for device
    ETXTBSY* = OSErrorCode(26)
      # Text file busy
    EFBIG* = OSErrorCode(27)
      # File too large
    ENOSPC* = OSErrorCode(28)
      # No space left on device
    ESPIPE* = OSErrorCode(29)
      # Illegal seek
    EROFS* = OSErrorCode(30)
      # Read-only filesystem
    EMLINK* = OSErrorCode(31)
      # Too many links
    EPIPE* = OSErrorCode(32)
      # Broken pipe
    EDOM* = OSErrorCode(33)
      # Numerical argument out of domain
    ERANGE* = OSErrorCode(34)
      # Result too large
    EAGAIN* = OSErrorCode(35)
      # Resource temporarily unavailable
    EWOULDBLOCK* = EAGAIN
      # Operation would block
    EINPROGRESS* = OSErrorCode(36)
      # Operation now in progress
    EALREADY* = OSErrorCode(37)
      # Operation already in progress
    ENOTSOCK* = OSErrorCode(38)
      # Socket operation on non-socket
    EDESTADDRREQ* = OSErrorCode(39)
      # Destination address required
    EMSGSIZE* = OSErrorCode(40)
      # Message too long
    EPROTOTYPE* = OSErrorCode(41)
      # Protocol wrong type for socket
    ENOPROTOOPT* = OSErrorCode(42)
      # Protocol not available
    EPROTONOSUPPORT* = OSErrorCode(43)
      # Protocol not supported
    ESOCKTNOSUPPORT* = OSErrorCode(44)
      # Socket type not supported
    EOPNOTSUPP* = OSErrorCode(45)
      # Operation not supported
    ENOTSUP* = EOPNOTSUPP
      # Operation not supported
    EPFNOSUPPORT* = OSErrorCode(46)
      # Protocol family not supported
    EAFNOSUPPORT* = OSErrorCode(47)
      # Address family not supported by protocol family
    EADDRINUSE* = OSErrorCode(48)
      # Address already in use
    EADDRNOTAVAIL* = OSErrorCode(49)
      # Can't assign requested address
    ENETDOWN* = OSErrorCode(50)
      # Network is down
    ENETUNREACH* = OSErrorCode(51)
      # Network is unreachable
    ENETRESET* = OSErrorCode(52)
      # Network dropped connection on reset
    ECONNABORTED* = OSErrorCode(53)
      # Software caused connection abort
    ECONNRESET* = OSErrorCode(54)
      # Connection reset by peer
    ENOBUFS* = OSErrorCode(55)
      # No buffer space available
    EISCONN* = OSErrorCode(56)
      # Socket is already connected
    ENOTCONN* = OSErrorCode(57)
      # Socket is not connected
    ESHUTDOWN* = OSErrorCode(58)
      # Can't send after socket shutdown
    ETOOMANYREFS* = OSErrorCode(59)
      # Too many references: can't splice
    ETIMEDOUT* = OSErrorCode(60)
      # Operation timed out
    ECONNREFUSED* = OSErrorCode(61)
      # Connection refused
    ELOOP* = OSErrorCode(62)
      # Too many levels of symbolic links
    ENAMETOOLONG* = OSErrorCode(63)
      # File name too long
    EHOSTDOWN* = OSErrorCode(64)
      # Host is down
    EHOSTUNREACH* = OSErrorCode(65)
      # No route to host
    ENOTEMPTY* = OSErrorCode(66)
      # Directory not empty
    EPROCLIM* = OSErrorCode(67)
      # Too many processes
    EUSERS* = OSErrorCode(68)
      # Too many users
    EDQUOT* = OSErrorCode(69)
      # Disc quota exceeded
    ESTALE* = OSErrorCode(70)
      # Stale NFS file handle
    EREMOTE* = OSErrorCode(71)
      # Too many levels of remote in path
    EBADRPC* = OSErrorCode(72)
      # RPC struct is bad
    ERPCMISMATCH* = OSErrorCode(73)
      # RPC version wrong
    EPROGUNAVAIL* = OSErrorCode(74)
      # RPC prog. not avail
    EPROGMISMATCH* = OSErrorCode(75)
      # Program version wrong
    EPROCUNAVAIL* = OSErrorCode(76)
      # Bad procedure for program
    ENOLCK* = OSErrorCode(77)
      # No locks available
    ENOSYS* = OSErrorCode(78)
      # Function not implemented
    EFTYPE* = OSErrorCode(79)
      # Inappropriate file type or format
    EAUTH* = OSErrorCode(80)
      # Authentication error
    ENEEDAUTH* = OSErrorCode(81)
      # Need authenticator
    EIDRM* = OSErrorCode(82)
      # Identifier removed
    ENOMSG* = OSErrorCode(83)
      # No message of desired type
    EOVERFLOW* = OSErrorCode(84)
      # Value too large to be stored in data type
    ECANCELED* = OSErrorCode(85)
      # Operation canceled
    EILSEQ* = OSErrorCode(86)
      # Illegal byte sequence
    ENOATTR* = OSErrorCode(87)
      # Attribute not found
    EDOOFUS* = OSErrorCode(88)
      # Programming error
    EBADMSG* = OSErrorCode(89)
      # Bad message
    EMULTIHOP* = OSErrorCode(90)
      # Multihop attempted
    ENOLINK* = OSErrorCode(91)
      # Link has been severed
    EPROTO* = OSErrorCode(92)
      # Protocol error
    ENOMEDIUM* = OSErrorCode(93)
      # linux
    ENOTRECOVERABLE* = OSErrorCode(94)
      # State not recoverable
    EOWNERDEAD* = OSErrorCode(95)
      # Previous owner died
    EASYNC* = OSErrorCode(99)
      # XXX
    ELAST* = OSErrorCode(99)
      # Must be equal largest errno

elif defined(macos) or defined(macosx):
  ## Source: https://github.com/apple/darwin-xnu/blob/main/bsd/sys/errno.h
  const
    EPERM* = OSErrorCode(1)
      # Operation not permitted
    ENOENT* = OSErrorCode(2)
      # No such file or directory
    ESRCH* = OSErrorCode(3)
      # No such process
    EINTR* = OSErrorCode(4)
      # Interrupted system call
    EIO* = OSErrorCode(5)
      # Input/output error
    ENXIO* = OSErrorCode(6)
      # Device not configured
    E2BIG* = OSErrorCode(7)
      # Argument list too long
    ENOEXEC* = OSErrorCode(8)
      # Exec format error
    EBADF* = OSErrorCode(9)
      # Bad file descriptor
    ECHILD* = OSErrorCode(10)
      # No child processes
    EDEADLK* = OSErrorCode(11)
      # Resource deadlock avoided
    ENOMEM* = OSErrorCode(12)
      # Cannot allocate memory
    EACCES* = OSErrorCode(13)
      # Permission denied
    EFAULT* = OSErrorCode(14)
      # Bad address
    ENOTBLK* = OSErrorCode(15)
      # Block device required
    EBUSY* = OSErrorCode(16)
      # Device / Resource busy
    EEXIST* = OSErrorCode(17)
      # File exists
    EXDEV* = OSErrorCode(18)
      # Cross-device link
    ENODEV* = OSErrorCode(19)
      # Operation not supported by device
    ENOTDIR* = OSErrorCode(20)
      # Not a directory
    EISDIR* = OSErrorCode(21)
      # Is a directory
    EINVAL* = OSErrorCode(22)
      # Invalid argument
    ENFILE* = OSErrorCode(23)
      # Too many open files in system
    EMFILE* = OSErrorCode(24)
      # Too many open files
    ENOTTY* = OSErrorCode(25)
      # Inappropriate ioctl for device
    ETXTBSY* = OSErrorCode(26)
      # Text file busy
    EFBIG* = OSErrorCode(27)
      # File too large
    ENOSPC* = OSErrorCode(28)
      # No space left on device
    ESPIPE* = OSErrorCode(29)
      # Illegal seek
    EROFS* = OSErrorCode(30)
      # Read-only file system
    EMLINK* = OSErrorCode(31)
      # Too many links
    EPIPE* = OSErrorCode(32)
      # Broken pipe
    EDOM* = OSErrorCode(33)
      # Numerical argument out of domain
    ERANGE* = OSErrorCode(34)
      # Result too large
    EAGAIN* = OSErrorCode(35)
      # Resource temporarily unavailable
    EWOULDBLOCK* = EAGAIN
      # Operation would block
    EINPROGRESS* = OSErrorCode(36)
      # Operation now in progress
    EALREADY* = OSErrorCode(37)
      # Operation already in progress
    ENOTSOCK* = OSErrorCode(38)
      # Socket operation on non-socket
    EDESTADDRREQ* = OSErrorCode(39)
      # Destination address required
    EMSGSIZE* = OSErrorCode(40)
      # Message too long
    EPROTOTYPE* = OSErrorCode(41)
      # Protocol wrong type for socket
    ENOPROTOOPT* = OSErrorCode(42)
      # Protocol not available
    EPROTONOSUPPORT* = OSErrorCode(43)
      # Protocol not supported
    ESOCKTNOSUPPORT* = OSErrorCode(44)
      # Socket type not supported
    ENOTSUP* = OSErrorCode(45)
      # Operation not supported
    EPFNOSUPPORT* = OSErrorCode(46)
      # Protocol family not supported
    EAFNOSUPPORT* = OSErrorCode(47)
      # Address family not supported by protocol family
    EADDRINUSE* = OSErrorCode(48)
      # Address already in use
    EADDRNOTAVAIL* = OSErrorCode(49)
      # Can't assign requested address
    ENETDOWN* = OSErrorCode(50)
      # Network is down
    ENETUNREACH* = OSErrorCode(51)
      # Network is unreachable
    ENETRESET* = OSErrorCode(52)
      # Network dropped connection on reset
    ECONNABORTED* = OSErrorCode(53)
      # Software caused connection abort
    ECONNRESET* = OSErrorCode(54)
      # Connection reset by peer
    ENOBUFS* = OSErrorCode(55)
      # No buffer space available
    EISCONN* = OSErrorCode(56)
      # Socket is already connected
    ENOTCONN* = OSErrorCode(57)
      # Socket is not connected
    ESHUTDOWN* = OSErrorCode(58)
      # Can't send after socket shutdown
    ETOOMANYREFS* = OSErrorCode(59)
      # Too many references: can't splice
    ETIMEDOUT* = OSErrorCode(60)
      # Operation timed out
    ECONNREFUSED* = OSErrorCode(61)
      # Connection refused
    ELOOP* = OSErrorCode(62)
      # Too many levels of symbolic links
    ENAMETOOLONG* = OSErrorCode(63)
      # File name too long
    EHOSTDOWN* = OSErrorCode(64)
      # Host is down
    EHOSTUNREACH* = OSErrorCode(65)
      # No route to host
    ENOTEMPTY* = OSErrorCode(66)
      # Directory not empty
    EPROCLIM* = OSErrorCode(67)
      # Too many processes
    EUSERS* = OSErrorCode(68)
      # Too many users
    EDQUOT* = OSErrorCode(69)
      # Disc quota exceeded
    ESTALE* = OSErrorCode(70)
      # Stale NFS file handle
    EREMOTE* = OSErrorCode(71)
      # Too many levels of remote in path
    EBADRPC* = OSErrorCode(72)
      # RPC struct is bad
    ERPCMISMATCH* = OSErrorCode(73)
      # RPC version wrong
    EPROGUNAVAIL* = OSErrorCode(74)
      # RPC prog. not avail
    EPROGMISMATCH* = OSErrorCode(75)
      # Program version wrong
    EPROCUNAVAIL* = OSErrorCode(76)
      # Bad procedure for program
    ENOLCK* = OSErrorCode(77)
      # No locks available
    ENOSYS* = OSErrorCode(78)
      # Function not implemented
    EFTYPE* = OSErrorCode(79)
      # Inappropriate file type or format
    EAUTH* = OSErrorCode(80)
      # Authentication error
    ENEEDAUTH* = OSErrorCode(81)
      # Need authenticator
    EPWROFF* = OSErrorCode(82)
      # Device power is off
    EDEVERR* = OSErrorCode(83)
      # Device error, e.g. paper out
    EOVERFLOW* = OSErrorCode(84)
      # Value too large to be stored in data type
    EBADEXEC* = OSErrorCode(85)
      # Bad executable
    EBADARCH* = OSErrorCode(86)
      # Bad CPU type in executable
    ESHLIBVERS* = OSErrorCode(87)
      # Shared library version mismatch
    EBADMACHO* = OSErrorCode(88)
      # Malformed Macho file
    ECANCELED* = OSErrorCode(89)
      # Operation canceled
    EIDRM* = OSErrorCode(90)
      # Identifier removed
    ENOMSG* = OSErrorCode(91)
      # No message of desired type
    EILSEQ* = OSErrorCode(92)
      # Illegal byte sequence
    ENOATTR* = OSErrorCode(93)
      # Attribute not found
    EBADMSG* = OSErrorCode(94)
      # Bad message
    EMULTIHOP* = OSErrorCode(95)
      # Reserved
    ENODATA* = OSErrorCode(96)
      # No message available on STREAM
    ENOLINK* = OSErrorCode(97)
      # Reserved
    ENOSR* = OSErrorCode(98)
      # No STREAM resources
    ENOSTR* = OSErrorCode(99)
      # Not a STREAM
    EPROTO* = OSErrorCode(100)
      # Protocol error
    ETIME* = OSErrorCode(101)
      # STREAM ioctl timeout
    EOPNOTSUPP* = OSErrorCode(102)
      # Operation not supported on socket
    ENOPOLICY* = OSErrorCode(103)
      # No such policy registered
    ENOTRECOVERABLE* = OSErrorCode(104)
      # State not recoverable
    EOWNERDEAD* = OSErrorCode(105)
      # Previous owner died
    EQFULL* = OSErrorCode(106)
      # Interface output queue is full
    ELAST* = OSErrorCode(106)
      # Must be equal largest errno

elif defined(linux):
  ## Source: https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/errno-base.h
  ##         https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/errno.h
  const
    EPERM* = OSErrorCode(1)
      # Operation not permitted
    ENOENT* = OSErrorCode(2)
      # No such file or directory
    ESRCH* = OSErrorCode(3)
      # No such process
    EINTR* = OSErrorCode(4)
      # Interrupted system call
    EIO* = OSErrorCode(5)
      # I/O error
    ENXIO* = OSErrorCode(6)
      # No such device or address
    E2BIG* = OSErrorCode(7)
      # Argument list too long
    ENOEXEC* = OSErrorCode(8)
      # Exec format error
    EBADF* = OSErrorCode(9)
      # Bad file number
    ECHILD* = OSErrorCode(10)
      # No child processes
    EAGAIN* = OSErrorCode(11)
      # Try again
    ENOMEM* = OSErrorCode(12)
      # Out of memory
    EACCES* = OSErrorCode(13)
      # Permission denied
    EFAULT* = OSErrorCode(14)
      # Bad address
    ENOTBLK* = OSErrorCode(15)
      # Block device required
    EBUSY* = OSErrorCode(16)
      # Device or resource busy
    EEXIST* = OSErrorCode(17)
      # File exists
    EXDEV* = OSErrorCode(18)
      # Cross-device link
    ENODEV* = OSErrorCode(19)
      # No such device
    ENOTDIR* = OSErrorCode(20)
      # Not a directory
    EISDIR* = OSErrorCode(21)
      # Is a directory
    EINVAL* = OSErrorCode(22)
      # Invalid argument
    ENFILE* = OSErrorCode(23)
      # File table overflow
    EMFILE* = OSErrorCode(24)
      # Too many open files
    ENOTTY* = OSErrorCode(25)
      # Not a typewriter
    ETXTBSY* = OSErrorCode(26)
      # Text file busy
    EFBIG* = OSErrorCode(27)
      # File too large
    ENOSPC* = OSErrorCode(28)
      # No space left on device
    ESPIPE* = OSErrorCode(29)
      # Illegal seek
    EROFS* = OSErrorCode(30)
      # Read-only file system
    EMLINK* = OSErrorCode(31)
      # Too many links
    EPIPE* = OSErrorCode(32)
      # Broken pipe
    EDOM* = OSErrorCode(33)
      # Math argument out of domain of func
    ERANGE* = OSErrorCode(34)
      # Math result not representable
    EDEADLK* = OSErrorCode(35)
      # Resource deadlock would occur
    ENAMETOOLONG* = OSErrorCode(36)
      # File name too long
    ENOLCK* = OSErrorCode(37)
      # No record locks available
    ENOSYS* = OSErrorCode(38)
      # Invalid system call number
    ENOTEMPTY* = OSErrorCode(39)
      # Directory not empty
    ELOOP* = OSErrorCode(40)
      # Too many symbolic links encountered
    EWOULDBLOCK* = EAGAIN
      # Operation would block
    ENOMSG* = OSErrorCode(42)
      # No message of desired type
    EIDRM* = OSErrorCode(43)
      # Identifier removed
    ECHRNG* = OSErrorCode(44)
      # Channel number out of range
    EL2NSYNC* = OSErrorCode(45)
      # Level 2 not synchronized
    EL3HLT* = OSErrorCode(46)
      # Level 3 halted
    EL3RST* = OSErrorCode(47)
      # Level 3 reset
    ELNRNG* = OSErrorCode(48)
      # Link number out of range
    EUNATCH* = OSErrorCode(49)
      # Protocol driver not attached
    ENOCSI* = OSErrorCode(50)
      # No CSI structure available
    EL2HLT* = OSErrorCode(51)
      # Level 2 halted
    EBADE* = OSErrorCode(52)
      # Invalid exchange
    EBADR* = OSErrorCode(53)
      # Invalid request descriptor
    EXFULL* = OSErrorCode(54)
      # Exchange full
    ENOANO* = OSErrorCode(55)
      # No anode
    EBADRQC* = OSErrorCode(56)
      # Invalid request code
    EBADSLT* = OSErrorCode(57)
      # Invalid slot
    EDEADLOCK* = EDEADLK
      # Resource deadlock would occur
    EBFONT* = OSErrorCode(59)
      # Bad font file format
    ENOSTR* = OSErrorCode(60)
      # Device not a stream
    ENODATA* = OSErrorCode(61)
      # No data available
    ETIME* = OSErrorCode(62)
      # Timer expired
    ENOSR* = OSErrorCode(63)
      # Out of streams resources
    ENONET* = OSErrorCode(64)
      # Machine is not on the network
    ENOPKG* = OSErrorCode(65)
      # Package not installed
    EREMOTE* = OSErrorCode(66)
      # Object is remote
    ENOLINK* = OSErrorCode(67)
      # Link has been severed
    EADV* = OSErrorCode(68)
      # Advertise error
    ESRMNT* = OSErrorCode(69)
      # Srmount error
    ECOMM* = OSErrorCode(70)
      # Communication error on send
    EPROTO* = OSErrorCode(71)
      # Protocol error
    EMULTIHOP* = OSErrorCode(72)
      # Multihop attempted
    EDOTDOT* = OSErrorCode(73)
      # RFS specific error
    EBADMSG* = OSErrorCode(74)
      # Not a data message
    EOVERFLOW* = OSErrorCode(75)
      # Value too large for defined data type
    ENOTUNIQ* = OSErrorCode(76)
      # Name not unique on network
    EBADFD* = OSErrorCode(77)
      # File descriptor in bad state
    EREMCHG* = OSErrorCode(78)
      # Remote address changed
    ELIBACC* = OSErrorCode(79)
      # Can not access a needed shared library
    ELIBBAD* = OSErrorCode(80)
      # Accessing a corrupted shared library
    ELIBSCN* = OSErrorCode(81)
      # .lib section in a.out corrupted
    ELIBMAX* = OSErrorCode(82)
      # Attempting to link in too many shared libraries
    ELIBEXEC* = OSErrorCode(83)
      # Cannot exec a shared library directly
    EILSEQ* = OSErrorCode(84)
      # Illegal byte sequence
    ERESTART* = OSErrorCode(85)
      # Interrupted system call should be restarted
    ESTRPIPE* = OSErrorCode(86)
      # Streams pipe error
    EUSERS* = OSErrorCode(87)
      # Too many users
    ENOTSOCK* = OSErrorCode(88)
      # Socket operation on non-socket
    EDESTADDRREQ* = OSErrorCode(89)
      # Destination address required
    EMSGSIZE* = OSErrorCode(90)
      # Message too long
    EPROTOTYPE* = OSErrorCode(91)
      # Protocol wrong type for socket
    ENOPROTOOPT* = OSErrorCode(92)
      # Protocol not available
    EPROTONOSUPPORT* = OSErrorCode(93)
      # Protocol not supported
    ESOCKTNOSUPPORT* = OSErrorCode(94)
      # Socket type not supported
    EOPNOTSUPP* = OSErrorCode(95)
      # Operation not supported on transport endpoint
    EPFNOSUPPORT* = OSErrorCode(96)
      # Protocol family not supported
    EAFNOSUPPORT* = OSErrorCode(97)
      # Address family not supported by protocol
    EADDRINUSE* = OSErrorCode(98)
      # Address already in use
    EADDRNOTAVAIL* = OSErrorCode(99)
      # Cannot assign requested address
    ENETDOWN* = OSErrorCode(100)
      # Network is down
    ENETUNREACH* = OSErrorCode(101)
      # Network is unreachable
    ENETRESET* = OSErrorCode(102)
      # Network dropped connection because of reset
    ECONNABORTED* = OSErrorCode(103)
      # Software caused connection abort
    ECONNRESET* = OSErrorCode(104)
      # Connection reset by peer
    ENOBUFS* = OSErrorCode(105)
      # No buffer space available
    EISCONN* = OSErrorCode(106)
      # Transport endpoint is already connected
    ENOTCONN* = OSErrorCode(107)
      # Transport endpoint is not connected
    ESHUTDOWN* = OSErrorCode(108)
      # Cannot send after transport endpoint shutdown
    ETOOMANYREFS* = OSErrorCode(109)
      # Too many references: cannot splice
    ETIMEDOUT* = OSErrorCode(110)
      # Connection timed out
    ECONNREFUSED* = OSErrorCode(111)
      # Connection refused
    EHOSTDOWN* = OSErrorCode(112)
      # Host is down
    EHOSTUNREACH* = OSErrorCode(113)
      # No route to host
    EALREADY* = OSErrorCode(114)
      # Operation already in progress
    EINPROGRESS* = OSErrorCode(115)
      # Operation now in progress
    ESTALE* = OSErrorCode(116)
      # Stale file handle
    EUCLEAN* = OSErrorCode(117)
      # Structure needs cleaning
    ENOTNAM* = OSErrorCode(118)
      # Not a XENIX named type file
    ENAVAIL* = OSErrorCode(119)
      # No XENIX semaphores available
    EISNAM* = OSErrorCode(120)
      # Is a named type file
    EREMOTEIO* = OSErrorCode(121)
      # Remote I/O error
    EDQUOT* = OSErrorCode(122)
      # Quota exceeded
    ENOMEDIUM* = OSErrorCode(123)
      # No medium found
    EMEDIUMTYPE* = OSErrorCode(124)
      # Wrong medium type
    ECANCELED* = OSErrorCode(125)
      # Operation Canceled
    ENOKEY* = OSErrorCode(126)
      # Required key not available
    EKEYEXPIRED* = OSErrorCode(127)
      # Key has expired
    EKEYREVOKED* = OSErrorCode(128)
      # Key has been revoked
    EKEYREJECTED* = OSErrorCode(129)
      # Key was rejected by service
    EOWNERDEAD* = OSErrorCode(130)
      # Owner died
    ENOTRECOVERABLE* = OSErrorCode(131)
      # State not recoverable
    ERFKILL* = OSErrorCode(132)
      # Operation not possible due to RF-kill
    EHWPOISON* = OSErrorCode(133)
      # Memory page has hardware error
elif defined(windows):
  const
    ERROR_SUCCESS* = OSErrorCode(0)
    ERROR_FILE_NOT_FOUND* = OSErrorCode(2)
    ERROR_TOO_MANY_OPEN_FILES* = OSErrorCode(4)
    ERROR_ACCESS_DENIED* = OSErrorCode(5)
    ERROR_ALREADY_EXISTS* = OSErrorCode(183)
    ERROR_NOT_SUPPORTED* = OSErrorCode(50)
    ERROR_BROKEN_PIPE* = OSErrorCode(109)
    ERROR_BUFFER_OVERFLOW* = OSErrorCode(111)
    ERROR_PIPE_BUSY* = OSErrorCode(231)
    ERROR_NO_DATA* = OSErrorCode(232)
    ERROR_PIPE_NOT_CONNECTED* = OSErrorCode(233)
    ERROR_PIPE_CONNECTED* = OSErrorCode(535)
    ERROR_OPERATION_ABORTED* = OSErrorCode(995)
    ERROR_IO_PENDING* = OSErrorCode(997)
    ERROR_CONNECTION_REFUSED* = OSErrorCode(1225)
    ERROR_CONNECTION_ABORTED* = OSErrorCode(1236)
    WSAEMFILE* = OSErrorCode(10024)
    WSAENETDOWN* = OSErrorCode(10050)
    WSAENETRESET* = OSErrorCode(10052)
    WSAECONNABORTED* = OSErrorCode(10053)
    WSAECONNRESET* = OSErrorCode(10054)
    WSAENOBUFS* = OSErrorCode(10055)
    WSAETIMEDOUT* = OSErrorCode(10060)
    WSAEADDRINUSE* = OSErrorCode(10048)
    WSAEDISCON* = OSErrorCode(10101)
    WSANOTINITIALISED* = OSErrorCode(10093)
    WSAENOTSOCK* = OSErrorCode(10038)
    WSAEINPROGRESS* = OSErrorCode(10036)
    WSAEINTR* = OSErrorCode(10004)
    WSAEWOULDBLOCK* = OSErrorCode(10035)
    ERROR_NETNAME_DELETED* = OSErrorCode(64)
    STATUS_PENDING* = OSErrorCode(0x103)

else:
  {.fatal: "Operation system is not yet supported!".}
