package main

import "syscall"
import "log"
import "runtime"
import "flag"
import "fmt"
import "strconv"
import "os"
import "os/signal"
import "bytes"
import "errors"
import "unsafe"

var pid int = -1

type SyscallTable map[int]func(syscall.PtraceRegs) func(syscall.PtraceRegs)

func init() {
    runtime.LockOSThread()
    flag.IntVar(&pid, "p", -1, "pid")
    flag.Parse()
}

const (
    SysRead    = 0
    SysWrite   = 1
    SysOpen    = 2
    SysClose   = 3
    SysSocket  = 41
    SysConnect = 42
    SysSendto  = 44
    SysSendmsg = 46
    SysRecvmsg = 47
    SysClone   = 56
    SysFork    = 57
    SysVfork   = 58
    SysGetuid  = 102
    SysSyslog  = 103
    SysGetgid  = 104
    SysSetuid  = 105
    SysSetgid  = 106
    SysRestart = 219
    SysExit    = 231
)

var families = []string{
                "PF_UNSPEC",
                "PF_UNIX",
                "PF_INET",
                "PF_AX25",
                "PF_IPX",
                "PF_APPLETALK",
                "PF_NETROM",
                "PF_BRIDGE",
                "PF_ATMPVC",
                "PF_X25",
                "PF_INET6",
                /* more */
            }

var types = []string {
    "",
    "SOCK_STREAM",
    "SOCK_DGRAM",
    "SOCK_RAW",
    "SOCK_RDM",
    "SOCK_SEQPACKET",
    "SOCK_DCCP",
    "SOCK_PACKET",
}

func initSyscalls() SyscallTable {
    read_or_write := func(name string, regs syscall.PtraceRegs) func(syscall.PtraceRegs) {
        var addr   = regs.Rsi
        var count  = int32(regs.Rdx)

        fd := regs.Rdi
        fmt.Printf(`%s(%d, `, name, fd)

        return func(regs syscall.PtraceRegs) {
            result := int32(regs.Rax)
            var buf []byte = []byte{}

            if (result > 0) {
                buf = make([]byte, result+4)
                for i := 0; i <= int(result); i += 4 {
                    syscall.PtracePeekData(pid, uintptr(addr), buf[i:i+4])
                    addr += 4
                }
                fmt.Printf("%s, %d) = %d\n", strconv.Quote(string(buf[0:result])), count, result)
            } else {
                fmt.Printf("\"\", %d) = %d\n", count, result)
            }
        }
    }

    fork_or_vfork := func(name string, regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
        fmt.Printf("%s()", name)
        return func(regs syscall.PtraceRegs) {
            var code = int32(regs.Rax)

            fmt.Printf(" = %d", code)
        }
    }

    parseSockAddr := func(bs []byte) (error, *syscall.RawSockaddr) {
        if len(bs) < 2 {
            return errors.New("ETOOSHORT"), nil
        }
        var family uint16 = uint16(bs[1]) << 8 | uint16(bs[0])

        log.Printf("FAMILY IS %d\n", family)
        switch family {
            case syscall.AF_LOCAL:
                var rsau *syscall.RawSockaddrUnix
                rsau = (*syscall.RawSockaddrUnix)(unsafe.Pointer(&bs))
                log.Printf("%#v", rsau)
        }
        return errors.New("LUL"), nil
    }

    readBytes := func(addr uintptr, length int) []byte {
        var buf = make([]byte, length + 4)

        log.Printf("READBYTES addr: %v length: %d\n", addr, length)

        for i := 0; i < length; i += 4 {
            syscall.PtracePeekData(pid, addr, buf[i:i+4])
            addr += 4
        }
        return buf
    }

    readString := func(addr uintptr, length int) string {
        buf := readBytes(addr, length)

        return strconv.Quote(string(buf))
    }

    m := SyscallTable{

        SysRead: func(regs syscall.PtraceRegs) func(syscall.PtraceRegs) {
            return read_or_write("read",  regs)
        },

        SysWrite: func(regs syscall.PtraceRegs) func(syscall.PtraceRegs) {
            return read_or_write("write", regs)
        },

        SysClose: func(regs syscall.PtraceRegs) func(syscall.PtraceRegs) {
            fd := regs.Rdi
            fmt.Printf("close(%d)", fd)
            return func(regs syscall.PtraceRegs) {
                var ret = int32(regs.Rax)

                fmt.Printf(" = %d\n", ret)
            }
        },

        SysOpen: func(regs syscall.PtraceRegs) func(syscall.PtraceRegs) {
            var fnameptr = regs.Rdi
            var flags    = regs.Rsi
            var mode     = regs.Rdx
            var buf      = bytes.NewBuffer([]byte{})
            var mbuf     = make([]byte, 4)
            var nullFound = false

            for {
                syscall.PtracePeekData(pid, uintptr(fnameptr), mbuf[0:4])
                j := 0
                for _, v := range mbuf {
                    if v == '\x00' {
                        nullFound = true
                        break
                    }
                    j++
                }
                buf.Write(mbuf[0:j])
                if nullFound {
                    break
                }
                fnameptr += 4
            }
            fmt.Printf("open(%s, %x, %x)", strconv.Quote(string(buf.Bytes())), flags, mode)

            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                fmt.Printf(" = %d\n", ret)
            }
        },

        SysSocket: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            family := regs.Rdi
            typ    := regs.Rsi
            proto  := regs.Rdx

            fmt.Printf("socket(%s, %s, %d)", families[family], types[typ & 0xf], proto)

            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                fmt.Printf(" = %d\n", ret)
            }
        },

        SysConnect: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            fd := regs.Rdi
            sockaddr := regs.Rsi
            addrlen  := regs.Rdx

            if sockaddr != 0 && addrlen != 0 {
                buf := readBytes(uintptr(sockaddr), int(addrlen))
                parseSockAddr(buf)
            }
            fmt.Printf("connect(%d, %x, %x)", fd, sockaddr, addrlen)

            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                fmt.Printf(" = %d\n", ret)
            }
        },

        SysSendto: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            fd := regs.Rdi
            bufptr := regs.Rsi
            length := regs.Rdx
            flags  := regs.Rcx
            sockaddr := regs.R8
            addrlen := regs.R9

            buf := readString(uintptr(bufptr), int(length))

            fmt.Printf("sendto(%d, %s, %d, %d, %v, %d)", fd, buf, length, flags, sockaddr, addrlen)

            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                fmt.Printf("= %d\n", ret)
            }
        },

        SysSendmsg: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            fd := regs.Rdi
            msg := regs.Rsi
            flags := regs.Rdx

            fmt.Printf("sendmsg(%d, %v, %v)", fd, msg, flags)
            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                fmt.Printf("= %d\n", ret)
            }
        },

        SysRecvmsg: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            fd := regs.Rdi
            msg := regs.Rsi
            flags := regs.Rdx

            fmt.Printf("recvmsg(%d, ", fd)
            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                if ret >= 0 {
                    fmt.Printf("\"%v\", %s) = %d\n", msg, flags, ret)
                } else {
                    fmt.Printf("\"\", %s) = %d\n", flags, ret)
                }
            }
        },

        SysSyslog: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            typ := regs.Rdi
            msgptr := regs.Rsi
            length := regs.Rdx

            msg := readString(uintptr(msgptr), int(length))

            fmt.Printf("syslog(%d, %s, %d)", typ, msg, length)

            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                fmt.Printf(" = %d\n", ret)
            }
        },

        SysGetuid: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            fmt.Printf("getuid()")

            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                fmt.Printf(" = %d\n", ret)
            }
        },

        SysGetgid: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            fmt.Printf("getgid()")

            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                fmt.Printf(" = %d\n", ret)
            }
        },

        SysSetuid: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            uid := int32(regs.Rdi)
            fmt.Printf("setuid(%d)", uid)

            return func(regs syscall.PtraceRegs) {
                ret := int32(regs.Rax)

                fmt.Printf(" = %d\n", ret)
            }
        },

        SysExit: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            var code = regs.Rdi
            fmt.Printf("exit_group(%d)\n", code)

            return func(regs syscall.PtraceRegs) { }
        },

        SysFork: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            return fork_or_vfork("fork", regs)
        },

        SysVfork: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            return fork_or_vfork("vfork", regs)
        },

        SysRestart: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            fmt.Printf("<restarting syscall>")
            return func(regs syscall.PtraceRegs) {
            }
        },

        SysClone: func(regs syscall.PtraceRegs) func(regs syscall.PtraceRegs) {
            var flags = regs.Rdi
            var sp    = regs.Rsi
            var envp  = regs.Rdx
            fmt.Printf("clone(%x, %x, %x)", flags, sp, envp)

            return func(regs syscall.PtraceRegs) {
                var code = int32(regs.Rax)

                fmt.Printf(" = %d", code)
            }
        },
    }

    return m
}

func (sc SyscallTable) Call(regs syscall.PtraceRegs) func(syscall.PtraceRegs) {
    f, ok := sc[int(regs.Orig_rax)]
    if ok {
        return f(regs)
    } else {
        log.Printf("unknown syscall %d", int(regs.Orig_rax))
        return nil
    }
}

func check(c chan os.Signal, die *bool) {
    for {
        <-c
        log.Printf("dying")
        *die = true
    }
}

func main() {
    var wstat syscall.WaitStatus
    var complete func(syscall.PtraceRegs) = nil
    var die = false
    regs := syscall.PtraceRegs{}
    isSyscall := func(wstat syscall.WaitStatus) bool {
        return (((uint32(wstat) & 0xff00) >> 8) & 0x80) != 0
    }

    sc := initSyscalls()

    c := make(chan os.Signal, 1)
    signal.Notify(c, os.Kill, os.Interrupt)
    go check(c, &die)

    if pid == -1 {
        log.Fatal("No pid set")
    }

    err := syscall.PtraceAttach(pid)
    if err != nil {
        log.Print("attach")
        log.Print(err)
        goto fail
    }

    _, err = syscall.Wait4(pid, &wstat, 0, nil)
    if err != nil {
        log.Printf("wait %d err %s\n", pid, err)
        goto fail
    }
    err = syscall.PtraceSetOptions(pid, syscall.PTRACE_O_TRACESYSGOOD)
    if err != nil {
        log.Print("ptrace set options")
        log.Print(err)
        goto fail
    }

    for !die {
        err = syscall.PtraceSyscall(pid, 0)
        if err != nil {
            log.Print("syscall")
            log.Print(err)
            goto fail
        }

        _, err = syscall.Wait4(pid, &wstat, 0, nil)
        if err != nil {
            log.Printf("wait %d err %s\n", pid, err)
            goto fail
        }

        // ENTER
        if wstat.Stopped() {
            if isSyscall(wstat) {
                err = syscall.PtraceGetRegs(pid, &regs)
                if err != nil {
                    log.Print("regs")
                    log.Print(err)
                    goto fail
                }
                complete = sc.Call(regs)
            }
        }
        err = syscall.PtraceSyscall(pid, 0)
        if err != nil {
            log.Print("syscall 2")
            log.Print(err)
            goto fail
        }

        _, err = syscall.Wait4(pid, &wstat, 0, nil)
        if err != nil {
            log.Printf("wait %d err %s\n", pid, err)
            goto fail
        }

        os.Stdout.Sync()
        if wstat.Stopped() {
            if isSyscall(wstat) {
                err = syscall.PtraceGetRegs(pid, &regs)
                if err != nil {
                    log.Print("regs")
                    log.Print(err)
                    goto fail
                }
                //log.Printf("NUM: %d ::%#v", syscallNum, regs)
                if (complete != nil) {
                    complete(regs)
                    complete = nil
                }
            }
        }
    }

fail:
    syscall.Kill(pid, 18)
    err = syscall.PtraceDetach(pid)
    if err != nil {
        log.Print("detach")
        log.Print(err)
    }
}
