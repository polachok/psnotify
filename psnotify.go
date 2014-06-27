package main

import "syscall"
import "log"
import "errors"
import "os"
import "fmt"
import "bufio"
import "strings"
import "encoding/binary"
import "flag"
import "strconv"

// #include <linux/connector.h>
// #include <linux/cn_proc.h>
import "C"

type NetLinkSocket struct {
	fd int
	lsa syscall.SockaddrNetlink
}

type NetlinkRequestData interface {
	Len() int
	ToWireFormat() []byte
}

type NetLinkRequest struct {
	syscall.NlMsghdr
	Data []NetlinkRequestData
}

func (rr *NetLinkRequest) ToWireFormat() []byte {
	native := binary.LittleEndian

	length := rr.Len
    //log.Printf("length = %d", length)
	dataBytes := make([][]byte, len(rr.Data))
	for i, data := range rr.Data {
		dataBytes[i] = data.ToWireFormat()
		length += uint32(len(dataBytes[i]))
        //log.Printf("length = %d", length)
	}
	b := make([]byte, length)
    //log.Printf("length = %d", length)

	native.PutUint32(b[0:4], length)
	native.PutUint16(b[4:6], rr.Type)
	native.PutUint16(b[6:8], rr.Flags)
	native.PutUint32(b[8:12], rr.Seq)
	native.PutUint32(b[12:16], rr.Pid)

	next := 16
	for _, data := range dataBytes {
		copy(b[next:], data)
		next += len(data)
	}
    //log.Printf("%#v", b)
	return b
}

type ProcEvent struct {
	what uint32
	cpu  uint32
	ts   uint64
	data EventData
}

type EventData interface {
    getPid() uint32
    name()   string
}

type ForkEvent struct {
	ptid  uint32
	ppid  uint32
	tid  uint32
	pid  uint32
}

func (fork ForkEvent) getPid() uint32 {
    return fork.ppid // returns parent!
}

func (fork ForkEvent) name() string {
    return "fork"
}

type ExecEvent struct {
    tid uint32
    pid uint32
}

func (exec ExecEvent) getPid() uint32 {
    return exec.pid
}

func (exec ExecEvent) name() string {
    return "exec"
}

type UidChangeEvent struct {
	tid  uint32
	pid  uint32
	ruid uint32
	euid uint32
}

func (uid UidChangeEvent) getPid() uint32 {
    return uid.pid
}

func (uid UidChangeEvent) name() string {
    return "uid"
}

type CommChangeEvent struct {
    tid uint32
    pid uint32
    title string
}

func (comm CommChangeEvent) getPid() uint32 {
    return comm.pid
}

func (comm CommChangeEvent) name() string {
    return "comm"
}

type ExitEvent struct {
	tid uint32
	pid uint32
	exit_code uint32
	exit_signal uint32
}

func (exit ExitEvent) getPid() uint32 {
    return exit.pid
}

func (exit ExitEvent) name() string {
    return "exit"
}

type ConnectorMsg struct {
	idx uint32
	val uint32
	seq uint32
	ack uint32
	len uint16
	flags uint16
	op   uint32
}

func (self ConnectorMsg) Len() int {
	return (4 + 4 + 4 + 4 + 2 + 2/* + 1*/)
}

func (self ConnectorMsg) ToWireFormat() []byte {
	b := make([]byte, self.Len()+4)

	binary.LittleEndian.PutUint32(b[0:4], self.idx)
	binary.LittleEndian.PutUint32(b[4:8], self.val)
	binary.LittleEndian.PutUint32(b[8:12], self.seq)
	binary.LittleEndian.PutUint32(b[12:16], self.ack)
	binary.LittleEndian.PutUint16(b[16:18], self.len)
	binary.LittleEndian.PutUint16(b[18:20], self.flags)
	binary.LittleEndian.PutUint32(b[20:24], self.op)
	return b
}

var (
	ErrWrongSockType = errors.New("Wrong socket type")
	ErrShortResponse = errors.New("Got short response from netlink")
)

func NewNetLinkSocket() (*NetLinkSocket, error) {
	fd, err := syscall.Socket(syscall.AF_NETLINK, syscall.SOCK_DGRAM, syscall.NETLINK_CONNECTOR)
	if err != nil {
		return nil, err
	}
	s := &NetLinkSocket{ fd: fd }
	s.lsa.Family = syscall.AF_NETLINK
	s.lsa.Groups = C.CN_IDX_PROC
	//s.lsa.Pid    = uint32(syscall.Getpid())

	if err = syscall.Bind(fd, &s.lsa); err != nil {
		syscall.Close(fd)
		return nil, err
	}

	return s, nil
}

func listen(on bool) *NetLinkRequest {
	var msg ConnectorMsg
	var request NetLinkRequest

	msg.idx = C.CN_IDX_PROC
	msg.val = C.CN_VAL_PROC
	msg.len = 4
	if on {
		msg.op = C.PROC_CN_MCAST_LISTEN
	} else {
		msg.op = C.PROC_CN_MCAST_IGNORE
	}
	request.Data = make([]NetlinkRequestData, 1)
	request.Data[0] = msg
	request.Len = 16 //uint32(msg.Len())
    //log.Printf("request.Len = %v", request.Len)
	request.Pid = uint32(syscall.Getpid())
	request.Type = syscall.NLMSG_DONE

	return &request
}

func (self *NetLinkSocket) Send(request *NetLinkRequest) error {
	if err := syscall.Sendto(self.fd, request.ToWireFormat(), 0, &self.lsa); err != nil {
		return err
	}
	return nil
}

func parseProcEvent(bytes []byte) (*ProcEvent, error) {
	var ev ProcEvent

	if (len(bytes) < syscall.NLMSG_HDRLEN+20) {
		return nil, ErrShortResponse
	}
	msg := bytes[syscall.NLMSG_HDRLEN+20:]
	ev.what = binary.LittleEndian.Uint32(msg[0:4])
	ev.cpu = binary.LittleEndian.Uint32(msg[4:8])
	ev.ts = binary.LittleEndian.Uint64(msg[8:16])

	switch (ev.what) {
	case C.PROC_EVENT_NONE:
		log.Printf("listen ok!")
	case C.PROC_EVENT_FORK:
		if (len(msg) >= 32) {
			event_data := msg[16:]
			fork_event := ForkEvent {
				ptid: binary.LittleEndian.Uint32(event_data[0:4]),
				ppid: binary.LittleEndian.Uint32(event_data[4:8]),
				tid:  binary.LittleEndian.Uint32(event_data[8:12]),
				pid:  binary.LittleEndian.Uint32(event_data[12:16]),
			}
			ev.data = fork_event
		}
	case C.PROC_EVENT_EXEC:
        if (len(msg) >= 32) {
			event_data := msg[16:]
            exec_event := ExecEvent {
                tid: binary.LittleEndian.Uint32(event_data[0:4]),
                pid: binary.LittleEndian.Uint32(event_data[4:8]),
           }
           ev.data = exec_event
        }
	case C.PROC_EVENT_UID:
		if (len(msg) >= 32) {
			event_data := msg[16:]
			uid_change_event := UidChangeEvent {
				tid: binary.LittleEndian.Uint32(event_data[0:4]),
				pid: binary.LittleEndian.Uint32(event_data[4:8]),
				ruid: binary.LittleEndian.Uint32(event_data[8:12]),
				euid: binary.LittleEndian.Uint32(event_data[12:16]),
			}
			ev.data = uid_change_event
		}
/*
	case C.PROC_EVENT_GID:
		println("gid!");
	case C.PROC_EVENT_SID:
		println("sid!");
	case C.PROC_EVENT_PTRACE:
		println("ptrace!");
*/
	case C.PROC_EVENT_COMM:
		if (len(msg) >= 32) {
            event_data := msg[16:]
            comm_change_event := CommChangeEvent {
                tid: binary.LittleEndian.Uint32(event_data[0:4]),
                pid: binary.LittleEndian.Uint32(event_data[4:8]),
                title: string(event_data[8:24]),
            }
            ev.data = comm_change_event
        }
	case C.PROC_EVENT_EXIT:
		if (len(msg) >= 32) {
			event_data := msg[16:]
			exit_event := ExitEvent {
				tid: binary.LittleEndian.Uint32(event_data[0:4]),
				pid: binary.LittleEndian.Uint32(event_data[4:8]),
				exit_code: binary.LittleEndian.Uint32(event_data[8:12]),
				exit_signal: binary.LittleEndian.Uint32(event_data[12:16]),
			}
			ev.data = exit_event
		}
	default:
		//println("whatever")
	}
	return &ev, nil
}

func (self *NetLinkSocket) Receive() (*ProcEvent, error) {
	rb := make([]byte, 76)

	nr, _, err := syscall.Recvfrom(self.fd, rb, 0)
	if err != nil {
		return nil, err
	}
	if nr < syscall.NLMSG_HDRLEN {
		return nil, ErrShortResponse
	}
	rb = rb[:nr]
	return parseProcEvent(rb)
}

var filter, filterarg string

func init() {
    f := flag.String("f", "", "filter")

    flag.Parse()
    if f != nil && *f != "" {
        fltarg := strings.Split(*f, "=")
        filter = fltarg[0]
        filterarg = fltarg[1]
    }
}

func parseStatus(pid int) (error, map[string]string) {
    m := make(map[string]string)

    f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
    if err != nil {
        return err, nil
    }

    reader := bufio.NewReader(f)

    for {
        line, _, err := reader.ReadLine()
        if err != nil {
            break
        }
        key_value := strings.Split(string(line), ":")
        m[key_value[0]] = strings.Trim(key_value[1], " \t")
    }

    return nil, m
}

type Uid struct {
    real uint64
    effective uint64
    saved uint64
    fs    uint64
}

func (uid Uid) Matches(field string, value string) bool {
    switch (field) {
    case "real":
        i64, _ := strconv.ParseUint(value, 10, 0)
        return i64 == uid.real
    case "effective":
        i64, _ := strconv.ParseUint(value, 10, 0)
        return i64 == uid.effective
    case "saved":
        i64, _ := strconv.ParseUint(value, 10, 0)
        return i64 == uid.saved
    case "fs":
        i64, _ := strconv.ParseUint(value, 10, 0)
        return i64 == uid.fs
    }
    return false
}

func getProcessUid(line string) Uid {
    uid := Uid{}

    uids := strings.Fields(line)
    uid.real,_ = strconv.ParseUint(uids[0], 10, 0)
    uid.effective,_ = strconv.ParseUint(uids[1], 10, 0)
    uid.saved,_ = strconv.ParseUint(uids[2], 10, 0)
    uid.fs,_    = strconv.ParseUint(uids[3], 10, 0)

    return uid
}

type Proc struct {
    pid     uint32
    ppid    uint32
    uid     Uid

    cmdline string
}

func (proc Proc) Matches(field string, value string) bool {
    switch (field) {
    case "pid":
        i64, _ := strconv.ParseUint(value, 10, 0)
        return uint32(i64) == proc.pid
    case "ppid":
        i64, _ := strconv.ParseUint(value, 10, 0)
        return uint32(i64) == proc.ppid
    case "cmdline":
        return strings.Index(proc.cmdline, value) != -1
    default:
        idx := strings.Index(field, ".")
        if idx != -1 && field[0:idx] == "uid" {
            return proc.uid.Matches(field[idx+1:], value)
        }
        return false
    }
}

func getProcessStatus(pid uint32) (error, string) {
	path := fmt.Sprintf("/proc/%d/cmdline", pid)
	file, err := os.Open(path)
	if err != nil {
		return err, ""
	}
	reader := bufio.NewReader(file)
	cmdline,_ := reader.ReadString('\n')
    cmdline = strings.Replace(cmdline, "\x00", " ", -1)
	return nil, cmdline
}

func newProc(pid uint32) (err error, proc Proc) {
    proc.pid = pid

    m := make(map[string](func(p *Proc, val string) bool))

    m["PPid"] = func(p *Proc, val string) bool {
        i64, err := strconv.ParseUint(val, 10, 0)
        if err != nil {
            return false
        } else {
            p.ppid = uint32(i64)
            return true
        }
    }

    m["Uid"] = func(p *Proc, val string) bool {
        uid := getProcessUid(val)
        if err == nil {
            proc.uid = uid
            return true
        }
        return false
    }

    err, cmdline := getProcessStatus(pid)
    if err == nil {
        proc.cmdline = cmdline
    }

    f, err := os.Open(fmt.Sprintf("/proc/%d/status", pid))
    if err != nil {
        return err, proc
    }

    reader := bufio.NewReader(f)

    for {
        line, _, err := reader.ReadLine()
        if err != nil {
            break
        }
        key_value := strings.Split(string(line), ":")
        f, ok := m[key_value[0]]
        if !ok {
            continue
        }
        f(&proc, key_value[1])
    }
    return nil, proc
}

func main() {
    //runtime.GOMAXPROCS(1)
    //runtime.LockOSThread()
    if filter != "" && filterarg != "" {
        log.Printf("Filter: %s Arg: %s\n", filter, filterarg)
    }
	s, err := NewNetLinkSocket()
	if err != nil {
		log.Print(err)
	}
	err = s.Send(listen(true))
	if err != nil {
		log.Print(err)
	}
	for {
		ev, err := s.Receive()
		if err != nil || ev.data == nil {
            continue
		}
        switch (ev.what) {
        case C.PROC_EVENT_FORK:
            _,proc := newProc(ev.data.(ForkEvent).pid)
            if ((filter == "" && filterarg == "") || proc.Matches(filter, filterarg)) {
                log.Printf("Fork: %+v proc: %#v\n", ev.data.(ForkEvent), proc)
            }
        case C.PROC_EVENT_EXEC:
            _,proc := newProc(ev.data.(ExecEvent).pid)
            if ((filter == "" && filterarg == "") || proc.Matches(filter, filterarg)) {
                log.Printf("Exec: %+v cmd: %#v\n", ev.data.(ExecEvent), proc)
            }
        case C.PROC_EVENT_EXIT:
            _,proc := newProc(ev.data.(ExitEvent).pid)
            if ((filter == "" && filterarg == "") || proc.Matches(filter, filterarg)) {
                log.Printf("Exit: %+v cmd: %#v\n", ev.data.(ExitEvent), proc)
            }
        case C.PROC_EVENT_UID:
            _,proc := newProc(ev.data.(UidChangeEvent).pid)
            if ((filter == "" && filterarg == "") || proc.Matches(filter, filterarg)) {
                log.Printf("Uid: %+v cmd: %#v\n", ev.data.(UidChangeEvent), proc)
            }
        }
    }
}
