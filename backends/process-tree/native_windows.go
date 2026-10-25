package processtree

import (
	"syscall"
	"unsafe"
)

var kernel = syscall.NewLazyDLL("kernel32.dll")
var openProcess = kernel.NewProc("OpenProcess")
var closeHandle = kernel.NewProc("CloseHandle")
var getTimes = kernel.NewProc("GetProcessTimes")
var getImage = kernel.NewProc("QueryFullProcessImageNameW")
var queryBasic = syscall.NewLazyDLL("ntdll.dll").NewProc("NtQueryInformationProcess")

type NativeSource struct{}
type filetime struct{ Low, High uint32 }

func (f filetime) value() uint64 { return uint64(f.High)<<32 | uint64(f.Low) }

func (NativeSource) Read(pid uint32) (Process, error) {
	if pid <= 4 {
		return Process{}, ErrUnavailable
	}
	h, _, _ := openProcess.Call(0x1000, 0, uintptr(pid)) // PROCESS_QUERY_LIMITED_INFORMATION
	if h == 0 {
		return Process{}, ErrUnavailable
	}
	defer closeHandle.Call(h)
	var created, exited, system, user filetime
	ok, _, _ := getTimes.Call(h, uintptr(unsafe.Pointer(&created)), uintptr(unsafe.Pointer(&exited)), uintptr(unsafe.Pointer(&system)), uintptr(unsafe.Pointer(&user)))
	if ok == 0 || created.value() == 0 || exited.value() != 0 {
		return Process{}, ErrUnavailable
	}
	// PROCESS_BASIC_INFORMATION is six pointer-sized slots on Windows x64.
	var basic [6]uintptr
	status, _, _ := queryBasic.Call(h, 0, uintptr(unsafe.Pointer(&basic)), unsafe.Sizeof(basic), 0)
	if status != 0 || basic[4] != uintptr(pid) || basic[5] > 0xffffffff {
		return Process{}, ErrUnavailable
	}
	var sequence uint64
	status, _, _ = queryBasic.Call(h, 92, uintptr(unsafe.Pointer(&sequence)), unsafe.Sizeof(sequence), 0)
	if status != 0 || sequence == 0 {
		return Process{}, ErrUnavailable
	}
	buffer := make([]uint16, 32768)
	size := uint32(len(buffer))
	ok, _, _ = getImage.Call(h, 0, uintptr(unsafe.Pointer(&buffer[0])), uintptr(unsafe.Pointer(&size)))
	if ok == 0 || size == 0 || size >= uint32(len(buffer)) {
		return Process{}, ErrUnavailable
	}
	return Process{Identity{pid, created.value(), sequence}, uint32(basic[5]), syscall.UTF16ToString(buffer[:size])}, nil
}
