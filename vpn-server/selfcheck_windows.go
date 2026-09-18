//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

func checkDiskFree(path string) (uint64, error) {
	var free, total, avail uint64
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	kernel32 := syscall.NewLazyDLL("kernel32.dll")
	getDiskFreeSpaceEx := kernel32.NewProc("GetDiskFreeSpaceExW")
	ret, _, e := getDiskFreeSpaceEx.Call(
		uintptr(unsafe.Pointer(p)),
		uintptr(unsafe.Pointer(&free)),
		uintptr(unsafe.Pointer(&total)),
		uintptr(unsafe.Pointer(&avail)),
	)
	if ret == 0 {
		return 0, e
	}
	return free, nil
}
