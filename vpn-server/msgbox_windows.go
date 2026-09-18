//go:build windows

package main

import (
	"syscall"
	"unsafe"
)

var (
	msgboxUser32    = syscall.NewLazyDLL("user32.dll")
	procMessageBoxW = msgboxUser32.NewProc("MessageBoxW")
)

const (
	mbOK              = 0x00000000
	mbOKCancel        = 0x00000001
	mbYesNo           = 0x00000004
	mbIconInformation = 0x00000040
	mbIconWarning     = 0x00000030
	mbIconQuestion    = 0x00000020

	idOK  = 1
	idYes = 6
	idNo  = 7
)

// showMsgBox 弹出一个带"确定"按钮的信息框
func showMsgBox(title, text string) {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	textPtr, _ := syscall.UTF16PtrFromString(text)
	procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(mbOK|mbIconInformation),
	)
}

// showMsgBoxYesNo 弹出"是/否"确认框，返回用户是否点了"是"
func showMsgBoxYesNo(title, text string) bool {
	titlePtr, _ := syscall.UTF16PtrFromString(title)
	textPtr, _ := syscall.UTF16PtrFromString(text)
	ret, _, _ := procMessageBoxW.Call(
		0,
		uintptr(unsafe.Pointer(textPtr)),
		uintptr(unsafe.Pointer(titlePtr)),
		uintptr(mbYesNo|mbIconQuestion),
	)
	return int(ret) == idYes
}
