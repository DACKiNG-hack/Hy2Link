//go:build !windows

package main

// 非 Windows 平台不做单实例限制，所有函数为空实现。
func EnsureSingleInstance() bool { return true }
func ReleaseSingleInstance()     {}
func ShowAlreadyRunningDialog()  {}
