package main

import (
	"io"
	"log"
	"os"
)

// defaultLogOutput 保存程序启动时的默认日志输出目标
var defaultLogOutput io.Writer = os.Stderr

// initLogControl 记录当前日志输出（在 main 最开始调用一次）
func initLogControl() {
	defaultLogOutput = log.Writer()
}

// SetLogEnabled 开/关全局日志
//   - true:  恢复到默认输出
//   - false: 输出到 io.Discard，丢弃所有日志
func SetLogEnabled(enabled bool) {
	if enabled {
		log.SetOutput(defaultLogOutput)
	} else {
		log.SetOutput(io.Discard)
	}
}
