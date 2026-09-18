package main

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"time"
)

// SetupLogOutput 配置日志输出目标
//
// - 有控制台：输出到 stderr（屏幕）
// - 无控制台：输出到 logs/server-YYYY-MM-DD.log
//
// 返回一个 close 函数，程序退出时调用
func SetupLogOutput(dataDir string) func() {
	if HasConsole() {
		// 有控制台，保持默认（stderr）
		return func() {}
	}

	// 无控制台：写文件
	logDir := filepath.Join(dataDir, "logs")
	if err := os.MkdirAll(logDir, 0755); err != nil {
		// 无法创建日志目录，丢弃日志
		log.SetOutput(io.Discard)
		return func() {}
	}

	filename := time.Now().Format("2006-01-02") + ".log"
	logPath := filepath.Join(logDir, filename)

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		log.SetOutput(io.Discard)
		return func() {}
	}

	// 同时输出到文件（stderr 无法用，io.MultiWriter 可以扩展）
	log.SetOutput(f)

	return func() {
		_ = f.Close()
	}
}
