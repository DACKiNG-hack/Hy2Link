package cert

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type acmeState struct {
	manager *autocert.Manager
	httpSrv *http.Server
}

func newACMEManager(domain, email, cacheDir string) *autocert.Manager {
	return &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache(cacheDir),
		HostPolicy: autocert.HostWhitelist(domain),
		Email:      email,
	}
}

// startACMEHTTP 启动 80 端口 HTTP 服务器用于 ACME 验证
func (a *acmeState) start() error {
	mux := http.NewServeMux()
	mux.Handle("/", a.manager.HTTPHandler(nil))

	srv := &http.Server{
		Addr:              ":80",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}
	a.httpSrv = srv

	errCh := make(chan error, 1)
	go func() {
		log.Printf("🔐 [ACME] HTTP 验证服务器已启动 :80")
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errCh <- err
		}
	}()

	// 等 500ms 看是否启动失败（端口占用等）
	select {
	case err := <-errCh:
		return fmt.Errorf("启动 80 端口失败: %w（请确认 80 端口未被占用且可入站）", err)
	case <-time.After(500 * time.Millisecond):
		return nil
	}
}

func (a *acmeState) stop() {
	if a.httpSrv != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = a.httpSrv.Shutdown(ctx)
	}
}
