module vpn-tool

go 1.25.5

require (
	github.com/apernet/hysteria/core/v2 v2.12.2
	github.com/apernet/hysteria/extras/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e
	github.com/energye/systray v1.0.3
	github.com/google/uuid v1.6.0
	github.com/wailsapp/wails/v2 v2.15.0
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
)

require (
	git.sr.ht/~jackmordaunt/go-toast/v2 v2.0.3 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/bep/debounce v1.2.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/jchv/go-winloader v0.0.0-20210711035445-715c2860da7e // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/labstack/echo/v4 v4.13.3 // indirect
	github.com/labstack/gommon v0.4.2 // indirect
	github.com/leaanthony/go-ansi-parser v1.6.1 // indirect
	github.com/leaanthony/gosod v1.0.4 // indirect
	github.com/leaanthony/slicer v1.6.0 // indirect
	github.com/leaanthony/u v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/samber/lo v1.49.1 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	github.com/tkrajina/go-reflector v0.5.8 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fasttemplate v1.2.2 // indirect
	github.com/wailsapp/go-webview2 v1.0.22 // indirect
	github.com/wailsapp/mimetype v1.4.1 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/apernet/hysteria/core/v2 => ../hy-core

replace github.com/apernet/hysteria/extras/v2 => ../hy-extras

replace github.com/apernet/quic-go => ../quic-go

exclude github.com/quic-go/quic-go v0.60.0

exclude github.com/quic-go/quic-go v0.61.0

exclude github.com/quic-go/quic-go v0.62.0
