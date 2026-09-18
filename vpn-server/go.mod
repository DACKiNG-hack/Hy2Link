//服务端go.mod文件
module vpn-server

go 1.25.0

require (
	fyne.io/systray v1.12.2
	github.com/apernet/hysteria/core/v2 v2.12.2
	github.com/apernet/hysteria/extras/v2 v2.0.0-00010101000000-000000000000
	github.com/apernet/quic-go v0.61.1-0.20260806010916-184d081eef3e
	github.com/jech/portmap v0.0.0-20240609101148-1151a9a8a46b
	github.com/phuslu/iploc v1.0.20260901
	github.com/pion/stun v0.6.1
	golang.org/x/crypto v0.54.0
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842
	golang.org/x/sys v0.47.0
	golang.org/x/term v0.45.0
	golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/godbus/dbus/v5 v5.1.0 // indirect
	github.com/huin/goupnp v1.3.0 // indirect
	github.com/jackpal/gateway v1.0.10 // indirect
	github.com/jackpal/go-nat-pmp v1.0.2 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/pion/dtls/v2 v2.2.7 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/transport/v2 v2.2.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/refraction-networking/utls v1.8.2 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/stretchr/testify v1.11.1 // indirect
	golang.org/x/net v0.57.0 // indirect
	golang.org/x/sync v0.22.0 // indirect
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
