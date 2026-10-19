module router-vpn/mobile/torpt

go 1.26.0

require (
	github.com/refraction-networking/utls v1.8.2
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.6.0
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird v0.0.0-20261008205628-362a60bb4e3f
	golang.org/x/net v0.59.0
	router-vpn v0.0.0
)

require (
	filippo.io/edwards25519 v1.2.0 // indirect
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	gitlab.com/yawning/edwards25519-extra v0.0.0-20231005122941-2149dcafc266 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/webtunnel v0.0.7 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
)

replace router-vpn => ../..
