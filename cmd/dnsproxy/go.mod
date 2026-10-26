module router-vpn/cmd/dnsproxy

go 1.26.3

require (
	github.com/quic-go/quic-go v0.64.1
	router-vpn v0.0.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/crypto v0.54.0 // indirect
	golang.org/x/net v0.56.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)

replace router-vpn => ../..
