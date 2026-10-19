package meeklite

import (
	utls "github.com/refraction-networking/utls"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/lyrebird/transports/base"
	"net/http"
)

// NewBrokerRoundTripper uses the same pinned, corrected uTLS fingerprint and
// captured-dial ALPN implementation for one owned Snowflake broker exchange.
// The caller joins the exchange and calls CloseIdleConnections before release.
func NewBrokerRoundTripper(dial base.DialFunc, hello *utls.ClientHelloID) http.RoundTripper {
	return newRoundTripper(dial, hello)
}
