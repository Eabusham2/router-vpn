package main

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"

	"router-vpn/internal/controllertransport"
)

// captureListener changes only an explicitly owned in-memory TLS session.
// Existing Unix launchers have no pinnedTLS identity and retain their current
// authenticated HTTP transport. No certificate or private key is persisted.
func (c *ownedDesktopController) captureListener(listener net.Listener) (net.Listener, error) {
	if c == nil || c.pinnedTLS == nil {
		return listener, nil
	}
	address, ok := listener.Addr().(*net.TCPAddr)
	if !ok || !address.IP.Equal(net.IPv4(127, 0, 0, 1)) || address.Port != 8788 {
		return nil, errors.New("the pinned native controller requires its exact loopback listener")
	}
	config, err := c.pinnedTLS.Config()
	if err != nil {
		return nil, err
	}
	return tls.NewListener(listener, config), nil
}

func validPinnedControllerDrainRequest(r *http.Request) bool {
	return r.Method == http.MethodGet && r.URL.RequestURI() == controllertransport.DrainPath &&
		r.ContentLength == 0 && len(r.TransferEncoding) == 0 &&
		len(r.Header.Values("Authorization")) == 0 && len(r.Header.Values("Cookie")) == 0 &&
		len(r.Header.Values("X-RouterVPN-Challenge")) == 0
}

// drainHTTP returns only the captured process and terminal cleanup state. It
// deliberately stays available after launcher EOF: wrappers still have their
// captured public TLS pin and process while completing owned engine teardown.
// The outer owner middleware independently requires actual TLS, the exact
// loopback peer/Host and this one credential-free, body-free GET.
func (c *controllerShutdown) drainHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Schema   int  `json:"schema"`
		PID      int  `json:"process_id"`
		Draining bool `json:"draining"`
	}{1, c.processID, c.a.controllerClosing()})
}
