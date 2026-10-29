package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync"
)

const linuxOwnedControllerArgument = "--linux-owned-controller"
const linuxOwnedControllerAddress = "127.0.0.1:8788"
const controllerIdentityPath = "/api/controller/identity"

// The desktop keeps the only write end of stdin alive until its exact child
// has joined. Credentials stay in memory and never enter argv, environment,
// persisted status or a publicly readable discovery file.
type linuxOwnedController struct {
	processID   int
	callerUID   uint32
	accessToken string
	ownerToken  string
	ownerDone   <-chan struct{}
	input       *os.File
	installLock *os.File
	processLock *os.File
	closeOnce   sync.Once
}

func (c *linuxOwnedController) close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		for _, file := range []*os.File{c.input, c.processLock, c.installLock} {
			if file != nil {
				_ = file.Close()
			}
		}
	})
}

func (c *linuxOwnedController) retired() bool {
	if c == nil {
		return false
	}
	select {
	case <-c.ownerDone:
		return true
	default:
		return false
	}
}

func validLocalControllerSecret(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' && digit < 'a' || digit > 'f' {
			return false
		}
	}
	return true
}

func localControllerMAC(secret, message string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(message))
	return hex.EncodeToString(mac.Sum(nil))
}

func (c *linuxOwnedController) handler(next http.Handler) http.Handler {
	if c == nil {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || peer != "127.0.0.1" || r.Host != linuxOwnedControllerAddress ||
			r.URL.IsAbs() || len(r.Header.Values("Origin")) != 0 || len(r.Header.Values("Sec-Fetch-Site")) != 0 ||
			!validLocalControllerSecret(c.accessToken) || !validControllerOwnerToken(c.ownerToken) ||
			c.processID <= 0 || c.callerUID == 0 || len(r.Header.Values("Authorization")) != 1 {
			http.Error(w, "the captured native controller owner is required", http.StatusForbidden)
			return
		}
		// Observe a closed desktop lifetime at admission itself. The server's
		// cleanup goroutine may not have published its shutdown latch yet.
		if c.retired() {
			http.Error(w, errControllerClosing.Error(), http.StatusServiceUnavailable)
			return
		}
		if r.URL.Path == controllerIdentityPath {
			c.identity(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+c.accessToken)) != 1 {
			http.Error(w, "the captured native controller owner is required", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (c *linuxOwnedController) identity(w http.ResponseWriter, r *http.Request) {
	challenge := r.Header.Get("X-RouterVPN-Challenge")
	if r.Method != http.MethodGet || r.URL.RawQuery != "" || r.ContentLength != 0 ||
		len(r.Header.Values("X-RouterVPN-Challenge")) != 1 || !validControllerOwnerToken(challenge) ||
		subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("RouterVPN-Identity "+localControllerMAC(c.accessToken, "routervpn-controller-identity-request\n"+challenge))) != 1 {
		http.Error(w, "the captured native controller identity challenge is required", http.StatusForbidden)
		return
	}
	// A process already occupying the loopback port never receives the bearer
	// secret. The desktop first verifies this response against the stdin secret,
	// fresh challenge and the retained, unreaped child PID.
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(struct {
		Schema    int    `json:"schema"`
		ProcessID int    `json:"process_id"`
		Challenge string `json:"challenge"`
		Proof     string `json:"proof"`
	}{1, c.processID, challenge, localControllerMAC(c.accessToken, "routervpn-controller-identity-response\n"+strconv.Itoa(c.processID)+"\n"+challenge)})
}
