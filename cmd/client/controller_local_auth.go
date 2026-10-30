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

	"router-vpn/internal/common"
	"router-vpn/internal/controllertransport"
)

const linuxOwnedControllerArgument = "--linux-owned-controller"
const linuxOwnedControllerAddress = "127.0.0.1:8788"
const controllerIdentityPath = "/api/controller/identity"

// The desktop retains its authenticated lifetime channel until its exact child
// has joined: an anonymous pipe on Linux, a kernel-authenticated Unix connection
// on macOS. Credentials stay in memory and never enter argv, environment,
// persisted status or a publicly readable discovery file.
type ownedDesktopController struct {
	processID   int
	callerUID   uint32
	accessToken string
	ownerToken  string
	ownerDone   <-chan struct{}
	input       *os.File
	installLock *os.File
	processLock *os.File
	closeOnce   sync.Once
	pinnedTLS   *controllertransport.Identity
	nativeOwner ownedDesktopNativeOwner
}

// Native Windows ownership is a retained kernel process/pipe capture, not a
// fabricated Unix UID or a request/environment flag. Its data layout also
// belongs to that capture so the portable and installed roots cannot mix.
type ownedDesktopNativeOwner interface {
	Captured() bool
	Alive() error
	Close() error
	CaptureConfiguration(common.ClientConfig) (common.ClientConfig, error)
	CaptureModes([]common.Mode) ([]common.Mode, error)
}

// Keep the Linux launcher API compatible while both installed desktops share
// exactly the same HTTP identity, admission and teardown boundary.
type linuxOwnedController = ownedDesktopController

func (c *ownedDesktopController) close() {
	if c == nil {
		return
	}
	c.closeOnce.Do(func() {
		if c.nativeOwner != nil {
			_ = c.nativeOwner.Close()
		}
		for _, file := range []*os.File{c.input, c.processLock, c.installLock} {
			if file != nil {
				_ = file.Close()
			}
		}
	})
}

func (c *ownedDesktopController) validateConfiguration(config *common.ClientConfig) error {
	if c != nil && c.nativeOwner != nil {
		captured, err := c.nativeOwner.CaptureConfiguration(*config)
		if err == nil {
			*config = captured
		}
		return err
	}
	return validateNativeOwnedConfiguration(*config)
}

func (c *ownedDesktopController) captureModes(modes []common.Mode) ([]common.Mode, error) {
	if c != nil && c.nativeOwner != nil {
		return c.nativeOwner.CaptureModes(modes)
	}
	return modes, nil
}

func (c *ownedDesktopController) hasCapturedCaller() bool {
	if c == nil {
		return false
	}
	if c.nativeOwner != nil {
		return c.callerUID == 0 && c.nativeOwner.Captured()
	}
	return c.callerUID != 0
}

func (c *ownedDesktopController) retired() bool {
	if c == nil {
		return false
	}
	if c.nativeOwner != nil && c.nativeOwner.Alive() != nil {
		return true
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

func (c *ownedDesktopController) handler(next http.Handler) http.Handler {
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
			c.processID <= 0 || !c.hasCapturedCaller() || c.pinnedTLS != nil && r.TLS == nil {
			http.Error(w, "the captured native controller owner is required", http.StatusForbidden)
			return
		}
		// An owned native helper needs only bounded process/drain observation
		// while GUI authority is retiring. This exact operation carries no bearer
		// or shutdown secret and exists only on the captured TLS listener.
		if c.pinnedTLS != nil && r.URL.Path == controllertransport.DrainPath {
			if !validPinnedControllerDrainRequest(r) {
				http.Error(w, "the exact read-only native drain request is required", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if len(r.Header.Values("Authorization")) != 1 {
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

func (c *ownedDesktopController) identity(w http.ResponseWriter, r *http.Request) {
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
