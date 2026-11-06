package mobilemultihop

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

type importedProofEngine struct {
	id, selected string
	public       func(context.Context, string, string) (net.Conn, error)
	final        *httptest.Server
	dnsCalls     atomic.Int32
	dnsFailure   bool
	cancel       context.CancelFunc
}

func (e *importedProofEngine) Identity() string { return e.id }
func (e *importedProofEngine) Selected() string { return e.selected }
func (e *importedProofEngine) Select(tag string) error {
	if tag != LocalTag {
		return errors.New("unowned server route")
	}
	e.selected = tag
	return nil
}
func (e *importedProofEngine) DNSProof(ctx context.Context) error {
	e.dnsCalls.Add(1)
	if e.dnsFailure {
		return errors.New("selected DNS failed")
	}
	if e.cancel != nil {
		e.cancel()
	}
	return ctx.Err()
}
func (e *importedProofEngine) Dial(ctx context.Context, tag, address string) (net.Conn, error) {
	if tag == "entry-wg" {
		return e.public(ctx, "captured-entry", address)
	}
	if tag != LocalTag && tag != "proxy" {
		return nil, errors.New("foreign tag")
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", e.final.Listener.Addr().String())
}

func TestImportedEntryRuntimeDistinctProofsAndSelectedDNS(t *testing.T) {
	importedRuntimeProofs(t, false)
}
func TestImportedEntrySOCKSRuntimeDistinctProofsAndSelectedDNS(t *testing.T) {
	importedRuntimeProofs(t, true)
}
func importedRuntimeProofs(t *testing.T, socks bool) {
	for _, fault := range []string{"success", "wrong-public-ip", "wrong-paired-final", "dns-failure", "cancel-during-dns", "missing-dns-capability", "changed-owner"} {
		t.Run(fault, func(t *testing.T) {
			config, capture, files, profile := importedEntryFixture(t, "", "")
			if socks {
				source := importedSOCKSFixture(t, "shadowsocks")
				config, capture, files, profile = source[0], source[1], source[3], source[4]
			}
			c, err := NewImportedEntry(config, capture, "shadowsocks", files, profile, "", "")
			if err != nil {
				t.Fatal(err)
			}
			certificate, trust := externalPublicProofCertificate(t, "1.1.1.1")
			ip := "203.0.113.88"
			if fault == "wrong-public-ip" {
				ip = "203.0.113.89"
			}
			body := "ip=" + ip + "\n"
			dial, requests, _ := externalPublicProofPeer(t, certificate, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
			var finals atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				finals.Add(1)
				if r.Header.Get("Authorization") != "Bearer "+c.meta.ExitToken || r.URL.Path != "/health" {
					t.Error("paired final proof changed")
				}
				node := c.meta.ExitNodeID
				if fault == "wrong-paired-final" {
					node = "foreign"
				}
				fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":"router-vpn-private-agent-v1"}`, node)
			}))
			defer server.Close()
			engine := &importedProofEngine{id: "actual-captured-model", selected: LocalTag, public: dial, final: server, dnsFailure: fault == "dns-failure"}
			c.engine, c.engineID, c.externalResponseTLS = engine, engine.id, trust
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if fault == "cancel-during-dns" {
				engine.cancel = cancel
			}
			if fault == "changed-owner" {
				engine.id = "replacement"
			}
			if fault == "missing-dns-capability" {
				c.engine = &importedNoDNS{Engine: engine}
			}
			err = (&trial{owner: c, tag: LocalTag}).Verify(ctx)
			if fault == "success" {
				if err != nil || requests.Load() != 1 || engine.dnsCalls.Load() != 1 || finals.Load() != 1 {
					t.Fatal("distinct actual proofs were not completed", err)
				}
			} else if err == nil {
				t.Fatal("fault produced readiness")
			}
			if (fault == "wrong-public-ip" || fault == "dns-failure" || fault == "cancel-during-dns" || fault == "missing-dns-capability" || fault == "changed-owner") && finals.Load() != 0 {
				t.Fatal("final proof proceeded after failed prerequisite")
			}
		})
	}
}

type importedNoDNS struct{ Engine }

func TestImportedEntryRuntimeLocalSelectionRetiresWithOriginalOwner(t *testing.T) {
	config, capture, files, profile := importedEntryFixture(t, "", "")
	c, err := NewImportedEntry(config, capture, "shadowsocks", files, profile, "", "")
	if err != nil {
		t.Fatal(err)
	}
	cert, trust := externalPublicProofCertificate(t, "1.1.1.1")
	body := "ip=203.0.113.88\n"
	dial, requests, _ := externalPublicProofPeer(t, cert, fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n%s", len(body), body))
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/check" {
			_, _ = w.Write([]byte("actual-routed-probe"))
			return
		}
		if r.URL.Path != "/health" || r.Header.Get("Authorization") != "Bearer "+c.meta.ExitToken {
			http.Error(w, "foreign", 403)
			return
		}
		fmt.Fprintf(w, `{"ok":true,"node_id":%q,"proof":"router-vpn-private-agent-v1"}`, c.meta.ExitNodeID)
	}))
	defer final.Close()
	engine := &importedProofEngine{id: "retained-native-model", selected: LocalTag, public: dial, final: final}
	c.externalResponseTLS = trust
	old := Targets
	Targets = []string{"http://1.1.1.1/check"}
	defer func() { Targets = old }()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Run(ctx, engine); err != nil {
		t.Fatal(err)
	}
	if !c.Healthy() || engine.selected != LocalTag || requests.Load() == 0 || engine.dnsCalls.Load() == 0 || c.progress.Execution != "local" {
		t.Fatal("local selection did not follow both original proofs and DNS")
	}
	measurement, err := c.NewImportedHopMeasurement(&importedHopInput{engine})
	if err != nil {
		t.Fatal("same retained typed measurement refused", err)
	}
	defer measurement.Close()
	if _, err := c.NewImportedHopMeasurement(&importedHopInput{&importedProofEngine{id: "foreign", selected: LocalTag}}); err == nil {
		t.Fatal("foreign native instance acquired measurement")
	}
	c.NetworkChanged()
	if c.Healthy() {
		t.Fatal("changed original native path retained readiness")
	}
	if _, err := c.NewImportedHopMeasurement(&importedHopInput{engine}); err == nil {
		t.Fatal("retired source acquired measurement")
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
}

type importedHopInput struct{ *importedProofEngine }

func (e *importedHopInput) Identity() string { return e.id + ":" + e.selected }
