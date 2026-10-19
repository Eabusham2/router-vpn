package mobilemultihop

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type maxResolverProbe struct {
	id       atomic.Value
	current  atomic.Bool
	lookups  atomic.Int32
	cancels  atomic.Int32
	lookup   func(string) (string, error)
	canceled func()
}

func newMAXResolverProbe() *maxResolverProbe {
	p := &maxResolverProbe{}
	p.id.Store("captured-network-17")
	p.current.Store(true)
	return p
}
func (p *maxResolverProbe) OwnerID() string { return p.id.Load().(string) }
func (p *maxResolverProbe) Current() bool   { return p.current.Load() }
func (p *maxResolverProbe) Cancel() {
	p.cancels.Add(1)
	if p.canceled != nil {
		p.canceled()
	}
}
func (p *maxResolverProbe) Lookup(host string) (string, error) {
	p.lookups.Add(1)
	if p.lookup != nil {
		return p.lookup(host)
	}
	return maxResolverAnswer(p.OwnerID(), host), nil
}
func maxResolverAnswer(owner, host string) string {
	raw, _ := json.Marshal(map[string]any{"owner_id": owner, "hostname": host, "addresses": []string{"192.0.2.79", "2001:db8::79"}})
	return string(raw)
}

func TestMAXNativeRequestCapturesExactOwnerAndLaunch(t *testing.T) {
	for _, mode := range []string{"max-tls-wg", "max-tls-awg", "max-quic-wg", "max-quic-awg"} {
		for _, layer := range []string{"off", "aes-256-gcm", "aes-256-gcm+xor-whitening"} {
			files, metadata := maxHostnameFixture(t, mode, layer, "captured-max.example")
			original := pqEncoded(files)
			owner := newMAXResolverProbe()
			request, err := NewMAXResolveRequest(context.Background(), mode, original, metadata, owner)
			if err != nil || owner.lookups.Load() != 0 || request.Healthy() {
				t.Fatal("construction performed DNS or adopted a runtime", err)
			}
			result, err := request.Run()
			if err != nil || !request.Healthy() || owner.lookups.Load() != 1 || owner.cancels.Load() != 0 {
				t.Fatal("captured native resolution failed", err)
			}
			var envelope map[string]any
			if json.Unmarshal([]byte(result), &envelope) != nil || len(envelope) != 8 || envelope["schema"] != float64(1) || envelope["owner_id"] != owner.OwnerID() || envelope["source_sha256"] != request.SourceSHA256() || envelope["hostname"] != "captured-max.example" || envelope["endpoint"] != "192.0.2.79" {
				t.Fatal("native result lost its exact source or owner binding")
			}
			compiled, err := CompileMAXProfile(mode, envelope["files_json"].(string), envelope["metadata_json"].(string))
			if err != nil || compiled != envelope["config_json"] || pqEncoded(files) != original {
				t.Fatal("native launch bypassed strict compilation or changed source", err)
			}
			if _, err := request.Run(); err == nil || owner.lookups.Load() != 1 {
				t.Fatal("native request performed a second lookup")
			}
			request.Cancel()
			request.Close()
			request.Close()
			if request.Healthy() || owner.cancels.Load() != 1 {
				t.Fatal("retired request remained adoptable or closed another owner")
			}
		}
	}
}

func TestMAXNativeRequestRejectsForeignAndAmbiguousAnswers(t *testing.T) {
	files, metadata := maxHostnameFixture(t, "max-quic-wg", "off", "captured-max.example")
	for _, fault := range []string{"hostname", "owner", "duplicate", "extra-field", "nonliteral", "oversize", "empty", "error-with-answer", "retired-before", "retired-during", "swapped-owner"} {
		t.Run(fault, func(t *testing.T) {
			owner := newMAXResolverProbe()
			owner.lookup = func(host string) (string, error) {
				raw := maxResolverAnswer(owner.OwnerID(), host)
				switch fault {
				case "hostname":
					return maxResolverAnswer(owner.OwnerID(), "foreign-max.example"), nil
				case "owner":
					return maxResolverAnswer("replacement-network-18", host), nil
				case "duplicate":
					return strings.Replace(raw, "{", `{"hostname":"captured-max.example",`, 1), nil
				case "extra-field":
					return strings.Replace(raw, "{", `{"fallback":"system",`, 1), nil
				case "nonliteral":
					return strings.Replace(raw, "192.0.2.79", "unowned-answer.example", 1), nil
				case "oversize":
					return raw + strings.Repeat(" ", 4096), nil
				case "empty":
					return "", nil
				case "error-with-answer":
					return raw, errors.New("private-DNS-credential")
				case "retired-during":
					owner.current.Store(false)
				case "swapped-owner":
					owner.id.Store("replacement-network-18")
				}
				return raw, nil
			}
			request, err := NewMAXResolveRequest(context.Background(), "max-quic-wg", pqEncoded(files), metadata, owner)
			if err != nil {
				t.Fatal(err)
			}
			if fault == "retired-before" {
				owner.current.Store(false)
			}
			result, err := request.Run()
			request.Close()
			if result != "" || err == nil || strings.Contains(err.Error(), "private-") || request.Healthy() || owner.cancels.Load() != 1 {
				t.Fatal("foreign or failed answer became an adoptable launch", err)
			}
			if fault == "retired-before" && owner.lookups.Load() != 0 {
				t.Fatal("retired resolver performed DNS")
			}
			if strings.HasPrefix(fault, "retired-") || fault == "swapped-owner" {
				if !errors.Is(err, ErrMAXResolutionOwner) {
					t.Fatal("owner loss was flattened into an ordinary candidate failure", err)
				}
			}
		})
	}
}

func TestMAXNativeRequestJoinsLookupAndCancellationBeforeClose(t *testing.T) {
	files, metadata := maxHostnameFixture(t, "max-tls-awg", "aes-256-gcm", "captured-max.example")
	owner := newMAXResolverProbe()
	entered, callbackStarted, callbackRelease, lookupReturned := make(chan struct{}), make(chan struct{}), make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(callbackRelease) }) }
	defer release()
	owner.lookup = func(host string) (string, error) {
		close(entered)
		<-callbackStarted
		close(lookupReturned)
		return maxResolverAnswer(owner.OwnerID(), host), nil
	}
	owner.canceled = func() {
		close(callbackStarted)
		<-callbackRelease
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	request, err := NewMAXResolveRequest(ctx, "max-tls-awg", pqEncoded(files), metadata, owner)
	if err != nil {
		t.Fatal(err)
	}
	runDone, closeDone := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(runDone)
		result, err := request.Run()
		if result != "" || !errors.Is(err, context.Canceled) {
			t.Error("late DNS result survived captured context cancellation", err)
		}
	}()
	<-entered
	cancel()
	<-callbackStarted
	<-lookupReturned
	cancelReturned := make(chan struct{})
	go func() { request.Cancel(); close(cancelReturned) }()
	select {
	case <-cancelReturned:
	case <-time.After(time.Second):
		t.Fatal("immediate Cancel blocked on a foreign resolver callback")
	}
	select {
	case <-runDone:
		t.Fatal("Run abandoned its still-active cancellation callback")
	default:
	}
	go func() { request.Close(); close(closeDone) }()
	select {
	case <-closeDone:
		t.Fatal("Close allowed fallback before the owner finished cancellation")
	default:
	}
	release()
	select {
	case <-runDone:
	case <-time.After(2 * time.Second):
		t.Fatal("canceled lookup failed to drain")
	}
	select {
	case <-closeDone:
	case <-time.After(2 * time.Second):
		t.Fatal("native Close did not join Run")
	}
	if request.Healthy() || owner.lookups.Load() != 1 || owner.cancels.Load() != 1 {
		t.Fatal("canceled request remained healthy or changed resolver owners")
	}
}

func TestMAXNativeRequestCapturesLiteralWithoutDNSAndPreCanceledOwner(t *testing.T) {
	files, metadata := maxFixture(t, "max-tls-wg")
	request, err := NewMAXResolveRequest(context.Background(), "max-tls-wg", pqEncoded(files), metadata, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result, err := request.Run(); result == "" || err != nil || !request.Healthy() {
		t.Fatal("literal request required DNS", err)
	}
	request.Close()
	owner := newMAXResolverProbe()
	request, err = NewMAXResolveRequest(context.Background(), "max-tls-wg", pqEncoded(files), metadata, owner)
	if err != nil {
		t.Fatal(err)
	}
	request.Cancel()
	request.Close()
	if result, err := request.Run(); result != "" || !errors.Is(err, context.Canceled) || owner.lookups.Load() != 0 || owner.cancels.Load() != 1 {
		t.Fatal("pre-canceled request performed work or lost cancellation identity", err)
	}
	owner = newMAXResolverProbe()
	owner.current.Store(false)
	if request, err = NewMAXResolveRequest(context.Background(), "max-tls-wg", pqEncoded(files), metadata, owner); request != nil || !errors.Is(err, ErrMAXResolutionOwner) || owner.lookups.Load() != 0 {
		t.Fatal("retired resolver acquired a request", err)
	}
}
