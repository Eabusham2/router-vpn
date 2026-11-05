//go:build linux && routervpn_controller_privileged

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"router-vpn/internal/linuxprotection"
	"router-vpn/internal/mobiletor"
	"strings"
	"syscall"
	"testing"
	"time"
)

func imageEnvelopeFixture() linuxStandardImageUpgradeEnvelope {
	h := strings.Repeat("a", 64)
	o := linuxprotection.NativeObject{Device: 1, Inode: 2, Mode: 0600}
	return linuxStandardImageUpgradeEnvelope{Schema: 1, ID: strings.Repeat("a", 32), DeadlineNS: time.Now().Add(time.Minute).UnixNano(), OldGeneration: linuxStandardGenerationSelection{1, h, h}, NewGeneration: linuxStandardGenerationSelection{1, strings.Repeat("b", 64), h}, ActivationSHA256: h, Root: o, Run: o, MutationLock: o, SavedState: o, SavedStateSHA256: h, ProfileID: "original", ProfileRevision: h, Endpoints: []netip.Addr{netip.MustParseAddr("198.18.0.2"), netip.MustParseAddr("198.18.0.10"), netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8::10")}, SourceSHA256: h, DestinationSession: strings.Repeat("b", 32), DestinationSHA256: h}
}
func TestLinuxStandardServiceImageEnvelopeKeepsNativeOrdering(t *testing.T) {
	t.Run("numeric-roundtrip", func(t *testing.T) {
		e := imageEnvelopeFixture()
		if err := e.validate(); err != nil {
			t.Fatal(err)
		}
		raw, _ := json.Marshal(e)
		var actual linuxStandardImageUpgradeEnvelope
		if err := linuxStandardServiceDecode(raw, &actual); err != nil {
			t.Fatal(err)
		}
		if err := actual.validate(); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("lexical-reorder", func(t *testing.T) {
		e := imageEnvelopeFixture()
		e.Endpoints[0], e.Endpoints[1] = e.Endpoints[1], e.Endpoints[0]
		if e.validate() == nil {
			t.Fatal("lexical endpoint reorder accepted")
		}
	})
	t.Run("duplicate", func(t *testing.T) {
		e := imageEnvelopeFixture()
		e.Endpoints[1] = e.Endpoints[0]
		if e.validate() == nil {
			t.Fatal("duplicate original endpoint accepted")
		}
	})
	t.Run("mapped", func(t *testing.T) {
		e := imageEnvelopeFixture()
		e.Endpoints = []netip.Addr{netip.MustParseAddr("::ffff:198.18.0.2")}
		if e.validate() == nil {
			t.Fatal("mapped substitute accepted")
		}
	})
	t.Run("cross-scope", func(t *testing.T) {
		q := linuxStandardServiceResponse{Schema: 1, Action: "current", ImageUpgrade: &linuxStandardServiceImageUpgradeResponse{Envelope: imageEnvelopeFixture()}}
		raw, _ := json.Marshal(q)
		var v linuxStandardServiceResponse
		if linuxStandardServiceDecode(raw, &v) == nil {
			t.Fatal("ordinary service accepted unrelated image evidence")
		}
	})
}
func TestLinuxStandardServiceImageCleanupKeepsOriginalClock(t *testing.T) {
	t.Run("lazy", func(t *testing.T) {
		x := &linuxStandardImageUpgrade{envelope: imageEnvelopeFixture()}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		call, stop, err := x.context(ctx, false, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer stop()
		d, _ := call.Deadline()
		if d.UnixNano() != x.envelope.DeadlineNS || x.cleanupDeadline != 0 {
			t.Fatal("work renewed or started cleanup")
		}
	})
	t.Run("once", func(t *testing.T) {
		x := &linuxStandardImageUpgrade{envelope: imageEnvelopeFixture()}
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		stamp := time.Now().Add(10 * time.Second).UnixNano()
		_, stop, err := x.context(ctx, true, stamp)
		if err != nil {
			t.Fatal(err)
		}
		stop()
		original := x.cleanupDeadline
		_, stop, err = x.context(ctx, true, stamp)
		if err != nil {
			t.Fatal(err)
		}
		stop()
		if x.cleanupDeadline != original || original != stamp {
			t.Fatal("cleanup original absolute deadline renewed")
		}
		if _, _, err = x.context(ctx, false, 0); err == nil {
			t.Fatal("candidate work admitted after cleanup began")
		}
	})
	t.Run("expired-observation", func(t *testing.T) {
		x := &linuxStandardImageUpgrade{envelope: imageEnvelopeFixture()}
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if _, _, err := x.context(ctx, true, 0); !errors.Is(err, context.Canceled) || x.cleanupDeadline != 0 {
			t.Fatal("expired observer activated cleanup")
		}
	})
	t.Run("same-cross-process-clock", func(t *testing.T) {
		old := &linuxStandardImageUpgrade{envelope: imageEnvelopeFixture()}
		candidate := &linuxStandardImageUpgrade{envelope: old.envelope, candidate: true}
		full, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		_, finish, err := old.context(full, true, 0)
		if err != nil {
			t.Fatal(err)
		}
		finish()
		short, stop := context.WithTimeout(context.Background(), time.Second)
		defer stop()
		call, release, err := candidate.context(short, true, old.cleanupDeadline)
		if err != nil {
			t.Fatal(err)
		}
		release()
		deadline, _ := call.Deadline()
		outer, _ := short.Deadline()
		if candidate.cleanupDeadline != old.cleanupDeadline || !deadline.Equal(outer) {
			t.Fatal("candidate renewed or shortened shared cleanup clock")
		}
		if _, _, err = old.context(full, true, old.cleanupDeadline+int64(time.Second)); err == nil {
			t.Fatal("cleanup renewal accepted")
		}
	})

	t.Run("outer-clamp", func(t *testing.T) {
		x := &linuxStandardImageUpgrade{envelope: imageEnvelopeFixture()}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, stop, err := x.context(ctx, true, 0)
		if err != nil {
			t.Fatal(err)
		}
		stop()
		deadline, _ := ctx.Deadline()
		if x.cleanupDeadline != deadline.UnixNano() {
			t.Fatal("cleanup exceeded original outer bound")
		}
	})
}
func imageSocketPair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := make([]*net.UnixConn, 2)
	for i, fd := range fds {
		file := os.NewFile(uintptr(fd), "image-codec-fixture")
		c, e := net.FileConn(file)
		file.Close()
		if e != nil {
			t.Fatal(e)
		}
		out[i] = c.(*net.UnixConn)
		t.Cleanup(func() { c.Close() })
		_ = out[i].SetDeadline(time.Now().Add(2 * time.Second))
	}
	return out[0], out[1]
}
func TestLinuxStandardServiceImageControlKeepsExactDescriptors(t *testing.T) {
	for _, test := range []struct {
		name  string
		limit int
		want  bool
	}{{"three", 3, true}, {"ordinary-one", 1, false}} {
		t.Run(test.name, func(t *testing.T) {
			a, b := imageSocketPair(t)
			var files []*os.File
			for i := 0; i < 3; i++ {
				f, e := os.Open("/proc/self/ns/net")
				if e != nil {
					t.Fatal(e)
				}
				defer f.Close()
				files = append(files, f)
			}
			if err := linuxStandardImageWriteFiles(a, map[string]int{"schema": 1}, files); err != nil {
				t.Fatal(err)
			}
			_, received, err := linuxStandardServiceReadFiles(b, test.limit)
			defer func() {
				for _, f := range received {
					f.Close()
				}
			}()
			if (err == nil) != test.want {
				t.Fatalf("exact descriptor inventory: %v", err)
			}
			if test.want && len(received) != 3 {
				t.Fatal("incomplete frozen process capabilities")
			}
		})
	}
}
func TestLinuxStandardServiceImageSourceLeasePinsOriginalInode(t *testing.T) {
	path := t.TempDir() + "/source.lock"
	source, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	if err = syscall.Flock(int(source.Fd()), syscall.LOCK_SH|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	owner, err := os.OpenFile(t.TempDir()+"/owner.lock", os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	a, err := captureLinuxStandardImageAuthority(nil, source, owner, path)
	if err != nil {
		t.Fatal(err)
	}
	defer a.sourceIdentity.Close()
	original, err := a.sourceIdentity.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if err = source.Close(); err != nil {
		t.Fatal(err)
	}
	a.source = nil
	replacement, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err = syscall.Flock(int(replacement.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatalf("readonly inode pin retained source admission lock: %v", err)
	}
	replacement.Close()
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	replacement, err = os.OpenFile(path, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	actual, _ := replacement.Stat()
	still, _ := a.sourceIdentity.Stat()
	if !os.SameFile(original, still) || os.SameFile(original, actual) {
		t.Fatal("original source inode was not retained across unlink")
	}
	s := &linuxStandardService{imageAuthority: a}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err = s.imageAcquireSource(ctx, nil); err == nil || !strings.Contains(err.Error(), "source lock changed original inode") {
		t.Fatalf("replacement source lease was admitted: %v", err)
	}
	if a.source != nil {
		t.Fatal("replacement source lease escaped failed reacquisition")
	}
}
func TestLinuxStandardServiceImageControlKeepsOriginalSequence(t *testing.T) {
	a, b := imageSocketPair(t)
	e := imageEnvelopeFixture()
	q := linuxStandardImageUpgradeControl{Schema: 1, Sequence: 1, Action: "status", DeadlineNS: e.DeadlineNS, Envelope: &e}
	body, _ := json.Marshal(q)
	state := &linuxStandardServiceImageUpgradeResponse{Envelope: e, Phase: "aborted"}
	cached := &linuxStandardImageUpgradeControlReply{Schema: 1, Sequence: 1, Action: "status", Complete: true, Upgrade: state}
	r := &linuxStandardImageCoordinator{state: state, sequence: 1, last: body, reply: cached}
	done := make(chan error, 1)
	go func() { done <- r.serve(context.Background(), b) }()
	exchange := func(control linuxStandardImageUpgradeControl) linuxStandardImageUpgradeControlReply {
		t.Helper()
		if err := linuxStandardServiceWrite(a, control, nil); err != nil {
			t.Fatal(err)
		}
		body, files, err := linuxStandardServiceRead(a)
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 0 {
			for _, f := range files {
				f.Close()
			}
			t.Fatal("status replay transferred authority")
		}
		var response linuxStandardImageUpgradeControlReply
		if err = linuxStandardServiceDecode(body, &response); err != nil {
			t.Fatal(err)
		}
		return response
	}
	if response := exchange(q); !response.Complete || response.Upgrade.Phase != "aborted" {
		t.Fatal("identical original reply was not retained")
	}
	changed := q
	changed.Action = "commit"
	if response := exchange(changed); response.Complete || !strings.Contains(response.Error, "replay changed original sequence") {
		t.Fatal("changed replay entered another operation")
	}
	if response := exchange(q); !response.Complete || response.Upgrade.Phase != "aborted" {
		t.Fatal("rejected replay discarded retained terminal reply")
	}
	if err := a.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("terminal original coordinator did not join EOF")
	}
}
func TestLinuxStandardServiceImagePromotionRejectsExtraCode(t *testing.T) {
	for _, kind := range []string{"exact", "extra-tree", "extra-helper", "private-preserved"} {
		t.Run(kind, func(t *testing.T) {
			base, err := os.MkdirTemp("/run", "rvi-code-")
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(base)
			root := base + "/root"
			if err = os.Mkdir(root, 0700); err != nil {
				t.Fatal(err)
			}
			image := []byte("exact admitted image")
			helper := []byte("exact admitted helper")
			manifest := linuxStandardGenerationManifestData{Schema: 1, Files: []linuxStandardGenerationEntry{{Path: "client", Mode: 0700}, {Path: "client/helper", Mode: 0600, SHA256: linuxStandardImageBytesDigest(helper)}, {Path: "router-vpn-client", Mode: 0755, SHA256: linuxStandardImageBytesDigest(image)}}}
			raw, _ := json.Marshal(manifest)
			selection := linuxStandardGenerationSelection{1, linuxStandardImageBytesDigest(raw), linuxStandardImageBytesDigest(image)}
			directory := root + ".service-generations/" + selection.Generation
			if err = os.MkdirAll(directory+"/client", 0700); err != nil {
				t.Fatal(err)
			}
			if err = os.Mkdir(root+"/client", 0700); err != nil {
				t.Fatal(err)
			}
			for _, where := range []string{directory, root} {
				if err = os.WriteFile(where+"/client/helper", helper, 0600); err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(where+"/router-vpn-client", image, 0755); err != nil {
					t.Fatal(err)
				}
			}
			if err = os.WriteFile(directory+"/generation.json", raw, 0600); err != nil {
				t.Fatal(err)
			}
			if err = os.WriteFile(directory+".lock", nil, 0600); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			g, err := captureLinuxStandardServiceGenerationSelection(ctx, root, selection)
			if err != nil {
				t.Fatal(err)
			}
			defer g.Close()
			switch kind {
			case "extra-tree":
				err = os.WriteFile(root+"/client/foreign", []byte("foreign"), 0600)
			case "extra-helper":
				err = os.WriteFile(root+"/router-vpn-update", []byte("foreign"), 0700)
			case "private-preserved":
				err = os.WriteFile(root+"/app.cfg", []byte("original private data"), 0600)
			}
			if err != nil {
				t.Fatal(err)
			}
			err = verifyLinuxStandardGenerationCode(ctx, root, g)
			want := kind == "exact" || kind == "private-preserved"
			if (err == nil) != want {
				t.Fatalf("code-only inventory %s: %v", kind, err)
			}
		})
	}
}

// This is a retained-reservation comparison fixture with actual privileged
// kernel peers. It does not model a native guard or supply creator authority.
func TestLinuxStandardServiceImageReservationLookupKeepsOriginalPeer(t *testing.T) {
	original, _, stop := linuxStandardPeerFixture(t)
	defer stop()
	for _, kind := range []string{"lost-reply", "foreign-peer", "deadline", "generation", "scope", "expired-observation"} {
		t.Run(kind, func(t *testing.T) {
			e := imageEnvelopeFixture()
			e.DeadlineNS = time.Now().Add(-time.Second).UnixNano()
			retained := &linuxStandardImageUpgrade{envelope: e, phase: "reserved", coordinator: original}
			s := &linuxStandardService{imageUpgrade: retained}
			q := linuxStandardServiceRequest{Schema: 1, Action: "image-reservation", Session: e.NewGeneration.Generation[:32], BudgetMS: 1000, DeadlineNS: time.Now().Add(time.Second).UnixNano(), ImageUpgrade: &linuxStandardServiceImageUpgradeRequest{Generation: &e.NewGeneration, DeadlineNS: e.DeadlineNS}}
			peer := original
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			switch kind {
			case "foreign-peer":
				var finish func()
				peer, _, finish = linuxStandardPeerFixture(t)
				defer finish()
			case "deadline":
				q.ImageUpgrade.DeadlineNS++
			case "generation":
				changed := e.NewGeneration
				changed.Generation = strings.Repeat("c", 64)
				q.ImageUpgrade.Generation = &changed
			case "scope":
				q.ImageUpgrade.Source = &mobiletor.DesktopLinuxClosedTransferSnapshot{}
			case "expired-observation":
				cancel()
			}
			result, fd, err := s.imageRequest(ctx, peer, "coordinator", q)
			if fd != nil {
				fd.Close()
				t.Fatal("reservation read transferred native authority")
			}
			if kind == "lost-reply" {
				if err != nil || result == nil || !reflectImageEnvelope(result.Envelope, retained.envelope) {
					t.Fatalf("original lost reply lookup failed: %v", err)
				}
				if result.Ready || result.Frozen {
					t.Fatal("partial reservation became a native completion")
				}
			} else if err == nil {
				t.Fatal("foreign or expired observation recovered original reservation")
			}
			if s.imageUpgrade != retained || retained.transfer != nil || retained.cleanupDeadline != 0 || retained.envelope.DeadlineNS != e.DeadlineNS {
				t.Fatal("read-only reservation lookup recreated or renewed original operation")
			}
		})
	}
}
func TestLinuxStandardServiceImageSuccessorWaitKeepsOriginalConnect(t *testing.T) {
	t.Run("actual-listener", func(t *testing.T) {
		directory, err := os.MkdirTemp("/run", "rvi-wait-")
		if err != nil {
			t.Fatal(err)
		}
		defer os.RemoveAll(directory)
		path := directory + "/candidate.sock"
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		first := make(chan struct{})
		created := make(chan *net.UnixListener, 1)
		failure := make(chan error, 1)
		go func() {
			select {
			case <-ctx.Done():
				failure <- ctx.Err()
				return
			case <-first:
			}
			listener, err := net.ListenUnix("unixpacket", &net.UnixAddr{Name: path, Net: "unixpacket"})
			if err != nil {
				failure <- err
				return
			}
			created <- listener
		}()
		attempts := 0
		_, err = linuxStandardImageWaitForListener(ctx, func() (*linuxStandardServiceImageUpgradeResponse, error) {
			attempts++
			connection, e := linuxStandardImageDial(ctx, path, false)
			if attempts == 1 {
				close(first)
			}
			if connection != nil {
				connection.Close()
			}
			return nil, e
		})
		select {
		case listener := <-created:
			listener.Close()
		case e := <-failure:
			t.Fatal(e)
		case <-ctx.Done():
			t.Fatal("fixture listener did not join original admission")
		}
		if err != nil || attempts < 2 {
			t.Fatalf("asynchronous original listener was not awaited: %v", err)
		}
	})
	t.Run("source-disappearance", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		calls := 0
		_, err := linuxStandardImageWaitForListener(ctx, func() (*linuxStandardServiceImageUpgradeResponse, error) {
			calls++
			_, e := os.Lstat(t.TempDir() + "/missing-generation")
			return nil, e
		})
		if err == nil || calls != 1 {
			t.Fatal("source disappearance was retried as listener startup")
		}
	})
	t.Run("mixed-loss", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		calls := 0
		lost := errors.New("actual source changed")
		_, err := linuxStandardImageWaitForListener(ctx, func() (*linuxStandardServiceImageUpgradeResponse, error) {
			calls++
			return nil, errors.Join(&linuxStandardImageListenerPending{syscall.ENOENT}, lost)
		})
		if !errors.Is(err, lost) || calls != 1 {
			t.Fatal("mixed source failure was hidden by pending listener")
		}
	})
	t.Run("captured-peer", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		calls := 0
		_, err := linuxStandardImageWaitForListener(ctx, func() (*linuxStandardServiceImageUpgradeResponse, error) {
			calls++
			_, e := linuxStandardImageDial(ctx, t.TempDir()+"/retired.sock", true)
			return nil, e
		})
		if err == nil || calls != 1 {
			t.Fatal("captured peer disappearance admitted a replacement wait")
		}
	})
	t.Run("cancelled", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		calls := 0
		_, err := linuxStandardImageWaitForListener(ctx, func() (*linuxStandardServiceImageUpgradeResponse, error) {
			calls++
			cancel()
			return nil, &linuxStandardImageListenerPending{syscall.ENOENT}
		})
		if !errors.Is(err, context.Canceled) || calls != 1 {
			t.Fatal("listener wait renewed original cancellation")
		}
	})
}
