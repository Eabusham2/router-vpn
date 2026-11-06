//go:build linux

package desktopnetwork

import (
	"context"
	"os"
	"runtime"
	"testing"
	"time"
)

func TestResolvedNamespaceDescriptorProvenance(t *testing.T) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	original, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer original.Close()
	info, err := original.Stat()
	if err != nil {
		t.Fatal(err)
	}
	observer := &linuxObserver{namespace: original, originalNamespace: original, namespaceInfo: info}
	_, ino, err := observer.resolvedNamespaceCurrent()
	if err != nil || ino == 0 {
		t.Fatal("original descriptor lost", err)
	}
	successor, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Close()
	observer.namespace = successor
	if _, _, err = observer.resolvedNamespaceCurrent(); err == nil {
		t.Fatal("same namespace adopted successor capability")
	}
	observer.namespace = original
	observer.closing = true
	if _, _, err = observer.resolvedNamespaceCurrent(); err == nil {
		t.Fatal("closing observer retained namespace authority")
	}
	observer.closing = false
	other, err := os.Stat("/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	observer.namespaceInfo = other
	if _, _, err = observer.resolvedNamespaceCurrent(); err == nil {
		t.Fatal("different native object treated as namespace")
	}
	observer.namespaceInfo = info
	original.Close()
	if _, _, err = observer.resolvedNamespaceCurrent(); err == nil {
		t.Fatal("closed original descriptor accepted")
	}
}

func TestResolvedOriginalObserverNamespace(t *testing.T) {
	if os.Getenv("ROUTERVPN_NATIVE_NETWORK_EVENTS") != "1" {
		t.Skip("requires explicit native network observer gate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	tracker, err := Open(ctx, nil)
	if err != nil {
		t.Fatal("actual subscribed physical observer", err)
	}
	defer tracker.Close()
	dev, ino, indexes, err := tracker.ResolvedNamespace(ctx)
	if err != nil || ino == 0 || len(indexes) == 0 {
		t.Fatal("actual original namespace missing", dev, ino, indexes, err)
	}
	for i, index := range indexes {
		if index <= 0 || i > 0 && index <= indexes[i-1] {
			t.Fatal("noncanonical original physical links")
		}
	}
	indexes[0] = 99999
	_, _, again, err := tracker.ResolvedNamespace(ctx)
	if err != nil || again[0] == 99999 {
		t.Fatal("namespace projection aliases mutable caller", err)
	}
	original := tracker.native.(*linuxObserver)
	replacement, err := os.Open("/proc/thread-self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	defer replacement.Close()
	old := original.namespace
	original.namespace = replacement
	if _, _, _, err = tracker.ResolvedNamespace(ctx); err == nil {
		t.Fatal("same numeric namespace adopted replacement descriptor")
	}
	original.namespace = old
	if err = tracker.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = tracker.ResolvedNamespace(ctx); err == nil {
		t.Fatal("closed physical observer retained resolver authority")
	}
}
