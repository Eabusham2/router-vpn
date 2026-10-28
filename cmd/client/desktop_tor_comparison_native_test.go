package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"router-vpn/internal/mobiletor"
)

// This is an explicit private-IPC child fixture. Its durations are fixture
// records, not Tor network evidence. Native adapter tests separately exercise
// the actual circuit/control and HTTP engines that produce these records.
func desktopTorComparisonChildFixture(kind string, root *os.Root, expected mobiletor.DesktopBridgeMetadata, write func(string, any)) func() {
	if !strings.HasPrefix(kind, "tor-compare-") && kind != "receipt-before-exit" {
		return func() {}
	}
	var record mobiletor.DesktopTorCompareStatus
	var due time.Time
	read := func(name string, target any) bool {
		raw, err := readDesktopRuntimeSnapshot(root, name, mobiletor.DesktopTorCompareFileLimit)
		return err == nil && decodeRelayControlJSON(raw, target) == nil
	}
	return func() {
		var cancel mobiletor.DesktopTorCompareRequest
		if read(mobiletor.DesktopTorCompareCancelFile, &cancel) && record.Generation != 0 && cancel == record.DesktopTorCompareRequest && record.Action != mobiletor.DesktopTorCompareClose {
			if kind != "tor-compare-held" {
				record.Complete, record.Cancelled, record.ResponseNS = true, true, 0
			}
			_ = root.Remove(mobiletor.DesktopTorCompareCancelFile)
		}
		var request mobiletor.DesktopTorCompareRequest
		if read(mobiletor.DesktopTorCompareRequestFile, &request) && request.Validate(time.Now()) == nil && request.SessionID == expected.SessionID && request.SourceSHA256 == expected.SourceSHA256 && request.ConfigSHA256 == expected.ConfigSHA256 {
			prepare := request.Action == mobiletor.DesktopTorComparePrepare && request.Sequence == 1 && request.Generation > record.Generation && (record.Generation == 0 || record.Drained)
			next := record.Complete && !record.Drained && request.Generation == record.Generation && request.RequestID == record.RequestID && request.Target == record.Target && request.Sequence == record.Sequence+1
			if prepare || next {
				identity := record.IdentitySHA256
				if prepare {
					identity = request.RequestID + request.RequestID
				}
				record = mobiletor.DesktopTorCompareStatus{DesktopTorCompareRequest: request, IdentitySHA256: identity}
				write(mobiletor.DesktopTorCompareStatusFile, record)
				_ = root.Remove(mobiletor.DesktopTorCompareRequestFile)
				due = time.Now().Add(15 * time.Millisecond)
				if kind == "tor-compare-slow-mailbox" {
					due = time.Now().Add(120 * time.Millisecond)
				}
			}
		}
		if record.Generation == 0 {
			return
		}
		_, released := root.Stat("comparison-release.fixture")
		held := kind == "tor-compare-held" && record.Action == mobiletor.DesktopTorCompareLast || kind == "tor-compare-close-delay" && record.Action == mobiletor.DesktopTorCompareClose
		if !record.Complete && time.Now().After(due) && (!held || released == nil) {
			record.Complete = true
			switch record.Action {
			case mobiletor.DesktopTorCompareLast:
				record.ResponseNS = int64(17 * time.Millisecond)
			case mobiletor.DesktopTorCompareExternal:
				record.ResponseNS = int64(31 * time.Millisecond)
			case mobiletor.DesktopTorCompareClose:
				record.Drained = true
			}
		}
		published := record
		if record.Complete && record.Action == mobiletor.DesktopTorCompareLast {
			switch strings.TrimPrefix(kind, "tor-compare-wrong-") {
			case "schema":
				published.Schema++
			case "session":
				published.SessionID = strings.Repeat("0", 32)
			case "source":
				published.SourceSHA256 = strings.Repeat("0", 64)
			case "config":
				published.ConfigSHA256 = strings.Repeat("0", 64)
			case "generation":
				published.Generation++
			case "request":
				published.RequestID = strings.Repeat("0", 32)
			case "sequence":
				published.Sequence++
			case "action":
				published.Action = mobiletor.DesktopTorCompareExternal
			case "target":
				published.Target = "https://1.0.0.1/cdn-cgi/trace"
			case "expiry":
				published.ExpiresAt++
			case "identity":
				published.IdentitySHA256 = strings.Repeat("0", 64)
			case "empty-identity":
				published.IdentitySHA256 = ""
			case "zero":
				published.ResponseNS = 0
			case "negative":
				published.ResponseNS = -1
			case "over-budget":
				published.ResponseNS = int64(11 * time.Second)
			case "failure-timing":
				published.Failed = true
			case "cancel-timing":
				published.Cancelled = true
			case "stop-required":
				published.StopRequired = true
			case "drained":
				published.Drained = true
			case "incomplete":
				published.Complete = false
			}
		}
		write(mobiletor.DesktopTorCompareStatusFile, published)
	}
}

func desktopTorComparisonFixture(t *testing.T, kind string) (*app, *desktopNodeLaunch, *desktopTorComparisonClient) {
	t.Helper()
	a, launch, _ := desktopTorRunningFixture(t, kind)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	c, err := newDesktopTorComparisonClient(a, launch, "https://1.1.1.1/cdn-cgi/trace")
	if err != nil || c == nil {
		t.Fatal("capture comparison", err)
	}
	t.Cleanup(func() {
		c.Cancel()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = requestDesktopTorStop(ctx, a, launch, launch.command)
		_ = c.Close(ctx)
	})
	return a, launch, c
}

func releaseDesktopTorComparisonFixture(t *testing.T, launch *desktopNodeLaunch) {
	t.Helper()
	file, err := launch.directoryRoot.OpenFile("comparison-release.fixture", os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, writeErr := file.Write([]byte("release exact retained IPC fixture"))
	if closeErr := file.Close(); writeErr != nil || closeErr != nil {
		t.Fatal("fixture release publication", writeErr, closeErr)
	}
}

func waitDesktopTorComparisonAction(t *testing.T, c *desktopTorComparisonClient, action string) mobiletor.DesktopTorCompareStatus {
	t.Helper()
	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		record, err := c.read(false)
		if err == nil && record.Action == action {
			return record
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("native comparison fixture did not enter", action)
	return mobiletor.DesktopTorCompareStatus{}
}

func TestDesktopTorComparisonActualIPCUsesNativeDurationsAndRetainsConnection(t *testing.T) {
	a, launch, c := desktopTorComparisonFixture(t, "tor-compare-slow-mailbox")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if c.Identity() != "" || c.Prepare(ctx) != nil || c.Identity() == "" || c.Verify(ctx) != nil {
		t.Fatal("captured comparison preparation or independent verification failed")
	}
	identity := c.Identity()
	started := time.Now()
	last, err := c.ProbeLast(ctx)
	if err != nil || last != 17*time.Millisecond || time.Since(started) <= last {
		t.Fatal("controller used mailbox elapsed time as relay HTTP response time", last, err)
	}
	external, err := c.ProbeExternal(ctx, c.base.Target)
	if err != nil || external != 31*time.Millisecond || c.Identity() != identity {
		t.Fatal("controller changed target, identity or external HTTP response", external, err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal("comparison drain", err)
	}
	if desktopNodeProcessExited(launch) || a.desktopTorCurrent(launch) != nil || c.Identity() != "" || c.claimed() {
		t.Fatal("closing measurements stopped the retained VPN or retained a drained claim")
	}
	replacement, err := newDesktopTorComparisonClient(a, launch, c.base.Target)
	if err != nil || replacement.base.Generation <= c.base.Generation || replacement.Prepare(ctx) != nil {
		t.Fatal("drained native owner could not admit a distinct generation", err)
	}
	if err := c.Close(ctx); err != nil || !replacement.claimed() {
		t.Fatal("old repeated cleanup disturbed the replacement comparison", err)
	}
	if err := replacement.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopTorComparisonActualIPCRejectsChangedReceiptsWithoutScoring(t *testing.T) {
	for _, kind := range []string{"schema", "session", "source", "config", "generation", "request", "sequence", "action", "target", "expiry", "identity", "empty-identity", "zero", "negative", "over-budget", "failure-timing", "cancel-timing", "stop-required", "drained", "incomplete"} {
		t.Run(kind, func(t *testing.T) {
			_, _, c := desktopTorComparisonFixture(t, "tor-compare-wrong-"+kind)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := c.Prepare(ctx); err != nil {
				t.Fatal(err)
			}
			if duration, err := c.ProbeLast(ctx); err == nil || duration != 0 || c.Identity() != "" || !c.claimed() {
				t.Fatal("invalid native result was scored or its uncertain owner discarded", duration, err)
			}
		})
	}
}

func TestDesktopTorComparisonCancellationRetainsEnteredActionAndRetryableClose(t *testing.T) {
	a, launch, c := desktopTorComparisonFixture(t, "tor-compare-held")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() { _, err := c.ProbeLast(ctx); result <- err }()
	waitDesktopTorComparisonAction(t, c, mobiletor.DesktopTorCompareLast)
	c.Cancel()
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("cancelled probe returned a measurement")
		}
	case <-ctx.Done():
		t.Fatal("cancel could not return an entered action")
	}
	short, shortCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	if err := c.Close(short); err == nil || !c.claimed() {
		t.Fatal("cleanup timeout discarded native ownership", err)
	}
	shortCancel()
	if other, err := newDesktopTorComparisonClient(a, launch, c.base.Target); err == nil || other != nil {
		t.Fatal("replacement comparison entered before old native resources drained")
	}
	releaseDesktopTorComparisonFixture(t, launch)
	if err := c.Close(ctx); err != nil || c.claimed() || desktopNodeProcessExited(launch) {
		t.Fatal("retry did not drain only the retained measurement", err)
	}
	_ = launch.directoryRoot.Remove("comparison-release.fixture")
}

func TestDesktopTorComparisonCloseWaitExpiryCannotRetirePendingNativeClose(t *testing.T) {
	_, launch, c := desktopTorComparisonFixture(t, "tor-compare-close-delay")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	short, shortCancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- c.Close(short) }()
	first := waitDesktopTorComparisonAction(t, c, mobiletor.DesktopTorCompareClose)
	shortCancel()
	if err := <-finished; err == nil || !c.claimed() {
		t.Fatal("expired Close abandoned its native command")
	}
	releaseDesktopTorComparisonFixture(t, launch)
	if err := c.Close(ctx); err != nil {
		t.Fatal("same retained Close could not complete", err)
	}
	final, err := c.read(true)
	if err != nil || final.DesktopTorCompareRequest != first.DesktopTorCompareRequest || !final.Drained {
		t.Fatal("Close retry fabricated a new action or lost drain identity", err)
	}
	_ = launch.directoryRoot.Remove("comparison-release.fixture")
}

func TestDesktopTorComparisonCleanupFollowsOnlyCapturedDirectory(t *testing.T) {
	_, launch, c := desktopTorComparisonFixture(t, "tor-compare-good")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Prepare(ctx); err != nil {
		t.Fatal(err)
	}
	original := launch.directory
	if err := os.Rename(original, original+"-retired"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(original, mobiletor.DesktopTorCompareCancelFile)
	if err := os.WriteFile(sentinel, []byte("replacement owner"), 0600); err != nil {
		t.Fatal(err)
	}
	if result, err := c.ProbeExternal(ctx, c.base.Target); err == nil || result != 0 {
		t.Fatal("renamed old runtime adopted a measurement", result, err)
	}
	short, shortCancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer shortCancel()
	if err := c.Close(short); err == nil || !c.claimed() || c.nativeJoined() {
		t.Fatal("replaced directory or unacknowledged process exit discarded the old owner", err)
	}
	oldClose, err := readDesktopRuntimeSnapshot(launch.directoryRoot, mobiletor.DesktopTorCompareRequestFile, mobiletor.DesktopTorCompareFileLimit)
	var captured mobiletor.DesktopTorCompareRequest
	if err != nil || decodeRelayControlJSON(oldClose, &captured) != nil || captured != c.last.request || captured.Action != mobiletor.DesktopTorCompareClose {
		t.Fatal("cleanup did not address the original pinned workspace", err)
	}
	raw, err := os.ReadFile(sentinel)
	if err != nil || string(raw) != "replacement owner" {
		t.Fatal("old cleanup changed replacement files", err)
	}
}

func TestDesktopTorComparisonRequiresStoppedReceiptAndActualProcessJoin(t *testing.T) {
	a, launch, release := desktopTorRunningFixture(t, "receipt-before-exit")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := a.waitDesktopTorProof(ctx, launch); err != nil {
		t.Fatal(err)
	}
	c, err := newDesktopTorComparisonClient(a, launch, "https://1.1.1.1/cdn-cgi/trace")
	if err != nil || c.Prepare(ctx) != nil {
		t.Fatal("comparison setup failed", err)
	}
	request, _ := json.Marshal(desktopExternalStop{Schema: 1, SessionID: c.base.SessionID, SourceSHA256: c.base.SourceSHA256})
	if err := writeDesktopRuntimeFile(launch, "stop.json", request, true); err != nil {
		t.Fatal(err)
	}
	for {
		if stopped, _ := desktopTorStopped(launch); stopped {
			break
		}
		if ctx.Err() != nil {
			t.Fatal("fixture never published its explicit terminal receipt")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if c.nativeJoined() {
		t.Fatal("terminal receipt replaced actual process and output-reader join")
	}
	if err := os.WriteFile(release, []byte("join exact fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case <-desktopNodeProcessDone(launch):
	case <-ctx.Done():
		t.Fatal("fixture did not join")
	}
	if !c.nativeJoined() || c.Close(ctx) != nil || c.claimed() {
		t.Fatal("checked exact whole-runtime drain did not release measurement claim")
	}
}

func TestDesktopTorComparisonUnusedClaimAndTargetSubstitution(t *testing.T) {
	a, launch, c := desktopTorComparisonFixture(t, "tor-compare-good")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := c.Close(ctx); err != nil || c.claimed() {
		t.Fatal("unused claim retained nonexistent native work", err)
	}
	next, err := newDesktopTorComparisonClient(a, launch, c.base.Target)
	if err != nil || next.base.Generation != c.base.Generation+1 || next.Prepare(ctx) != nil {
		t.Fatal("unused generation prevented next independently captured preparation", err)
	}
	if result, err := next.ProbeExternal(ctx, "https://1.0.0.1/cdn-cgi/trace"); result != 0 || err == nil {
		t.Fatal("external endpoint changed within a comparison", result, err)
	}
	if err := next.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
