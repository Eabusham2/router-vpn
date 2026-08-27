package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func testRecoveryController(t *testing.T) *controller {
	t.Helper()
	return &controller{
		statePath: filepath.Join(t.TempDir(), "update-controller.json"),
		state:     updateState{Version: 1, Status: "idle"},
	}
}

func TestRollbackComposeSnapshotIsPrivateAndExact(t *testing.T) {
	c := testRecoveryController(t)
	previous := testTemplate()
	if got := composeSHA(previous); got != testOldSHA {
		t.Fatalf("test previous compose SHA=%q", got)
	}
	if err := c.saveRollbackCompose(previous, testOldSHA); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(c.rollbackComposePath())
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("rollback snapshot mode=%#o", info.Mode().Perm())
	}
	loaded, err := c.loadRollbackCompose(testOldSHA)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != previous {
		t.Fatal("rollback snapshot changed compose bytes")
	}
}

func TestExactComposeIdentityRequiresOneExpectedSHA(t *testing.T) {
	exact := testTemplate()
	if !exactComposeIdentity(exact, testOldSHA) {
		t.Fatal("exact rollback compose was not recognized")
	}
	if exactComposeIdentity(exact, testNewSHA) {
		t.Fatal("wrong target SHA was accepted as exact rollback identity")
	}
	mixed := strings.Replace(exact, "router-vpn-agent:"+testOldSHA, "router-vpn-agent:"+testNewSHA, 1)
	if exactComposeIdentity(mixed, testOldSHA) || exactComposeIdentity(mixed, testNewSHA) {
		t.Fatal("mixed compose was accepted as an exact identity")
	}
	if exactComposeIdentity(exact, "short") {
		t.Fatal("non-SHA expected identity was accepted")
	}
}

func TestClearRollbackComposeRemovesValidatedStaleSnapshotBeforeNewTransaction(t *testing.T) {
	c := testRecoveryController(t)
	stale := strings.ReplaceAll(testTemplate(), testOldSHA, testNewSHA)
	if composeSHA(stale) != testNewSHA {
		t.Fatal("stale test compose is not exact new SHA")
	}
	if err := atomicWriteUpdaterPrivate(c.rollbackComposePath(), []byte(stale)); err != nil {
		t.Fatal(err)
	}
	if err := c.clearRollbackCompose(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(c.rollbackComposePath()); !os.IsNotExist(err) {
		t.Fatalf("validated stale snapshot survived preflight cleanup: %v", err)
	}
	if err := c.saveRollbackCompose(testTemplate(), testOldSHA); err != nil {
		t.Fatal(err)
	}
	loaded, err := c.loadRollbackCompose(testOldSHA)
	if err != nil {
		t.Fatal(err)
	}
	if loaded != testTemplate() {
		t.Fatal("new transaction snapshot was not published exactly")
	}
}

func TestClearRollbackComposeUnsafeStaleSnapshotBlocksNewTransaction(t *testing.T) {
	c := testRecoveryController(t)
	path := c.rollbackComposePath()
	if err := os.WriteFile(path, []byte(testTemplate()), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := c.clearRollbackCompose(); err == nil {
		t.Fatal("unsafe stale rollback snapshot did not block preflight cleanup")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("unsafe stale snapshot was silently rewritten: %#o", info.Mode().Perm())
	}
}

func TestSaveRollbackComposeRefusesUnexpectedExistingSnapshotAfterTransactionStart(t *testing.T) {
	c := testRecoveryController(t)
	unexpected := strings.ReplaceAll(testTemplate(), testOldSHA, testNewSHA)
	if err := atomicWriteUpdaterPrivate(c.rollbackComposePath(), []byte(unexpected)); err != nil {
		t.Fatal(err)
	}
	if err := c.saveRollbackCompose(testTemplate(), testOldSHA); err == nil || !strings.Contains(err.Error(), "unexpectedly exists") {
		t.Fatalf("unexpected recovery evidence was overwritten/accepted: %v", err)
	}
	body, err := os.ReadFile(c.rollbackComposePath())
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != unexpected {
		t.Fatal("unexpected rollback evidence was modified")
	}
}

func TestRollbackComposeRejectsWrongExpectedSHA(t *testing.T) {
	c := testRecoveryController(t)
	if err := c.saveRollbackCompose(testTemplate(), testOldSHA); err != nil {
		t.Fatal(err)
	}
	if _, err := c.loadRollbackCompose(testNewSHA); err == nil || !strings.Contains(err.Error(), "mismatch") {
		t.Fatalf("wrong rollback identity was accepted: %v", err)
	}
}

func TestRollbackComposeRejectsMixedOrUnknownPreviousStack(t *testing.T) {
	c := testRecoveryController(t)
	mixed := strings.Replace(testTemplate(), "router-vpn-agent:"+testOldSHA, "router-vpn-agent:"+testNewSHA, 1)
	if got := composeSHA(mixed); got != "unknown" {
		t.Fatalf("mixed compose unexpectedly resolved to %q", got)
	}
	if err := c.saveRollbackCompose(mixed, testOldSHA); err == nil {
		t.Fatal("mixed previous stack was accepted as a rollback snapshot")
	}
}

func TestRollbackComposeSymlinkFailsClosed(t *testing.T) {
	c := testRecoveryController(t)
	realPath := filepath.Join(filepath.Dir(c.statePath), "real-compose")
	if err := os.WriteFile(realPath, []byte(testTemplate()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, c.rollbackComposePath()); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := c.saveRollbackCompose(testTemplate(), testOldSHA); err == nil {
		t.Fatal("symlink rollback snapshot target was accepted")
	}
	if _, err := c.loadRollbackCompose(testOldSHA); err == nil {
		t.Fatal("symlink rollback snapshot was accepted for recovery")
	}
	got, err := os.ReadFile(realPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != testTemplate() {
		t.Fatal("symlink target was modified")
	}
}

func TestClearRollbackComposeRefusesSymlink(t *testing.T) {
	c := testRecoveryController(t)
	realPath := filepath.Join(filepath.Dir(c.statePath), "real-compose")
	if err := os.WriteFile(realPath, []byte(testTemplate()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(realPath, c.rollbackComposePath()); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := c.clearRollbackCompose(); err == nil {
		t.Fatal("clear removed/accepted a symlink rollback path")
	}
	if _, err := os.Lstat(c.rollbackComposePath()); err != nil {
		t.Fatalf("symlink unexpectedly removed: %v", err)
	}
}

func TestInterruptedPreDeploymentApplyingCanFailWithoutSnapshot(t *testing.T) {
	c := testRecoveryController(t)
	c.state = updateState{Version: 1, Status: "applying", TargetSHA: testNewSHA}
	if err := c.reconcileRecovery(); err != nil {
		t.Fatal(err)
	}
	if c.state.Status != "failed" {
		t.Fatalf("status=%q", c.state.Status)
	}
	if !strings.Contains(c.state.Message, "before Portainer deployment began") {
		t.Fatalf("message=%q", c.state.Message)
	}
	body, err := readUpdaterPrivate(c.statePath, 64<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"status": "failed"`) {
		t.Fatalf("durable terminal state missing: %s", body)
	}
}
