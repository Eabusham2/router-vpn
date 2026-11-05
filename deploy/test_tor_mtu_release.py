#!/usr/bin/env python3
"""Execute actual Tor lease methods and test with only the native owner modeled.

The full Box/kernel fixture remains mandatory in test_desktop_node_physical.py.
This portable control checks cancellation accounting without requiring netlink.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def declaration(source, signature):
    start = source.index(signature)
    end = source.index("\n}", start) + 2
    return source[start:end]


BOUNDARY = r'''
package box
import("context";"sync";"sync/atomic";"testing")
type desktopTorBoxFixture struct{}
type modeledPolicy struct{}
func (modeledPolicy) Metadata() modeledPolicy {return modeledPolicy{}}
func (modeledPolicy) AllowMTUOptimization() bool{return true}
type modeledActivity struct{active atomic.Int64}
func(a *modeledActivity) beginMeasurement()(func(),error){a.active.Add(1);return func(){a.active.Add(-1)},nil}
type RouterVPNDesktopTor struct{
 mu sync.Mutex;workers sync.WaitGroup;closing bool
 mtuLease atomic.Pointer[RouterVPNDesktopTorMTULease]
 policy modeledPolicy;activity modeledActivity;ctx context.Context
}
func(r *RouterVPNDesktopTor) Healthy()bool{return r.ctx.Err()==nil}
func(r *RouterVPNDesktopTor) readerLifetimeCurrent()bool{return r.ctx.Err()==nil}
func desktopTorMTULeaseFixture(t *testing.T)(*desktopTorBoxFixture,*RouterVPNDesktopTor,*RouterVPNDesktopTorMTULease){
 ctx,cancel:=context.WithCancel(context.Background())
 owner:=&RouterVPNDesktopTor{ctx:ctx};lease:=&RouterVPNDesktopTorMTULease{owner:owner,ctx:ctx,cancel:cancel};owner.mtuLease.Store(lease)
 t.Cleanup(func(){cancel();owner.workers.Wait();if owner.activity.active.Load()!=0{t.Error("inherited measurement activity leaked")}})
 return &desktopTorBoxFixture{},owner,lease
}
'''


def execute():
    compiler = shutil.which("go")
    if not compiler:
        raise RuntimeError("Go required for actual Tor lease cancellation control")
    source = (ROOT / "mobile/desktop/tor_box_mtu.go.tmpl").read_text()
    tests = (ROOT / "mobile/desktop/tor_box_mtu_test.go.tmpl").read_text()
    signatures = ["type RouterVPNDesktopTorMTULease struct", "type routerVPNDesktopTorMTUActivity struct",
                  "func (a *routerVPNDesktopTorMTUActivity) retain(",
                  "func (a *routerVPNDesktopTorMTUActivity) release(",
                  "func (a *routerVPNDesktopTorMTUActivity) current(",
                  "func (l *RouterVPNDesktopTorMTULease) BeginMeasurement(",
                  "func (l *RouterVPNDesktopTorMTULease) Healthy(",
                  "func (l *RouterVPNDesktopTorMTULease) currentLifetime(",
                  "func (l *RouterVPNDesktopTorMTULease) RegisterOperation(",
                  "func (l *RouterVPNDesktopTorMTULease) Lifetime("]
    actual = 'package box\nimport("context";"encoding/hex";"errors";"sync";"sync/atomic";"leasecontrol/mobiletor")\ntype routerVPNDesktopTorMTUActivityKey struct{}\n' + "\n\n".join(declaration(source, s) for s in signatures)
    test = 'package box\nimport("context";"errors";"strings";"sync";"testing";"time")\n' + declaration(tests, "func TestRouterVPNDesktopTorMTUReleaseWithHeldOwner(")
    before = "\t\t\tl.active.Add(-1)\n"
    if actual.count(before) != 1:
        raise RuntimeError("actual Tor lease release boundary changed")
    mutant = actual.replace(before, "\t\t\tr.mu.Lock()\n" + before + "\t\t\tr.mu.Unlock()\n", 1)
    env = dict(os.environ, GOWORK="off", GOFLAGS="", GOTOOLCHAIN="local")
    host_os, host_arch = subprocess.check_output([compiler, "env", "GOHOSTOS", "GOHOSTARCH"], env=env, text=True).split()
    race = [] if (host_os, host_arch) == ("windows", "arm64") else ["-race"]
    env.update(GOOS=host_os, GOARCH=host_arch, CGO_ENABLED="1" if race else "0")
    with tempfile.TemporaryDirectory(prefix="tor-lease-release-") as temporary:
        folder = Path(temporary)
        (folder / "go.mod").write_text("module leasecontrol\n\ngo 1.24.0\n")
        (folder / "mobiletor").mkdir()
        (folder / "mobiletor/transition.go").write_text("package mobiletor\ntype DesktopBridgeMTUTransition struct{}\n")
        (folder / "boundary_test.go").write_text(BOUNDARY)
        (folder / "lease_test.go").write_text(test)
        for name, code in (("current", actual), ("held-owner-mutation", mutant)):
            (folder / "lease.go").write_text(code)
            result = subprocess.run([compiler, "test", *race, "-count=1", "-timeout=15s", "-v", "."], cwd=folder, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
            if name == "current":
                if result.returncode != 0:
                    raise RuntimeError("actual Tor lease failed:\n" + result.stdout)
                for child in ("ordinary", "inherited-measurement"):
                    if "--- PASS: TestRouterVPNDesktopTorMTUReleaseWithHeldOwner/" + child not in result.stdout:
                        raise RuntimeError("actual Tor lease omitted " + child)
                print(result.stdout, end="")
            else:
                if result.returncode == 0 or result.stdout.count("cancelled MTU release waited on the owner mutex") != 2 or "[build failed]" in result.stdout or "panic:" in result.stdout:
                    raise RuntimeError("held-owner mutation lacked the exact cancellation failure:\n" + result.stdout)
                print("Held-owner causal mutation rejected in both actual test leaves")


if __name__ == "__main__":
    execute()
