#!/usr/bin/env python3
"""Execute captured desktop network observation and its rejecting controls.

Linux mutation tests run only in a new owned network namespace. Windows/macOS
execute the actual read-only notification adapter; their platform route-change
acceptance remains a separate native/device boundary. No sleep is a callback
flush and no missing native capability is converted into a pass.
"""
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "internal/desktopnetwork"
PARENTS = (
    "TestNetworkCohortOwnedTransitionsAndTransient",
    "TestNetworkCohortPhysicalAndUnclaimedChangesStayInvalid",
    "TestNetworkCohortOriginalAndUnregisterOwnership",
    "TestNetworkReceiptAndLinuxWireStrictIdentity",
    "TestNetworkReceiptMTUMatchesAddressFamily",
    "TestDarwinCloneRequiresExactCapturedParent",
    "TestLinuxMulticastFIBIdentityRemainsAmbient",
    "TestWindowsUnlimitedLoopbackMTURetainsNativeIdentity",
    "TestLinuxOwnedGotoRuleTransitions",
)


def execute(argv, *, cwd=ROOT, env=None, timeout=150, succeeds=True):
    completed = subprocess.run(argv, cwd=cwd, env=env, text=True,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               timeout=timeout)
    if succeeds and completed.returncode:
        print(completed.stdout, end="")
        raise RuntimeError("native network observer command failed")
    return completed


def require_pass(output, name):
    if f"--- PASS: {name} " not in output:
        raise RuntimeError("network gate omitted its executed case: " + name)


def main():
    if sys.platform not in ("linux", "darwin", "win32"):
        raise RuntimeError("desktop network observer gate has no native adapter on this host")
    go = shutil.which("go")
    if not go:
        raise RuntimeError("Go is required for the native network observer gate")
    env = dict(os.environ)
    env.pop("ROUTERVPN_NATIVE_NETWORK_EVENTS", None)
    env.pop("ROUTERVPN_NETWORK_PARENT_NAMESPACE", None)
    env.update(GOWORK="off", GOFLAGS="")
    base = execute([go, "test", "-race", "-v", "-count=1", "-timeout=120s",
                    "./internal/desktopnetwork"], env=env)
    for parent in PARENTS:
        require_pass(base.stdout, parent)
    if sys.platform == "linux":
        require_pass(base.stdout, "TestLinuxRouteTableCompatibilityAndOwnedCarrierTransition")
    print("Captured network state/receipt and transition cases passed.")

    native_env = dict(env, ROUTERVPN_NATIVE_NETWORK_EVENTS="1")
    read_only = execute([go, "test", "-race", "-v", "-count=1", "-timeout=30s",
                         "./internal/desktopnetwork", "-run", "^TestNativeNetworkObserverReadOnlyBarrier$"], env=native_env, timeout=60)
    require_pass(read_only.stdout, "TestNativeNetworkObserverReadOnlyBarrier")
    print("Actual native read-only subscription, snapshot and joined close passed.")

    with tempfile.TemporaryDirectory(prefix="routervpn-network-gate-") as temporary:
        work = Path(temporary)
        if sys.platform == "linux":
            binary = work / "network-native.test"
            execute([go, "test", "-race", "-c", "-o", str(binary), "./internal/desktopnetwork"], env=env)
            parent = os.readlink("/proc/self/ns/net")
            command = ["/usr/bin/env", "ROUTERVPN_NATIVE_NETWORK_EVENTS=1",
                       "ROUTERVPN_NETWORK_PARENT_NAMESPACE=" + parent,
                       "/usr/bin/unshare", "--user", "--map-root-user", "--net", "--fork", str(binary),
                       "-test.v", "-test.timeout=45s", "-test.run=^TestLinuxNativeNetworkCohortEvents$"]
            native = execute(command, env=env, timeout=60)
            require_pass(native.stdout, "TestLinuxNativeNetworkCohortEvents")
            for leaf in ("unchanged-physical-owner", "gateway-away-and-back", "address-away-and-back",
                         "mtu-away-and-back", "unclaimed-virtual-start-and-stop",
                         "owned-interface-route-rule-and-drain", "foreign-rule-without-interface-key",
                         "proved-transient-closes-before-final-off"):
                require_pass(native.stdout, "TestLinuxNativeNetworkCohortEvents/" + leaf)
            print("Eight real isolated Linux link/address/gateway/route/rule and join cases passed.")

        mutant = work / "mutant"
        mutant.mkdir()
        (mutant / "go.mod").write_text("module routervpn-network-observer-fixture\n\ngo 1.25.0\n")
        for source in PACKAGE.glob("*.go"):
            if source.is_symlink():
                raise RuntimeError("linked network observer fixture source")
            shutil.copyfile(source, mutant / source.name)
        target = mutant / "observer.go"
        original = target.read_text()
        controls = (
            ("drop-physical-events", 'if !t.initializing && !t.transition {',
             'if event.Kind != "" { return }\n\tif !t.initializing && !t.transition {',
             "TestNetworkCohortPhysicalAndUnclaimedChangesStayInvalid", "gateway-away-and-back"),
            ("accept-unclaimed-transition", 'if !owned {\n\t\t\treturn t.failLocked(errors.New("native transition contained an unclaimed routing, address or interface event"))\n\t\t}',
             'if !owned { continue }', "TestNetworkCohortOriginalAndUnregisterOwnership", "unclaimed-failed-start"),
            ("skip-final-physical-snapshot", 'receiptKey(t.current) != receiptKey(current) || key != t.baseline {',
             'receiptKey(t.current) != receiptKey(current) || false && key != t.baseline {', "TestNetworkCohortOriginalAndUnregisterOwnership", "snapshot-after-callback-loss"),
            ("drop-late-close-event", 'late := t.failure != nil && !t.reportedFailure',
             'late := false', "TestNetworkCohortOriginalAndUnregisterOwnership", "late-callback-before-joined-close"),
        )
        for name, before, after, test, witness in controls:
            if original.count(before) != 1:
                raise RuntimeError("network negative-control boundary changed: " + name)
            try:
                target.write_text(original.replace(before, after, 1))
                result = execute([go, "test", "-race", "-v", "-count=1", "-timeout=60s", ".", "-run", "^" + test + "$"],
                                 cwd=mutant, env=env, timeout=90, succeeds=False)
                marker = "--- FAIL: " + test + "/" + witness + " "
                if result.returncode == 0 or marker not in result.stdout or "[build failed]" in result.stdout:
                    print(result.stdout, end="")
                    raise RuntimeError("network control did not reject the actual defect: " + name)
            finally:
                target.write_text(original)
            print("Executed network negative control rejected:", name)
        shape_controls = (
            ("multicast-not-unicast", "desktop_network_wire.go", "family, bits = 128, 32", "family, bits = 4, 32",
             "TestLinuxMulticastFIBIdentityRemainsAmbient", "128"),
            ("goto-needs-exact-target", "desktop_network_wire.go", "binary.LittleEndian.Uint32(current[offset+4:]) == target.Priority", "true",
             "TestLinuxOwnedGotoRuleTransitions", "2/wrong-target"),
            ("loopback-needs-native-mtu", "desktop_network_windows_shape.go", "row.MTU != ^uint32(0)", "false",
             "TestWindowsUnlimitedLoopbackMTURetainsNativeIdentity", "different-native-mtu"),
        )
        for name, filename, before, after, test, witness in shape_controls:
            target = mutant / filename
            original = target.read_text()
            if original.count(before) != 1:
                raise RuntimeError("network shape negative-control boundary changed: " + name)
            try:
                target.write_text(original.replace(before, after, 1))
                result = execute([go, "test", "-race", "-v", "-count=1", "-timeout=60s", ".", "-run", "^" + test + "$"],
                                 cwd=mutant, env=env, timeout=90, succeeds=False)
                marker = "--- FAIL: " + test + "/" + witness + " "
                if result.returncode == 0 or marker not in result.stdout or "[build failed]" in result.stdout:
                    print(result.stdout, end="")
                    raise RuntimeError("network shape control did not reject the actual defect: " + name)
            finally:
                target.write_text(original)
            print("Executed network shape negative control rejected:", name)
    print("Desktop captured network observer gate passed; native device transition acceptance remains separate.")


if __name__ == "__main__":
    main()
