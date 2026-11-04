#!/usr/bin/env python3
"""Execute captured desktop network observation and its rejecting controls.

Linux mutation tests run only in a new owned network namespace. Windows/macOS
execute the actual read-only notification adapter; their platform route-change
acceptance remains a separate native/device boundary. No sleep is a callback
flush and no missing native capability is converted into a pass.
"""
from pathlib import Path
import importlib.util
import os
import shutil
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "internal/desktopnetwork"
PARENTS = (
    "TestNetworkRetainedLifetimeKeepsOriginalOperationBudget",
    "TestNetworkInitializationCannotAdoptCancelledCaller",
    "TestNetworkCohortOwnedTransitionsAndTransient",
    "TestNetworkCohortPhysicalAndUnclaimedChangesStayInvalid",
    "TestNetworkCohortOriginalAndUnregisterOwnership",
    "TestNetworkReceiptAndLinuxWireStrictIdentity",
    "TestNetworkReceiptMTUMatchesAddressFamily",
    "TestDarwinCloneRequiresExactCapturedParent",
    "TestDarwinCloneDerivesOriginalInterfaceScope",
    "TestDarwinLocalCloneRemainsObservedPolicy",
    "TestDarwinCloneScopeKeepsExactParentRefusals",
    "TestDarwinCloneFailureDiagnosticsStayBoundedAndPrivate",
    "TestDarwinIdleCacheRequiresOriginalNativeProof",
    "TestDarwinIdleCacheRefusesForgedOrChangedOriginal",
    "TestDarwinIdleCacheParentAndLifetimeConstraints",
    "TestLinuxMulticastFIBIdentityRemainsAmbient",
    "TestWindowsUnlimitedLoopbackMTURetainsNativeIdentity",
    "TestDarwinIncompleteInterfaceReadbackNeverAdmitsOrReplacesCapture",
    "TestDarwinInterfaceLinkIdentityWireBoundsAndOwnership",
    "TestDarwinUnusedInterfaceCaptureRequiresCompleteNativeIdentity",
    "TestDarwinUnusedInterfaceRetainsExactCohortIdentity",
    "TestDarwinUnusedInterfaceCannotOwnOrCarryTraffic",
    "TestDarwinUnusedInterfaceChangesStayLatched",
    "TestLinuxOwnedGotoRuleTransitions",
)
ROUTING_RETIREMENT_CASES = (
    "empty", "route-remains", "rule-remains", "duplicate-owned", "malformed", "unjoined", "failed-join",
    "owned-baseline", "incomplete-baseline", "read-failure", "cancelled", "late-cancel", "foreign-reader",
    "missing-ledger", "owned-baseline-alias", "new-foreign-route", "partial-ledger", "foreign-same-key", "incomplete-dump",
)


def check_routing_retirement_verdict(output):
    parent="TestLinuxRoutingRetirementRequiresOriginalJoinedInventory"
    for name in (parent, *(parent+"/"+leaf for leaf in ROUTING_RETIREMENT_CASES)):
        if output.count("--- PASS: "+name+" (") != 1:
            raise ValueError("Routing retirement gate omitted or duplicated its original boundary: "+name)
        if "--- SKIP: "+name+" (" in output or "--- FAIL: "+name+" (" in output:
            raise ValueError("Routing retirement gate skipped or failed: "+name)


NATIVE_CASES = (
    "ipv6-rule-away-and-back",
    "joined-original-routing-absence",
    "unchanged-physical-owner", "gateway-away-and-back", "address-away-and-back",
    "mtu-away-and-back", "unclaimed-virtual-start-and-stop",
    "owned-interface-route-rule-and-drain", "foreign-rule-without-interface-key",
    "proved-transient-closes-before-final-off",
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


def namespace_runner():
    spec = importlib.util.spec_from_file_location("desktop_network_owned_namespace", ROOT / "deploy/test_desktop_socket_uid.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


def namespace_fixture_image(binary):
    # Use the same retained, read/execute-only image staging as the native
    # routing receipt gate. The compiler workspace remains private: mapped
    # root in a new user namespace cannot traverse another user's 0700 root.
    spec = importlib.util.spec_from_file_location("desktop_network_fixture_image", ROOT / "deploy/test_desktop_node_physical.py")
    images = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(images)
    return images.routing_fixture_image(binary)


def linux_namespace_test(binary, env):
    if sys.platform != "linux":
        raise RuntimeError("the network mutation fixture requires native Linux")
    # Only this already-compiled image elevates. The trusted runner retains and
    # joins its exact new process group on timeout, including sudo descendants.
    # No host policy is changed to permit an unprivileged user-namespace map.
    runner = namespace_runner()
    sudo = runner.privilege_tool()
    parent = os.readlink("/proc/self/ns/net")
    with namespace_fixture_image(binary) as staged:
        command = ["/usr/bin/env", "ROUTERVPN_NATIVE_NETWORK_EVENTS=1",
                   "ROUTERVPN_NETWORK_PARENT_NAMESPACE=" + parent,
                   "/usr/bin/unshare", "--user", "--map-root-user", "--net", "--fork", str(staged),
                   "-test.v", "-test.timeout=45s", "-test.run=^TestLinuxNativeNetworkCohortEvents$"]
        if sudo is not None:
            command = [sudo, "-n", "--", *command]
        try:
            output = runner.run(command, cwd=ROOT, env=env, timeout=60, sudo=sudo)
        except subprocess.CalledProcessError as error:
            output = error.output or b""
            print(output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output, end="")
            raise RuntimeError("isolated native network fixture failed") from error
    parent = "TestLinuxNativeNetworkCohortEvents"
    require_pass(output, parent)
    for leaf in NATIVE_CASES:
        require_pass(output, parent + "/" + leaf)
    if "--- FAIL:" in output or "--- SKIP:" in output:
        raise RuntimeError("isolated native network fixture returned a failed or skipped case")
    return output


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
    execute([sys.executable, str(ROOT / "deploy/test_desktop_network_cohort_runner.py")], env=env, timeout=30)
    base = execute([go, "test", "-race", "-v", "-count=1", "-timeout=120s",
                    "./internal/desktopnetwork"], env=env)
    for parent in PARENTS:
        require_pass(base.stdout, parent)
    if sys.platform == "linux":
        check_routing_retirement_verdict(base.stdout)
        for parent in ("TestLinuxNetworkDumpCancellationJoinsOriginalSocket", "TestLinuxNetworkDumpStrictOriginalDatagrams", "TestLinuxRoutingRetirementRequiresOriginalJoinedInventory"):
            require_pass(base.stdout, parent)
    if sys.platform == "darwin":
        for parent in ("TestDarwinNetworkMessageAlignmentAndOwnership",
                       "TestDarwinNetworkMessageSocketAddressBounds",
                       "TestDarwinNetworkMessageRejectsIncompleteHeaders",
                       "TestDarwinInformationalMessageFraming",
                       "TestDarwinNetworkReceiveNativeSocket",
                       "TestDarwinNetworkReceiveLoopAndJoinedClose",
                       "TestDarwinInterfaceReadbackBoundsAndNativeFields",
                       "TestDarwinUnusedInterfaceNativeReadbackComposition",
                       "TestDarwinCloneNativeScopeProjectionAndFailure",
                       "TestDarwinLocalCloneRetainedInCohortAndChangesInvalidate",
                       "TestDarwinRouteDump2OriginalIdleCapture"):
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
            linux_namespace_test(binary, env)
            print("Ten real isolated Linux link/address/gateway/route/rule and join cases passed.")

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
            ("unused-link-needs-raw-flags", "desktop_network_darwin_unused.go", "shape.Flags != 0", "false",
             "TestDarwinUnusedInterfaceCaptureRequiresCompleteNativeIdentity", "unmapped-native-flag"),
            ("unused-link-needs-original-capture", "desktop_network_darwin_unused.go", "link == proof.original", "true",
             "TestDarwinUnusedInterfaceRetainsExactCohortIdentity", "name"),
            ("unused-link-needs-lossless-name", "desktop_network_darwin_unused.go", "!utf8.ValidString(link.Name)", "false && !utf8.ValidString(link.Name)",
             "TestDarwinUnusedInterfaceCaptureRequiresCompleteNativeIdentity", "lossy-name-identity"),
            ("unused-link-cannot-have-address", "observer.go", " || link.MTU <= 0 {", " {",
             "TestDarwinUnusedInterfaceCannotOwnOrCarryTraffic", "ipv4-address"),
            ("unused-link-cannot-have-route", "observer.go", "exists && link.MTU <= 0", "exists && false && link.MTU <= 0",
             "TestDarwinUnusedInterfaceCannotOwnOrCarryTraffic", "route"),
            ("unused-link-stays-in-cohort", "observer.go", "result.Links = append(result.Links, link)",
             "if !unused { result.Links = append(result.Links, link) }",
             "TestDarwinUnusedInterfaceRetainsExactCohortIdentity", "retained-original"),
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
        if sys.platform == "darwin":
            target = mutant / "observer_darwin.go"
            original = target.read_text()
            native_controls = (
                ("unsafe-unaligned-native-parser", "\t\tvar message syscall.RoutingMessage\n",
                 "\t\t_, _ = syscall.ParseRoutingMessage(frame)\n\t\tvar message syscall.RoutingMessage\n",
                 "TestDarwinNetworkMessageAlignmentAndOwnership",
                 "fatal error: checkptr: misaligned pointer conversion"),
                ("borrowed-receive-buffer", "return payload, nil",
                 "return frame[size:len(frame):len(frame)], nil", "TestDarwinNetworkMessageAlignmentAndOwnership",
                 "reused receive buffer mutated a captured native message"),
                ("generic-route-sender-conversion", "size, flags, received = darwinReceiveNotification(fd, buffer)",
                 "size, _, flags, _, received = syscall.Recvmsg(int(fd), buffer, nil, syscall.MSG_DONTWAIT)",
                 "TestNativeNetworkObserverReadOnlyBarrier", "address family not supported by protocol family"),
                ("lost-native-datagram-truncation", "return int(size), int(message.Flags), nil",
                 "return int(size), 0, nil", "TestDarwinNetworkReceiveNativeSocket/payload-truncated",
                 "native recvmsg lost its actual datagram truncation witness"),
                ("concealed-native-receive-error", "return 0, 0, failure",
                 "return 0, 0, nil", "TestDarwinNetworkReceiveNativeSocket/invalid-descriptor",
                 "native receive concealed an invalid original descriptor"),
            )
            for name, before, after, test, witness in native_controls:
                if original.count(before) != 1:
                    raise RuntimeError("Darwin native decoding control boundary changed: " + name)
                try:
                    target.write_text(original.replace(before, after, 1))
                    result = execute([go, "test", "-race", "-gcflags=all=-d=checkptr=2", "-v", "-count=1",
                                      "-timeout=30s", ".", "-run", "^" + test + "$"],
                                     cwd=mutant, env=native_env, timeout=90, succeeds=False)
                    if result.returncode == 0 or witness not in result.stdout or "[build failed]" in result.stdout:
                        print(result.stdout, end="")
                        raise RuntimeError("Darwin decoding control did not reject its actual defect: " + name)
                finally:
                    target.write_text(original)
                print("Executed Darwin native decoding control rejected:", name)
            target = mutant / "desktop_network_darwin_wire.go"
            original = target.read_text()
            inventory_controls = (
                ("original-dump2-read", "read(syscall.NET_RT_DUMP2, 0)", "read(syscall.NET_RT_DUMP, 0)",
                 "original native route inventory changed its ABI or retried"),
                ("original-dump2-cache-proof",
                 "object = desktopDarwinCaptureCacheObservation(object, uint32(header.Flags), uint32(header.ParentFlags), header.References, header.Rmx.Expire)",
                 "// Deliberate defect: discard the original native cache observation.",
                 "DUMP2 changed its original route or lost private native fields"),
            )
            for name, before, after, witness in inventory_controls:
                if original.count(before) != 1:
                    raise RuntimeError("Darwin inventory control boundary changed: " + name)
                try:
                    target.write_text(original.replace(before, after, 1))
                    result = execute([go, "test", "-race", "-gcflags=all=-d=checkptr=2", "-v", "-count=1",
                                      "-timeout=30s", ".", "-run", "^TestDarwinRouteDump2OriginalIdleCapture$/^4$"],
                                     cwd=mutant, env=native_env, timeout=90, succeeds=False)
                    marker = "--- FAIL: TestDarwinRouteDump2OriginalIdleCapture/4 "
                    if result.returncode == 0 or marker not in result.stdout or witness not in result.stdout or "[build failed]" in result.stdout:
                        print(result.stdout, end="")
                        raise RuntimeError("Darwin inventory control did not reject its actual defect: " + name)
                finally:
                    target.write_text(original)
                print("Executed Darwin native inventory control rejected:", name)
    print("Desktop captured network observer gate passed; native device transition acceptance remains separate.")


if __name__ == "__main__":
    main()
