#!/usr/bin/env python3
"""Run the original mobile package selections with independent Go alarms."""
import argparse
from pathlib import Path
import subprocess
import tempfile

import test_go_source_groups as groups
from test_node_chain_candidate_preparation import ROOTS as CANDIDATE_CASES, TYPED_ROOT


MODULE = "github.com/sagernet/sing-box"
SHARED = MODULE + "/experimental/libbox/routervpn/"
MULTIHOP = SHARED + "mobilemultihop"
ANDROID_FLAGS = ("-race", "-ldflags=-checklinkname=0", "-tags", "with_quic,with_wireguard,with_gvisor")


def run_root(image, root, directory, tool, package, grouped, timeout):
    def phase(families=(), exclude=False):
        return groups.run_phase(image, root, directory, tool, package, allowed_packages=grouped,
                                alarm=f"{timeout}s", process_timeout=timeout + 30,
                                child_families=families, exclude=exclude)

    if package != MODULE or root != TYPED_ROOT:
        return phase()

    # Nine native 50-sample trials can exhaust 90s together. Run each whole
    # protocol branch, including new counts, and execute every other branch
    # via its exact complement so a new protocol remains part of both builds.
    required = CANDIDATE_CASES[package][root]
    families = tuple(dict.fromkeys(name.split("/")[0] for name in required))
    receipts = {}
    partitions = [((family,), False) for family in families]
    partitions.append((families, True))
    for selected, exclude in partitions:
        evidence = phase(selected, exclude)
        for name, verdict in evidence.items():
            if name == root:
                if receipts.setdefault(root, verdict) != verdict:
                    raise ValueError("Inconsistent native typed-suffix parent verdict")
                continue
            family = name.split("/")[1]
            if (family in selected) == exclude or name in receipts:
                raise ValueError("Overlapping native typed-suffix partition: " + name)
            receipts[name] = verdict
    if any(root + "/" + case not in receipts for case in required):
        raise ValueError("Missing native typed-suffix trial")
    return receipts


def run(vendor, suite):
    if suite == "shared":
        patterns = ("./experimental/libbox/routervpn/...",)
        flags, selector, timeout = (), ".", 600
    elif suite == "android-chain":
        patterns = (".", "./route")
        flags, selector, timeout = ANDROID_FLAGS, "^TestRouterVPNNodeChain", 90
    elif suite == "ios-chain":
        patterns = (".", "./daemon", "./route")
        flags, selector, timeout = ("-race",), "^TestRouterVPN(Strategy|NodeChain)", 90
    else:
        raise ValueError("Unknown native test suite: " + suite)

    packages = tuple(subprocess.check_output(["go", "list", *flags, *patterns], cwd=vendor,
                                             text=True, timeout=180).splitlines())
    if suite == "shared":
        if (MULTIHOP not in packages or len(set(packages)) != len(packages)
                or any(not name.startswith(SHARED) for name in packages)):
            raise ValueError("Incomplete prepared mobile package inventory")
        grouped = (MULTIHOP,)
    else:
        grouped = tuple(MODULE + name[1:] for name in patterns)
        if packages != grouped:
            raise ValueError("Prepared native package selection changed: " + str(packages))

    print(f"Selected mobile packages for {suite}: {packages}", flush=True)
    tool = groups.test2json_tool(vendor)
    with tempfile.TemporaryDirectory(prefix="routervpn-mobile-go-") as temp:
        image = Path(temp) / "native.test"
        for package in grouped:
            # go test normally launches each image in its own package directory.
            directory = vendor / package.removeprefix(MODULE).lstrip("/")
            subprocess.run(["go", "test", "-c", *flags, "-o", str(image), package],
                           cwd=vendor, check=True)
            listing = subprocess.check_output([str(image), "-test.list=" + selector],
                                              cwd=directory, text=True, timeout=30)
            roots = groups.inventory(listing)
            print(f"Compiled {package} roots matching {selector}: {roots}", flush=True)
            results = [(root, run_root(image, root, directory, tool, package, grouped, timeout))
                       for root in roots]
            counts = groups.complete(roots, results)
            print(f"{package}: {len(roots)} complete roots, {counts['pass']} passed and "
                  f"{counts['skip']} explicit skip receipts", flush=True)
            image.unlink()
    remaining = [package for package in packages if package not in grouped]
    if remaining:
        subprocess.run(["go", "test", *remaining], cwd=vendor, check=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=("shared", "android-chain", "ios-chain"))
    parser.add_argument("vendor", type=Path)
    args = parser.parse_args()
    run(args.vendor.resolve(), args.suite)
