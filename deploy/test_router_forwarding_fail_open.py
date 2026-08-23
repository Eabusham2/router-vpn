#!/usr/bin/env python3
from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "router/asus-merlin-router-vpn-forwards.sh"


def write_exe(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8")
    path.chmod(0o755)


def run(cmd: list[str], env: dict[str, str], *, ok: bool = True) -> subprocess.CompletedProcess[str]:
    cp = subprocess.run(cmd, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
    if ok and cp.returncode:
        raise AssertionError(f"command failed {cmd!r}\nstdout:\n{cp.stdout}\nstderr:\n{cp.stderr}")
    if not ok and cp.returncode == 0:
        raise AssertionError(f"command unexpectedly succeeded {cmd!r}\n{cp.stdout}")
    return cp


def read_rules(state: Path, table: str, chain: str) -> list[str]:
    p = state / f"{table}.{chain}"
    return p.read_text(encoding="utf-8").splitlines() if p.exists() else []


def unrelated(state: Path) -> tuple[list[str], list[str]]:
    nat = [r for r in read_rules(state, "nat", "PREROUTING") if "ROUTER_VPN" not in r]
    fwd = [r for r in read_rules(state, "filter", "FORWARD") if "ROUTER_VPN" not in r]
    return nat, fwd


def owned(state: Path) -> tuple[list[str], list[str]]:
    nat = [r for r in read_rules(state, "nat", "PREROUTING") if "--comment ROUTER_VPN" in r]
    fwd = [r for r in read_rules(state, "filter", "FORWARD") if "--comment ROUTER_VPN" in r]
    return nat, fwd


def state_snapshot(state: Path) -> dict[str, str]:
    return {p.name: p.read_text(encoding="utf-8") for p in sorted(state.iterdir()) if p.is_file()}


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="router-vpn-forward-test-") as td:
        base = Path(td)
        fakebin = base / "bin"
        jffs = base / "jffs" / "scripts"
        state = base / "state"
        fakebin.mkdir(parents=True)
        jffs.mkdir(parents=True)
        state.mkdir()

        (state / "nat.PREROUTING").write_text(
            "-A PREROUTING -i eth0 -p tcp --dport 5555 -j DNAT --to-destination 192.168.50.99:5555\n"
            "-A PREROUTING -i eth0 -j ROUTER_VPN_DNAT\n",
            encoding="utf-8",
        )
        (state / "nat.ROUTER_VPN_DNAT").write_text(
            "-A ROUTER_VPN_DNAT -p tcp --dport 443 -j DNAT --to-destination 192.168.50.133:443\n",
            encoding="utf-8",
        )
        (state / "filter.FORWARD").write_text(
            "-A FORWARD -s 192.168.50.0/24 -o eth0 -j ACCEPT\n"
            "-A FORWARD -i eth0 -d 192.168.50.99 -p tcp --dport 5555 -j ACCEPT\n"
            "-A FORWARD -i eth0 -d 192.168.50.133 -j ROUTER_VPN_FWD\n",
            encoding="utf-8",
        )
        (state / "filter.ROUTER_VPN_FWD").write_text(
            "-A ROUTER_VPN_FWD -p tcp --dport 443 -j ACCEPT\n",
            encoding="utf-8",
        )
        initial_unrelated = unrelated(state)

        write_exe(
            fakebin / "iptables",
            r'''#!/bin/sh
STATE=${ROUTER_VPN_TEST_STATE:?}
TABLE=filter
if [ "${1:-}" = -m ] && { [ "${2:-}" = comment ] || [ "${2:-}" = state ]; } && [ "${3:-}" = -h ]; then exit 0; fi
if [ "${1:-}" = -t ]; then TABLE=$2; shift 2; fi
OP=${1:-}; [ -n "$OP" ] || exit 2
if [ "$OP" = -S ]; then
  CHAIN=${2:-}
  if [ -n "$CHAIN" ]; then [ ! -f "$STATE/$TABLE.$CHAIN" ] || cat "$STATE/$TABLE.$CHAIN"; else cat "$STATE/$TABLE."* 2>/dev/null || true; fi
  exit 0
fi
[ $# -ge 2 ] || exit 2
CHAIN=$2; shift 2
FILE="$STATE/$TABLE.$CHAIN"
RULE="-A $CHAIN"
[ $# -eq 0 ] || RULE="$RULE $*"
case "$OP" in
  -C) [ -f "$FILE" ] && grep -Fqx -- "$RULE" "$FILE" ;;
  -A)
    case " $* " in *" --dport ${ROUTER_VPN_TEST_FAIL_ADD_PORT:-__none__} "*) [ -z "${ROUTER_VPN_TEST_FAIL_ADD_PORT:-}" ] || exit 7 ;; esac
    printf '%s\n' "$RULE" >> "$FILE" ;;
  -D)
    [ -f "$FILE" ] || exit 1
    grep -Fqx -- "$RULE" "$FILE" || exit 1
    TMP="$FILE.tmp.$$"; grep -Fvx -- "$RULE" "$FILE" > "$TMP" || true; mv "$TMP" "$FILE" ;;
  -F) [ -f "$FILE" ] || exit 1; : > "$FILE" ;;
  -X) [ -f "$FILE" ] || exit 1; [ ! -s "$FILE" ] || exit 1; rm -f "$FILE" ;;
  *) exit 2 ;;
esac
''',
        )
        write_exe(fakebin / "curl", "#!/bin/sh\n[ \"${ROUTER_VPN_TEST_HEALTH:-up}\" = up ]\n")
        write_exe(fakebin / "ip6tables-save", "#!/bin/sh\nprintf '%s\\n' '*filter' 'COMMIT'\n")

        nat_hook = jffs / "nat-start"
        fw_hook = jffs / "firewall-start"
        nat_hook.write_text(
            "#!/bin/sh\necho unrelated-nat-hook >/dev/null\n/jffs/scripts/router-vpn-forward.sh apply-nat\n",
            encoding="utf-8",
        )
        fw_hook.write_text(
            "#!/bin/sh\n/jffs/scripts/cod-na-block.sh &\n/jffs/scripts/rogue-dhcp-ra-guard.sh\n"
            "/jffs/scripts/att-bgw-guard.sh\n/jffs/scripts/router-vpn-forward.sh apply-filter\n",
            encoding="utf-8",
        )

        env = os.environ.copy()
        env.update(
            {
                "PATH": str(fakebin) + os.pathsep + env.get("PATH", ""),
                "ROUTER_VPN_JFFS_DIR": str(jffs),
                "ROUTER_VPN_IPTABLES": str(fakebin / "iptables"),
                "ROUTER_VPN_TEST_STATE": str(state),
                "ROUTER_VPN_WAN_INTERFACE": "eth0",
                "ROUTER_VPN_SKIP_NVRAM": "1",
                "ROUTER_VPN_TEST_HEALTH": "up",
            }
        )

        # Old broad chain migration -> direct exact-port rules.
        run(["/bin/sh", str(HELPER), "install"], env)
        runtime = jffs / "router-vpn-forward.sh"
        assert runtime.exists()
        assert f"{runtime} apply-nat || true" in nat_hook.read_text(encoding="utf-8")
        assert f"{runtime} apply-filter || true" in fw_hook.read_text(encoding="utf-8")
        assert unrelated(state) == initial_unrelated
        assert not (state / "nat.ROUTER_VPN_DNAT").exists()
        assert not (state / "filter.ROUTER_VPN_FWD").exists()
        nat1, fwd1 = owned(state)
        assert len(nat1) == 16, len(nat1)
        assert len(fwd1) == 16, len(fwd1)
        assert all("-i eth0 -p " in r and "--dport" in r for r in nat1)
        assert all("-i eth0 -d 192.168.50.133 -p " in r and "--state NEW" in r for r in fwd1)
        run(["/bin/sh", str(runtime), "verify"], env)

        # Healthy repeated apply and both Merlin hooks do not churn rules.
        snap = state_snapshot(state)
        for cmd in (
            ["/bin/sh", str(runtime), "apply"],
            ["/bin/sh", str(runtime), "apply"],
            ["/bin/sh", str(nat_hook)],
            ["/bin/sh", str(nat_hook)],
            ["/bin/sh", str(fw_hook)],
            ["/bin/sh", str(fw_hook)],
        ):
            run(cmd, env)
        assert state_snapshot(state) == snap

        # Router VPN/AI Board down -> only Router VPN exposure disappears.
        down = env | {"ROUTER_VPN_TEST_HEALTH": "down"}
        run(["/bin/sh", str(runtime), "apply"], down, ok=False)
        run(["/bin/sh", str(nat_hook)], down)
        run(["/bin/sh", str(fw_hook)], down)
        assert unrelated(state) == initial_unrelated
        assert owned(state) == ([], [])

        # Injected iptables rule failure -> partial Router VPN rules are cleaned.
        fail = env | {"ROUTER_VPN_TEST_FAIL_ADD_PORT": "8443"}
        run(["/bin/sh", str(runtime), "apply"], fail, ok=False)
        assert unrelated(state) == initial_unrelated
        assert owned(state) == ([], [])

        # Recover, then malformed config fails closed for Router VPN only.
        run(["/bin/sh", str(runtime), "apply"], env)
        cfg = jffs / "router-vpn-forward.conf"
        good_cfg = cfg.read_text(encoding="utf-8")
        cfg.write_text(good_cfg.replace(': "${WG_PORT:=51820}"', 'WG_PORT=not-a-port'), encoding="utf-8")
        run(["/bin/sh", str(runtime), "apply"], env, ok=False)
        assert unrelated(state) == initial_unrelated
        assert owned(state) == ([], [])
        cfg.write_text(good_cfg, encoding="utf-8")

        # apply -> apply -> remove -> reinstall/apply preserves unrelated state.
        run(["/bin/sh", str(runtime), "apply"], env)
        run(["/bin/sh", str(runtime), "apply"], env)
        run(["/bin/sh", str(runtime), "remove"], env)
        assert unrelated(state) == initial_unrelated
        assert owned(state) == ([], [])
        assert "unrelated-nat-hook" in nat_hook.read_text(encoding="utf-8")
        fw_text = fw_hook.read_text(encoding="utf-8")
        for protected in ("cod-na-block.sh", "rogue-dhcp-ra-guard.sh", "att-bgw-guard.sh"):
            assert protected in fw_text
        assert "router-vpn-forward.sh" not in nat_hook.read_text(encoding="utf-8")
        assert "router-vpn-forward.sh" not in fw_text

        run(["/bin/sh", str(HELPER), "install"], env)
        runtime = jffs / "router-vpn-forward.sh"
        run(["/bin/sh", str(runtime), "verify"], env)
        assert unrelated(state) == initial_unrelated
        nat2, fwd2 = owned(state)
        assert len(nat2) == len(set(nat2)) == 16
        assert len(fwd2) == len(set(fwd2)) == 16
        assert nat_hook.read_text(encoding="utf-8").count("router-vpn-forward.sh apply-nat || true") == 1
        assert fw_hook.read_text(encoding="utf-8").count("router-vpn-forward.sh apply-filter || true") == 1
        assert "unrelated-nat-hook" in nat_hook.read_text(encoding="utf-8")
        for protected in ("cod-na-block.sh", "rogue-dhcp-ra-guard.sh", "att-bgw-guard.sh"):
            assert protected in fw_hook.read_text(encoding="utf-8")

    print("ASUS Router VPN fail-open forwarding simulation: OK")


if __name__ == "__main__":
    main()
