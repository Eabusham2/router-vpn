#!/usr/bin/env python3
from __future__ import annotations
import os, subprocess, tempfile
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
HELPER=ROOT/'router/asus-merlin-router-vpn-forwards.sh'

def exe(p:Path,body:str): p.write_text(body); p.chmod(0o755)
def run(cmd,env,ok=True):
    cp=subprocess.run(cmd,env=env,text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,timeout=12)
    if ok and cp.returncode: raise AssertionError(f'FAIL {cmd}\n{cp.stdout}\n{cp.stderr}')
    if not ok and cp.returncode==0: raise AssertionError(f'expected failure {cmd}\n{cp.stdout}')
    return cp

def lines(state,table,chain):
    p=state/f'{table}.{chain}'; return p.read_text().splitlines() if p.exists() else []
def owned(state):
    return ([x for x in lines(state,'nat','PREROUTING') if '--comment ROUTER_VPN' in x],
            [x for x in lines(state,'filter','FORWARD') if '--comment ROUTER_VPN' in x])
def unrelated(state):
    return ([x for x in lines(state,'nat','PREROUTING') if 'ROUTER_VPN' not in x],
            [x for x in lines(state,'filter','FORWARD') if 'ROUTER_VPN' not in x])
def snap(state): return {p.name:p.read_text() for p in sorted(state.iterdir()) if p.is_file()}

def main():
  with tempfile.TemporaryDirectory(prefix='rv-fwd-') as td:
    b=Path(td); bin=b/'bin'; jffs=b/'jffs/scripts'; state=b/'state'; bin.mkdir(); jffs.mkdir(parents=True); state.mkdir()
    (state/'nat.PREROUTING').write_text('-A PREROUTING -i eth0 -p tcp --dport 5555 -j DNAT --to-destination 192.168.50.99:5555\n-A PREROUTING -i eth0 -j ROUTER_VPN_DNAT\n')
    (state/'nat.ROUTER_VPN_DNAT').write_text('-A ROUTER_VPN_DNAT -p tcp --dport 443 -j DNAT --to-destination 192.168.50.133:443\n')
    (state/'filter.FORWARD').write_text('-A FORWARD -s 192.168.50.0/24 -o eth0 -j ACCEPT\n-A FORWARD -i eth0 -d 192.168.50.99 -p tcp --dport 5555 -j ACCEPT\n-A FORWARD -i eth0 -d 192.168.50.133 -j ROUTER_VPN_FWD\n')
    (state/'filter.ROUTER_VPN_FWD').write_text('-A ROUTER_VPN_FWD -p tcp --dport 443 -j ACCEPT\n')
    baseline=unrelated(state)
    exe(bin/'iptables',r'''#!/bin/sh
STATE=${ROUTER_VPN_TEST_STATE:?}; TABLE=filter
if [ "${1:-}" = -m ] && { [ "${2:-}" = comment ] || [ "${2:-}" = state ]; } && [ "${3:-}" = -h ]; then exit 0; fi
if [ "${1:-}" = -t ]; then TABLE=$2; shift 2; fi
OP=${1:-}; [ "$OP" = -S ] && { C=${2:-}; [ -n "$C" ] && { [ ! -f "$STATE/$TABLE.$C" ] || cat "$STATE/$TABLE.$C"; } || cat "$STATE/$TABLE."* 2>/dev/null || true; exit 0; }
[ $# -ge 2 ] || exit 2; C=$2; shift 2; F="$STATE/$TABLE.$C"; R="-A $C"; [ $# -eq 0 ] || R="$R $*"
case "$OP" in
 -C) [ -f "$F" ] && grep -Fqx -- "$R" "$F" ;;
 -A) case " $* " in *" --dport ${ROUTER_VPN_TEST_FAIL_ADD_PORT:-__none__} "*) [ -z "${ROUTER_VPN_TEST_FAIL_ADD_PORT:-}" ] || exit 7;; esac; printf '%s\n' "$R" >>"$F" ;;
 -D) [ -f "$F" ] && grep -Fqx -- "$R" "$F" || exit 1; T="$F.$$"; grep -Fvx -- "$R" "$F" >"$T" || true; mv "$T" "$F" ;;
 -F) [ -f "$F" ] || exit 1; : >"$F" ;;
 -X) [ -f "$F" ] && [ ! -s "$F" ] || exit 1; rm -f "$F" ;;
 *) exit 2;;
esac
''')
    exe(bin/'curl',r'''#!/bin/sh
C=${ROUTER_VPN_TEST_HEALTH_COUNT:-}; if [ -n "$C" ]; then N=0; [ ! -f "$C" ] || N=$(cat "$C"); printf '%s\n' $((N+1)) >"$C"; fi
[ "${ROUTER_VPN_TEST_HEALTH:-up}" = up ]
''')
    exe(bin/'ip6tables-save',"#!/bin/sh\nprintf '%s\\n' '*filter' 'COMMIT'\n")
    nat=jffs/'nat-start'; fw=jffs/'firewall-start'
    nat.write_text('#!/bin/sh\necho unrelated-nat-hook >/dev/null\n/jffs/scripts/router-vpn-forward.sh apply-nat\n')
    fw.write_text('#!/bin/sh\n/jffs/scripts/cod-na-block.sh &\n/jffs/scripts/rogue-dhcp-ra-guard.sh\n/jffs/scripts/att-bgw-guard.sh\n/jffs/scripts/router-vpn-forward.sh apply-filter\n')
    env=os.environ.copy(); env.update(PATH=str(bin)+os.pathsep+env.get('PATH',''),ROUTER_VPN_JFFS_DIR=str(jffs),ROUTER_VPN_IPTABLES=str(bin/'iptables'),ROUTER_VPN_TEST_STATE=str(state),ROUTER_VPN_WAN_INTERFACE='eth0',ROUTER_VPN_SKIP_NVRAM='1',ROUTER_VPN_TEST_HEALTH='up',ROUTER_VPN_TEST_HEALTH_COUNT=str(b/'health-count'))

    run(['/bin/sh',str(HELPER),'install'],env); rt=jffs/'router-vpn-forward.sh'; cfg=jffs/'router-vpn-forward.conf'
    assert rt.exists() and cfg.exists(); assert f'{rt} apply || true' in nat.read_text(); assert f'{rt} apply || true' in fw.read_text(); assert unrelated(state)==baseline
    assert 'echo unrelated-nat-hook >/dev/null' in nat.read_text()
    for protected in ('cod-na-block.sh','rogue-dhcp-ra-guard.sh','att-bgw-guard.sh'): assert protected in fw.read_text()
    if os.name != 'nt':
        assert rt.stat().st_mode & 0o777 == 0o755 and cfg.stat().st_mode & 0o777 == 0o600
        assert nat.stat().st_mode & 0o777 == 0o755 and fw.stat().st_mode & 0o777 == 0o755
    assert not list(jffs.glob('.*.router-vpn.*')), 'atomic JFFS staging files survived install'
    assert not (state/'nat.ROUTER_VPN_DNAT').exists() and not (state/'filter.ROUTER_VPN_FWD').exists(); assert tuple(map(len,owned(state)))==(18,18)
    run(['/bin/sh',str(rt),'verify'],env)

    hc=Path(env['ROUTER_VPN_TEST_HEALTH_COUNT']); hc.write_text('0\n'); run(['/bin/sh',str(rt),'apply'],env); assert hc.read_text().strip()=='1'
    s=snap(state)
    for c in ([ '/bin/sh',str(rt),'apply'],['/bin/sh',str(nat)],['/bin/sh',str(fw)]): run(c,env)
    assert snap(state)==s

    down=env|{'ROUTER_VPN_TEST_HEALTH':'down'}; run(['/bin/sh',str(rt),'apply'],down,False); run(['/bin/sh',str(nat)],down); run(['/bin/sh',str(fw)],down); assert unrelated(state)==baseline and owned(state)==([],[])
    run(['/bin/sh',str(rt),'apply'],env)

    foreign='-A PREROUTING -i eth0 -p tcp --dport 443 -j DNAT --to-destination 192.168.50.77:443'; nf=state/'nat.PREROUTING'; nf.write_text(nf.read_text()+foreign+'\n'); ub=unrelated(state)
    run(['/bin/sh',str(rt),'apply'],env,False); assert unrelated(state)==ub and foreign in lines(state,'nat','PREROUTING') and owned(state)==([],[])
    nf.write_text('\n'.join(x for x in lines(state,'nat','PREROUTING') if x!=foreign)+'\n'); assert unrelated(state)==baseline; run(['/bin/sh',str(rt),'apply'],env)

    # force a fresh add, then inject failure
    run(['/bin/sh',str(rt),'remove'],env); assert rt.exists() and cfg.exists(); assert owned(state)==([],[])
    fail=env|{'ROUTER_VPN_TEST_FAIL_ADD_PORT':'8443'}; run(['/bin/sh',str(rt),'apply'],fail,False); assert unrelated(state)==baseline and owned(state)==([],[])
    run(['/bin/sh',str(rt),'apply'],env)

    good=cfg.read_text(); cfg.write_text(good.replace(': "${WG_PORT:=51820}"','WG_PORT=not-a-port')); run(['/bin/sh',str(rt),'apply'],env,False); assert unrelated(state)==baseline and owned(state)==([],[]); cfg.write_text(good)
    run(['/bin/sh',str(rt),'apply'],env); run(['/bin/sh',str(rt),'remove'],env); assert rt.exists() and cfg.exists(); assert 'router-vpn-forward.sh' not in nat.read_text() and 'router-vpn-forward.sh' not in fw.read_text(); assert unrelated(state)==baseline
    run(['/bin/sh',str(rt),'apply'],env); run(['/bin/sh',str(rt),'verify'],env)

    bad='-A PREROUTING -i eth0 -p udp --dport 45999 -m comment --comment ROUTER_VPN -j DNAT --to-destination 192.168.50.133:45999'; nf.write_text(nf.read_text()+bad+'\n'); run(['/bin/sh',str(rt),'verify'],env,False); nf.write_text('\n'.join(x for x in lines(state,'nat','PREROUTING') if x!=bad)+'\n'); run(['/bin/sh',str(rt),'verify'],env)
    for protected in ('cod-na-block.sh','rogue-dhcp-ra-guard.sh','att-bgw-guard.sh'): assert protected in fw.read_text()

    # The persisted config is sourced as root. A symlink must be rejected before
    # any content in its target can execute.
    marker=b/'config-was-sourced'
    evil=b/'evil-forward.conf'; evil.write_text(f'touch {marker}\n')
    cfg.unlink(); cfg.symlink_to(evil)
    run(['/bin/sh',str(rt),'status'],env,False)
    assert not marker.exists(), 'symlinked Router VPN config was sourced as root'
    cfg.unlink(); cfg.write_text(good); cfg.chmod(0o600)

    # A symlink in the JFFS ancestry is also rejected before persistent files are
    # read or written.
    real_parent=b/'real-jffs'; real_scripts=real_parent/'scripts'; real_scripts.mkdir(parents=True)
    alias=b/'jffs-alias'; alias.symlink_to(real_parent, target_is_directory=True)
    redirected=env|{'ROUTER_VPN_JFFS_DIR':str(alias/'scripts')}
    run(['/bin/sh',str(HELPER),'status'],redirected,False)
    assert not list(real_scripts.iterdir()), 'redirected JFFS ancestry received Router VPN state'
  print('ASUS Router VPN fail-open forwarding simulation: OK')
if __name__=='__main__': main()