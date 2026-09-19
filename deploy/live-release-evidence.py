#!/usr/bin/env python3
"""Bind physical/live Router VPN release evidence to one exact source SHA.

This tool never infers PASS from source or CI. A live gate can be marked PASS
only when at least one evidence file is hashed into the manifest.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tempfile

SCHEMA="router-vpn-live-release-evidence-v1"
SHA_RE=re.compile(r"^[0-9a-f]{40}$")
MAX_BYTES=512*1024*1024
GATES={
 "physical-windows":"Windows install/elevation, routing, DNS/IPv4/IPv6, reconnect/network change, custom exits and leak-negative behavior.",
 "physical-macos":"macOS native networking, DNS/IPv4/IPv6, reconnect/sleep/wake, custom exits, PF and leak-negative behavior.",
 "physical-linux":"Linux distro/runtime integration, DNS/IPv4/IPv6, reconnect/network change, custom exits, nftables and leak-negative behavior.",
 "physical-android":"Android VPN permission, VpnService routing, lockdown, reconnect/network change, DNS/IPv4/IPv6, supported multihop/custom exits and leak-negative behavior.",
 "physical-ios-ipados":"iPhone/iPad permission, PacketTunnel startup, route lockdown, reconnect/network change/on-demand, DNS/IPv4/IPv6, Libbox/custom exits and leak-negative behavior.",
 "off-lan-methods":"Off-LAN simple-method import, connect, tunneled DNS, HTTP and exact expected public exit proof.",
 "native-visual-qa":"Map-first native visual/DPI/responsive/orientation/accessibility QA on real targets.",
 "private-server-features":"Live benchmark/forwarding/Stop/Emergency Stop/Resume/updater rollback on the private production-class path.",
 "live-ai-providers":"Live configured AI Help provider matrix with server-side keys and bounded/redacted context.",
 "apple-signing-notarization":"Legitimate Apple signing/provisioning, macOS notarization where applicable, install/launch and distribution proof.",
 "production-exact-sha-deploy":"One deliberate exact-SHA Portainer deployment plus live health/path smoke proof.",
 "asus-forwarding-revalidation":"ASUS fail-open exact-port forwarding/JFFS revalidation with unrelated rules/hooks and ordinary household Internet preserved.",
 "final-regression":"Final post-deployment regression without borrowing stale evidence.",
}

def utc_now():
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00","Z")

def valid_time(value):
    if not isinstance(value,str) or not value.endswith("Z"):
        return False
    try:
        datetime.fromisoformat(value[:-1]+"+00:00")
        return True
    except ValueError:
        return False

def atomic_write(path,data):
    path.parent.mkdir(parents=True,exist_ok=True)
    payload=(json.dumps(data,indent=2,sort_keys=True)+"\n").encode()
    fd,tmp=tempfile.mkstemp(prefix=path.name+".",suffix=".tmp",dir=path.parent)
    try:
        with os.fdopen(fd,"wb") as handle:
            handle.write(payload); handle.flush(); os.fsync(handle.fileno())
        try: os.chmod(tmp,0o600)
        except OSError: pass
        os.replace(tmp,path)
    finally:
        try: os.unlink(tmp)
        except FileNotFoundError: pass

def load(path):
    try: data=json.loads(path.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as exc: raise ValueError(f"cannot read manifest: {exc}") from exc
    if not isinstance(data,dict): raise ValueError("manifest root must be an object")
    return data

def blank(sha):
    if not SHA_RE.fullmatch(sha): raise ValueError("release SHA must be exactly 40 lowercase hex characters")
    stamp=utc_now()
    return {"schema":SCHEMA,"release_sha":sha,"created_at":stamp,"updated_at":stamp,
            "gates":{gate:{"status":"pending","note":"","evidence":[]} for gate in GATES}}

def digest_file(path):
    if path.is_symlink() or not path.is_file(): raise ValueError(f"evidence is not a regular non-symlink file: {path}")
    size=path.stat().st_size
    if size<1 or size>MAX_BYTES: raise ValueError(f"evidence size must be 1..{MAX_BYTES} bytes: {path}")
    h=hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda:handle.read(1024*1024),b""): h.update(block)
    return h.hexdigest(),size

def evidence_source_problems(data,gate_names=None):
    """Re-hash recorded raw proof so stale/missing/tampered files lose credit."""
    out=[]
    gates=data.get("gates")
    if not isinstance(gates,dict): return ["gates must be an object"]
    names=list(gate_names) if gate_names is not None else list(GATES)
    for gate in names:
        item=gates.get(gate)
        if not isinstance(item,dict) or item.get("status")!="pass": continue
        rows=item.get("evidence")
        if not isinstance(rows,list): continue
        for i,row in enumerate(rows):
            if not isinstance(row,dict): continue
            source=row.get("source")
            if not isinstance(source,str) or not source: continue
            try: digest,size=digest_file(Path(source))
            except (OSError,ValueError) as exc:
                out.append(f"{gate}: evidence[{i}] source verification failed: {exc}")
                continue
            if digest!=row.get("sha256"): out.append(f"{gate}: evidence[{i}] source sha256 changed")
            if size!=row.get("size"): out.append(f"{gate}: evidence[{i}] source size changed")
    return out

def problems(data,expected_sha=None,require_final=False):
    out=[]
    if data.get("schema")!=SCHEMA: out.append(f"schema must be {SCHEMA}")
    sha=data.get("release_sha")
    if not isinstance(sha,str) or not SHA_RE.fullmatch(sha): out.append("release_sha must be 40 lowercase hex characters")
    elif expected_sha and sha!=expected_sha: out.append(f"manifest SHA {sha} != required SHA {expected_sha}")
    if not valid_time(data.get("created_at")) or not valid_time(data.get("updated_at")): out.append("created_at/updated_at must be valid UTC Z timestamps")
    gates=data.get("gates")
    if not isinstance(gates,dict): return out+["gates must be an object"]
    missing=sorted(set(GATES)-set(gates)); extra=sorted(set(gates)-set(GATES))
    if missing: out.append("missing gates: "+", ".join(missing))
    if extra: out.append("unknown gates: "+", ".join(extra))
    for gate in GATES:
        item=gates.get(gate)
        if not isinstance(item,dict): continue
        status=item.get("status")
        if status not in {"pending","pass","fail"}: out.append(f"{gate}: invalid status")
        note=item.get("note")
        if not isinstance(note,str) or len(note)>4096: out.append(f"{gate}: invalid note")
        evidence=item.get("evidence")
        if not isinstance(evidence,list): out.append(f"{gate}: evidence must be a list"); continue
        if status=="pass" and not evidence: out.append(f"{gate}: PASS requires hashed evidence")
        seen=set()
        for i,row in enumerate(evidence):
            if not isinstance(row,dict): out.append(f"{gate}: evidence[{i}] must be an object"); continue
            d=row.get("sha256"); size=row.get("size")
            if not isinstance(d,str) or not re.fullmatch(r"[0-9a-f]{64}",d): out.append(f"{gate}: evidence[{i}] invalid sha256")
            elif d in seen: out.append(f"{gate}: duplicate evidence digest {d}")
            else: seen.add(d)
            if not isinstance(size,int) or size<1 or size>MAX_BYTES: out.append(f"{gate}: evidence[{i}] invalid size")
            if not isinstance(row.get("source"),str) or not row["source"] or len(row["source"])>1024: out.append(f"{gate}: evidence[{i}] invalid source")
            if not valid_time(row.get("captured_at")): out.append(f"{gate}: evidence[{i}] invalid captured_at")
    if require_final:
        incomplete=[g for g in GATES if not isinstance(gates.get(g),dict) or gates[g].get("status")!="pass"]
        if incomplete: out.append("final release still incomplete: "+", ".join(incomplete))
    return out

def cmd_init(args):
    p=Path(args.manifest)
    if p.exists() and not args.force: raise ValueError("manifest already exists; use --force only to deliberately reset live evidence")
    atomic_write(p,blank(args.sha)); print(f"initialized {p} for exact release SHA {args.sha}"); return 0

def cmd_record(args):
    p=Path(args.manifest); data=load(p)
    bad=problems(data)
    if bad: raise ValueError("existing manifest invalid: "+"; ".join(bad))
    item=data["gates"][args.gate]; rows=[] if args.replace else list(item["evidence"]); known={r["sha256"] for r in rows}
    for raw in args.evidence:
        src=Path(raw).expanduser().resolve(strict=True); d,size=digest_file(src)
        if d not in known:
            rows.append({"sha256":d,"size":size,"source":str(src),"captured_at":utc_now()}); known.add(d)
    if args.status=="pass" and not rows: raise ValueError("PASS requires at least one --evidence file")
    item.update(status=args.status,note=args.note or "",evidence=rows); data["updated_at"]=utc_now()
    bad=problems(data)
    if bad: raise ValueError("refusing invalid update: "+"; ".join(bad))
    atomic_write(p,data); print(f"{args.gate}: {args.status.upper()} ({len(rows)} evidence file(s))"); return 0

def cmd_status(args):
    data=load(Path(args.manifest)); bad=problems(data,args.sha)
    if bad:
        for value in bad: print("INVALID:",value)
        return 2
    print("release SHA:",data["release_sha"])
    for gate,desc in GATES.items():
        item=data["gates"][gate]
        print(f"{item['status'].upper():7} {gate:31} evidence={len(item['evidence'])}  {desc}")
    return 0

def cmd_validate(args):
    if args.sha and not SHA_RE.fullmatch(args.sha): raise ValueError("--sha must be exactly 40 lowercase hex characters")
    data=load(Path(args.manifest)); bad=problems(data,args.sha,args.require_final)
    if args.require_final: bad.extend(evidence_source_problems(data))
    if bad:
        for value in bad: print("INVALID:",value)
        return 2
    print("live release evidence manifest: PASS")
    print("exact release SHA:",data["release_sha"])
    return 0

def build_parser():
    p=argparse.ArgumentParser(description=__doc__); sub=p.add_subparsers(dest="command",required=True)
    x=sub.add_parser("init"); x.add_argument("manifest"); x.add_argument("--sha",required=True); x.add_argument("--force",action="store_true"); x.set_defaults(func=cmd_init)
    x=sub.add_parser("record"); x.add_argument("manifest"); x.add_argument("--gate",required=True,choices=sorted(GATES)); x.add_argument("--status",required=True,choices=("pending","pass","fail")); x.add_argument("--evidence",action="append",default=[]); x.add_argument("--note",default=""); x.add_argument("--replace",action="store_true"); x.set_defaults(func=cmd_record)
    x=sub.add_parser("status"); x.add_argument("manifest"); x.add_argument("--sha"); x.set_defaults(func=cmd_status)
    x=sub.add_parser("validate"); x.add_argument("manifest"); x.add_argument("--sha"); x.add_argument("--require-final",action="store_true"); x.set_defaults(func=cmd_validate)
    return p

def main():
    try:
        args=build_parser().parse_args()
        return args.func(args)
    except (OSError,ValueError) as exc:
        print("ERROR:",exc,file=sys.stderr)
        return 2

if __name__=="__main__": raise SystemExit(main())
