#!/usr/bin/env python3
"""Actual UDP DNS reuse recovery and its original ownership failure controls."""
import hashlib
import json
import re

ROOT="TestRouterVPNUDPReusedSOCKSAssociation"
CASES=("reused","fresh-eof","second-eof","cancelled","deadline","owner-replaced",
       "transport-closed","transport-reset","malformed-then-valid","wrong-id-then-valid")
NAMES=(ROOT,*(ROOT+"/"+case for case in CASES))
CONTROLS=(
    dict(name="udp-dns-reuse-disabled",path="dns/transport/udp.go",case="reused",
         before="\t\tretryReadError: true,\n",after="",
         witness="stale SOCKS UDP association was not renewed"),
    dict(name="udp-dns-reuse-fresh",path="dns/transport/multiplexer.go",case="fresh-eof",
         before="retryReadError && m.options.retryReadError && !created)",
         after="retryReadError && m.options.retryReadError)",
         witness="fresh or retired UDP association failure was retried"),
    dict(name="udp-dns-reuse-context",path="dns/transport/multiplexer.go",case="reused",
         before="\t\tpending.retryCtx = ctx\n",after="\t\tpending.retryCtx = context.WithoutCancel(ctx)\n",
         witness="DNS retry replaced its original deadline"),
    dict(name="udp-dns-reuse-reset",path="dns/transport/multiplexer.go",case="transport-reset",
         before="if pending.retryCtx != nil && readFailed {",
         after="if pending.retryCtx != nil && (readFailed || connErr != nil) {",
         witness="failed original UDP observation was reported successful"),
)

def control_events(raw,status,control):
    output=raw.decode()
    names=(ROOT,ROOT+"/"+control["case"])
    runs=re.findall(r"(?m)^=== RUN\s+(\S+)\s*$",output)
    failed=re.findall(r"(?m)^\s*--- FAIL: (\S+) \([^\n]*\)$",output)
    if status!=1 or sorted(runs)!=sorted(names) or sorted(failed)!=sorted(names) or output.count(control["witness"])!=1 or any(value in output for value in ("DATA RACE","panic:","--- SKIP:","--- PASS:","[build failed]")):
        raise ValueError("Original UDP DNS recovery control failed: "+control["name"])
    return dict(expected_failure=True,witness=control["witness"],failed=failed)

def validate(base,gate,run,compiler,core,work,flags):
    status,raw=run("udp-dns-reuse-positive",[compiler,"test",*flags,"-run=^"+ROOT+"$","-count=1","-timeout=30s","-v","./dns/transport"],core,600)
    if status:raise ValueError("Original UDP DNS recovery failed")
    gate.NODE.require_native_verdicts(raw.decode(),NAMES,"captured UDP DNS reuse, ownership and cancellation")
    controls=[]
    for control in CONTROLS:
        original=core/control["path"]
        replacement=work/(control["name"]+".go")
        changed=base.mutate(control,original.read_text())
        replacement.write_text(changed)
        overlay=work/(control["name"]+".json")
        overlay.write_text(json.dumps({"Replace":{str(original):str(replacement)}}))
        status,raw=run(control["name"],[compiler,"test",*flags,"-overlay="+str(overlay),"-run=^"+ROOT+"$/"+control["case"]+"$","-count=1","-timeout=30s","-v","./dns/transport"],core,600)
        controls.append(dict(name=control["name"],original_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),
                             mutation_sha256=hashlib.sha256(changed.encode()).hexdigest(),**control_events(raw,status,control)))
    return dict(udp_dns_reuse_records=list(NAMES),udp_dns_reuse_controls=controls,
                udp_dns_reuse_scope="one additional reused-connection read retry, original dialer/resolver/context, unchanged write retry policy",
                udp_dns_reuse_idle_timeout_unchanged=True,udp_dns_reuse_device_accepted=False)
