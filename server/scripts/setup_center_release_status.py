#!/usr/bin/env python3
"""Read-only release/recovery status for authenticated Router VPN Setup Center.

This deliberately does NOT talk to Docker, Portainer, or the host socket. Normal
production is exact-SHA image-only, so replacing production remains a deliberate
operator action after release validation. The Setup Center can still truthfully
report what SHA it is serving and the bounded recovery workflow without gaining
unsafe container-management authority.
"""
from __future__ import annotations

import os
from pathlib import Path
import re

SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def current_sha() -> str:
    value = os.environ.get("ROUTER_VPN_GITHUB_SHA", "").strip().lower()
    return value if SHA_RE.fullmatch(value) else "unknown"


def release_status(base: Path) -> dict:
    sha = current_sha()
    config = base / "config"
    admin_state = base / "admin-state"
    downloads = base / "downloads"
    return {
        "ok": True,
        "deployed_sha": sha,
        "exact_sha": sha != "unknown",
        "production_model": "exact-sha-image-only",
        "self_update_available": False,
        "self_update_reason": (
            "Setup Center intentionally has no Docker/Portainer control. Publish a validated exact-SHA release, "
            "then update the Portainer stack deliberately."
        ),
        "recovery": {
            "emergency_client_stop": "Use the Router VPN app Emergency stop for client-side rollback.",
            "server_config_present": config.is_dir(),
            "admin_state_present": admin_state.is_dir(),
            "downloads_present": downloads.is_dir(),
            "safe_sequence": [
                "Record the currently deployed exact SHA and current server status.",
                "Do not prune Docker globally or manually delete Docker storage-driver directories.",
                "If a new release is being applied, use only validated exact-SHA images in server/portainer-current.yaml.",
                "Perform one deliberate Portainer stack update after source/native/release gates pass.",
                "Verify init/finalize, long-running services, Setup Center, DNS/exit, clients, and protected ports.",
                "Revalidate ASUS forwarding after the production smoke test; do not blindly reinstall the helper.",
            ],
        },
        "protected_invariants": [
            "no production build: source path",
            "Setup Center 8786 stays private",
            "router admin/API ports stay private",
            "SOCKS5 1080 stays LAN/tunnel-only",
            "Portainer, SSH, and AdGuard admin stay private",
            "preserve unrelated ASUS/JFFS hooks",
        ],
    }


RELEASE_PANEL = r'''
<section class="panel" data-tab="release-status">
  <div class="card hero"><div class="row"><div class="grow"><h2 style="margin-bottom:4px">Release & recovery</h2><div class="small">Truthful exact-SHA status without granting Setup Center Docker/Portainer control.</div></div><button class="btn primary" onclick="refreshReleaseStatus()">Refresh</button></div><div id="rvpnReleaseSummary" class="grid3" style="margin-top:12px"></div></div>
  <div class="card"><h2>Safe update boundary</h2><div id="rvpnReleaseBoundary" class="small">Loading…</div></div>
  <div class="card"><h2>Recovery sequence</h2><ol id="rvpnRecoverySteps" class="small"></ol></div>
  <div class="card"><h2>Protected invariants</h2><ul id="rvpnReleaseInvariants" class="small"></ul></div>
</section>
<script id="routerVpnReleaseStatusScript">
(()=>{const tab=document.createElement('button');tab.textContent='Release';tab.dataset.tab='release-status';tab.onclick=()=>{gotoTab('release-status');refreshReleaseStatus()};document.getElementById('tabs').appendChild(tab);const esc=v=>String(v??'').replace(/[&<>\"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','\"':'&quot;',"'":'&#39;'}[c]));const card=(t,v,n)=>`<div class="card" style="margin:0"><div class="small">${esc(t)}</div><div style="font-size:20px;font-weight:750;margin:4px 0">${esc(v)}</div><div class="small">${esc(n)}</div></div>`;window.refreshReleaseStatus=async()=>{const summary=document.getElementById('rvpnReleaseSummary');summary.innerHTML=card('Status','Loading…','Reading local release metadata');try{const r=await fetch('/api/release-status',{credentials:'same-origin',cache:'no-store'}),d=await r.json();if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);summary.innerHTML=card('Deployed SHA',d.deployed_sha,d.exact_sha?'Exact 40-hex source identity':'SHA metadata unavailable')+card('Production model',d.production_model,'No normal production build: path')+card('Self update',d.self_update_available?'Available':'Intentionally unavailable',d.self_update_reason);document.getElementById('rvpnReleaseBoundary').textContent=d.self_update_reason;document.getElementById('rvpnRecoverySteps').innerHTML=(d.recovery?.safe_sequence||[]).map(x=>`<li>${esc(x)}</li>`).join('');document.getElementById('rvpnReleaseInvariants').innerHTML=(d.protected_invariants||[]).map(x=>`<li>${esc(x)}</li>`).join('')}catch(e){summary.innerHTML=card('Status','Unavailable',e.message||'Release status failed')}}})();
</script>
'''
