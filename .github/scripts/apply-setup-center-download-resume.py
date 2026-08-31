#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REL = "server/scripts/setup_center_ux_patch.py"
PATH = ROOT / REL


def run(*args: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=ROOT, text=True, check=check)


def commit(paths: list[str], message: str) -> None:
    run("git", "add", "-A", "--", *paths)
    status = run("git", "diff", "--cached", "--quiet", check=False)
    if status.returncode == 0:
        return
    if status.returncode != 1:
        raise SystemExit(f"git diff failed: {status.returncode}")
    run("git", "commit", "-m", message)


def replace_once_or_verify(text: str, old: str, new: str, label: str) -> str:
    old_count = text.count(old)
    new_count = text.count(new)
    if old_count == 1 and new_count == 0:
        return text.replace(old, new, 1)
    if old_count == 0 and new_count == 1:
        return text
    raise SystemExit(f"{label} drift: old={old_count} new={new_count}")


def patch() -> None:
    text = PATH.read_text(encoding="utf-8")
    text = replace_once_or_verify(
        text,
        " let family='unknown',active=null,pollTimer=0,lastRequest=null,downloadStarted=false;",
        " const persistedJobKey='routervpn.setup.download-job.v2';\n let family='unknown',active=null,pollTimer=0,lastRequest=null,downloadStarted=false;",
        "download persistence key",
    )
    text = replace_once_or_verify(
        text,
        " function terminal(j){return ['failed','cancelled','delivered','delivery-interrupted','expired'].includes(j.status)}\n function render(j){",
        " function terminal(j){return ['failed','cancelled','delivered','delivery-interrupted','expired'].includes(j.status)}\n function safeSameOriginPath(value,prefix){try{const u=new URL(String(value||''),location.href);return u.origin===location.origin&&u.pathname.startsWith(prefix)?u.pathname+u.search:''}catch(_){return''}}\n function persistActive(){try{if(!active||terminal(active)){sessionStorage.removeItem(persistedJobKey);return}const status=safeSameOriginPath(active.status_url,'/api/download-jobs/');if(!status){sessionStorage.removeItem(persistedJobKey);return}sessionStorage.setItem(persistedJobKey,JSON.stringify({status_url:status,name:active.name||'',saved_at:Date.now()}))}catch(_){}}\n function clearPersisted(){try{sessionStorage.removeItem(persistedJobKey)}catch(_){}}\n function render(j){",
        "download persistence helpers",
    )
    text = replace_once_or_verify(
        text,
        "   cancel.disabled=terminal(j)||j.status==='delivered';cancel.style.display=terminal(j)?'none':'';retry.style.display=(j.status==='failed'||j.status==='cancelled'||j.status==='delivery-interrupted'||j.status==='expired')?'':'none';\n }",
        "   cancel.disabled=terminal(j)||j.status==='delivered';cancel.style.display=terminal(j)?'none':'';retry.style.display=(j.status==='failed'||j.status==='cancelled'||j.status==='delivery-interrupted'||j.status==='expired')?'':'none';\n   if(terminal(j))clearPersisted();else persistActive();\n }",
        "download render persistence",
    )
    text = replace_once_or_verify(
        text,
        " async function json(path,opt={}){const r=await fetch(path,{credentials:'same-origin',cache:'no-store',...opt});let d={};try{d=await r.json()}catch{}if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);return d}",
        " async function json(path,opt={}){const safe=safeSameOriginPath(path,'/api/');if(!safe)throw new Error('Refused a non-local Setup Center job URL');const r=await fetch(safe,{credentials:'same-origin',cache:'no-store',redirect:'error',...opt});let d={};try{d=await r.json()}catch{}if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);return d}",
        "same-origin job API",
    )
    text = replace_once_or_verify(
        text,
        " function stopPoll(){if(pollTimer){clearTimeout(pollTimer);pollTimer=0}}\n async function poll(){",
        " function stopPoll(){if(pollTimer){clearTimeout(pollTimer);pollTimer=0}}\n function schedulePoll(delay){stopPoll();pollTimer=setTimeout(poll,document.hidden?Math.max(delay,1600):delay)}\n async function poll(){",
        "visibility-aware polling",
    )
    text = replace_once_or_verify(
        text,
        "     if(j.status==='ready'&&!downloadStarted&&j.download_url){downloadStarted=true;frame.src=j.download_url;phase.textContent='Starting browser download…';}\n     if(!terminal(j)){pollTimer=setTimeout(poll,500)}\n   }catch(e){phase.textContent=`Progress check failed: ${e.message}`;pollTimer=setTimeout(poll,1200)}",
        "     if(j.status==='ready'&&!downloadStarted&&j.download_url){const download=safeSameOriginPath(j.download_url,'/api/download-jobs/');if(!download){phase.textContent='The job returned an unsafe download URL and was not opened.'}else{downloadStarted=true;frame.src=download;phase.textContent='Browser download requested. Setup Center will not claim delivery until the server confirms it.'}}\n     if(!terminal(j))schedulePoll(500)\n   }catch(e){phase.textContent=navigator.onLine?`Progress check failed: ${e.message}`:'Offline. The authenticated download job will resume when this device reconnects.';persistActive();schedulePoll(1200)}",
        "safe download and resilient poll",
    )
    text = replace_once_or_verify(
        text,
        "     const d=await json('/api/download-jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});render(d.job);poll();",
        "     const d=await json('/api/download-jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});render(d.job);persistActive();poll();",
        "persist created job",
    )
    text = replace_once_or_verify(
        text,
        " close.addEventListener('click',()=>{panel.style.display='none'});\n\n // A method with a missing prerequisite",
        " close.addEventListener('click',()=>{panel.style.display='none'});\n frame.addEventListener('load',()=>{if(active&&!terminal(active)){phase.textContent='The browser accepted the download request; waiting for server delivery confirmation…';persistActive()}});\n document.addEventListener('visibilitychange',()=>{if(active&&!terminal(active)&&!document.hidden)schedulePoll(0)});\n window.addEventListener('online',()=>{if(active&&!terminal(active)){phase.textContent='Back online; resuming authenticated download progress…';schedulePoll(0)}});\n window.addEventListener('offline',()=>{if(active&&!terminal(active)){stopPoll();phase.textContent='Offline. The authenticated download job is preserved for this tab.';persistActive()}});\n try{const saved=JSON.parse(sessionStorage.getItem(persistedJobKey)||'null');const status=safeSameOriginPath(saved&&saved.status_url,'/api/download-jobs/');if(status&&Date.now()-Number(saved.saved_at||0)<6*60*60*1000){active={status_url:status,name:String(saved.name||'Router VPN package')};panel.style.display='block';title.textContent=active.name;phase.textContent='Resuming authenticated download job…';poll()}else clearPersisted()}catch(_){clearPersisted()}\n\n // A method with a missing prerequisite",
        "download resume listeners",
    )
    PATH.write_text(text, encoding="utf-8")
    commit([REL], "Resume Setup Center downloads after interruption [skip ci]")


def cleanup() -> None:
    paths = [
        ".github/workflows/one-shot-setup-center-download-resume.yml",
        ".github/scripts/apply-setup-center-download-resume.py",
    ]
    for rel in paths:
        path = ROOT / rel
        if path.exists():
            path.unlink()
    commit(paths, "Remove completed download-resume automation [skip ci]")


def main() -> int:
    patch()
    run("git", "diff", "--check")
    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
