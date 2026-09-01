#!/usr/bin/env python3
"""Guard the private Setup Center's responsive, non-blocking admin UI."""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
errors: list[str] = []


def read(path: str) -> str:
    p = ROOT / path
    if not p.is_file():
        errors.append(f"missing {path}")
        return ""
    return p.read_text(encoding="utf-8", errors="replace")


def need(path: str, *markers: str) -> None:
    body = read(path)
    for marker in markers:
        if marker not in body:
            errors.append(f"{path}: missing {marker!r}")


# The generated private LAN Setup Center must use explicit readable button
# colors rather than browser defaults, keep the onboarding overlay hidden until
# requested, remain keyboard visible, and collapse cleanly on narrow screens.
need(
    "server/scripts/generate-setup-assets.py",
    "background-color:#15213a;background-image:none",
    "color:var(--text);cursor:pointer",
    ".overlay[hidden]{display:none}",
    "max-height:92vh;overflow:auto",
    "@media(max-width:820px)",
    "Start / resume setup",
    "Close for now",
    "Full guide",
    "Keep this page private",
)
need(
    "server/scripts/setup_center_ux_patch.py",
    "Shipping Setup Center accessibility/responsive overrides",
    "button:focus-visible",
    "outline:3px solid #69d2ff",
    "button:disabled{opacity:.55;cursor:not-allowed}",
    ".tabs button{flex:1 1 130px}",
    ".download .btn{width:100%;text-align:center}",
    ".wizard{padding:15px;max-height:calc(100vh - 24px)}",
)

# Progressive download UI may float, but it must not exceed the viewport or
# cover the entire small-screen Setup Center. Safe-area spacing matters on iOS.
need(
    "server/scripts/setup_center_ux_patch.py",
    "max-height:calc(100vh - 44px);overflow:auto",
    "@media(max-width:560px)",
    "right:12px",
    "env(safe-area-inset-bottom)",
    "width:auto;max-width:none;text-align:center",
    "max-height:calc(100vh - 24px - env(safe-area-inset-bottom))",
    'role="status" aria-live="polite"',
    'aria-label="Hide download progress"',
    "Cancel",
    "Retry",
)

# A browser/network interruption must not orphan an authenticated package job
# or make the UI claim delivery merely because an iframe loaded. Persist only a
# bounded same-origin job-status path in tab-local sessionStorage, reject
# redirects/non-local job URLs, pause while offline, and resume on visibility or
# connectivity restoration. The declaration may share a statement with nearby
# immutable browser-capability values; audit the durable key itself rather than
# enforcing one source-formatting layout.
need(
    "server/scripts/setup_center_ux_patch.py",
    "persistedJobKey='routervpn.setup.download-job.v2'",
    "function safeSameOriginPath(value,prefix)",
    "sessionStorage.setItem(persistedJobKey",
    "sessionStorage.removeItem(persistedJobKey)",
    "redirect:'error'",
    "Refused a non-local Setup Center job URL",
    "The job returned an unsafe download URL and was not opened.",
    "Setup Center will not claim delivery until the server confirms it.",
    "document.addEventListener('visibilitychange'",
    "window.addEventListener('online'",
    "window.addEventListener('offline'",
    "Resuming authenticated download job",
    "Date.now()-Number(saved.saved_at||0)<6*60*60*1000",
    "direct_href:safeSameOriginPath(lastRequest&&lastRequest.directHref,'/')",
    "lastRequest={name:active.name,directHref:direct||''}",
)

# Setup Center remains deployment/admin/recovery. It must not claim to be the
# native daily VPN app or expose itself on WAN as part of UI convenience.
need(
    "server/scripts/generate-setup-assets.py",
    "Private LAN Setup Center",
    "Router VPN app",
    "do not WAN-forward it",
    "ASUS forwarding",
)
need(
    "server/scripts/setup_center_ux_patch.py",
    "Download for this device",
)
need(
    "server/scripts/setup-center-server.py",
    "Server status & administration",
    "Connected clients",
    "persistent server controls",
)

if errors:
    print("SETUP CENTER RESPONSIVE UI AUDIT: FAIL")
    for error in errors:
        print(" - " + error)
    raise SystemExit(1)

print("SETUP CENTER RESPONSIVE UI AUDIT: PASS")
