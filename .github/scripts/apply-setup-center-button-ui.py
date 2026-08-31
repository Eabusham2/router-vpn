#!/usr/bin/env python3
from __future__ import annotations

import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REL = "server/scripts/generate-setup-assets.py"
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


def patch_ui() -> None:
    text = PATH.read_text(encoding="utf-8")
    old = '.tabs button,.btn,button,select,input{font:inherit}.tabs button,.btn,button{padding:10px 13px;border-radius:11px;border:1px solid var(--line);background:#15213a;color:var(--text);cursor:pointer}.tabs button.active,.btn.primary{border-color:#4aa6cf;background:#163d54}.btn.danger{border-color:#80434d;background:#391b24}'
    new = '.tabs button,.btn,button,select,input{font:inherit}.tabs button,.btn,button{-webkit-appearance:none;appearance:none;display:inline-flex;align-items:center;justify-content:center;gap:7px;min-height:40px;padding:10px 13px;border-radius:11px;border:1px solid var(--line);background-color:#15213a;background-image:none;background-clip:padding-box;color:var(--text);cursor:pointer;text-decoration:none;line-height:1.2;font-weight:600;box-shadow:inset 0 1px 0 #ffffff0b;transition:border-color .15s ease,background-color .15s ease,transform .08s ease,opacity .15s ease}.tabs button:hover,.btn:hover,button:hover{border-color:#426c92;background-color:#1a2a47}.tabs button:active,.btn:active,button:active{transform:translateY(1px);background-color:#112039}.tabs button:focus-visible,.btn:focus-visible,button:focus-visible,select:focus-visible,input:focus-visible{outline:3px solid #69d2ff66;outline-offset:2px}.tabs button:disabled,.btn[aria-disabled="true"],button:disabled{cursor:not-allowed;opacity:.48;transform:none;background-color:#101a2d;color:#9cabca}.tabs button.active,.btn.primary{border-color:#4aa6cf;background-color:#163d54;color:#eefaff}.btn.danger{border-color:#80434d;background-color:#391b24;color:#ffeef1}.btn.danger:hover{background-color:#4a202b}.btn>svg,button>svg{flex:none}'
    if text.count(old) == 1 and new not in text:
        text = text.replace(old, new, 1)
    elif old not in text and text.count(new) == 1:
        pass
    else:
        raise SystemExit("Setup Center button CSS drifted")

    old_input = 'select,input{padding:10px;border-radius:10px;border:1px solid var(--line);background:#0c1425;color:var(--text)}'
    new_input = 'select,input{-webkit-appearance:none;appearance:none;min-height:40px;padding:10px 12px;border-radius:10px;border:1px solid var(--line);background-color:#0c1425;background-image:none;color:var(--text);caret-color:var(--accent)}select{padding-right:34px;background-image:linear-gradient(45deg,transparent 50%,#9cabca 50%),linear-gradient(135deg,#9cabca 50%,transparent 50%);background-position:calc(100% - 17px) 50%,calc(100% - 12px) 50%;background-size:5px 5px,5px 5px;background-repeat:no-repeat}'
    if text.count(old_input) == 1 and new_input not in text:
        text = text.replace(old_input, new_input, 1)
    elif old_input not in text and text.count(new_input) == 1:
        pass
    else:
        raise SystemExit("Setup Center input CSS drifted")

    old_media = '@media(max-width:820px){.grid2,.grid3{grid-template-columns:1fr}.wrap{padding:12px}.card{padding:13px}.tabs{position:static}.download{align-items:flex-start;flex-direction:column}.grow{min-width:0;width:100%}}'
    new_media = '@media(max-width:820px){.grid2,.grid3{grid-template-columns:1fr}.wrap{padding:max(12px,env(safe-area-inset-top)) max(12px,env(safe-area-inset-right)) max(12px,env(safe-area-inset-bottom)) max(12px,env(safe-area-inset-left))}.card{padding:13px}.tabs{position:static;overflow-x:auto;flex-wrap:nowrap;padding-bottom:6px;-webkit-overflow-scrolling:touch}.tabs button{white-space:nowrap;flex:0 0 auto}.download{align-items:flex-start;flex-direction:column}.grow{min-width:0;width:100%}.row>.btn,.row>button{max-width:100%}.wizard{padding:15px}.overlay{padding:max(10px,env(safe-area-inset-top)) max(10px,env(safe-area-inset-right)) max(10px,env(safe-area-inset-bottom)) max(10px,env(safe-area-inset-left))}}@media(forced-colors:active){.tabs button,.btn,button,select,input{forced-color-adjust:auto;border:1px solid ButtonText}.tabs button.active,.btn.primary{outline:2px solid Highlight}.btn.danger{border-color:Mark}}'
    if text.count(old_media) == 1 and new_media not in text:
        text = text.replace(old_media, new_media, 1)
    elif old_media not in text and text.count(new_media) == 1:
        pass
    else:
        raise SystemExit("Setup Center responsive CSS drifted")

    PATH.write_text(text, encoding="utf-8")
    commit([REL], "Fix Setup Center button and background rendering [skip ci]")


def cleanup() -> None:
    paths = [
        ".github/workflows/one-shot-setup-center-button-ui.yml",
        ".github/scripts/apply-setup-center-button-ui.py",
    ]
    for rel in paths:
        path = ROOT / rel
        if path.exists():
            path.unlink()
    commit(paths, "Remove completed Setup Center UI automation [skip ci]")


def main() -> int:
    patch_ui()
    run("git", "diff", "--check")
    cleanup()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
