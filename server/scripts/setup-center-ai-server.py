#!/usr/bin/env python3
"""Authenticated Router VPN Setup Center + Full Guide + device UX + AI Help."""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from urllib.parse import urlparse

HERE = Path(__file__).resolve().parent


def _load(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, HERE / filename)
    if spec is None or spec.loader is None: raise RuntimeError(f"cannot load {filename}")
    module = importlib.util.module_from_spec(spec); sys.modules[name] = module; spec.loader.exec_module(module); return module

_core = _load("routervpn_setup_center_core", "setup-center-server.py")
_ai = _load("routervpn_ai_help_provider", "ai_help_provider.py")
_guide = _load("routervpn_setup_center_guide", "setup_center_guide.py")
_ux = _load("routervpn_setup_center_ux", "setup_center_ux_patch.py")

AI_PANEL = r'''
<style>
#rvpn-ai-help{position:fixed;right:22px;bottom:22px;z-index:1000;width:min(440px,calc(100vw - 32px));background:#111827;color:#f8fafc;border:1px solid #334155;border-radius:18px;box-shadow:0 20px 60px #0008;overflow:hidden;font:14px/1.45 system-ui}
#rvpn-ai-help summary{cursor:pointer;padding:14px 16px;font-weight:750;list-style:none;background:#172033}#rvpn-ai-help .rvpn-ai-body{padding:14px;display:grid;gap:10px}#rvpn-ai-help textarea{box-sizing:border-box;width:100%;min-height:100px;resize:vertical;background:#0b1220;color:#f8fafc;border:1px solid #334155;border-radius:12px;padding:10px}#rvpn-ai-help button{border:0;border-radius:11px;padding:9px 14px;background:#3157e3;color:white;font-weight:700;cursor:pointer}#rvpn-ai-answer{white-space:pre-wrap;max-height:260px;overflow:auto;background:#0b1220;border-radius:12px;padding:10px;display:none}#rvpn-ai-status{color:#94a3b8;font-size:12px}
</style>
<details id="rvpn-ai-help"><summary>AI Help</summary><div class="rvpn-ai-body"><div id="rvpn-ai-status">Checking provider…</div><textarea id="rvpn-ai-question" maxlength="4000" placeholder="Ask about setup, DNS, forwarding, kill switch, multihop, or a failed connection…"></textarea><button id="rvpn-ai-ask" type="button">Ask AI Help</button><div id="rvpn-ai-answer"></div><small>Provider keys stay server-side. Do not paste private keys, passwords, tokens, or full private bundles.</small></div></details>
<script>(()=>{const status=document.getElementById('rvpn-ai-status'),ask=document.getElementById('rvpn-ai-ask'),q=document.getElementById('rvpn-ai-question'),answer=document.getElementById('rvpn-ai-answer');const show=(t,b=false)=>{answer.style.display='block';answer.textContent=t;answer.style.color=b?'#fda4af':'#e2e8f0'};async function refresh(){try{const r=await fetch('/api/ai-help/status',{credentials:'same-origin',cache:'no-store'}),j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);status.textContent=j.available?`OpenAI AI Help ready • ${j.model}`:`AI Help unavailable • ${j.reason||'not configured'}`;ask.disabled=!j.available}catch(e){status.textContent='AI Help status unavailable';ask.disabled=true}}ask.addEventListener('click',async()=>{const question=q.value.trim();if(!question)return;ask.disabled=true;show('Thinking…');try{const r=await fetch('/api/ai-help',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({question})}),j=await r.json();if(!r.ok)throw new Error(j.error||r.statusText);show(j.answer||'No answer returned.')}catch(e){show(e.message||'AI Help failed',true)}finally{await refresh()}});refresh()})();</script>
'''


class Handler(_core.Handler):
    def _send_ai_json(self, status: int, payload: dict) -> None:
        raw = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        self.send_response(status); self.send_header("Content-Type", "application/json; charset=utf-8"); self.send_header("Cache-Control", "no-store"); self.send_header("X-Content-Type-Options", "nosniff"); self.send_header("Content-Length", str(len(raw))); self.end_headers(); self.wfile.write(raw)

    @staticmethod
    def _before_body(text: str, fragment: str) -> str:
        return text.replace("</body>", fragment + "\n</body>", 1) if "</body>" in text else text + fragment

    def _inject_admin_ui(self, text: str) -> str:
        enriched = super()._inject_admin_ui(text)
        if 'id="rvpn-guide-open"' not in enriched: enriched = self._before_body(enriched, _guide.GUIDE_PANEL)
        if 'id="rvpn-device-download"' not in enriched: enriched = self._before_body(enriched, _ux.UX_PATCH)
        if 'id="rvpn-ai-help"' not in enriched: enriched = self._before_body(enriched, AI_PANEL)
        return enriched

    def _ai_context(self) -> dict:
        return {"setup_center":"authenticated", "request_source":self.client_address[0] if self.client_address else "unknown", "path":urlparse(self.path).path}

    def do_GET(self) -> None:
        if urlparse(self.path).path == "/api/ai-help/status":
            if not self._require_auth(): return
            self._send_ai_json(200, self.server.ai_provider.status()); return
        super().do_GET()

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/ai-help": super().do_POST(); return
        if not self._require_auth(): return
        if self.headers.get("Transfer-Encoding"): self._send_ai_json(400, {"error":"chunked request bodies are not accepted"}); return
        try: length = int(self.headers.get("Content-Length", "0"))
        except ValueError: length = -1
        if length <= 0 or length > 16 * 1024: self._send_ai_json(413 if length > 16 * 1024 else 400, {"error":"invalid AI Help request size"}); return
        try: payload = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError): self._send_ai_json(400, {"error":"invalid JSON"}); return
        if not isinstance(payload, dict) or not isinstance(payload.get("question", ""), str): self._send_ai_json(400, {"error":"question must be text"}); return
        try:
            result = self.server.ai_provider.ask(payload.get("question", ""), context=self._ai_context(), client_id=self.client_address[0] if self.client_address else "unknown")
        except _ai.AIHelpError as exc: self._send_ai_json(503, {"error":str(exc)}); return
        except Exception:
            # Never return provider/key internals to the browser.
            self._send_ai_json(502, {"error":"AI Help provider failed"}); return
        self._send_ai_json(200, result)


class Server(_core.Server):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs); self.ai_provider = _ai.AIHelpProvider()


def main() -> int:
    ap=argparse.ArgumentParser(); ap.add_argument("--base",default="/opt/router-vpn"); ap.add_argument("--bind",default="0.0.0.0"); ap.add_argument("--port",type=int,default=8786); args=ap.parse_args()
    base=Path(args.base).resolve(); static=base/"downloads"; static.mkdir(parents=True,exist_ok=True); _core._broker.cleanup_stale_temp(); server=Server((args.bind,args.port),Handler,base,static)
    print(f"Router VPN Setup Center on {args.bind}:{args.port}; authenticated admin/downloads + Full Guide + device UX + server-side AI Help", flush=True)
    try: server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt: pass
    finally: server.server_close()
    return 0

if __name__ == "__main__": raise SystemExit(main())
