#!/usr/bin/env python3
from pathlib import Path

# Repair the one-shot patch's indentation handling and avoid mutating text that
# the permanent Setup Center normalizer intentionally replaces/test-drives.
p = Path('server/scripts/_final_gap_patch.py')
s = p.read_text(encoding='utf-8')
old = '''def replace_between(text: str, start: str, end: str, replacement: str, label: str) -> str:\n    a = text.find(start)\n    if a < 0:\n        raise SystemExit(f"{label}: start marker not found")\n    b = text.find(end, a)\n    if b < 0:\n        raise SystemExit(f"{label}: end marker not found")\n    return text[:a] + textwrap.dedent(replacement).lstrip("\\n") + text[b:]\n'''
new = '''def replace_between(text: str, start: str, end: str, replacement: str, label: str, *, dedent: bool = True) -> str:\n    a = text.find(start)\n    if a < 0:\n        raise SystemExit(f"{label}: start marker not found")\n    b = text.find(end, a)\n    if b < 0:\n        raise SystemExit(f"{label}: end marker not found")\n    value = textwrap.dedent(replacement).lstrip("\\n") if dedent else replacement.lstrip("\\n")\n    return text[:a] + value + text[b:]\n'''
if old not in s:
    raise SystemExit('replace_between helper source not found')
s = s.replace(old, new, 1)
old_call = 's = replace_between(s, devices_start, devices_end, new_devices, "native device guidance")'
new_call = 's = replace_between(s, devices_start, devices_end, new_devices, "native device guidance", dedent=False)'
if old_call not in s:
    raise SystemExit('device replacement call not found')
s = s.replace(old_call, new_call, 1)
# The normalizer owns hero-card and Methods-selector replacement.
s = s.replace('    "app/controller": "native app",\n', '')
start = s.find('# The Methods picker itself must never re-surface arbitrary advanced stacks.')
end = s.find('old_downloads = ', start)
if start < 0 or end < 0:
    raise SystemExit('temporary Methods selector patch block not found')
s = s[:start] + s[end:]
# Match the normalizer's permanent node-link label so its patch is idempotent.
s = s.replace("['Private recovery bundle','router-vpn-client-bundle.zip','Explicit private fallback/recovery bundle']", "['Private node-link bundle','router-vpn-client-bundle.zip','Separate private node data for an already-installed Router VPN app; extract router-vpn-bundle.json for file import']")
p.write_text(s, encoding='utf-8')

# Update the permanent normalizer so corrected source can be normalized twice
# without treating the new product contract as template drift.
p = Path('server/scripts/normalize-setup-imports.py')
s = p.read_text(encoding='utf-8')
old = '''def _replace_required(html: str, old: str, new: str, label: str) -> str:\n    if old not in html:\n        raise RuntimeError(f"Setup Center UI template drifted before {label} patch")\n    return html.replace(old, new, 1)\n'''
new = '''def _replace_required(html: str, old: str, new: str, label: str) -> str:\n    if old in html:\n        return html.replace(old, new, 1)\n    if new in html:\n        return html\n    raise RuntimeError(f"Setup Center UI template drifted before {label} patch")\n'''
if old not in s:
    raise SystemExit('normalizer required-replace helper not found')
s = s.replace(old, new, 1)
s = s.replace(
    'if ident == "shadowsocks" and method.get("config") and endpoint:',
    'if ident == "shadowsocks" and method.get("config") and endpoint and endpoint != "router.invalid":',
    1,
)
s = s.replace(
    'method["simple"] = lane in ("simple-native", "universal") or ident == "router-vpn-app"',
    'method["simple"] = lane in SETUP_METHOD_LANES or ident == "router-vpn-app"',
    1,
)
old = '''        if not payload:\n            method["qrSupported"] = False\n            method["qrPayload"] = ""\n            method["qrPngBase64"] = ""\n        else:\n'''
new = '''        if not payload or "router.invalid" in payload.lower():\n            method["qrSupported"] = False\n            method["qrPayload"] = ""\n            method["qrPngBase64"] = ""\n        else:\n'''
if old not in s:
    raise SystemExit('normalizer QR guard not found')
s = s.replace(old, new, 1)
p.write_text(s, encoding='utf-8')
