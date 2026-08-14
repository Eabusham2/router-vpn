#!/usr/bin/env python3
from pathlib import Path

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
p.write_text(s, encoding='utf-8')
