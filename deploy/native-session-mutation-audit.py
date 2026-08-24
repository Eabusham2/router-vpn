#!/usr/bin/env python3
from pathlib import Path
import subprocess, sys
ROOT=Path(__file__).resolve().parents[1]
AUDITS=(
    'deploy/ios-session-mutation-audit.py',
    'deploy/android-session-mutation-audit.py',
    'deploy/windows-session-mutation-audit.py',
    'deploy/macos-session-mutation-audit.py',
    'deploy/linux-session-mutation-audit.py',
)
for rel in AUDITS:
    path=ROOT/rel
    if not path.is_file():
        raise SystemExit(f'native session mutation audit missing: {rel}')
    subprocess.run([sys.executable,str(path)],cwd=ROOT,check=True)
print('Cross-platform native session mutation audit: PASS')
