#!/usr/bin/env python3
"""Execute the exact pinned HTTP response correction with the race detector."""
from pathlib import Path
import importlib.util
import os
import subprocess
import tempfile
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('connections',ROOT/'deploy/xray_connection_policy.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)

def main():
    old,new=next((a,b) for a,b in module.PATCHES['transport/internet/splithttp/client.go'] if a.startswith('type WaitReadCloser'))
    tests=(ROOT/'mobile/applexray/wait_reader_test.go.tmpl').read_text()
    with tempfile.TemporaryDirectory(prefix='routervpn-http-owner-') as tmp:
        root=Path(tmp);(root/'go.mod').write_text('module routervpn-http-owner\n\ngo 1.23\n')
        (root/'response.go').write_text('package splithttp\nimport("io";"sync")\n'+new)
        (root/'response_test.go').write_text(tests)
        subprocess.run(['go','test','-race','-count=1','-timeout=30s','./...'],cwd=root,check=True,timeout=60)
    print('PASS exact shipping HTTP response publication, late adoption, and close barrier')
if __name__=='__main__':main()
