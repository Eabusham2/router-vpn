#!/usr/bin/env python3
"""Run original shipping callbacks and controls independently for HTTP and HTTPS CONNECT."""
import importlib.util
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
spec=importlib.util.spec_from_file_location('callbacks',ROOT/'deploy/test_ios_ordered_latency_callbacks.py')
C=importlib.util.module_from_spec(spec);spec.loader.exec_module(C)
def main():
    original=C.BOUNDARY.replace('var connected=true,', 'var forceForeignKind=false\n var connected=true,').replace('boundaryTransport == "socks5" ? .socks', '(boundaryTransport == "socks5" || forceForeignKind) ? .socks')
    C.TESTS=C.TESTS.replace('  for position in 0..<3{', '\n  let foreign=RouterVPNModel();foreign.forceForeignKind=true;let unavailable=IOSOrderedLatency();unavailable.load(foreign)\n  check("CONNECT cannot borrow SOCKS capture",unavailable.ids.isEmpty)\n  for position in 0..<3{')
    for mode in ('http-connect','https-connect'):
        assert original.count('let boundaryTransport="socks5"')==1
        C.BOUNDARY=original.replace('let boundaryTransport="socks5"','let boundaryTransport="'+mode+'"')
        C.TESTS=C.TESTS.replace('iOS ordered fifty actual app callbacks:', 'iOS '+mode+' fifty actual app callbacks:')
        C.main([('typed-capture','guard path[1].mode == "socks5", Data(original.source.utf8) == active','guard true, Data(original.source.utf8) == active','CONNECT cannot borrow SOCKS capture')])
        C.TESTS=C.TESTS.replace('iOS '+mode+' fifty actual app callbacks:', 'iOS ordered fifty actual app callbacks:')
        print('Completed actual CONNECT fifty callback mode: '+mode,flush=True)
if __name__=='__main__':main()
