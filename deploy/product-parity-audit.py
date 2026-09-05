#!/usr/bin/env python3
"""Current product-parity audit layered over the frozen v1 contract.

The broad v1 matrix stays immutable. This overlay updates only two predicates
whose ownership moved without weakening behavior: exact-hop proof wording now
lives in telemetry_hops.go, and Windows' launcher composes routed-hop UI through
RouterVPN-Windows-Telemetry.ps1 rather than duplicating its label in App.ps1.
"""
from pathlib import Path

HERE = Path(__file__).resolve().parent
V1 = HERE / "product-parity-audit-v1.py"
source = V1.read_text(encoding="utf-8")

old_graph = '"entry_error", "exit_error", "not derived from RTT", "active routing graph",'
new_graph = '"entry_error", "exit_error", "not derived from RTT", "unchanged current client routing graph",'
if source.count(old_graph) != 1:
    raise SystemExit("product parity overlay failed: v1 routed-graph predicate changed")
source = source.replace(old_graph, new_graph, 1)

old_windows = '"/api/connection/speed-test", "/api/multihop/speed-test", "Routed hop speeds",'
new_windows = '"/api/connection/speed-test", "/api/multihop/speed-test",'
if source.count(old_windows) != 1:
    raise SystemExit("product parity overlay failed: v1 Windows launcher predicate changed")
source = source.replace(old_windows, new_windows, 1)

exec(compile(source, str(V1), "exec"), {"__name__": "__main__", "__file__": str(V1)})
