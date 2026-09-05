#!/usr/bin/env python3
"""Compatibility alias for the flattened recovered release scorer.

All current predicates live directly in recovered-release-audit-v3.py. Keep this
entry point temporarily only for callers that have not yet been repointed; it
must not rewrite scorer source in memory.
"""
from pathlib import Path

V3 = Path(__file__).resolve().with_name("recovered-release-audit-v3.py")
source = V3.read_text(encoding="utf-8")
exec(compile(source, str(V3), "exec"), {"__name__": "__main__", "__file__": str(V3)})
