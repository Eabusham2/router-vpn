#!/usr/bin/env python3
"""Package provenance compatibility entrypoint.

The implementation lives in ``deploy/source_provenance.py`` so release and
package provenance share one audited parser, atomic writer, and verifier.  This
server-side path remains stable because the download broker and native package
scripts execute it from the complete exact-SHA source tree.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_IMPL = Path(__file__).resolve().parents[2] / "deploy" / "source_provenance.py"
_SPEC = importlib.util.spec_from_file_location("router_vpn_source_provenance_impl", _IMPL)
if _SPEC is None or _SPEC.loader is None:
    raise RuntimeError(f"cannot load source provenance implementation: {_IMPL}")
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)

# Re-export the implementation API for build-download-on-demand.py, whose
# existing compatibility import loads this file as a module.
for _name in dir(_MODULE):
    if not _name.startswith("__"):
        globals()[_name] = getattr(_MODULE, _name)

if __name__ == "__main__":
    raise SystemExit(_MODULE._main())
