#!/usr/bin/env python3
"""Run the current durable-state contract without rewriting its predicates.

The v1 filename is retained for continuity, but its contract already includes
Android profile migration, retained MTU owners and captured native children.
Reapplying the historical textual overlay rejects those stronger predicates
before any source or behavior checks can run. Execute that contract directly
and preserve its failures and complete behavior-test matrix.
"""
from pathlib import Path
import runpy


if __name__ == "__main__":
    contract = Path(__file__).resolve().with_name("durable-state-transaction-audit-v1.py")
    runpy.run_path(str(contract), run_name="__main__")
