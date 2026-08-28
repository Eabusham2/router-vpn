#!/usr/bin/env python3
from __future__ import annotations

import ast
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
from unittest import mock

SCRIPT = Path(__file__).with_name("benchmark-dns.py")


def load():
    spec = importlib.util.spec_from_file_location("router_vpn_dns_benchmark", SCRIPT)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {SCRIPT}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def main() -> int:
    module = load()
    with tempfile.TemporaryDirectory(prefix="router-vpn-dns-state-") as td:
        root = Path(td)
        target = root / "dns-fastest.json"
        module.write_private_atomic(target, '{"measurement_only":true}\n')
        assert target.read_text(encoding="utf-8") == '{"measurement_only":true}\n'
        if os.name != "nt":
            assert target.stat().st_mode & 0o777 == 0o600
        assert not list(root.glob(".dns-fastest.json.tmp-*"))

        foreign = root / "foreign-dns.json"
        foreign.write_text('{"foreign":true}\n', encoding="utf-8")
        os.chmod(foreign, 0o600)
        real_mkstemp = module.PRIVATE_WRITER.tempfile.mkstemp

        def mkstemp_then_swap(*args, **kwargs):
            fd, name = real_mkstemp(*args, **kwargs)
            os.replace(foreign, target)
            return fd, name

        with mock.patch.object(module.PRIVATE_WRITER.tempfile, "mkstemp", side_effect=mkstemp_then_swap):
            try:
                module.write_private_atomic(target, '{"measurement_only":false}\n')
            except RuntimeError as exc:
                assert "identity changed before adoption" in str(exc)
            else:
                raise AssertionError("DNS benchmark overwrote a foreign regular replacement")
        assert target.read_text(encoding="utf-8") == '{"foreign":true}\n'

        if os.name != "nt":
            real = root / "real.json"
            real.write_text("keep\n", encoding="utf-8")
            os.chmod(real, 0o600)
            target.unlink()
            target.symlink_to(real)
            try:
                module.write_private_atomic(target, "replace\n")
            except RuntimeError as exc:
                assert "symlink" in str(exc)
            else:
                raise AssertionError("DNS benchmark accepted a symlink output")
            assert real.read_text(encoding="utf-8") == "keep\n"

    # Benchmark execution owns only its measurement output. An AST constant
    # check ignores explanatory comments while failing if code reintroduces a
    # literal routers.json path for policy mutation.
    tree = ast.parse(SCRIPT.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Constant) and isinstance(node.value, str) and "routers.json" in node.value:
            raise AssertionError("DNS benchmark code regained routers.json ownership")

    print("DNS benchmark measurement-only persistence tests: OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
