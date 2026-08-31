#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
source = (ROOT / "ios/RouterVPN/App/IOSConnectionProfilesView.swift").read_text(encoding="utf-8")
for marker in (
    "static func add(model: RouterVPNModel, name: String) throws",
    "var values = try loadAll(); guard values.count < 64",
    "var values = try loadAll(); guard let index = values.firstIndex",
    "var values = try loadAll(); let before = values.count",
    "guard let saved = try loadAll().first(where: { $0.id == id })",
):
    assert marker in source, f"iOS connection-profile mutation lost fail-closed loader: {marker}"
for function in ("add", "update", "delete", "load"):
    start = source.index(f"    static func {function}(")
    next_start = source.find("\n    static func ", start + 8)
    body = source[start: next_start if next_start >= 0 else len(source)]
    for forbidden in ("var values = all()", "guard let saved = all().first"):
        assert forbidden not in body, f"iOS {function} still converts corrupt profile state into an empty collection: {forbidden}"
print("iOS connection-profile mutations fail closed on private-store errors: PASS")
