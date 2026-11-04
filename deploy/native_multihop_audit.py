"""Source-only closure for the public native multihop shipping adapters.

This is a bounded structural guard, not evidence of native runtime execution.
Comments and string contents cannot supply calls; calls must occur in the owned
handler, whose sole public wrapper installs the exact production adapters.
"""
from __future__ import annotations

import re

_TOKEN = re.compile(r'//[^\n]*|/\*.*?\*/|"(?:\\.|[^"\\])*"|`[^`]*`|\'(?:\\.|[^\'\\])*\'|[A-Za-z_][A-Za-z_0-9]*|\d+|[^\s]', re.S)


def _tokens(source: str) -> list[str]:
    return [m.group() for m in _TOKEN.finditer(source)
            if not m.group().startswith(("//", "/*"))]


def _positions(tokens: list[str], fragment: str) -> list[int]:
    wanted = _tokens(fragment)
    return [i for i in range(len(tokens) - len(wanted) + 1)
            if tokens[i:i + len(wanted)] == wanted]


def _function(tokens: list[str], declaration: str) -> list[str] | None:
    positions = _positions(tokens, declaration + " {")
    if len(positions) != 1:
        return None
    start = positions[0] + len(_tokens(declaration)) + 1
    depth = 1
    for end in range(start, len(tokens)):
        depth += (tokens[end] == "{") - (tokens[end] == "}")
        if depth == 0:
            return tokens[start:end]
    return None


def native_multihop_shipping_chain(source: str) -> bool:
    tokens = _tokens(source)
    public = _function(tokens, "func (a *app) nativeMultihopConnect(w http.ResponseWriter, r *http.Request)")
    expected = _tokens("""
        a.nativeMultihopConnectOwned(w, r, nativeMultihopConnectRuntime{
            capture: captureNativeMultihopForApp, preflight: preflightOwnedNativeMultihopCommand,
            stage: stageOwnedNativeMultihopCommand, proof: (*app).proveNativeMultihop,
        })
    """)
    if public != expected:
        return False
    routes = _function(tokens, "func registerDesktopMultihopRoutes(h *http.ServeMux, a *app)")
    if routes is None or len(_positions(routes, 'h.HandleFunc("/api/multihop/connect", a.nativeMultihopConnect)')) != 1:
        return False
    owned = _function(tokens, "func (a *app) nativeMultihopConnectOwned(w http.ResponseWriter, r *http.Request, driver nativeMultihopConnectRuntime)")
    if owned is None or owned.count("driver") != 4:
        return False
    calls = (
        "sel, err = driver.capture(a, sel, []string{sel.ExitMode})",
        "native, err := driver.preflight(a, sel, nil)",
        "err = driver.stage(a, sel, native)",
        "cmd := native.command",
        "err = cmd.Start()",
        "err = bindNativeMultihopRuntime(a, native, sel, network)",
        "proofErr := driver.proof(a, sel, cmd)",
    )
    previous = -1
    for call in calls:
        matches = _positions(owned, call)
        if len(matches) != 1 or matches[0] <= previous:
            return False
        previous = matches[0]
    return True
