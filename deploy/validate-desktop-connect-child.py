#!/usr/bin/env python3
"""Compile the original typed CONNECT desktop child and Box with strict controls.

The bounded process owner, source projection, verdict parser, original generic
regressions and heartbeat controls are shared with the existing SOCKS gate.
This component gate does not establish installed native acceptance.
"""
from pathlib import Path
from collections import Counter
import copy
import importlib.util
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("desktop_connect_original_child_gate", ROOT/"deploy/validate-desktop-socks-child.py")
BASE = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = BASE
spec.loader.exec_module(BASE)


def concrete(value):
    """Translate only the closed typed-family inventory, never regressions."""
    if isinstance(value, str):
        return value.replace("socks", "connect").replace("SOCKS", "CONNECT")
    if isinstance(value, list):
        return [concrete(item) for item in value]
    if isinstance(value, dict):
        return {concrete(key): concrete(item) for key, item in value.items()}
    return value


ORIGINAL_REGRESSIONS = copy.deepcopy(BASE.REGRESSIONS)
ORIGINAL_CONTROLS = copy.deepcopy(BASE.CONTROLS)
INVENTORY = copy.deepcopy(BASE.INVENTORY)
INVENTORY["child"] = concrete(INVENTORY["child"])
INVENTORY["projections"] = concrete(INVENTORY["projections"])
CHILD = INVENTORY["child"]
CHILD["dependencies"] = [
    "published original macosprocess NodeChainCONNECTFamily and transfer",
    "original private CONNECT final Shadowsocks UoT-v2 capability",
]
CHILD["source_files"].extend([
    "deploy/validate-desktop-connect-child.py", "deploy/validate-desktop-socks-child.py",
    "internal/mobilemultihop/desktop_node_chain_connect_policy.go",
    "internal/mobilemultihop/desktop_node_chain_connect_physical.go",
    "internal/mobilemultihop/node_chain_connect_source.go",
    "internal/mobilemultihop/node_chain_connect_integrity.go",
    "internal/mobilemultihop/node_chain_connect_runtime.go",
])
graph_root = "TestRouterVPNDesktopNodeChainCONNECTPhysicalRejectsGraphDrift"
carrier_case = graph_root+"/final-carrier"
CHILD["box_cases"].insert(CHILD["box_cases"].index(graph_root+"/final-detour")+1, carrier_case)

# The new templates are formatted Go. Each causal replacement still removes
# exactly its original check, without changing timeout or ownership budgets.
CONTROLS = CHILD["controls"]
for control in CONTROLS:
    name = control["name"]
    if name in ("original-factory-join", "original-proof-join"):
        control["before"] = "\tselect {\n\tcase <-state.done:\n\tcase <-ctx.Done():\n\t\treturn ctx.Err()\n\t}"
    elif name == "failed-proof-retention":
        control["before"] = "\tif state.proof != nil {\n\t\tif err := state.proof.CloseContext(ctx); err != nil {\n\t\t\treturn err\n\t\t}\n\t}"
        control["after"] = "\tif state.proof != nil { _ = state.proof.CloseContext(ctx) }"
    elif name == "original-caller-local-registry":
        control["before"] = "\tif err := owner.construction.current(ctx); err != nil {\n\t\treturn err\n\t}"
    elif name == "original-measurement-hold":
        control["before"] = "\tif owner == nil || owner.measurementHold.Load() || owner.current(ctx) != nil {\n\t\treturn nil, routerVPNExternalFailure\n\t}"
        control["after"] = "\tif owner == nil || owner.current(ctx) != nil {\n\t\treturn nil, routerVPNExternalFailure\n\t}"
        control["additional_replacements"] = [{
            "before": "\tif err := owner.current(ctx); err != nil || owner.measurementHold.Load() {\n\t\tactivity.release()\n\t\treturn nil, errors.Join(err, routerVPNExternalFailure)\n\t}",
            "after": "\tif err := owner.current(ctx); err != nil {\n\t\tactivity.release()\n\t\treturn nil, errors.Join(err, routerVPNExternalFailure)\n\t}",
        }]
    elif name == "typed-whole-box-before-acquisition":
        control["cases"].insert(control["cases"].index(graph_root+"/final-detour")+1, carrier_case)

# Every invocation retains the original 90-second Go limit and 100-second
# process bound. CONNECT's repeated original-source/physical-authority checks
# make the aggregate 83-case invocation exceed 90 seconds under the race build;
# the three closed groups preserve every original case and lifecycle deadline.
COMMAND_GROUPS = (
    ("typed-child-command", (
        "TestRouterVPNDesktopCONNECTCommandExactSourceReplay",
        "TestRouterVPNDesktopCONNECTCommandRefusesChangedCapture",
        "TestRouterVPNDesktopNodeChainCONNECTCommandKeepsCapturedArguments",
        "TestRouterVPNDesktopNodeChainCONNECTCommandRefusesMixedDarwinFlags",
        "TestRouterVPNDesktopNodeChainCONNECTCommandRequiresOriginalParent",
        "TestRouterVPNDesktopNodeChainCONNECTCommandDarwinOriginalManifest",
        "TestRouterVPNDesktopCONNECTFiftyOperationSchema",
        "TestRouterVPNDesktopCONNECTFiftyBorrowedOperationHTTP",
    )),
    ("typed-child-construction", (
        "TestRouterVPNDesktopCONNECTConstructionKeepsLocalRegistry",
        "TestRouterVPNDesktopCONNECTConstructionRejectsReplacement",
    )),
    ("typed-child-runtime", (
        "TestRouterVPNDesktopNodeChainCONNECTRuntimeOriginalGeneration",
        "TestRouterVPNDesktopNodeChainCONNECTRuntimeLateFactoryJoin",
        "TestRouterVPNDesktopNodeChainCONNECTRuntimeEnteredProofJoin",
        "TestRouterVPNDesktopNodeChainCONNECTRuntimeRetainsFailedJoin",
        "TestRouterVPNDesktopNodeChainCONNECTRuntimeRejectsForeignIdentity",
        "TestRouterVPNDesktopNodeChainCONNECTRuntimeActivityJoin",
        "TestRouterVPNDesktopNodeChainCONNECTRuntimeMeasurementExcludesMTU",
        "TestRouterVPNDesktopNodeChainCONNECTRuntimeRejectsCandidateAuthority",
    )),
)


def child_command_suites():
    names = tuple(name for name, _ in COMMAND_GROUPS)
    roots = [root for _, group in COMMAND_GROUPS for root in group]
    expected_roots = CHILD["command_roots"]
    expected_cases = CHILD["command_cases"]
    if (names != ("typed-child-command", "typed-child-construction", "typed-child-runtime")
            or Counter(roots) != Counter(expected_roots)
            or len(set(roots)) != len(roots)
            or len(set(expected_cases)) != len(expected_cases)):
        raise ValueError("CONNECT command groups lost their exact original roots")
    suites = []
    for name, group in COMMAND_GROUPS:
        cases = [case for case in expected_cases if case.split("/", 1)[0] in group]
        if not group or not cases or any(root not in cases for root in group):
            raise ValueError("CONNECT command group lost its original root verdict")
        suites.append(dict(name=name, package="cmd", selector="^("+"|".join(group)+")$",
                           cases=cases, process_seconds=100))
    if (Counter(case for suite in suites for case in suite["cases"]) != Counter(expected_cases)
            or tuple(len(suite["cases"]) for suite in suites) != (53, 11, 19)):
        raise ValueError("CONNECT command groups lost the exact disjoint 83-case inventory")
    return suites


BASE.SUITE = "desktop-connect-child"
BASE.SOURCE_PROJECTION_SCRIPT = "deploy/test_desktop_connect_child_sources.py"
BASE.SOURCE_PROJECTION_CLASS = "DesktopCONNECTChildProjection"
BASE.INVENTORY = INVENTORY
BASE.CHILD = CHILD
BASE.PROJECTIONS = INVENTORY["projections"]
BASE.CONTROLS = CONTROLS
BASE.REGRESSIONS = INVENTORY["regressions"]
BASE.child_command_suites = child_command_suites

# Export the exact existing parser/process APIs for focused regression tests.
SUITE = BASE.SUITE
PROJECTIONS = BASE.PROJECTIONS
REGRESSIONS = BASE.REGRESSIONS
PACKAGE = BASE.PACKAGE
PROJECTION_TESTS = BASE.PROJECTION_TESTS
require_projection = BASE.require_projection
require_verdict = BASE.require_verdict
mutate = BASE.mutate
validate = BASE.validate

if __name__ == "__main__":
    BASE.main()
