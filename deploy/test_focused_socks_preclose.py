#!/usr/bin/env python3
"""Require captured SOCKS preclose and every original native MTU/owner gate."""
from pathlib import Path
import argparse
import hashlib
import importlib.util
import json
import sys

ROOT=Path(__file__).resolve().parents[1]
SUITE="socks-preclose"
BASE_PATH=ROOT/"deploy/test_focused_socks_native_mtu.py"
spec=importlib.util.spec_from_file_location("socks_preclose_original_mtu",BASE_PATH)
MTU=importlib.util.module_from_spec(spec);sys.modules[spec.name]=MTU;spec.loader.exec_module(MTU)
BASE=MTU.BASE
DATA=json.loads(r'''{"roots":["TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement","TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners","TestRouterNodeChainSOCKSPrecloseSurvivesRetiredProof","TestRouterNodeChainSOCKSPrecloseKeepsInvalidatedSourceCleanup","TestRouterNodeChainSOCKSPrecloseSealsUnacquiredFactory"],"cases":["TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement","TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement/box-joined","TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement/box-failed","TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement/instance-joined","TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement/instance-failed","TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners","TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners/box","TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners/instance","TestRouterNodeChainSOCKSPrecloseSurvivesRetiredProof","TestRouterNodeChainSOCKSPrecloseKeepsInvalidatedSourceCleanup","TestRouterNodeChainSOCKSPrecloseSealsUnacquiredFactory"],"projections":{"socks_close_native_test.go.tmpl":"experimental/libbox/routervpn_node_chain_socks_close_test.go"},"controls":[{"name":"preclose-direct-box-before-endpoint","path":"routervpn_node_chain_execution_close.go","before":"\tpreclose := s.RouterVPNCloseSOCKSMiddle()\n","after":"\tvar preclose error\n","root":"TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement$/^box-(joined|failed)","cases":["TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement","TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement/box-joined","TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement/box-failed"],"witness":"native cancellation or endpoint close preceded original SOCKS join","package":"github.com/sagernet/sing-box/experimental/libbox"},{"name":"preclose-instance-before-cancel","path":"daemon/routervpn_instance_close.go","before":"\tpreclose := i.instance.RouterVPNCloseSOCKSMiddle()\n","after":"\tvar preclose error\n","root":"TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement$/^instance-(joined|failed)","cases":["TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement","TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement/instance-joined","TestRouterNodeChainSOCKSPrecloseBeforeNativeRetirement/instance-failed"],"witness":"native cancellation or endpoint close preceded original SOCKS join","package":"github.com/sagernet/sing-box/experimental/libbox"},{"name":"preclose-retained-original-outbound","path":"protocol/routervpnnodesocks/socks_owner.go","before":"\tc.original = original\n","after":"\t// causal control omits the retained original\n","root":"TestRouterNodeChainSOCKSPrecloseKeepsInvalidatedSourceCleanup","cases":["TestRouterNodeChainSOCKSPrecloseKeepsInvalidatedSourceCleanup"],"witness":"retained original source cleanup was not joined","package":"github.com/sagernet/sing-box/experimental/libbox"},{"name":"preclose-acquired-box-identity","path":"routervpn_node_chain_socks.go","before":"\ts.RouterVPNCaptureCloseReceipt()\n","after":"\t// causal control omits acquired Box identity\n","root":"TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners$/^box","cases":["TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners","TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners/box"],"witness":"foreign native close retired original association","package":"github.com/sagernet/sing-box/experimental/libbox"},{"name":"preclose-acquired-instance-identity","path":"daemon/routervpn_instance_close.go","before":"\tif r.owner != nil && r.owner != i || r.original != nil && r.original != i.instance {\n","after":"\tif r.original != nil && r.original != i.instance {\n","root":"TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners$/^instance","cases":["TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners","TestRouterNodeChainSOCKSPrecloseRejectsCopiedOwners/instance"],"witness":"foreign native close retired original association","package":"github.com/sagernet/sing-box/experimental/libbox"},{"name":"preclose-sealed-unacquired-factory","path":"protocol/routervpnnodesocks/socks_owner.go","before":"\tif c.registered || c.claimed || c.retired {\n","after":"\tif c.registered || c.claimed {\n","root":"TestRouterNodeChainSOCKSPrecloseSealsUnacquiredFactory","cases":["TestRouterNodeChainSOCKSPrecloseSealsUnacquiredFactory"],"witness":"retired captured factory reopened registration","package":"github.com/sagernet/sing-box/experimental/libbox"}]}''')
ROOTS=tuple(DATA["roots"]);CASES=tuple(DATA["cases"])
CONTROLS=tuple(dict(x,cases=tuple(x["cases"])) for x in DATA["controls"])
ORIGINAL_TYPED=tuple(BASE.VERDICTS)
ORIGINAL_BOX=tuple(BASE.ORIGINAL_BOX)
ORIGINAL_CONTROLS=tuple(BASE.CONTROLS)
# Only the fixed inventory changes. The original separate desktop/mobile
# preparers, strict parser, immutable-source checks, image identity, process
# joins and all compiler/native/caller deadlines remain in the original driver.
BASE.SUITE=SUITE
BASE.PROJECTIONS.update(DATA["projections"])
BASE.BRIDGE_ROOTS=(*BASE.BRIDGE_ROOTS,*ROOTS)
BASE.BRIDGE=(*BASE.BRIDGE,*CASES)
BASE.VERDICTS=(*BASE.VERDICTS,*CASES)
BASE.CONTROLS=(*BASE.CONTROLS,*CONTROLS)

def validate(source,source_sha,output,go="go"):
    receipt=MTU.validate(source,source_sha,output,go)
    receipt.update(scope="captured-original-SOCKS-preclose-and-native-MTU-component-composition",
        preserved_preclose_typed_cases=list(ORIGINAL_TYPED),
        preserved_preclose_box_cases=list(ORIGINAL_BOX),
        preclose_cases=list(CASES),preclose_component_accepted=True,
        preclose_component_boundaries=["finite packet-prefix TCP/UDP socket boundary",
            "actual authenticated SOCKS association and original control-reader join",
            "original typed Box and daemon Instance with held/failed/copy-owner retirement"],
        trusted_preclose_validator_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        trusted_original_mtu_validator_sha256=hashlib.sha256(BASE_PATH.read_bytes()).hexdigest())
    # This component gate cannot certify successful encrypted Run, installed
    # native routing, a physical interface or any public admission decision.
    for name in ("receipt.json","progress.json"):
        path=Path(output)/name;temporary=path.with_suffix(".tmp")
        temporary.write_text(json.dumps(receipt,indent=2)+"\n");temporary.replace(path)
    return receipt

def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite",required=True,choices=(SUITE,))
    parser.add_argument("--source",required=True,type=Path)
    parser.add_argument("--source-sha",required=True)
    parser.add_argument("--output",required=True,type=Path)
    parser.add_argument("--go",default="go")
    args=parser.parse_args();validate(args.source,args.source_sha,args.output,args.go)
if __name__=="__main__":main()
