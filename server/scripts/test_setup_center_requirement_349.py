#!/usr/bin/env python3
"""Requirement 349: prove server-management components ship in final served Setup Center."""
from __future__ import annotations
import importlib.util, sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[2]
path=ROOT/'server/scripts/setup-center-product-server.py'
spec=importlib.util.spec_from_file_location('rvpn_req349',path); mod=importlib.util.module_from_spec(spec); assert spec and spec.loader; sys.modules[spec.name]=mod; spec.loader.exec_module(mod)
h=object.__new__(mod.Handler)
base='<html><body><div id="tabs"></div><div id="wizard" class="overlay"></div><script>function gotoTab(x){}</script></body></html>'
rendered=h._inject_product_ui(base)
for marker in (
    'data-tab="server-admin"','Server status & administration','Connected clients','Persistent port forwarding','Protected ports & listeners',
    'data-tab="release-status"','Release & recovery','id="rvpn-server-control-script"','Stop VPN','Emergency Stop','Resume VPN',
    'id="rvpn-update-script"','Exact-SHA update','routerVpnCheckUpdate','routerVpnApplyUpdate',
    'Authenticated exact-SHA update is available from Release & recovery','automatically restores the prior stack',
):
    assert marker in rendered, f'final served Setup Center missing requirement-349 marker: {marker!r}'
assert 'Server update and one-click recovery remain unavailable' not in rendered
source=path.read_text(encoding='utf-8')
for marker in ('/api/release-status','/api/admin/update','/api/admin/server-control','/api/admin/forwarding-extension','_require_auth()'):
    assert marker in source, f'final Setup Center proxy missing {marker}'
# Forwarding card may be constructed dynamically by JS; require its creation/API path rather than a static DOM id.
admin=(ROOT/'server/scripts/setup-center-server.py').read_text(encoding='utf-8')
for marker in ('adminForwardRules','addAdminForwardRule','/api/admin/forwarding','forwarding_master','lan_access'):
    assert marker in admin, f'server admin shipping path missing {marker}'
for marker in ('delete caps.server_update','delete caps.recovery_actions','caps.setup_center_exact_sha_update=true','caps.automatic_update_rollback=true'):
    assert marker in admin, f'served capability boundary missing {marker}'
assert "server update: not implemented" not in rendered.lower(), 'served product still contradicts exact-SHA Update support'
assert "recovery actions: not implemented" not in rendered.lower(), 'served product still contradicts rollback/recovery support'
print('Setup Center requirement 349 final served-product integration: PASS')
