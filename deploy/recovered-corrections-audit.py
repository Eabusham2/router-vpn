#!/usr/bin/env python3
"""Binding chat-history corrections C1-C7."""
from pathlib import Path
import json
ROOT=Path(__file__).resolve().parents[1]
def text(rel): return (ROOT/rel).read_text(encoding='utf-8')
def need(rel,*markers):
 s=text(rel)
 for m in markers: assert m in s, f'C1-C7: {rel} missing {m!r}'
def forbid(rel,*markers):
 s=text(rel)
 for m in markers: assert m not in s, f'C1-C7: {rel} contains superseded {m!r}'
# C1: AWG config/source exists, but third-party off-LAN readiness remains live until validated.
need('server/scripts/generate-setup-assets.py','Third-party off-LAN interoperability remains a live validation gate','Amnezia-compatible app')
# C2: onboarding lifecycle must auto-return until complete and remain reopenable.
need('server/scripts/generate-setup-assets.py',"WIZKEY='routervpn.setupcenter.done.v5'",'localStorage.getItem(WIZKEY)',"startWizard(false)")
need('server/scripts/setup_center_verified_onboarding.py','Run onboarding again','routerVpnRunOnboardingAgain')
# C3: sensitive management routes require authenticated same-origin proxy handling.
need('server/scripts/setup-center-product-server.py','_require_auth()','/api/admin/update','/api/admin/server-control','/api/admin/forwarding-extension')
need('server/scripts/setup-center-server.py','ADMIN_MUTATION_EXACT','/api/admin/clients/revoke','/api/admin/forwarding')
# C4: blank AdGuard Allowed Clients means unrestricted; VPN ranges only matter for an intentionally restrictive list.
for rel in ('docs/CURRENT-GUIDE.md','server/scripts/generate-setup-assets.py','server/scripts/setup_center_guide.py'):
 need(rel,'Allowed Clients','blank','10.77.0.0/24','10.78.0.0/24','fd77:77::/64','fd78:78::/64')
# C5: router-local fallback is a requested generic Windows package, never home-linked node material.
need('server/scripts/download-broker.py','"local_build_platforms": ["windows-amd64", "windows-arm64", "windows-portable-amd64", "windows-portable-arm64"]')
need('server/scripts/publish-downloads.sh','generic_packages_secret_free','node_linking','separate-bundle-or-pairing')
# C6: normal production stays image-only; local compile is not a server/Portainer fallback.
compose=text('server/portainer-current.yaml')
assert 'build:' not in compose, 'C6: production compose regained build:'
assert 'image:' in compose, 'C6: production compose is not image based'
need('docs/CURRENT-GUIDE.md','macOS and Linux never use the AI Board as a substitute native build environment')
# C7: installer packages are generic; add/link many nodes as separate data.
need('server/scripts/generate-setup-assets.py','Install Router VPN once','without reinstalling','router-vpn-bundle.json','one-time pairing')
need('server/scripts/publish-downloads.sh', "'router-vpn-client-bundle.zip'", "'node_linking':'separate-bundle-or-pairing'")
assert 'router-vpn-portableapps-amd64.zip' not in text('server/scripts/publish-downloads.sh').split('wanted=[',1)[1].split(']',1)[0], 'C7: retired PortableApps became an active download target'
for rel in ('README.md','docs/CURRENT-GUIDE.md','docs/INSTALL-PORTAINER.md','docs/PRODUCTION-RELEASE.md','docs/CURRENT-STATUS.md'):
    body=text(rel)
    assert '45999' in body, f'C4/security: {rel} lost private DAITA-like 45999 boundary'
    assert ('8786-8793' in body or '8786–8793' in body), f'C4/security: {rel} lost private Setup Center/control 8786-8793 boundary'
print('Recovered chat-history corrections C1-C7: PASS')
