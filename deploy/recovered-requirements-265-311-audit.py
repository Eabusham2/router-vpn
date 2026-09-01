#!/usr/bin/env python3
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
errors=[]
def text(p):
 q=ROOT/p
 if not q.is_file(): errors.append(f'missing {p}'); return ''
 return q.read_text(errors='replace')
def need(p,*ms):
 s=text(p)
 for m in ms:
  if m not in s: errors.append(f'{p}: missing {m!r}')
def forbid(p,*ms):
 s=text(p)
 for m in ms:
  if m in s: errors.append(f'{p}: forbidden {m!r}')
def exists(*ps):
 for p in ps:
  if not (ROOT/p).exists(): errors.append(f'missing {p}')
rc=text('.github/workflows/release-candidate.yml')
def rc_has(*cs):
 for c in cs:
  if c not in rc: errors.append(f'RC missing {c!r}')

# 265-274 release proof: source gates now cover typed URI round trips, forced
# strategy rollback and broker jobs. Physical interoperability/leak/visual proof
# remains live instead of being inferred from process-running smoke tests.
rc_has('python3 server/scripts/test_setup_imports.py','python3 modes/test_smart_auto_rollback.py','python3 server/scripts/test_download_jobs.py','python3 modes/test_multihop.py','python3 deploy/test-killswitch-transition-contract.py')
need('server/scripts/test_setup_imports.py','test_sip002','test_ssr','test_hysteria_validation')
need('modes/test_smart_auto_rollback.py','last-good rollback behavior')
need('server/scripts/test_download_jobs.py','queued','building','ready','cancel')

# 275-276 readiness truth and GitHub-first/native ARM64 development.
need('server/scripts/generate-setup-assets.py','does <b>not</b> promise every platform has that engine','exact live reason before Connect')
need('.github/workflows/arm64-portainer-preflight.yml','runs-on: ubuntu-24.04-arm')
need('docs/CURRENT-GUIDE.md','never use the AI Board as a substitute native build environment')

# 277-291 private exposure + production/ASUS/AI Board invariants.
need('router/asus-merlin-router-vpn-forwards.sh','8786','8787','9443','14444','45999','TAG=ROUTER_VPN','ACME_EXTERNAL_PORT=${ACME_EXTERNAL_PORT:-80}','ACME_INTERNAL_PORT=${ACME_INTERNAL_PORT:-18080}')
forbid('router/asus-merlin-router-vpn-forwards.sh','ip6tables -A','iptables -P FORWARD','iptables -F FORWARD')
need('server/portainer-current.yaml','image: ghcr.io/eabusham2/router-vpn-')
forbid('server/portainer-current.yaml','build:','context: https://github.com')
need('deploy/docker-cleanup-safety-audit.py','docker\\s+system\\s+prune','docker\\s+(?:image|container|volume|builder|buildx)\\s+prune')
need('server/wireguard/Dockerfile','wireguard-go')
need('server/finalize/current-entrypoint.sh','https://icanhazip.com','https://api.ipify.org')

# 292-301 docs/product truth.
need('deploy/package-builds.sh','LICENSE')
for term in ('Portainer','ASUS','Downloads','DNS','forward','Security','license'):
 if term.lower() not in text('README.md').lower(): errors.append(f'README missing product topic {term}')
need('README.md','## Production environment and images','WAN_INTERFACE=eth0','LAN_CIDR=192.168.50.0/24','ADGUARD4=192.168.50.133','## Automatic update, recovery, and troubleshooting','## License')
need('server/scripts/generate-setup-assets.py','20 raw runtimes','16 logical modes','DAITA-like','not claimed to be Mullvad','public exit IP','private SOCKS address')
need('README.md','Physical release validation still requires','real off-LAN compatible-client interoperability')

# 302-311 retired designs must stay retired from active product/build paths.
for p in ('client/Prepare-Windows-Mode-Catalog.ps1','client/RouterVPN-Windows-Product.ps1','deploy/full-audit-v3.py'):
 if (ROOT/p).exists(): errors.append(f'retired source revived: {p}')
need('deploy/check-generic-package-secrets.py','RETIRED_WINDOWS_PAYLOADS')
need('server/scripts/publish-downloads.sh','node_linking','separate-bundle-or-pairing')
need('docs/CURRENT-GUIDE.md','PortableApps/PAF is retired','image-only')
forbid('server/portainer-current.yaml','build:')

live_only=[265,266,268,269,271,272,274]
if errors:
 print('RECOVERED REQUIREMENTS 265-311 AUDIT: FAIL')
 for e in errors: print(' - '+e)
 raise SystemExit(1)
print('RECOVERED REQUIREMENTS 265-311 AUDIT: PASS')
print('Physical/live proof remains required for:',','.join(map(str,live_only)))
