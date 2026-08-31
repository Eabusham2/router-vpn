#!/usr/bin/env python3
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def require(path: str, *markers: str) -> None:
    body = (ROOT / path).read_text(encoding='utf-8')
    missing = [marker for marker in markers if marker not in body]
    if missing:
        raise SystemExit(f'{path}: missing Android session-mutation marker(s): {missing}')


require(
    'android/app/src/main/java/com/eabusham/routervpn/AndroidVpnMutationGuard.java',
    'final class AndroidVpnMutationGuard',
    'static boolean isBusy(Context context)',
    'if (context == null) return true',
    'hasOwnedVpnTransport(context)',
    'phaseBusy(home.connected, phase)',
    'Unknown/future',
    '"off".equals(phase)',
    '"disconnected".equals(phase)',
    '"failed".equals(phase)',
    'e.orchestrator.isRunning()',
    'e.multihop.isActiveOrTransitioning()',
    'e.standardExit.isActiveOrTransitioning()',
    'tunnelBusy(e.wireGuard.getState())',
    'tunnelBusy(e.amneziaWG.getState())',
    'runtimeBusy(e.singBox.getState())',
    'runtimeBusy(e.xray.getState())',
    'return true;',
)

require(
    'android/app/src/main/java/com/eabusham/routervpn/AndroidStandardExitRuntime.java',
    'synchronized boolean isActiveOrTransitioning()',
    'task!=null&&!task.isDone()',
    'if(state==null)return true',
    '!"external".equals(home.logicalMode)',
    'engines.wireGuard.getState()!=com.wireguard.android.backend.Tunnel.State.DOWN',
    'engines.amneziaWG.getState()!=org.amnezia.awg.backend.Tunnel.State.DOWN',
    'runtimeBusy(engines.xray.getState())',
)
require(
    'android/app/src/main/java/com/eabusham/routervpn/AndroidUnifiedConnectionController.java',
    'boolean isActiveOrTransitioning() { return AndroidVpnMutationGuard.isBusy(activity); }',
)

require(
    'android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java',
    'private boolean mutationBusy()',
    'AndroidVpnMutationGuard.isBusy(this)',
    'nodeButton.setEnabled(!busy)',
    'fastestButton.setEnabled(!busy)',
    'killSwitch.setEnabled(!busy)',
    'multihopToggle.setEnabled(!busy)',
    'modeSpinner.setEnabled(!busy)',
    'dnsSpinner.setEnabled(!busy)',
    'VPN state changed while Fastest was measuring',
    'VPN state changed while permission was open',
    'before redeeming the one-time pairing code',
    'VPN state changed after pairing redemption',
   'before selecting another Router profile',
    'before deleting a Router profile',
    'before saving CUSTOM presets',
    'before deleting CUSTOM presets',
    'before saving multihop',
    'before changing persistent kill-switch policy',
   'before changing DNS',
)
require(
    'android/app/src/main/java/com/eabusham/routervpn/StandardExitActivity.java',
    'AndroidVpnMutationGuard.isBusy(this)',
    'addButton.setEnabled(!mutationBlocked)',
    'directButton.setEnabled(!mutationBlocked)',
    'hoppedButton.setEnabled(!mutationBlocked)',
    'before saving a custom exit',
   'before deleting a custom exit',
   'VPN state changed while permission was open',
)
require(
    'android/app/src/main/java/com/eabusham/routervpn/AndroidProductParity.java',
    'final boolean policyBusy=AndroidVpnMutationGuard.isBusy(activity)',
   'save.setEnabled(!AndroidVpnMutationGuard.isBusy(activity))',
    'Selected Router VPN profile changed while DNS settings were open',
    'persistBenchmark(nodeStore,openedProfileId,result)',
   'JSONObject bundle=activeBundle(store),profile=selectedProfile(bundle)',
    'measurement was not persisted',
)
# Benchmark persistence may update measured fastest metadata, but must never silently
# overwrite the selected dns_host from an asynchronously captured stale bundle.
dns_body = (ROOT / 'android/app/src/main/java/com/eabusham/routervpn/AndroidProductParity.java').read_text(encoding='utf-8')
persist = dns_body.split('private static void persistBenchmark', 1)[1].split('private static String dnsResultsText', 1)[0]
# Ignore the function signature parameter context; reject only an actual profile.put write.
if 'profile.put("dns_host"' in persist:
    raise SystemExit(g'AndroidProductParity.java: DNS benchmark persistence must not rewrite dns_host')

for path in [
    'android/app/src/main/java/com/eabusham/routervpn/AndroidProfileSettingsDialog.java',
    'android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfilesDialog.java',
    'android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java',
]:
    require(path, 'AndroidVpnMutationGuard.isBusy')

print('Android session mutation truth audit: PASS')
