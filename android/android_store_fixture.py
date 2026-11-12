"""Complete saved-store dependencies for standalone Java contract fixtures.

The files, parser, protection and transport structures are shipping source.
Native imported compilation is outside these fixtures and fails if entered;
the ordered source composition gate exercises that boundary against real Go.
"""
from pathlib import Path

JAVA = Path(__file__).resolve().parent / 'app/src/main/java/com/eabusham/routervpn'


def sources():
    result = {f'com/eabusham/routervpn/{name}.java': (JAVA / f'{name}.java').read_text()
              for name in ('AndroidStandardExitStore', 'AndroidNumericAddress',
                           'AndroidExternalProtection', 'AndroidExternalAmnezia', 'AndroidOpenVPN')}
    result['com/eabusham/routervpn/AndroidExternalPolicy.java'] = '''package com.eabusham.routervpn;
final class AndroidExternalPolicy {
 static org.json.JSONObject profile(AndroidStandardExitStore.Entry entry)throws Exception{
  throw new AssertionError("Imported ordered native capture belongs to the shipping shared-compiler composition gate.");
 }
}'''
    result['com/eabusham/routervpn/AndroidTorProfile.java'] = '''package com.eabusham.routervpn;
import java.security.MessageDigest;
final class AndroidTorProfile {
 static boolean isTor(String protocol){return "tor".equals(protocol)||"tor-bridge".equals(protocol);}
 static void validate(AndroidStandardExitStore.Entry entry)throws Exception{
  throw new AssertionError("Tor compilation belongs to the actual Tor compiler composition gate.");
 }
}'''
    digest = next(line for line in (JAVA / 'AndroidTorProfile.java').read_text().splitlines() if 'static String digest(byte[] data)' in line)
    key = 'com/eabusham/routervpn/AndroidTorProfile.java'
    result[key] = result[key][:-1] + digest + '\n}'
    return result


NATIVE_BOUNDARIES = '''
public static String routerCompileAmneziaProfile(String profile,String identity){throw new AssertionError("Unentered native Amnezia compiler boundary");}
public static void routerValidateExternalOpenVPNPairing(String profile,String pairing){throw new AssertionError("Unentered native OpenVPN pairing boundary");}
public static void routerValidateExternalOpenVPNResponseProbes(String profile,String probes){throw new AssertionError("Unentered native OpenVPN response boundary");}
public static void routerValidateExternalOpenVPNStartLayers(String profile,String probes,String layers,String mode){throw new AssertionError("Unentered native OpenVPN layer boundary");}
public static String routerOpenVPNEndpoint(String config,String username,String password,String tag,String detour){throw new AssertionError("Unentered native OpenVPN endpoint boundary");}
public static String version(){throw new AssertionError("Unentered native version boundary");}
'''
