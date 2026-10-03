#!/usr/bin/env python3
"""Execute the production saved-graph normalizer; no Android OS is simulated."""
from pathlib import Path
import re,shutil,subprocess,tempfile
ROOT=Path(__file__).resolve().parents[1]
source=(ROOT/'android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java').read_text()
match=re.search(r'    private static String normalizeMultiMode\(String value\)\{[^\n]+\}',source)
assert match,'saved-graph normalization method changed'
method=match.group(0)
harness='''import java.util.Locale;
public final class ModeContract {
'''+method+'''
public static void main(String[] args) {
 int checks=0;
 for(String mode:new String[]{"wg","awg2-fast","awg2-strong","shadowsocks","hysteria2"}){
  if(!normalizeMultiMode(mode).equals(mode)||!normalizeMultiMode(" "+mode.toUpperCase(Locale.ROOT)+" ").equals(mode))throw new AssertionError("saved exit transport changed"); checks+=2;
 }
 for(String mode:new String[]{"awg2","awg2-pq","max","wg;exec","none"}){
  boolean rejected=false;try{normalizeMultiMode(mode);}catch(IllegalArgumentException expected){rejected=true;}
  if(!rejected)throw new AssertionError("unimplemented or malformed transport accepted");checks++;
 }
 if(!normalizeMultiMode(null).equals("shadowsocks")||!normalizeMultiMode("").equals("shadowsocks"))throw new AssertionError("legacy default changed");checks+=2;
 System.out.println("Production Android saved multihop modes: PASS ("+checks+" checks)");
}}
'''
with tempfile.TemporaryDirectory(prefix='routervpn-mode-contract-') as folder:
 root=Path(folder);path=root/'ModeContract.java';path.write_text(harness)
 subprocess.run([shutil.which('javac') or 'javac',str(path)],check=True,timeout=45)
 subprocess.run([shutil.which('java') or 'java','-cp',str(root),'ModeContract'],check=True,timeout=15)
