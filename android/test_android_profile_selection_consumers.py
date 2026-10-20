#!/usr/bin/env python3
"""Exercise the real catalog, Activity and connection-profile selection helpers."""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / "app/src/main/java/com/eabusham/routervpn"


def body(name):
    source = (JAVA / name).read_text()
    start = source.index("    private static JSONObject selectedProfile(JSONObject bundle)")
    return source[start:source.index("\n", start)]


HARNESS = r'''package com.eabusham.routervpn;
import org.json.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;
public final class SelectedProfileHarness {
 static int checks;static void check(boolean value,String message){checks++;if(!value)throw new AssertionError(message);}
 interface Call{JSONObject run()throws Exception;}
 static JSONObject profile(String id)throws Exception{return new JSONObject().put("id",id).put("dns_host",id+".invalid");}
 static JSONObject bundle(String selected,JSONArray rows)throws Exception{JSONObject b=new JSONObject().put("routerProfiles",rows);if(selected!=null)b.put("selectedRouterID",selected);return b;}
 static void run(JSONObject value,String expected)throws Exception{
  Path file=Files.createTempFile("routervpn-owned-profile-",".json");
  try{
   Files.writeString(file,value.toString(),StandardCharsets.UTF_8);
   Call[] readers={()->ActivityProfile.selected(value),()->ConnectionProfile.selected(value),()->AndroidUnifiedNodeCatalog.selectedProfile(file.toFile())};
   for(Call reader:readers){
    if(expected==null){try{reader.run();throw new AssertionError("missing/duplicate selected identity silently fell back");}catch(IllegalStateException required){checks++;}}
    else{JSONObject result=reader.run();check(result.getString("id").equals(expected)&&result.getString("dns_host").equals(expected+".invalid"),"policy/telemetry selected another profile");}
   }
  }finally{Files.delete(file);}
 }
 public static void main(String[] args)throws Exception{
  run(bundle("second",new JSONArray().put(profile("first")).put(profile("second"))),"second");
  run(bundle("missing",new JSONArray().put(profile("first")).put(profile("second"))),null);
  run(bundle("same",new JSONArray().put(profile("same")).put(profile("same"))),null);
  run(bundle("second",new JSONArray().put(JSONObject.NULL).put(profile("second"))),"second");
  run(bundle("first",new JSONArray()),null);
  run(bundle(null,new JSONArray().put(profile("initial"))),"initial");
  run(new JSONObject().put("selected_id","alias").put("router_profiles",new JSONArray().put(profile("alias"))),"alias");
  run(new JSONObject().put("selected_id","gone").put("router_profiles",new JSONArray().put(profile("alias"))),null);
  run(bundle(" second ",new JSONArray().put(profile("first")).put(profile("second"))),"second");
  System.out.println("Android shipping profile selection consumers: PASS "+checks+" exact-identity checks");
 }
}
'''


def main():
    with tempfile.TemporaryDirectory(prefix="routervpn-profile-consumers-") as work:
        tmp = Path(work)
        app = tmp / "com/eabusham/routervpn";app.mkdir(parents=True)
        for name in ("AndroidProfileSelection.java", "AndroidUnifiedNodeCatalog.java"):
            (app / name).write_text((JAVA / name).read_text())
        for cls, name in (("ActivityProfile", "ProductActivity.java"), ("ConnectionProfile", "AndroidConnectionProfileStore.java")):
            (app / (cls+".java")).write_text("package com.eabusham.routervpn;import org.json.*;final class "+cls+" {"+body(name)+" static JSONObject selected(JSONObject value){return selectedProfile(value);}}")
        (app / "SelectedProfileHarness.java").write_text(HARNESS)
        (app / "CatalogStores.java").write_text('''package com.eabusham.routervpn;
import java.io.File;import java.util.*;
final class AndroidNodeStore {static final int MAX_BUNDLE=32*1024*1024;static final class Node{String id,name,endpoint;File file;}String activeId(){return "";}List<Node> list(){return Collections.emptyList();}}
final class AndroidStandardExitStore {static final class Entry{String id,name,server,protocol,expectedPublicIp;int serverPort;}List<Entry> list(){return Collections.emptyList();}}
''')
        jar="/usr/share/java/com.android.json.jar"
        compile_cmd=["javac","--release","17","-cp",jar,"-d",str(tmp),*map(str,tmp.rglob("*.java"))]
        subprocess.run(compile_cmd,check=True,timeout=30)
        run=["java","-cp",str(tmp)+":"+jar,"com.eabusham.routervpn.SelectedProfileHarness"]
        subprocess.run(run,check=True,timeout=15)
        original=(app/"AndroidProfileSelection.java").read_text()
        # Reintroduce the exact wrong-target behavior beneath all three consumers.
        start=original.index('        if (!selected.isEmpty()) {')
        stop=original.index('        if (first == null)',start)
        mutated=original[:start]+original[stop:]
        (app/"AndroidProfileSelection.java").write_text(mutated)
        subprocess.run(compile_cmd,check=True,timeout=30)
        result=subprocess.run(run,text=True,capture_output=True,timeout=15)
        assert result.returncode!=0 and "silently fell back" in result.stderr,result.stdout+result.stderr
    print("Android selected-profile negative control: missing-id first-profile fallback rejected")


if __name__ == "__main__":
    main()
