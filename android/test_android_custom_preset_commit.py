#!/usr/bin/env python3
"""Execute the shipping CUSTOM commit primitive and actual Activity handlers.

Android UI/engine boundaries are deterministic doubles. This tests storage
failure, saved-mode/layer capture and no-connect guards, not a device tunnel.
The full APK build still type-checks the real Activity and Android APIs.
"""
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parent
JAVA = ROOT / 'app/src/main/java/com/eabusham/routervpn'
activity = (JAVA / 'ProductActivity.java').read_text()


def method(signature):
    start = activity.index('    private ' + signature)
    end = activity.index('\n    private ', start + 10)
    return activity[start:end]


HANDLERS = method('void saveCustomBuilder(') + method('void connectSavedCustomPreset(')
SOURCES = {
'android/content/SharedPreferences.java': '''package android.content;
public interface SharedPreferences {
 boolean contains(String key); String getString(String key,String fallback); Editor edit();
 interface Editor {Editor putString(String k,String v);Editor remove(String k);boolean commit();}
}''',
'com/eabusham/routervpn/CustomBoundaries.java': r'''package com.eabusham.routervpn;
import android.content.SharedPreferences;
import java.util.*;
final class MemoryPreferences implements SharedPreferences {
 final Map<String,String> values=new HashMap<>();
 final Deque<Integer> outcomes=new ArrayDeque<>();
 int commits;
 public boolean contains(String key){return values.containsKey(key);}
 public String getString(String key,String fallback){return values.getOrDefault(key,fallback);}
 public Editor edit(){return new Editor(){
  final Map<String,String> staged=new HashMap<>();
  public Editor putString(String key,String value){staged.put(key,value);return this;}
  public Editor remove(String key){staged.put(key,null);return this;}
  public boolean commit(){
   commits++;
   for(Map.Entry<String,String> item:staged.entrySet())if(item.getValue()==null)values.remove(item.getKey());else values.put(item.getKey(),item.getValue());
   int result=outcomes.isEmpty()?1:outcomes.removeFirst();
   if(result<0)throw new IllegalStateException("injected disk exception after memory change");
   return result==1;
  }
 };}
}
final class AndroidUnifiedNodeCatalog {static final class Item {String id="fixture-node";boolean router=true;boolean isRouterVpn(){return router;}}}
final class AndroidNodeStore {static final class Node {final String id;Node(String id){this.id=id;}}}
final class AlertDialog {boolean dismissed;void dismiss(){dismissed=true;}}
final class EditText {final String text;EditText(String text){this.text=text;}String getText(){return text;}}
final class Toggle {boolean checked;boolean isChecked(){return checked;}}
final class Label {String text;void setText(String s){text=s;}}
final class Connection {int calls;String mode,id;List<String>layers;void connectNode(AndroidNodeStore.Node node,String mode,List<String> layers,Object callback){calls++;this.id=node.id;this.mode=mode;this.layers=layers;}}
''',
'com/eabusham/routervpn/CommitHarness.java': r'''package com.eabusham.routervpn;
import java.util.*;
public final class CommitHarness {
 static int cases;
 static void check(boolean value,String label){if(!value)throw new AssertionError(label);cases++;System.out.println("PASS "+label);}
 static String failure(Runnable op){try{op.run();throw new AssertionError("operation unexpectedly succeeded");}catch(IllegalStateException|IllegalArgumentException expected){return expected.getMessage();}}
 public static void main(String[] args){
  MemoryPreferences p=new MemoryPreferences();p.values.put("other","keep");
  AndroidCustomPresetCommit.publish(AndroidCustomPresetCommit.snapshot(p),"new choices","custom:test",()->true);
  check(p.commits==1&&"new choices".equals(p.values.get("custom_presets"))&&"custom:test".equals(p.values.get("mode"))&&"keep".equals(p.values.get("other")),"choices + selected mode use one checked commit; unrelated preferences preserved");
  Map<String,String> old=new HashMap<>(p.values);p.outcomes.addAll(Arrays.asList(0,1));
  check(failure(()->AndroidCustomPresetCommit.publish(AndroidCustomPresetCommit.snapshot(p),"bad","custom:bad",()->true)).contains("restored")&&p.values.equals(old),"failed commit rolls back in-memory choices and mode");
  p.outcomes.addAll(Arrays.asList(-1,1));
  check(failure(()->AndroidCustomPresetCommit.publish(AndroidCustomPresetCommit.snapshot(p),"bad","custom:bad",()->true)).contains("restored")&&p.values.equals(old),"commit exception restores both previous values");
  p.outcomes.addAll(Arrays.asList(0,0));
  check(failure(()->AndroidCustomPresetCommit.publish(AndroidCustomPresetCommit.snapshot(p),"bad","custom:bad",()->true)).contains("rollback was incomplete"),"unconfirmed rollback is surfaced, never claimed successful");
  MemoryPreferences absent=new MemoryPreferences();absent.values.put("other","keep");absent.outcomes.addAll(Arrays.asList(0,1));
  failure(()->AndroidCustomPresetCommit.publish(AndroidCustomPresetCommit.snapshot(absent),"bad","custom:bad",()->true));
  check(!absent.contains("custom_presets")&&!absent.contains("mode")&&absent.values.size()==1,"rollback restores missing-key identity as well as values");
  AndroidCustomPresetCommit.Snapshot stale=AndroidCustomPresetCommit.snapshot(p);p.values.put("mode","auto");int count=p.commits;
  check(failure(()->AndroidCustomPresetCommit.publish(stale,"new","custom:newer",()->true)).contains("changed")&&p.commits==count,"stale snapshot cannot overwrite a newer selection");
  check(failure(()->AndroidCustomPresetCommit.publish(AndroidCustomPresetCommit.snapshot(p),"new","custom:newer",()->false)).contains("VPN state changed")&&p.commits==count,"busy runtime refuses before any write");
  String huge="x".repeat(AndroidCustomPresetCommit.MAX_BYTES+1);
  failure(()->AndroidCustomPresetCommit.publish(AndroidCustomPresetCommit.snapshot(p),huge,"custom:test",()->true));
  check(p.commits==count,"oversized publication is refused before writing");
  for(String name:new String[]{"","new","NEW"," x", "x ","bad:name","bad[name]","bad\nname","a".repeat(65),"\ud800"})check(!AndroidCustomPresetCommit.validName(name),"invalid name rejected: "+name.replace('\n',' '));
  check(AndroidCustomPresetCommit.validName("Gaming")&&AndroidCustomPresetCommit.validName("😀".repeat(64)),"valid names preserve 64 Unicode code points");
  check(AndroidCustomPresetCommit.editableLayers(Arrays.asList("wireguard","tls"),Arrays.asList("wireguard","legacy-unavailable")).equals(Arrays.asList("wireguard","tls","legacy-unavailable")),"editing preserves saved layers absent from the selected node catalog");
  System.out.println("Shipping Android CUSTOM persistence checks: "+cases+" PASS");
 }
}
''',
'com/eabusham/routervpn/ActivityCustomHarness.java': r'''package com.eabusham.routervpn;
import java.util.*;
public final class ActivityCustomHarness {
 private static final class CustomPreset {final String name;final List<String>layers;CustomPreset(String n,List<String>l){name=n;layers=l;}}
 final MemoryPreferences prefs=new MemoryPreferences();
 final Toggle multihopToggle=new Toggle();final Label statusView=new Label();final Connection connection=new Connection();
 AndroidUnifiedNodeCatalog.Item selected=new AndroidUnifiedNodeCatalog.Item();
 boolean busy,afterSaveBusy,finishing,destroyed,missingNode;String message="";int refreshes;
 boolean mutationBusy(){return busy;}boolean isFinishing(){return finishing;}boolean isDestroyed(){return destroyed;}
 AndroidUnifiedNodeCatalog.Item selectedCatalogItem(){return selected;}
 AndroidNodeStore.Node nodeById(String id){return missingNode?null:new AndroidNodeStore.Node(id);}
 Object callback(){return new Object();}void toast(String m){message=m;}String safe(Throwable t){return t.getMessage();}
 void refreshModeChoices(){refreshes++;}
 void saveCustomPreset(CustomPreset p,String oldName){
  AndroidCustomPresetCommit.publish(AndroidCustomPresetCommit.snapshot(prefs),p.layers.toString(),"custom:"+p.name,()->!mutationBusy());
  if(afterSaveBusy)busy=true;
 }
''' + HANDLERS + r'''
 static void check(boolean test,String message){if(!test)throw new AssertionError(message);System.out.println("PASS "+message);}
 static AlertDialog save(ActivityCustomHarness h,boolean connect,String name,boolean[] checked){AlertDialog d=new AlertDialog();h.saveCustomBuilder(d,new EditText(name),Arrays.asList("wireguard","tls"),checked,null,connect);return d;}
 public static void main(String[] args){
  ActivityCustomHarness h=new ActivityCustomHarness();AlertDialog d=save(h,false,"Preset",new boolean[]{true,false});
  check(d.dismissed&&h.prefs.commits==1&&h.connection.calls==0,"actual Save handler persists/selects without connecting");
  h=new ActivityCustomHarness();d=save(h,true,"Preset",new boolean[]{true,false});
  check(d.dismissed&&h.prefs.commits==1&&h.connection.calls==1&&"custom:Preset".equals(h.connection.mode)&&h.connection.layers.equals(Arrays.asList("wireguard"))&&"fixture-node".equals(h.connection.id),"actual Save & Connect captures exact saved mode/layers/selected node");
  h=new ActivityCustomHarness();h.prefs.outcomes.addAll(Arrays.asList(0,1));d=save(h,true,"Preset",new boolean[]{true,false});
  check(!d.dismissed&&h.connection.calls==0&&!h.prefs.contains("mode"),"failed persistence keeps editor open and cannot connect");
  h=new ActivityCustomHarness();h.afterSaveBusy=true;d=save(h,true,"Preset",new boolean[]{true,false});
  check(d.dismissed&&h.connection.calls==0&&h.message.contains("state changed"),"runtime change after save never toggles or disconnects another session");
  h=new ActivityCustomHarness();h.multihopToggle.checked=true;d=save(h,true,"Preset",new boolean[]{true,false});
  check(d.dismissed&&h.connection.calls==0&&h.message.contains("no other graph"),"unsupported multihop cannot silently replace the CUSTOM graph");
  h=new ActivityCustomHarness();h.selected.router=false;d=save(h,true,"Preset",new boolean[]{true,false});
  check(d.dismissed&&h.connection.calls==0,"external exit cannot silently replace saved CUSTOM layers");
  h=new ActivityCustomHarness();h.missingNode=true;d=save(h,true,"Preset",new boolean[]{true,false});
  check(d.dismissed&&h.connection.calls==0,"missing captured node cannot fall back to another target");
  h=new ActivityCustomHarness();h.destroyed=true;d=save(h,true,"Preset",new boolean[]{true,false});
  check(h.connection.calls==0,"destroyed Activity cannot start a saved-preset connection");
  h=new ActivityCustomHarness();d=save(h,true,"new",new boolean[]{true,false});
  check(!d.dismissed&&h.prefs.commits==0&&h.connection.calls==0,"reserved builder name rejected before persistence");
  h=new ActivityCustomHarness();d=save(h,true,"Preset",new boolean[]{false,false});
  check(!d.dismissed&&h.prefs.commits==0&&h.connection.calls==0,"empty layer choice rejected before persistence");
  h=new ActivityCustomHarness();h.busy=true;d=save(h,true,"Preset",new boolean[]{true,false});
  check(!d.dismissed&&h.prefs.commits==0&&h.connection.calls==0,"busy editor action cannot mutate choices");
  System.out.println("Actual Android CUSTOM Activity handlers: 11 PASS");
 }
}
''',
}


def main():
    builder = method('void showCustomBuilder(')
    for marker in ('setPositiveButton("Save & Connect", null)', 'setNeutralButton("Save", null)', 'editing, false)', 'editing, true)', 'deleteCustomPreset(editing.name)'):
        assert marker in builder, f'CUSTOM dialog action lost {marker}'
    assert 'AndroidCustomPresetCommit.editableLayers(catalog, editing == null ? Collections.emptyList() : editing.layers)' in builder
    assert 'layerLabels.toArray(new CharSequence[0])' in builder
    assert 'modeDetails.setOnClickListener(v->showCustomPresetManager())' in activity
    assert 'presets.get(which - 2)' in method('void showCustomPresetManager(')
    for signature in ('void saveCustomPreset(', 'void deleteCustomPreset('):
        writer = method(signature)
        assert 'checkedCustomRows(before.presets)' in writer and 'AndroidCustomPresetCommit.publish(' in writer
        assert '.apply()' not in writer
    assert 'connectOrDisconnect()' not in HANDLERS, 'Save & Connect must never become a disconnect toggle'
    with tempfile.TemporaryDirectory(prefix='routervpn-custom-commit-') as work:
        tmp = Path(work)
        for path, text in SOURCES.items():
            file = tmp / path; file.parent.mkdir(parents=True, exist_ok=True); file.write_text(text)
        actual = tmp / 'com/eabusham/routervpn/AndroidCustomPresetCommit.java'
        actual.write_text((JAVA / actual.name).read_text())
        subprocess.run(['javac', '--release', '17', '-Xlint:all,-auxiliaryclass', '-Werror', '-d', str(tmp), *map(str, tmp.rglob('*.java'))], check=True, timeout=30)
        for harness in ('CommitHarness', 'ActivityCustomHarness'):
            subprocess.run(['java', '-cp', str(tmp), 'com.eabusham.routervpn.' + harness], check=True, timeout=15)
    print('Android CUSTOM Save / Edit / Delete / Save & Connect contract: PASS')


if __name__ == '__main__':
    main()
