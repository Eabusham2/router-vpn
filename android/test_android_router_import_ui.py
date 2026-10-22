#!/usr/bin/env python3
"""Execute shipping ProductActivity import, durable ranking and policy callbacks.

The document picker, UI dispatch and widgets are Android boundary doubles. Node
validation, atomic store logic, import capture, full statistics and ranking are
the real classes; no VPN is connected and no imported credentials are printed.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / 'android/app/src/main/java/com/eabusham/routervpn'
SOURCE = (JAVA / 'ProductActivity.java').read_text()

def module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / 'android' / filename)
    value = importlib.util.module_from_spec(spec); spec.loader.exec_module(value)
    return value

T = module('current_telemetry_boundaries', 'test_android_current_telemetry.py')
W = module('import_dialog_boundaries', 'test_android_tor_form.py')

def method(signature):
    start = SOURCE.index('    private ' + signature)
    return SOURCE[start:SOURCE.index('\n    private ', start + 10)]

METHODS = ['void showAddRouter(', 'void chooseRouterBundle(', 'void receiveRouterBundle(',
           'void showNodeSort(', 'void selectCatalog(AndroidUnifiedNodeCatalog.Item item)',
           'void refreshDnsSelection(', 'void refreshMultihopSummary(', 'boolean isExternalSelected(',
           'AlertDialog.Builder choiceDialog(', 'TextView text(', 'int dp(']

HARNESS = r'''package com.eabusham.routervpn;
import android.app.AlertDialog;import android.content.*;import android.graphics.*;import android.widget.*;
import java.util.*;import java.util.concurrent.*;import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.io.*;import org.json.*;
public final class RouterImportUITest extends android.app.Activity implements AutoCloseable {
 static final int IMPORT_ROUTER_BUNDLE=7607;static final String SELECTED_KIND="selected_kind",SELECTED_ID="selected_id",MULTI_ON="multihop_on",MULTI_ENTRY="multihop_entry",MULTI_EXIT="multihop_exit",MULTI_MODE="multihop_exit_mode";
 String importDecision="",message="",action="";long importGeneration;boolean destroyed;int refreshes,shownNodes;
 final AndroidNodeStore nodeStore;final AndroidStandardExitStore exitStore=new AndroidStandardExitStore();final AndroidUnifiedNodeCatalog catalog;final AndroidTelemetry telemetry;
 final TextView statusView=new TextView(this),dnsHint=new TextView(this),multihopHint=new TextView(this);final Spinner dnsSpinner=new Spinner(this);final CheckBox multihopToggle=new CheckBox(this);double currentPathMs;
 final BlockingQueue<Runnable> ui=new LinkedBlockingQueue<>();final android.content.ContentResolver documents=new android.content.ContentResolver();final Connection connection=new Connection();
 RouterImportUITest()throws Exception{files=Files.createTempDirectory("router-import-ui-").toFile();AndroidVpnMutationGuard.busy=false;AndroidHomeStateStore.home=new AndroidHomeStateStore.Snapshot();AndroidHomeStateStore.home.connected=false;AndroidHomeStateStore.home.phase="disconnected";nodeStore=new AndroidNodeStore(this);catalog=new AndroidUnifiedNodeCatalog(nodeStore,exitStore);telemetry=new AndroidTelemetry(this,nodeStore);dnsSpinner.setAdapter(new ArrayAdapter<>(this,0,new String[]{"Home","Fastest","Custom","DoT","DoH","DoH3","Rescue"}));}
 public void runOnUiThread(Runnable value){ui.add(value);}public boolean isDestroyed(){return destroyed;}public android.content.ContentResolver getContentResolver(){return documents;}
 SharedPreferences prefs(){return getSharedPreferences("router-vpn-unified",MODE_PRIVATE);}boolean mutationBusy(){return AndroidVpnMutationGuard.busy;}
 void toast(String value){message=value;}static String safe(Throwable error){return error==null?"unknown":error.getMessage();}void refreshAll(){refreshes++;}void showNodes(){shownNodes++;}void showPairDialog(){action="pair";}void openStandardExits(){action="external";}
 JSONObject activeRouterProfile(){try{return new JSONObject().put("dns_mode","rescue");}catch(Exception error){throw new IllegalStateException(error);}}
 AndroidNodeStore.Node nodeById(String id)throws Exception{for(var node:nodeStore.list())if(node.id.equals(id))return node;return null;}
 void deliver()throws Exception{Runnable next=ui.poll(4,TimeUnit.SECONDS);check(next!=null,"import worker never delivered callback");next.run();}
 void picked(byte[] bytes)throws Exception{documents.bytes=bytes;receiveRouterBundle(RESULT_OK,new Intent().setData(android.net.Uri.parse("content://fixture/router.json")));}
 public void close()throws Exception{telemetry.close();try(var paths=Files.walk(files.toPath())){paths.sorted(Comparator.reverseOrder()).forEach(p->{try{Files.deleteIfExists(p);}catch(Exception ignored){}});}}
 static byte[] bundle(String proof,String name)throws Exception{return new JSONObject().put("nodeProofId",proof).put("endpoint","192.0.2.10").put("profiles",new JSONObject().put("wg",new JSONObject())).put("modes",new JSONArray()).put("selectedRouterID","router").put("routerProfiles",new JSONArray().put(new JSONObject().put("id","router").put("name",name).put("endpoint","192.0.2.10").put("node_proof_id",proof))).toString().getBytes(StandardCharsets.UTF_8);}
 static int checks;static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
 static AlertDialog visible(int count){AlertDialog dialog=AlertDialog.last;check(dialog!=null&&dialog.itemsVisible()&&dialog.items.length==count,"shipping action rows are hidden");return dialog;}
 static void imports()throws Exception{
  try(RouterImportUITest h=new RouterImportUITest()){h.showAddRouter();visible(3).clickItem(0);check(h.action.equals("pair"),"LAN pairing action lost");h.showAddRouter();visible(3).clickItem(2);check(h.action.equals("external"),"custom import action lost");h.prefs().edit().putBoolean(MULTI_ON,true).putString(MULTI_ENTRY,"old-entry").putString(MULTI_EXIT,"old-exit").apply();h.showAddRouter();visible(3).clickItem(1);check(h.permissionRequest==IMPORT_ROUTER_BUNDLE&&Intent.ACTION_OPEN_DOCUMENT.equals(h.permission.action)&&h.permission.openable,"real document picker is not reachable");check(((String[])h.permission.extras.get(Intent.EXTRA_MIME_TYPES)).length==4,"picker MIME restrictions missing");byte[] exact=bundle("a".repeat(64),"Imported A");h.picked(exact);h.deliver();var saved=h.nodeStore.list();check(saved.size()==1&&Arrays.equals(Files.readAllBytes(saved.get(0).file.toPath()),exact),"actual bundle store did not adopt exact document");check(h.nodeStore.activeId().equals(saved.get(0).id)&&h.prefs().getString(SELECTED_ID,"").equals(saved.get(0).id)&&h.prefs().getString(SELECTED_KIND,"").equals("router-vpn"),"import did not select exact node");check(!h.prefs().getBoolean(MULTI_ON,true)&&h.prefs().getString(MULTI_ENTRY,"x").isEmpty()&&h.prefs().getString(MULTI_EXIT,"x").isEmpty(),"import retained stale paired graph");check(h.documents.closed==1&&h.message.contains("Press Connect"),"import failed to close document or implied automatic connection");}
  for(String changed:new String[]{"before-read","after-read","destroyed","superseded","source"})try(RouterImportUITest h=new RouterImportUITest()){
   AndroidNodeStore.Node existing=null;if(changed.equals("source"))existing=h.nodeStore.importBundle(bundle("b".repeat(64),"Old"));h.chooseRouterBundle();
   if(changed.equals("before-read"))AndroidHomeStateStore.home.pathGeneration++;
   h.picked(bundle("a".repeat(64),"New"));
   if(changed.equals("before-read")){check(h.documents.opens==0&&h.nodeStore.list().isEmpty(),"stale picker opened document before decision validation");continue;}
   Runnable pending=h.ui.poll(4,TimeUnit.SECONDS);check(pending!=null,"worker callback unavailable");
   if(changed.equals("after-read"))AndroidHomeStateStore.home.pathGeneration++;
   if(changed.equals("destroyed"))h.destroyed=true;
   if(changed.equals("superseded"))h.chooseRouterBundle();
   if(changed.equals("source"))Files.writeString(existing.file.toPath(),Files.readString(existing.file.toPath())+" ");
   pending.run();check(h.nodeStore.list().size()==(existing==null?0:1),"stale or destroyed import adopted document: "+changed);check(h.documents.closed==1,"rejected import leaked document");
  }
  for(String invalid:new String[]{"cancelled","file-uri","missing-decision","invalid-json","oversize"})try(RouterImportUITest h=new RouterImportUITest()){
   if(!invalid.equals("missing-decision"))h.chooseRouterBundle();
   if(invalid.equals("cancelled"))h.receiveRouterBundle(0,new Intent());
   else if(invalid.equals("file-uri"))h.receiveRouterBundle(RESULT_OK,new Intent().setData(android.net.Uri.parse("file:///outside.json")));
   else{h.picked(invalid.equals("oversize")?new byte[AndroidNodeStore.MAX_BUNDLE+1]:invalid.equals("invalid-json")?"{}".getBytes(StandardCharsets.UTF_8):bundle("a".repeat(64),"New"));if(!invalid.equals("missing-decision"))h.deliver();}
   check(h.nodeStore.list().isEmpty()&&h.nodeStore.activeId().isEmpty(),"invalid/cancelled document changed selection: "+invalid);
   if(invalid.equals("cancelled")||invalid.equals("file-uri")||invalid.equals("missing-decision"))check(h.documents.opens==0,"invalid picker reply opened arbitrary document");
  }
 }
 static void rankingAndPolicies()throws Exception{
  try(RouterImportUITest h=new RouterImportUITest()){var a=h.nodeStore.importBundle(bundle("a".repeat(64),"Slow"));var b=h.nodeStore.importBundle(bundle("b".repeat(64),"Fast"));for(var node:List.of(a,b)){double n=node==a?20:3;AndroidNodeStatistics.save(node,new AndroidNodeStatistics.Record(node.id,AndroidNodeStatistics.source(node),node.endpoint,"direct",System.currentTimeMillis(),n,n,n,n,n,n,50,0));}h.nodeStore.select(a.id);h.showNodeSort();visible(5).clickItem(3);check(h.prefs().getString("node_sort","").equals(AndroidUnifiedNodeCatalog.SORT_LATENCY)&&h.shownNodes==1,"Lowest latency order is not reachable");h.showNodeSort();visible(5).clickItem(4);check(h.nodeStore.activeId().equals(b.id)&&h.message.contains("Press Connect"),"Lowest latency did not select actual durable winner separately");h.nodeStore.select(a.id);h.showNodeSort();AlertDialog old=visible(5);Files.writeString(b.file.toPath(),Files.readString(b.file.toPath())+" ");old.clickItem(4);check(h.nodeStore.activeId().equals(a.id)&&h.message.contains("at least two"),"stale record was selected through old sorting dialog");}
  try(RouterImportUITest h=new RouterImportUITest()){h.prefs().edit().putString(SELECTED_KIND,"external").putString(SELECTED_ID,"exit").apply();for(String protocol:List.of("shadowsocks","tor"))for(String value:new String[]{null,"","  ","home","rescue","custom"}){h.exitStore.entry.protocol=protocol;JSONObject policy=value==null?null:new JSONObject().put("dns_mode",value);h.exitStore.entry.policy=policy;h.exitStore.entry.torPolicy=policy;h.refreshDnsSelection();check(h.dnsSpinner.getSelectedItemPosition()==("rescue".equals(value)?6:"custom".equals(value)?2:0),"missing external DNS did not default Home or explicit choice lost: "+protocol+"/"+value);}
   AndroidConnectionProfileStore.path.entry=h.nodeStore.importBundle(bundle("a".repeat(64),"Entry"));AndroidConnectionProfileStore.path.exit=h.exitStore.entry;AndroidConnectionProfileStore.path.entryMode="max-wg";String[] execution={"local","server","auto"},labels={"Local","Server","Compare"};for(int i=0;i<execution.length;i++){AndroidConnectionProfileStore.path.execution=execution[i];h.refreshMultihopSummary();check(h.multihopHint.getText().toString().endsWith(labels[i]),"external execution summary lost "+labels[i]);}AndroidConnectionProfileStore.path.entry=null;h.refreshMultihopSummary();check(h.multihopHint.getText().toString().startsWith("Direct"),"direct external path summary changed");}
 }
 public static void main(String[] args)throws Exception{imports();rankingAndPolicies();System.out.println("Android Router import and policy UI: "+checks+" shipping callback, atomic store, stale reply, durable ranking, Home default and execution summary checks PASS");}
}
'''

def run(overrides=None):
    sources=dict(W.UI);sources.update(T.SOURCES)
    sources['android/content/Context.java']=sources['android/content/Context.java'].replace('public Context getApplicationContext()', 'public android.content.res.Resources getResources(){return new android.content.res.Resources();}public Context getApplicationContext()')
    sources['android/content/Intent.java']=r'''package android.content;public class Intent {public static final String ACTION_OPEN_DOCUMENT="open-document",CATEGORY_OPENABLE="openable",EXTRA_MIME_TYPES="mime-types";public String action,type;public boolean openable;public final java.util.Map<String,Object> extras=new java.util.HashMap<>();private android.net.Uri uri;public Intent(){}public Intent(String value){action=value;}public Intent(Context context,Class<?> type){}public Intent addCategory(String value){openable=CATEGORY_OPENABLE.equals(value);return this;}public Intent setType(String value){type=value;return this;}public Intent putExtra(String key,String[] values){extras.put(key,values);return this;}public Intent setData(android.net.Uri value){uri=value;return this;}public android.net.Uri getData(){return uri;}}'''
    sources['android/net/Uri.java']=r'''package android.net;public final class Uri {final java.net.URI uri;private Uri(String value){uri=java.net.URI.create(value);}public static Uri parse(String value){return new Uri(value);}public String getScheme(){return uri.getScheme();}}'''
    sources['android/content/ContentResolver.java']=r'''package android.content;public final class ContentResolver {public byte[] bytes;public int opens,closed;public java.io.InputStream openInputStream(android.net.Uri uri){opens++;return new java.io.ByteArrayInputStream(bytes){public void close(){closed++;}};}}'''
    sources['android/graphics/Color.java']='package android.graphics;public final class Color {public static final int WHITE=-1;}'
    sources['android/widget/Spinner.java']=sources['android/widget/Spinner.java'].replace('public void setSelection(int value){','public void setSelection(int value,boolean animate){setSelection(value);}public void setSelection(int value){')
    sources['com/eabusham/routervpn/AndroidStandardExitStore.java']=r'''package com.eabusham.routervpn;public class AndroidStandardExitStore {static class Entry{String id="exit",name="External",server="192.0.2.2",protocol="shadowsocks",expectedPublicIp="";int serverPort=443;org.json.JSONObject policy,torPolicy;}final Entry entry=new Entry();Entry get(String id){return entry;}java.util.List<Entry> list(){return java.util.List.of();}}'''
    sources['com/eabusham/routervpn/PolicyUIBoundaries.java']=r'''package com.eabusham.routervpn;final class AndroidTorProfile{static boolean isTor(String protocol){return protocol.startsWith("tor");}}final class AndroidConnectionProfileStore{static class ExternalSelection{AndroidNodeStore.Node entry;AndroidStandardExitStore.Entry exit;String entryMode,execution;boolean direct(){return entry==null;}}static final ExternalSelection path=new ExternalSelection();AndroidConnectionProfileStore(android.content.Context c,AndroidNodeStore n,AndroidStandardExitStore e){}ExternalSelection currentExternalPath(String id){return path;}}final class Connection{boolean isMultihopConnected(){return false;}String activeMultihopEntryId(){return "";}String activeMultihopExitId(){return "";}String activeMultihopExitMode(){return "";}String activeMultihopEntryMode(){return "";}}'''
    handlers='\n'.join(method(signature) for signature in METHODS)
    for before,after in (overrides or []):
        assert handlers.count(before)==1,before
        handlers=handlers.replace(before,after)
    harness=HARNESS.replace(' static int checks;',handlers+'\n static int checks;')
    with tempfile.TemporaryDirectory(prefix='routervpn-import-ui-') as directory:
        root=Path(directory)
        for name,body in sources.items():
            path=root/name;path.parent.mkdir(parents=True,exist_ok=True);path.write_text(body)
        for name in T.PRODUCTION:
            (root/'com/eabusham/routervpn'/f'{name}.java').write_text((JAVA/(name+'.java')).read_text())
        (root/'com/eabusham/routervpn/RouterImportUITest.java').write_text(harness)
        build=subprocess.run(['javac','--release','17','-cp','/usr/share/java/com.android.json.jar','-d',str(root),*map(str,root.rglob('*.java'))],capture_output=True,text=True,timeout=45)
        assert build.returncode==0,build.stderr
        return subprocess.run(['java','-cp',str(root)+':/usr/share/java/com.android.json.jar','com.eabusham.routervpn.RouterImportUITest'],capture_output=True,text=True,timeout=25)

def main():
    assert 'if(requestCode==IMPORT_ROUTER_BUNDLE){receiveRouterBundle(resultCode,data);return;}' in SOURCE
    assert 'out.putString(STATE_IMPORT_DECISION,importDecision)' in SOURCE
    result=run();assert result.returncode==0,result.stdout+result.stderr;print(result.stdout.strip())
    mutations=[
        [('if(error!=null)throw new IllegalStateException(safe(error));AndroidRouterBundleImport.requireCurrent(this,nodeStore,captured);','if(error!=null)throw new IllegalStateException(safe(error));')],
        [('if(ticket!=importGeneration||isFinishing()||isDestroyed())return;','if(ticket!=importGeneration)return;')],
        [('p.optString("dns_mode","home")','p.optString("dns_mode","rescue")')],
        [('("server".equals(path.execution)?"Server":"auto".equals(path.execution)?"Compare":"Local")','"Local"')],
    ]
    for mutation in mutations:
        failed=run(mutation)
        assert failed.returncode!=0 and ('stale or destroyed import adopted' in failed.stderr or 'missing external DNS' in failed.stderr or 'external execution summary lost' in failed.stderr),failed.stdout+failed.stderr
    print('Android Router import UI: all four stale-adoption and policy-summary negative controls rejected')

if __name__=='__main__':main()
