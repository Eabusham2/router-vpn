#!/usr/bin/env python3
"""Exercise the actual ordered picker and draft-to-saved match at the Android UI boundary."""
from pathlib import Path
import os
import re
import subprocess
import tempfile

from test_android_tor_form import UI
from android_store_fixture import method

JAVA = Path(__file__).parent / 'app/src/main/java/com/eabusham/routervpn'
JAR = os.environ.get('ANDROID_JSON_JAR','/usr/share/java/com.android.json.jar')

DOMAIN = '''package com.eabusham.routervpn;
import android.app.*;import android.content.*;import java.util.*;import org.json.*;
final class AndroidNodeStore {
 static final class Node{final String id,name;Node(String id){this.id=id;name="Node "+id;}}
 static final class ChainSource{String id,profileId,layer="off";boolean imported;String original;ChainSource(String id){this.id=id;profileId="profile-"+id;original=id;}byte[] bytes(){return original.getBytes();}JSONObject profile()throws Exception{return new JSONObject().put("start_layer",layer);}}
 static final class ChainCapture{List<ChainSource> members;List<String> modes;String execution="local";void requireCurrent(){}}
}
final class AndroidStandardExitStore{}
final class AndroidRuntimeRegistry{static AndroidRuntimeRegistry get(Activity a){return new AndroidRuntimeRegistry();}}
final class AndroidTelemetry{}
final class AndroidHomeStateStore {static final class Snapshot{}static Snapshot snapshot(Activity a){return new Snapshot();}}
final class AndroidConnectionSelection {static String digest(Activity a,AndroidNodeStore n){return "selection";}static void requireCurrent(Activity a,AndroidNodeStore n,String s){}}
final class AndroidConnectionProfileStore {
 static AndroidNodeStore.ChainCapture saved;AndroidConnectionProfileStore(Activity a,AndroidNodeStore n,AndroidStandardExitStore e){} AndroidNodeStore.ChainCapture orderedEditorPath(){return saved;}
}
final class AndroidNodeChainCapture{static boolean responsePrefix(java.util.List<?> sources,java.util.List<String> modes,int position,String execution){return "auto".equals(execution)&&position==1&&modes.equals(List.of("wg","shadowsocks","shadowsocks"));}}
final class AndroidOrderedPathSelection {
 static final class Member{final AndroidNodeStore.ChainSource source;final String mode;Member(String id,String m){source=new AndroidNodeStore.ChainSource(id);mode=m;}}
 static final class Catalog {List<AndroidNodeStore.Node> nodes=new ArrayList<>();Map<String,AndroidNodeStore.ChainSource> sources=new HashMap<>();AndroidNodeStore.ChainSource source(String id){return sources.get(id);}}
 final Catalog catalog=new Catalog();final List<Member> members=new ArrayList<>(); final List<AndroidNodeStore.Node> options=new ArrayList<>();
 final AndroidConnectionProfileStore profiles=new AndroidConnectionProfileStore(null,null,null);Map<String,Object> preferences=new HashMap<>(); String execution="local";boolean stale;static int saves;
 AndroidOrderedPathSelection(String... modes){for(int i=0;i<modes.length;i++)members.add(new Member("p"+i,modes[i]));init();}
 AndroidOrderedPathSelection(AndroidNodeStore n,AndroidConnectionProfileStore s){var saved=s.orderedEditorPath();for(int i=0;i<saved.members.size();i++)members.add(new Member(saved.members.get(i).id,saved.modes.get(i)));init();markSaved();}
 void init(){for(Member m:members)catalog.nodes.add(new AndroidNodeStore.Node(m.source.id));for(String id:List.of("a","b")){options.add(new AndroidNodeStore.Node(id));catalog.sources.put(id,new AndroidNodeStore.ChainSource(id));}}
 void requireCurrent(){if(stale)throw new IllegalStateException("Draft source changed");}
 long revision(){return 0;}String execution(){return execution;} List<Member> members(){return members;}List<AndroidNodeStore.Node> choices(boolean f){return options;}
 AndroidNodeStore.ChainCapture snapshot(){var s=new AndroidNodeStore.ChainCapture();s.members=new ArrayList<>();s.modes=new ArrayList<>();s.execution=execution;for(Member m:members){s.members.add(new AndroidNodeStore.ChainSource(m.source.id));s.modes.add(m.mode);}return s;}
 void markSaved(){preferences.put("multihop_on",true);preferences.put("multihop_nodes","saved");}
 java.util.concurrent.Callable<AndroidNodeStore.ChainCapture> candidateDraftCapture(int prefix){requireCurrent();var captured=snapshot();return ()->captured;}
 AndroidNodeStore.ChainCapture save(){saves++;markSaved();return AndroidConnectionProfileStore.saved=snapshot();}
 // MATCH_SAVED
}
final class AndroidNodeCandidateResult{String id;double score=12.25;boolean current=true;AndroidNodeCandidateResult(String id){this.id=id;}boolean current(long t){return current;}}
final class AndroidNodeCandidatePreparation{
 interface Callback{void progress(String d);void finished(List<Choice> measured,Throwable error);}
 static boolean responseConnectable=true;static final class Choice{Object profile=responseConnectable?new Object():null;String saveReason="This original route cannot compile";AndroidNodeCandidateResult result=new AndroidNodeCandidateResult("profile-a");} static AndroidNodeCandidatePreparation active;
 Callback listener;boolean stale,holdCleanup,cancelled;boolean observes(Callback q){return listener==q;}void detach(Callback q){if(observes(q))listener=null;}void cancelFromUser(){cancelled=true;if(!holdCleanup&&active==this)active=null;}
 static AndroidNodeCandidatePreparation retained(){return active;}void requireSavedResultCurrent(AndroidNodeCandidateResult r){if(stale||!r.current)throw new IllegalStateException("Expired receipt");}
}
final class AndroidUnifiedConnectionController{
 // UNIFIED_PERMISSION_CONSTANT
 interface Callback{void progress(String s);void finished(boolean ok,String detail);}static int prefix=-1;
 int delivered,connections;String capturedExecution="";int capturedCount;boolean dispatchComplete=true;AndroidNodeCandidatePreparation.Callback delayed;Callback permissionOwner;
 boolean onActivityResult(int request,int result){delivered=request;return true;}
 void publishDelayed(){var owner=new AndroidNodeCandidatePreparation();owner.holdCleanup=true;owner.listener=delayed;AndroidNodeCandidatePreparation.active=owner;dispatchComplete=true;}
 boolean isActiveOrTransitioning(){return false;}boolean pathCurrent(AndroidHomeStateStore.Snapshot s){return true;}boolean isPermissionPending(){return false;}
 java.util.function.BooleanSupplier testOrderedCandidates(AndroidNodeStore.ChainCapture saved,AndroidHomeStateStore.Snapshot home,String selection,int p,AndroidNodeCandidatePreparation.Callback observer,Callback cb){connections++;prefix=p;capturedExecution=saved.execution;capturedCount=saved.members.size();permissionOwner=cb;if(dispatchComplete){var owner=new AndroidNodeCandidatePreparation();owner.listener=observer;AndroidNodeCandidatePreparation.active=owner;observer.finished(List.of(new AndroidNodeCandidatePreparation.Choice()),null);}else delayed=observer;return ()->dispatchComplete;}
 boolean cancelPending(Callback c){if(c!=permissionOwner)return false;permissionOwner=null;c.finished(false,"Cancelled");return true;}
}
final class AndroidViaEntryLatencyProbe {
 interface Callback {void progress(String detail);void finished(Result result,Throwable error);}
 static class Result{static double score(Double r){return r==null?Double.POSITIVE_INFINITY:r;}Double measurement(String id){return id.equals("b")?7.5:null;}void requireCurrent(){}}
 boolean busy;static int count;static String entry;static boolean cancelled;static Callback pending;
 AndroidViaEntryLatencyProbe(Activity a,AndroidRuntimeRegistry r,AndroidTelemetry t){}void cancel(){cancelled=true;}boolean isBusy(){return busy;}
 void measure(AndroidNodeStore.Node first,List<AndroidNodeStore.Node> paired,int samples,Callback cb){count=samples;entry=first.id;busy=true;pending=new Callback(){public void progress(String detail){cb.progress(detail);}public void finished(Result r,Throwable e){busy=false;cb.finished(r,e);}};}
}
final class PickerActivity extends Activity {
 final AndroidUnifiedConnectionController connection=new AndroidUnifiedConnectionController();AndroidOrderedCandidatePicker orderedPicker;
 // PRODUCT_PERMISSION_CONSTANTS
 String pendingProbeEntryId;List<String> pendingProbeCandidateIds;static final class LegacyProbe{Object unmeasured(AndroidNodeStore.Node n,List<AndroidNodeStore.Node> ignored){return null;}}
 LegacyProbe viaEntryProbe=new LegacyProbe();int refreshes;void refreshConnectionLater(){refreshes++;}void receiveRouterBundle(int r,Intent i){}
 void runPendingViaEntryProbe(){}void clearPendingProbe(){}void showViaEntryExitPicker(Object o,Exception e){}String safe(Exception e){return e.getMessage();}void toast(String s){}
 AndroidNodeStore.Node quietNode(String id){return null;}List<AndroidNodeStore.Node> quietNodes(List<String> ids){return List.of();}
 // PRODUCT_DISPATCHER
}
'''

HARNESS = '''package com.eabusham.routervpn;
import android.app.*;import android.net.VpnService;import android.widget.*;import java.util.*;
public class PickerTest{
 final PickerActivity activity=new PickerActivity();final AndroidNodeStore nodes=new AndroidNodeStore();final AndroidStandardExitStore exits=new AndroidStandardExitStore();
 final AndroidUnifiedConnectionController controller=activity.connection;AndroidOrderedCandidatePicker picker;AndroidOrderedPathSelection draft;String picked="";int reviews;AndroidOrderedPathSelection reviewed;
 void open(String... modes)throws Exception{draft=new AndroidOrderedPathSelection(modes);show();}
 void show()throws Exception{show(null);}void show(AndroidOrderedCandidatePicker previous)throws Exception{picker=new AndroidOrderedCandidatePicker(activity,draft,true,nodes,controller,new AndroidTelemetry(),(d,id)->picked=id,d->{reviewed=d;reviews++;},()->{});activity.orderedPicker=picker;picker.show(previous);}
 String label(int i){return AlertDialog.last.adapter.getItem(i).toString();}
 static void awaitDraft()throws Exception{for(Thread t:Thread.getAllStackTraces().keySet())if(t.getName().equals("routervpn-candidate-draft-capture")){t.join(4000);if(t.isAlive())throw new AssertionError("Draft worker did not complete");}}
 static int checks;static void ok(boolean b,String m){checks++;if(!b)throw new AssertionError(m);}
 public static void main(String[]args)throws Exception{
  PickerTest h=new PickerTest();h.open("shadowsocks");ok(AlertDialog.last.getButton(-3).visibility==8&&h.label(0).equals("Node a"),"no prefix produced a timing or measure action");h.picker.close();
  h=new PickerTest();VpnService.needsPermission=true;h.open("wg","shadowsocks");ok(AndroidOrderedCandidatePicker.isPermissionRequest(h.activity.permissionRequest),"single original WG prefix did not request permission");h.picker.permission(h.activity.permissionRequest+1,true);ok(!AlertDialog.last.getListView().isEnabled(),"another picker permission changed this operation");h.picker.permission(h.activity.permissionRequest,false);ok(AlertDialog.last.getListView().isEnabled()&&h.label(1).contains("Unmeasured"),"denied permission must return unscored choices");h.picker.close();
  h=new PickerTest();VpnService.needsPermission=false;h.open("wg","shadowsocks");ok(AndroidViaEntryLatencyProbe.count==50&&AndroidViaEntryLatencyProbe.entry.equals("p0")&&!AlertDialog.last.getListView().isEnabled(),"first-hop automatic test lost mode, count, or pending ownership");
  var single=AndroidViaEntryLatencyProbe.pending;single.finished(new AndroidViaEntryLatencyProbe.Result(),null);ok(h.label(0).endsWith("Unmeasured")&&h.label(1).endsWith("7.5 ms"),"single-hop candidate bound to incorrect row");AlertDialog.last.clickItem(1);ok(h.picked.equals("b")&&AndroidOrderedPathSelection.saves==0,"single WG selection wrote the draft");
  h=new PickerTest();AndroidUnifiedConnectionController.prefix=-1;h.open("awg2-fast","wg","shadowsocks");awaitDraft();
  ok(AndroidOrderedPathSelection.saves==0&&AndroidUnifiedConnectionController.prefix==1&&h.label(0).endsWith("12.3 ms")&&h.label(1).endsWith("Unmeasured"),"automatic unsaved recursive prefix did not bind scored and unscored rows");
  AndroidNodeCandidatePreparation.retained().stale=true;AlertDialog.last.clickItem(0);ok(h.picked.isEmpty(),"stale completed score authorized selection");
  h=new PickerTest();h.draft=new AndroidOrderedPathSelection("awg2-fast","wg","shadowsocks");h.draft.markSaved();AndroidConnectionProfileStore.saved=h.draft.snapshot();h.show();
  ok(AndroidOrderedPathSelection.saves==0&&h.label(0).endsWith("12.3 ms"),"exact saved prefix must retest without another save");h.picker.close();
  h=new PickerTest();h.draft=new AndroidOrderedPathSelection("awg2-fast","wg","shadowsocks");h.draft.markSaved();h.draft.members.get(0).source.original="changed";
  ok(h.draft.matchingSavedPath()==null,"different private source reused a saved measurement");h.show();awaitDraft();ok(AndroidOrderedPathSelection.saves==0&&h.label(0).endsWith("12.3 ms"),"changed draft required a save to measure");h.picker.close();
  h=new PickerTest();h.draft=new AndroidOrderedPathSelection("socks5","shadowsocks");h.show();ok(AlertDialog.last.getButton(-3).visibility==8&&h.label(0).endsWith("Unmeasured"),"unsupported prefix invented candidate timing");h.picker.close();
  h=new PickerTest();VpnService.needsPermission=true;h.open("wg","shadowsocks");int firstPermission=h.activity.permissionRequest;
  h.activity.onActivityResult(AndroidUnifiedConnectionController.PREPARE_UNIFIED,Activity.RESULT_OK,null);
  ok(h.controller.delivered==AndroidUnifiedConnectionController.PREPARE_UNIFIED&&h.activity.refreshes==1&&!AlertDialog.last.getListView().isEnabled(),"Product intercepted a fresh ordinary VPN permission as a picker result");
  h.activity.onActivityResult(firstPermission,0,null);ok(AlertDialog.last.getListView().isEnabled()&&h.activity.refreshes==1,"Product lost the real picker permission result");
  AlertDialog.last.getButton(-2).performClick();ok(h.reviewed==h.draft&&h.reviews==1,"denied permission lost the original draft on review");
  h=new PickerTest();h.open("wg","shadowsocks");int abandoned=h.activity.permissionRequest;AlertDialog.last.getButton(-2).performClick();h.open("wg","shadowsocks");
  h.activity.onActivityResult(abandoned,Activity.RESULT_OK,null);ok(h.reviews==1&&h.activity.permissionRequest!=abandoned&&!AlertDialog.last.getListView().isEnabled(),"a late picker grant resolved the replacement picker");
  h.activity.onActivityResult(0xffff,Activity.RESULT_OK,null);ok(h.controller.delivered==0xffff,"Product clipped the high unified permission range");h.picker.close();
  h=new PickerTest();VpnService.needsPermission=false;h.open("wg","shadowsocks");single=AndroidViaEntryLatencyProbe.pending;AlertDialog active=AlertDialog.last;
  active.getButton(-2).performClick();ok(h.reviews==0&&active.showing&&!active.getListView().isEnabled(),"Review reopened an editor before the original WireGuard cleanup");
  single.progress("late");android.os.Handler.tick();ok(h.reviews==0,"a cleanup tick released a live entry");single.finished(new AndroidViaEntryLatencyProbe.Result(),null);android.os.Handler.tick();
  ok(h.reviewed==h.draft&&h.reviews==1&&!active.showing&&h.picked.isEmpty(),"owned teardown lost, selected, or reopened the original draft twice");
  h=new PickerTest();h.controller.dispatchComplete=false;h.open("awg2-fast","wg","shadowsocks");awaitDraft();active=AlertDialog.last;
  active.getButton(-2).performClick();android.os.Handler.tick();ok(h.reviews==0&&!active.getListView().isEnabled(),"Review outran a still-reserving capture");
  h.controller.publishDelayed();var late=AndroidNodeCandidatePreparation.retained();android.os.Handler.tick();ok(late.cancelled&&late.listener==null&&h.reviews==0,"Review lost the original late native reservation");
  var other=new AndroidNodeCandidatePreparation();AndroidNodeCandidatePreparation.active=other;android.os.Handler.tick();ok(!other.cancelled&&h.reviews==1&&h.reviewed==h.draft,"Review cancelled a replacement owner or lost its exact draft");
  h=new PickerTest();h.open("wg","shadowsocks");active=AlertDialog.last;single=AndroidViaEntryLatencyProbe.pending;active.cancel();ok(active.showing&&h.reviews==0,"system Back abandoned an owned pending test");single.finished(null,new Exception("cancelled"));android.os.Handler.tick();
  ok(h.reviews==1&&h.reviewed==h.draft,"system Back did not return the unsaved path after cleanup");
  h=new PickerTest();h.open("wg","shadowsocks");single=AndroidViaEntryLatencyProbe.pending;AlertDialog.last.getButton(-2).performClick();h.picker.close();single.finished(null,new Exception("late"));android.os.Handler.tick();
  ok(h.reviews==0&&AndroidOrderedPathSelection.saves==0,"closed Activity revived or saved a draft after teardown");
  h=new PickerTest();h.open("awg2-fast","wg","shadowsocks");awaitDraft();var retiring=AndroidNodeCandidatePreparation.retained();retiring.holdCleanup=true;var previous=h.picker;AlertDialog.last.clickItem(0);
  var next=new PickerTest();next.draft=new AndroidOrderedPathSelection("awg2-fast","wg","wg","shadowsocks");next.show(previous);awaitDraft();
  ok(next.controller.connections==0&&!AlertDialog.last.getListView().isEnabled(),"next picker began a new measurement while its previous network observer was retiring");
  AndroidNodeCandidatePreparation.active=null;android.os.Handler.tick();awaitDraft();ok(next.controller.connections==1&&AndroidUnifiedConnectionController.prefix==2&&next.label(0).endsWith("12.3 ms"),"next picker failed to measure its actual longer prefix after cleanup");next.picker.close();
  h=new PickerTest();h.open("shadowsocks","shadowsocks","shadowsocks");ok(h.controller.connections==0&&AlertDialog.last.getButton(-3).visibility==8&&h.label(0).endsWith("Unmeasured"),"custom-entry route borrowed an unrelated packet candidate score");h.draft.stale=true;AlertDialog.last.getButton(-2).performClick();ok(h.reviews==0,"Review reopened a changed draft");
  for(String execution:List.of("server","auto"))for(boolean saved:new boolean[]{false,true}){
   h=new PickerTest();h.draft=new AndroidOrderedPathSelection("wg","shadowsocks");h.draft.execution=execution;
   if(saved){h.draft.markSaved();AndroidConnectionProfileStore.saved=h.draft.snapshot();}
   int firstProbes=AndroidViaEntryLatencyProbe.count;h.show();awaitDraft();
   ok(h.controller.connections==1&&h.controller.capturedExecution.equals(execution)&&h.controller.capturedCount==2&&AndroidUnifiedConnectionController.prefix==0,"selected draft lost its complete execution before automatic timing");
   ok(AndroidViaEntryLatencyProbe.count==firstProbes&&h.label(0).endsWith("12.3 ms")&&AndroidOrderedPathSelection.saves==0,"selected draft borrowed first Local probe or changed saved profiles");h.picker.close();
  }
  h=new PickerTest();h.draft=new AndroidOrderedPathSelection("wg","shadowsocks","awg2-strong","shadowsocks");h.draft.execution="auto";h.show();awaitDraft();
  ok(h.controller.connections==1&&h.controller.capturedCount==4&&AndroidUnifiedConnectionController.prefix==2&&h.controller.capturedExecution.equals("auto"),"selected draft lost a later packet position beyond an imported node");h.picker.close();
  h=new PickerTest();h.draft=new AndroidOrderedPathSelection("wg","awg2-fast","shadowsocks");h.draft.execution="server";h.controller.dispatchComplete=false;h.show();awaitDraft();active=AlertDialog.last;
  active.getButton(-2).performClick();android.os.Handler.tick();ok(h.reviews==0&&!active.getListView().isEnabled(),"selected draft Review escaped while its full graph was starting");
  h.controller.publishDelayed();var selectedRetiring=AndroidNodeCandidatePreparation.retained();android.os.Handler.tick();ok(selectedRetiring.cancelled&&h.reviews==0,"selected draft lost its exact retiring full graph");
  AndroidNodeCandidatePreparation.active=null;android.os.Handler.tick();ok(h.reviewed==h.draft&&h.reviewed.execution.equals("server")&&h.reviews==1&&AndroidOrderedPathSelection.saves==0,"selected draft retirement lost requested execution or saved implicitly");
  for(int selected:List.of(1,0))for(boolean connectable:List.of(false,true)){
   h=new PickerTest();h.draft=new AndroidOrderedPathSelection("wg","shadowsocks","shadowsocks");h.draft.execution="auto";AndroidNodeCandidatePreparation.responseConnectable=connectable;
   h.show();awaitDraft();
   ok(h.label(0).endsWith("12.3 ms"),"selected private response disappeared from Choose");
   AlertDialog.last.clickItem(selected);ok(selected==0 && connectable?"a".equals(h.picked):h.picked.isEmpty(),"selected response Choose ignored the original score or compiled proposal");
   ok(AndroidOrderedPathSelection.saves==0,"Choose changed Home or implicitly saved the measured final");h.picker.close();
  }
  System.out.println("Android ordered candidate picker: "+checks+" behavior checks passed (native owners and widgets doubled)");
 }
}
'''

def main():
    sources=dict(UI)
    sources["android/content/SharedPreferences.java"]="package android.content;public interface SharedPreferences{String getString(String k,String f);}"
    sources['android/widget/ArrayAdapter.java']='package android.widget;import java.util.*;public final class ArrayAdapter<T>{List<T> items=new ArrayList<>();public ArrayAdapter(android.content.Context c,int r){}public ArrayAdapter(android.content.Context c,int r,T[] a){items.addAll(Arrays.asList(a));}public void setDropDownViewResource(int r){}public void add(T t){items.add(t);}public void clear(){items.clear();}public int getCount(){return items.size();}public T getItem(int i){return items.get(i);}public void notifyDataSetChanged(){}public void setNotifyOnChange(boolean b){}}'
    sources['android/app/Activity.java']=sources['android/app/Activity.java'][:-1]+'public boolean isDestroyed(){return false;}}'
    sources['android/R.java']=sources['android/R.java'].replace('simple_spinner_item=1','simple_list_item_1=3,simple_spinner_item=1')
    sources['android/view/View.java']=sources['android/view/View.java'].replace('private boolean enabled=', 'public static final int GONE=8;public int visibility;public void setVisibility(int v){visibility=v;}private boolean enabled=')
    s=sources['android/app/AlertDialog.java'].replace('BUTTON_NEGATIVE=-2','BUTTON_NEUTRAL=-3,BUTTON_NEGATIVE=-2').replace('private final Context context;', 'public android.widget.ArrayAdapter<?> adapter;private View list;public View getListView(){if(list==null)list=new View(context);return list;}public boolean isShowing(){return showing;}private final Context context;')
    s=s.replace('public Builder setTitle(', 'public Builder setAdapter(android.widget.ArrayAdapter<?> rows,OnClickListener listener){dialog.adapter=rows;dialog.items=new String[rows.getCount()];dialog.itemClick=listener;return this;}public Builder setNeutralButton(CharSequence s,OnClickListener l){return button(-3,s,l);}public Builder setTitle(')
    s=s.replace('public void setOnDismissListener(', 'private java.util.function.Consumer<AlertDialog> onCancel;public void setOnCancelListener(java.util.function.Consumer<AlertDialog> listener){onCancel=listener;}public void setCanceledOnTouchOutside(boolean ignored){}public void cancel(){showing=false;if(onCancel!=null)onCancel.accept(this);if(onDismiss!=null)onDismiss.onDismiss(this);}public void setOnDismissListener(')
    sources['android/app/AlertDialog.java']=s
    sources['android/os/Handler.java']='package android.os;public class Handler{public Handler(Looper l){}static final java.util.List<Runnable> pending=new java.util.ArrayList<>();public void postDelayed(Runnable r,long t){pending.add(r);}public void removeCallbacks(Runnable r){pending.removeIf(x->x==r);}public static void tick(){var copy=new java.util.ArrayList<>(pending);pending.clear();for(Runnable r:copy)r.run();}}'
    sources['android/os/Looper.java']='package android.os;public class Looper{public static Looper getMainLooper(){return new Looper();}}'
    base='com/eabusham/routervpn/'
    sources[base+'PickerTest.java']=HARNESS
    sources[base+'AndroidOrderedCandidatePicker.java']=(JAVA/'AndroidOrderedCandidatePicker.java').read_text()
    product=(JAVA/'ProductActivity.java').read_text()
    unified=(JAVA/'AndroidUnifiedConnectionController.java').read_text()
    domain=DOMAIN.replace('// PRODUCT_DISPATCHER',method(product,'    @Override protected void onActivityResult('))
    domain=domain.replace('// PRODUCT_PERMISSION_CONSTANTS',re.search(r'private static final int PREPARE_VIA_ENTRY_RTT=[^;]+;',product).group())
    domain=domain.replace('// UNIFIED_PERMISSION_CONSTANT',re.search(r'static final int PREPARE_UNIFIED = [^;]+;',unified).group())
    sources[base+'Boundaries.java']=domain.replace('// MATCH_SAVED',method((JAVA/'AndroidOrderedPathSelection.java').read_text(),'    AndroidNodeStore.ChainCapture matchingSavedPath('))
    with tempfile.TemporaryDirectory() as work:
        temp=Path(work)
        for name,src in sources.items():
            target=temp/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(src)
        subprocess.run(['javac','--release','17','-cp',JAR,'-d',work,*map(str,temp.rglob('*.java'))],check=True)
        classpath=os.pathsep.join((work,JAR))
        command=['java','-cp',classpath,'com.eabusham.routervpn.PickerTest']
        subprocess.run(command,check=True)
        picker=temp/base/'AndroidOrderedCandidatePicker.java'
        original=picker.read_text()
        for before,after,witness in (
            ('0x2000,LAST_PERMISSION=AndroidUnifiedConnectionController.PREPARE_UNIFIED-1','0x4000,LAST_PERMISSION=0x7fff','Product intercepted a fresh ordinary VPN permission'),
            ('!captureDispatched.getAsBoolean()||single.isBusy()','single.isBusy()','Review outran a still-reserving capture'),
            ('if(previous!=null&&previous.closed)retiringOwner=previous.retiringOwner;', '', 'next picker began a new measurement'),
        ):
            assert original.count(before)==1
            picker.write_text(original.replace(before,after))
            subprocess.run(['javac','--release','17','-cp',classpath,'-d',work,str(picker)],check=True)
            result=subprocess.run(command,capture_output=True,text=True,timeout=20)
            if result.returncode==0 or witness not in result.stderr:
                raise AssertionError("Picker control missed its exact defect: "+witness+"\n"+result.stderr)
        print("Android ordered picker rejected three causal permission, capture and retirement regressions")

if __name__=='__main__':main()
