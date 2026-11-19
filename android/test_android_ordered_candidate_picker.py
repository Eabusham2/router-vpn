#!/usr/bin/env python3
"""Exercise the actual ordered picker and draft-to-saved match at the Android UI boundary."""
from pathlib import Path
import os
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
final class AndroidOrderedPathSelection {
 static final class Member{final AndroidNodeStore.ChainSource source;final String mode;Member(String id,String m){source=new AndroidNodeStore.ChainSource(id);mode=m;}}
 static final class Catalog {List<AndroidNodeStore.Node> nodes=new ArrayList<>();Map<String,AndroidNodeStore.ChainSource> sources=new HashMap<>();AndroidNodeStore.ChainSource source(String id){return sources.get(id);}}
 final Catalog catalog=new Catalog();final List<Member> members=new ArrayList<>(); final List<AndroidNodeStore.Node> options=new ArrayList<>();
 final AndroidConnectionProfileStore profiles=new AndroidConnectionProfileStore(null,null,null);Map<String,Object> preferences=new HashMap<>(); String execution="local";boolean stale;static int saves;
 AndroidOrderedPathSelection(String... modes){for(int i=0;i<modes.length;i++)members.add(new Member("p"+i,modes[i]));init();}
 AndroidOrderedPathSelection(AndroidNodeStore n,AndroidConnectionProfileStore s){var saved=s.orderedEditorPath();for(int i=0;i<saved.members.size();i++)members.add(new Member(saved.members.get(i).id,saved.modes.get(i)));init();markSaved();}
 void init(){for(Member m:members)catalog.nodes.add(new AndroidNodeStore.Node(m.source.id));for(String id:List.of("a","b")){options.add(new AndroidNodeStore.Node(id));catalog.sources.put(id,new AndroidNodeStore.ChainSource(id));}}
 void requireCurrent(){if(stale)throw new IllegalStateException("Draft source changed");}
 String execution(){return execution;} List<Member> members(){return members;}List<AndroidNodeStore.Node> choices(boolean f){return options;}
 AndroidNodeStore.ChainCapture snapshot(){var s=new AndroidNodeStore.ChainCapture();s.members=new ArrayList<>();s.modes=new ArrayList<>();s.execution=execution;for(Member m:members){s.members.add(new AndroidNodeStore.ChainSource(m.source.id));s.modes.add(m.mode);}return s;}
 void markSaved(){preferences.put("multihop_on",true);preferences.put("multihop_nodes","saved");}
 AndroidNodeStore.ChainCapture save(){saves++;markSaved();return AndroidConnectionProfileStore.saved=snapshot();}
 // MATCH_SAVED
}
final class AndroidNodeCandidateResult{String id;double score=12.25;boolean current=true;AndroidNodeCandidateResult(String id){this.id=id;}boolean current(long t){return current;}}
final class AndroidNodeCandidatePreparation{
 interface Callback{void progress(String d);void finished(List<Choice> measured,Throwable error);}
 static final class Choice{AndroidNodeCandidateResult result=new AndroidNodeCandidateResult("profile-a");} static AndroidNodeCandidatePreparation active;
 Callback listener;boolean stale;boolean observes(Callback q){return listener==q;}void detach(Callback q){if(observes(q))listener=null;}void cancelFromUser(){active=null;}
 static AndroidNodeCandidatePreparation retained(){return active;}void requireSavedResultCurrent(AndroidNodeCandidateResult r){if(stale||!r.current)throw new IllegalStateException("Expired receipt");}
}
final class AndroidUnifiedConnectionController{
 interface Callback{void progress(String s);void finished(boolean ok,String detail);}static int prefix=-1;
 boolean isActiveOrTransitioning(){return false;}boolean pathCurrent(AndroidHomeStateStore.Snapshot s){return true;}boolean isPermissionPending(){return false;}
 void testOrderedCandidates(AndroidNodeStore.ChainCapture saved,AndroidHomeStateStore.Snapshot home,String selection,int p,AndroidNodeCandidatePreparation.Callback observer,Callback cb){prefix=p;var owner=new AndroidNodeCandidatePreparation();owner.listener=observer;AndroidNodeCandidatePreparation.active=owner;observer.finished(List.of(new AndroidNodeCandidatePreparation.Choice()),null);}
 boolean cancelPending(Callback c){return false;}
}
final class AndroidViaEntryLatencyProbe {
 interface Callback {void progress(String detail);void finished(Result result,Throwable error);}
 static class Result{static double score(Double r){return r==null?Double.POSITIVE_INFINITY:r;}Double measurement(String id){return id.equals("b")?7.5:null;}void requireCurrent(){}}
 static int count;static String entry;static boolean cancelled;static Callback pending;
 AndroidViaEntryLatencyProbe(Activity a,AndroidRuntimeRegistry r,AndroidTelemetry t){}void cancel(){cancelled=true;}
 void measure(AndroidNodeStore.Node first,List<AndroidNodeStore.Node> paired,int samples,Callback cb){count=samples;entry=first.id;pending=cb;}
}
'''

HARNESS = '''package com.eabusham.routervpn;
import android.app.*;import android.net.VpnService;import android.widget.*;import java.util.*;
public class PickerTest{
 final Activity activity=new Activity();final AndroidNodeStore nodes=new AndroidNodeStore();final AndroidStandardExitStore exits=new AndroidStandardExitStore();
 final AndroidUnifiedConnectionController controller=new AndroidUnifiedConnectionController();AndroidOrderedCandidatePicker picker;AndroidOrderedPathSelection draft;String picked="";
 void open(String... modes)throws Exception{draft=new AndroidOrderedPathSelection(modes);show();}
 void show()throws Exception{picker=new AndroidOrderedCandidatePicker(activity,draft,true,nodes,exits,controller,new AndroidTelemetry(),(d,id)->picked=id,d->{},()->{});picker.show();}
 String label(int i){return AlertDialog.last.adapter.getItem(i).toString();}
 static int checks;static void ok(boolean b,String m){checks++;if(!b)throw new AssertionError(m);}
 public static void main(String[]args)throws Exception{
  PickerTest h=new PickerTest();h.open("shadowsocks");ok(AlertDialog.last.getButton(-3).visibility==8&&h.label(0).equals("Node a"),"no prefix produced a timing or measure action");h.picker.close();
  h=new PickerTest();VpnService.needsPermission=true;h.open("wg","shadowsocks");ok(AndroidOrderedCandidatePicker.isPermissionRequest(h.activity.permissionRequest),"single original WG prefix did not request permission");h.picker.permission(h.activity.permissionRequest+1,true);ok(!AlertDialog.last.getListView().isEnabled(),"another picker permission changed this operation");h.picker.permission(h.activity.permissionRequest,false);ok(AlertDialog.last.getListView().isEnabled()&&h.label(1).contains("Unmeasured"),"denied permission must return unscored choices");h.picker.close();
  h=new PickerTest();VpnService.needsPermission=false;h.open("wg","shadowsocks");ok(AndroidViaEntryLatencyProbe.count==50&&AndroidViaEntryLatencyProbe.entry.equals("p0")&&!AlertDialog.last.getListView().isEnabled(),"first-hop automatic test lost mode, count, or pending ownership");
  var single=AndroidViaEntryLatencyProbe.pending;single.finished(new AndroidViaEntryLatencyProbe.Result(),null);ok(h.label(0).endsWith("Unmeasured")&&h.label(1).endsWith("7.5 ms"),"single-hop candidate bound to incorrect row");AlertDialog.last.clickItem(1);ok(h.picked.equals("b")&&AndroidOrderedPathSelection.saves==0,"single WG selection wrote the draft");
  h=new PickerTest();h.open("awg2-fast","wg","shadowsocks");ok(AlertDialog.last.getButton(-3).getText().toString().equals("Save path & measure")&&AndroidOrderedPathSelection.saves==0,"unsaved draft implicitly published");AlertDialog.last.getButton(-2).performClick();ok(AndroidOrderedPathSelection.saves==0,"Back published the draft");
  h=new PickerTest();h.open("awg2-fast","wg","shadowsocks");AlertDialog.last.getButton(-3).performClick();
  ok(AndroidOrderedPathSelection.saves==1&&AndroidUnifiedConnectionController.prefix==1&&h.label(0).endsWith("12.3 ms")&&h.label(1).endsWith("Unmeasured"),"saved recursive prefix did not bind scored and unscored rows");
  AndroidNodeCandidatePreparation.retained().stale=true;AlertDialog.last.clickItem(0);ok(h.picked.isEmpty(),"stale completed score authorized selection");
  h=new PickerTest();h.draft=new AndroidOrderedPathSelection("awg2-fast","wg","shadowsocks");h.draft.markSaved();h.show();
  ok(AndroidOrderedPathSelection.saves==1&&h.label(0).endsWith("12.3 ms"),"exact saved prefix must retest without another save");h.picker.close();
  h=new PickerTest();h.draft=new AndroidOrderedPathSelection("awg2-fast","wg","shadowsocks");h.draft.markSaved();h.draft.members.get(0).source.original="changed";h.show();
  ok(AlertDialog.last.getButton(-3).getText().toString().startsWith("Save path")&&h.label(0).endsWith("Unmeasured"),"different private source reused a saved measurement");h.picker.close();
  h=new PickerTest();h.draft=new AndroidOrderedPathSelection("socks5","shadowsocks");h.show();ok(AlertDialog.last.getButton(-3).visibility==8&&h.label(0).endsWith("Unmeasured"),"unsupported prefix invented candidate timing");h.picker.close();
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
    sources['android/app/AlertDialog.java']=s
    sources['android/os/Handler.java']='package android.os;public class Handler{public Handler(Looper l){}public void postDelayed(Runnable r,long t){}public void removeCallbacks(Runnable r){}}'
    sources['android/os/Looper.java']='package android.os;public class Looper{public static Looper getMainLooper(){return new Looper();}}'
    base='com/eabusham/routervpn/'
    sources[base+'PickerTest.java']=HARNESS
    sources[base+'AndroidOrderedCandidatePicker.java']=(JAVA/'AndroidOrderedCandidatePicker.java').read_text()
    sources[base+'Boundaries.java']=DOMAIN.replace('// MATCH_SAVED',method((JAVA/'AndroidOrderedPathSelection.java').read_text(),'    AndroidNodeStore.ChainCapture matchingSavedPath('))
    with tempfile.TemporaryDirectory() as work:
        temp=Path(work)
        for name,src in sources.items():
            target=temp/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(src)
        subprocess.run(['javac','--release','17','-cp',JAR,'-d',work,*map(str,temp.rglob('*.java'))],check=True)
        subprocess.run(['java','-cp',os.pathsep.join((work,JAR)),'com.eabusham.routervpn.PickerTest'],check=True)
if __name__=='__main__':main()
