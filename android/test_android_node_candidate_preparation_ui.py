#!/usr/bin/env python3
"""Execute the shipping temporary-candidate dialog and Product entry/lifecycle.

Android widgets, permission dispatch and the already independently exercised
process supervisor/profile transaction are explicit boundaries. No test score
is native-network evidence. Permission, supervisor and Profile have separate
mandatory composed shipping-source gates.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT=Path(__file__).resolve().parents[1]
JAVA=ROOT/'android/app/src/main/java/com/eabusham/routervpn'
SOURCES={
 'android/content/Context.java':'package android.content;public class Context{}',
 'android/app/Activity.java':'package android.app;public class Activity extends android.content.Context{public boolean destroyed;public boolean isFinishing(){return false;}public boolean isDestroyed(){return destroyed;}public void runOnUiThread(Runnable action){action.run();}}',
 'android/app/AlertDialog.java':'''package android.app;public class AlertDialog{public interface Click{void run(AlertDialog d,int w);}public interface Dismiss{void run(AlertDialog d);}public static volatile AlertDialog last;public String title,message;public CharSequence[] items;public Click selected,negative,positive;public Object view;boolean showing;Dismiss dismissed;public boolean isShowing(){return showing;}public void show(){showing=true;last=this;}public void dismiss(){showing=false;if(dismissed!=null)dismissed.run(this);}public void setOnDismissListener(Dismiss d){dismissed=d;}public void pick(int i){selected.run(this,i);dismiss();}public static class Builder{final AlertDialog d=new AlertDialog();public Builder(Activity a){}public Builder setTitle(String s){d.title=s;return this;}public Builder setMessage(String s){d.message=s;return this;}public Builder setItems(CharSequence[] a,Click c){d.items=a;d.selected=c;return this;}public Builder setView(Object v){d.view=v;return this;}public Builder setNegativeButton(String s,Click c){d.negative=c;return this;}public Builder setPositiveButton(String s,Click c){d.positive=c;return this;}public AlertDialog create(){return d;}public AlertDialog show(){d.show();return d;}}}''',
 'android/widget/TextView.java':'package android.widget;public class TextView{public static volatile String latest="";public TextView(android.content.Context c){}public void setPadding(int a,int b,int c,int d){}public void setTextIsSelectable(boolean b){}public void setText(String s){latest=s;}}',
 'android/widget/Button.java':'package android.widget;public class Button{public interface Click{void run(Button b);}public static volatile Button last;public Click click;public String text;public Button(android.content.Context c){last=this;}public void setText(String s){text=s;}public void setOnClickListener(Click c){click=c;}}',
 'android/widget/EditText.java':'package android.widget;public class EditText{public static EditText last;public String text="";public EditText(android.content.Context c){last=this;}public void setHint(String s){}public CharSequence getText(){return text;}}',
 'android/widget/LinearLayout.java':'package android.widget;public class LinearLayout{public static final int VERTICAL=1;public LinearLayout(android.content.Context c){}public void setOrientation(int i){}public void addView(Object o){}}',
 'android/widget/ScrollView.java':'package android.widget;public class ScrollView{public ScrollView(android.content.Context c){}public void addView(Object o){}}',
}
BOUNDARIES=r'''package com.eabusham.routervpn;
import android.content.Context;import java.util.*;
final class AndroidNodeStore{static final class ChainCapture{final List<String> modes=List.of("wg","awg2-fast","awg2-strong","shadowsocks");String execution="local";boolean valid=true;void requireCurrent(){if(!valid)throw new IllegalStateException("source changed");}}}
final class AndroidStandardExitStore{AndroidStandardExitStore(Context c){}}
final class AndroidHomeStateStore{static final class Snapshot{boolean connected;}static Snapshot home=new Snapshot();static Snapshot snapshot(Context c){return home;}}
final class AndroidConnectionSelection{static String selected="original";static String digest(Context c,AndroidNodeStore n){return selected;}static void requireCurrent(Context c,AndroidNodeStore n,String s){if(!s.equals(selected))throw new IllegalStateException("selection changed");}}
final class AndroidConnectionProfileStore{static AndroidNodeStore.ChainCapture source=new AndroidNodeStore.ChainCapture();static class Record{String name;Record(String n){name=n;}}AndroidConnectionProfileStore(Context c,AndroidNodeStore n,AndroidStandardExitStore e){}AndroidNodeStore.ChainCapture currentOrderedPath(){return source;}}
final class AndroidNodeCandidateResult{final String name="Original candidate";final double score=2.5;boolean valid=true;boolean current(long now){return valid;}}
final class AndroidNodeCandidateProfile{static int writes;final String description="Original saved prefix → candidate";final AndroidNodeCandidatePreparation owner;final AndroidNodeCandidateResult result;AndroidNodeCandidateProfile(AndroidNodeCandidatePreparation o,AndroidNodeCandidateResult r){owner=o;result=r;}AndroidConnectionProfileStore.Record save(Context c,String name){if(!owner.retired||owner.cancelled||!result.valid)throw new IllegalStateException("retired result authority");if(name.trim().isEmpty())throw new IllegalStateException("name required");writes++;return new AndroidConnectionProfileStore.Record(name);}}
final class AndroidNodeCandidatePreparation{
 interface Callback{void progress(String detail);void finished(List<Choice> choices,Throwable failure);}static final class Choice{final AndroidNodeCandidateResult result=new AndroidNodeCandidateResult();final AndroidNodeCandidateProfile profile;Choice(AndroidNodeCandidatePreparation o){profile=new AndroidNodeCandidateProfile(o,result);}}
 static volatile AndroidNodeCandidatePreparation active;volatile boolean started,cancelled,retired;volatile Callback observer;final List<Choice> results=new ArrayList<>();static AndroidNodeCandidatePreparation retained(){return active;}
 synchronized boolean observes(Callback c){return observer==c;}void detach(Callback c){if(observer==c)observer=null;}void attach(Callback c){observer=c;if(retired)c.finished(results,null);else c.progress("Testing saved path; original candidate drain pending");}
 void cancelFromUser(){cancelled=true;if(active==this)active=null;}
 void complete(){retired=true;results.add(new Choice(this));Callback c=observer;if(c!=null)c.finished(results,null);}
}
final class AndroidUnifiedConnectionController{
 interface Callback{void progress(String detail);void finished(boolean ok,String detail);}
 boolean connected,busy;int requests;AndroidNodeStore.ChainCapture captured;int prefix=-1;Callback pending;AndroidNodeCandidatePreparation purpose;
 boolean isActiveOrTransitioning(){return busy;}boolean isConnected(){return connected;}boolean pathCurrent(AndroidHomeStateStore.Snapshot h){return h==AndroidHomeStateStore.home;}
 void testOrderedCandidates(AndroidNodeStore.ChainCapture source,AndroidHomeStateStore.Snapshot home,String selection,int prefix,AndroidNodeCandidatePreparation.Callback observer,Callback callback){requests++;captured=source;this.prefix=prefix;pending=callback;purpose=new AndroidNodeCandidatePreparation();purpose.observer=observer;AndroidNodeCandidatePreparation.active=purpose;callback.progress("Waiting for Android VPN permission to test saved path");}
 boolean cancelPending(Callback c){if(pending!=c)return false;pending=null;purpose.cancelFromUser();c.finished(false,"Cancelled exact permission");return true;}
 boolean cancelCandidatePermission(AndroidNodeCandidatePreparation captured){if(captured!=purpose||pending==null)return false;return cancelPending(pending);}
 void approve(){purpose.started=true;pending=null;purpose.observer.progress("Testing saved path and candidate connections");}
}
final class AndroidNodeCandidateDialog{static int shown,closed;AndroidNodeCandidateDialog(android.app.Activity a){}void show(){shown++;}void close(){closed++;}}
'''
PRODUCT=r'''package com.eabusham.routervpn;
final class CandidateProductSurface extends android.app.Activity{
 final AndroidNodeStore nodeStore=new AndroidNodeStore();final AndroidUnifiedConnectionController connection=new AndroidUnifiedConnectionController();AndroidNodeCandidateDialog candidateDialog;AndroidNodeCandidatePreparationDialog preparedCandidateDialog;int refreshes;void refreshConnectionLater(){refreshes++;}
 void test(){runCandidateTimes();}void resumeTest(){resumeCandidatePreparation();}void pauseTest(){detachCandidatePreparation();}
 // SHIPPING_PRODUCT_METHODS
}'''
HARNESS=r'''package com.eabusham.routervpn;
import android.app.*;import android.widget.*;import java.util.*;
public final class CandidatePreparationUITest{
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}static void workers()throws Exception{long end=System.nanoTime()+5_000_000_000L;for(;;){List<Thread> work=new ArrayList<>();for(Thread t:Thread.getAllStackTraces().keySet())if(t.isAlive()&&(t.getName().equals("routervpn-candidate-choice-capture")||t.getName().equals("save-prepared-candidate-profile")))work.add(t);if(work.isEmpty())return;for(Thread t:work){long left=end-System.nanoTime();if(left<=0)throw new AssertionError("UI worker did not finish");t.join(Math.max(1,left/1000000));}}}
 static CandidateProductSurface screen(){AndroidNodeCandidatePreparation.active=null;AlertDialog.last=null;AndroidHomeStateStore.home=new AndroidHomeStateStore.Snapshot();AndroidConnectionSelection.selected="original";AndroidConnectionProfileStore.source=new AndroidNodeStore.ChainCapture();AndroidNodeCandidateProfile.writes=0;return new CandidateProductSurface();}
 static void idleAndRotation()throws Exception{
  for(int prefix=0;prefix<3;prefix++){
   var ui=screen();ui.test();workers();var picker=AlertDialog.last;check(picker!=null&&picker.items!=null&&picker.items.length==3,"shipping idle picker omitted a WG/AWG prefix or offered lazy final TCP");check(TextView.latest.contains("existing final node must work"),"idle UI concealed complete saved-final preparation limit");check(ui.connection.requests==0,"idle UI started temporary VPN before explicit prefix choice");picker.pick(prefix);
   var owner=ui.connection.purpose;check(ui.connection.captured==AndroidConnectionProfileStore.source&&ui.connection.prefix==prefix&&!owner.started,"shipping dialog lost original saved source or bypassed permission");
   var old=ui.preparedCandidateDialog;ui.pauseTest();check(!owner.cancelled&&owner.observer==null,"Activity pause cancelled process-owned temporary testing");ui.resumeTest();check(owner.observer!=null&&TextView.latest.contains("drain pending"),"recreated sheet did not attach captured progress");
   ui.connection.approve();Button.last.click.run(Button.last);check(AndroidNodeCandidateProfile.writes==0&&TextView.latest.contains("cleanup to finish"),"Save was offered before native DOWN completion");owner.complete();check(TextView.latest.contains("Temporary VPN stopped")&&TextView.latest.contains("50/50")&&TextView.latest.contains("not HTTP"),"completed UI lost TCP-only measurement meaning");
   ui.pauseTest();ui.resumeTest();check(TextView.latest.contains("50/50"),"recreated sheet did not recover retained completed choices");
   old.detach();check(owner.observer!=null,"retired screen detached its replacement observer");
   Button.last.click.run(Button.last);AlertDialog.last.pick(0);check(AndroidNodeCandidateProfile.writes==0&&AlertDialog.last.message.contains("Load, then Connect"),"candidate choice saved or connected before explicit confirmation");EditText.last.text="Chosen path";AlertDialog.last.positive.run(AlertDialog.last,0);workers();check(AndroidNodeCandidateProfile.writes==1&&TextView.latest.contains("Saved Chosen path"),"explicit Save did not use completed proposal");check(ui.connection.requests==1,"explicit profile Save also connected a path");
   ui.preparedCandidateDialog.cancel();check(owner.cancelled&&AndroidNodeCandidatePreparation.retained()==null,"explicit result Close retained its reservation");
  }
 }
 static void ownershipAndFailure()throws Exception{
  var ui=screen();ui.test();workers();AlertDialog.last.pick(0);var owner=ui.connection.purpose;ui.pauseTest();ui.resumeTest();ui.preparedCandidateDialog.cancel();check(ui.connection.pending==null,"recreated sheet retained captured permission receipt");check(owner.cancelled&&!owner.started,"explicit permission Cancel leaked original reservation");
  ui=screen();ui.test();workers();AlertDialog.last.pick(0);owner=ui.connection.purpose;ui.connection.approve();owner.complete();var old=ui.preparedCandidateDialog;ui.pauseTest();AndroidNodeCandidatePreparation replacement=new AndroidNodeCandidatePreparation();AndroidNodeCandidatePreparation.active=replacement;old.cancel();check(!replacement.cancelled,"stale Activity cancellation stopped a replacement owner");
  ui=screen();ui.test();workers();AlertDialog.last.pick(0);owner=ui.connection.purpose;ui.connection.approve();owner.complete();Button.last.click.run(Button.last);AlertDialog.last.pick(0);owner.results.get(0).result.valid=false;EditText.last.text="Stale";AlertDialog.last.positive.run(AlertDialog.last,0);workers();check(AndroidNodeCandidateProfile.writes==0&&TextView.latest.contains("not saved"),"late profile Save ignored detached authority refusal");ui.preparedCandidateDialog.cancel();
  ui=screen();ui.connection.connected=true;ui.test();check(ui.preparedCandidateDialog==null&&AndroidNodeCandidateDialog.shown>0,"normal connected prefix chooser was replaced by temporary preparation");
 }
 public static void main(String[] args)throws Exception{idleAndRotation();ownershipAndFailure();System.out.println("Android candidate shipping UI: "+checks+" exact source, purpose, rotation, DOWN and explicit Save checks PASS");}
}'''

def main():
    if not shutil.which('javac'):raise RuntimeError('JDK17 required')
    product=(JAVA/'ProductActivity.java').read_text()
    methods=[]
    for signature in ('    private void runCandidateTimes(', '    private void resumeCandidatePreparation(', '    private void detachCandidatePreparation(', '    private void closeCandidateMeasurement('):
        start=product.index(signature);methods.append(product[start:product.index('\n',start)])
    for signature in ('    @Override protected void onPause(', '    @Override protected void onDestroy('):
        start=product.index(signature);assert 'detachCandidatePreparation();' in product[start:product.index('\n',start)]
    start=product.index('    @Override protected void onResume(');assert 'resumeCandidatePreparation();' in product[start:product.index('\n',start)]
    with tempfile.TemporaryDirectory(prefix='routervpn-candidate-ui-') as directory:
        work=Path(directory);app=work/'com/eabusham/routervpn';app.mkdir(parents=True)
        for name,body in SOURCES.items():
            target=work/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(body)
        (app/'Boundaries.java').write_text(BOUNDARIES);(app/'CandidateProductSurface.java').write_text(PRODUCT.replace('// SHIPPING_PRODUCT_METHODS','\n'.join(methods)));(app/'CandidatePreparationUITest.java').write_text(HARNESS)
        target=app/'AndroidNodeCandidatePreparationDialog.java';source=(JAVA/target.name).read_text();target.write_text(source)
        classes=work/'classes';compile=['javac','--release','17','-d',str(classes),*map(str,work.rglob('*.java'))]
        subprocess.run(compile,check=True,timeout=45);run=['java','-cp',str(classes),'com.eabusham.routervpn.CandidatePreparationUITest'];subprocess.run(run,check=True,timeout=30)
        controls=(
            ('AndroidNodeCandidatePreparationDialog.java','if(captured!=null)connection.cancelCandidatePermission(captured);', '', 'recreated sheet retained captured permission receipt'),
            ('AndroidNodeCandidatePreparationDialog.java','owner.attach(notice);','/* no attachment */','recreated sheet did not attach captured progress'),
            ('AndroidNodeCandidatePreparationDialog.java','if(detached)return;detached=true;', 'if(detached)return;if(owner!=null)owner.cancelFromUser();detached=true;', 'Activity pause cancelled process-owned temporary testing'),
            ('AndroidNodeCandidatePreparationDialog.java','void cancel(){if(detached)return;', 'void cancel(){if(detached){AndroidNodeCandidatePreparation replacement=AndroidNodeCandidatePreparation.retained();if(replacement!=null)replacement.cancelFromUser();return;}', 'stale Activity cancellation stopped a replacement owner'),
            ('CandidateProductSurface.java','AndroidNodeCandidatePreparation.retained()!=null||!connection.isConnected()', 'false', 'shipping idle picker omitted a WG/AWG prefix or offered lazy final TCP'),
        )
        for name,before,after,witness in controls:
            file=app/name;original=file.read_text();assert original.count(before)==1,(name,before);file.write_text(original.replace(before,after));subprocess.run(compile,check=True,timeout=45,capture_output=True);failed=subprocess.run(run,text=True,capture_output=True,timeout=30);file.write_text(original)
            assert failed.returncode and witness in failed.stderr,'UI causal control missed '+witness+'\n'+failed.stdout+failed.stderr
            print('Android candidate UI causal control rejected:',witness,flush=True)

if __name__=='__main__':main()
