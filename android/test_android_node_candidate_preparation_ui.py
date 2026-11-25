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
 'android/widget/Button.java':'package android.widget;public class Button{public interface Click{void run(Button b);}public static volatile Button last;public static Button draft;public Click click;public String text;public Button(android.content.Context c){last=this;}public void setText(String s){text=s;if(s.equals("Use in draft"))draft=this;}public void setOnClickListener(Click c){click=c;}}',
 'android/widget/EditText.java':'package android.widget;public class EditText{public static EditText last;public String text="";public EditText(android.content.Context c){last=this;}public void setHint(String s){}public CharSequence getText(){return text;}}',
 'android/widget/LinearLayout.java':'package android.widget;public class LinearLayout{public static final int VERTICAL=1;public LinearLayout(android.content.Context c){}public void setOrientation(int i){}public void addView(Object o){}}',
 'android/widget/ScrollView.java':'package android.widget;public class ScrollView{public ScrollView(android.content.Context c){}public void addView(Object o){}}',
}
BOUNDARIES=r'''package com.eabusham.routervpn;
import android.content.Context;import java.util.*;
final class AndroidNodeChainCapture{static boolean responsePrefix(java.util.List<?> sources,java.util.List<String> modes,int position,String execution){return position>0&&position<modes.size()-1&&modes.get(position).equals("shadowsocks")&&(execution.equals("local")||execution.equals("auto")&&modes.get(0).equals("wg"));}}
final class AndroidNodeStore{static final int PHYSICAL_TRAVERSAL_DEPTH=96;static final class ChainCapture{final List<?> members=List.of();List<String> modes=List.of("wg","awg2-fast","awg2-strong","shadowsocks");String execution="local";boolean valid=true;int draftPrefix=-1;boolean measurementOnly(){return draftPrefix>=0;}void requirePurpose(int p){if(!"local".equals(execution))throw new IllegalStateException("selected draft cannot start a normal connection");requireCandidatePurpose(p);}void requireCandidatePurpose(int p){if(p!=draftPrefix)throw new IllegalStateException("wrong draft prefix");}void requireCurrent(){if(!valid)throw new IllegalStateException("source changed");}}}
final class AndroidOrderedPathSelection{long revision(){return insertions;}List<String> members(){return source.modes;}boolean canMeasureResponseThrough(int p){return AndroidNodeChainCapture.responsePrefix(source.members,source.modes,p,source.execution);}AndroidNodeStore.ChainCapture source=new AndroidNodeStore.ChainCapture();int measured=-1,insertions;java.util.concurrent.Callable<AndroidNodeStore.ChainCapture> candidateDraftCapture(int prefix){measured=prefix;return ()->source;}}
final class AndroidStandardExitStore{AndroidStandardExitStore(Context c){}}
final class AndroidHomeStateStore{static final class Snapshot{boolean connected;}static Snapshot home=new Snapshot();static Snapshot snapshot(Context c){return home;}}
final class AndroidConnectionSelection{static String selected="original";static String digest(Context c,AndroidNodeStore n){return selected;}static void requireCurrent(Context c,AndroidNodeStore n,String s){if(!s.equals(selected))throw new IllegalStateException("selection changed");}}
final class AndroidConnectionProfileStore{static AndroidNodeStore.ChainCapture source=new AndroidNodeStore.ChainCapture();static class Record{String name;Record(String n){name=n;}}AndroidConnectionProfileStore(Context c,AndroidNodeStore n,AndroidStandardExitStore e){}AndroidNodeStore.ChainCapture currentOrderedPath(){return source;}}
final class AndroidNodeCandidateResult{final String name;AndroidNodeCandidateResult(){this("Original candidate");}AndroidNodeCandidateResult(String name){this.name=name;}final double score=2.5;boolean valid=true;boolean current(long now){return valid;}}
final class AndroidNodeCandidateProfile{static int writes;static AndroidNodeCandidateResult lastSavedResult;final String description="Original saved prefix → candidate";final AndroidNodeCandidatePreparation owner;final AndroidNodeCandidateResult result;AndroidNodeCandidateProfile(AndroidNodeCandidatePreparation o,AndroidNodeCandidateResult r){owner=o;result=r;}int useInDraft(AndroidOrderedPathSelection draft){if(!owner.retired||owner.cancelled||!result.valid)throw new IllegalStateException("retired insertion");draft.insertions++;var fresh=new AndroidNodeStore.ChainCapture();fresh.modes=new ArrayList<>(draft.source.modes);fresh.draftPrefix=draft.source.draftPrefix+1;fresh.modes.add(fresh.draftPrefix,"shadowsocks");fresh.execution=draft.source.execution;draft.source=fresh;return fresh.draftPrefix;}AndroidConnectionProfileStore.Record save(Context c,String name){if(!owner.retired||owner.cancelled||!result.valid)throw new IllegalStateException("retired result authority");if(name.trim().isEmpty())throw new IllegalStateException("name required");writes++;lastSavedResult=result;return new AndroidConnectionProfileStore.Record(name);}}
final class AndroidNodeCandidatePreparation{
 // SHIPPING_PREFIX_DECISION
 // SHIPPING_REVIEW_RELEASE
 Runnable afterReviewRelease;boolean delayRelease,userCancelled;
 interface Callback{void progress(String detail);void finished(List<Choice> choices,Throwable failure);}static final class Choice{final AndroidNodeCandidateResult result;final AndroidNodeCandidateProfile profile;final String saveReason;String draftReason(){return saveReason;}AndroidNodeCandidateProfile draftInsertion(){return profile;}Choice(AndroidNodeCandidatePreparation o){result=new AndroidNodeCandidateResult();profile=new AndroidNodeCandidateProfile(o,result);saveReason="";}Choice(String reason){result=new AndroidNodeCandidateResult("Measured retained duplicate");profile=null;saveReason=reason;}}
 AndroidNodeStore.ChainCapture original;boolean ownsSource(AndroidNodeStore.ChainCapture value){return original!=null&&original==value;}static volatile AndroidNodeCandidatePreparation active;volatile boolean started,cancelled,retired;volatile Callback observer;final List<Choice> results=new ArrayList<>();static AndroidNodeCandidatePreparation retained(){return active;}
 synchronized boolean observes(Callback c){return observer==c;}void detach(Callback c){if(observer==c)observer=null;}void attach(Callback c){observer=c;if(retired)c.finished(results,null);else c.progress("Testing saved path; original candidate drain pending");}
 void cancelFromUser(){cancelled=userCancelled=true;if(!delayRelease)releaseReview();}
 void finishNetworkClose(){cancelled=userCancelled;releaseReview();}
 void complete(){retired=true;results.add(new Choice(this));Callback c=observer;if(c!=null)c.finished(results,null);}
}
final class AndroidUnifiedConnectionController{
 interface Callback{void progress(String detail);void finished(boolean ok,String detail);}
 boolean connected,busy;int requests;AndroidNodeStore.ChainCapture captured;int prefix=-1;Callback pending;AndroidNodeCandidatePreparation purpose;
 boolean isActiveOrTransitioning(){return busy;}boolean isConnected(){return connected;}boolean pathCurrent(AndroidHomeStateStore.Snapshot h){return h==AndroidHomeStateStore.home;}
 void testOrderedCandidates(AndroidNodeStore.ChainCapture source,AndroidHomeStateStore.Snapshot home,String selection,int prefix,AndroidNodeCandidatePreparation.Callback observer,Callback callback){requests++;captured=source;this.prefix=prefix;pending=callback;purpose=new AndroidNodeCandidatePreparation();purpose.original=source;purpose.observer=observer;AndroidNodeCandidatePreparation.active=purpose;callback.progress("Waiting for Android VPN permission to test saved path");}
 boolean cancelPending(Callback c){if(pending!=c)return false;pending=null;purpose.cancelFromUser();c.finished(false,"Cancelled exact permission");return true;}
 boolean cancelCandidatePermission(AndroidNodeCandidatePreparation captured){if(captured!=purpose||pending==null)return false;return cancelPending(pending);}
 void approve(){purpose.started=true;pending=null;purpose.observer.progress("Testing saved path and candidate connections");}
}
final class AndroidNodeCandidateDialog{static int shown,closed;AndroidNodeCandidateDialog(android.app.Activity a){}void show(){shown++;}void close(){closed++;}}
'''
PRODUCT=r'''package com.eabusham.routervpn;
final class CandidateProductSurface extends android.app.Activity{
 static class EditorPicker{boolean visible(){return true;}}EditorPicker orderedPicker;
 final AndroidNodeStore nodeStore=new AndroidNodeStore();final AndroidUnifiedConnectionController connection=new AndroidUnifiedConnectionController();AndroidNodeCandidateDialog candidateDialog;AndroidNodeCandidatePreparationDialog preparedCandidateDialog;int refreshes;void refreshConnectionLater(){refreshes++;}
 boolean resumed=true;void toast(String value){}String safe(Exception e){return e.getMessage();}
 AndroidOrderedPathSelection reviewed;void showOrderedEditor(AndroidOrderedPathSelection d){reviewed=d;}
 void edit(AndroidOrderedPathSelection d,int p)throws Exception{measureOrderedDraft(d,p);}
 void test(){runCandidateTimes();}void resumeTest(){resumeCandidatePreparation();}void pauseTest(){detachCandidatePreparation();}
 // SHIPPING_PRODUCT_METHODS
}'''
HARNESS=r'''package com.eabusham.routervpn;
import android.app.*;import android.widget.*;import java.util.*;
public final class CandidatePreparationUITest{
 static int checks;static void check(boolean ok,String message){checks++;if(!ok)throw new AssertionError(message);}static void workers()throws Exception{long end=System.nanoTime()+5_000_000_000L;for(;;){List<Thread> work=new ArrayList<>();for(Thread t:Thread.getAllStackTraces().keySet())if(t.isAlive()&&(t.getName().equals("routervpn-candidate-choice-capture")||t.getName().equals("save-prepared-candidate-profile")))work.add(t);if(work.isEmpty())return;for(Thread t:work){long left=end-System.nanoTime();if(left<=0)throw new AssertionError("UI worker did not finish");t.join(Math.max(1,left/1000000));}}}
 static CandidateProductSurface screen(){Button.draft=null;AndroidNodeCandidatePreparation.active=null;AlertDialog.last=null;AndroidHomeStateStore.home=new AndroidHomeStateStore.Snapshot();AndroidConnectionSelection.selected="original";AndroidConnectionProfileStore.source=new AndroidNodeStore.ChainCapture();AndroidNodeCandidateProfile.writes=0;return new CandidateProductSurface();}
 static void idleAndRotation()throws Exception{
  for(int prefix=0;prefix<3;prefix++){
   var ui=screen();ui.test();workers();var picker=AlertDialog.last;check(picker!=null&&picker.items!=null&&picker.items.length==3,"shipping idle picker omitted a WG/AWG prefix or offered lazy final TCP");check(TextView.latest.contains("without later nodes")&&picker.items[prefix].toString().contains("prefix only"),"idle UI concealed independent packet prefix preparation");check(ui.connection.requests==0,"idle UI started temporary VPN before explicit prefix choice");picker.pick(prefix);
   var owner=ui.connection.purpose;check(ui.connection.captured==AndroidConnectionProfileStore.source&&ui.connection.prefix==prefix&&!owner.started,"shipping dialog lost original saved source or bypassed permission");
   var old=ui.preparedCandidateDialog;ui.pauseTest();check(!owner.cancelled&&owner.observer==null,"Activity pause cancelled process-owned temporary testing");ui.resumeTest();check(owner.observer!=null&&TextView.latest.contains("drain pending"),"recreated sheet did not attach captured progress");
   ui.connection.approve();Button.last.click.run(Button.last);check(AndroidNodeCandidateProfile.writes==0&&TextView.latest.contains("cleanup to finish"),"Save was offered before native DOWN completion");owner.complete();check(TextView.latest.contains("Temporary VPN stopped")&&TextView.latest.contains("50/50")&&TextView.latest.contains("TCP handshakes")&&TextView.latest.contains("authenticated responses"),"completed UI lost the packet and private response measurement meanings");
   ui.pauseTest();ui.resumeTest();check(TextView.latest.contains("50/50"),"recreated sheet did not recover retained completed choices");
   old.detach();check(owner.observer!=null,"retired screen detached its replacement observer");
   Button.last.click.run(Button.last);AlertDialog.last.pick(0);check(AndroidNodeCandidateProfile.writes==0&&AlertDialog.last.message.contains("Load, then Connect"),"candidate choice saved or connected before explicit confirmation");EditText.last.text="Chosen path";AlertDialog.last.positive.run(AlertDialog.last,0);workers();check(AndroidNodeCandidateProfile.writes==1&&TextView.latest.contains("Saved Chosen path"),"explicit Save did not use completed proposal");check(ui.connection.requests==1,"explicit profile Save also connected a path");
   ui.preparedCandidateDialog.cancel();check(owner.cancelled&&AndroidNodeCandidatePreparation.retained()==null,"explicit result Close retained its reservation");
  }
 }
 static void mixedProposalRows()throws Exception{
  var ui=screen();ui.test();workers();AlertDialog.last.pick(0);var owner=ui.connection.purpose;ui.connection.approve();
  owner.results.add(new AndroidNodeCandidatePreparation.Choice("This replacement duplicates a retained node."));owner.complete();
  check(TextView.latest.contains("Save unavailable: This replacement duplicates a retained node.")&&TextView.latest.split("50/50",-1).length==3,"measured incompatible row or explicit Save reason disappeared");
  Button.last.click.run(Button.last);check(AlertDialog.last.items!=null&&AlertDialog.last.items.length==1,"incompatible measured row entered the Save picker");
  try{AlertDialog.last.pick(0);EditText.last.text="Supported measured path";AlertDialog.last.positive.run(AlertDialog.last,0);workers();check(AndroidNodeCandidateProfile.writes==1&&AndroidNodeCandidateProfile.lastSavedResult==owner.results.get(1).result,"incompatible measured row changed the selected valid proposal identity");}
  catch(Throwable failure){throw new AssertionError("incompatible measured row changed the selected valid proposal identity",failure);}ui.preparedCandidateDialog.cancel();
  ui=screen();ui.test();workers();AlertDialog.last.pick(0);owner=ui.connection.purpose;ui.connection.approve();owner.complete();
  owner.results.clear();owner.results.add(new AndroidNodeCandidatePreparation.Choice("An imported middle needs the penultimate position."));owner.observer.finished(owner.results,null);
  check(TextView.latest.contains("Candidate measurements are available")&&TextView.latest.contains("Save unavailable:"),"all-incompatible rows were presented as compiled paths");
  Button.last.click.run(Button.last);check(TextView.latest.contains("no supported complete profile proposal")&&TextView.latest.contains("Save unavailable: An imported middle needs the penultimate position.")&&TextView.latest.contains("50/50")&&AndroidNodeCandidateProfile.writes==0,"all-incompatible rows acquired Save or lost their measured reason");ui.preparedCandidateDialog.cancel();
 }
 static void ownershipAndFailure()throws Exception{
  var ui=screen();ui.test();workers();AlertDialog.last.pick(0);var owner=ui.connection.purpose;ui.pauseTest();ui.resumeTest();ui.preparedCandidateDialog.cancel();check(ui.connection.pending==null,"recreated sheet retained captured permission receipt");check(owner.cancelled&&!owner.started,"explicit permission Cancel leaked original reservation");
  ui=screen();ui.test();workers();AlertDialog.last.pick(0);owner=ui.connection.purpose;ui.connection.approve();owner.complete();var old=ui.preparedCandidateDialog;ui.pauseTest();AndroidNodeCandidatePreparation replacement=new AndroidNodeCandidatePreparation();AndroidNodeCandidatePreparation.active=replacement;old.cancel();check(!replacement.cancelled,"stale Activity cancellation stopped a replacement owner");
  ui=screen();ui.test();workers();AlertDialog.last.pick(0);owner=ui.connection.purpose;ui.connection.approve();owner.complete();Button.last.click.run(Button.last);AlertDialog.last.pick(0);owner.results.get(0).result.valid=false;EditText.last.text="Stale";AlertDialog.last.positive.run(AlertDialog.last,0);workers();check(AndroidNodeCandidateProfile.writes==0&&TextView.latest.contains("not saved"),"late profile Save ignored detached authority refusal");ui.preparedCandidateDialog.cancel();
  ui=screen();ui.connection.connected=true;ui.test();check(ui.preparedCandidateDialog==null&&AndroidNodeCandidateDialog.shown>0,"normal connected prefix chooser was replaced by temporary preparation");
 }
 static void fullSavedChoices()throws Exception{
  for(var modes:List.of(List.of("wg"),List.of("shadowsocks","awg2-fast","shadowsocks"),List.of("wg","awg2-strong"))){
   var ui=screen();AndroidConnectionProfileStore.source.modes=modes;ui.test();workers();var picker=AlertDialog.last;int selected=picker.items.length-1;
   check(picker.items[selected].toString().contains("complete saved path")&&TextView.latest.contains("Other selections require the complete saved path"),"unsupported or final prefix lost complete-path disclosure");
   picker.pick(selected);check(ui.connection.requests==1&&!ui.connection.purpose.started,"full-saved fallback bypassed original permission");ui.preparedCandidateDialog.cancel();
  }
 }
 static void earlierDraft()throws Exception{
  var ui=screen();var draft=new AndroidOrderedPathSelection();draft.source.modes=List.of("awg2-fast","shadowsocks","shadowsocks","shadowsocks");draft.source.draftPrefix=1;
  ui.edit(draft,1);workers();check(ui.reviewed==draft&&draft.measured==1&&ui.connection.captured==draft.source&&ui.connection.prefix==1,"draft editor dispatched a different source or position");
  check(!ui.connection.purpose.started&&AndroidNodeCandidateProfile.writes==0,"draft editor bypassed permission or implicitly saved");ui.connection.approve();ui.connection.purpose.complete();
  Button.last.click.run(Button.last);AlertDialog.last.pick(0);EditText.last.text="Earlier draft candidate";AlertDialog.last.positive.run(AlertDialog.last,0);workers();
  check(AndroidNodeCandidateProfile.writes==1&&ui.connection.requests==1,"draft Save failed or started another connection");ui.preparedCandidateDialog.cancel();
  ui=screen();draft.source.execution="auto";draft.source.modes=List.of("wg","shadowsocks","shadowsocks","shadowsocks");
  ui.edit(draft,1);workers();check(ui.connection.requests==1&&ui.connection.prefix==1&&ui.connection.captured==draft.source&&!ui.connection.purpose.started,"selected intermediate bypassed permission or used the normal Connect purpose");
  Button.draft.click.run(Button.draft);
  check(draft.insertions==0&&TextView.latest.contains("fresh, complete insertion"),"draft insertion became available before DOWN");
  ui.pauseTest();Button.draft=null;ui.resumeTest();check(Button.draft!=null,"activity lost the original measured draft on permission return");
  ui.connection.approve();var owner=ui.connection.purpose;owner.complete();
  var originalSource=draft.source;owner.delayRelease=true;Button.draft.click.run(Button.draft);AlertDialog.last.pick(0);workers();
  check(owner.userCancelled&&AndroidNodeCandidatePreparation.retained()==owner&&ui.connection.requests==1,"next trial ignored the retained original network observer");
  owner.finishNetworkClose();workers();
  check(ui.connection.requests==2&&ui.connection.prefix==2&&ui.connection.purpose!=owner&&!ui.connection.purpose.started&&ui.connection.captured!=originalSource&&ui.connection.captured.modes.size()==5,"next trial skipped permission, reused a source, or measured the last prefix instead of the inserted hop");
  check(draft.insertions==1&&ui.reviewed==draft&&owner.cancelled&&AndroidNodeCandidateProfile.writes==0&&ui.connection.requests==2,"explicit insertion saved, reconnected, or lost the measured draft");
  ui.preparedCandidateDialog.cancel();draft.source.draftPrefix=1;ui=screen();ui.edit(draft,1);workers();ui.connection.approve();owner=ui.connection.purpose;owner.complete();
  Button.draft.click.run(Button.draft);owner.results.get(0).result.valid=false;AlertDialog.last.pick(0);
  check(ui.connection.requests==1&&draft.insertions==1&&TextView.latest.contains("retired insertion"),"expired result inserted an intermediate");
  ui.preparedCandidateDialog.cancel();
  ui=screen();var full=new AndroidOrderedPathSelection();full.source.execution="auto";full.source.draftPrefix=1;
  full.source.modes=new ArrayList<>(Collections.nCopies(95,"shadowsocks"));full.source.modes.set(0,"wg");ui.edit(full,1);workers();ui.connection.approve();ui.connection.purpose.complete();
  Button.draft.click.run(Button.draft);AlertDialog.last.pick(0);ui.connection.purpose.finishNetworkClose();workers();
  check(full.members().size()==96&&ui.connection.requests==1&&ui.reviewed==full,"capacity-limited draft opened another trial");
  ui=screen();draft.source.valid=false;ui.edit(draft,1);workers();check(ui.connection.requests==0&&TextView.latest.contains("source changed"),"stale draft entered measurement");
  ui=screen();draft.source.valid=true;ui.edit(draft,2);workers();check(ui.connection.requests==0&&TextView.latest.contains("wrong draft prefix"),"draft changed its captured position");
 }
 static void changedWhileReleasing()throws Exception{
  for(int change=0;change<4;change++){
   var ui=screen();var draft=new AndroidOrderedPathSelection();draft.source.execution="auto";draft.source.draftPrefix=1;draft.source.modes=List.of("wg","shadowsocks","shadowsocks","shadowsocks");
   ui.edit(draft,1);workers();ui.connection.approve();var old=ui.connection.purpose;old.complete();old.delayRelease=true;
   Button.draft.click.run(Button.draft);AlertDialog.last.pick(0);
   if(change==0)ui.pauseTest();
   if(change==1)draft.insertions++;
   if(change==2)AndroidHomeStateStore.home=new AndroidHomeStateStore.Snapshot();
   if(change==3)ui.preparedCandidateDialog.cancel();
   old.finishNetworkClose();workers();
   check(ui.connection.requests==1,"retired candidate review launched through a changed editor, home, or Activity");
  }
 }
 public static void main(String[] args)throws Exception{idleAndRotation();earlierDraft();changedWhileReleasing();ownershipAndFailure();mixedProposalRows();fullSavedChoices();System.out.println("Android candidate shipping UI: "+checks+" exact source, purpose, rotation, DOWN and explicit Save checks PASS");}
}'''

def main():
    if not shutil.which('javac'):raise RuntimeError('JDK17 required')
    product=(JAVA/'ProductActivity.java').read_text()
    helper=(JAVA/'AndroidNodeCandidatePreparation.java').read_text()
    start=helper.index('    static boolean packetPrefix(');end=helper.index('    boolean prefixOnly()',start)
    boundaries=BOUNDARIES.replace('// SHIPPING_PREFIX_DECISION',helper[start:end])
    review=helper[helper.index('    boolean finishDraftReview('):helper.index('    private long deliverCompletion(')]
    boundaries=boundaries.replace('// SHIPPING_REVIEW_RELEASE',review)
    methods=[]
    for signature in ('    private void runCandidateTimes(', '    private void resumeCandidatePreparation(', '    private void detachCandidatePreparation(', '    private void closeCandidateMeasurement('):
        start=product.index(signature);methods.append(product[start:product.index('\n',start)])
    for signature in ('    private void measureOrderedDraft(', '    private void continueOrderedDraft('):
        start=product.index(signature);methods.append(product[start:product.index('\n    }',start)+6])
    for signature in ('    @Override protected void onPause(', '    @Override protected void onDestroy('):
        start=product.index(signature);assert 'detachCandidatePreparation();' in product[start:product.index('\n',start)]
    start=product.index('    @Override protected void onResume(');assert 'resumeCandidatePreparation();' in product[start:product.index('\n',start)]
    with tempfile.TemporaryDirectory(prefix='routervpn-candidate-ui-') as directory:
        work=Path(directory);app=work/'com/eabusham/routervpn';app.mkdir(parents=True)
        for name,body in SOURCES.items():
            target=work/name;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(body)
        (app/'Boundaries.java').write_text(boundaries);(app/'CandidateProductSurface.java').write_text(PRODUCT.replace('// SHIPPING_PRODUCT_METHODS','\n'.join(methods)));(app/'CandidatePreparationUITest.java').write_text(HARNESS)
        target=app/'AndroidNodeCandidatePreparationDialog.java';source=(JAVA/target.name).read_text();target.write_text(source)
        classes=work/'classes';compile=['javac','--release','17','-d',str(classes),*map(str,work.rglob('*.java'))]
        subprocess.run(compile,check=True,timeout=45);run=['java','-cp',str(classes),'com.eabusham.routervpn.CandidatePreparationUITest'];subprocess.run(run,check=True,timeout=30)
        controls=(
            ('AndroidNodeCandidatePreparationDialog.java','continueDraft.accept(editor,inserted);','continueDraft.accept(editor,inserted+1);','next trial skipped permission, reused a source, or measured the last prefix instead of the inserted hop'),
            ('AndroidNodeCandidatePreparationDialog.java','AndroidNodeCandidatePreparation.packetPrefix(source,i)','true','unsupported or final prefix lost complete-path disclosure'),
            ('AndroidNodeCandidatePreparationDialog.java','if(captured!=null)connection.cancelCandidatePermission(captured);', '', 'recreated sheet retained captured permission receipt'),
            ('AndroidNodeCandidatePreparationDialog.java','owner.attach(notice);','/* no attachment */','recreated sheet did not attach captured progress'),
            ('AndroidNodeCandidatePreparationDialog.java','if(detached)return;detached=true;', 'if(detached)return;if(owner!=null)owner.cancelFromUser();detached=true;', 'Activity pause cancelled process-owned temporary testing'),
            ('AndroidNodeCandidatePreparationDialog.java','if(choice.profile!=null&&choice.saveReason.isEmpty()){available.add(choice);','if(true){available.add(choice);','incompatible measured row entered the Save picker'),
            ('AndroidNodeCandidatePreparationDialog.java','var selected=available.get(w);','var selected=choices.get(w);','incompatible measured row changed the selected valid proposal identity'),
            ('AndroidNodeCandidatePreparationDialog.java','if(measured)appendMeasuredRows(detail,choices);','','all-incompatible rows acquired Save or lost their measured reason'),
            ('AndroidNodeCandidatePreparationDialog.java','if(!choice.saveReason.isEmpty())text.append("\\nSave unavailable: ").append(choice.saveReason);','if(false)text.append("\\nSave unavailable: ").append(choice.saveReason);','measured incompatible row or explicit Save reason disappeared'),
            ('AndroidNodeCandidatePreparationDialog.java','void cancel(){if(detached)return;', 'void cancel(){if(detached){AndroidNodeCandidatePreparation replacement=AndroidNodeCandidatePreparation.retained();if(replacement!=null)replacement.cancelFromUser();return;}', 'stale Activity cancellation stopped a replacement owner'),
            ('CandidateProductSurface.java','AndroidNodeCandidatePreparation.retained()!=null||!connection.isConnected()', 'false', 'shipping idle picker omitted a WG/AWG prefix or offered lazy final TCP'),
        )
        for name,before,after,witness in controls:
            file=app/name;original=file.read_text();assert original.count(before)==1,(name,before);file.write_text(original.replace(before,after));subprocess.run(compile,check=True,timeout=45,capture_output=True);failed=subprocess.run(run,text=True,capture_output=True,timeout=30);file.write_text(original)
            assert failed.returncode and witness in failed.stderr,'UI causal control missed '+witness+'\n'+failed.stdout+failed.stderr
            print('Android candidate UI causal control rejected:',witness,flush=True)

if __name__=='__main__':main()
