#!/usr/bin/env python3
"""Run the responsive row and home comparison/response decisions with Android view doubles."""
from pathlib import Path
import subprocess
import tempfile
from android_store_fixture import method

JAVA=Path(__file__).parent/'app/src/main/java/com/eabusham/routervpn'
VIEW='''package android.view;
public class View {
 public static final int GONE=8,VISIBLE=0;public int visibility,width,minimum,measured;
 public android.widget.LinearLayout.LayoutParams params;
 public View(){}public View(int width){this.width=width;}
 public int getVisibility(){return visibility;}public void setVisibility(int v){visibility=v;}
 public void measure(int w,int h){measured=width;}public int getMeasuredWidth(){return measured;}
 public int getMinimumWidth(){return minimum;}public Object getLayoutParams(){return params;}
 public static class MeasureSpec{public static final int UNSPECIFIED=0,EXACTLY=1<<30;public static int getMode(int v){return v&0xc0000000;}public static int getSize(int v){return v&0x3fffffff;}}
}'''
LAYOUT='''package android.widget;import android.view.View;import java.util.*;
public class LinearLayout extends View{
 public static final int VERTICAL=1,HORIZONTAL=0;private int orientation;final List<View> children=new ArrayList<>();
 public LinearLayout(android.content.Context c){}public void setGravity(int g){}public int getPaddingLeft(){return 4;}public int getPaddingRight(){return 4;}
 public void setOrientation(int o){orientation=o;}public int getOrientation(){return orientation;}public int getChildCount(){return children.size();}public View getChildAt(int i){return children.get(i);}
 public void addView(View v,LayoutParams p){v.params=p;children.add(v);}public void measure(int w,int h){onMeasure(w,h);}protected void onMeasure(int w,int h){}
 public static class LayoutParams{public static final int MATCH_PARENT=-1,WRAP_CONTENT=-2;public int width,leftMargin,rightMargin;public float weight;public LayoutParams(int w,float f){width=w;weight=f;}}
}'''
BOUND='''package com.eabusham.routervpn;import java.util.*;import android.view.View;
final class AndroidUnifiedNodeCatalog {static class Item{boolean router;String endpoint;Item(boolean r,String e){router=r;endpoint=e;}boolean isRouterVpn(){return router;}}}
final class AndroidNodeStore{}
final class AndroidStandardExitStore {static class Entry{boolean direct,via;Entry(boolean d,boolean v){direct=d;via=v;}}List<Entry> rows=new ArrayList<>();List<Entry> list(){return rows;}}
final class AndroidConnectionProfileStore {
 static class ExternalSelection{Object entry=new Object(),ordinaryEntry=null;String entryMode="wg",execution="local";boolean direct(){return false;}}
 static ExternalSelection selected;
 AndroidConnectionProfileStore(Object c,Object n,Object e){}ExternalSelection currentExternalPath(String id){return selected;}
 static void validateExternalGraph(AndroidStandardExitStore.Entry e,Object n,Object o,String m,String x){if(n==null?!e.direct:!e.via)throw new IllegalStateException();}
}
final class AndroidHomeStateStore{static class Snapshot{String logicalMode="node-chain",activeEntryId="",activeExternalId="";}static Snapshot home=new Snapshot();static Snapshot snapshot(Object a){return home;}}
final class Receipt{boolean current=true;String id="external";double medianMs=9.8;void requireCurrent(){if(!current)throw new IllegalStateException();}}
final class Label extends View{String text="";void setText(String s){text=s;}String getText(){return text;}}
final class Connection{boolean connected=true;boolean isConnected(){return connected;}}
'''
TEST='''package com.eabusham.routervpn;import java.util.*;import android.view.View;import android.widget.LinearLayout.LayoutParams;
public class RowTest{
 static int n; static void ok(boolean c,String m){n++;if(!c)throw new AssertionError(m);}
 final AndroidNodeStore nodeStore=new AndroidNodeStore();final AndroidStandardExitStore exitStore=new AndroidStandardExitStore();boolean external;
 final Label hopsButton=new Label(),multihopTotal=new Label(),multihopHint=new Label(),liveRouteDetails=new Label();final Connection connection=new Connection();Receipt currentPathReceipt,currentExternalReceipt;
 static final String SELECTED_ID="selected_id";boolean isExternalSelected(){return external;}RowTest prefs(){return this;}String getString(String k,String d){return d;}
 // PRODUCTION
 public static void main(String[] args)throws Exception{
 var row=new AndroidControlRow(null);View kill=new View(48),connect=new View(80),forward=new View(66);
 row.addView(kill,new LayoutParams(-2,0));row.addView(connect,new LayoutParams(0,1));row.addView(forward,new LayoutParams(-2,0));
 row.measure(View.MeasureSpec.EXACTLY|250,0);ok(row.getOrientation()==0&&connect.params.width==0&&connect.params.weight==1,"wide actions lost weighted Connect");
 row.measure(View.MeasureSpec.EXACTLY|170,0);ok(row.getOrientation()==1&&connect.params.width==-1&&connect.params.weight==0,"narrow actions clipped");
 row.measure(View.MeasureSpec.EXACTLY|250,0);ok(row.getOrientation()==0&&connect.params.weight==1,"wide window did not recover after resize");
 connect.width=155;row.measure(View.MeasureSpec.EXACTLY|250,0);ok(row.getOrientation()==1,"large font had no effect on layout");forward.setVisibility(View.GONE);row.measure(View.MeasureSpec.EXACTLY|250,0);ok(row.getOrientation()==0,"hidden action consumed width");
 var h=new RowTest();var r=new AndroidUnifiedNodeCatalog.Item(true,"node");var e=new AndroidUnifiedNodeCatalog.Item(false,"external");
 ok(!h.hasFastestComparison(List.of(r,e)),"unlike metrics formed a Fastest cohort");ok(h.hasFastestComparison(List.of(r,r)),"two Router endpoints did not enable Fastest");ok(!h.hasFastestComparison(List.of(r,new AndroidUnifiedNodeCatalog.Item(true,""))),"unusable Router endpoint counted");
 h.exitStore.rows.add(new AndroidStandardExitStore.Entry(true,false));h.exitStore.rows.add(new AndroidStandardExitStore.Entry(false,true));h.external=true;AndroidConnectionProfileStore.selected=new AndroidConnectionProfileStore.ExternalSelection();
 ok(!h.hasFastestComparison(List.of(e,e)),"unlike entry contexts formed a cohort");h.exitStore.rows.add(new AndroidStandardExitStore.Entry(false,true));ok(h.hasFastestComparison(List.of(e,e,e)),"two exits in a shared saved entry context did not enable Fastest");
 h.currentPathReceipt=new Receipt();h.multihopHint.text="A → B";h.refreshLiveRoute();ok(h.multihopTotal.text.contains("9.8 ms HTTP")&&h.liveRouteDetails.text.startsWith("A → B"),"final response missing on multihop screen");
 h.currentPathReceipt.current=false;h.refreshLiveRoute();ok(h.multihopTotal.text.contains("unavailable"),"stale final response retained");
 AndroidHomeStateStore.home.logicalMode="external";AndroidHomeStateStore.home.activeEntryId="entry";AndroidHomeStateStore.home.activeExternalId="external";h.currentExternalReceipt=new Receipt();h.refreshLiveRoute();ok(h.multihopTotal.text.contains("9.8 ms HTTPS"),"external routed response lost its source label");
 AndroidHomeStateStore.home.activeExternalId="changed";h.refreshLiveRoute();ok(h.multihopTotal.text.contains("unavailable"),"replacement external owner borrowed total");h.connection.connected=false;h.refreshLiveRoute();ok(h.multihopTotal.visibility==View.GONE,"disconnected path retained latency");
 System.out.println("Android adaptive controls and live route: "+n+" behavior checks passed");
 }
}'''
def main():
    prod=(JAVA/'ProductActivity.java').read_text()
    methods='\n'.join(method(prod,marker) for marker in ('    private boolean hasFastestComparison(', '    private void refreshLiveRoute('))
    sources={'android/view/View.java':VIEW,'android/widget/LinearLayout.java':LAYOUT,'android/view/Gravity.java':'package android.view;public class Gravity{public static final int CENTER_VERTICAL=16;}','android/content/Context.java':'package android.content;public class Context{}',
        'Boundaries.java':BOUND,'RowTest.java':TEST.replace('// PRODUCTION',methods),'AndroidControlRow.java':(JAVA/'AndroidControlRow.java').read_text()}
    with tempfile.TemporaryDirectory() as work:
        temp=Path(work)
        for name,text in sources.items():
            f=temp/name;f.parent.mkdir(parents=True,exist_ok=True);f.write_text(text)
        subprocess.run(['javac','--release','17','-d',work,*map(str,temp.rglob('*.java'))],check=True)
        subprocess.run(['java','-cp',work,'com.eabusham.routervpn.RowTest'],check=True)
if __name__=='__main__':main()
