#!/usr/bin/env python3
"""Execute ProductActivity's choice handlers at Android's dialog API boundary.

The selected shipping Java methods are compiled unchanged. The Android widget
double models AOSP AlertController.setupContent: setMessage suppresses setItems.
Storage, telemetry and VPN handles are bounded doubles; this is not device UI QA.
Each former broken builder is restored independently as a negative control.
"""
from pathlib import Path
import importlib.util
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
SOURCE = (JAVA / "ProductActivity.java").read_text()
spec = importlib.util.spec_from_file_location("product_dialog_widgets", ROOT / "android/test_android_tor_form.py")
W = importlib.util.module_from_spec(spec)
spec.loader.exec_module(W)

SIGNATURES = (
    "void showFastConnectMenu(", "void showPerformance(", "void showNodes(",
    "void showProfileManager(",
    "void chooseMultihopExecution(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit,String mode,String entryMode)",
    "void configureMultihop(", "void showViaEntryExitPicker(",
)


def method(signature):
    start = SOURCE.index("    private " + signature)
    end = SOURCE.index("\n    private ", start + 10)
    return SOURCE[start:end]


BOUNDARIES = r'''package com.eabusham.routervpn;
import java.util.*;
final class MemoryPreferences implements android.content.SharedPreferences {
 final Map<String,Object> values=new LinkedHashMap<>();int writes;
 public String getString(String key,String fallback){return (String)values.getOrDefault(key,fallback);}
 public Editor edit(){return new Editor(){final Map<String,Object> next=new LinkedHashMap<>();
  public Editor putString(String key,String value){next.put(key,value);return this;}
  public Editor putBoolean(String key,boolean value){next.put(key,value);return this;}
  public void apply(){writes++;values.putAll(next);}
 };}
}
final class AndroidNodeStore {
 static final class Node {final String id,name;Node(String id){this.id=id;name="Node "+id;}}
 final List<Node> nodes=new ArrayList<>(Arrays.asList(new Node("a"),new Node("b"),new Node("c")));
 String selected="a";int selections;
 List<Node> list(){return nodes;}String activeId(){return selected;}
 void select(String id){selected=id;selections++;}
}
final class AndroidUnifiedNodeCatalog {
 static final String SORT_CURRENT="current";
 static final class Item {
  final String id,name;final boolean router;Item(String id,boolean router){this.id=id;this.name="Catalog "+id;this.router=router;}
  boolean isRouterVpn(){return router;}boolean hasCoordinates(){return router;}
 }
 final List<Item> items=new ArrayList<>(Arrays.asList(new Item("a",true),new Item("external",false)));
 List<Item> list(String order){return items;}
}
final class AndroidTelemetry {
 static final class Result {
  final String id,name;final double medianMs;final int samples=50,failed=0;final String proof="routed proof";
  Result(String id,double ms){this.id=id;name="Measured "+id;medianMs=ms;}
  String shortLabel(){return medianMs+" ms";}String detail(){return "detail "+id;}
 }
 interface One{void result(Result value,Throwable error);}interface Many{void result(List<Result> values,Throwable error);}
 final List<Result> results=Arrays.asList(new Result("b",3),new Result("a",8),new Result("c",12));
 int allSamples,nodeSamples,currentSamples,speedBytes;String measuredNode="";
 double cachedMedian(String id){return id.equals("a")?7:0;}
 void measureAll(int count,Many callback){allSamples=count;callback.result(results,null);}
 void measureNode(AndroidNodeStore.Node node,int count,One callback){measuredNode=node.id;nodeSamples=count;callback.result(results.get(0),null);}
 void currentPath(int count,One callback){currentSamples=count;callback.result(results.get(0),null);}
 void speedTest(int bytes,One callback){speedBytes=bytes;callback.result(results.get(0),null);}
}
final class Connection {boolean connected=true;boolean isConnected(){return connected;}}
'''

HARNESS_PREFIX = r'''package com.eabusham.routervpn;
import android.app.AlertDialog;import android.content.SharedPreferences;import android.graphics.Color;import android.graphics.Typeface;
import android.widget.*;import org.json.JSONObject;import java.util.*;
public final class ProductDialogHarness extends android.app.Activity {
 static final String SELECTED_KIND="selected_kind",SELECTED_ID="selected_id",MULTI_ON="multihop_on",MULTI_ENTRY="multihop_entry",MULTI_EXIT="multihop_exit",MULTI_MODE="multihop_mode";
 final MemoryPreferences saved=new MemoryPreferences();final AndroidNodeStore nodeStore=new AndroidNodeStore();
 final AndroidUnifiedNodeCatalog catalog=new AndroidUnifiedNodeCatalog();final AndroidTelemetry telemetry=new AndroidTelemetry();
 final Connection connection=new Connection();final Button fastestButton=new Button(this);final CheckBox multihopToggle=new CheckBox(this);
 boolean busy;String selected="",profile="",pair="",entry="",exit="",message="",infoTitle="",info="";int routed,refreshes;
 SharedPreferences prefs(){return saved;}boolean mutationBusy(){return busy;}void toast(String text){message=text;}
 void refreshNodes(){}void refreshAll(){refreshes++;}void refreshMap(){}void dialog(String title,String text){infoTitle=title;info=text;}
 void showPairDialog(){pair="router";}void openStandardExits(){pair="external";}
 boolean openSelectedExternal(boolean selectPath){return false;}
 void selectCatalog(AndroidUnifiedNodeCatalog.Item item){selected=item.id;}
 void showProfileActions(AndroidNodeStore.Node node){profile=node.id;}
 AndroidNodeStore.Node nodeById(String id){for(AndroidNodeStore.Node n:nodeStore.nodes)if(n.id.equals(id))return n;return null;}
 JSONObject activeRouterProfile(){return new JSONObject();}void runRoutedHopSpeeds(){routed++;}
 void prepareViaEntryExitMeasurement(AndroidNodeStore.Node node,List<AndroidNodeStore.Node> nodes){entry=node.id;exit=Integer.toString(nodes.size());}
 void chooseMultihopMode(AndroidNodeStore.Node first,AndroidNodeStore.Node last){entry=first.id;exit=last.id;}
 static String safe(Throwable error){return error==null?"error":error.getMessage();}
'''

HARNESS_SUFFIX = r'''
 static int checks;
 static void check(boolean value,String label){checks++;if(!value)throw new AssertionError(label);}
 static AlertDialog shown(int count,String title){
  AlertDialog value=AlertDialog.last;check(value!=null&&value.itemsVisible(),title+" items must be reachable under AOSP message/list semantics");
  check(value.items.length==count,title+" item count");check(value.message==null,title+" must not suppress list with message");
  check(value.customTitle instanceof LinearLayout,title+" retains accessible explanatory header");
  LinearLayout header=(LinearLayout)value.customTitle;
  check(header.children.size()==2&&((TextView)header.children.get(0)).getText().toString().contains(title),title+" visible title");
  check(((TextView)header.children.get(1)).getText().length()>20,title+" explanation retained");return value;
 }
 static void fastest(){
  ProductDialogHarness h=new ProductDialogHarness();h.showFastConnectMenu();AlertDialog d=shown(4,"Select node");d.clickItem(0);
  check(h.telemetry.allSamples==3&&h.nodeStore.selected.equals("b")&&h.saved.getString(SELECTED_ID,"").equals("b"),"Fastest chooses measured first node");
  check(h.message.contains("Press Connect"),"Fastest selects without connecting");
  h=new ProductDialogHarness();h.showFastConnectMenu();d=shown(4,"Select node");d.clickItem(2);check(h.nodeStore.selected.equals("a"),"specific Fastest list choice exact");
  h=new ProductDialogHarness();h.showFastConnectMenu();d=shown(4,"Select node");h.busy=true;d.clickItem(0);check(h.nodeStore.selections==0&&h.saved.writes==0,"late busy prevents Fastest mutation");
  h=new ProductDialogHarness();h.busy=true;h.showFastConnectMenu();check(h.telemetry.allSamples==0,"initial busy avoids measurement");
 }
 static void performance(){
  for(int action=0;action<6;action++){
   ProductDialogHarness h=new ProductDialogHarness();h.showPerformance();AlertDialog d=shown(6,"Performance");d.clickItem(action);
   switch(action){case 0:check(h.telemetry.currentSamples==5,"current path actual callback");break;
    case 1:check(h.telemetry.nodeSamples==50&&h.telemetry.measuredNode.equals("a"),"durable 50-sample selected node");break;
    case 2:check(h.telemetry.allSamples==5,"all-node callback");break;
    case 3:check(h.telemetry.speedBytes==8<<20,"real transfer requested8MiB");break;
    case 4:check(h.routed==1,"native routed hop speed action");break;
    default:check(h.infoTitle.equals("Path throughput / Auto MTU")&&h.info.contains("No proven"),"unmeasured MTU is truthful");
   }
  }
  for(int action:new int[]{0,3}){ProductDialogHarness h=new ProductDialogHarness();h.connection.connected=false;h.showPerformance();shown(6,"Performance").clickItem(action);check(h.telemetry.currentSamples==0&&h.telemetry.speedBytes==0,"disconnected path speed cannot run");}
 }
 static void nodes(){
  ProductDialogHarness h=new ProductDialogHarness();h.showNodes();AlertDialog d=shown(2,"Choose node");check(d.items[1].contains("list only"),"no invented external coordinates");d.clickItem(1);check(h.selected.equals("external"),"exact external node callback");
  h=new ProductDialogHarness();h.catalog.items.clear();h.showNodes();check(AlertDialog.last.items==null&&AlertDialog.last.message!=null,"empty node informational dialog retained");
 }
 static void profiles(){ProductDialogHarness h=new ProductDialogHarness();h.showProfileManager();shown(3,"Router profiles").clickItem(2);check(h.profile.equals("c"),"exact stored router profile callback");}
 static void execution(){
  String[] policies={"local","server","auto"};
  for(int i=0;i<3;i++){
   ProductDialogHarness h=new ProductDialogHarness();h.chooseMultihopExecution(h.nodeById("a"),h.nodeById("b"),"hysteria2","max-quic-awg");shown(3,"Multihop execution").clickItem(i);
   check(h.saved.writes==1&&h.saved.getString("multihop_execution","").equals(policies[i]),"exact saved execution preference");
   check(h.saved.getString(MULTI_ENTRY,"").equals("a")&&h.saved.getString(MULTI_EXIT,"").equals("b")&&h.saved.getString(MULTI_MODE,"").equals("hysteria2")&&h.saved.getString("multihop_entry_mode","").equals("max-quic-awg"),"frozen entry/exit/mode choices preserved");
   check(h.multihopToggle.isChecked()&&Boolean.TRUE.equals(h.saved.values.get(MULTI_ON)),"multihop enabled only by actual choice");
  }
  ProductDialogHarness h=new ProductDialogHarness();h.chooseMultihopExecution(h.nodeById("a"),h.nodeById("b"),"wg","wg");h.busy=true;shown(3,"Multihop execution").clickItem(2);check(h.saved.writes==0&&!h.multihopToggle.isChecked(),"late busy refuses saved multihop mutation");
 }
 static void entry(){ProductDialogHarness h=new ProductDialogHarness();h.configureMultihop();shown(3,"Multihop entry").clickItem(2);check(h.entry.equals("c")&&h.exit.equals("3"),"chosen entry and complete candidate list passed to measurement");h=new ProductDialogHarness();h.busy=true;h.configureMultihop();check(h.entry.isEmpty(),"busy multihop setup cannot create temporary tunnel");}
 static void exits(){
  ProductDialogHarness h=new ProductDialogHarness();List<AndroidNodeStore.Node> exits=Arrays.asList(h.nodeById("b"),h.nodeById("c"));
  h.showViaEntryExitPicker(h.nodeById("a"),exits,Collections.singletonList(new AndroidTelemetry.Result("b",4.2)),null);
  AlertDialog d=shown(2,"Multihop hop 2");check(d.items[0].contains("4.2 ms")&&d.items[1].contains("unavailable"),"only measured via-entry result gets RTT");d.clickItem(1);check(h.entry.equals("a")&&h.exit.equals("c"),"exact second-hop callback");
  h.showViaEntryExitPicker(h.nodeById("a"),exits,null,new IllegalStateException("no route proof"));d=shown(2,"Multihop hop 2");check(d.items[0].contains("unavailable")&&((TextView)((LinearLayout)d.customTitle).children.get(1)).getText().toString().contains("no route proof"),"failed proof remains visible without invented latency");
 }
 public static void main(String[] args){
  if(args.length>0){switch(args[0]){case "0":fastest();break;case "1":performance();break;case "2":nodes();break;case "3":profiles();break;case "4":execution();break;case "5":entry();break;case "6":exits();break;default:throw new AssertionError("unknown negative");}return;}
  AlertDialog broken=new AlertDialog.Builder(new ProductDialogHarness()).setMessage("suppresses list").setItems(new String[]{"unreachable"},(d,i)->{throw new AssertionError("hidden callback ran");}).show();
  check(!broken.itemsVisible(),"AOSP precedence double must reject original form");
  try{broken.clickItem(0);throw new AssertionError("hidden item clickable");}catch(IllegalStateException expected){checks++;}
  fastest();performance();nodes();profiles();execution();entry();exits();
  System.out.println("Android shipping ProductActivity dialog actions: PASS "+checks+" checks (AOSP dialog boundary; OS/network handles doubled)");
 }
}
'''


def main():
    handlers = [method(signature) for signature in SIGNATURES]
    for signature, handler in zip(SIGNATURES, handlers):
        assert handler.count("choiceDialog(") == 1, signature
    support = method("AlertDialog.Builder choiceDialog(") + method("TextView text(") + method("int dp(")
    with tempfile.TemporaryDirectory(prefix="routervpn-product-dialog-") as work:
        tmp = Path(work)
        sources = dict(W.UI)
        sources["android/app/AlertDialog.java"] = sources["android/app/AlertDialog.java"].replace(
            "public Builder setNegativeButton(",
            "public Builder setNeutralButton(CharSequence text,OnClickListener listener){return button(-3,text,listener);}\n  public Builder setNegativeButton(")
        sources["android/graphics/Color.java"] = "package android.graphics;public final class Color {public static final int WHITE=-1;}"
        sources["android/content/SharedPreferences.java"] = """package android.content;
public interface SharedPreferences {String getString(String key,String fallback);default Editor edit(){throw new UnsupportedOperationException();}
interface Editor{Editor putString(String key,String value);Editor putBoolean(String key,boolean value);void apply();}}"""
        sources["com/eabusham/routervpn/ProductBoundaries.java"] = BOUNDARIES
        for name, text in sources.items():
            path = tmp / name;path.parent.mkdir(parents=True, exist_ok=True);path.write_text(text)
        target = tmp / "com/eabusham/routervpn/ProductDialogHarness.java"
        def compile_run(parts, negative=None):
            target.write_text(HARNESS_PREFIX + "\n".join(parts) + support + HARNESS_SUFFIX)
            build = subprocess.run(["javac", "--release", "17", "-cp", "/usr/share/java/com.android.json.jar", "-d", str(tmp), *map(str, tmp.rglob("*.java"))], text=True, capture_output=True, timeout=30)
            assert build.returncode == 0, build.stderr
            run = subprocess.run(["java", "-cp", str(tmp)+":/usr/share/java/com.android.json.jar", "com.eabusham.routervpn.ProductDialogHarness", *([] if negative is None else [str(negative)])], text=True, capture_output=True, timeout=15)
            if negative is None:
                assert run.returncode == 0, run.stdout+run.stderr
                print(run.stdout.strip())
            else:
                assert run.returncode != 0 and "items must be reachable" in run.stderr, f"negative {negative} survived or failed for unrelated reason: {run.stdout}{run.stderr}"
        compile_run(handlers)
        # An exact old builder on any affected surface must fail its actual action test.
        for index in range(len(handlers)):
            changed = handlers.copy()
            changed[index] = changed[index].replace("choiceDialog(", "brokenChoiceDialog(", 1)
            changed.append("private AlertDialog.Builder brokenChoiceDialog(String title,String note){return new AlertDialog.Builder(this).setTitle(title).setMessage(note);}")
            compile_run(changed, index)
    print("Android product dialogs: all seven original-builder negative controls rejected")


if __name__ == "__main__":
    main()
