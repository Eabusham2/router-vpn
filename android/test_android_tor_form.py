#!/usr/bin/env python3
"""Execute the shipping Tor Activity, editor and private store with real Go policy.

Android widgets, permission delivery and runtime starts are bounded doubles.
The dialog boundary follows AOSP AlertController.setupContent: a non-null
message suppresses the item list. A deliberate negative control checks that
behavior before exercising the real Activity callbacks. This is a JVM/API
boundary regression, not an Android SDK or device rendering test.
"""
from pathlib import Path
import importlib.util
import os
import re
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"
spec = importlib.util.spec_from_file_location("tor_form_profile", ROOT / "android/test_android_tor_profile.py")
T = importlib.util.module_from_spec(spec)
spec.loader.exec_module(T)

UI = {
"android/content/Context.java": r'''package android.content;
public class Context {public static final String CONNECTIVITY_SERVICE="connectivity";public Object getSystemService(String name){return null;}
 public static java.io.File nextFiles; private final java.io.File files;
 public Context(){this(nextFiles);}public Context(java.io.File f){files=f;}
 public Context getApplicationContext(){return this;}public java.io.File getFilesDir(){return files;}
 public static final int MODE_PRIVATE=0;
 public Object startService(Intent i){throw new AssertionError("Activity must use the captured runtime");}
 public Object startForegroundService(Intent i){throw new AssertionError("Activity must use the captured runtime");}
 public SharedPreferences getSharedPreferences(String name,int mode){return (key,fallback)->fallback;}
 public android.content.res.Resources getResources(){return new android.content.res.Resources();}
}''',
"android/content/Intent.java": r'''package android.content;public class Intent {
 public final java.util.Map<String,Object> extras=new java.util.LinkedHashMap<>();
 public Intent(){}public Intent(String action){}public Intent(Context context,Class<?> type){}
 public Intent setAction(String value){return this;}public Intent putExtra(String key,String value){extras.put(key,value);return this;}
 public Intent putExtra(String key,long value){extras.put(key,value);return this;}public String getStringExtra(String key){return (String)extras.get(key);}
}''',
"android/content/DialogInterface.java": r'''package android.content;public interface DialogInterface {
 void dismiss();interface OnClickListener{void onClick(DialogInterface dialog,int which);}
 interface OnShowListener{void onShow(DialogInterface dialog);}interface OnDismissListener{void onDismiss(DialogInterface dialog);}
}''',
"android/content/res/Resources.java": "package android.content.res;public final class Resources {public android.util.DisplayMetrics getDisplayMetrics(){return new android.util.DisplayMetrics();}}",
"android/util/DisplayMetrics.java": "package android.util;public final class DisplayMetrics {public float density=1;}",
"android/os/Bundle.java": r'''package android.os;public final class Bundle {
 public final java.util.Map<String,Object> values=new java.util.LinkedHashMap<>();
 public void putString(String key,String value){values.put(key,value);}public void putBoolean(String key,boolean value){values.put(key,value);}
 public String getString(String key,String fallback){Object value=values.get(key);return value instanceof String?(String)value:fallback;}
 public boolean getBoolean(String key,boolean fallback){Object value=values.get(key);return value instanceof Boolean?(Boolean)value:fallback;}
}''',
"android/app/Activity.java": r'''package android.app;public class Activity extends android.content.Context {
 public static final int RESULT_OK=-1;public android.view.View content;public android.content.Intent permission;public int permissionRequest;
 protected void onCreate(android.os.Bundle state){}protected void onResume(){}protected void onDestroy(){}
 protected void onSaveInstanceState(android.os.Bundle state){}protected void onActivityResult(int request,int result,android.content.Intent data){}
 public void setContentView(android.view.View view){content=view;}public boolean isFinishing(){return false;}
 public void runOnUiThread(Runnable action){action.run();}public android.content.Intent getIntent(){return new android.content.Intent();}
 public void startActivity(android.content.Intent intent){}public void startActivityForResult(android.content.Intent intent,int request){permission=intent;permissionRequest=request;}
}''',
"android/net/VpnService.java": "package android.net;public final class VpnService {public static boolean needsPermission=true;public static android.content.Intent prepare(android.content.Context c){return needsPermission?new android.content.Intent():null;}}",
"android/view/View.java": r'''package android.view;public class View {
 public static final int IMPORTANT_FOR_AUTOFILL_NO=2;public final android.content.Context context;
 private boolean enabled=true,saved=true;private int autofill;private OnClickListener listener;
 public View(android.content.Context c){context=c;}public interface OnClickListener{void onClick(View view);}
 public void setEnabled(boolean value){enabled=value;}public boolean isEnabled(){return enabled;}
 public void setSaveEnabled(boolean value){saved=value;}public boolean isSaveEnabled(){return saved;}
 public void setImportantForAutofill(int value){autofill=value;}public int getImportantForAutofill(){return autofill;}
 public void setOnClickListener(OnClickListener value){listener=value;}public boolean performClick(){if(!enabled||listener==null)return false;listener.onClick(this);return true;}
 public void setPadding(int a,int b,int c,int d){}
}''',
"android/text/Editable.java": r'''package android.text;public final class Editable implements CharSequence {
 private final String value;public Editable(CharSequence text){value=text==null?"":text.toString();}
 public int length(){return value.length();}public char charAt(int index){return value.charAt(index);}
 public CharSequence subSequence(int start,int end){return value.subSequence(start,end);}public String toString(){return value;}
}''',
"android/text/InputType.java": "package android.text;public final class InputType {public static final int TYPE_CLASS_TEXT=1,TYPE_CLASS_NUMBER=2,TYPE_TEXT_VARIATION_PASSWORD=128,TYPE_TEXT_FLAG_MULTI_LINE=131072,TYPE_TEXT_FLAG_NO_SUGGESTIONS=524288;}",
"android/text/TextUtils.java": "package android.text;public final class TextUtils {public static String join(CharSequence delimiter,Iterable<?> values){java.util.List<String> strings=new java.util.ArrayList<>();for(Object value:values)strings.add(String.valueOf(value));return String.join(delimiter,strings);}}",
"android/graphics/Typeface.java": "package android.graphics;public class Typeface {public static final int BOLD=1;}",
"android/widget/TextView.java": r'''package android.widget;public class TextView extends android.view.View {
 protected CharSequence value="",hint="";public TextView(android.content.Context c){super(c);}
 public void setText(CharSequence text){value=text==null?"":text;}public CharSequence getText(){return value;}
 public void setHint(CharSequence text){hint=text;}public CharSequence getHint(){return hint;}
 public void setTextSize(float size){}public void setTextColor(int color){}public android.graphics.Typeface getTypeface(){return new android.graphics.Typeface();}
 public void setTypeface(android.graphics.Typeface face,int style){}
}''',
"android/widget/EditText.java": r'''package android.widget;public class EditText extends TextView {
 private int inputType;public EditText(android.content.Context c){super(c);}public android.text.Editable getText(){return new android.text.Editable(value);}
 public void setSingleLine(boolean value){}public void setMinLines(int value){}public void setMaxLines(int value){}
 public void setInputType(int type){inputType=type;}public int getInputType(){return inputType;}
}''',
"android/widget/Button.java": "package android.widget;public class Button extends TextView {public Button(android.content.Context c){super(c);}public void setAllCaps(boolean value){}}",
"android/widget/CheckBox.java": "package android.widget;public final class CheckBox extends Button {private boolean checked;public CheckBox(android.content.Context c){super(c);}public void setChecked(boolean value){checked=value;}public boolean isChecked(){return checked;}}",
"android/widget/LinearLayout.java": r'''package android.widget;public class LinearLayout extends android.view.View {
 public static final int VERTICAL=1;public final java.util.List<android.view.View> children=new java.util.ArrayList<>();
 public LinearLayout(android.content.Context c){super(c);}public void setOrientation(int value){}
 public void addView(android.view.View child){children.add(child);}public void addView(android.view.View child,LayoutParams params){children.add(child);}
 public static final class LayoutParams {public static final int MATCH_PARENT=-1,WRAP_CONTENT=-2;public LayoutParams(int width,int height){}public void setMargins(int a,int b,int c,int d){}}
}''',
"android/widget/ScrollView.java": "package android.widget;public final class ScrollView extends LinearLayout {public ScrollView(android.content.Context c){super(c);}}",
"android/widget/ArrayAdapter.java": r'''package android.widget;public final class ArrayAdapter<T> {
 private final T[] values;public ArrayAdapter(android.content.Context c,int layout,T[] source){values=source.clone();}
 public void setDropDownViewResource(int id){}public int getCount(){return values.length;}public T getItem(int position){return values[position];}
}''',
"android/widget/AdapterView.java": r'''package android.widget;public class AdapterView<T> extends android.view.View {
 public AdapterView(android.content.Context c){super(c);}public interface OnItemSelectedListener {
 void onNothingSelected(AdapterView<?> parent);void onItemSelected(AdapterView<?> parent,android.view.View view,int position,long id);}
}''',
"android/widget/Spinner.java": r'''package android.widget;public final class Spinner extends AdapterView<ArrayAdapter<?>> {
 private ArrayAdapter<?> adapter;private int position;private OnItemSelectedListener listener;
 public Spinner(android.content.Context c){super(c);}public void setAdapter(ArrayAdapter<?> value){adapter=value;}
 public ArrayAdapter<?> getAdapter(){return adapter;}public int getSelectedItemPosition(){return position;}
 public void setSelection(int value){if(value<0||adapter==null||value>=adapter.getCount())throw new AssertionError("Invalid spinner item");position=value;deliver();}
 public void setOnItemSelectedListener(OnItemSelectedListener value){listener=value;deliver();}
 private void deliver(){if(listener!=null)listener.onItemSelected(this,null,position,position);}
}''',
"android/widget/Toast.java": r'''package android.widget;public final class Toast {
 public static final int LENGTH_LONG=1;public static final java.util.List<String> messages=new java.util.ArrayList<>();private final String message;
 private Toast(CharSequence value){message=value.toString();}public static Toast makeText(android.content.Context c,CharSequence text,int duration){return new Toast(text);}
 public void show(){messages.add(message);}
}''',
"android/provider/Settings.java": "package android.provider;public final class Settings {public static final String ACTION_VPN_SETTINGS=\"android.settings.VPN_SETTINGS\";}",
"android/R.java": "package android;public final class R {public static final class layout {public static final int simple_spinner_item=1,simple_spinner_dropdown_item=2;}}",
"android/app/AlertDialog.java": r'''package android.app;
import android.content.*;import android.view.View;import android.widget.Button;
public final class AlertDialog implements DialogInterface {
 public static final int BUTTON_POSITIVE=-1,BUTTON_NEGATIVE=-2;public static AlertDialog last;
 public CharSequence title,message;public View view,customTitle;public String[] items;public boolean showing;
 private final Context context;private OnClickListener itemClick;private OnShowListener onShow;private OnDismissListener onDismiss;
 private final java.util.Map<Integer,Button> buttons=new java.util.HashMap<>();
 private AlertDialog(Context c){context=c;}public void setOnShowListener(OnShowListener value){onShow=value;}
 public void setOnDismissListener(OnDismissListener value){onDismiss=value;}public Button getButton(int id){return buttons.get(id);}
 public void show(){last=this;showing=true;if(onShow!=null)onShow.onShow(this);}
 public void dismiss(){if(!showing)return;showing=false;if(onDismiss!=null)onDismiss.onDismiss(this);}
 // AOSP AlertController.setupContent attaches the list only in the no-message branch.
 public boolean itemsVisible(){return showing&&message==null&&items!=null;}
 public void clickItem(int index){if(!itemsVisible())throw new IllegalStateException("Android message suppresses the item list");itemClick.onClick(this,index);dismiss();}
 public static final class Builder {
  private final AlertDialog dialog;public Builder(Context c){dialog=new AlertDialog(c);}
  public Builder setTitle(CharSequence value){dialog.title=value;return this;}public Builder setMessage(CharSequence value){dialog.message=value;return this;}
  public Builder setCustomTitle(View value){dialog.customTitle=value;return this;}public Builder setView(View value){dialog.view=value;return this;}
  public Builder setItems(String[] values,OnClickListener listener){dialog.items=values.clone();dialog.itemClick=listener;return this;}
  private Builder button(int which,CharSequence label,OnClickListener listener){Button button=new Button(dialog.context);button.setText(label);if(listener!=null)button.setOnClickListener(v->{listener.onClick(dialog,which);dialog.dismiss();});else if(which==BUTTON_NEGATIVE)button.setOnClickListener(v->dialog.dismiss());dialog.buttons.put(which,button);return this;}
  public Builder setPositiveButton(CharSequence text,OnClickListener listener){return button(BUTTON_POSITIVE,text,listener);}
  public Builder setNegativeButton(CharSequence text,OnClickListener listener){return button(BUTTON_NEGATIVE,text,listener);}
  public AlertDialog create(){return dialog;}public AlertDialog show(){dialog.show();return dialog;}
 }
}''',
}

APP = r'''
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(android.content.Context c){return busy;}}
final class AndroidHomeStateStore {
 static final class Snapshot{boolean connected;String sessionId="form-session",phase="idle",logicalMode="",activeExternalName="",activeExternalProtocol="";}
 static boolean emergencyDisconnectPending(android.content.Context c){return false;}static Snapshot snapshot(android.content.Context c){return new Snapshot();}static String actualExitForCurrentSession(android.content.Context c){return "";}
}
final class AndroidStandardExitRuntime {
 interface Callback{void progress(String value);void finished(boolean success,String value);}
 int starts;String mode="";java.io.File entry;AndroidStandardExitStore.Entry exit;
 void connectDirect(AndroidStandardExitStore.Entry value,Callback cb){starts++;exit=value;mode="external";}
 void connect(java.io.File file,AndroidStandardExitStore.Entry value,String selected,Callback cb){starts++;entry=file;exit=value;mode=selected;}
 void disconnect(){}
}
final class AndroidRuntimeRegistry {
 static final class Engine{String getState(){return "STOPPED";}boolean isRunning(){return false;}boolean isActiveOrTransitioning(){return false;}}
 static final java.util.Map<String,AndroidRuntimeRegistry> instances=new java.util.HashMap<>();
 final Engine orchestrator=new Engine(),multihop=new Engine(),xray=new Engine();
 final NativeSingBoxController singBox;final AndroidStandardExitRuntime standardExit=new AndroidStandardExitRuntime();
 AndroidRuntimeRegistry(android.content.Context context){singBox=new NativeSingBoxController(context);}
 static AndroidRuntimeRegistry get(android.content.Context context){return instances.computeIfAbsent(context.getFilesDir().toString(),key->new AndroidRuntimeRegistry(context));}
}
final class AndroidOpenVPN {static JSONObject endpoint(AndroidStandardExitStore.Entry e,String value){throw new AssertionError("Tor editor called OpenVPN");}}
'''

HARNESS = r'''package com.eabusham.routervpn;
import android.app.*;import android.content.*;import android.os.*;import android.view.*;import android.widget.*;
import java.nio.file.*;import java.nio.charset.StandardCharsets;import java.lang.reflect.*;import java.util.*;import org.json.*;
public final class TorFormHarness {
 static int checks,roundtrips;static Path root;
 static void check(boolean value,String message){if(!value)throw new AssertionError(message);checks++;}
 static Object get(Object owner,String name)throws Exception{Field field=owner.getClass().getDeclaredField(name);field.setAccessible(true);return field.get(owner);}
 static Object invoke(Object owner,String name,Object... values)throws Exception{
  for(Method method:owner.getClass().getDeclaredMethods())if(method.getName().equals(name)&&method.getParameterCount()==values.length){method.setAccessible(true);try{return method.invoke(owner,values);}catch(InvocationTargetException error){Throwable cause=error.getCause();if(cause instanceof Exception)throw (Exception)cause;throw (Error)cause;}}
  throw new AssertionError("Missing shipping Activity method: "+name);
 }
 static List<View> views(View root){List<View> result=new ArrayList<>();if(root==null)return result;result.add(root);if(root instanceof LinearLayout)for(View child:((LinearLayout)root).children)result.addAll(views(child));return result;}
 static EditText field(AlertDialog dialog,String hint){for(View view:views(dialog.view))if(view instanceof EditText&&hint.equals(((EditText)view).getHint().toString()))return (EditText)view;throw new AssertionError("Missing form field: "+hint);}
 static Spinner spinner(AlertDialog dialog,String first){for(View view:views(dialog.view))if(view instanceof Spinner&&first.equals(((Spinner)view).getAdapter().getItem(0)))return (Spinner)view;throw new AssertionError("Missing choice: "+first);}
 static CheckBox lan(AlertDialog dialog){for(View view:views(dialog.view))if(view instanceof CheckBox)return (CheckBox)view;throw new AssertionError("Missing LAN policy");}
 static String displayed(View root){StringBuilder result=new StringBuilder();for(View view:views(root))if(view instanceof TextView)result.append(((TextView)view).getText()).append('\n');return result.toString();}
 static StandardExitActivity activity(Path directory,Bundle state)throws Exception{Context.nextFiles=directory.toFile();Files.createDirectories(directory);StandardExitActivity result=new StandardExitActivity();result.onCreate(state);return result;}
 static AndroidStandardExitStore store(StandardExitActivity activity)throws Exception{return (AndroidStandardExitStore)get(activity,"exitStore");}
 static String compiled(AndroidStandardExitStore.Entry entry)throws Exception{return io.nekohasekai.libbox.Libbox.routerCompileTorProfile(AndroidTorProfile.profile(entry).toString(),"form-roundtrip","");}
 static boolean same(String a,String b)throws Exception{return io.nekohasekai.libbox.Libbox.testSameJSON(a,b);}
 static AlertDialog form(StandardExitActivity activity,AndroidStandardExitStore.Entry entry)throws Exception{invoke(activity,"showTorForm",entry==null?"tor":entry.protocol,entry);return AlertDialog.last;}
 static JSONObject policy(String mode,String protocol)throws Exception{
  JSONObject result=new JSONObject().put("dns_mode",mode).put("dns_protocol",protocol).put("dns_host","149.112.112.112")
   .put("dns_port",8443).put("dns_server_name","dns.example.test").put("dns_path","/selected-query")
   .put("ipv6_mode","on").put("home_lan_access",false).put("home_lan_cidrs",new JSONArray().put("192.168.50.0/24").put("fd12:3456::/48"))
   .put("mtu_policy","fixed").put("manual_mtu",1360);return result;
 }
 static void roundtrips()throws Exception{
  List<JSONObject> policies=new ArrayList<>();policies.add(new JSONObject());policies.add(policy("rescue","tcp"));policies.add(policy("","dot"));
  policies.add(policy("dot","tcp"));policies.add(policy("doh","tcp"));
  for(String protocol:new String[]{"tcp","dot","tls","doh","https"})policies.add(policy("custom",protocol));
  for(String ipv6:new String[]{"","off","auto","on"})for(boolean allow:new boolean[]{true,false})policies.add(policy("custom","doh").put("ipv6_mode",ipv6).put("home_lan_access",allow));
  policies.add(policy("custom","tcp").put("mtu_policy","auto").put("manual_mtu",8192));
  for(String kind:KINDS)for(JSONObject policy:policies){
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"roundtrip-"),null);AndroidStandardExitStore.Entry selected=tor(kind,"doh");selected.torPolicy=new JSONObject(policy.toString());
   store(activity).save(selected);selected=store(activity).get(selected.id);String before=AndroidStandardExitStore.snapshot(selected),graph=compiled(selected);
   JSONObject editor=AndroidTorProfile.editorPolicy(selected);editor.put("dns_host","192.0.2.199");
   check(before.equals(AndroidStandardExitStore.snapshot(selected)),"editor policy aliases the saved entry");
   AlertDialog dialog=form(activity,selected);check(dialog.showing,"saved valid policy did not open");
   EditText bridge=null;if(!kind.equals("tor")){bridge=field(dialog,"Paste bridge lines, one per line");check(!bridge.isSaveEnabled()&&bridge.getImportantForAutofill()==View.IMPORTANT_FOR_AUTOFILL_NO,"bridge credentials entered Android saved/autofill state");check(bridge.getText().toString().equals(String.join("\n",selected.torBridges)),"bridge order/credentials changed on edit");}
   field(dialog,"Display name").setText("Renamed private Tor node");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(!dialog.showing,"valid name-only edit was rejected");AndroidStandardExitStore.Entry after=store(activity).get(selected.id);
   check(after.id.equals(selected.id)&&after.protocol.equals(selected.protocol)&&after.name.equals("Renamed private Tor node"),"editor replaced the saved node identity");
   check(same(graph,compiled(after)),"name-only edit changed effective DNS/IPv6/LAN/MTU/bridge policy: "+kind+" "+policy);
   check(before.equals(AndroidStandardExitStore.snapshot(selected)),"saving aliased its captured source");
   if(bridge!=null)check(bridge.getText().length()==0,"dismissed form retained bridge credentials");roundtrips++;
  }
  check(roundtrips==114,"Tor editor policy matrix incomplete");
 }
 static void newFormAndRejections()throws Exception{
  StandardExitActivity activity=activity(Files.createTempDirectory(root,"create-"),null);AlertDialog dialog=form(activity,null);
  check(spinner(dialog,"Rescue DoH (Cloudflare)").getSelectedItemPosition()==0&&spinner(dialog,"IPv6 off").getSelectedItemPosition()==0&&lan(dialog).isChecked(),"new Tor defaults changed");
  EditText host=field(dialog,"Custom DNS literal IP"),port=field(dialog,"Custom DNS port (blank uses protocol default)"),name=field(dialog,"DoT / DoH certificate server name"),path=field(dialog,"DoH path (default /dns-query)");
  check(!host.isEnabled()&&!port.isEnabled()&&!name.isEnabled()&&!path.isEnabled(),"rescue editor enables ignored custom fields");
  Spinner dns=spinner(dialog,"Rescue DoH (Cloudflare)");dns.setSelection(1);check(host.isEnabled()&&port.isEnabled()&&!name.isEnabled()&&!path.isEnabled(),"TCP DNS widget dependencies wrong");
  dns.setSelection(2);check(name.isEnabled()&&!path.isEnabled(),"DoT widget dependencies wrong");dns.setSelection(3);check(path.isEnabled(),"DoH path cannot be set");
  field(dialog,"Display name").setText("New exact Tor policy");host.setText("149.112.112.112");port.setText("8443");name.setText("dns.example.test");path.setText("/private-query");
  spinner(dialog,"IPv6 off").setSelection(2);lan(dialog).setChecked(false);field(dialog,"Manual interface MTU, 1280–9000 (blank uses automatic)").setText("1500");
  dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!dialog.showing&&store(activity).list().size()==1,"new valid Tor policy was not saved");
  AndroidStandardExitStore.Entry selected=store(activity).list().get(0);JSONObject p=selected.torPolicy;
  check(p.getString("dns_protocol").equals("doh")&&p.getString("dns_host").equals("149.112.112.112")&&p.getInt("dns_port")==8443&&p.getString("dns_path").equals("/private-query"),"custom endpoint was substituted");
  check(p.getString("ipv6_mode").equals("on")&&p.getBoolean("home_lan_access")&&p.getInt("manual_mtu")==1500,"new interface policy was substituted");compiled(selected);
  String[][] invalid={{"Custom DNS literal IP","dns.example.test"},{"Custom DNS literal IP","127.0.0.1"},{"Custom DNS port (blank uses protocol default)","65536"},{"DoT / DoH certificate server name",""},{"DoH path (default /dns-query)","https://other.example.test/query"},{"Manual interface MTU, 1280–9000 (blank uses automatic)","1279"},{"Manual interface MTU, 1280–9000 (blank uses automatic)","9001"}};
  for(String[] mutation:invalid){String before=Files.readString(activity.getFilesDir().toPath().resolve("standard-exits.json"));dialog=form(activity,selected);field(dialog,mutation[0]).setText(mutation[1]);dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(dialog.showing&&before.equals(Files.readString(activity.getFilesDir().toPath().resolve("standard-exits.json"))),"invalid form changed the store: "+mutation[0]);dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();}
  selected=tor("custom","doh");store(activity).save(selected);String before=AndroidStandardExitStore.snapshot(store(activity).get(selected.id));
  for(String bridge:new String[]{OBFS+"\n".repeat(1)+String.join("\n",Collections.nCopies(8,OBFS)),OBFS+"\nClientTransportPlugin obfs4 exec /bin/sh","x".repeat(65537)}){
   dialog=form(activity,selected);EditText secret=field(dialog,"Paste bridge lines, one per line");secret.setText(bridge);dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(dialog.showing&&before.equals(AndroidStandardExitStore.snapshot(store(activity).get(selected.id))),"invalid bridge block changed the saved node");
   for(View view:views(dialog.view))if(view instanceof TextView&&!(view instanceof EditText))check(!((TextView)view).getText().toString().contains("cert=Y2VydA"),"validation exposed bridge credentials");
   dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();check(secret.getText().length()==0,"cancel retained an invalid bridge secret");
  }
  dialog=form(activity,selected);EditText secret=field(dialog,"Paste bridge lines, one per line");secret.setText("  "+OBFS+"\r\n\r\n"+MEEK+"  \r\n");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
  check(!dialog.showing&&store(activity).get(selected.id).torBridges.equals(Arrays.asList(OBFS,MEEK)),"CRLF bridge block order/normalization failed");
  dialog=form(activity,selected);AndroidVpnMutationGuard.busy=true;dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(dialog.showing,"form mutated a live VPN capture");AndroidVpnMutationGuard.busy=false;dialog.dismiss();
 }
 static AndroidNodeStore.Node node(Path directory)throws Exception{
  JSONObject bundle=MultihopGraphHarness.bundle('a');JSONObject profiles=bundle.getJSONObject("profiles");JSONArray modes=bundle.getJSONArray("modes");
  for(String mode:ALL)if(!mode.equals("wg")){profiles.put(mode,new JSONObject().put("ui-catalog-fixture",""));modes.put(new JSONObject().put("id",mode).put("name","Captured "+mode));}
  profiles.put("unknown",new JSONObject());modes.put(new JSONObject().put("id","unknown"));modes.put(new JSONObject().put("id","max"));
  Path file=directory.resolve("captured-node.json");Files.writeString(file,bundle.toString());AndroidNodeStore.Node node=new AndroidNodeStore.Node("saved-router","Captured router","192.0.2.1",file.toFile());
  AndroidNodeStore.nodes.clear();AndroidNodeStore.nodes.add(node);return node;
 }
 static void dialogAndPermission()throws Exception{
  Context context=new Context(root.toFile());AlertDialog negative=new AlertDialog.Builder(context).setMessage("Explainer").setItems(new String[]{"Hidden"},(d,w)->{throw new AssertionError("hidden item executed");}).show();
  check(!negative.itemsVisible(),"dialog double ignores Android message/list exclusivity");boolean hidden=false;try{negative.clickItem(0);}catch(IllegalStateException expected){hidden=true;}check(hidden,"hidden-list negative control cannot reject an item");negative.dismiss();
  for(String mode:ALL){
   Path directory=Files.createTempDirectory(root,"permission-");StandardExitActivity activity=activity(directory,null);AndroidNodeStore.Node node=node(directory);AndroidStandardExitStore.Entry selected=tor("custom","doh");store(activity).save(selected);
   invoke(activity,"showExitActions",selected);AlertDialog actions=AlertDialog.last;check(actions.itemsVisible()&&actions.items.length==4,"saved Tor actions are hidden");
   check(!displayed(actions.customTitle).contains("cert=Y2VydA"),"actions header exposed bridge credentials");actions.clickItem(1);
   AlertDialog entries=AlertDialog.last;check(entries.itemsVisible()&&entries.items.length==1,"entry choices are hidden");entries.clickItem(0);
   AlertDialog modes=AlertDialog.last;check(modes.itemsVisible()&&modes.items.length==19,"exact native mode choices missing or duplicated");int index=-1;
   for(int i=0;i<modes.items.length;i++)if(modes.items[i].endsWith("["+mode+"]"))index=i;check(index>=0,"entry mode not selectable: "+mode);modes.clickItem(index);
   check(activity.permission!=null&&activity.permissionRequest==2101&&mode.equals(get(activity,"pendingEntryMode")),"permission handoff changed selected entry mode");
   Bundle state=new Bundle();activity.onSaveInstanceState(state);check(state.getString("pending_entry_digest","").matches("[0-9a-f]{64}")&&state.getString("pending_exit_digest","").matches("[0-9a-f]{64}"),"permission state lacks exact source digests");
   check(!state.values.toString().contains("cert=Y2VydA")&&!state.values.toString().contains("/selected-query"),"saved Activity state contains private bridge/DNS configuration");
   StandardExitActivity restored=activity(directory,state);restored.onActivityResult(2101,Activity.RESULT_OK,null);AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.get(restored).standardExit;
   check(runtime.starts==1&&runtime.mode.equals(mode)&&runtime.entry.equals(node.file)&&runtime.exit.id.equals(selected.id),"restored permission relabeled the selected path");
  }
  for(String mutation:new String[]{"entry","exit","denied","busy"}){
   Path directory=Files.createTempDirectory(root,"changed-");StandardExitActivity activity=activity(directory,null);AndroidNodeStore.Node node=node(directory);AndroidStandardExitStore.Entry selected=tor("obfs4","doh");store(activity).save(selected);
   invoke(activity,"requestConnect",node,selected,"max-tls-wg");
   if(mutation.equals("entry"))Files.writeString(node.file.toPath(),Files.readString(node.file.toPath())+"\n");
   if(mutation.equals("exit")){selected.name="Changed while permission was open";store(activity).save(selected);}
   if(mutation.equals("busy"))AndroidVpnMutationGuard.busy=true;
   activity.onActivityResult(2101,mutation.equals("denied")?0:Activity.RESULT_OK,null);AndroidVpnMutationGuard.busy=false;
   check(AndroidRuntimeRegistry.get(activity).standardExit.starts==0&&get(activity,"pendingExit")==null,"changed or denied permission started a stale capture: "+mutation);
  }
  Path directory=Files.createTempDirectory(root,"direct-");StandardExitActivity activity=activity(directory,null);AndroidStandardExitStore.Entry selected=tor("tor","doh");store(activity).save(selected);
  invoke(activity,"requestDirect",selected);activity.onActivityResult(2101,Activity.RESULT_OK,null);
  check(AndroidRuntimeRegistry.get(activity).standardExit.starts==1&&AndroidRuntimeRegistry.get(activity).standardExit.mode.equals("external"),"direct Tor permission path was lost");
 }

 static AndroidStandardExitStore.Entry ordinary(String kind)throws Exception{
  AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id="ordinary-"+kind;e.name="Selected "+kind;e.protocol=kind;e.server="203.0.113.20";e.serverPort=443;e.expectedPublicIp="203.0.113.88";
  byte[] bytes=new byte[32];Arrays.fill(bytes,(byte)'p');String key=Base64.getEncoder().encodeToString(bytes);
  if(kind.equals("wireguard")){e.wgPrivateKey=key;e.wgPeerPublicKey=key;e.wgAddresses.addAll(List.of("10.93.0.2/32","fd93::2/128"));e.wgAllowedIps.addAll(List.of("0.0.0.0/0","::/0"));e.wgMtu=1420;}
  if(kind.equals("socks5")||kind.equals("http")||kind.equals("https")){e.username="private-user";e.password="private-password";}
  if(kind.equals("shadowsocks")){e.method="2022-blake3-aes-256-gcm";e.secret=key;}if(kind.equals("hysteria2"))e.secret="private-hy2-password";e.tlsServerName="exit.example.test";
  return e;
 }
 static void ordinaryPolicies()throws Exception{
  int ordinaryRoundtrips=0;
  for(String kind:new String[]{"wireguard","socks5","http","https","shadowsocks","hysteria2"})for(String dns:new String[]{"rescue","tcp","dot","doh","doh3"}){
   if(dns.equals("doh3")&&(kind.equals("http")||kind.equals("https")))continue;
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"ordinary-form-"),null);AndroidStandardExitStore.Entry selected=ordinary(kind);
   selected.policy=policy(dns.equals("tcp")?"custom":dns,dns.equals("rescue")?"tcp":dns);selected.policy.put("effective_mtu",8800);
   store(activity).save(selected);String before=AndroidStandardExitStore.snapshot(selected);String compiled=AndroidExternalPolicy.compile(selected,null,"external").config;
   invoke(activity,"showExitActions",selected);AlertDialog actions=AlertDialog.last;check(actions.itemsVisible()&&actions.items.length==4,"ordinary policy settings are unreachable");actions.clickItem(2);AlertDialog editor=AlertDialog.last;
   check(editor.showing&&editor.title.toString().contains("Connection settings"),"ordinary policy form was not opened");
   editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!editor.showing,"saved ordinary policy roundtrip rejected: "+kind+"/"+dns+" "+displayed(editor.view));
   AndroidStandardExitStore.Entry after=store(activity).get(selected.id);check(compiled.equals(AndroidExternalPolicy.compile(after,null,"external").config),"ordinary form replaced selected DNS or interface policy");
   check(before.equals(AndroidStandardExitStore.snapshot(selected)),"ordinary form aliased the saved credentials or policy");check(!after.policy.has("effective_mtu"),"ordinary form kept stale current-path MTU");ordinaryRoundtrips++;
  }
  StandardExitActivity activity=activity(Files.createTempDirectory(root,"ordinary-home-"),null);AndroidStandardExitStore.Entry selected=ordinary("socks5");selected.policy=AndroidExternalPolicy.editorPolicy(null);store(activity).save(selected);
  invoke(activity,"showExternalPolicyForm",selected);AlertDialog home=AlertDialog.last;check(spinner(home,"Home AdGuard through captured Router VPN entry").getSelectedItemPosition()==0,"Home was silently replaced in editor");home.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!home.showing&&store(activity).get(selected.id).policy.getString("dns_mode").equals("home"),"Home failed private persistence");
  boolean rejected=false;try{AndroidExternalPolicy.compile(store(activity).get(selected.id),null,"external");}catch(Exception expected){rejected=true;}check(rejected,"direct Home silently fell back to public DNS");
  selected=store(activity).get(selected.id);String before=AndroidStandardExitStore.snapshot(selected);invoke(activity,"showExternalPolicyForm",selected);AlertDialog invalid=AlertDialog.last;field(invalid,"Fixed MTU 1280–9000 (blank: Auto baseline)").setText("9001");invalid.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(invalid.showing&&before.equals(AndroidStandardExitStore.snapshot(store(activity).get(selected.id))),"invalid ordinary MTU overwrote the saved policy");invalid.dismiss();
  invoke(activity,"showExternalPolicyForm",selected);AlertDialog active=AlertDialog.last;AndroidVpnMutationGuard.busy=true;active.getButton(AlertDialog.BUTTON_POSITIVE).performClick();AndroidVpnMutationGuard.busy=false;check(active.showing&&before.equals(AndroidStandardExitStore.snapshot(store(activity).get(selected.id))),"ordinary editor changed a live capture");active.dismiss();
  for(String mutation:new String[]{"exit","denied"}){StandardExitActivity pending=activity(Files.createTempDirectory(root,"ordinary-permission-"),null);AndroidStandardExitStore.Entry e=ordinary("socks5");e.policy.put("dns_mode","rescue");store(pending).save(e);invoke(pending,"requestDirect",e);if(mutation.equals("exit")){e.policy.put("dns_mode","home");store(pending).save(e);}pending.onActivityResult(2101,mutation.equals("denied")?0:Activity.RESULT_OK,null);check(AndroidRuntimeRegistry.get(pending).standardExit.starts==0,"permission adopted changed external policy");}
  System.out.println("Android ordinary external settings: "+ordinaryRoundtrips+" real Java/Go graph roundtrips plus Home, rejection and permission ownership checks passed");
 }

 public static void main(String[] args)throws Exception{root=Path.of(args[0]);roundtrips();newFormAndRejections();dialogAndPermission();ordinaryPolicies();System.out.println("Android Tor form: PASS ("+roundtrips+" real compiler roundtrips, all 19 mode choices, "+checks+" checks; full shipping Activity, Android widgets/permission doubled)");}
}
'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("Android JSON implementation required")
    with tempfile.TemporaryDirectory(prefix=".tor-form-policy-", dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix="android-tor-form-") as work:
        go_dir, work = Path(go_dir), Path(work)
        (go_dir / "main.go").write_text(T.GO.replace('case "tor-profile":', 'case "external-policy":value,err=mobilemultihop.CompileExternalPolicy(r.Config,r.Policy)\n case "tor-profile":', 1))
        native = work / "policy"
        subprocess.run(["go", "build", "-o", str(native), str(go_dir / "main.go")], cwd=ROOT, check=True, timeout=90)
        stubs = dict(T.P.M.STUBS)
        stubs.update(UI)
        stubs.pop("com/eabusham/routervpn/AndroidHomeStateStore.java", None)
        src = work / "src"
        for path, text in stubs.items():
            if path.endswith("/Boundaries.java"):
                source = (JAVA / "AndroidNodeStore.java").read_text()
                methods = source[source.index("    static String stableNodeIdentity("):source.index("    static String deriveId(")]
                methods += source[source.index("    private static String wireGuardPeerPublicKey("):source.index("    private static JSONObject load(")]
                methods += next(line for line in source.splitlines() if "private static String hex(byte[] data)" in line)
                constants = "\n".join(line for line in source.splitlines() if any(part in line for part in ("private static final String NODE_PROOF_DOMAIN =", "static final int MAX_PROFILE_SCHEMA =", "static final int MAX_BUNDLE =")))
                node = r'''static final class Node {final String id,name,endpoint;final java.io.File file;Node(String id,String name,String endpoint,java.io.File file){this.id=id;this.name=name;this.endpoint=endpoint;this.file=file;}}
 static final java.util.List<Node> nodes=new java.util.ArrayList<>();AndroidNodeStore(android.content.Context c){}java.util.List<Node> list(){return new java.util.ArrayList<>(nodes);}
'''
                start, end = text.index("final class AndroidNodeStore {"), text.index("final class AndroidKillSwitchPolicy {")
                private_files = T.TOR_BOUNDARIES[:T.TOR_BOUNDARIES.index("final class AndroidVpnMutationGuard")]
                text = text[:start] + "final class AndroidNodeStore {\n" + constants + node + methods + "\n}\n" + text[end:] + private_files + APP
                text = text.replace("import org.json.JSONObject;", "import org.json.JSONObject; import org.json.JSONArray; import java.security.MessageDigest; import java.nio.charset.StandardCharsets; import android.util.Base64;")
            if path.endswith("/Libbox.java"):
                begin = text.index(" private static String call(")
                end = text.index(" public static String routerCompilePQProfile(", begin)
                text = text[:begin] + T.P.PIPE_CALL + text[end:]
                text = text.replace(" public static String routerCompilePQProfile(", r'''
 public static String routerCompileTorProfile(String profile,String session,String predecessor)throws Exception{return call("tor-profile",new JSONObject().put("Profile",profile).put("Session",session).toString(),predecessor);}
 public static String routerCompileExternalPolicy(String config,String capture)throws Exception{return call("external-policy",config,capture);}
 public static String routerCompilePQProfile(''', 1)
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / "com/eabusham/routervpn"
        for name in ("AndroidMultihopController", "NativeSingBoxController", "AndroidNativeMAXProfile", "AndroidNativeCompositeProfile", "AndroidProfileSelection", "AndroidNumericAddress", "AndroidNativeProfilePolicy", "AndroidWireGuardLibboxPolicy", "AndroidStartLayer", "AndroidXrayLibboxPolicy", "NativeXrayController", "AndroidMultihopStartLayer", "AndroidTorProfile", "AndroidStandardExitStore", "AndroidExternalPolicy", "AndroidDirectStandardExitController", "StandardExitActivity"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        (app / "MultihopGraphHarness.java").write_text(T.P.M.HARNESS)
        constants = "\n".join(re.findall(r" static final String (?:OBFS|MEEK|SNOW|WEB)=.*;", T.HARNESS))
        constants += '\n' + next(line for line in T.HARNESS.splitlines() if 'static final String[] KINDS=' in line)
        constants += '\n' + next(line for line in T.HARNESS.splitlines() if 'static final String[] ALL=' in line)
        tor = T.HARNESS[T.HARNESS.index(" static AndroidStandardExitStore.Entry tor("):T.HARNESS.index(" static JSONObject tagged(")]
        (app / "TorFormHarness.java").write_text(HARNESS.replace(" static int checks,roundtrips;", constants + tor + " static int checks,roundtrips;", 1))
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(work / "classes"), *map(str, src.rglob("*.java"))], check=True, timeout=60)
        data = work / "data"
        data.mkdir()
        environment = dict(os.environ, ROUTERVPN_GO_POLICY_TEST=str(native))
        subprocess.run(["java", "-cp", str(work / "classes") + os.pathsep + str(jar), "com.eabusham.routervpn.TorFormHarness", str(data)], env=environment, check=True, timeout=120)
        # Reintroduce each actual defect only in isolated compiled fixtures.
        # These controls establish that the Activity/Go checks fail for the
        # original behavior; neither working source nor positive classes change.
        controls = (
            ("ipv6-default", "AndroidTorProfile.java",
             'if (ipv6.isEmpty()) policy.put("ipv6_mode", "auto");',
             '// original editor omitted the saved IPv6 default',
             "name-only edit changed effective DNS/IPv6/LAN/MTU/bridge policy"),
            ("lan-default", "AndroidTorProfile.java",
             'if (!policy.has("home_lan_access")) policy.put("home_lan_access", true);',
             '// original editor omitted the saved LAN default',
             "name-only edit changed effective DNS/IPv6/LAN/MTU/bridge policy"),
            ("dns-precedence", "AndroidTorProfile.java",
             'String protocol = "custom".equals(mode) ? policy.optString("dns_protocol", "") : mode;',
             'String protocol = policy.optString("dns_protocol", mode);',
             "name-only edit changed effective DNS/IPv6/LAN/MTU/bridge policy"),
            ("hidden-mode-list", "StandardExitActivity.java",
             '.setCustomTitle(choiceHeader("Exact Router VPN entry mode","The complete selected encryption and Start Layer will be retained before Tor. Both entry identity and the Tor circuit must pass proof."))',
             '.setTitle("Exact Router VPN entry mode").setMessage("The complete selected encryption and Start Layer will be retained before Tor. Both entry identity and the Tor circuit must pass proof.")',
             "exact native mode choices missing or duplicated"),
        )
        for label, filename, before, after, failure in controls:
            source = (app / filename).read_text()
            if source.count(before) != 1:
                raise AssertionError("Shipping form mutation anchor changed: " + label)
            classes = work / ("negative-" + label)
            shutil.copytree(work / "classes", classes)
            mutation = work / ("source-" + label) / filename
            mutation.parent.mkdir()
            mutation.write_text(source.replace(before, after, 1))
            classpath = str(classes) + os.pathsep + str(jar)
            subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", classpath, "-d", str(classes), str(mutation)], check=True, timeout=60)
            rejected = subprocess.run(["java", "-cp", classpath, "com.eabusham.routervpn.TorFormHarness", str(data)], env=environment, capture_output=True, text=True, timeout=120)
            if rejected.returncode == 0 or failure not in rejected.stderr:
                raise AssertionError("Original Tor form defect did not fail its executable check: " + label + "\n" + rejected.stderr)
        print("Android Tor form: all four original-source negative controls rejected")


if __name__ == "__main__":
    main()
