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

DNS_BOUNDARY = r'''package com.eabusham.routervpn;
final class AndroidNativeDNSMeasurement {
 interface Callback{void progress(String stage);void finished(String result,Throwable error);}
 static AndroidNativeDNSMeasurement last;static String receipt;static boolean stale,autoFinish;static int runs,cancels;
 boolean active,cancelled;Callback callback;String mode,node;
 boolean isRunning(){return active;}
 void run(String node,String mode,Callback callback){last=this;runs++;this.node=node;this.mode=mode;this.callback=callback;active=true;if(autoFinish)finish();}
 void finish(){active=false;callback.finished(receipt,null);}
 void cancel(){cancels++;active=false;cancelled=true;}
 org.json.JSONObject currentReceipt()throws Exception{if(stale||cancelled||active||receipt==null)throw new IllegalStateException("measurement owner changed");return new org.json.JSONObject(receipt);}
}'''

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
 public Intent putExtra(String key,boolean value){extras.put(key,value);return this;}public boolean getBooleanExtra(String key,boolean fallback){return (Boolean)extras.getOrDefault(key,fallback);}
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
 public static final int RESULT_OK=-1;public android.view.View content;public android.content.Intent permission;public int permissionRequest;public android.content.Intent intent=new android.content.Intent();public boolean finished;
 protected void onCreate(android.os.Bundle state){}protected void onResume(){}protected void onDestroy(){}
 protected void onSaveInstanceState(android.os.Bundle state){}protected void onActivityResult(int request,int result,android.content.Intent data){}
 public void setContentView(android.view.View view){content=view;}public boolean isFinishing(){return finished;}public void finish(){finished=true;}
 public void runOnUiThread(Runnable action){action.run();}public android.content.Intent getIntent(){return intent;}
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
// Selection persistence is exercised with the shipping stores by test_android_connection_profiles.py.
// Here its API boundary records only public references so permission/UI behavior stays isolated.
final class AndroidConnectionProfileStore {
 static final java.util.Map<String,String> selected=new java.util.HashMap<>(),executions=new java.util.HashMap<>();final android.content.Context context;
 AndroidConnectionProfileStore(android.content.Context c,AndroidNodeStore nodes,AndroidStandardExitStore exits){context=c;}
 void selectExternalPath(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,String mode){selected.put(context.getFilesDir().toString(),exit.id+"|"+(entry==null?"":entry.id)+"|"+mode);}
 void selectExternalPath(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,String mode,String execution){selectExternalPath(exit,entry,mode);executions.put(context.getFilesDir().toString(),execution);}
 void selectOrdinaryTorPath(AndroidStandardExitStore.Entry exit,AndroidStandardExitStore.Entry entry){selected.put(context.getFilesDir().toString(),exit.id+"|external:"+entry.id+"|"+AndroidExternalPolicy.protocol(entry.protocol));executions.put(context.getFilesDir().toString(),"local");}
}
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(android.content.Context c){return busy;}}
final class AndroidHomeStateStore {
 static final class Snapshot{boolean connected;String sessionId="form-session",phase="idle",logicalMode="",activeExternalName="",activeExternalProtocol="",activeExternalId="",pathProof="",activeEntryId="",activeEntryMode="";}
 static Snapshot current;static boolean emergencyDisconnectPending(android.content.Context c){return false;}static Snapshot snapshot(android.content.Context c){return current==null?new Snapshot():current;}static String actualExitForCurrentSession(android.content.Context c){return "";}
}
final class AndroidStandardExitRuntime {
 interface Callback{void progress(String value);void finished(boolean success,String value);}
 int starts;String mode="",execution="local";java.io.File entry;AndroidStandardExitStore.Entry exit,ordinaryEntry;
 void connectDirect(AndroidStandardExitStore.Entry value,Callback cb){starts++;exit=value;mode="external";}
 void connectOrdinary(AndroidStandardExitStore.Entry entry,AndroidStandardExitStore.Entry value,String selected,Callback cb){starts++;ordinaryEntry=entry;exit=value;mode=AndroidExternalPolicy.protocol(entry.protocol);execution=selected;}
 void connect(java.io.File file,AndroidStandardExitStore.Entry value,String selected,Callback cb){starts++;entry=file;exit=value;mode=selected;}
 void connect(java.io.File file,AndroidStandardExitStore.Entry value,String selected,String execution,Callback cb){connect(file,value,selected,cb);this.execution=execution;}
 volatile int disconnects;String disconnectedSession="";boolean disconnectFails,disconnectReplaced;volatile Thread disconnectThread;java.util.concurrent.CountDownLatch disconnectEntered,disconnectRelease;
 void disconnect(){}
 boolean disconnectAndDrainCaptured(String session){disconnectThread=Thread.currentThread();disconnects++;disconnectedSession=session;if(disconnectEntered!=null){disconnectEntered.countDown();try{disconnectRelease.await();}catch(InterruptedException error){throw new IllegalStateException(error);}}if(disconnectFails)throw new IllegalStateException("native teardown pending");if(disconnectReplaced)return false;AndroidHomeStateStore.current.connected=false;AndroidHomeStateStore.current.phase="off";AndroidVpnMutationGuard.busy=false;return true;}
}
final class AndroidRuntimeRegistry {
 static final class Engine{String getState(){return "STOPPED";}boolean isRunning(){return false;}boolean isActiveOrTransitioning(){return false;}}
 static final java.util.Map<String,AndroidRuntimeRegistry> instances=new java.util.HashMap<>();
 final Engine orchestrator=new Engine(),multihop=new Engine(),xray=new Engine();
 final NativeSingBoxController singBox;final AndroidStandardExitRuntime standardExit=new AndroidStandardExitRuntime();
 AndroidRuntimeRegistry(android.content.Context context){singBox=new NativeSingBoxController(context);}
 static AndroidRuntimeRegistry get(android.content.Context context){return instances.computeIfAbsent(context.getFilesDir().toString(),key->new AndroidRuntimeRegistry(context));}
}
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
 static CheckBox jumbo(AlertDialog dialog){for(View view:views(dialog.view))if(view instanceof CheckBox&&((CheckBox)view).getText().toString().equals("Jumbo virtual interface (9000)"))return (CheckBox)view;throw new AssertionError("Missing Tor Jumbo policy");}
 static CheckBox padding(AlertDialog dialog){for(View view:views(dialog.view))if(view instanceof CheckBox&&((CheckBox)view).getText().toString().equals("Outgoing Tor padding"))return (CheckBox)view;throw new AssertionError("Missing Tor outgoing padding policy");}
 static String displayed(View root){StringBuilder result=new StringBuilder();for(View view:views(root))if(view instanceof TextView)result.append(((TextView)view).getText()).append('\n');return result.toString();}
 static StandardExitActivity activity(Path directory,Bundle state)throws Exception{Context.nextFiles=directory.toFile();Files.createDirectories(directory);StandardExitActivity result=new StandardExitActivity();result.onCreate(state);return result;}
 static AndroidStandardExitStore store(StandardExitActivity activity)throws Exception{return (AndroidStandardExitStore)get(activity,"exitStore");}
 static String compiled(AndroidStandardExitStore.Entry entry)throws Exception{
  JSONObject profile=AndroidTorProfile.profile(entry);io.nekohasekai.libbox.Libbox.routerValidateTorProfile(profile.toString());
  String mode=profile.optString("dns_mode","");
  if(mode.isEmpty()||mode.equals("home")){
   boolean rejected=false;try{io.nekohasekai.libbox.Libbox.routerCompileTorProfile(profile.toString(),"form-roundtrip","");}catch(Exception expected){rejected=true;}
   check(rejected,"unresolved Home draft silently compiled with another resolver");return profile.toString();
  }
  return io.nekohasekai.libbox.Libbox.routerCompileTorProfileWithPredecessor(profile.toString(),"form-roundtrip","","");
 }
 static boolean same(String a,String b)throws Exception{return io.nekohasekai.libbox.Libbox.testSameJSON(a,b);}
 static AlertDialog form(StandardExitActivity activity,AndroidStandardExitStore.Entry entry)throws Exception{invoke(activity,"showTorForm",entry==null?"tor":entry.protocol,entry);return AlertDialog.last;}
 static JSONObject policy(String mode,String protocol)throws Exception{
  JSONObject result=new JSONObject().put("dns_mode",mode).put("dns_protocol",protocol).put("dns_host","149.112.112.112")
   .put("dns_port",8443).put("dns_server_name","dns.example.test").put("dns_path","/selected-query")
   .put("ipv6_mode","on").put("home_lan_access",false).put("home_lan_cidrs",new JSONArray().put("192.168.50.0/24").put("fd12:3456::/48"))
   .put("mtu_policy","fixed").put("manual_mtu",1360);return result;
 }
 static void roundtrips()throws Exception{
  List<JSONObject> policies=new ArrayList<>();policies.add(new JSONObject());policies.add(policy("rescue","tcp"));policies.add(policy("","dot").put("dns_host","10.77.0.53"));
  for(String protocol:new String[]{"udp","tcp","dot","doh","doh3","tls","https","h3"})policies.add(policy("home",protocol).put("dns_host","10.77.0.53"));
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
   String expectedIPv6=policy.optString("ipv6_mode","");int ipIndex=expectedIPv6.equals("off")?0:expectedIPv6.equals("on")?2:1;
   check(spinner(dialog,"IPv6 off").getSelectedItemPosition()==ipIndex,"Tor editor displayed another saved IPv6 policy");
   check(lan(dialog).isChecked()==!policy.optBoolean("home_lan_access",true),"Tor editor displayed another saved LAN policy");
   String expectedDNS=policy.optString("dns_mode","");String expectedProtocol=expectedDNS.equals("custom")?policy.optString("dns_protocol",""):expectedDNS;
   int dnsIndex=(expectedDNS.isEmpty()||expectedDNS.equals("home"))?0:expectedDNS.equals("rescue")?1:expectedProtocol.equals("tcp")?2:(expectedProtocol.equals("dot")||expectedProtocol.equals("tls"))?3:4;
   check(spinner(dialog,"Home AdGuard through captured Router VPN entry").getSelectedItemPosition()==dnsIndex,"Tor editor displayed another saved DNS policy");
   if(dnsIndex==0){String home=policy.optString("dns_protocol","");int transport=home.equals("tcp")?1:(home.equals("dot")||home.equals("tls"))?2:(home.equals("doh")||home.equals("https"))?3:(home.equals("doh3")||home.equals("h3"))?4:0;check(spinner(dialog,"Home UDP").getSelectedItemPosition()==transport,"Tor Home editor changed the saved DNS transport");}
   EditText bridge=null;if(!kind.equals("tor")){bridge=field(dialog,"Paste bridge lines, one per line");check(!bridge.isSaveEnabled()&&bridge.getImportantForAutofill()==View.IMPORTANT_FOR_AUTOFILL_NO,"bridge credentials entered Android saved/autofill state");check(bridge.getText().toString().equals(String.join("\n",selected.torBridges)),"bridge order/credentials changed on edit");}
   field(dialog,"Display name").setText("Renamed private Tor node");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(!dialog.showing,"valid name-only edit was rejected");AndroidStandardExitStore.Entry after=store(activity).get(selected.id);
   check(after.id.equals(selected.id)&&after.protocol.equals(selected.protocol)&&after.name.equals("Renamed private Tor node"),"editor replaced the saved node identity");
   check(same(graph,compiled(after)),"name-only edit changed effective DNS/IPv6/LAN/MTU/bridge policy: "+kind+" "+policy);
   check(same(selected.torPolicy.toString(),after.torPolicy.toString()),"name-only edit rewrote the frozen Tor policy");
   check(before.equals(AndroidStandardExitStore.snapshot(selected)),"saving aliased its captured source");
   if(bridge!=null)check(bridge.getText().length()==0,"dismissed form retained bridge credentials");roundtrips++;
  }
  check(roundtrips==162,"Tor editor policy matrix incomplete");
 }
 static void independentPolicyEdits()throws Exception{
  for(String initial:new String[]{"default","auto","fixed"}){
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"independent-"),null);AndroidStandardExitStore.Entry selected=tor("tor","doh");
   selected.torPolicy=policy("dot","tcp").put("mtu_policy",initial).put("manual_mtu",1360);store(activity).save(selected);
   AlertDialog dialog=form(activity,selected);field(dialog,"Custom DNS literal IP").setText("9.9.9.9");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(!dialog.showing,"valid isolated DNS edit rejected");AndroidStandardExitStore.Entry changed=store(activity).get(selected.id);JSONObject expected=new JSONObject(selected.torPolicy.toString());
   for(String key:new String[]{"dns_mode","dns_protocol","dns_host","dns_port","dns_server_name","dns_path"}){expected.remove(key);if(changed.torPolicy.has(key))expected.put(key,changed.torPolicy.get(key));}
   check(changed.torPolicy.getString("dns_host").equals("9.9.9.9")&&same(expected.toString(),changed.torPolicy.toString()),"DNS edit changed unrelated saved policy");
   check(changed.torPolicy.getString("mtu_policy").equals(initial),"DNS edit enabled or disabled adaptive MTU");compiled(changed);
   dialog=form(activity,changed);field(dialog,"Manual interface MTU, 1280–9000 (blank uses automatic)").setText("1400");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(!dialog.showing,"valid isolated MTU edit rejected");AndroidStandardExitStore.Entry resized=store(activity).get(selected.id);JSONObject resizedExpected=new JSONObject(changed.torPolicy.toString()).put("mtu_policy","manual").put("manual_mtu",1400);
   check(same(resizedExpected.toString(),resized.torPolicy.toString()),"MTU edit changed another saved policy");compiled(resized);
   dialog=form(activity,resized);field(dialog,"Manual interface MTU, 1280–9000 (blank uses automatic)").setText("");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(!dialog.showing&&store(activity).get(selected.id).torPolicy.getString("mtu_policy").equals("auto")&&!store(activity).get(selected.id).torPolicy.has("manual_mtu"),"clearing fixed MTU failed to select Auto");
  }
 }
 static void jumboPolicyEdits()throws Exception{
  for(String initial:new String[]{"default","auto","fixed"}){
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"jumbo-form-"),null);AndroidStandardExitStore.Entry selected=tor("obfs4","doh");
   selected.torPolicy=policy("doh","doh").put("mtu_policy",initial).put("manual_mtu",initial.equals("fixed")?9000:8192);store(activity).save(selected);String original=AndroidStandardExitStore.snapshot(selected);
   AlertDialog dialog=form(activity,selected);check(!jumbo(dialog).isChecked(),"Jumbo became an import default");jumbo(dialog).setChecked(true);dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(!dialog.showing,"valid Tor Jumbo edit rejected");AndroidStandardExitStore.Entry enabled=store(activity).get(selected.id);JSONObject expected=new JSONObject(selected.torPolicy.toString()).put("jumbo_tun",true);
   check(same(expected.toString(),enabled.torPolicy.toString())&&enabled.torPolicy.getString("mtu_policy").equals(initial),"Jumbo edit replaced saved Auto/Default or unrelated DNS/protection policy");
   check(new JSONObject(compiled(enabled)).getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==9000,"saved Tor Jumbo did not reach real compiler");
   check(original.equals(AndroidStandardExitStore.snapshot(selected)),"Jumbo editor mutated its input source");
   dialog=form(activity,enabled);check(jumbo(dialog).isChecked(),"saved Tor Jumbo was not displayed");field(dialog,"Display name").setText("Renamed Jumbo");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   AndroidStandardExitStore.Entry renamed=store(activity).get(selected.id);check(same(enabled.torPolicy.toString(),renamed.torPolicy.toString()),"name-only edit erased Jumbo capacity");
   dialog=form(activity,renamed);String before=AndroidStandardExitStore.snapshot(renamed);field(dialog,"Manual interface MTU, 1280–9000 (blank uses automatic)").setText("1420");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(dialog.showing&&before.equals(AndroidStandardExitStore.snapshot(store(activity).get(selected.id))),"conflicting Jumbo and Fixed MTU overwrote the saved profile");dialog.dismiss();
   dialog=form(activity,renamed);jumbo(dialog).setChecked(false);dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(!dialog.showing,"valid Tor Jumbo disable rejected");AndroidStandardExitStore.Entry disabled=store(activity).get(selected.id);expected.put("jumbo_tun",false);check(same(expected.toString(),disabled.torPolicy.toString()),"disabling Jumbo changed its captured MTU preference");compiled(disabled);
  }
 }
 static final String PADDING_RATE="Padding rate, 32–192 kbps (blank uses 192 when On)";
 static void paddingPolicyEdits()throws Exception{
  for(String kind:new String[]{"tor","obfs4"})for(Boolean enabled:new Boolean[]{null,false,true})for(Integer rate:new Integer[]{null,0,32,64,192}){
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"padding-form-"),null);AndroidStandardExitStore.Entry selected=tor(kind,"doh");
   if(enabled!=null)selected.torPolicy.put("daita_enabled",enabled);if(rate!=null)selected.torPolicy.put("daita_rate_kbps",rate);store(activity).save(selected);String original=AndroidStandardExitStore.snapshot(selected);
   AlertDialog dialog=form(activity,selected);check(padding(dialog).isChecked()==Boolean.TRUE.equals(enabled),"Tor padding editor changed the captured enable choice");
   check(field(dialog,PADDING_RATE).getText().toString().equals(rate==null||rate==0?"":rate.toString()),"Tor padding editor changed selected or dormant rate");
   field(dialog,"Display name").setText("Renamed outgoing-padding choice");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   AndroidStandardExitStore.Entry renamed=store(activity).get(selected.id);check(!dialog.showing&&same(selected.torPolicy.toString(),renamed.torPolicy.toString()),"name-only edit rewrote absent/default/dormant Tor padding");
   dialog=form(activity,renamed);padding(dialog).setChecked(!Boolean.TRUE.equals(enabled));dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   AndroidStandardExitStore.Entry toggled=store(activity).get(selected.id);JSONObject expected=new JSONObject(selected.torPolicy.toString()).put("daita_enabled",!Boolean.TRUE.equals(enabled)).put("daita_rate_kbps",rate==null?0:rate);
   check(!dialog.showing&&same(expected.toString(),toggled.torPolicy.toString()),"padding toggle changed DNS, MTU, protection or its dormant rate");
   dialog=form(activity,toggled);int next=rate!=null&&rate==64?32:64;field(dialog,PADDING_RATE).setText(Integer.toString(next));dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   AndroidStandardExitStore.Entry changed=store(activity).get(selected.id);expected.put("daita_rate_kbps",next);check(!dialog.showing&&same(expected.toString(),changed.torPolicy.toString()),"padding rate edit changed another complete policy group");
   check(original.equals(AndroidStandardExitStore.snapshot(selected)),"padding form mutated its saved input capture");
   for(String invalid:new String[]{"31","193","-1","64.5","true","2147483648"}){
    dialog=form(activity,changed);field(dialog,PADDING_RATE).setText(invalid);dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
    check(dialog.showing&&same(changed.torPolicy.toString(),store(activity).get(selected.id).torPolicy.toString()),"invalid outgoing padding rate replaced saved policy: "+invalid);dialog.getButton(AlertDialog.BUTTON_NEGATIVE).performClick();
   }
  }
 }
 static void paddingCompiler()throws Exception{
  int captures=0;
  for(String kind:new String[]{"tor","obfs4"})for(int rate:new int[]{0,32,64,192}){
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"padding-compiled-form-"),null);AndroidStandardExitStore.Entry selected=tor(kind,"doh");store(activity).save(selected);
   AlertDialog dialog=form(activity,selected);padding(dialog).setChecked(true);field(dialog,PADDING_RATE).setText(rate==0?"":Integer.toString(rate));dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   AndroidStandardExitStore.Entry saved=store(activity).get(selected.id);String raw=compiled(saved);JSONObject profile=AndroidTorProfile.profile(saved),owner=torOwner(new JSONObject(raw));
   check(!dialog.showing&&same(owner.getJSONObject("padding_source").getString("profile"),profile.toString()),"saved editor choice failed real captured Local padding compilation");
   check(io.nekohasekai.libbox.Libbox.routerTorPaddingSource(raw,profile.toString(),"form-roundtrip").matches("[0-9a-f]{64}"),"saved editor padding has no independently reconstructed source");captures++;
  }
  for(String kind:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"))for(String torKind:new String[]{"tor","obfs4"})for(int rate:new int[]{0,32,64,192}){
   Path directory=Files.createTempDirectory(root,"ordinary-padding-");AndroidStandardExitStore.Entry entry=ordinary(kind),exit=tor(torKind,"doh");entry.policy=policy("custom","tcp").put("dns_host","9.9.9.9");exit.torPolicy.put("daita_enabled",true).put("daita_rate_kbps",rate);
   String before=AndroidStandardExitStore.snapshot(entry),exitBefore=AndroidStandardExitStore.snapshot(exit);NativeSingBoxController.SessionInfo session=AndroidTorProfile.prepareOrdinary(new Context(directory.toFile()),entry,exit,"local");Path folder=directory.resolve("layered-sessions").resolve(session.sessionId);
   String raw=Files.readString(folder.resolve("sing-box.json")),metadata=Files.readString(folder.resolve(AndroidTorProfile.SESSION_FILE));JSONObject meta=AndroidTorProfile.session(raw,metadata,session.sessionId,session.modeId),graph=new JSONObject(raw),owner=torOwner(graph),source=owner.getJSONObject("padding_source");
   check(same(source.getString("profile"),meta.getJSONObject("tor_profile").toString())&&same(source.getString("predecessor_profile"),meta.getJSONObject("predecessor_profile").toString()),"ordinary padding replaced captured selected or entry policy");
   check(source.getString("predecessor_config").equals(owner.getString("external_predecessor_config"))&&meta.getJSONObject("predecessor_profile").getString("node_kind").equals("external"),"ordinary padding source borrowed private Router authority or changed credentials");
   check(io.nekohasekai.libbox.Libbox.routerTorPaddingSource(raw,meta.getJSONObject("tor_profile").toString(),session.sessionId).matches("[0-9a-f]{64}"),"ordinary padding exact source capture failed");
   check(before.equals(AndroidStandardExitStore.snapshot(entry))&&exitBefore.equals(AndroidStandardExitStore.snapshot(exit)),"padding capture mutated saved ordinary credentials");
   for(String fault:new String[]{"padding-policy","padding-entry","padding-config","padding-missing","route"}){
    JSONObject changed=new JSONObject(raw),changedMeta=new JSONObject(metadata),changedOwner=torOwner(changed),capture=changedOwner.getJSONObject("padding_source");
    if(fault.equals("padding-policy"))capture.put("profile",new JSONObject(capture.getString("profile")).put("daita_rate_kbps",rate==32?64:32).toString());
    if(fault.equals("padding-entry"))capture.put("predecessor_profile",new JSONObject(capture.getString("predecessor_profile")).put("id","different-provider").toString());
    if(fault.equals("padding-config"))capture.put("predecessor_config","{}");if(fault.equals("padding-missing"))changedOwner.remove("padding_source");if(fault.equals("route"))changed.getJSONObject("route").put("final","custom-exit");
    changedMeta.put("config_sha256",AndroidTorProfile.digest(changed.toString().getBytes(StandardCharsets.UTF_8)));
    rejectOrdinary(()->AndroidTorProfile.session(changed.toString(),changedMeta.toString(),session.sessionId,session.modeId),"padding source tampering "+kind+"/"+fault);
   }
   String output=System.getenv("ROUTERVPN_ANDROID_LOCAL_PADDING_GRAPHS");if(output!=null&&!output.isEmpty())Files.writeString(Path.of(output).resolve(String.format("ordinary-padding-%03d.json",captures)),raw,StandardOpenOption.CREATE_NEW);
   captures++;
  }
  check(captures==72,"padding editor/direct/eight ordinary transport/rate matrix incomplete");
  System.out.println("Android Local Tor padding form/compiler: PASS ("+captures+" real captured graphs, "+checks+" checks; actual production admission)");
 }
 static void newFormAndRejections()throws Exception{
  StandardExitActivity activity=activity(Files.createTempDirectory(root,"create-"),null);AlertDialog dialog=form(activity,null);
  check(spinner(dialog,"Home AdGuard through captured Router VPN entry").getSelectedItemPosition()==0&&spinner(dialog,"IPv6 off").getSelectedItemPosition()==2&&!lan(dialog).isChecked()&&!jumbo(dialog).isChecked(),"new Tor defaults changed");
  EditText host=field(dialog,"Custom DNS literal IP"),port=field(dialog,"Custom DNS port (blank uses protocol default)"),name=field(dialog,"DoT / DoH certificate server name"),path=field(dialog,"DoH path (default /dns-query)");
  check(host.isEnabled()&&port.isEnabled()&&!name.isEnabled()&&!path.isEnabled(),"Home UDP editor cannot retain its captured endpoint");
  Spinner dns=spinner(dialog,"Home AdGuard through captured Router VPN entry"),home=spinner(dialog,"Home UDP");home.setSelection(4);check(name.isEnabled()&&path.isEnabled(),"Home DoH3 endpoint cannot be edited");
  dns.setSelection(1);check(!host.isEnabled()&&!port.isEnabled()&&!name.isEnabled()&&!path.isEnabled()&&!home.isEnabled(),"rescue editor enables ignored custom fields");
  dns.setSelection(2);check(host.isEnabled()&&port.isEnabled()&&!name.isEnabled()&&!path.isEnabled(),"TCP DNS widget dependencies wrong");
  dns.setSelection(3);check(name.isEnabled()&&!path.isEnabled(),"DoT widget dependencies wrong");dns.setSelection(4);check(path.isEnabled(),"DoH path cannot be set");
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
  dialog=form(activity,store(activity).get(selected.id));AndroidVpnMutationGuard.busy=true;dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(dialog.showing,"form mutated a live VPN capture");AndroidVpnMutationGuard.busy=false;dialog.dismiss();
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
  for(String execution:new String[]{"local","server"})for(String mode:ALL){
   Path directory=Files.createTempDirectory(root,"permission-");StandardExitActivity activity=activity(directory,null);AndroidNodeStore.Node node=node(directory);AndroidStandardExitStore.Entry selected=tor("custom","doh");store(activity).save(selected);
   invoke(activity,"showExitActions",selected);AlertDialog actions=AlertDialog.last;check(actions.itemsVisible()&&actions.items.length==5&&actions.items[3].equals("Compare DNS on this connected path"),"saved Tor actions are hidden");
   check(!displayed(actions.customTitle).contains("cert=Y2VydA"),"actions header exposed bridge credentials");actions.clickItem(1);
   AlertDialog entries=AlertDialog.last;check(entries.itemsVisible()&&entries.items.length==1,"entry choices are hidden");entries.clickItem(0);
   AlertDialog modes=AlertDialog.last;check(modes.itemsVisible()&&modes.items.length==19,"exact native mode choices missing or duplicated");int index=-1;
   for(int i=0;i<modes.items.length;i++)if(modes.items[i].endsWith("["+mode+"]"))index=i;check(index>=0,"entry mode not selectable: "+mode);modes.clickItem(index);
   AlertDialog choices=AlertDialog.last;check(choices.itemsVisible()&&Arrays.equals(choices.items,new String[]{"Local","Server"}),"Tor execution choices are hidden or use unproved Compare");choices.clickItem(execution.equals("server")?1:0);
   check(activity.permission!=null&&activity.permissionRequest==2101&&mode.equals(get(activity,"pendingEntryMode")),"permission handoff changed selected entry mode");
   Bundle state=new Bundle();activity.onSaveInstanceState(state);check(state.getString("pending_entry_digest","").matches("[0-9a-f]{64}")&&state.getString("pending_exit_digest","").matches("[0-9a-f]{64}"),"permission state lacks exact source digests");
   check(!state.values.toString().contains("cert=Y2VydA")&&!state.values.toString().contains("/selected-query"),"saved Activity state contains private bridge/DNS configuration");
   StandardExitActivity restored=activity(directory,state);restored.onActivityResult(2101,Activity.RESULT_OK,null);AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.get(restored).standardExit;
   check(runtime.starts==1&&runtime.mode.equals(mode)&&runtime.entry.equals(node.file)&&runtime.exit.id.equals(selected.id)&&runtime.execution.equals(execution),"restored permission relabeled the selected path or Tor execution");
   check(state.getString("pending_execution","").equals(execution)&&AndroidConnectionProfileStore.executions.get(directory.toString()).equals(execution),"Tor execution was omitted from permission or saved path");
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
  for(boolean direct:new boolean[]{true,false}){
   directory=Files.createTempDirectory(root,"select-only-");activity=activity(directory,null);AndroidNodeStore.Node entry=node(directory);selected=tor("obfs4","doh");store(activity).save(selected);
   activity.intent.putExtra(StandardExitActivity.EXTRA_EXIT_ID,selected.id).putExtra(StandardExitActivity.EXTRA_SELECT_PATH,true);activity.onResume();
   AlertDialog paths=AlertDialog.last;check(paths.itemsVisible()&&paths.items.length==2,"external path choices are reachable without connecting");paths.clickItem(direct?0:1);
   if(!direct){AlertDialog.last.clickItem(0);AlertDialog.last.clickItem(0);AlertDialog.last.clickItem(0);}
   check(activity.finished&&activity.permission==null&&get(activity,"pendingExit")==null&&AndroidRuntimeRegistry.get(activity).standardExit.starts==0,"selection-only path requested permission or started VPN");
   check(AndroidConnectionProfileStore.selected.get(directory.toString()).equals(selected.id+"|"+(direct?"":entry.id)+"|wg"),"selection-only lost exact entry/exit reference");
  }
 }

 static AndroidStandardExitStore.Entry ordinary(String kind)throws Exception{
  AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.id="ordinary-"+kind;e.name="Selected "+kind;e.protocol=kind;e.server="203.0.113.20";e.serverPort=443;e.expectedPublicIp="203.0.113.88";
  byte[] bytes=new byte[32];Arrays.fill(bytes,(byte)'p');String key=Base64.getEncoder().encodeToString(bytes);
  if(kind.equals("wireguard")||kind.equals("amneziawg")){e.wgPrivateKey=key;e.wgPeerPublicKey=key;e.wgAddresses.addAll(List.of("10.93.0.2/32","fd93::2/128"));e.wgAllowedIps.addAll(List.of("0.0.0.0/0","::/0"));e.wgMtu=1420;e.wgKeepalive=17;if(kind.equals("amneziawg"))e.awgParameters=new JSONObject().put("jc","3").put("jmin","40").put("jmax","900").put("s1","15").put("s2","16").put("s3","32").put("s4","32").put("h1","100-110").put("h2","200-210").put("h3","300-310").put("h4","400-410");}
  if(kind.equals("socks5")||kind.equals("http")||kind.equals("https")){e.username="private-user";e.password="private-password";}
  if(kind.equals("shadowsocks")){e.method="2022-blake3-aes-256-gcm";e.secret=key;}if(kind.equals("hysteria2"))e.secret="private-hy2-password";e.tlsServerName="exit.example.test";
  if(kind.equals("openvpn")){e.username=" private OpenVPN user ";e.password=" private OpenVPN password ";e.openVPNConfig="client\ndev tun\nproto udp\nremote 203.0.113.20 443\nremote 203.0.113.21 1194 tcp-client\nauth-user-pass\nremote-cert-tls server\n<ca>\n-----BEGIN CERTIFICATE-----\nfixture-only\n-----END CERTIFICATE-----\n</ca>\n";}
  return e;
 }
 static JSONObject torOwner(JSONObject graph)throws Exception{
  JSONObject owner=null;JSONArray rows=graph.getJSONArray("outbounds");
  for(int i=0;i<rows.length();i++)if(AndroidTorProfile.OUTBOUND.equals(rows.getJSONObject(i).optString("tag"))){check(owner==null,"ordinary Tor duplicated native owner");owner=rows.getJSONObject(i);}
  check(owner!=null,"ordinary Tor native owner is absent");return owner;
 }
 interface OrdinaryAttempt{void run()throws Exception;}
 static void rejectOrdinary(OrdinaryAttempt attempt,String reason)throws Exception{boolean rejected=false;try{attempt.run();}catch(Exception expected){rejected=true;}check(rejected,"ordinary Tor accepted "+reason);}
 static void ordinaryTorProfiles()throws Exception{
  int index=0;
  for(String kind:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"))for(String torKind:Arrays.asList(KINDS)){
   Path directory=Files.createTempDirectory(root,"ordinary-tor-profile-");Context context=new Context(directory.toFile());
   AndroidStandardExitStore.Entry entry=ordinary(kind),exit=tor(torKind,new String[]{"tcp","dot","doh"}[index++%3]);
   entry.policy=policy("custom","tcp").put("dns_host","9.9.9.9").put("dns_port",5353).put("kill_switch",false).put("kill_switch_policy","off");
   exit.torPolicy.put("kill_switch",false).put("kill_switch_policy","off");
   String entrySource=AndroidStandardExitStore.snapshot(entry),exitSource=AndroidStandardExitStore.snapshot(exit);
   NativeSingBoxController.SessionInfo session=AndroidTorProfile.prepareOrdinary(context,entry,exit,"local");Path folder=directory.resolve("layered-sessions").resolve(session.sessionId);
   String config=Files.readString(folder.resolve("sing-box.json")),raw=Files.readString(folder.resolve(AndroidTorProfile.SESSION_FILE));
   JSONObject graph=new JSONObject(config),meta=AndroidTorProfile.session(config,raw,session.sessionId,session.modeId),owner=torOwner(graph);
   check(session.modeId.equals("standard-"+exit.protocol)&&owner.getString("detour").equals("custom-exit"),"ordinary Tor fell back to a direct path or private entry");
   JSONObject captured=AndroidExternalPolicy.captureTorPredecessor(entry),profile=meta.getJSONObject("tor_profile"),predecessor=meta.getJSONObject("predecessor_profile");
   check(predecessor.getString("node_kind").equals("external")&&predecessor.getString("id").equals(entry.id)&&!predecessor.has("agent_token")&&!predecessor.has("node_proof_id"),"ordinary provider borrowed private Router authority");
   check(same(predecessor.toString(),owner.getString("external_predecessor_profile"))&&same(captured.getString("config"),owner.getString("external_predecessor_config")),"ordinary Tor substituted source transport credentials or original source");
   check(meta.getString("predecessor_config_sha256").equals(AndroidTorProfile.digest(owner.getString("external_predecessor_config").getBytes(StandardCharsets.UTF_8))),"ordinary Tor lost canonical source checksum");
   check(profile.getString("multihop_entry_id").equals(entry.id)&&profile.getString("multihop_exit_id").equals(exit.id)&&profile.getString("multihop_entry_mode").equals(AndroidExternalPolicy.protocol(kind))&&profile.getString("multihop_execution").equals("local"),"ordinary Tor changed captured roles or execution");
   check(graph.getJSONArray("inbounds").length()==1&&graph.getJSONArray("inbounds").getJSONObject(0).getInt("mtu")==1360,"ordinary Tor lost selected single-TUN MTU");
   JSONObject dns=graph.getJSONObject("dns");boolean selectedDNS=false;
   for(int i=0;i<dns.getJSONArray("servers").length();i++){JSONObject resolver=dns.getJSONArray("servers").getJSONObject(i);if(dns.getString("final").equals(resolver.optString("tag"))){selectedDNS=true;check(resolver.getString("server").equals("149.112.112.112")&&resolver.getString("detour").equals(AndroidTorProfile.OUTBOUND),"ordinary Tor DNS bypassed selected exit");}}
   check(selectedDNS&&!Files.exists(folder.resolve(AndroidKillSwitchPolicy.SESSION_MARKER)),"ordinary Tor failed captured protection Off");
   check(entrySource.equals(AndroidStandardExitStore.snapshot(entry))&&exitSource.equals(AndroidStandardExitStore.snapshot(exit)),"ordinary Tor preparation rewrote saved nodes");
   for(String fault:List.of("source","profile","credentials","dns","route","mtu","detour","server","mode","lost-owner")){
    JSONObject changed=new JSONObject(config),metadata=new JSONObject(raw),out=torOwner(changed);
    switch(fault){
     case "source":out.put("external_predecessor_config",out.getString("external_predecessor_config")+" ");break;
     case "profile":metadata.getJSONObject("predecessor_profile").put("id","other-provider");break;
     case "credentials":JSONObject source=new JSONObject(out.getString("external_predecessor_config"));source.put("experimental",new JSONObject().put("changed",true));out.put("external_predecessor_config",source.toString());metadata.put("predecessor_config_sha256",AndroidTorProfile.digest(source.toString().getBytes(StandardCharsets.UTF_8)));break;
     case "dns":changed.getJSONObject("dns").put("final","selected-dns");break;
     case "route":changed.getJSONObject("route").put("final","custom-exit");break;
     case "mtu":changed.getJSONArray("inbounds").getJSONObject(0).put("mtu",1500);break;
     case "detour":out.put("detour","proxy");break;
     case "server":metadata.put("execution","server");break;
     case "mode":metadata.put("entry_mode","wg");break;
     case "lost-owner":metadata.remove("predecessor_profile");break;
    }
    String altered=changed.toString();metadata.put("config_sha256",AndroidTorProfile.digest(altered.getBytes(StandardCharsets.UTF_8)));
    rejectOrdinary(()->AndroidTorProfile.session(altered,metadata.toString(),session.sessionId,session.modeId),"changed captured "+fault+" for "+kind);
   }
   String output=System.getenv("ROUTERVPN_ANDROID_ORDINARY_TOR_GRAPHS");
   if(output!=null)Files.writeString(Path.of(output).resolve("ordinary-"+torKind+"-"+kind+".json"),config,StandardOpenOption.CREATE_NEW);
  }
  AndroidStandardExitStore.Entry entry=ordinary("socks5"),exit=tor("obfs4","tcp");entry.policy=policy("custom","tcp");
  for(String execution:List.of("server","auto","compare",""))rejectOrdinary(()->AndroidTorProfile.compileOrdinary(entry,exit,"ordinary-invalid",execution),"private execution without Router entry: "+execution);
  AndroidStandardExitStore.Entry home=AndroidStandardExitStore.copy(exit);home.torPolicy.put("dns_mode","home");rejectOrdinary(()->AndroidTorProfile.compileOrdinary(entry,home,"ordinary-home","local"),"Home DNS without private Router identity");
  AndroidStandardExitStore.Entry sameID=AndroidStandardExitStore.copy(exit);sameID.id=entry.id;rejectOrdinary(()->AndroidTorProfile.compileOrdinary(entry,sameID,"ordinary-duplicate","local"),"same entry/exit identity");
  for(String mutation:List.of("entry","exit","cancel")){
   Path directory=Files.createTempDirectory(root,"ordinary-tor-stale-");AndroidStandardExitStore.Entry a=AndroidStandardExitStore.copy(entry),b=AndroidStandardExitStore.copy(exit);
   io.nekohasekai.libbox.Libbox.afterCheck=()->{if(mutation.equals("entry"))a.password+=" replacement";else if(mutation.equals("exit"))b.name+=" replacement";else Thread.currentThread().interrupt();};
   try{rejectOrdinary(()->AndroidTorProfile.prepareOrdinary(new Context(directory.toFile()),a,b,"local"),"stale preparation "+mutation);}finally{io.nekohasekai.libbox.Libbox.afterCheck=null;Thread.interrupted();}
   check(!Files.exists(directory.resolve("layered-sessions")),"stale ordinary Tor preparation staged private material");
  }
 }
 static void ordinaryHomeDrafts()throws Exception{
  for(String kind:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"})for(String mode:new String[]{"missing","","home"}){
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"ordinary-home-draft-"),null);AndroidStandardExitStore.Entry selected=ordinary(kind);selected.policy=new JSONObject();if(!mode.equals("missing"))selected.policy.put("dns_mode",mode);
   String source=AndroidStandardExitStore.snapshot(selected);invoke(activity,"showExternalPolicyForm",selected);AlertDialog dialog=AlertDialog.last;check(spinner(dialog,"Home AdGuard through captured Router VPN entry").getSelectedItemPosition()==0,"missing ordinary DNS displayed Rescue or Custom");dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(!dialog.showing,"valid Home draft could not be saved: "+kind+"/"+mode+" "+displayed(dialog.view));AndroidStandardExitStore.Entry saved=store(activity).get(selected.id);
   check(mode.equals("missing")?!saved.policy.has("dns_mode"):mode.equals(saved.policy.getString("dns_mode")),"unrelated Home draft save changed missing/blank/explicit DNS representation");check(source.equals(AndroidStandardExitStore.snapshot(selected)),"Home draft form aliased source credentials");
   boolean rejected=false;try{AndroidExternalPolicy.compile(saved,null,"external");}catch(Exception expected){rejected=true;}check(rejected,"Home draft form authorized direct runtime without entry");
  }
  for(String fault:new String[]{"transport","dns"}){
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"ordinary-home-invalid-"),null);AndroidStandardExitStore.Entry selected=ordinary("https");selected.policy=new JSONObject().put("dns_mode","home");if(fault.equals("transport"))selected.tlsServerName="invalid..example";else selected.policy.put("dns_protocol","smtp");
   invoke(activity,"showExternalPolicyForm",selected);AlertDialog dialog=AlertDialog.last;dialog.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(dialog.showing&&store(activity).list().isEmpty(),"Home draft bypassed native "+fault+" validation");dialog.dismiss();
  }
 }
 static void externalExecutionForm()throws Exception{
  String urlHint="This server's HTTPS response URL (required for Server / Compare both)",nameHint="Response TLS server name (optional)";
  StandardExitActivity editor=activity(Files.createTempDirectory(root,"external-response-"),null);AndroidStandardExitStore.Entry selected=ordinary("shadowsocks");selected.policy=AndroidExternalPolicy.editorPolicy(null);store(editor).save(selected);
  invoke(editor,"showExternalPolicyForm",selected);AlertDialog form=AlertDialog.last;field(form,urlHint).setText("https://203.0.113.20:8443/response");field(form,nameHint).setText("external.example.test");form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
  check(!form.showing,"valid same-node response endpoint was not saved");selected=store(editor).get(selected.id);String saved=AndroidStandardExitStore.snapshot(selected);
  check(selected.responseProbe.getString("url").equals("https://203.0.113.20:8443/response")&&selected.responseProbe.getString("server_name").equals("external.example.test"),"response identity changed during save");
  invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;check(field(form,urlHint).getText().toString().equals(selected.responseProbe.getString("url")),"response endpoint missing after reopen");form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"response roundtrip changed saved policy or credentials");
  for(String[] invalid:new String[][]{{urlHint,"https://203.0.113.21:8443/response"},{urlHint,"http://203.0.113.20/response"},{urlHint,"https://203.0.113.20/response?owner=other"},{nameHint,"localhost"},{nameHint,"8.8.8.8"}}){
   invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;field(form,invalid[0]).setText(invalid[1]);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"invalid response identity changed private profile: "+invalid[1]);form.dismiss();
  }
  String[] executions={"local","server","auto"};for(int choice=0;choice<executions.length;choice++)for(String scenario:new String[]{"current","recreated","altered"}){
   Path directory=Files.createTempDirectory(root,"external-execution-permission-");StandardExitActivity picker=activity(directory,null);AndroidNodeStore.Node entry=node(directory);AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(selected);store(picker).save(exit);
   invoke(picker,"chooseExecution",entry,exit,"wg");AlertDialog execution=AlertDialog.last;check(execution.itemsVisible()&&Arrays.equals(execution.items,new String[]{"Local","Server","Compare both"}),"supported external execution choices are not visible");execution.clickItem(choice);
   Bundle pending=new Bundle();picker.onSaveInstanceState(pending);check(pending.getString("pending_execution","").equals(executions[choice]),"Android permission omitted captured execution");
   if(scenario.equals("altered"))pending.putString("pending_execution",executions[(choice+1)%executions.length]);if(!scenario.equals("current"))picker=activity(directory,pending);picker.onActivityResult(2101,Activity.RESULT_OK,null);
   AndroidStandardExitRuntime run=AndroidRuntimeRegistry.get(picker).standardExit;if(scenario.equals("altered")){check(run.starts==0,"restored permission borrowed a different execution");continue;}
   check(run.starts==1&&run.execution.equals(executions[choice])&&run.mode.equals("wg")&&run.entry.equals(entry.file),"permission launch replaced chosen external execution");check(AndroidConnectionProfileStore.executions.get(directory.toString()).equals(executions[choice]),"saved path omitted execution");
  }
  Path directory=Files.createTempDirectory(root,"external-execution-select-");StandardExitActivity picker=activity(directory,null);AndroidNodeStore.Node entry=node(directory);AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(selected);store(picker).save(exit);picker.intent.putExtra(StandardExitActivity.EXTRA_SELECT_PATH,true);invoke(picker,"chooseExecution",entry,exit,"wg");AlertDialog.last.clickItem(2);
  check(picker.finished&&AndroidRuntimeRegistry.get(picker).standardExit.starts==0&&"auto".equals(AndroidConnectionProfileStore.executions.get(directory.toString())),"selection-only Compare did not persist without starting VPN");
 }
 static JSONObject packetServerPeer()throws Exception{return new JSONObject().put("public_key","bBq3qZ0192YFNiixFZqNRUwTqYBvfydnB3GJrDJliAg=").put("addresses",new JSONArray().put("10.94.0.3/32").put("fd94::3/128")).put("mtu",1360).put("persistent_keepalive_interval",25);}
 static void packetExecutionForms()throws Exception{
  String hint="Public Server peer descriptor JSON (optional for Local)",urlHint="This server's HTTPS response URL (required for Server / Compare both)";
  for(String protocol:new String[]{"wireguard","amneziawg"})for(int layer=0;layer<3;layer++){
   Path directory=Files.createTempDirectory(root,"packet-form-");StandardExitActivity editor=activity(directory,null);AndroidStandardExitStore.Entry original=ordinary(protocol);original.wgMtu=1280;original.policy=AndroidExternalPolicy.editorPolicy(null);store(editor).save(original);String originalSnapshot=AndroidStandardExitStore.snapshot(original);
   invoke(editor,"showExternalPolicyForm",original);AlertDialog form=AlertDialog.last;field(form,hint).setText(packetServerPeer().toString());field(form,urlHint).setText("https://203.0.113.20:8443/response");field(form,"Response TLS server name (optional)").setText("external.example.test");spinner(form,"Off").setSelection(layer);
   if(layer!=0){field(form,"Provisioned private service API URL").setText("http://10.99.0.1:8787");field(form,"Provisioned AES port").setText("8388");field(form,"Provisioned AES-256-GCM key").setText(Base64.getEncoder().encodeToString("l".repeat(32).getBytes(StandardCharsets.UTF_8)));}
   form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing,"packet descriptor form failed actual native validation: "+protocol+" "+displayed(form.view));AndroidStandardExitStore.Entry selected=store(editor).get(original.id);String saved=AndroidStandardExitStore.snapshot(selected);
   check(selected.serverPeer.getString("public_key").equals(packetServerPeer().getString("public_key"))&&selected.serverPeer.getInt("mtu")==1360&&selected.wgPrivateKey.equals(original.wgPrivateKey),"packet editor mixed Local and Server peer ownership");check(originalSnapshot.equals(AndroidStandardExitStore.snapshot(original)),"packet editor mutated its input capture");
   invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;check(field(form,hint).getText().toString().equals(selected.serverPeer.toString()),"packet descriptor missing after reopening");form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"packet descriptor or selected Start Layer changed on settings roundtrip");
   for(String invalid:new String[]{"null",packetServerPeer().put("private_key","forbidden server secret").toString(),packetServerPeer().put("mtu",JSONObject.NULL).toString(),packetServerPeer().put("addresses",new JSONArray().put("10.93.0.2/24").put("fd94::3/128")).toString()}){
    invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;field(form,hint).setText(invalid);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"invalid public packet descriptor changed saved private node");form.dismiss();
   }
   for(int execution=0;execution<3;execution++){
    Path target=Files.createTempDirectory(root,"packet-permission-");StandardExitActivity picker=activity(target,null);AndroidNodeStore.Node entry=node(target);AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(selected);store(picker).save(exit);invoke(picker,"chooseExecution",entry,exit,"wg");AlertDialog menu=AlertDialog.last;check(menu.itemsVisible()&&menu.items.length==3,"packet execution menu unavailable");menu.clickItem(execution);Bundle state=new Bundle();picker.onSaveInstanceState(state);StandardExitActivity restored=activity(target,state);restored.onActivityResult(2101,Activity.RESULT_OK,null);AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.get(restored).standardExit;
    check(runtime.starts==1&&runtime.execution.equals(new String[]{"local","server","auto"}[execution])&&runtime.exit.serverPeer.toString().equals(exit.serverPeer.toString())&&runtime.exit.wgPrivateKey.equals(exit.wgPrivateKey),"permission restoration substituted packet descriptor, private key or execution");
   }
  }
  for(String change:new String[]{"replacement","deletion","new-conflict","before-open"}){
   StandardExitActivity editor=activity(Files.createTempDirectory(root,"packet-stale-form-"),null);AndroidStandardExitStore.Entry selected=ordinary("wireguard");selected.policy=AndroidExternalPolicy.editorPolicy(null);selected.serverPeer=packetServerPeer();
   if(!change.equals("new-conflict"))store(editor).save(selected);
   if(change.equals("before-open")){store(editor).remove(selected.id);AlertDialog previous=AlertDialog.last;invoke(editor,"showExternalPolicyForm",selected);check(AlertDialog.last==previous&&store(editor).list().isEmpty(),"stale external editor resurrected a node deleted before opening");continue;}
   invoke(editor,"showExternalPolicyForm",selected);AlertDialog form=AlertDialog.last;
   AndroidStandardExitStore otherStore=new AndroidStandardExitStore(editor);if(change.equals("deletion"))otherStore.remove(selected.id);else{AndroidStandardExitStore.Entry newer=AndroidStandardExitStore.copy(selected);newer.serverPeer.put("mtu",1400);otherStore.save(newer);}
   String current=otherStore.storedSnapshot(selected.id);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(form.showing&&current.equals(otherStore.storedSnapshot(selected.id)),"stale external editor overwrote another owner or resurrected deletion: "+change);form.dismiss();
  }
 }
 static void openVPNExecutionForms()throws Exception{
  JSONObject fixtures=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_OPENVPN_CLIENT_FIXTURE")))).getJSONObject("layers");String[] layers={"off","aes-256-gcm","aes-256-gcm+xor-whitening"};String hint="Private OpenVPN pairing JSON (optional for Local)";
  for(int layer=0;layer<layers.length;layer++){
   JSONObject external=fixtures.getJSONObject(layers[layer]).getJSONObject("external"),original=external.getJSONObject("openvpn");
   Path directory=Files.createTempDirectory(root,"openvpn-pairing-form-");StandardExitActivity editor=activity(directory,null);AndroidStandardExitStore.Entry selected=ordinary("openvpn");selected.openVPNConfig=original.getString("config");selected.username=original.getString("username");selected.password=original.getString("password");selected.expectedPublicIp=external.getString("expected_public_ip");selected.policy=AndroidExternalPolicy.editorPolicy(null);store(editor).save(selected);String before=AndroidStandardExitStore.snapshot(selected);
   invoke(editor,"showExternalPolicyForm",selected);AlertDialog form=AlertDialog.last;String pairing=external.getJSONObject("openvpn_pairing").toString();field(form,hint).setText(pairing);field(form,"This server's HTTPS response URL (required for Server / Compare both)").setText(external.getJSONObject("response_probe").getString("url"));field(form,"Response TLS server name (optional)").setText("provider.example");spinner(form,"Off").setSelection(layer);
   if(layer!=0){JSONObject provision=external.getJSONObject("start_layer"),transport=provision.getJSONObject("transport");field(form,"Provisioned private service API URL").setText(provision.getString("api"));field(form,"Provisioned AES port").setText(transport.getString("server_port"));field(form,"Provisioned AES-256-GCM key").setText(transport.getString("password"));}
   form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing,"OpenVPN private pairing form failed native validation: "+displayed(form.view));check(before.equals(AndroidStandardExitStore.snapshot(selected)),"OpenVPN editor aliased its input capture");selected=store(editor).get(selected.id);String saved=AndroidStandardExitStore.snapshot(selected);
   check(selected.openVPNConfig.equals(original.getString("config"))&&selected.username.equals(original.getString("username"))&&selected.password.equals(original.getString("password"))&&same(selected.openVPNPairing.toString(),pairing),"OpenVPN form changed original source, credentials or private pairing");
   invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;check(same(field(form,hint).getText().toString(),pairing),"OpenVPN pairing missing after reopening");form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"OpenVPN private pairing settings did not roundtrip");
   for(String invalid:new String[]{"null",pairing+" {}",pairing.substring(0,pairing.length()-1)+",\"unknown\":true}",pairing.substring(0,pairing.length()-1)+",\"private_key\":\""+external.getJSONObject("openvpn_pairing").getString("private_key")+"\"}"}){
    invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;field(form,hint).setText(invalid);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"invalid raw OpenVPN pairing overwrote the private node");form.dismiss();
   }
   for(int execution=0;execution<3;execution++){
    Path target=Files.createTempDirectory(root,"openvpn-pairing-permission-");StandardExitActivity picker=activity(target,null);AndroidNodeStore.Node entry=node(target);AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(selected);store(picker).save(exit);invoke(picker,"chooseExecution",entry,exit,"wg");AlertDialog menu=AlertDialog.last;check(menu.itemsVisible()&&menu.items.length==3,"OpenVPN Local/Server/Compare menu unavailable");menu.clickItem(execution);Bundle state=new Bundle();picker.onSaveInstanceState(state);StandardExitActivity restored=activity(target,state);restored.onActivityResult(2101,Activity.RESULT_OK,null);AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.get(restored).standardExit;
    check(runtime.starts==1&&runtime.execution.equals(new String[]{"local","server","auto"}[execution])&&same(runtime.exit.openVPNPairing.toString(),pairing)&&runtime.exit.openVPNConfig.equals(exit.openVPNConfig)&&runtime.exit.password.equals(exit.password),"OpenVPN permission restoration substituted private pairing, source, credentials or execution");
   }
  }
 }
 static JSONObject openVPNProbeMap()throws Exception{return new JSONObject().put("203.0.113.20",new JSONObject().put("url","https://203.0.113.20:8443/response").put("server_name","provider.example")).put("203.0.113.21",new JSONObject().put("url","https://203.0.113.21:9443/response").put("server_name","other-provider.example"));}
 static void openVPNResponseMaps()throws Exception{
  String hint="OpenVPN per-remote HTTPS response map JSON (optional)",singleHint="This server's HTTPS response URL (required for Server / Compare both)";
  JSONObject source=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_OPENVPN_CLIENT_FIXTURE")))).getJSONObject("layers").getJSONObject("off").getJSONObject("external").getJSONObject("openvpn");
  Path directory=Files.createTempDirectory(root,"openvpn-remote-map-");StandardExitActivity editor=activity(directory,null);AndroidStandardExitStore.Entry selected=ordinary("openvpn");
  selected.openVPNConfig=source.getString("config").replace("remote 203.0.113.20 443 tcp","remote 203.0.113.21 443 tcp");selected.username=source.getString("username");selected.password=source.getString("password");selected.policy=policy("custom","tcp");store(editor).save(selected);String before=AndroidStandardExitStore.snapshot(selected),raw=openVPNProbeMap().toString();
  invoke(editor,"showExternalPolicyForm",selected);AlertDialog form=AlertDialog.last;field(form,hint).setText(raw);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing,"OpenVPN remote map failed shared idle validation: "+displayed(form.view));
  check(before.equals(AndroidStandardExitStore.snapshot(selected)),"OpenVPN remote map editor aliased its source");selected=store(editor).get(selected.id);String saved=AndroidStandardExitStore.snapshot(selected);
  check(same(raw,selected.openVPNResponseProbes.toString())&&selected.openVPNConfig.equals(source.getString("config").replace("remote 203.0.113.20 443 tcp","remote 203.0.113.21 443 tcp"))&&selected.username.equals(source.getString("username"))&&selected.password.equals(source.getString("password")),"OpenVPN map changed private original transport or credentials");
  JSONObject captured=AndroidExternalPolicy.profile(selected);check(same(raw,captured.getJSONObject("external").getJSONObject("openvpn_response_probes").toString()),"OpenVPN private map lost from native capture");
  JSONObject graph=new JSONObject(AndroidExternalPolicy.compile(selected,null,"external").config);JSONArray remotes=graph.getJSONArray("endpoints").getJSONObject(0).getJSONArray("servers");check(remotes.length()==2&&remotes.getJSONObject(1).getString("server").equals("203.0.113.21"),"OpenVPN map flattened Local multiremote transport");
  check(!selected.summary().has("openvpn_response_probes")&&!selected.summary().toString().contains("other-provider.example"),"private OpenVPN remote map entered public node summary");
  AndroidStandardExitStore.Entry copy=AndroidStandardExitStore.copy(selected);copy.openVPNResponseProbes.getJSONObject("203.0.113.21").put("url","https://203.0.113.21:9443/replaced");check(saved.equals(AndroidStandardExitStore.snapshot(selected)),"OpenVPN snapshot borrowed mutable response map");
  invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;check(same(raw,field(form,hint).getText().toString()),"OpenVPN remote map missing after reopening");form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing&&same(saved,AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"OpenVPN remote map changed on an unrelated settings save");selected=store(editor).get(selected.id);saved=AndroidStandardExitStore.snapshot(selected);
  // Android JSON preserves insertion order, while the fallback test jar uses a
  // HashMap. An accepted edit can reorder policy members without changing data;
  // after this semantic roundtrip, rejected edits must preserve exact bytes.
  for(String changedField:new String[]{"dns","mtu","probe","credential"}){JSONObject changed=new JSONObject(saved);if(changedField.equals("dns"))changed.getJSONObject("policy").put("dns_host","8.8.8.8");if(changedField.equals("mtu"))changed.getJSONObject("policy").put("manual_mtu",1281);if(changedField.equals("probe"))changed.getJSONObject("openvpn_response_probes").getJSONObject("203.0.113.21").put("url","https://203.0.113.21/replaced");if(changedField.equals("credential"))changed.put("password","different-private-password");check(!same(saved,changed.toString()),"semantic roundtrip ignored changed "+changedField);}
  String duplicate=raw.substring(0,raw.length()-1)+",\"203.0.113.20\":"+openVPNProbeMap().getJSONObject("203.0.113.20").toString()+"}";
  String urlMember=JSONObject.quote("url")+":"+JSONObject.quote("https://203.0.113.20:8443/response"),duplicateURL=raw.replace(urlMember,urlMember+","+urlMember);check(!duplicateURL.equals(raw),"duplicate endpoint fixture did not change raw bytes");
  JSONObject wrongHost=openVPNProbeMap();wrongHost.getJSONObject("203.0.113.21").put("url","https://203.0.113.22:9443/response");int invalidIndex=0;
  for(String invalid:new String[]{"null","{}",raw+" {}",duplicate,duplicateURL,raw.replace("\"url\":","\"unexpected\":true,\"url\":"),wrongHost.toString(),new JSONObject().put("203.0.113.20",openVPNProbeMap().getJSONObject("203.0.113.20")).toString()}){
   invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;field(form,hint).setText(invalid);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"malformed OpenVPN remote map changed saved private node, case "+invalidIndex++);form.dismiss();
  }
  invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;field(form,singleHint).setText("https://203.0.113.20:8443/response");form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"OpenVPN map accepted a competing single response endpoint");form.dismiss();
  AndroidStandardExitStore.Entry layered=AndroidStandardExitStore.copy(selected);layered.policy.put("start_layer","aes-256-gcm");boolean rejected=false;try{AndroidOpenVPN.validateResponseProbes(layered);}catch(Exception expected){rejected=true;}check(rejected,"multi-host OpenVPN map borrowed a single-server exit layer");
  AndroidStandardExitStore.Entry wrong=ordinary("shadowsocks");wrong.openVPNResponseProbes=openVPNProbeMap();rejected=false;try{AndroidStandardExitStore.validate(wrong);}catch(Exception expected){rejected=true;}check(rejected,"OpenVPN response map attached to another protocol");
  Path storeFile=directory.resolve("standard-exits.json");byte[] stored=Files.readAllBytes(storeFile);String malformed="{\"schema_version\":1,\"exits\":["+saved.replace(raw,duplicate)+"]}";check(!malformed.equals("{\"schema_version\":1,\"exits\":["+saved+"]}"),"duplicate stored map fixture did not change raw bytes");Files.writeString(storeFile,malformed);rejected=false;try{store(editor).get(selected.id);}catch(Exception expected){rejected=true;}check(rejected,"private store collapsed duplicate OpenVPN response hosts before validation");Files.write(storeFile,stored);
  byte[] invalidUTF8=Arrays.copyOf(stored,stored.length+1);invalidUTF8[stored.length]=(byte)0xff;Files.write(storeFile,invalidUTF8);rejected=false;try{store(editor).get(selected.id);}catch(Exception expected){rejected=true;}check(rejected,"private store replaced invalid UTF-8 before response-map validation");Files.write(storeFile,stored);
  check(saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"OpenVPN source changed during rejected map edits");
  JSONObject pairedSource=new JSONObject(Files.readString(Path.of(System.getenv("ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE")))).getJSONObject("external"),pairedInline=pairedSource.getJSONObject("openvpn");
  StandardExitActivity pairedEditor=activity(Files.createTempDirectory(root,"openvpn-paired-remote-map-"),null);AndroidStandardExitStore.Entry paired=ordinary("openvpn");paired.openVPNConfig=pairedInline.getString("config");paired.username=pairedInline.getString("username");paired.password=pairedInline.getString("password");paired.expectedPublicIp=pairedSource.getString("expected_public_ip");paired.policy=policy("custom","tcp");store(pairedEditor).save(paired);
  invoke(pairedEditor,"showExternalPolicyForm",paired);form=AlertDialog.last;field(form,"Private OpenVPN pairing JSON (optional for Local)").setText(pairedSource.getJSONObject("openvpn_pairing").toString());field(form,hint).setText(pairedSource.getJSONObject("openvpn_response_probes").toString());form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing,"paired multi-host OpenVPN editor failed private idle validation: "+displayed(form.view));
  paired=store(pairedEditor).get(paired.id);JSONObject pairedCapture=AndroidExternalPolicy.profile(paired).getJSONObject("external");check(same(pairedCapture.getJSONObject("openvpn_pairing").toString(),pairedSource.getJSONObject("openvpn_pairing").toString())&&same(pairedCapture.getJSONObject("openvpn_response_probes").toString(),pairedSource.getJSONObject("openvpn_response_probes").toString()),"paired multi-host map or private independent identity lost in native capture");
  for(int execution=0;execution<3;execution++)for(boolean recreate:new boolean[]{false,true}){
   Path target=Files.createTempDirectory(root,"openvpn-mapped-permission-");StandardExitActivity picker=activity(target,null);AndroidNodeStore.Node owned=node(target);AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(paired);store(picker).save(exit);String frozen=AndroidStandardExitStore.snapshot(exit);
   invoke(picker,"chooseExecution",owned,exit,"max-quic-awg");AlertDialog menu=AlertDialog.last;check(menu.itemsVisible()&&menu.items.length==3,"mapped OpenVPN execution choices unavailable");menu.clickItem(execution);Bundle state=new Bundle();picker.onSaveInstanceState(state);if(recreate)picker=activity(target,state);picker.onActivityResult(2101,Activity.RESULT_OK,null);AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.get(picker).standardExit;
   check(runtime.starts==1&&runtime.execution.equals(new String[]{"local","server","auto"}[execution])&&runtime.mode.equals("max-quic-awg"),"mapped OpenVPN permission changed captured entry mode or execution");
   check(same(runtime.exit.openVPNResponseProbes.toString(),paired.openVPNResponseProbes.toString())&&same(runtime.exit.openVPNPairing.toString(),paired.openVPNPairing.toString())&&runtime.exit.openVPNConfig.equals(paired.openVPNConfig)&&frozen.equals(AndroidStandardExitStore.snapshot(store(picker).get(exit.id))),"mapped permission substituted private map, pairing or saved source");
  }
  for(boolean recreate:new boolean[]{false,true}){
   Path target=Files.createTempDirectory(root,"openvpn-mapped-stale-permission-");StandardExitActivity picker=activity(target,null);AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(paired);store(picker).save(exit);invoke(picker,"chooseExecution",node(target),exit,"wg");AlertDialog.last.clickItem(2);Bundle state=new Bundle();picker.onSaveInstanceState(state);AndroidStandardExitStore.Entry changed=store(picker).get(exit.id);String host=changed.openVPNResponseProbes.names().getString(0);changed.openVPNResponseProbes.getJSONObject(host).put("url","https://"+host+"/new-owner");store(picker).save(changed);if(recreate)picker=activity(target,state);picker.onActivityResult(2101,Activity.RESULT_OK,null);
   check(AndroidRuntimeRegistry.get(picker).standardExit.starts==0,"permission restored an obsolete mapped OpenVPN owner");
  }

 }
 static void openVPNLayerMaps()throws Exception{
  String hint="Private OpenVPN per-remote Start Layer map JSON (optional)",probeHint="OpenVPN per-remote HTTPS response map JSON (optional)",pairHint="Private OpenVPN pairing JSON (optional for Local)";
  String[] modes={"aes-256-gcm","aes-256-gcm+xor-whitening"};
  for(int index=0;index<modes.length;index++){
   String mode=modes[index];JSONObject fixture=new JSONObject(Files.readString(Path.of(System.getenv(index==0?"ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE":"ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE")))),external=fixture.getJSONObject("external"),inline=external.getJSONObject("openvpn"),layers=external.getJSONObject("openvpn_start_layers");String raw=layers.toString();
   Path directory=Files.createTempDirectory(root,"openvpn-layer-map-form-");StandardExitActivity editor=activity(directory,null);AndroidStandardExitStore.Entry original=ordinary("openvpn");original.openVPNConfig=inline.getString("config");original.username=inline.getString("username");original.password=inline.getString("password");original.expectedPublicIp=external.getString("expected_public_ip");original.policy=policy("custom","tcp");store(editor).save(original);String originalSnapshot=AndroidStandardExitStore.snapshot(original);
   invoke(editor,"showExternalPolicyForm",original);AlertDialog form=AlertDialog.last;EditText privateMap=field(form,hint);check(!privateMap.isSaveEnabled()&&privateMap.getImportantForAutofill()==View.IMPORTANT_FOR_AUTOFILL_NO,"private OpenVPN layer keys entered Android saved/autofill state");
   field(form,pairHint).setText(external.getJSONObject("openvpn_pairing").toString());field(form,probeHint).setText(external.getJSONObject("openvpn_response_probes").toString());privateMap.setText(raw);spinner(form,"Off").setSelection(index+1);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   check(!form.showing,"OpenVPN per-remote layer form failed native validation: "+mode+" "+displayed(form.view));check(privateMap.getText().length()==0,"OpenVPN layer keys survived dialog dismissal");check(originalSnapshot.equals(AndroidStandardExitStore.snapshot(original)),"layer-map form aliased its source");
   AndroidStandardExitStore.Entry selected=store(editor).get(original.id);String saved=AndroidStandardExitStore.snapshot(selected);check(same(raw,selected.openVPNStartLayers.toString())&&selected.policy.getString("start_layer").equals(mode)&&selected.startLayer==null&&selected.responseProbe.length()==0,"layer-map form mixed singular and per-remote ownership");
   check(selected.openVPNConfig.equals(inline.getString("config"))&&selected.username.equals(inline.getString("username"))&&selected.password.equals(inline.getString("password")),"layer-map form rewrote original OpenVPN transport or credentials");check(!selected.summary().has("openvpn_start_layers")&&!selected.summary().toString().contains(layers.getJSONObject("203.0.113.20").getJSONObject("transport").getString("password")),"per-remote layer keys entered public node summary");
   JSONObject capture=AndroidExternalPolicy.profile(selected);check(same(raw,capture.getJSONObject("external").getJSONObject("openvpn_start_layers").toString()),"native capture omitted per-remote layers");
   invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;check(same(raw,field(form,hint).getText().toString())&&field(form,"Provisioned private service API URL").getText().length()==0&&field(form,"Provisioned AES-256-GCM key").getText().length()==0,"reopened layer map became a singular provision");form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing&&same(saved,AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"per-remote layer map changed on unrelated save");selected=store(editor).get(selected.id);saved=AndroidStandardExitStore.snapshot(selected);
   String duplicate=raw.substring(0,raw.length()-1)+",\"203.0.113.20\":"+layers.getJSONObject("203.0.113.20")+"}";JSONObject missing=new JSONObject(raw);missing.remove("203.0.113.21");JSONObject foreign=new JSONObject(raw);foreign.put("203.0.113.22",foreign.remove("203.0.113.21"));JSONObject wrongServer=new JSONObject(raw);wrongServer.getJSONObject("203.0.113.21").getJSONObject("transport").put("server","203.0.113.20");JSONObject wrongMode=new JSONObject(raw);wrongMode.getJSONObject("203.0.113.21").put("mode",index==0?modes[1]:modes[0]);
   for(String invalid:new String[]{"null","{}","[]",raw+" {}",duplicate,missing.toString(),foreign.toString(),wrongServer.toString(),wrongMode.toString(),raw.replace("\"api\":","\"unknown\":true,\"api\":"),raw.replace("\"api\":","\"api\":null,\"api\":"),raw+" ".repeat(131073)}){
    invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;field(form,hint).setText(invalid);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"malformed OpenVPN layer map changed saved private node");form.dismiss();
   }
   for(String conflict:new String[]{"singular","off","missing-probes","missing-layers"}){
    invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;if(conflict.equals("singular"))field(form,"Provisioned private service API URL").setText("http://10.93.0.1:8787");if(conflict.equals("off"))spinner(form,"Off").setSelection(0);if(conflict.equals("missing-probes"))field(form,probeHint).setText("");if(conflict.equals("missing-layers"))field(form,hint).setText("");form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(form.showing&&saved.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"conflicting per-remote layer selection changed saved node: "+conflict);form.dismiss();
   }
   AndroidStandardExitStore.Entry cloned=AndroidStandardExitStore.copy(selected);cloned.openVPNStartLayers.getJSONObject("203.0.113.20").put("api","http://10.93.0.2:8787");check(saved.equals(AndroidStandardExitStore.snapshot(selected)),"private layer map aliased a mutable snapshot");
   for(int execution=0;execution<3;execution++)for(boolean recreate:new boolean[]{false,true}){
    Path target=Files.createTempDirectory(root,"openvpn-layer-map-permission-");StandardExitActivity picker=activity(target,null);AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(selected);store(picker).save(exit);invoke(picker,"chooseExecution",node(target),exit,"max-quic-awg");AlertDialog.last.clickItem(execution);Bundle state=new Bundle();picker.onSaveInstanceState(state);if(recreate)picker=activity(target,state);picker.onActivityResult(2101,Activity.RESULT_OK,null);AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.get(picker).standardExit;
    check(runtime.starts==1&&runtime.execution.equals(new String[]{"local","server","auto"}[execution])&&runtime.mode.equals("max-quic-awg")&&same(raw,runtime.exit.openVPNStartLayers.toString())&&runtime.exit.policy.getString("start_layer").equals(mode),"permission restoration substituted per-remote layer owner or execution");
   }
   for(String mutation:new String[]{"api","key"})for(boolean recreate:new boolean[]{false,true}){
    Path target=Files.createTempDirectory(root,"openvpn-layer-map-stale-");StandardExitActivity picker=activity(target,null);AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(selected);store(picker).save(exit);invoke(picker,"chooseExecution",node(target),exit,"wg");AlertDialog.last.clickItem(2);Bundle state=new Bundle();picker.onSaveInstanceState(state);AndroidStandardExitStore.Entry replacement=store(picker).get(exit.id);JSONObject provision=replacement.openVPNStartLayers.getJSONObject("203.0.113.21");if(mutation.equals("api"))provision.put("api","http://10.93.0.2:8787");else provision.getJSONObject("transport").put("password",Base64.getEncoder().encodeToString("q".repeat(32).getBytes(StandardCharsets.UTF_8)));store(picker).save(replacement);if(recreate)picker=activity(target,state);picker.onActivityResult(2101,Activity.RESULT_OK,null);check(AndroidRuntimeRegistry.get(picker).standardExit.starts==0,"permission restored a replaced per-remote layer owner");
   }
   invoke(editor,"showExternalPolicyForm",selected);form=AlertDialog.last;AndroidStandardExitStore.Entry newer=AndroidStandardExitStore.copy(selected);newer.openVPNStartLayers.getJSONObject("203.0.113.20").put("api","http://10.93.0.2:8787");store(editor).save(newer);String newerSnapshot=AndroidStandardExitStore.snapshot(newer);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(form.showing&&newerSnapshot.equals(AndroidStandardExitStore.snapshot(store(editor).get(selected.id))),"stale layer-map editor overwrote replacement keys");form.dismiss();
   invoke(editor,"showExternalPolicyForm",newer);form=AlertDialog.last;field(form,hint).setText("");spinner(form,"Off").setSelection(0);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing&&store(editor).get(selected.id).openVPNStartLayers==null&&store(editor).get(selected.id).policy.getString("start_layer").equals("off")&&store(editor).get(selected.id).openVPNResponseProbes!=null,"explicit Off did not clear only the private layer map");
  }
 }
 static void ordinaryPolicies()throws Exception{
  int ordinaryRoundtrips=0;
  for(String kind:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"})for(String dns:new String[]{"rescue","tcp","dot","doh","doh3"}){
   if(dns.equals("doh3")&&(kind.equals("http")||kind.equals("https")))continue;
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"ordinary-form-"),null);AndroidStandardExitStore.Entry selected=ordinary(kind);
   selected.policy=policy(dns.equals("tcp")?"custom":dns,dns.equals("rescue")?"tcp":dns);selected.policy.put("effective_mtu",8800);
   store(activity).save(selected);String before=AndroidStandardExitStore.snapshot(selected);String compiled=AndroidExternalPolicy.compile(selected,null,"external").config;
   invoke(activity,"showExitActions",selected);AlertDialog actions=AlertDialog.last;check(actions.itemsVisible()&&actions.items.length==5&&actions.items[2].contains("DNS")&&actions.items[3].equals("Compare DNS on this connected path"),"ordinary policy settings are unreachable");actions.clickItem(2);AlertDialog editor=AlertDialog.last;
   check(editor.showing&&editor.title.toString().contains("Connection settings"),"ordinary policy form was not opened");
   editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!editor.showing,"saved ordinary policy roundtrip rejected: "+kind+"/"+dns+" "+displayed(editor.view));
   AndroidStandardExitStore.Entry after=store(activity).get(selected.id);check(compiled.equals(AndroidExternalPolicy.compile(after,null,"external").config),"ordinary form replaced selected DNS or interface policy");
   check(before.equals(AndroidStandardExitStore.snapshot(selected)),"ordinary form aliased the saved credentials or policy");check(!after.policy.has("effective_mtu"),"ordinary form kept stale current-path MTU");ordinaryRoundtrips++;
  }
  StandardExitActivity activity=activity(Files.createTempDirectory(root,"ordinary-home-"),null);AndroidStandardExitStore.Entry selected=ordinary("socks5");selected.policy=AndroidExternalPolicy.editorPolicy(null);store(activity).save(selected);
  invoke(activity,"showExternalPolicyForm",selected);AlertDialog home=AlertDialog.last;check(spinner(home,"Home AdGuard through captured Router VPN entry").getSelectedItemPosition()==0,"Home was silently replaced in editor");home.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!home.showing&&store(activity).get(selected.id).policy.getString("dns_mode").equals("home"),"Home failed private persistence");
  boolean rejected=false;try{AndroidExternalPolicy.compile(store(activity).get(selected.id),null,"external");}catch(Exception expected){rejected=true;}check(rejected,"direct Home silently fell back to public DNS");
  JSONObject entry=MultihopGraphHarness.bundle('a');JSONObject entryProfile=entry.getJSONArray("routerProfiles").getJSONObject(0);entryProfile.put("node_proof_id",entry.getString("nodeProofId")).put("adguard_ipv6","fd50::53");
  selected=store(activity).get(selected.id);selected.policy.put("dns_host","fd50::53").put("dns_protocol","tcp").put("dns_port",5353);store(activity).save(selected);
  String selectedHomeGraph=AndroidExternalPolicy.compile(selected,entry,"wg").config;
  invoke(activity,"showExternalPolicyForm",selected);AlertDialog explicitHome=AlertDialog.last;explicitHome.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!explicitHome.showing,"explicit Home resolver was rejected on unrelated save");
  AndroidStandardExitStore.Entry preservedHome=store(activity).get(selected.id);check(preservedHome.policy.getString("dns_host").equals("fd50::53")&&preservedHome.policy.getString("dns_protocol").equals("tcp")&&preservedHome.policy.getInt("dns_port")==5353,"Home editor replaced explicit IPv6/TCP/nonstandard port");
  check(selectedHomeGraph.equals(AndroidExternalPolicy.compile(preservedHome,entry,"wg").config),"Home editor changed the actual native selected DNS graph");
  selected=store(activity).get(selected.id);String before=AndroidStandardExitStore.snapshot(selected);invoke(activity,"showExternalPolicyForm",selected);AlertDialog invalid=AlertDialog.last;field(invalid,"Fixed MTU 1280–9000 (blank: Auto baseline)").setText("9001");invalid.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(invalid.showing&&before.equals(AndroidStandardExitStore.snapshot(store(activity).get(selected.id))),"invalid ordinary MTU overwrote the saved policy");invalid.dismiss();
  invoke(activity,"showExternalPolicyForm",selected);AlertDialog active=AlertDialog.last;AndroidVpnMutationGuard.busy=true;active.getButton(AlertDialog.BUTTON_POSITIVE).performClick();AndroidVpnMutationGuard.busy=false;check(active.showing&&before.equals(AndroidStandardExitStore.snapshot(store(activity).get(selected.id))),"ordinary editor changed a live capture");active.dismiss();
  for(String mutation:new String[]{"exit","denied"}){StandardExitActivity pending=activity(Files.createTempDirectory(root,"ordinary-permission-"),null);AndroidStandardExitStore.Entry e=ordinary("socks5");e.policy.put("dns_mode","rescue");store(pending).save(e);invoke(pending,"requestDirect",e);if(mutation.equals("exit")){e.policy.put("dns_mode","home");store(pending).save(e);}pending.onActivityResult(2101,mutation.equals("denied")?0:Activity.RESULT_OK,null);check(AndroidRuntimeRegistry.get(pending).standardExit.starts==0,"permission adopted changed external policy");}
  for(String kind:new String[]{"wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"})for(String mode:ALL){
   Path directory=Files.createTempDirectory(root,"ordinary-mode-");StandardExitActivity picker=activity(directory,null);AndroidNodeStore.Node owned=node(directory);AndroidStandardExitStore.Entry e=ordinary(kind);e.policy.put("dns_mode","rescue");store(picker).save(e);
   invoke(picker,"chooseEntry",e);AlertDialog.last.clickItem(0);AlertDialog modes=AlertDialog.last;check(modes.itemsVisible()&&modes.items.length==19,"ordinary external mode picker omitted a captured entry");int index=-1;for(int i=0;i<modes.items.length;i++)if(modes.items[i].endsWith("["+mode+"]"))index=i;check(index>=0,"ordinary entry mode unavailable: "+mode);modes.clickItem(index);
   if(List.of("wireguard","amneziawg","shadowsocks","hysteria2","socks5","http","https","openvpn").contains(kind)){AlertDialog execution=AlertDialog.last;check(execution.itemsVisible()&&Arrays.equals(execution.items,new String[]{"Local","Server","Compare both"}),"external execution choices disappeared");execution.clickItem(0);}
   picker.onActivityResult(2101,Activity.RESULT_OK,null);
   AndroidStandardExitRuntime run=AndroidRuntimeRegistry.get(picker).standardExit;check(run.starts==1&&run.mode.equals(mode)&&run.entry.equals(owned.file)&&run.exit.protocol.equals(kind),"ordinary permission handoff changed selected mode or exit");
  }
  System.out.println("Android ordinary external settings: "+ordinaryRoundtrips+" real Java/Go graph roundtrips plus Home, rejection and permission ownership checks passed");
 }
 static void openVPNForm()throws Exception{
  StandardExitActivity activity=activity(Files.createTempDirectory(root,"openvpn-add-"),null);AndroidStandardExitStore.Entry example=ordinary("openvpn");
  invoke(activity,"showOpenVPNForm");AlertDialog add=AlertDialog.last;EditText config=field(add,"Paste complete inline .ovpn profile"),username=field(add,"Username (when required)"),password=field(add,"Password (when required)");
  field(add,"Display name").setText(example.name);field(add,"Expected public exit IP").setText(example.expectedPublicIp);config.setText(example.openVPNConfig);username.setText(example.username);password.setText(example.password);
  check(!config.isSaveEnabled()&&!username.isSaveEnabled()&&!password.isSaveEnabled(),"OpenVPN form retained private credentials in Android saved state");
  add.getButton(AlertDialog.BUTTON_POSITIVE).performClick();AlertDialog settings=AlertDialog.last;check(!add.showing&&settings.showing&&settings.title.toString().contains("Connection settings"),"OpenVPN skipped its saved policy form");
  check(config.getText().length()==0&&username.getText().length()==0&&password.getText().length()==0,"OpenVPN credential fields survived dismissal");check(store(activity).list().isEmpty(),"OpenVPN was saved before policy capture");
  check(spinner(settings,"Home AdGuard through captured Router VPN entry").getSelectedItemPosition()==0,"new OpenVPN node replaced Home default");settings.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!settings.showing&&store(activity).list().size()==1,"OpenVPN full private profile was not saved");
  AndroidStandardExitStore.Entry saved=store(activity).list().get(0);check(saved.openVPNConfig.equals(example.openVPNConfig)&&saved.username.equals(example.username)&&saved.password.equals(example.password)&&saved.policy.getString("dns_mode").equals("home"),"OpenVPN settings handoff changed config, credentials or selected Home DNS");
  boolean rejected=false;try{AndroidExternalPolicy.compile(saved,null,"external");}catch(Exception expected){rejected=true;}check(rejected,"new direct OpenVPN silently replaced Home DNS without a captured entry");
 }


 static boolean sameParams(JSONObject a,JSONObject b)throws Exception{if(a.length()!=11||b.length()!=11)return false;for(String key:AndroidExternalAmnezia.PARAMETERS)if(!a.get(key).equals(b.get(key)))return false;return true;}
 static void amneziaForm()throws Exception{
  StandardExitActivity activity=activity(Files.createTempDirectory(root,"amnezia-add-"),null);AndroidStandardExitStore.Entry example=ordinary("amneziawg");
  invoke(activity,"chooseProtocol");AlertDialog protocols=AlertDialog.last;check(protocols.itemsVisible()&&protocols.items[0].equals("WireGuard / AmneziaWG"),"WG/AWG family import selector missing");protocols.clickItem(0);AlertDialog family=AlertDialog.last;check(family.itemsVisible()&&family.items.length==2,"AmneziaWG imported through another protocol");family.clickItem(1);
  AlertDialog add=AlertDialog.last;EditText config=field(add,"Paste complete AmneziaWG .conf profile");field(add,"Display name").setText(example.name);field(add,"Expected public exit IP").setText(example.expectedPublicIp);
  String raw="[Interface]\nPrivateKey="+example.wgPrivateKey+"\nAddress="+String.join(",",example.wgAddresses)+"\nMTU=1420\nDNS=9.9.9.9,2620:fe::fe\n";for(String key:AndroidExternalAmnezia.PARAMETERS)raw+=key+"="+example.awgParameters.getString(key)+"\n";raw+="[Peer]\nPublicKey="+example.wgPeerPublicKey+"\nEndpoint=203.0.113.20:443\nAllowedIPs=0.0.0.0/0,::/0\nPersistentKeepalive=17\n";
  check(!config.isSaveEnabled()&&config.getImportantForAutofill()==View.IMPORTANT_FOR_AUTOFILL_NO,"AmneziaWG keys entered Android saved/autofill state");config.setText(raw+"PostUp=bad\n");add.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(add.showing&&store(activity).list().isEmpty(),"invalid AmneziaWG profile reached storage");config.setText(raw);AndroidVpnMutationGuard.busy=true;add.getButton(AlertDialog.BUTTON_POSITIVE).performClick();AndroidVpnMutationGuard.busy=false;check(add.showing&&store(activity).list().isEmpty(),"AmneziaWG import changed an active VPN capture");
  add.getButton(AlertDialog.BUTTON_POSITIVE).performClick();AlertDialog settings=AlertDialog.last;check(!add.showing&&settings.showing&&config.getText().length()==0&&store(activity).list().isEmpty(),"AmneziaWG skipped private policy capture or retained pasted keys");check(spinner(settings,"Home AdGuard through captured Router VPN entry").getSelectedItemPosition()==2&&field(settings,"Selected DNS IP or hostname").getText().toString().equals("9.9.9.9"),"AmneziaWG silently replaced imported DNS selection");settings.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!settings.showing&&store(activity).list().size()==1,"AmneziaWG full profile not saved");
  AndroidStandardExitStore.Entry saved=store(activity).list().get(0);check(saved.protocol.equals("amneziawg")&&sameParams(saved.awgParameters,example.awgParameters)&&saved.wgKeepalive==17&&saved.wgDns.equals(List.of("9.9.9.9","2620:fe::fe")),"AmneziaWG form dropped parameters, keepalive or secondary DNS capture");check(new JSONObject(AndroidExternalPolicy.compile(saved,null,"external").config).getJSONArray("endpoints").getJSONObject(0).getString("type").equals("routervpn-amneziawg"),"saved AmneziaWG did not compile native protocol");
 }
 interface DNSAttempt{void run()throws Exception;}
 static void dnsReject(DNSAttempt action,String reason)throws Exception{boolean rejected=false;try{action.run();}catch(Exception expected){rejected=true;}check(rejected,reason);}
 static Button button(AlertDialog dialog,String text){for(View view:views(dialog.view))if(view instanceof Button&&text.equals(((Button)view).getText().toString()))return (Button)view;throw new AssertionError("Missing DNS button: "+text);}
 static JSONObject dnsReceipt(String node,String mode)throws Exception{
  String[] ids={"cf4a","cf4b","cf6a","cf6b","g4a","g4b","g6a","g6b","q4a","q4b","q6a","q6b"},addresses={"1.1.1.1","1.0.0.1","2606:4700:4700::1111","2606:4700:4700::1001","8.8.8.8","8.8.4.4","2001:4860:4860::8888","2001:4860:4860::8844","9.9.9.9","149.112.112.112","2620:fe::fe","2620:fe::9"},names={"cloudflare-dns.com","dns.google","dns.quad9.net"};
  JSONArray rows=new JSONArray().put(new JSONObject().put("id","selected").put("name","Selected DNS").put("kind","selected").put("address","10.77.0.53").put("port",5353).put("transport","udp").put("route","entry-wg").put("route_label","Selected DNS via entry-wg").put("samples",3).put("failed",0).put("ready",true).put("median_ms",0.1));
  for(int i=0;i<12;i++){JSONObject row=new JSONObject().put("id",ids[i]).put("name",ids[i]).put("kind","public").put("address",addresses[i]).put("port",mode.equals("tcp")?53:mode.equals("tls")?853:443).put("transport",mode).put("route","exit").put("route_label","Current Tor connection").put("samples",3).put("failed",0).put("ready",true).put("median_ms",i==8?2.5:10.0+i);if(!mode.equals("tcp"))row.put("server_name",names[i/4]);if(mode.equals("https"))row.put("path","/dns-query");rows.put(row);}
  JSONObject failed=rows.getJSONObject(5);failed.put("samples",2).put("failed",1).put("ready",false).put("failure","No complete DNS answers");failed.remove("median_ms");
  return new JSONObject().put("schema",1).put("request_id","a".repeat(32)).put("node_id",node).put("session_id","native-dns-session").put("public_transport",mode).put("stage","complete").put("complete",true).put("drained",true).put("results",rows);
 }
 static void dnsDrafts()throws Exception{
  for(String kind:new String[]{"tor","obfs4","socks5"})for(String mode:new String[]{"tcp","tls","https"}){
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"dns-draft-"),null);AndroidStandardExitStore.Entry saved=kind.equals("socks5")?ordinary(kind):tor(kind,"doh");store(activity).save(saved);String before=AndroidStandardExitStore.snapshot(saved);
   JSONObject receipt=dnsReceipt(saved.id,mode);AndroidDNSSelectionDraft draft=AndroidDNSSelectionDraft.create(saved,AndroidDNSSelectionDraft.Path.direct(),receipt,null);check(draft.rowID.equals("q4a"),"fastest chose Home or an unavailable public row");
   dnsReject(()->AndroidDNSSelectionDraft.create(saved,AndroidDNSSelectionDraft.Path.direct(),receipt,"selected"),"selected DNS became a public choice");dnsReject(()->AndroidDNSSelectionDraft.create(saved,AndroidDNSSelectionDraft.Path.direct(),receipt,"g4a"),"failed resolver became a draft");
   JSONObject stale=new JSONObject(receipt.toString()).put("request_id","b".repeat(32));dnsReject(()->draft.requireReceipt(stale),"superseded DNS receipt accepted");
   AndroidStandardExitStore.Entry changed=AndroidStandardExitStore.copy(saved);changed.name+=" changed";dnsReject(()->draft.apply(changed),"changed saved source accepted by DNS draft");
   AndroidStandardExitStore.Entry exact=draft.apply(saved);JSONObject policy=kind.equals("socks5")?exact.policy:exact.torPolicy;String selected=kind.equals("socks5")?mode:mode.equals("tls")?"dot":mode.equals("https")?"doh":mode;
   check(policy.getString("dns_mode").equals("custom")&&policy.getString("dns_protocol").equals(selected)&&policy.getString("dns_host").equals("9.9.9.9")&&policy.getInt("dns_port")==(mode.equals("tcp")?53:mode.equals("tls")?853:443),"DNS draft did not keep exact measured endpoint");
   check(!policy.has("dns_results")&&!policy.has("fastest_dns_host")&&!policy.has("fastest_dns_latency_ms")&&AndroidStandardExitStore.snapshot(saved).equals(before),"DNS draft persisted legacy metrics or changed source");
   if(kind.equals("socks5"))invoke(activity,"showExternalDNSDraft",saved,draft);else invoke(activity,"showTorDNSDraft",saved.protocol,saved,draft);AlertDialog editor=AlertDialog.last;
   String host=kind.equals("socks5")?"Selected DNS IP or hostname":"Custom DNS literal IP",port=kind.equals("socks5")?"DNS port (blank keeps the protocol default)":"Custom DNS port (blank uses protocol default)",name=kind.equals("socks5")?"Encrypted DNS certificate name":"DoT / DoH certificate server name",path=kind.equals("socks5")?"DoH / DoH3 path":"DoH path (default /dns-query)";
   check(field(editor,host).getText().toString().equals("9.9.9.9")&&field(editor,port).getText().toString().equals(Integer.toString(mode.equals("tcp")?53:mode.equals("tls")?853:443)),"measured DNS fields were not editable");
   if(!mode.equals("tcp"))check(field(editor,name).getText().toString().equals("dns.quad9.net"),"measured DNS certificate name dropped");if(mode.equals("https"))check(field(editor,path).getText().toString().equals("/dns-query"),"measured DoH path dropped");
   check(AndroidStandardExitStore.snapshot(store(activity).get(saved.id)).equals(before)&&AndroidRuntimeRegistry.get(activity).standardExit.starts==0,"opening DNS draft saved or connected");
   store(activity).save(changed);editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(editor.showing&&store(activity).get(saved.id).name.equals(changed.name),"DNS Save overwrote a changed captured source");store(activity).save(saved);
   editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!editor.showing,"valid measured DNS draft did not save");AndroidStandardExitStore.Entry result=store(activity).get(saved.id);JSONObject resultPolicy=kind.equals("socks5")?result.policy:result.torPolicy;
   check(resultPolicy.getString("dns_mode").equals("custom")&&resultPolicy.getString("dns_protocol").equals(selected)&&resultPolicy.getString("dns_host").equals("9.9.9.9")&&result.torBridges.equals(saved.torBridges)&&result.secret.equals(saved.secret)&&result.password.equals(saved.password),"explicit Save lost DNS, bridge or credentials");
   if(kind.equals("socks5"))AndroidExternalPolicy.compile(result,null,"external");else compiled(result);
  }
 }
 static void dnsDialog()throws Exception{
  for(String action:new String[]{"fastest","manual","expired-chooser","owner","session","pending-close","replaced-close","destroyed-handoff","dismiss","cancel"}){
   AndroidHomeStateStore.current=null;AndroidVpnMutationGuard.busy=false;AndroidNativeDNSMeasurement.runs=0;AndroidNativeDNSMeasurement.cancels=0;AndroidNativeDNSMeasurement.stale=false;AndroidNativeDNSMeasurement.autoFinish=!action.equals("dismiss")&&!action.equals("cancel");
   StandardExitActivity activity=activity(Files.createTempDirectory(root,"dns-dialog-"),null);AndroidStandardExitStore.Entry saved=ordinary("socks5");store(activity).save(saved);String before=AndroidStandardExitStore.snapshot(saved);AndroidNativeDNSMeasurement.receipt=dnsReceipt(saved.id,"https").toString();
   AndroidHomeStateStore.Snapshot home=new AndroidHomeStateStore.Snapshot();home.connected=true;home.activeExternalId=saved.id;home.sessionId="captured-home-session";home.pathProof="passed";AndroidHomeStateStore.current=home;AndroidVpnMutationGuard.busy=true;
   invoke(activity,"showDNSComparison",saved.id);AlertDialog dialog=AlertDialog.last;Button measure=button(dialog,"Measure DNS"),fastest=button(dialog,"Use fastest measured public DNS next time"),choose=button(dialog,"Choose measured public resolver…");
   check(AndroidNativeDNSMeasurement.runs==0&&!fastest.isEnabled()&&!choose.isEnabled(),"opening DNS dialog started traffic or allowed unmeasured choice");measure.performClick();
   if(action.equals("dismiss")||action.equals("cancel")){check(AndroidNativeDNSMeasurement.runs==1&&!fastest.isEnabled()&&!spinner(dialog,"TCP DNS").isEnabled(),"active DNS measurement allowed selection or transport mutation");if(action.equals("dismiss"))activity.onDestroy();else button(dialog,"Cancel measurement").performClick();check(AndroidNativeDNSMeasurement.cancels>0,"DNS cancellation lost exact UI owner");AndroidNativeDNSMeasurement.last.finish();check(!fastest.isEnabled(),"cancelled DNS result became selectable");AndroidHomeStateStore.current=null;AndroidVpnMutationGuard.busy=false;continue;}
   check(fastest.isEnabled()&&choose.isEnabled()&&displayed(dialog.view).contains("Complete DNS query time")&&displayed(dialog.view).contains("Selected DNS via entry-wg")&&displayed(dialog.view).contains("Unavailable"),"valid DNS results lost selected route or usable choices");
   if(action.equals("manual")||action.equals("expired-chooser")){choose.performClick();AlertDialog list=AlertDialog.last;check(list.itemsVisible()&&list.items.length==11,"measured resolver picker included failed or selected DNS row");if(action.equals("expired-chooser"))AndroidNativeDNSMeasurement.stale=true;list.clickItem(1);}else fastest.performClick();
   if(action.equals("expired-chooser")){check(!fastest.isEnabled()&&AndroidRuntimeRegistry.get(activity).standardExit.disconnects==0&&AndroidStandardExitStore.snapshot(store(activity).get(saved.id)).equals(before),"expired chooser result disconnected or saved a resolver");activity.onDestroy();AndroidHomeStateStore.current=null;AndroidVpnMutationGuard.busy=false;continue;}
   AlertDialog confirmation=AlertDialog.last;AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.get(activity).standardExit;check(confirmation.message!=null&&confirmation.message.toString().contains(action.equals("manual")?"1.0.0.1:443":"9.9.9.9:443")&&runtime.disconnects==0&&runtime.starts==0&&AndroidStandardExitStore.snapshot(store(activity).get(saved.id)).equals(before),"choosing measured DNS saved, disconnected, connected or lost endpoint before confirmation");
   if(action.equals("owner"))AndroidNativeDNSMeasurement.stale=true;if(action.equals("session"))home.sessionId="replacement-home-session";runtime.disconnectFails=action.equals("pending-close");runtime.disconnectReplaced=action.equals("replaced-close");
   if(action.equals("destroyed-handoff")){runtime.disconnectEntered=new java.util.concurrent.CountDownLatch(1);runtime.disconnectRelease=new java.util.concurrent.CountDownLatch(1);}
   confirmation.getButton(AlertDialog.BUTTON_POSITIVE).performClick();
   if(action.equals("destroyed-handoff")){check(runtime.disconnectEntered.await(2,java.util.concurrent.TimeUnit.SECONDS),"captured DNS disconnect did not start");activity.onDestroy();runtime.disconnectRelease.countDown();runtime.disconnectThread.join(2000);check(!runtime.disconnectThread.isAlive()&&AlertDialog.last==confirmation&&AndroidStandardExitStore.snapshot(store(activity).get(saved.id)).equals(before),"destroyed Activity opened or saved a DNS editor");AndroidHomeStateStore.current=null;AndroidVpnMutationGuard.busy=false;continue;}
   if(action.equals("owner")||action.equals("session")){check(!(Boolean)get(activity,"busy")&&runtime.disconnects==0&&AndroidStandardExitStore.snapshot(store(activity).get(saved.id)).equals(before),"stale DNS choice disconnected or saved another session");activity.onDestroy();}
   else{
    long deadline=System.nanoTime()+3_000_000_000L;while(((Boolean)get(activity,"busy")||!action.endsWith("close")&&AlertDialog.last==confirmation)&&System.nanoTime()<deadline)Thread.sleep(2);check(!(Boolean)get(activity,"busy")&&runtime.disconnects==1&&runtime.disconnectedSession.equals("captured-home-session"),"DNS draft did not wait for exact captured disconnect");
    if(action.endsWith("close"))check(AlertDialog.last==confirmation&&AndroidStandardExitStore.snapshot(store(activity).get(saved.id)).equals(before),"unconfirmed disconnect opened or saved DNS draft");
    else{AlertDialog editor=AlertDialog.last;check(editor!=confirmation&&editor.showing&&field(editor,"Selected DNS IP or hostname").getText().toString().equals(action.equals("manual")?"1.0.0.1":"9.9.9.9")&&AndroidStandardExitStore.snapshot(store(activity).get(saved.id)).equals(before),"DNS editor lost exact draft or saved before explicit Save");editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!editor.showing&&store(activity).get(saved.id).policy.getString("dns_mode").equals("custom")&&runtime.starts==0,"DNS handoff did not remain explicit Save without Connect");}
   }
   AndroidHomeStateStore.current=null;AndroidVpnMutationGuard.busy=false;
  }
 }
 static void dnsLinkedEntries()throws Exception{
  for(String kind:new String[]{"tor","socks5"})for(String mutation:new String[]{"bundle","mapping","removed"}){
   Path directory=Files.createTempDirectory(root,"dns-entry-");StandardExitActivity activity=activity(directory,null);AndroidStandardExitStore.Entry saved=kind.equals("tor")?tor("tor","doh"):ordinary("socks5");store(activity).save(saved);String before=AndroidStandardExitStore.snapshot(saved);
   AndroidNodeStore.Node entry=node(directory);byte[] bytes=Files.readAllBytes(entry.file.toPath());AndroidHomeStateStore.Snapshot home=new AndroidHomeStateStore.Snapshot();home.activeEntryId=entry.id;home.activeEntryMode="wg";AndroidNodeStore nodes=(AndroidNodeStore)get(activity,"nodeStore");
   AndroidDNSSelectionDraft.Path path=AndroidDNSSelectionDraft.Path.capture(nodes,home);path.requireActive(home);home.activeEntryMode="max";dnsReject(()->path.requireActive(home),"captured DNS entry mode changed");home.activeEntryMode="wg";
   AndroidDNSSelectionDraft draft=AndroidDNSSelectionDraft.create(saved,path,dnsReceipt(saved.id,"https"),null);
   if(kind.equals("tor"))invoke(activity,"showTorDNSDraft",saved.protocol,saved,draft);else invoke(activity,"showExternalDNSDraft",saved,draft);AlertDialog editor=AlertDialog.last;
   if(mutation.equals("bundle"))Files.writeString(entry.file.toPath(),new String(bytes,StandardCharsets.UTF_8)+"\n");
   if(mutation.equals("mapping")){Path other=directory.resolve("another-private-entry.json");Files.write(other,bytes);AndroidNodeStore.nodes.clear();AndroidNodeStore.nodes.add(new AndroidNodeStore.Node(entry.id,entry.name,entry.endpoint,other.toFile()));}
   if(mutation.equals("removed"))AndroidNodeStore.nodes.clear();
   dnsReject(()->path.requireCurrent(),"changed or removed entry remained a measurement source");dnsReject(()->draft.requireSource(store(activity).get(saved.id)),"DNS draft accepted a changed predecessor");
   editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(editor.showing&&AndroidStandardExitStore.snapshot(store(activity).get(saved.id)).equals(before),"DNS Save accepted a changed predecessor");
   Files.write(entry.file.toPath(),bytes);AndroidNodeStore.nodes.clear();AndroidNodeStore.nodes.add(entry);editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!editor.showing,"unchanged captured predecessor prevented explicit DNS Save");
  }
  AndroidHomeStateStore.Snapshot direct=new AndroidHomeStateStore.Snapshot();AndroidDNSSelectionDraft.Path path=AndroidDNSSelectionDraft.Path.capture(null,direct);check(path.entryID.isEmpty()&&path.entryMode.isEmpty(),"direct DNS draft borrowed ambient Router node");direct.activeEntryMode="wg";dnsReject(()->AndroidDNSSelectionDraft.Path.capture(null,direct),"direct DNS capture accepted an unexplained entry mode");
 }
 static CheckBox startupCheck(AlertDialog dialog){for(View view:views(dialog.view))if(view instanceof CheckBox&&((CheckBox)view).getText().toString().startsWith("Auto-connect this saved external path"))return (CheckBox)view;throw new AssertionError("Missing external startup control");}
 static void startupSettings()throws Exception{
  for(String kind:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn","tor","tor-bridge")){
   StandardExitActivity a=activity(Files.createTempDirectory(root,"startup-form-"),null);AndroidStandardExitStore.Entry saved=AndroidTorProfile.isTor(kind)?tor(kind.equals("tor-bridge")?"obfs4":kind,"doh"):ordinary(kind);store(a).save(saved);
   check(saved.startupMode.equals("smart-auto")&&!saved.autoConnect,"external startup default is not SMART AUTO / Off");
   if(AndroidTorProfile.isTor(kind))invoke(a,"showTorForm",kind,saved);else invoke(a,"showExternalPolicyForm",saved);
   AlertDialog editor=AlertDialog.last;Spinner mode=spinner(editor,"SMART AUTO — saved external path");CheckBox enabled=startupCheck(editor);check(mode.getSelectedItemPosition()==0&&!enabled.isChecked(),"external startup defaults not shown");mode.setSelection(2);enabled.setChecked(true);editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!editor.showing,"valid external startup setting did not save");AndroidStandardExitStore.Entry current=store(a).get(saved.id);check(current.startupMode.equals("last")&&current.autoConnect,"external startup choices did not round trip");JSONObject policy=AndroidTorProfile.isTor(kind)?current.torPolicy:current.policy;check(!policy.has("startup_mode")&&!policy.has("auto_connect"),"app startup metadata contaminated native DNS policy");
   if(AndroidTorProfile.isTor(kind))invoke(a,"showTorForm",kind,current);else invoke(a,"showExternalPolicyForm",current);
   editor=AlertDialog.last;mode=spinner(editor,"SMART AUTO — saved external path");enabled=startupCheck(editor);check(mode.getSelectedItemPosition()==2&&enabled.isChecked(),"external editor lost saved startup mode");mode.setSelection(3);check(!enabled.isChecked()&&!enabled.isEnabled(),"external Manual did not disable auto-connect");editor.getButton(AlertDialog.BUTTON_POSITIVE).performClick();current=store(a).get(saved.id);check(current.startupMode.equals("manual")&&!current.autoConnect,"external Manual persisted auto-connect");
  }
  java.lang.reflect.Method parse=AndroidStandardExitStore.class.getDeclaredMethod("fromJson",JSONObject.class);parse.setAccessible(true);JSONObject old=new JSONObject(AndroidStandardExitStore.snapshot(ordinary("socks5")));old.remove("startup_mode");old.remove("auto_connect");AndroidStandardExitStore.Entry legacy=(AndroidStandardExitStore.Entry)parse.invoke(null,old);check(legacy.startupMode.equals("smart-auto")&&!legacy.autoConnect,"legacy external node gained automatic startup");
  for(String kind:List.of("string-bool","null-bool","number-mode","unknown","manual-on")){JSONObject malformed=new JSONObject(old.toString());malformed.put("startup_mode",kind.equals("number-mode")?3:kind.equals("unknown")?"random":kind.equals("manual-on")?"manual":"auto");malformed.put("auto_connect",kind.equals("string-bool")?"true":kind.equals("null-bool")?JSONObject.NULL:true);boolean rejected=false;try{parse.invoke(null,malformed);}catch(Exception expected){rejected=true;}check(rejected,"invalid external startup metadata accepted: "+kind);}
 }
 static void protectionSettings()throws Exception{
  for(String kind:new String[]{"socks5","tor","tor-bridge"}){
   StandardExitActivity a=activity(Files.createTempDirectory(root,"protection-form-"),null);boolean isTor=AndroidTorProfile.isTor(kind);AndroidStandardExitStore.Entry saved=isTor?tor(kind.equals("tor-bridge")?"obfs4":kind,"doh"):ordinary(kind);store(a).save(saved);
   if(!isTor){invoke(a,"showExternalPolicyForm",saved);AlertDialog baseline=AlertDialog.last;baseline.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!baseline.showing,"ordinary baseline settings failed");saved=store(a).get(saved.id);}
   String original=AndroidStandardExitStore.snapshot(saved);
   if(isTor)invoke(a,"showTorForm",kind,saved);else invoke(a,"showExternalPolicyForm",saved);
   AlertDialog form=AlertDialog.last;Spinner control=spinner(form,"Keep saved protection default");check(control.getSelectedItemPosition()==0,"external form replaced the legacy protection default");control.setSelection(2);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing,"external protection form did not save On");
   AndroidStandardExitStore.Entry current=store(a).get(saved.id);JSONObject p=isTor?current.torPolicy:current.policy;check(p.has("kill_switch")&&p.has("kill_switch_policy")&&p.getBoolean("kill_switch")&&p.getString("kill_switch_policy").equals("always"),"external form lost explicit protection");
   AndroidStandardExitStore.Entry untouched=AndroidStandardExitStore.copy(current);JSONObject unchanged=isTor?untouched.torPolicy:untouched.policy;unchanged.remove("kill_switch");unchanged.remove("kill_switch_policy");check(same(original,AndroidStandardExitStore.snapshot(untouched)),"external protection form rewrote credentials or saved DNS/device policy");
   if(isTor)invoke(a,"showTorForm",kind,current);else invoke(a,"showExternalPolicyForm",current);form=AlertDialog.last;control=spinner(form,"Keep saved protection default");check(control.getSelectedItemPosition()==2,"external form failed to restore explicit On");control.setSelection(1);form.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(!form.showing,"external protection form did not save Off");current=store(a).get(saved.id);p=isTor?current.torPolicy:current.policy;check(!p.getBoolean("kill_switch")&&p.getString("kill_switch_policy").equals("off"),"external form did not save explicit Off");
   for(String fault:new String[]{"replaced","removed"}){
    store(a).save(current);if(isTor)invoke(a,"showTorForm",kind,current);else invoke(a,"showExternalPolicyForm",current);AlertDialog stale=AlertDialog.last;
    if(fault.equals("removed"))store(a).remove(current.id);else{AndroidStandardExitStore.Entry replacement=AndroidStandardExitStore.copy(current);replacement.name+=" replacement";store(a).save(replacement);}
    String expected=store(a).storedSnapshot(current.id);spinner(stale,"Keep saved protection default").setSelection(2);stale.getButton(AlertDialog.BUTTON_POSITIVE).performClick();check(stale.showing&&expected.equals(store(a).storedSnapshot(current.id)),"stale normal external protection form overwrote or resurrected its node");stale.dismiss();
   }
  }
 }
 static void ordinaryTorUI()throws Exception{
  for(String protocol:List.of("wireguard","amneziawg","socks5","http","https","shadowsocks","hysteria2","openvpn"))for(boolean selectionOnly:new boolean[]{false,true})for(boolean restored:new boolean[]{false,true}){
   Path directory=Files.createTempDirectory(root,"ordinary-tor-ui-");StandardExitActivity picker=activity(directory,null);AndroidNodeStore.Node collision=node(directory);
   AndroidStandardExitStore.Entry entry=ordinary(protocol),exit=tor("obfs4","doh");entry.id=collision.id;entry.policy=policy("custom","tcp");store(picker).save(entry);store(picker).save(exit);
   String entrySource=AndroidStandardExitStore.snapshot(entry),exitSource=AndroidStandardExitStore.snapshot(exit);
   if(selectionOnly)picker.intent.putExtra(StandardExitActivity.EXTRA_SELECT_PATH,true);
   invoke(picker,"chooseEntry",exit);AlertDialog choices=AlertDialog.last;
   check(choices.itemsVisible()&&choices.items.length==2&&choices.items[0].contains("Router VPN")&&choices.items[1].contains(protocol),"ordinary Tor picker omitted typed entry or hid choices");choices.clickItem(1);
   check(AndroidConnectionProfileStore.selected.get(directory.toString()).equals(exit.id+"|external:"+entry.id+"|"+AndroidExternalPolicy.protocol(protocol))&&AndroidConnectionProfileStore.executions.get(directory.toString()).equals("local"),"ordinary Tor selection persisted another entry kind or mode");
   if(selectionOnly){check(picker.finished&&picker.permission==null&&AndroidRuntimeRegistry.get(picker).standardExit.starts==0,"ordinary selection-only requested permission or started native engine");continue;}
   check(picker.permissionRequest==2101&&AndroidRuntimeRegistry.get(picker).standardExit.starts==0,"ordinary Tor picker bypassed VPN permission");Bundle state=new Bundle();picker.onSaveInstanceState(state);
   check(state.getString("pending_ordinary_entry","").equals(entry.id)&&state.getString("pending_entry","").isEmpty()&&(entry.password.isEmpty()||!state.values.toString().contains(entry.password))&&!state.values.toString().contains("cert=Y2VydA"),"ordinary permission lost typed references or exposed private data");
   if(restored)picker=activity(directory,state);picker.onActivityResult(2101,Activity.RESULT_OK,null);AndroidStandardExitRuntime runtime=AndroidRuntimeRegistry.get(picker).standardExit;
   check(runtime.starts==1&&runtime.entry==null&&runtime.ordinaryEntry!=null&&entrySource.equals(AndroidStandardExitStore.snapshot(runtime.ordinaryEntry))&&exitSource.equals(AndroidStandardExitStore.snapshot(runtime.exit))&&runtime.execution.equals("local"),"ordinary UI permission substituted source or borrowed colliding private entry");
  }
  for(String fault:List.of("entry","exit","removed","kind","mode","server","direct","digest","denied","busy")){
   Path directory=Files.createTempDirectory(root,"ordinary-tor-permission-");StandardExitActivity picker=activity(directory,null);AndroidNodeStore.Node collision=node(directory);
   AndroidStandardExitStore.Entry entry=ordinary("socks5"),exit=tor("obfs4","doh");entry.id=collision.id;entry.policy=policy("custom","tcp");store(picker).save(entry);store(picker).save(exit);invoke(picker,"requestOrdinaryTor",entry,exit);Bundle state=new Bundle();picker.onSaveInstanceState(state);
   if(fault.equals("entry")){entry.password+=" replacement";store(picker).save(entry);}if(fault.equals("exit")){exit.name+=" replacement";store(picker).save(exit);}if(fault.equals("removed"))store(picker).remove(entry.id);
   if(fault.equals("kind")){state.values.remove("pending_ordinary_entry");state.putString("pending_entry",entry.id);}if(fault.equals("mode"))state.putString("pending_entry_mode","wg");if(fault.equals("server"))state.putString("pending_execution","server");if(fault.equals("direct"))state.putBoolean("pending_direct",true);if(fault.equals("digest"))state.putString("pending_entry_digest","0".repeat(64));
   picker=activity(directory,state);if(fault.equals("busy"))AndroidVpnMutationGuard.busy=true;picker.onActivityResult(2101,fault.equals("denied")?0:Activity.RESULT_OK,null);AndroidVpnMutationGuard.busy=false;
   check(AndroidRuntimeRegistry.get(picker).standardExit.starts==0&&get(picker,"pendingOrdinaryEntry")==null,"ordinary UI permission accepted changed source, kind or execution: "+fault);
  }
 }

 public static void main(String[] args)throws Exception{root=Path.of(args[0]);if(args.length>1&&args[1].equals("padding-only")){paddingCompiler();return;}if(args.length>1&&args[1].equals("ordinary-tor-only")){ordinaryTorProfiles();return;}roundtrips();independentPolicyEdits();jumboPolicyEdits();paddingPolicyEdits();newFormAndRejections();dialogAndPermission();ordinaryPolicies();ordinaryHomeDrafts();ordinaryTorProfiles();ordinaryTorUI();externalExecutionForm();packetExecutionForms();openVPNExecutionForms();openVPNResponseMaps();openVPNLayerMaps();openVPNForm();amneziaForm();dnsDrafts();dnsDialog();dnsLinkedEntries();startupSettings();protectionSettings();System.out.println("Android Tor form: PASS ("+roundtrips+" real compiler roundtrips, all 19 mode choices, "+checks+" checks; full shipping Activity, Android widgets/permission doubled)");}
}
'''


def main():
    for variable in ("ROUTERVPN_ANDROID_ORDINARY_TOR_GRAPHS", "ROUTERVPN_ANDROID_LOCAL_PADDING_GRAPHS"):
        output = os.environ.get(variable)
        if output:
            folder = Path(output)
            if folder.is_symlink() or not folder.is_dir() or any(folder.iterdir()):
                raise RuntimeError("Ordinary Tor parser fixtures require an existing empty owned directory")
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("Android JSON implementation required")
    with tempfile.TemporaryDirectory(prefix=".tor-form-policy-", dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix="android-tor-form-") as work:
        go_dir, work = Path(go_dir), Path(work)
        code = T.GO.replace('"router-vpn/internal/mobiletor"', '"router-vpn/internal/mobiletor";nativeopenvpn "router-vpn/mobile"', 1)
        code = code.replace('case "tor-profile":', '''case "external-openvpn":var p struct{Config,Username,Password,Tag,Detour string};err=json.Unmarshal([]byte(r.Config),&p);if err==nil{value,err=nativeopenvpn.RouterOpenVPNEndpoint(p.Config,p.Username,p.Password,p.Tag,p.Detour)}
 case "external-execution":var p struct{Config,Capture,Restored string};err=json.Unmarshal([]byte(r.Config),&p);if err==nil{value,err=mobilemultihop.PrepareExternalExecutionCapture(p.Config,p.Capture,p.Restored)}
 case "external-openvpn-probes":err=nativeopenvpn.RouterValidateExternalOpenVPNResponseProbes(r.Config,r.Policy)
 case "external-openvpn-layers":var layers struct{Probes,Layers,Mode string};err=json.Unmarshal([]byte(r.Policy),&layers);if err==nil{err=nativeopenvpn.RouterValidateExternalOpenVPNStartLayers(r.Config,layers.Probes,layers.Layers,layers.Mode)}
 case "external-openvpn-pairing":err=nativeopenvpn.RouterValidateExternalOpenVPNPairing(r.Config,r.Policy)
 case "external-policy":value,err=mobilemultihop.CompileExternalPolicy(r.Config,r.Policy)
 case "external-response":err=mobilemultihop.ValidateExternalResponseProbe(r.Config,r.Policy)
 case "external-transport":err=mobilemultihop.ValidateExternalTransport(r.Config,r.Policy)
 case "external-dns":err=mobilemultihop.ValidateExternalDNS(r.Config,r.Policy)
 case "tor-profile":''', 1)
        (go_dir / "main.go").write_text(code)
        native = work / "policy"
        subprocess.run(["go", "build", "-o", str(native), str(go_dir / "main.go")], cwd=ROOT, check=True, timeout=90)
        stubs = dict(T.P.M.STUBS)
        stubs.update(UI)
        stubs["com/eabusham/routervpn/AndroidNativeDNSMeasurement.java"] = DNS_BOUNDARY
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
 static final java.util.List<Node> nodes=new java.util.ArrayList<>();AndroidNodeStore(android.content.Context c){}java.util.List<Node> list(){return new java.util.ArrayList<>(nodes);}java.io.File file(String id){for(Node node:nodes)if(node.id.equals(id))return node.file;throw new IllegalStateException("entry was removed");}
'''
                start, end = text.index("final class AndroidNodeStore {"), text.index("final class AndroidKillSwitchPolicy {")
                private_files = T.TOR_BOUNDARIES[:T.TOR_BOUNDARIES.index("final class AndroidVpnMutationGuard")]
                text = text[:start] + "final class AndroidNodeStore {\n" + constants + node + methods + "\n}\n" + text[end:] + private_files + APP
                text = text.replace("import org.json.JSONObject;", "import org.json.JSONObject; import org.json.JSONArray; import java.security.MessageDigest; import java.nio.charset.StandardCharsets; import android.util.Base64;")
            if path.endswith("/Libbox.java"):
                begin = text.index(" private static String call(")
                end = text.index(" public static String routerCompilePQProfile(", begin)
                text = text[:begin] + T.P.PIPE_CALL + text[end:]
                text = text.replace(" public static boolean rejectConfig;", " public static Runnable afterCheck;\n public static boolean rejectConfig;")
                text = text.replace("new JSONObject(c);}", "new JSONObject(c);if(afterCheck!=null)afterCheck.run();}")
                text = text.replace(" public static String routerCompilePQProfile(", r'''
 public static String routerCompileTorProfile(String profile,String session,String predecessor)throws Exception{return call("tor-profile",new JSONObject().put("Profile",profile).put("Session",session).toString(),predecessor);}
 public static void routerValidateTorProfile(String profile)throws Exception{call("tor-validate",profile,"");}
 public static String routerTorPaddingSource(String config,String profile,String session)throws Exception{return call("tor-padding-source",new JSONObject().put("Profile",profile).put("Session",session).toString(),config);}
 public static String routerCompileTorProfileWithPredecessor(String profile,String session,String predecessor,String entry)throws Exception{return call("tor-profile-captured",new JSONObject().put("Profile",profile).put("Session",session).put("Entry",entry).toString(),predecessor);}
 public static String routerCompileTorProfileWithExternalPredecessor(String profile,String session,String predecessor,String entry)throws Exception{return call("tor-external-profile-captured",new JSONObject().put("Profile",profile).put("Session",session).put("Entry",entry).toString(),predecessor);}
 public static String routerCompileServerTorProfileWithPredecessor(String profile,String session,String predecessor,String entry)throws Exception{return call("tor-server-profile-captured",new JSONObject().put("Profile",profile).put("Session",session).put("Entry",entry).toString(),predecessor);}
 public static String routerCompileExternalPolicy(String config,String capture)throws Exception{return call("external-policy",config,capture);}
 public static void routerValidatePrivateNodeJSON(String raw)throws Exception{call("private-node-json",raw,"");}
 public static void routerValidateExternalOpenVPNResponseProbes(String profile,String probes)throws Exception{call("external-openvpn-probes",profile,probes);}
 public static void routerValidateExternalOpenVPNStartLayers(String profile,String probes,String layers,String mode)throws Exception{call("external-openvpn-layers",profile,new JSONObject().put("probes",probes).put("layers",layers).put("mode",mode).toString());}
 public static void routerValidateExternalOpenVPNPairing(String profile,String pairing)throws Exception{call("external-openvpn-pairing",profile,pairing);}
 public static void routerValidateExternalResponseProbe(String host,String probe)throws Exception{call("external-response",host,probe);}
 public static void routerValidateExternalTransport(String source,String capture)throws Exception{call("external-transport",source,capture);}public static void routerValidateExternalDNS(String profile,String entry)throws Exception{call("external-dns",profile,entry);}
 public static String routerPrepareExternalExecutionCapture(String config,String capture,String restored)throws Exception{return call("external-execution",new JSONObject().put("Config",config).put("Capture",capture).put("Restored",restored).toString(),"");}
 public static String version(){return "1.14.1";}public static String routerOpenVPNEndpoint(String config,String username,String password,String tag,String detour)throws Exception{return call("external-openvpn",new JSONObject().put("config",config).put("username",username).put("password",password).put("tag",tag).put("detour",detour).toString(),"");}
 public static String routerCompilePQProfile(''', 1)
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / "com/eabusham/routervpn"
        for name in ("AndroidExternalProtection", "AndroidMultihopController", "NativeSingBoxController", "AndroidNativeMAXProfile", "AndroidNativeCompositeProfile", "AndroidProfileSelection", "AndroidNumericAddress", "AndroidNativeProfilePolicy", "AndroidWireGuardLibboxPolicy", "AndroidStartLayer", "AndroidXrayLibboxPolicy", "NativeXrayController", "AndroidMultihopStartLayer", "AndroidTorProfile", "AndroidStandardExitStore", "AndroidExternalAmnezia", "AndroidExternalPolicy", "AndroidExternalEntry", "AndroidDirectStandardExitController", "AndroidOpenVPN", "StandardExitActivity", "AndroidDNSMeasurementDialog", "AndroidDNSSelectionDraft", "AndroidDNSMeasurementReceipt"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        dialog_api=src/"android/app/AlertDialog.java"
        dialog_api.write_text(dialog_api.read_text().replace("public void show(){","public boolean isShowing(){return showing;}public void show(){").replace("public static AlertDialog last;","public static volatile AlertDialog last;"))
        text_api=src/"android/widget/TextView.java"
        text_api.write_text(text_api.read_text()[:-1]+"public void setTextIsSelectable(boolean value){} }")
        (app / "MultihopGraphHarness.java").write_text(T.P.M.HARNESS)
        constants = "\n".join(re.findall(r" static final String (?:OBFS|MEEK|SNOW|WEB)=.*;", T.HARNESS))
        constants += '\n' + next(line for line in T.HARNESS.splitlines() if 'static final String[] KINDS=' in line)
        constants += '\n' + next(line for line in T.HARNESS.splitlines() if 'static final String[] ALL=' in line)
        tor = T.HARNESS[T.HARNESS.index(" static AndroidStandardExitStore.Entry tor("):T.HARNESS.index(" static JSONObject tagged(")]
        (app / "TorFormHarness.java").write_text(HARNESS.replace(" static int checks,roundtrips;", constants + tor + " static int checks,roundtrips;", 1))
        subprocess.run(["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(work / "classes"), *map(str, src.rglob("*.java"))], check=True, timeout=60)
        data = work / "data"
        data.mkdir()
        environment = dict(os.environ, ROUTERVPN_GO_POLICY_TEST=str(native), ROUTERVPN_OPENVPN_CLIENT_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-client.json'), ROUTERVPN_OPENVPN_MULTIHOST_CLIENT_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-multihost-client.json'), ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_AES_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-multihost-layered-aes-client.json'), ROUTERVPN_OPENVPN_MULTIHOST_LAYERED_XOR_FIXTURE=str(ROOT/'deploy/fixtures/external-openvpn-multihost-layered-xor-client.json'))
        subprocess.run(["java", "-cp", str(work / "classes") + os.pathsep + str(jar), "com.eabusham.routervpn.TorFormHarness", str(data)], env=environment, check=True, timeout=120)
        # Export only the unchanged positive shipping graphs. Mutated copies
        # exercise guard rejection and must never replace native parser input.
        environment.pop("ROUTERVPN_ANDROID_ORDINARY_TOR_GRAPHS", None)
        # Reintroduce each actual defect only in isolated compiled fixtures.
        # These controls establish that the Activity/Go checks fail for the
        # original behavior; neither working source nor positive classes change.
        controls = (
            ("tor-padding-choice", "StandardExitActivity.java",
             'p.put("daita_enabled",padding.isChecked())',
             'p.put("daita_enabled",false)',
             "padding toggle changed DNS, MTU, protection or its dormant rate"),
            ("tor-padding-rate", "StandardExitActivity.java",
             '.put("daita_rate_kbps",rate);return p;',
             '.put("daita_rate_kbps",0);return p;',
             "padding rate edit changed another complete policy group"),
            ("openvpn-layer-raw", "AndroidOpenVPN.java",
             'Libbox.routerValidateExternalOpenVPNStartLayers(profile.toString(), entry.openVPNResponseProbes.toString(), raw, mode);',
             '// omitted raw layer map validation before JSON conversion',
             "malformed OpenVPN layer map changed saved private node"),
            ("openvpn-response-raw", "AndroidOpenVPN.java",
             'Libbox.routerValidateExternalOpenVPNResponseProbes(profile.toString(), raw);',
             '// omitted raw map validation before JSON conversion',
             "malformed OpenVPN remote map changed saved private node"),
            ("private-store-raw", "AndroidStandardExitStore.java",
             'io.nekohasekai.libbox.Libbox.routerValidatePrivateNodeJSON(source);',
             '// omitted raw private store validation before JSON conversion',
             "private store collapsed duplicate OpenVPN response hosts before validation"),
            ("rewritten-policy", "StandardExitActivity.java",
             'entry.torPolicy=AndroidTorProfile.editedPolicy(saved,initialEditor,edited);',
             'entry.torPolicy=edited;',
             "name-only edit"),
            ("ipv6-default", "AndroidTorProfile.java",
             'if (ipv6.isEmpty()) policy.put("ipv6_mode", "auto");',
             '// original editor omitted the saved IPv6 default',
             "Tor editor displayed another saved IPv6 policy"),
            ("lan-default", "AndroidTorProfile.java",
             'if (!policy.has("home_lan_access")) policy.put("home_lan_access", true);',
             '// original editor omitted the saved LAN default',
             "Tor editor displayed another saved LAN policy"),
            ("dns-precedence", "AndroidTorProfile.java",
             'String protocol = "custom".equals(mode) ? policy.optString("dns_protocol", "") : mode;',
             'String protocol = policy.optString("dns_protocol", mode);',
             "Tor editor displayed another saved DNS policy"),
            ("hidden-mode-list", "StandardExitActivity.java",
             '.setCustomTitle(choiceHeader("Exact Router VPN entry mode","The complete selected encryption and Start Layer will be retained before "+exit.name+". Both entry identity and the selected external path must pass proof."))',
             '.setTitle("Exact Router VPN entry mode").setMessage("The complete selected encryption and Start Layer will be retained before "+exit.name+". Both entry identity and the selected external path must pass proof.")',
             "exact native mode choices missing or duplicated"),
            ("home-draft-native", "StandardExitActivity.java",
             'AndroidExternalPolicy.validateDraft(next);',
             '// omitted idle native validation',
             "Home draft bypassed native transport validation"),
            ("external-settings-owner", "AndroidStandardExitStore.java",
             'if(entry==null||expected==null||entry.wasPersisted&&expected.isEmpty()||!expected.equals(storedSnapshot(entry.id)))',
             'if(false)',
             "stale external editor overwrote another owner or resurrected deletion"),
            ("tor-settings-owner", "StandardExitActivity.java",
             'else exitStore.saveIfUnchanged(entry,storedSource);',
             'else exitStore.save(entry);',
             "stale normal external protection form overwrote or resurrected its node"),
            ("exit-protection-setting", "StandardExitActivity.java",
             'next.policy=protection.apply(next.policy);',
             '// omitted selected exit protection',
             "external form lost explicit protection"),
            ("dns-source-draft", "AndroidDNSSelectionDraft.java",
             'if(!nodeID.equals(current.id)||!source.equals(AndroidStandardExitStore.snapshot(current)))',
             'if(false)',
             "changed saved source accepted by DNS draft"),
            ("dns-confirmation", "StandardExitActivity.java",
             'draft.requireReceipt(measurement.currentReceipt());draft.requireSource(exitStore.get(draft.nodeID));',
             'draft.requireSource(exitStore.get(draft.nodeID));',
             "stale DNS choice disconnected or saved another session"),
            ("dns-disconnect-session", "StandardExitActivity.java",
             'runtime.disconnectAndDrainCaptured(homeSession)',
             'runtime.disconnectAndDrainCaptured("")',
             "DNS draft did not wait for exact captured disconnect"),
            ("dns-entry-draft", "AndroidDNSSelectionDraft.java",
             '\n        path.requireCurrent();\n',
             '\n',
             "DNS draft accepted a changed predecessor"),
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
        print(f"Android Tor form: all {len(controls)} original-source negative controls rejected")
        enabled=work/"padding-policy"
        T.build_padding_policy(go_dir,enabled)
        subprocess.run(["java","-cp",str(work/"classes")+os.pathsep+str(jar),"com.eabusham.routervpn.TorFormHarness",str(data),"padding-only"],env=dict(environment,ROUTERVPN_GO_POLICY_TEST=str(enabled)),check=True,timeout=120)


if __name__ == "__main__":
    main()
