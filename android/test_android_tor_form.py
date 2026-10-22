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
}
final class AndroidVpnMutationGuard {static boolean busy;static boolean isBusy(android.content.Context c){return busy;}}
final class AndroidHomeStateStore {
 static final class Snapshot{boolean connected;String sessionId="form-session",phase="idle",logicalMode="",activeExternalName="",activeExternalProtocol="",activeExternalId="",pathProof="",activeEntryId="",activeEntryMode="";}
 static Snapshot current;static boolean emergencyDisconnectPending(android.content.Context c){return false;}static Snapshot snapshot(android.content.Context c){return current==null?new Snapshot():current;}static String actualExitForCurrentSession(android.content.Context c){return "";}
}
final class AndroidStandardExitRuntime {
 interface Callback{void progress(String value);void finished(boolean success,String value);}
 int starts;String mode="",execution="local";java.io.File entry;AndroidStandardExitStore.Entry exit;
 void connectDirect(AndroidStandardExitStore.Entry value,Callback cb){starts++;exit=value;mode="external";}
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
  return io.nekohasekai.libbox.Libbox.routerCompileTorProfile(profile.toString(),"form-roundtrip","");
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
 static void newFormAndRejections()throws Exception{
  StandardExitActivity activity=activity(Files.createTempDirectory(root,"create-"),null);AlertDialog dialog=form(activity,null);
  check(spinner(dialog,"Home AdGuard through captured Router VPN entry").getSelectedItemPosition()==0&&spinner(dialog,"IPv6 off").getSelectedItemPosition()==2&&!lan(dialog).isChecked(),"new Tor defaults changed");
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
   invoke(activity,"showExitActions",selected);AlertDialog actions=AlertDialog.last;check(actions.itemsVisible()&&actions.items.length==5&&actions.items[3].equals("Compare DNS on this connected path"),"saved Tor actions are hidden");
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
  for(boolean direct:new boolean[]{true,false}){
   directory=Files.createTempDirectory(root,"select-only-");activity=activity(directory,null);AndroidNodeStore.Node entry=node(directory);selected=tor("obfs4","doh");store(activity).save(selected);
   activity.intent.putExtra(StandardExitActivity.EXTRA_EXIT_ID,selected.id).putExtra(StandardExitActivity.EXTRA_SELECT_PATH,true);activity.onResume();
   AlertDialog paths=AlertDialog.last;check(paths.itemsVisible()&&paths.items.length==2,"external path choices are reachable without connecting");paths.clickItem(direct?0:1);
   if(!direct){AlertDialog.last.clickItem(0);AlertDialog.last.clickItem(0);}
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
   if(kind.equals("shadowsocks")){AlertDialog execution=AlertDialog.last;check(execution.itemsVisible()&&Arrays.equals(execution.items,new String[]{"Local","Server","Compare both"}),"external execution choices disappeared");execution.clickItem(0);}
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
 public static void main(String[] args)throws Exception{root=Path.of(args[0]);roundtrips();independentPolicyEdits();newFormAndRejections();dialogAndPermission();ordinaryPolicies();ordinaryHomeDrafts();externalExecutionForm();openVPNForm();amneziaForm();dnsDrafts();dnsDialog();dnsLinkedEntries();System.out.println("Android Tor form: PASS ("+roundtrips+" real compiler roundtrips, all 19 mode choices, "+checks+" checks; full shipping Activity, Android widgets/permission doubled)");}
}
'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("Android JSON implementation required")
    with tempfile.TemporaryDirectory(prefix=".tor-form-policy-", dir=ROOT) as go_dir, tempfile.TemporaryDirectory(prefix="android-tor-form-") as work:
        go_dir, work = Path(go_dir), Path(work)
        code = T.GO.replace('"router-vpn/internal/mobiletor"', '"router-vpn/internal/mobiletor";nativeopenvpn "router-vpn/mobile"', 1)
        code = code.replace('case "tor-profile":', '''case "external-openvpn":var p struct{Config,Username,Password,Tag,Detour string};err=json.Unmarshal([]byte(r.Config),&p);if err==nil{value,err=nativeopenvpn.RouterOpenVPNEndpoint(p.Config,p.Username,p.Password,p.Tag,p.Detour)}
 case "external-execution":var p struct{Config,Capture,Restored string};err=json.Unmarshal([]byte(r.Config),&p);if err==nil{value,err=mobilemultihop.PrepareExternalExecutionCapture(p.Config,p.Capture,p.Restored)}
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
                text = text.replace(" public static String routerCompilePQProfile(", r'''
 public static String routerCompileTorProfile(String profile,String session,String predecessor)throws Exception{return call("tor-profile",new JSONObject().put("Profile",profile).put("Session",session).toString(),predecessor);}
 public static void routerValidateTorProfile(String profile)throws Exception{call("tor-validate",profile,"");}
 public static String routerCompileTorProfileWithPredecessor(String profile,String session,String predecessor,String entry)throws Exception{return call("tor-profile-captured",new JSONObject().put("Profile",profile).put("Session",session).put("Entry",entry).toString(),predecessor);}
 public static String routerCompileExternalPolicy(String config,String capture)throws Exception{return call("external-policy",config,capture);}
 public static void routerValidateExternalResponseProbe(String host,String probe)throws Exception{call("external-response",host,probe);}
 public static void routerValidateExternalTransport(String source,String capture)throws Exception{call("external-transport",source,capture);}public static void routerValidateExternalDNS(String profile,String entry)throws Exception{call("external-dns",profile,entry);}
 public static String routerPrepareExternalExecutionCapture(String config,String capture,String restored)throws Exception{return call("external-execution",new JSONObject().put("Config",config).put("Capture",capture).put("Restored",restored).toString(),"");}
 public static String version(){return "1.14.1";}public static String routerOpenVPNEndpoint(String config,String username,String password,String tag,String detour)throws Exception{return call("external-openvpn",new JSONObject().put("config",config).put("username",username).put("password",password).put("tag",tag).put("detour",detour).toString(),"");}
 public static String routerCompilePQProfile(''', 1)
            target = src / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        app = src / "com/eabusham/routervpn"
        for name in ("AndroidMultihopController", "NativeSingBoxController", "AndroidNativeMAXProfile", "AndroidNativeCompositeProfile", "AndroidProfileSelection", "AndroidNumericAddress", "AndroidNativeProfilePolicy", "AndroidWireGuardLibboxPolicy", "AndroidStartLayer", "AndroidXrayLibboxPolicy", "NativeXrayController", "AndroidMultihopStartLayer", "AndroidTorProfile", "AndroidStandardExitStore", "AndroidExternalAmnezia", "AndroidExternalPolicy", "AndroidExternalEntry", "AndroidDirectStandardExitController", "AndroidOpenVPN", "StandardExitActivity", "AndroidDNSMeasurementDialog", "AndroidDNSSelectionDraft", "AndroidDNSMeasurementReceipt"):
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
        environment = dict(os.environ, ROUTERVPN_GO_POLICY_TEST=str(native))
        subprocess.run(["java", "-cp", str(work / "classes") + os.pathsep + str(jar), "com.eabusham.routervpn.TorFormHarness", str(data)], env=environment, check=True, timeout=120)
        # Reintroduce each actual defect only in isolated compiled fixtures.
        # These controls establish that the Activity/Go checks fail for the
        # original behavior; neither working source nor positive classes change.
        controls = (
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


if __name__ == "__main__":
    main()
