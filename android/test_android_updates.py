#!/usr/bin/env python3
"""Exercise the shipped update provider, receipt and reachable native dialog.

Android UI/permission handles and HTTPS responses are deterministic boundaries.
No APK is downloaded or installed, and this is not Android device evidence.
"""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
JAVA = ROOT / "android/app/src/main/java/com/eabusham/routervpn"

STUBS = {
    "android/Manifest.java": '''package android;public final class Manifest {public static final class permission {public static final String POST_NOTIFICATIONS="post_notifications";}}''',
    "android/R.java": '''package android;public final class R {public static final class drawable {public static final int stat_sys_download_done=1;}}''',
    "android/os/Build.java": '''package android.os;public final class Build {public static final class VERSION {public static int SDK_INT=33;}}''',
    "android/content/pm/PackageManager.java": '''package android.content.pm;public final class PackageManager {public static final int PERMISSION_GRANTED=0;public static final int PERMISSION_DENIED=-1;public static final int GET_SIGNATURES=64,GET_SIGNING_CERTIFICATES=134217728;public final PackageInfo info=new PackageInfo();public PackageInfo getPackageInfo(String name,int flags){return info;}}''',
    "android/content/pm/Signature.java": '''package android.content.pm;public final class Signature {final byte[] bytes;public Signature(byte[] b){bytes=b;}public byte[] toByteArray(){return bytes;}}''',
    "android/content/pm/SigningInfo.java": '''package android.content.pm;public final class SigningInfo {public boolean multiple;public Signature[] history={new Signature("installed signing fixture".getBytes(java.nio.charset.StandardCharsets.UTF_8))};public boolean hasMultipleSigners(){return multiple;}public Signature[] getSigningCertificateHistory(){return history;}}''',
    "android/content/pm/PackageInfo.java": '''package android.content.pm;public final class PackageInfo {public int versionCode=2;public String versionName="0.1.2-"+"1".repeat(12);public SigningInfo signingInfo=new SigningInfo();public Signature[] signatures=signingInfo.history;public long getLongVersionCode(){return versionCode;}}''',
    "android/content/res/AssetManager.java": '''package android.content.res;public class AssetManager {public String source="",delivery="";public java.io.InputStream open(String name)throws java.io.IOException {String value;if(name.equals("ROUTER-VPN-SOURCE.json"))value=source;else if(name.equals("ROUTER-VPN-ANDROID.json"))value=delivery;else throw new java.io.IOException("unknown asset");return new java.io.ByteArrayInputStream(value.getBytes(java.nio.charset.StandardCharsets.UTF_8));}}''',
    "android/content/res/Resources.java": '''package android.content.res;public class Resources {public static class Metrics {public float density=1;}public Metrics getDisplayMetrics(){return new Metrics();}}''',
    "android/content/SharedPreferences.java": '''package android.content;public interface SharedPreferences {String getString(String k,String d);boolean getBoolean(String k,boolean d);int getInt(String k,int d);long getLong(String k,long d);Editor edit();interface Editor {Editor putString(String k,String v);Editor putBoolean(String k,boolean v);Editor putLong(String k,long v);Editor putInt(String k,int v);Editor remove(String k);void apply();}}''',
    "android/content/MemoryPreferences.java": '''package android.content;public class MemoryPreferences implements SharedPreferences {
 public final java.util.Map<String,Object> values=new java.util.concurrent.ConcurrentHashMap<>();
 public String getString(String k,String d){return (String)values.getOrDefault(k,d);}public boolean getBoolean(String k,boolean d){return (Boolean)values.getOrDefault(k,d);}public int getInt(String k,int d){return (Integer)values.getOrDefault(k,d);}public long getLong(String k,long d){return (Long)values.getOrDefault(k,d);}
 public Editor edit(){return new Editor(){final java.util.Map<String,Object> staged=new java.util.HashMap<>();public Editor putString(String k,String v){staged.put(k,v);return this;}public Editor putBoolean(String k,boolean v){staged.put(k,v);return this;}public Editor putLong(String k,long v){staged.put(k,v);return this;}public Editor putInt(String k,int v){staged.put(k,v);return this;}public Editor remove(String k){staged.put(k,null);return this;}public void apply(){for(var e:staged.entrySet()){if(e.getValue()==null)values.remove(e.getKey());else values.put(e.getKey(),e.getValue());}}};}}
''',
    "android/content/Context.java": '''package android.content;public class Context {
 public static final int MODE_PRIVATE=0;public int permission=-1;public final MemoryPreferences prefs=new MemoryPreferences();public final android.content.res.AssetManager assets=new android.content.res.AssetManager();public final android.app.NotificationManager manager=new android.app.NotificationManager();public final java.util.List<Intent> intents=new java.util.ArrayList<>();
 public Context getApplicationContext(){return this;}public MemoryPreferences getSharedPreferences(String n,int m){return prefs;}public android.content.res.AssetManager getAssets(){return assets;}public android.content.res.Resources getResources(){return new android.content.res.Resources();}public final android.content.pm.PackageManager packageManager=new android.content.pm.PackageManager();public android.content.pm.PackageManager getPackageManager(){return packageManager;}public String getPackageName(){return "com.eabusham.routervpn";}public int checkSelfPermission(String p){return permission;}public <T>T getSystemService(Class<T> t){return t.cast(manager);}public void startActivity(Intent i){intents.add(i);}}
''',
    "android/content/Intent.java": '''package android.content;public class Intent {public static final String ACTION_VIEW="view";public static final int FLAG_ACTIVITY_NEW_TASK=1;public final String action;public android.net.Uri data;public Intent(String a){action=a;}public Intent(String a,android.net.Uri d){action=a;data=d;}public Intent addFlags(int f){return this;}public Intent putExtra(String k,String v){return this;}}''',
    "android/content/DialogInterface.java": '''package android.content;public interface DialogInterface {interface OnClickListener {void onClick(DialogInterface d,int i);}interface OnShowListener {void onShow(DialogInterface d);}}''',
    "android/content/ContentValues.java": '''package android.content;public class ContentValues {}''',
    "android/database/Cursor.java": '''package android.database;public interface Cursor {}''',
    "android/content/ContentProvider.java": '''package android.content;public abstract class ContentProvider {public Context context;public Context getContext(){return context;}public abstract boolean onCreate();public abstract android.database.Cursor query(android.net.Uri u,String[] p,String s,String[] a,String o);public abstract String getType(android.net.Uri u);public abstract android.net.Uri insert(android.net.Uri u,ContentValues v);public abstract int delete(android.net.Uri u,String s,String[] a);public abstract int update(android.net.Uri u,ContentValues v,String s,String[] a);}''',
    "android/net/Uri.java": '''package android.net;public class Uri {final String value;private Uri(String s){value=s;}public static Uri parse(String s){return new Uri(s);}public String toString(){return value;}}''',
    "android/provider/Settings.java": '''package android.provider;public final class Settings {public static final String ACTION_VPN_SETTINGS="vpn_settings",ACTION_APP_NOTIFICATION_SETTINGS="notification_settings",ACTION_APPLICATION_DETAILS_SETTINGS="application_settings",EXTRA_APP_PACKAGE="package";}''',
    "android/app/Activity.java": '''package android.app;public class Activity extends android.content.Context {public boolean finishing,destroyed,rationale;public int requests,requestedCode;public String[] requestedPermissions;public boolean isFinishing(){return finishing;}public boolean isDestroyed(){return destroyed;}public void runOnUiThread(Runnable r){r.run();}public boolean shouldShowRequestPermissionRationale(String p){return rationale;}public void requestPermissions(String[] p,int c){requests++;requestedCode=c;requestedPermissions=p;}}''',
    "android/view/View.java": '''package android.view;public class View {public boolean enabled=true;public OnClickListener click;public interface OnClickListener {void onClick(View v);}public void setOnClickListener(OnClickListener c){click=c;}public void setEnabled(boolean b){enabled=b;}public void setPadding(int a,int b,int c,int d){}public void performClick(){if(enabled&&click!=null)click.onClick(this);}}''',
    "android/widget/TextView.java": '''package android.widget;public class TextView extends android.view.View {public String text="";public TextView(android.content.Context c){}public void setText(CharSequence s){text=s.toString();}public void setTextIsSelectable(boolean b){}}''',
    "android/widget/Button.java": '''package android.widget;public class Button extends TextView {public Button(android.content.Context c){super(c);}public void setAllCaps(boolean b){}}''',
    "android/widget/LinearLayout.java": '''package android.widget;public class LinearLayout extends android.view.View {public static final int VERTICAL=1;public final java.util.List<android.view.View> children=new java.util.ArrayList<>();public LinearLayout(android.content.Context c){}public void setOrientation(int i){}public void addView(android.view.View v){children.add(v);}}''',
    "android/widget/ScrollView.java": '''package android.widget;public class ScrollView extends android.view.View {public android.view.View child;public ScrollView(android.content.Context c){}public void addView(android.view.View v){child=v;}}''',
    "android/widget/Toast.java": '''package android.widget;public class Toast {public static final int LENGTH_LONG=1;public static String last="";public static Toast makeText(android.content.Context c,CharSequence s,int d){last=s.toString();return new Toast();}public void show(){}}''',
    "android/app/AlertDialog.java": '''package android.app;public class AlertDialog implements android.content.DialogInterface {
 public static AlertDialog last;public android.view.View view;public String title;public String[] items;public android.content.DialogInterface.OnClickListener itemClick;private android.content.DialogInterface.OnShowListener onShow;private boolean visible;
 public boolean isShowing(){return visible;}public void show(){visible=true;last=this;if(onShow!=null)onShow.onShow(this);}public void dismiss(){visible=false;}public void setOnShowListener(android.content.DialogInterface.OnShowListener l){onShow=l;}
 public static class Builder {final AlertDialog d=new AlertDialog();public Builder(android.content.Context c){}public Builder setTitle(String s){d.title=s;return this;}public Builder setView(android.view.View v){d.view=v;return this;}public Builder setItems(String[] a,android.content.DialogInterface.OnClickListener l){d.items=a;d.itemClick=l;return this;}public Builder setNegativeButton(String s,android.content.DialogInterface.OnClickListener l){return this;}public Builder setPositiveButton(String s,android.content.DialogInterface.OnClickListener l){return this;}public AlertDialog create(){return d;}public AlertDialog show(){d.show();return d;}}}
''',
    "android/app/NotificationChannel.java": '''package android.app;public class NotificationChannel {public NotificationChannel(String a,String b,int c){if(android.os.Build.VERSION.SDK_INT<26)throw new AssertionError("channel on old API");}}''',
    "android/app/NotificationManager.java": '''package android.app;public class NotificationManager {public static final int IMPORTANCE_DEFAULT=3;public int notifications,channels;public void createNotificationChannel(NotificationChannel c){channels++;}public void notify(int id,Notification n){notifications++;}}''',
    "android/app/PendingIntent.java": '''package android.app;public class PendingIntent {public static final int FLAG_UPDATE_CURRENT=1,FLAG_IMMUTABLE=2;public static android.content.Intent last;public static PendingIntent getActivity(android.content.Context c,int r,android.content.Intent i,int f){last=i;return new PendingIntent();}}''',
    "android/app/Notification.java": '''package android.app;public class Notification {public static class Builder {public Builder(android.content.Context c){}public Builder(android.content.Context c,String channel){if(android.os.Build.VERSION.SDK_INT<26)throw new AssertionError("API26 builder on Android24/25");}public Builder setSmallIcon(int i){return this;}public Builder setContentTitle(String s){return this;}public Builder setContentText(String s){return this;}public Builder setContentIntent(PendingIntent p){return this;}public Builder setAutoCancel(boolean b){return this;}public Notification build(){return new Notification();}}}''',
}

HARNESS = r'''package com.eabusham.routervpn;
import android.app.*;import android.widget.*;import android.os.Build;import java.net.*;import java.io.*;import java.util.*;import java.util.concurrent.*;import java.util.concurrent.atomic.*;import org.json.*;
public final class UpdatesHarness {
 static final String CURRENT="1".repeat(40),TARGET="2".repeat(40),DIGEST="a".repeat(64),BASE="https://github.com/Eabusham2/router-vpn/releases/download/router-vpn-sha-"+TARGET+"/",APK=BASE+"app-debug.apk",CERT=certificate();
 static String certificate(){try {byte[] raw=java.security.MessageDigest.getInstance("SHA-256").digest("installed signing fixture".getBytes(java.nio.charset.StandardCharsets.UTF_8));return java.util.HexFormat.of().formatHex(raw);}catch(Exception e){throw new AssertionError(e);}}
 static int checks;static volatile String fault="";static final AtomicInteger requests=new AtomicInteger();static volatile CountDownLatch entered,release;
 static void check(boolean b,String m){checks++;if(!b)throw new AssertionError(m);}
 static Activity owner()throws Exception{Activity a=new Activity();a.assets.source=new JSONObject().put("repository","Eabusham2/router-vpn").put("source_sha",CURRENT).toString();a.assets.delivery=new JSONObject().put("schema_version",1).put("source_sha",CURRENT).put("application_id","com.eabusham.routervpn").put("version_code",2).put("variant","debug").put("signing","debug-signed").put("certificate_sha256","").toString();return a;}
 static JSONObject asset(String name,long size)throws Exception{return new JSONObject().put("name",name).put("size",size).put("browser_download_url",BASE+name);}
 static String response(URL u)throws Exception {
  String path=u.getPath();
  if(path.endsWith("/releases")){
   if(entered!=null){entered.countDown();if(!release.await(5,TimeUnit.SECONDS))throw new AssertionError("held scan timed out");}
   JSONArray assets=new JSONArray().put(asset("RouterVPN-RELEASE.json",500)).put(asset("app-debug.apk",1024));
   if(fault.equals("duplicate"))assets.put(asset("app-debug.apk",1024));
   if(fault.equals("foreign-apk"))assets.getJSONObject(1).put("browser_download_url",APK.replace("Eabusham2/router-vpn","other/repo"));
   if(fault.equals("foreign-manifest"))assets.getJSONObject(0).put("browser_download_url",BASE.replace(TARGET,CURRENT)+"RouterVPN-RELEASE.json");
   return new JSONArray().put(new JSONObject().put("tag_name","router-vpn-sha-"+TARGET).put("target_commitish",fault.equals("wrong-target")?CURRENT:TARGET).put("draft",false).put("assets",assets)).toString();
  }
  if(path.contains("/compare/"))return new JSONObject().put("status",fault.equals("diverged")?"diverged":"ahead").put("ahead_by",1).put("behind_by",0).put("base_commit",new JSONObject().put("sha",CURRENT)).put("merge_base_commit",new JSONObject().put("sha",CURRENT)).toString();
  if(u.toString().equals(BASE+"RouterVPN-RELEASE.json")) {
   JSONObject delivery=new JSONObject().put("schema_version",1).put("source_sha",TARGET).put("application_id","com.eabusham.routervpn")
    .put("version_code",fault.equals("version")?2:3).put("version_name","0.1.3-"+TARGET.substring(0,12)).put("variant","release").put("signing","production-signed")
    .put("certificate_sha256",fault.equals("certificate")?"f".repeat(64):CERT).put("compatibility_asset","app-debug.apk")
    .put("apk_signature_verified",!fault.equals("unverified-signature")).put("apk_size",1024).put("apk_sha256",DIGEST);
   if(fault.equals("delivery-sha"))delivery.put("source_sha",CURRENT);
   JSONObject manifest=new JSONObject().put("schema_version",1).put("repository","Eabusham2/router-vpn").put("source_sha",TARGET).put("tag","router-vpn-sha-"+TARGET).put("producer_workflow",fault.equals("producer")?"untrusted.yml":"build-all.yml").put("assets",new JSONArray().put(new JSONObject().put("name","app-debug.apk").put("size",fault.equals("size")?1025:1024).put("sha256",fault.equals("digest")?"bad":DIGEST)));
   if(!fault.equals("missing-delivery"))manifest.put("android_delivery",delivery);
   return manifest.toString();
  }
  throw new AssertionError("unexpected endpoint: "+u);
 }
 static final class HTTP extends HttpURLConnection {
  byte[] bytes;HTTP(URL u){super(u);}public void connect(){}public void disconnect(){}public boolean usingProxy(){return false;}
  public int getResponseCode()throws IOException{requests.incrementAndGet();if(fault.equals("network"))throw new IOException("fixture unavailable");try{bytes=response(url).getBytes(java.nio.charset.StandardCharsets.UTF_8);return 200;}catch(Exception e){throw new IOException(e);}}
  public long getContentLengthLong(){return bytes==null?-1:bytes.length;}public InputStream getInputStream(){return new ByteArrayInputStream(bytes);}
 }
 static void scan(Activity a)throws Exception{CountDownLatch done=new CountDownLatch(1);RouterVpnUpdateProvider.requestCheck(a,done::countDown);check(done.await(5,TimeUnit.SECONDS),"scan completion");check(!RouterVpnUpdateProvider.isChecking(),"scan owner not released");}
 static void valid(Activity a)throws Exception{fault="";scan(a);check(RouterVpnUpdateProvider.availableUpdate(a)!=null,"verified exact-source receipt missing");}
 static LinearLayout body(AlertDialog d){return (LinearLayout)((ScrollView)d.view).child;}
 static Button button(AlertDialog d,int i){return (Button)body(d).children.get(i);}
 static void receipts()throws Exception{
  long now=100_000_000L;
  check(AndroidUpdateSnapshot.verified(CURRENT,CURRENT,TARGET,APK,1024,DIGEST,now,true,now)!=null,"valid snapshot");
  for(int bad=0;bad<15;bad++){
   String installed=CURRENT,from=CURRENT,target=TARGET,url=APK,digest=DIGEST;long bytes=1024,at=now,clock=now;boolean verified=true;
   switch(bad){case 0:installed="dev";break;case 1:from=TARGET;break;case 2:target=CURRENT;break;case 3:target="bad";break;case 4:url=APK.replace(TARGET,CURRENT);break;case 5:url+="?download=1";break;case 6:url+="#label";break;case 7:url=url.replace("github.com","evil.test");break;case 8:bytes=0;break;case 9:bytes=768L*1024*1024+1;break;case 10:digest="a".repeat(63);break;case 11:at=0;break;case 12:clock=now-1;break;case 13:clock=now+AndroidUpdateSnapshot.MAX_AGE_MS+1;break;case 14:verified=false;break;}
   check(AndroidUpdateSnapshot.verified(installed,from,target,url,bytes,digest,at,verified,clock)==null,"invalid snapshot "+bad);
  }
 }
 static void discovery()throws Exception{
  Activity a=owner();valid(a);check(a.manager.notifications==0&&a.requests==0,"denied notifications must not notify or auto-prompt");
  for(String bad:List.of("duplicate","foreign-apk","foreign-manifest","wrong-target","diverged","producer","size","digest","version","certificate","unverified-signature","delivery-sha","missing-delivery")){fault=bad;scan(a);check(RouterVpnUpdateProvider.availableUpdate(a)==null,"bad metadata adopted: "+bad);check(!a.prefs.values.containsKey("apk_url"),"rejected old receipt retained: "+bad);}
  valid(a);fault="network";scan(a);check(RouterVpnUpdateProvider.availableUpdate(a)!=null,"temporary check failure erased still-valid receipt");check(RouterVpnUpdateProvider.checkMessage(a).contains("unavailable"),"missing check failure");
  a.assets.source=a.assets.source.replace(CURRENT,TARGET);check(RouterVpnUpdateProvider.availableUpdate(a)==null,"different installed source reused cached receipt");
  a.prefs.values.put("check_message",42);check(RouterVpnUpdateProvider.checkMessage(a).contains("Check again"),"malformed preferences crashed UI");
 }
 static void installedSigningAndVersion()throws Exception{
  for(int api:List.of(24,28,36)){
   Build.VERSION.SDK_INT=api;Activity a=owner();valid(a);check(RouterVpnUpdateProvider.availableUpdate(a).deliveryLabel().contains("Production-signed"),"truthful delivery label");
   a.packageManager.info.signatures=new android.content.pm.Signature[]{new android.content.pm.Signature("different key".getBytes())};
   a.packageManager.info.signingInfo.history=a.packageManager.info.signatures;
   check(RouterVpnUpdateProvider.availableUpdate(a)==null,"cached receipt accepted another installed signer on API "+api);
   a=owner();a.packageManager.info.versionCode=3;scan(a);check(RouterVpnUpdateProvider.availableUpdate(a)==null,"actual installed version was ignored");
   a=owner();a.assets.delivery=new JSONObject(a.assets.delivery).put("signing","production-signed").put("variant","release").put("certificate_sha256",CERT).toString();valid(a);
   a.assets.delivery=new JSONObject(a.assets.delivery).put("certificate_sha256","f".repeat(64)).toString();check(RouterVpnUpdateProvider.availableUpdate(a)==null,"forged installed certificate metadata was trusted");
  }
  Build.VERSION.SDK_INT=36;Activity a=owner();a.packageManager.info.signingInfo.multiple=true;scan(a);check(RouterVpnUpdateProvider.availableUpdate(a)==null,"multiple signers accepted");
  a=owner();a.packageManager.info.signingInfo.history=new android.content.pm.Signature[]{a.packageManager.info.signatures[0],a.packageManager.info.signatures[0]};scan(a);check(RouterVpnUpdateProvider.availableUpdate(a)==null,"unimplemented rotation lineage accepted");
  a=owner();a.assets.delivery=new JSONObject(a.assets.delivery).put("schema_version",99).toString();scan(a);check(RouterVpnUpdateProvider.availableUpdate(a)==null,"invalid installed metadata schema accepted");
  Build.VERSION.SDK_INT=33;
 }
 static void notificationVersions()throws Exception{
  for(int api:List.of(24,25,26,32,33,36)){Build.VERSION.SDK_INT=api;Activity a=owner();a.permission=0;valid(a);check(a.manager.notifications==1,"notification omitted on API "+api);check(a.manager.channels==(api>=26?1:0),"channel API gate");check(PendingIntent.last.data.toString().equals(APK),"notification wrong exact asset");}
  Build.VERSION.SDK_INT=33;
 }
 static void dialog()throws Exception{
  Activity a=owner();valid(a);AndroidUpdateDialog.showHelpActions(a);AlertDialog menu=AlertDialog.last;check(menu.items[0].equals("Updates"),"missing help update action");menu.itemClick.onClick(menu,0);AlertDialog d=AlertDialog.last;
  check(d.title.equals("Router VPN updates")&&button(d,2).enabled&&a.requests==0,"updates not accessible without notification permission");
  button(d,2).performClick();check(a.intents.size()==1&&a.intents.get(0).data.toString().equals(APK),"download action not exact cached asset");
  a.assets.source=a.assets.source.replace(CURRENT,TARGET);button(d,2).performClick();check(a.intents.size()==1&&!button(d,2).enabled,"download action did not revalidate source");
  button(d,3).performClick();check(a.requests==1&&a.requestedCode==AndroidUpdateDialog.NOTIFICATION_PERMISSION&&a.requestedPermissions.length==1,"explicit permission action");
  check(!AndroidUpdateDialog.onPermissionResult(a,42),"unrelated permission swallowed");check(AndroidUpdateDialog.onPermissionResult(a,AndroidUpdateDialog.NOTIFICATION_PERMISSION)&&a.manager.notifications==0,"denial still notified");
  button(d,3).performClick();check(a.requests==1&&a.intents.get(a.intents.size()-1).action.equals(android.provider.Settings.ACTION_APP_NOTIFICATION_SETTINGS),"repeat denied permission must open settings");
  a.assets.source=a.assets.source.replace(TARGET,CURRENT);a.permission=0;AndroidUpdateDialog.onPermissionResult(a,AndroidUpdateDialog.NOTIFICATION_PERMISSION);check(a.manager.notifications==1,"grant omitted validated update notification");
  a.prefs.values.put("verified_at_ms",System.currentTimeMillis()-AndroidUpdateSnapshot.MAX_AGE_MS-1);AndroidUpdateDialog.onPermissionResult(a,AndroidUpdateDialog.NOTIFICATION_PERMISSION);check(a.manager.notifications==1,"expired receipt notified after grant");
  for(int api:List.of(24,25)){Build.VERSION.SDK_INT=api;AndroidUpdateDialog.show(a);button(AlertDialog.last,3).performClick();check(a.intents.get(a.intents.size()-1).action.equals(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS),"old Android notification settings fallback");}
  Build.VERSION.SDK_INT=33;
 }
 static void singleFlight()throws Exception{
  Activity a=owner();fault="";entered=new CountDownLatch(1);release=new CountDownLatch(1);CountDownLatch done=new CountDownLatch(2);int before=requests.get();
  RouterVpnUpdateProvider.requestCheck(a,done::countDown);check(entered.await(3,TimeUnit.SECONDS),"worker did not start");RouterVpnUpdateProvider.requestCheck(a,done::countDown);
  AndroidUpdateDialog.show(a);AlertDialog d=AlertDialog.last;check(!button(d,1).enabled,"visible startup scan should disable Check");String status=((TextView)body(d).children.get(0)).text;d.dismiss();a.destroyed=true;release.countDown();check(done.await(3,TimeUnit.SECONDS),"joined callbacks missing");
  long deadline=System.nanoTime()+TimeUnit.SECONDS.toNanos(1);while(requests.get()<before+3&&System.nanoTime()<deadline)Thread.yield();check(requests.get()==before+3,"parallel duplicate discovery scan");check(((TextView)body(d).children.get(0)).text.equals(status),"destroyed dialog rendered late result");entered=null;release=null;
 }
 public static void main(String[]args)throws Exception{URL.setURLStreamHandlerFactory(protocol->protocol.equals("https")?new URLStreamHandler(){protected URLConnection openConnection(URL u){return new HTTP(u);}}:null);receipts();discovery();installedSigningAndVersion();notificationVersions();dialog();singleFlight();System.out.println("Android shipped updates: PASS ("+checks+" checks; UI/HTTPS/permission boundary doubles)");}
}
'''


def main():
    jar = Path(os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar"))
    if not jar.is_file():
        raise RuntimeError("Real Android JSON implementation required")
    product = (JAVA / "ProductActivity.java").read_text()
    assert "AndroidUpdateDialog.showHelpActions(this)" in product
    assert "AndroidUpdateDialog.onPermissionResult(this,requestCode)" in product
    assert "android.permission.POST_NOTIFICATIONS" in (ROOT / "android/app/src/main/AndroidManifest.xml").read_text()
    assert "REQUEST_INSTALL_PACKAGES" not in (ROOT / "android/app/src/main/AndroidManifest.xml").read_text()
    with tempfile.TemporaryDirectory(prefix="android-updates-") as directory:
        work = Path(directory)
        src = work / "src"
        for name, content in STUBS.items():
            path = src / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        app = src / "com/eabusham/routervpn"
        app.mkdir(parents=True)
        for name in ("RouterVpnUpdateProvider", "AndroidUpdateSnapshot", "AndroidUpdateDialog"):
            shutil.copyfile(JAVA / (name + ".java"), app / (name + ".java"))
        (app / "UpdatesHarness.java").write_text(HARNESS)
        classes = work / "classes"
        compile_command = ["javac", "--release", "17", "-encoding", "UTF-8", "-proc:none", "-cp", str(jar), "-d", str(classes), *map(str, src.rglob("*.java"))]
        command = ["java", "-cp", str(classes) + os.pathsep + str(jar), "com.eabusham.routervpn.UpdatesHarness"]
        subprocess.run(compile_command, check=True, timeout=60)
        subprocess.run(command, check=True, timeout=45)
        snapshot = app / "AndroidUpdateSnapshot.java"
        original = snapshot.read_text()
        for marker in ("!installed.equals(checkedFrom)", "now-at > MAX_AGE_MS"):
            assert marker in original
            snapshot.write_text(original.replace(marker, "false", 1))
            subprocess.run(compile_command, check=True, timeout=60, capture_output=True)
            rejected = subprocess.run(command, timeout=45, capture_output=True, text=True)
            assert rejected.returncode != 0 and "invalid snapshot" in rejected.stderr, marker
        print("Android update installed-source and expiry negative controls: PASS")


if __name__ == "__main__":
    main()
