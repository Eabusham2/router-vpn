#!/usr/bin/env python3
"""Run the Home forwarding confirmation and authenticated request against an in-memory Android Network."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile

ANDROID = Path(__file__).resolve().parent
JAVA = ANDROID / "app/src/main/java/com/eabusham/routervpn"
JSON_JAR = os.environ.get("ANDROID_JSON_JAR", "/usr/share/java/com.android.json.jar")

STUBS = {
    "android/content/Context.java": """package android.content;
public class Context {
 public static final String CONNECTIVITY_SERVICE="network";
 public android.net.ConnectivityManager network=new android.net.ConnectivityManager();
 public Object getSystemService(String key){return network;}
 public Context getApplicationContext(){return this;}
}""",
    "android/net/ConnectivityManager.java": """package android.net;
public class ConnectivityManager {
 public Network active; public NetworkCapabilities capabilities=new NetworkCapabilities();
 public Network getActiveNetwork(){return active;}
 public NetworkCapabilities getNetworkCapabilities(Network network){return network==active?capabilities:null;}
}""",
    "android/net/Network.java": """package android.net; import java.net.*; import java.io.*;
public abstract class Network {public abstract URLConnection openConnection(URL url) throws IOException;}""",
    "android/net/NetworkCapabilities.java": """package android.net; public class NetworkCapabilities {
 public static final int TRANSPORT_VPN=4; public boolean vpn=true; public int owner=42;
 public boolean hasTransport(int t){return vpn && t==TRANSPORT_VPN;} public int getOwnerUid(){return owner;}
}""",
    "android/os/Process.java": "package android.os; public class Process {public static int myUid(){return 42;}}",
    "android/os/Build.java": "package android.os; public class Build {public static class VERSION {public static int SDK_INT=35;} public static class VERSION_CODES{public static final int R=30;}}",
    "android/app/AlertDialog.java": """package android.app;
public class AlertDialog {
 public interface Click {void click(AlertDialog d,int which);}
 public static Builder last;
 public static class Builder {
  public Click yes,no;
  public Builder(android.content.Context ignored){}
  public Builder setTitle(String t){return this;} public Builder setMessage(String t){return this;}
  public Builder setPositiveButton(String t,Click c){yes=c;return this;}
  public Builder setNeutralButton(String t,Click c){return this;}
  public Builder setNegativeButton(String t,Click c){no=c;return this;}
  public void show(){last=this;}
 }
}""",
}

HARNESS = r'''package com.eabusham.routervpn;
import android.app.AlertDialog;
import android.net.*;
import android.content.Context;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.util.concurrent.*;
import org.json.*;

final class AndroidHomeStateStore {
 static volatile Snapshot current;
 static Snapshot snapshot(Context c){return current;}
 static final class Snapshot {
  final String activeNodeId,activeExitId,logicalMode,sessionId; final long pathGeneration; final boolean connected;
  Snapshot(String node,String exit,String mode,String session,long generation,boolean up){
   activeNodeId=node;activeExitId=exit;logicalMode=mode;sessionId=session;pathGeneration=generation;connected=up;
  }
 }
}
final class AndroidNodeStore {
 static final int MAX_BUNDLE=1024*1024;
 final Path dir;
 AndroidNodeStore(Path dir){this.dir=dir;}
 File file(String id){return dir.resolve(id+".json").toFile();}
 void save(String id,String host,String token,String proof)throws Exception{
  JSONObject p=new JSONObject().put("id",id).put("router_api","http://"+host+":8787").put("api_token",token).put("node_proof_id",proof);
  Files.writeString(file(id).toPath(),new JSONObject().put("routerProfiles",new JSONArray().put(p)).put("selectedRouterID",id).toString());
 }
}
final class AndroidViaEntryLatencyProbe {static boolean hasActiveOperation(){return false;}}
public class ForwardingFixture extends Context {
 static class Label {String text;void setText(String s){text=s;}}
 final Label forwardButton=new Label();
 boolean forwardingBusy,resumed=true;
 final BlockingQueue<Runnable> queue=new LinkedBlockingQueue<>();
 String message="";
 final Path dir;
 final AndroidNodeStore store;
 final AndroidForwardingMaster forwardingMaster;
 static class Connection {boolean isConnected(){return AndroidHomeStateStore.current.connected;}}
 final Connection connection=new Connection();
 boolean isFinishing(){return false;} boolean isDestroyed(){return false;}
 void runOnUiThread(Runnable r){queue.add(r);}
 void dialog(String title,String body){message=body;} void toast(String s){message=s;}
 String safe(Throwable e){return e==null?"Unknown error":e.getMessage();}
 void next()throws Exception{Runnable action=queue.poll(5,TimeUnit.SECONDS);if(action==null)throw new AssertionError("missing UI result");action.run();}
 // SHIPPING_CALLBACKS

 static class VPN extends Network {
  boolean enabled; int opens,writes; String url,auth,body,reply; Runnable beforeSend,afterSend;
  public URLConnection openConnection(URL target){
   opens++;url=target.toString();
   if(beforeSend!=null){Runnable r=beforeSend;beforeSend=null;r.run();}
   return new HttpURLConnection(target){
    final ByteArrayOutputStream sent=new ByteArrayOutputStream();
    public void disconnect(){} public void connect(){} public boolean usingProxy(){return false;}
    public OutputStream getOutputStream(){writes++;return sent;}
    public int getResponseCode() throws IOException {
     auth=getRequestProperty("Authorization");
     if("PUT".equals(method)){
      body=sent.toString(StandardCharsets.UTF_8);try{enabled=new JSONObject(body).getBoolean("enabled");}catch(Exception e){throw new IOException(e);}
      if(afterSend!=null){Runnable r=afterSend;afterSend=null;r.run();}
     }
     return 200;
    }
    public InputStream getInputStream(){String json=reply==null?"{\"ok\":true,\"enabled\":"+enabled+"}":reply;return new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8));}
   };
  }
 }
 static void check(boolean result,String what){if(!result)throw new AssertionError(what);}
 final VPN vpn=new VPN();
 void owner(String node,String exit,String mode,String session,long generation,boolean up){AndroidHomeStateStore.current=new AndroidHomeStateStore.Snapshot(node,exit,mode,session,generation,up);}
 ForwardingFixture(Path root)throws Exception{
  dir=Files.createTempDirectory(root,"case-");store=new AndroidNodeStore(dir);
  store.save("A","10.7.0.1","token-A","proof-A");store.save("B","10.8.0.1","token-B","proof-B");
  forwardingMaster=new AndroidForwardingMaster(this,store);network.active=vpn;owner("A","","wg","one",1,true);
 }
 AlertDialog.Builder open()throws Exception {
  AlertDialog.last=null;showForwarding();next();
  check(AlertDialog.last!=null && AlertDialog.last.yes!=null,"verified read must open confirmation");return AlertDialog.last;
 }
 static void mainCase(Path root)throws Exception {
  var f=new ForwardingFixture(root);var dialog=f.open();
  check("Forward OFF".equals(f.forwardButton.text) && f.vpn.opens==1 && f.vpn.writes==0,"read without mutation");
  check(f.vpn.url.equals("http://10.7.0.1:8787/api/forwarding/master")&&f.vpn.auth.equals("Bearer token-A"),"read authenticated the displayed Router");
  dialog.yes.click(null,0);f.next();
  check(f.vpn.opens==2 && f.vpn.writes==1 && f.vpn.enabled && f.vpn.auth.equals("Bearer token-A")&&"Forward ON".equals(f.forwardButton.text),"confirmed same owner writes once and reads back");
  dialog=f.open();if(dialog.no!=null)dialog.no.click(null,0);check(f.vpn.writes==1,"cancelled confirmation wrote");
  f.owner("A","B","multihop","two",2,true);f.open().yes.click(null,0);f.next();
  check(f.vpn.url.contains("10.8.0.1")&&f.vpn.auth.equals("Bearer token-B")&&!f.vpn.enabled,"ordered path uses its captured final Router");
 }
 static void stale(Path root,String fault)throws Exception{
  var f=new ForwardingFixture(root);var d=f.open();
  switch(fault){
   case "node":f.owner("B","","wg","one",1,true);break;
   case "session":f.owner("A","","wg","two",1,true);break;
   case "generation":f.owner("A","","wg","one",2,true);break;
   case "external":f.owner("A","","external","one",1,true);break;
   case "disconnected":f.owner("A","","wg","one",1,false);break;
   case "network":f.network.active=new VPN();break;
   case "token":f.store.save("A","10.7.0.1","replacement","proof-A");break;
   case "address":f.store.save("A","10.8.0.1","token-A","proof-A");break;
   case "proof":f.store.save("A","10.7.0.1","token-A","replacement-proof");break;
   case "before-send":f.vpn.beforeSend=()->f.owner("B","","wg","two",2,true);break;
   default:throw new AssertionError(fault);
  }
  d.yes.click(null,0);if(f.forwardingBusy)f.next();
  check(f.vpn.writes==0 && ((VPN)f.network.active).writes==0,"stale confirmation wrote: "+fault);
  check(f.vpn.opens==(fault.equals("before-send")?2:1),"stale owner reached network: "+fault);
 }
 static void late(Path root)throws Exception{
  var f=new ForwardingFixture(root);AlertDialog.last=null;
  f.showForwarding();Runnable result=f.queue.poll(5,TimeUnit.SECONDS);check(result!=null,"read completed");
  f.owner("B","","wg","two",2,true);result.run();
  check(AlertDialog.last==null && "Forward".equals(f.forwardButton.text),"late read advertised another owner");
  f.open();f.vpn.afterSend=()->f.owner("A","","wg","three",3,true);
  AlertDialog.last.yes.click(null,0);f.next();
  check(f.vpn.writes==1 && "Forward".equals(f.forwardButton.text),"late PUT response updated the replacement session");
  f.vpn.reply="{\"ok\":true,\"enabled\":\"false\"}";AlertDialog.last=null;f.showForwarding();f.next();
  check(AlertDialog.last==null && "Forward ?".equals(f.forwardButton.text),"unverified boolean opened confirmation");
 }
 public static void main(String[] args)throws Exception{
  Path root=Path.of(args[0]);mainCase(root);
  for(String fault:new String[]{"node","session","generation","external","disconnected","network","address","token","proof","before-send"})stale(root,fault);
  late(root);System.out.println("Android forwarding: verified active Router/session/network, 10 stale owner refusals, cancellation and late readback PASS");
 }
}
'''


def main():
    source = (JAVA / "ProductActivity.java").read_text()
    callbacks = source[source.index("    private void refreshForwardingState("):source.index("    private void selectHomeDns(")]
    with tempfile.TemporaryDirectory(prefix="router-forwarding-") as temp:
        root = Path(temp)
        for name, content in STUBS.items():
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
        package = root / "com/eabusham/routervpn"
        package.mkdir(parents=True)
        for name in ("AndroidForwardingMaster.java", "AndroidNumericAddress.java", "AndroidProfileSelection.java"):
            shutil.copyfile(JAVA / name, package / name)
        (package / "ForwardingFixture.java").write_text(HARNESS.replace(" // SHIPPING_CALLBACKS", callbacks))
        compile_command = ["javac", "--release", "17", "-cp", JSON_JAR, "-d", str(root), *map(str, root.rglob("*.java"))]
        command = ["java", "-ea", "-cp", os.pathsep.join((str(root), JSON_JAR)),
                   "com.eabusham.routervpn.ForwardingFixture", str(root)]
        subprocess.run(compile_command, check=True, timeout=45)
        subprocess.run(command, check=True, timeout=30)

        client = package / "AndroidForwardingMaster.java"
        original = client.read_text()
        for guard, defect, witness in (
            ("if (!isCurrent(displayed)) throw changed();", "", "stale confirmation wrote: before-send"),
            ("!displayed.token.equals(token)", "false", "stale confirmation wrote: token"),
        ):
            assert original.count(guard) == 1, guard
            client.write_text(original.replace(guard, defect))
            subprocess.run(compile_command, check=True, timeout=45)
            result = subprocess.run(command, text=True, capture_output=True, timeout=30)
            assert result.returncode != 0 and ("AssertionError: " + witness) in result.stderr, result
        print("Android forwarding: removing either the pre-send session check or paired-token check reproduced its unauthorized write")


if __name__ == "__main__":
    main()
