package com.eabusham.routervpn;

import android.content.Context;

import com.wireguard.android.backend.Tunnel;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Android AUTO/SMART/CUSTOM/ALL chooses only native candidates and requires selected-node path proof. */
final class AndroidModeOrchestrator {
    interface Callback { void progress(String message); void finished(boolean success, String modeId, String message); }
    private enum Kind { WG, AWG, LIBBOX, XRAY }
    private static final class Candidate {
        final Kind kind; final String id,name; final List<String> layers,simplify; final int order;
        Candidate(Kind kind,String id,String name,List<String> layers,List<String>simplify,int order){this.kind=kind;this.id=id;this.name=name;this.layers=layers;this.simplify=simplify;this.order=order;}
    }

    private final Context context;
    private final NativeWireGuardController wg;
    private final NativeAmneziaWGController awg;
    private final NativeSingBoxController sing;
    private final NativeXrayController xray;
    private final ExecutorService executor=Executors.newSingleThreadExecutor();
    private volatile boolean running;
    private volatile Candidate current;

    AndroidModeOrchestrator(Context context, NativeWireGuardController wg, NativeAmneziaWGController awg, NativeSingBoxController sing, NativeXrayController xray){this.context=context.getApplicationContext();this.wg=wg;this.awg=awg;this.sing=sing;this.xray=xray;}
    boolean isRunning(){return running;} void close(){executor.shutdownNow();}
    void auto(File bundle, boolean smart, Callback cb){run(bundle,smart,null,cb);} void custom(File bundle,List<String> requested,Callback cb){run(bundle,false,new ArrayList<>(requested),cb);} void all(File bundle,Callback cb){runAll(bundle,cb);}

    private void run(File bundle,boolean smart,List<String> custom,Callback cb){
        if(running){cb.finished(false,"","Another Android mode selection is already running.");return;}
        running=true;
        final String requested=custom!=null?"CUSTOM":smart?"SMART AUTO":"AUTO";
        AndroidHomeStateStore.begin(context,requested,"","auto");
        executor.execute(()->{
            try{
                List<Candidate> candidates=collect(bundle,true);
                if(custom!=null){Set<String>wanted=new HashSet<>();for(String layer:custom){String v=layer==null?"":layer.trim().toLowerCase();if(!v.isEmpty())wanted.add(v);}if(wanted.isEmpty())throw new IllegalStateException("CUSTOM requires at least one layer.");candidates.removeIf(c->!c.layers.containsAll(wanted));candidates.sort(Comparator.<Candidate>comparingInt(c->c.layers.size()-wanted.size()).thenComparingInt(c->c.order));}
                if(candidates.isEmpty())throw new IllegalStateException(custom==null?"No compliant native Android AUTO candidate is available.":"No compliant native Android candidate contains the requested CUSTOM layers.");
                Candidate best=null;
                for(Candidate c:candidates){cb.progress(requested+" trying "+c.name+"…");if(startAndProve(bundle,c,cb)){best=c;break;}}
                if(best==null)throw new IllegalStateException("No candidate passed selected-node path proof.");
                Candidate initial=best;
                if(smart)best=smartReduce(bundle,best,candidates,cb);
                current=best;
                String transition=smart&&!initial.id.equals(best.id)?initial.id+" -> "+best.id:"";
                AndroidHomeStateStore.connected(context,requested,best.id,baseFor(best),transition);
                cb.finished(true,best.id,requested+" selected "+best.name+" after real selected-node path proof.");
            }catch(Throwable error){try{stopCurrent();}catch(Throwable ignored){}AndroidHomeStateStore.failed(context,safe(error));cb.finished(false,"",safe(error));}finally{running=false;}
        });
    }

    private void runAll(File bundle,Callback cb){
        if(running){cb.finished(false,"","Another Android mode selection is already running.");return;}
        running=true;AndroidHomeStateStore.begin(context,"ALL","","auto");
        executor.execute(()->{
            try{
                List<Candidate> candidates=collect(bundle,false);candidates.sort(Comparator.<Candidate>comparingInt(AndroidModeOrchestrator::protectionRank).reversed().thenComparingInt(c->c.order));
                if(candidates.isEmpty())throw new IllegalStateException("ALL found no truthful Android-native branch. Composite desktop MAX sidecar chains are not silently downgraded.");
                Candidate best=null;for(Candidate c:candidates){cb.progress("ALL testing protected Android-native branch "+c.name+"…");if(startAndProve(bundle,c,cb)){best=c;break;}}
                if(best==null)throw new IllegalStateException("ALL failed closed because no Android-native branch passed selected-node path proof.");
                current=best;AndroidHomeStateStore.connected(context,"ALL",best.id,baseFor(best),"");
                cb.finished(true,best.id,"ALL selected the strongest available Android-native branch that passed selected-node path proof: "+best.name+". Composite desktop MAX chains remain separate and are never faked on Android.");
            }catch(Throwable error){try{stopCurrent();}catch(Throwable ignored){}AndroidHomeStateStore.failed(context,safe(error));cb.finished(false,"",safe(error));}finally{running=false;}
        });
    }

    private static String baseFor(Candidate c){if(c==null)return"";if(c.kind==Kind.WG)return"wg";if(c.kind==Kind.AWG)return"awg";if(c.kind==Kind.LIBBOX)return"libbox";return"xray";}

    private static int protectionRank(Candidate c){int score=0;Set<String>layers=new HashSet<>(c.layers);if(layers.contains("vless-pq"))score+=1000;if(layers.contains("rosenpass-pq"))score+=900;if(layers.contains("reality"))score+=400;if(layers.contains("xhttp"))score+=300;if(layers.contains("finalmask"))score+=250;if(layers.contains("protocol-split"))score+=220;if(layers.contains("hysteria2"))score+=180;if(layers.contains("quic"))score+=100;if(layers.contains("xtls-vision"))score+=90;if(layers.contains("utls-chrome"))score+=80;if(layers.contains("strong-obfuscation"))score+=70;if(layers.contains("shadowsocks2022"))score+=60;if(layers.contains("amneziawg2"))score+=40;if(layers.contains("wireguard"))score+=20;score+=Math.min(50,layers.size());return score;}

    private Candidate smartReduce(File bundle,Candidate best,List<Candidate> all,Callback cb)throws Exception{Map<String,Candidate>byId=new HashMap<>();for(Candidate c:all)byId.put(c.id,c);Set<String>visited=new HashSet<>();visited.add(best.id);while(true){boolean changed=false;for(String id:best.simplify){if(!visited.add(id))continue;Candidate candidate=byId.get(id);if(candidate==null)continue;Candidate last=best;cb.progress("SMART testing simplification "+last.id+" → "+candidate.id+"…");stopCurrent();if(startAndProve(bundle,candidate,cb)){best=candidate;changed=true;break;}cb.progress("SMART restoring last-known-good "+last.name+"…");if(!startAndProve(bundle,last,cb))throw new IllegalStateException("SMART AUTO could not restore its last-known-good mode.");best=last;}if(!changed)return best;}}

    private boolean startAndProve(File bundle,Candidate c,Callback cb)throws Exception{stopCurrent();boolean up;if(c.kind==Kind.WG)up=startWg(bundle);else if(c.kind==Kind.AWG)up=startAwg(bundle);else if(c.kind==Kind.XRAY)up=startXray(bundle,c.id);else up=startLibbox(bundle,c.id);if(!up){cb.progress(c.name+" failed to establish a native VPN TUN.");stopCurrent();return false;}boolean proof;try{proof=AndroidPathProbe.prove(bundle,8000);}catch(Exception error){cb.progress(c.name+" path proof error: "+safe(error));proof=false;}if(!proof){cb.progress(c.name+" did not reach the selected Router VPN health path; rejecting it.");stopCurrent();return false;}current=c;return true;}
    private boolean startWg(File bundle)throws Exception{CountDownLatch latch=new CountDownLatch(1);final Tunnel.State[]state={Tunnel.State.DOWN};wg.connect(bundle,(s,m,e)->{state[0]=s;latch.countDown();});return latch.await(20,TimeUnit.SECONDS)&&state[0]==Tunnel.State.UP;}
    private boolean startAwg(File bundle)throws Exception{CountDownLatch latch=new CountDownLatch(1);final org.amnezia.awg.backend.Tunnel.State[]state={org.amnezia.awg.backend.Tunnel.State.DOWN};awg.connect(bundle,(s,m,e)->{state[0]=s;latch.countDown();});return latch.await(20,TimeUnit.SECONDS)&&state[0]==org.amnezia.awg.backend.Tunnel.State.UP;}
    private boolean startLibbox(File bundle,String id)throws Exception{NativeSingBoxController.SessionInfo session=sing.prepareSession(bundle,id);sing.start(session);long end=System.currentTimeMillis()+20000L;while(System.currentTimeMillis()<end){String s=sing.getState();if("UP".equals(s))return true;if("FAILED".equals(s)||"REVOKED".equals(s))return false;Thread.sleep(200);}return false;}
    private boolean startXray(File bundle,String id)throws Exception{NativeXrayController.SessionInfo session=xray.prepareSession(bundle,id);xray.start(session);long end=System.currentTimeMillis()+25000L;while(System.currentTimeMillis()<end){String s=xray.getState();if("UP".equals(s))return true;if("FAILED".equals(s)||"REVOKED".equals(s))return false;Thread.sleep(200);}return false;}

    private void stopCurrent()throws Exception{Candidate c=current;if(c==null){if(wg.getState()==Tunnel.State.UP)stopWg();if(awg.getState()==org.amnezia.awg.backend.Tunnel.State.UP)stopAwg();String ls=sing.getState();if("UP".equals(ls)||"STARTING".equals(ls))stopLibbox();String xs=xray.getState();if("UP".equals(xs)||"STARTING".equals(xs))stopXray();AndroidHomeStateStore.disconnected(context);return;}if(c.kind==Kind.WG)stopWg();else if(c.kind==Kind.AWG)stopAwg();else if(c.kind==Kind.XRAY)stopXray();else stopLibbox();current=null;AndroidHomeStateStore.disconnected(context);}
    private void stopWg()throws Exception{CountDownLatch l=new CountDownLatch(1);wg.disconnect((s,m,e)->l.countDown());l.await(8,TimeUnit.SECONDS);} private void stopAwg()throws Exception{CountDownLatch l=new CountDownLatch(1);awg.disconnect((s,m,e)->l.countDown());l.await(8,TimeUnit.SECONDS);} private void stopLibbox()throws Exception{sing.stop();long end=System.currentTimeMillis()+8000;while(System.currentTimeMillis()<end){String s=sing.getState();if("DOWN".equals(s)||"FAILED".equals(s)||"REVOKED".equals(s))return;Thread.sleep(150);}} private void stopXray()throws Exception{xray.stop();long end=System.currentTimeMillis()+8000;while(System.currentTimeMillis()<end){String s=xray.getState();if("DOWN".equals(s)||"FAILED".equals(s)||"REVOKED".equals(s))return;Thread.sleep(150);}}

    private List<Candidate> collect(File bundle,boolean autoOnly)throws Exception{JSONObject root=load(bundle);JSONObject profiles=root.optJSONObject("profiles");JSONArray catalog=root.optJSONArray("modes");boolean strict=AndroidKillSwitchPolicy.strictRequested(root);Set<String>direct=new HashSet<>();for(NativeSingBoxController.ModeInfo m:sing.listDirectLibboxModes(bundle))direct.add(m.id);Set<String>directXray=new HashSet<>();for(NativeXrayController.ModeInfo m:xray.listDirectXrayModes(bundle))directXray.add(m.id);List<Candidate>out=new ArrayList<>();if(catalog==null)return out;for(int i=0;i<catalog.length();i++){JSONObject m=catalog.optJSONObject(i);if(m==null||(autoOnly&&!m.optBoolean("auto_eligible",false)))continue;String id=m.optString("id","");Kind kind=null;if(!strict&&"wg".equals(id)&&has(profiles,"wg","wg.conf"))kind=Kind.WG;else if(!strict&&"awg2-fast".equals(id)&&has(profiles,"awg2-fast","awg.conf"))kind=Kind.AWG;else if(direct.contains(id))kind=Kind.LIBBOX;else if(directXray.contains(id))kind=Kind.XRAY;if(kind==null)continue;out.add(new Candidate(kind,id,m.optString("name",id),strings(m.optJSONArray("layers")),strings(m.optJSONArray("smart_simplify")),i));}return out;}
    private static boolean has(JSONObject profiles,String id,String name){JSONObject p=profiles==null?null:profiles.optJSONObject(id);return p!=null&&!p.optString(name,"").trim().isEmpty();} private static List<String>strings(JSONArray values){if(values==null)return Collections.emptyList();List<String>out=new ArrayList<>();for(int i=0;i<values.length();i++){String v=values.optString(i,"").trim().toLowerCase();if(!v.isEmpty())out.add(v);}return out;}
    private static JSONObject load(File file)throws Exception{if(file==null||!file.isFile()||file.length()<=0||file.length()>64L*1024L*1024L)throw new IllegalStateException("Private node bundle is missing or invalid.");try(FileInputStream in=new FileInputStream(file)){ByteArrayOutputStream out=new ByteArrayOutputStream();byte[]b=new byte[8192];int n,total=0;while((n=in.read(b))!=-1){total+=n;if(total>64*1024*1024)throw new IllegalStateException("Bundle exceeds safety limit.");out.write(b,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private static String safe(Throwable error){String m=error==null?"unknown error":error.getMessage();if(m==null||m.trim().isEmpty())m=error==null?"unknown error":error.getClass().getSimpleName();return m.replace('\n',' ').replace('\r',' ').trim();}
}
