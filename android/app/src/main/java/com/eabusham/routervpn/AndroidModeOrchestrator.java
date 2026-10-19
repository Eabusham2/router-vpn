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
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

/** Android AUTO/SMART/CUSTOM/ALL/logical mode chooser. Every success requires selected-node path proof. */
final class AndroidModeOrchestrator {
    interface Callback { void progress(String message); void finished(boolean success, String modeId, String message); }
    private enum Kind { WG, AWG, LIBBOX, XRAY }
    private static final class Candidate {
        final Kind kind; final String id,name; final List<String> layers,simplify; final int order;
        Candidate(Kind kind,String id,String name,List<String>layers,List<String>simplify,int order){this.kind=kind;this.id=id;this.name=name;this.layers=layers;this.simplify=simplify;this.order=order;}
    }

    private final Context context;
    private final NativeWireGuardController wg;
    private final NativeAmneziaWGController awg;
    private final NativeSingBoxController sing;
    private final NativeXrayController xray;
    private final ExecutorService executor=Executors.newSingleThreadExecutor();
    private volatile boolean running;
    private volatile Candidate current;
    private String selectionSessionId="", selectionNodeId="", selectionSource;

    private static final class SelectionAbortedException extends Exception {
        private static final long serialVersionUID=1L;
        SelectionAbortedException(String message){super(message);}
    }

    AndroidModeOrchestrator(Context context,NativeWireGuardController wg,NativeAmneziaWGController awg,NativeSingBoxController sing,NativeXrayController xray){this.context=context.getApplicationContext();this.wg=wg;this.awg=awg;this.sing=sing;this.xray=xray;}
    boolean isRunning(){return running;}
    boolean isActive(){return current!=null||wg.getState()==Tunnel.State.UP||awg.getState()==org.amnezia.awg.backend.Tunnel.State.UP||runtimeBusy(sing.getState())||runtimeBusy(xray.getState());}
    void close(){executor.shutdownNow();}

    void auto(File bundle,boolean smart,Callback cb){run(bundle,smart,null,cb);}
    void custom(File bundle,List<String>requested,Callback cb){run(bundle,false,new ArrayList<>(requested),cb);}
    void all(File bundle,Callback cb){runAll(bundle,cb);}
    void logical(File bundle,String logicalId,Callback cb){runLogical(bundle,logicalId,cb);}
    void disconnect(Callback cb){
        if(running){cb.finished(false,"","A Router VPN transition is still running.");return;}
        running=true;
        AndroidHomeStateStore.beginPathRevalidation(context,"Router VPN disconnect requested; retaining logical runtime ownership until every child proves terminal.");
        executor.execute(()->{
            try{
                stopCurrent(true);
                cb.finished(true,"","Disconnected Router VPN native transports.");
            }catch(Throwable error){
                String message="Disconnect incomplete; runtime ownership retained: "+safe(error);
                AndroidHomeStateStore.failedPreservingOwnership(context,message);
                cb.finished(false,"",message);
            }finally{running=false;}
        });
    }

    private void run(File bundle,boolean smart,List<String>custom,Callback cb){
        if(running){cb.finished(false,"","Another Android mode selection is already running.");return;}
        running=true;
        final String requested=custom!=null?"CUSTOM":smart?"SMART AUTO":"AUTO";
        final String activeNodeId=nodeId(bundle);
        selectionNodeId=activeNodeId;selectionSource=null;
        selectionSessionId=AndroidHomeStateStore.begin(context,requested,"","auto",activeNodeId);
        executor.execute(()->{
            try{
                List<Candidate> candidates=collect(bundle,true,custom==null);
                if(custom!=null){
                    Set<String>wanted=new HashSet<>();for(String layer:custom){String v=layer==null?"":layer.trim().toLowerCase();if(!v.isEmpty())wanted.add(v);}
                    if(wanted.isEmpty())throw new IllegalStateException("CUSTOM requires at least one layer.");
                    candidates.removeIf(c->!c.layers.containsAll(wanted));
                    candidates.sort(Comparator.<Candidate>comparingInt(c->c.layers.size()-wanted.size()).thenComparingInt(c->c.order));
                }
                if(candidates.isEmpty()){
                    JSONObject profile=selectedProfile(load(bundle));
                    String requirement=autoRequirementLabel(profile);
                    String start=profile==null?AndroidStartLayer.OFF:AndroidStartLayer.selectedMode(load(bundle));
                    String startSuffix=AndroidStartLayer.OFF.equals(start)?"":" with Start Layer "+start;
                    throw new IllegalStateException(custom==null?"No compliant native Android AUTO candidate is available"+(requirement.isEmpty()?"":" after "+requirement+" filtering")+startSuffix+".":"No compliant native Android candidate contains every requested CUSTOM layer"+startSuffix+".");
                }
                Candidate best=null;
                for(Candidate c:candidates){cb.progress(requested+" trying "+c.name+"…");if(startAndProve(bundle,c,cb)){best=c;break;}}
                if(best==null)throw new IllegalStateException("No candidate passed selected-node path proof.");
                Candidate initial=best;
                if(smart)best=smartReduce(bundle,best,candidates,cb);
                checkedBundle(bundle);current=best;
                String transition=smart&&!initial.id.equals(best.id)?initial.id+" -> "+best.id:"";
                AndroidHomeStateStore.connected(context,requested,best.id,baseFor(best),transition,activeNodeId);
                if(best.kind==Kind.LIBBOX)LayeredVpnService.startAutomaticMTU();
                cb.finished(true,best.id,requested+" selected "+best.name+" after real selected-node path proof.");
            }catch(Throwable error){String message=failClosedAfterError(error);cb.finished(false,"",message);}finally{selectionSource=null;running=false;}
        });
    }

    private void runLogical(File bundle,String logicalId,Callback cb){
        if("all".equals(logicalId)){runAll(bundle,cb);return;}
        if(running){cb.finished(false,"","Another Android mode selection is already running.");return;}
        final String activeNodeId=nodeId(bundle);
        running=true;selectionNodeId=activeNodeId;selectionSource=null;
        selectionSessionId=AndroidHomeStateStore.begin(context,logicalId,"","auto",activeNodeId);
        executor.execute(()->{
            try{
                JSONObject root=checkedBundle(bundle);
                JSONObject logical=findLogical(root.optJSONArray("logicalModes"),logicalId);
                if(logical==null)logical=findLogical(root.optJSONArray("logical_modes"),logicalId);
                if(logical==null)throw new IllegalStateException("Unknown logical mode: "+logicalId);
                List<Candidate> available=collect(bundle,false,false);
                Map<String,Candidate> byId=new HashMap<>();for(Candidate c:available)byId.put(c.id,c);
                JSONObject variants=logical.optJSONObject("variants");
                if(variants==null||variants.length()==0)throw new IllegalStateException("Logical mode has no runtime variants: "+logicalId);
                List<String> candidateIds=new ArrayList<>();
                String nativeId=variants.optString("native","");
                if(!nativeId.isEmpty())candidateIds.add(nativeId);
                else if(!logical.optBoolean("base_selector",variants.has("wg")&&variants.has("awg"))){
                    // An AWG-only mode owns its base; an unrelated saved WG
                    // preference must not make that explicit mode disappear.
                    for(String base:new String[]{"wg","awg"}){String id=variants.optString(base,"");if(!id.isEmpty())candidateIds.add(id);}
                    if(candidateIds.size()!=1)throw new IllegalStateException("Logical mode without a base selector requires exactly one runtime variant.");
                }else{
                    for(String base:baseOrder(selectedProfile(root),logical.optBoolean("fallback",false))){String id=variants.optString(base,"");if(!id.isEmpty()&&!candidateIds.contains(id))candidateIds.add(id);}
                }
                Candidate winner=null;List<String> failures=new ArrayList<>();
                for(String rawId:candidateIds){Candidate c=byId.get(rawId);if(c==null){failures.add(rawId+": unavailable on Android under current node/Start Layer policy");continue;}cb.progress(logical.optString("name",logicalId)+" trying "+c.name+"…");if(startAndProve(bundle,c,cb)){winner=c;break;}failures.add(rawId+": selected-node proof or Start Layer requirement failed");}
                if(winner==null)throw new IllegalStateException("Logical mode "+logical.optString("name",logicalId)+" failed closed: "+String.join(" • ",failures));
                checkedBundle(bundle);current=winner;
                String transition=candidateIds.get(0).equals(winner.id)?"":candidateIds.get(0)+" -> "+winner.id;
                AndroidHomeStateStore.connected(context,logicalId,winner.id,baseFor(winner),transition,activeNodeId);
                if(winner.kind==Kind.LIBBOX)LayeredVpnService.startAutomaticMTU();
                cb.finished(true,winner.id,logical.optString("name",logicalId)+" connected with runtime "+winner.id+" after selected-node proof.");
            }catch(Throwable error){String message=failClosedAfterError(error);cb.finished(false,"",message);}finally{selectionSource=null;running=false;}
        });
    }

    private void runAll(File bundle,Callback cb){
        if(running){cb.finished(false,"","Another Android mode selection is already running.");return;}
        final String activeNodeId=nodeId(bundle);
        running=true;selectionNodeId=activeNodeId;selectionSource=null;
        selectionSessionId=AndroidHomeStateStore.begin(context,"ALL","","auto",activeNodeId);
        executor.execute(()->{
            try{
                List<String> bases=baseOrder(selectedProfile(checkedBundle(bundle)),true);
                List<Candidate> candidates=collect(bundle,false,false);
                candidates.removeIf(c->protectionRank(c)==0||!bases.contains(baseFor(c)));
                candidates.sort(Comparator.<Candidate>comparingInt(AndroidModeOrchestrator::protectionRank).reversed().thenComparingInt(c->bases.indexOf(baseFor(c))).thenComparingInt(c->c.order));
                if(candidates.isEmpty())throw new IllegalStateException("ALL requires a complete MAX TLS/QUIC branch under the selected base, fallback and Start Layer policy.");
                Candidate best=null;for(Candidate c:candidates){cb.progress("ALL testing protected Android-native branch "+c.name+"…");if(startAndProve(bundle,c,cb)){best=c;break;}}
                if(best==null)throw new IllegalStateException("ALL failed closed because no Android-native branch passed Start Layer requirements and selected-node path proof.");
                checkedBundle(bundle);current=best;
                String preferred="max-tls-"+bases.get(0),transition=preferred.equals(best.id)?"":preferred+" -> "+best.id;
                AndroidHomeStateStore.connected(context,"ALL",best.id,baseFor(best),transition,activeNodeId);
                if(best.kind==Kind.LIBBOX)LayeredVpnService.startAutomaticMTU();
                cb.finished(true,best.id,"ALL selected complete MAX branch "+best.name+" after selected-node path proof."+(transition.isEmpty()?"":" Fallback: "+transition+"."));
            }catch(Throwable error){String message=failClosedAfterError(error);cb.finished(false,"",message);}finally{selectionSource=null;running=false;}
        });
    }

    private static JSONObject findLogical(JSONArray values,String id){if(values==null)return null;for(int i=0;i<values.length();i++){JSONObject x=values.optJSONObject(i);if(x!=null&&id.equals(x.optString("id")))return x;}return null;}
    private static String baseFor(Candidate c){if(c==null)return"";if(c.kind==Kind.WG||"wg".equals(c.id)||"wg-pq".equals(c.id)||c.id.endsWith("-wg"))return"wg";if(c.kind==Kind.AWG||c.id.startsWith("awg2-")||c.id.endsWith("-awg"))return"awg";if(c.kind==Kind.LIBBOX)return"libbox";return"xray";}
    private static int protectionRank(Candidate c){switch(c.id){case"max-tls-wg":case"max-tls-awg":return 2;case"max-quic-wg":case"max-quic-awg":return 1;default:return 0;}}

    private static List<String> baseOrder(JSONObject profile,boolean logicalFallback){
        Object raw=profile==null?null:profile.opt("base_tunnel");
        if(raw!=null&&!(raw instanceof String))throw new IllegalStateException("Base preference must be a string.");
        String preferred=raw==null?"auto":((String)raw).trim().toLowerCase(Locale.ROOT);
        if(preferred.isEmpty())preferred="auto";
        if(!java.util.Arrays.asList("auto","wg","awg").contains(preferred))throw new IllegalStateException("Unknown base preference.");
        Object fallback=profile==null?null:profile.opt("base_fallback");
        if(fallback!=null&&!(fallback instanceof Boolean))throw new IllegalStateException("Base fallback must be a boolean.");
        String first="awg".equals(preferred)?"awg":"wg";
        List<String> order=new ArrayList<>();order.add(first);
        if("auto".equals(preferred)||(logicalFallback&&!Boolean.FALSE.equals(fallback)))order.add("wg".equals(first)?"awg":"wg");
        return order;
    }

    private Candidate smartReduce(File bundle,Candidate best,List<Candidate>all,Callback cb)throws Exception{
        Map<String,Candidate>byId=new HashMap<>();for(Candidate c:all)byId.put(c.id,c);Set<String>visited=new HashSet<>();visited.add(best.id);
        while(true){boolean changed=false;for(String id:best.simplify){if(!visited.add(id))continue;Candidate candidate=byId.get(id);if(candidate==null)continue;Candidate last=best;cb.progress("SMART testing simplification "+last.id+" → "+candidate.id+"…");stopCurrent(false);if(startAndProve(bundle,candidate,cb)){best=candidate;changed=true;break;}cb.progress("SMART restoring last-known-good "+last.name+"…");if(!startAndProve(bundle,last,cb))throw new IllegalStateException("SMART AUTO could not restore its last-known-good mode.");best=last;}if(!changed)return best;}
    }

    private boolean startAndProve(File bundle,Candidate c,Callback cb)throws Exception{
        JSONObject currentBundle=checkedBundle(bundle);
        String startReason=AndroidStartLayer.nativeCapabilityReason(currentBundle,c.id);
        if(!startReason.isEmpty()){cb.progress(c.name+" rejected before launch: "+startReason);return false;}
        // A teardown failure is an operation failure. It must never be caught
        // as an ordinary bad candidate and followed by another live engine.
        stopCurrent(false);checkSelection();boolean up;
        try{
            if(c.kind==Kind.WG)up=startWg(bundle);else if(c.kind==Kind.AWG)up=startAwg(bundle,c.id);else if(c.kind==Kind.XRAY)up=startXray(bundle,c.id);else up=startLibbox(bundle,c.id);
        }catch(Exception error){
            rethrowCancellation(error);checkedBundle(bundle);
            if(revoked(c))throw new SelectionAbortedException("Android VPN permission was revoked; mode selection stopped.");
            stopCurrent(false);checkedBundle(bundle);
            cb.progress(c.name+" could not prepare or start its native transport; the failed attempt was stopped.");
            return false;
        }
        checkedBundle(bundle);
        if(revoked(c))throw new SelectionAbortedException("Android VPN permission was revoked; mode selection stopped.");
        if(!up){cb.progress(c.name+" failed to establish a native VPN TUN.");stopCurrent(false);return false;}
        boolean proof;try{proof=AndroidPathProbe.prove(bundle,8000);}catch(Exception error){rethrowCancellation(error);checkedBundle(bundle);cb.progress(c.name+" path proof failed.");proof=false;}
        checkedBundle(bundle);
        if(revoked(c))throw new SelectionAbortedException("Android VPN permission was revoked; mode selection stopped.");
        if(!transportUp(c))proof=false;
        if(!proof){cb.progress(c.name+" did not reach the selected Router VPN health path; rejecting it.");stopCurrent(false);return false;}current=c;return true;
    }
    private boolean startWg(File bundle)throws Exception{CountDownLatch latch=new CountDownLatch(1);final Tunnel.State[]state={Tunnel.State.DOWN};final Throwable[]error={null};wg.connectManaged(bundle,(s,m,e)->{state[0]=s;error[0]=e;latch.countDown();});boolean completed=latch.await(20,TimeUnit.SECONDS);if(error[0]!=null)rethrowCancellation(error[0]);return completed&&error[0]==null&&state[0]==Tunnel.State.UP;}
    private boolean startAwg(File bundle,String rawProfileID)throws Exception{CountDownLatch latch=new CountDownLatch(1);final org.amnezia.awg.backend.Tunnel.State[]state={org.amnezia.awg.backend.Tunnel.State.DOWN};final Throwable[]error={null};awg.connectManaged(bundle,rawProfileID,(s,m,e)->{state[0]=s;error[0]=e;latch.countDown();});boolean completed=latch.await(20,TimeUnit.SECONDS);if(error[0]!=null)rethrowCancellation(error[0]);return completed&&error[0]==null&&state[0]==org.amnezia.awg.backend.Tunnel.State.UP;}
    private boolean startLibbox(File bundle,String id)throws Exception{NativeSingBoxController.SessionInfo session=sing.prepareSession(bundle,id);checkedBundle(bundle);sing.start(session);long end=System.currentTimeMillis()+20000L;while(System.currentTimeMillis()<end){checkSelection();String s=sing.getState();if("UP".equals(s))return true;if("FAILED".equals(s)||"REVOKED".equals(s))return false;Thread.sleep(200);}return false;}
    private boolean startXray(File bundle,String id)throws Exception{NativeXrayController.SessionInfo session=xray.prepareSession(bundle,id);checkedBundle(bundle);xray.start(session);long end=System.currentTimeMillis()+25000L;while(System.currentTimeMillis()<end){checkSelection();String s=xray.getState();if("UP".equals(s))return true;if("FAILED".equals(s)||"REVOKED".equals(s))return false;Thread.sleep(200);}return false;}

    private boolean revoked(Candidate c){return(c.kind==Kind.LIBBOX&&"REVOKED".equals(sing.getState()))||(c.kind==Kind.XRAY&&"REVOKED".equals(xray.getState()));}
    private boolean transportUp(Candidate c){if(c.kind==Kind.WG)return wg.getState()==Tunnel.State.UP;if(c.kind==Kind.AWG)return awg.getState()==org.amnezia.awg.backend.Tunnel.State.UP;return"UP".equals(c.kind==Kind.XRAY?xray.getState():sing.getState());}
    private static void rethrowCancellation(Throwable error)throws Exception{
        for(int depth=0;error!=null&&depth<16;depth++,error=error.getCause()){
            if(error instanceof InterruptedException){Thread.currentThread().interrupt();throw new InterruptedException("Android mode selection was interrupted.");}
            if(error instanceof SelectionAbortedException)throw(SelectionAbortedException)error;
            if(error instanceof CancellationException||error instanceof SecurityException)throw new SelectionAbortedException("Android mode selection was cancelled or VPN permission was lost.");
        }
    }
    private boolean ownsSelection(){AndroidHomeStateStore.Snapshot state=AndroidHomeStateStore.snapshot(context);return!selectionSessionId.isEmpty()&&selectionSessionId.equals(state.sessionId)&&selectionNodeId.equals(state.activeNodeId);}
    private void checkSelection()throws Exception{
        if(Thread.currentThread().isInterrupted()||executor.isShutdown())throw new InterruptedException("Android mode selection was cancelled.");
        if(!ownsSelection()||AndroidHomeStateStore.emergencyDisconnectPending(context)||!"connecting".equals(AndroidHomeStateStore.snapshot(context).phase))throw new SelectionAbortedException("Android selection lost its captured session ownership; no fallback was started.");
    }
    private JSONObject checkedBundle(File bundle)throws Exception{
        checkSelection();JSONObject root=load(bundle);String source=root.toString();checkSelection();
        if(selectionSource==null)selectionSource=source;
        else if(!selectionSource.equals(source))throw new SelectionAbortedException("Selected node or policy changed; no fallback was started.");
        return root;
    }

    private String failClosedAfterError(Throwable error){
        String message=safe(error);
        // A superseded operation cannot stop or overwrite the newer session.
        if(!ownsSelection())return message;
        boolean cleanupComplete=true;
        boolean interrupted=Thread.interrupted();
        try{stopCurrent(false);}catch(Throwable cleanup){cleanupComplete=false;message += "; runtime cleanup failed: "+safe(cleanup);}finally{if(interrupted)Thread.currentThread().interrupt();}
        if(ownsSelection()){
            if(cleanupComplete)AndroidHomeStateStore.failed(context,message);
            else AndroidHomeStateStore.failedPreservingOwnership(context,message);
        }
        return message;
    }

    private void stopCurrent(boolean clearHomeState)throws Exception{
        Candidate c=current;
        if(c==null){
            if(wg.getState()==Tunnel.State.UP)stopWg();
            if(awg.getState()==org.amnezia.awg.backend.Tunnel.State.UP)stopAwg();
            if(runtimeBusy(sing.getState()))stopLibbox();
            if(runtimeBusy(xray.getState()))stopXray();
            if(clearHomeState)AndroidHomeStateStore.disconnected(context);
            return;
        }
        if(c.kind==Kind.WG)stopWg();else if(c.kind==Kind.AWG)stopAwg();else if(c.kind==Kind.XRAY)stopXray();else stopLibbox();
        current=null;
        if(clearHomeState)AndroidHomeStateStore.disconnected(context);
    }
    private void stopWg()throws Exception{CountDownLatch l=new CountDownLatch(1);wg.disconnectManaged((s,m,e)->l.countDown());if(!l.await(8,TimeUnit.SECONDS)||wg.getState()!=Tunnel.State.DOWN)throw new IllegalStateException("WireGuard teardown did not prove DOWN before timeout.");}
    private void stopAwg()throws Exception{CountDownLatch l=new CountDownLatch(1);awg.disconnectManaged((s,m,e)->l.countDown());if(!l.await(8,TimeUnit.SECONDS)||awg.getState()!=org.amnezia.awg.backend.Tunnel.State.DOWN)throw new IllegalStateException("AmneziaWG teardown did not prove DOWN before timeout.");}
    private void stopLibbox()throws Exception{sing.stop();long end=System.currentTimeMillis()+8000;while(System.currentTimeMillis()<end){String s=sing.getState();if(terminal(s))return;Thread.sleep(150);}throw new IllegalStateException("Libbox teardown did not reach DOWN/FAILED/REVOKED before timeout.");}
    private void stopXray()throws Exception{xray.stop();long end=System.currentTimeMillis()+8000;while(System.currentTimeMillis()<end){String s=xray.getState();if(terminal(s))return;Thread.sleep(150);}throw new IllegalStateException("Xray teardown did not reach DOWN/FAILED/REVOKED before timeout.");}
    private static boolean terminal(String state){if(state==null)return false;String s=state.trim().toUpperCase();return"DOWN".equals(s)||"FAILED".equals(s)||"REVOKED".equals(s);}
    private static boolean runtimeBusy(String state){return!terminal(state);}

    private List<Candidate> collect(File bundle,boolean autoOnly,boolean applyAutoRequirements)throws Exception{
        JSONObject root=checkedBundle(bundle);JSONObject profiles=root.optJSONObject("profiles");JSONArray catalog=root.optJSONArray("modes");boolean strict=AndroidKillSwitchPolicy.strictRequested(root);JSONObject profile=selectedProfile(root);
        boolean requireEncrypted=applyAutoRequirements&&profile!=null&&profile.optBoolean("auto_require_encrypted",false);
        boolean requireObfuscation=applyAutoRequirements&&profile!=null&&profile.optBoolean("auto_require_obfuscation",false);
        String startLayer=profile==null?AndroidStartLayer.OFF:AndroidStartLayer.selectedMode(root);
        boolean startLayerEnabled=!AndroidStartLayer.OFF.equals(startLayer);
        Set<String>direct=new HashSet<>();for(NativeSingBoxController.ModeInfo m:sing.listDirectLibboxModes(bundle))direct.add(m.id);Set<String>directXray=new HashSet<>();for(NativeXrayController.ModeInfo m:xray.listDirectXrayModes(bundle))directXray.add(m.id);
        List<Candidate>out=new ArrayList<>();if(catalog==null)return out;
        for(int i=0;i<catalog.length();i++){
            JSONObject m=catalog.optJSONObject(i);if(m==null||(autoOnly&&!m.optBoolean("auto_eligible",false)))continue;String id=m.optString("id","");List<String>layers=strings(m.optJSONArray("layers"));
            if(requireEncrypted&&!hasEncrypted(layers))continue;if(requireObfuscation&&!hasObfuscation(layers))continue;
            Kind kind=null;if(!strict&&"wg".equals(id)&&!AndroidNativeProfilePolicy.requiresLibbox(root)&&has(profiles,"wg","wg.conf"))kind=Kind.WG;else if(!strict&&NativeAmneziaWGController.supportedRawProfile(id)&&has(profiles,id,"awg.conf")&&!AndroidNativeProfilePolicy.requiresLibbox(root))kind=Kind.AWG;else if(direct.contains(id))kind=Kind.LIBBOX;else if(directXray.contains(id)&&!AndroidStartLayer.nativeXray(id))kind=Kind.XRAY;if(kind==null)continue;
            if(startLayerEnabled){
                if(kind!=Kind.LIBBOX||!AndroidStartLayer.supportsRawMode(id))continue;
            }
            out.add(new Candidate(kind,id,m.optString("name",id),layers,strings(m.optJSONArray("smart_simplify")),i));
        }
        return out;
    }

    private static boolean hasEncrypted(List<String>layers){for(String v:new String[]{"wireguard","amneziawg","amneziawg2","shadowsocks2022","reality","hysteria2","tls","https","xtls-vision","naive","vless-pq","rosenpass-pq"})if(layers.contains(v))return true;return false;}
    private static boolean hasObfuscation(List<String>layers){for(String v:new String[]{"light-obfuscation","strong-obfuscation","reality","salamander","v2ray-plugin","websocket","utls-chrome","finalmask","xhttp","naive","https","protocol-split"})if(layers.contains(v))return true;return false;}
    private static String autoRequirementLabel(JSONObject p){if(p==null)return"";boolean e=p.optBoolean("auto_require_encrypted",false),o=p.optBoolean("auto_require_obfuscation",false);if(e&&o)return"Require encrypted + Require obfuscation";if(e)return"Require encrypted";if(o)return"Require obfuscation";return"";}
    private static JSONObject selectedProfile(JSONObject bundle){return AndroidProfileSelection.selectedRouterProfile(bundle);}
    private static boolean has(JSONObject profiles,String id,String name){JSONObject p=profiles==null?null:profiles.optJSONObject(id);return p!=null&&!p.optString(name,"").trim().isEmpty();}
    private static List<String>strings(JSONArray values){if(values==null)return Collections.emptyList();List<String>out=new ArrayList<>();for(int i=0;i<values.length();i++){String v=values.optString(i,"").trim().toLowerCase();if(!v.isEmpty())out.add(v);}return out;}
    private static JSONObject load(File file)throws Exception{if(file==null||!file.isFile()||file.length()<=0||file.length()>64L*1024L*1024L)throw new IllegalStateException("Private node bundle is missing or invalid.");try(FileInputStream in=new FileInputStream(file)){ByteArrayOutputStream out=new ByteArrayOutputStream();byte[]b=new byte[8192];int n,total=0;while((n=in.read(b))!=-1){total+=n;if(total>64*1024*1024)throw new IllegalStateException("Bundle exceeds safety limit.");out.write(b,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private static String nodeId(File bundle){return AndroidHomeStateStore.nodeIdFromBundleFile(bundle);}
    private static String safe(Throwable error){String m=error==null?"unknown error":error.getMessage();if(m==null||m.trim().isEmpty())m=error==null?"unknown error":error.getClass().getSimpleName();return m.replace('\n',' ').replace('\r',' ').trim();}
}
