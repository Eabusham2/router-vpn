package com.eabusham.routervpn;

import android.content.Context;
import android.content.SharedPreferences;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.UUID;

/** One cold-process startup decision. Permission state contains only its nonce;
 * exact private sources remain in this process and must still match at launch. */
final class AndroidStartupPolicy {
    private static final String PREFS="router-vpn-unified", LAST_FILE="startup-last-v1.json", TOR_LAST_FILE="startup-tor-last-v1.json";
    private static final int MAX_LAST=4096;
    private static final String[] CHOICES={"smart-auto","auto","last","manual"};
    private static boolean coldLaunchClaimed;
    private static Attempt pending;

    static final class Attempt {
        final String nonce=UUID.randomUUID().toString().replace("-", "");
        final String mode, source, lastRaw, lastExecution, entryMode, exitMode, execution;
        final AndroidNodeStore.Node node, entry, exit;
        final AndroidStandardExitStore.Entry external, ordinaryEntry;
        private final String nodeKind, externalSnapshot, ordinaryEntrySnapshot;
        private final String selectedID, activeID;
        private final AndroidHomeStateStore.Snapshot idle;
        private final Map<String,Object> preferences;
        private final Map<String,byte[]> files;
        private boolean retired;

        private Attempt(String mode, AndroidNodeStore.Node node, AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, AndroidStandardExitStore.Entry external,
                        String entryMode, String exitMode, String execution, String source, String lastRaw,
                        String selectedID, String activeID, AndroidHomeStateStore.Snapshot idle,
                        Map<String,Object> preferences, Map<String,byte[]> files)throws Exception {
            this(mode,node,entry,exit,external,null,entryMode,exitMode,execution,source,lastRaw,selectedID,activeID,idle,preferences,files);
        }

        private Attempt(String mode, AndroidNodeStore.Node node, AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, AndroidStandardExitStore.Entry external,
                        AndroidStandardExitStore.Entry ordinaryEntry, String entryMode, String exitMode, String execution, String source, String lastRaw,
                        String selectedID, String activeID, AndroidHomeStateStore.Snapshot idle,
                        Map<String,Object> preferences, Map<String,byte[]> files)throws Exception {
            this(mode,node,entry,exit,external,ordinaryEntry,entryMode,exitMode,execution,source,lastRaw,selectedID,activeID,idle,preferences,files,"");
        }

        private Attempt(String mode, AndroidNodeStore.Node node, AndroidNodeStore.Node entry, AndroidNodeStore.Node exit, AndroidStandardExitStore.Entry external,
                        AndroidStandardExitStore.Entry ordinaryEntry, String entryMode, String exitMode, String execution, String source, String lastRaw,
                        String selectedID, String activeID, AndroidHomeStateStore.Snapshot idle,
                        Map<String,Object> preferences, Map<String,byte[]> files,String lastExecution)throws Exception {
            if(ordinaryEntry!=null&&(entry!=null||external==null||ordinaryEntry.id.equals(external.id)))throw new IllegalArgumentException("Startup must retain two distinct ordinary path owners.");
            this.mode=mode;this.node=node;this.entry=entry;this.exit=exit;this.entryMode=entryMode;this.exitMode=exitMode;
            this.execution=execution;this.source=source;this.lastRaw=lastRaw;this.lastExecution=lastExecution;this.selectedID=selectedID;this.activeID=activeID;
            this.idle=idle;this.preferences=Collections.unmodifiableMap(new LinkedHashMap<>(preferences));
            this.external=external==null?null:AndroidStandardExitStore.copy(external);
            this.nodeKind=external==null?"router-vpn":"external";
            this.externalSnapshot=external==null?"":AndroidStandardExitStore.snapshot(this.external);
            this.ordinaryEntry=ordinaryEntry==null?null:AndroidStandardExitStore.copy(ordinaryEntry);
            this.ordinaryEntrySnapshot=ordinaryEntry==null?"":AndroidStandardExitStore.snapshot(this.ordinaryEntry);
            Map<String,byte[]> copy=new LinkedHashMap<>();
            for(Map.Entry<String,byte[]> value:files.entrySet())copy.put(value.getKey(),value.getValue().clone());
            this.files=Collections.unmodifiableMap(copy);
        }

        boolean multihop(){return entry!=null||ordinaryEntry!=null;}
        boolean external(){return external!=null;}

        void requireCurrent(Context context, AndroidNodeStore nodes, AndroidUnifiedConnectionController connection)throws Exception {
            synchronized(AndroidStartupPolicy.class){
                if(retired||pending!=this)throw new IllegalStateException("The startup decision was cancelled or belongs to an earlier app process.");
            }
            requireNoVPN(context);
            if(!connection.idleCurrent(idle))throw new IllegalStateException("A newer VPN decision cancelled automatic startup.");
            if(!activeID.equals(nodes.activeId())||!preferences.equals(selectionPreferences(context)))
                throw new IllegalStateException("The selected node or connection preferences changed during startup permission.");
            SharedPreferences prefs=prefs(context);
            if(!nodeKind.equals(prefs.getString("selected_kind","router-vpn"))
                    ||!selectedID.equals(prefs.getString("selected_id",nodes.activeId())))
                throw new IllegalStateException("The selected startup node changed.");
            if(external!=null&&(!externalSnapshot.equals(AndroidStandardExitStore.snapshot(external))
                    ||!externalSnapshot.equals(AndroidStandardExitStore.snapshot(new AndroidStandardExitStore(context).get(selectedID)))))
                throw new IllegalStateException("The selected external startup profile or its credentials changed.");
            if(ordinaryEntry!=null&&(!ordinaryEntrySnapshot.equals(AndroidStandardExitStore.snapshot(ordinaryEntry))
                    ||!ordinaryEntrySnapshot.equals(AndroidStandardExitStore.snapshot(new AndroidStandardExitStore(context).get(ordinaryEntry.id)))))
                throw new IllegalStateException("The captured ordinary startup entry or its credentials changed.");
            for(Map.Entry<String,byte[]> captured:files.entrySet()){
                File current=nodes.file(captured.getKey());
                if(!Arrays.equals(captured.getValue(),AndroidPrivateFileStore.read(current,AndroidNodeStore.MAX_BUNDLE)))
                    throw new IllegalStateException("A captured startup node or path policy changed; choose Connect again.");
            }
            requireNoVPN(context);
            if(!connection.idleCurrent(idle))throw new IllegalStateException("A newer VPN owner replaced the startup decision.");
        }

        /** Called once, immediately before the existing permission-approved dispatch. */
        void dispatched()throws Exception {
            synchronized(AndroidStartupPolicy.class){
                if(retired||pending!=this)throw new IllegalStateException("The startup request was already consumed or cancelled.");
                retired=true;pending=null;
            }
        }

        void cancel(){synchronized(AndroidStartupPolicy.class){retired=true;if(pending==this)pending=null;}}
    }

    /** Rotation/resume never creates another request, and a saved Activity from a
     * dead process cannot revive private permission state from its old nonce. */
    static Attempt coldLaunch(Context context,AndroidNodeStore nodes,AndroidUnifiedConnectionController connection,boolean restoredActivity)throws Exception {
        synchronized(AndroidStartupPolicy.class){
            if(coldLaunchClaimed)return null;
            coldLaunchClaimed=true;
            if(restoredActivity)return null;
        }
        SharedPreferences prefs=prefs(context);
        String selected=prefs.getString("selected_id",nodes.activeId());
        if(selected==null||selected.isEmpty())return null;
        String kind=prefs.getString("selected_kind","router-vpn");
        if("external".equals(kind))return captureExternal(context,nodes,connection,selected);
        if(!"router-vpn".equals(kind))throw new IllegalStateException("The selected startup node kind is unsupported.");
        AndroidNodeStore.Node node=requiredNode(nodes,selected);
        byte[] bytes=AndroidPrivateFileStore.read(node.file,AndroidNodeStore.MAX_BUNDLE);
        JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(bytes));AndroidNodeStore.validateBundle(bundle);
        JSONObject profile=AndroidProfileSelection.selectedRouterProfile(bundle);
        if(profile==null)throw new IllegalStateException("The selected startup node has no exact Router profile.");
        Object auto=profile.opt("auto_connect");
        if(auto!=null&&!(auto instanceof Boolean))throw new IllegalStateException("Auto-connect must be On or Off.");
        if(!Boolean.TRUE.equals(auto))return null;
        String mode=startupMode(profile);
        if("manual".equals(mode))return null;
        requireNoVPN(context);
        AndroidHomeStateStore.Snapshot idle=connection.captureIdle();
        if(!selected.equals(nodes.activeId()))throw new IllegalStateException("The selected Router and active private node disagree; select the node before connecting.");
        Map<String,Object> preferences=selectionPreferences(context);
        Map<String,byte[]> files=new LinkedHashMap<>();files.put(node.id,bytes);
        AndroidNodeStore.Node entry=null,exit=null;String entryMode="wg",exitMode="",execution="local";
        if(prefs.getBoolean("multihop_on",false)){
            if(!"router-vpn".equals(prefs.getString("multihop_entry_kind","router-vpn")))throw new IllegalStateException("An ordinary startup entry cannot be interpreted as a private Router node.");
            entry=requiredNode(nodes,prefs.getString("multihop_entry",""));
            exit=requiredNode(nodes,prefs.getString("multihop_exit",""));
            if(entry.id.equals(exit.id))throw new IllegalStateException("Saved startup multihop requires two different nodes.");
            entryMode=prefs.getString("multihop_entry_mode","wg");exitMode=prefs.getString("multihop_exit_mode","");execution=prefs.getString("multihop_execution","local");
            if(!NativeSingBoxController.nativeMultihopEntry(entryMode)||exitMode.isEmpty()
                    ||!Arrays.asList("local","server","auto").contains(execution))
                throw new IllegalStateException("The saved multihop startup path is incomplete; it cannot become a single-node connection.");
            files.putIfAbsent(entry.id,AndroidPrivateFileStore.read(entry.file,AndroidNodeStore.MAX_BUNDLE));
            files.putIfAbsent(exit.id,AndroidPrivateFileStore.read(exit.file,AndroidNodeStore.MAX_BUNDLE));
        }
        String source=bundle.toString();
        String last="last".equals(mode)&&entry==null?lastRaw(context,node.id,bundle):"";
        Attempt capture=new Attempt(mode,node,entry,exit,null,entryMode,exitMode,execution,source,last,selected,nodes.activeId(),idle,preferences,files);
        synchronized(AndroidStartupPolicy.class){if(pending!=null)throw new IllegalStateException("Another startup permission request is pending.");pending=capture;}
        try{capture.requireCurrent(context,nodes,connection);return capture;}catch(Exception changed){capture.cancel();throw changed;}
    }

    private static Attempt captureExternal(Context context,AndroidNodeStore nodes,AndroidUnifiedConnectionController connection,String selected)throws Exception{
        AndroidStandardExitStore exits=new AndroidStandardExitStore(context);
        AndroidStandardExitStore.Entry saved=AndroidStandardExitStore.copy(exits.get(selected));
        AndroidStandardExitStore.validate(saved);
        if(!saved.autoConnect||"manual".equals(saved.startupMode))return null;
        requireNoVPN(context);
        AndroidHomeStateStore.Snapshot idle=connection.captureIdle();
        Map<String,Object> preferences=selectionPreferences(context);
        AndroidConnectionProfileStore.ExternalSelection path=new AndroidConnectionProfileStore(context,nodes,exits).currentExternalPath(selected);
        if(!AndroidStandardExitStore.snapshot(saved).equals(AndroidStandardExitStore.snapshot(path.exit)))
            throw new IllegalStateException("The external startup selection changed while its complete path was captured.");
        Map<String,byte[]> files=new LinkedHashMap<>();
        if(path.entry!=null)files.put(path.entry.id,AndroidPrivateFileStore.read(path.entry.file,AndroidNodeStore.MAX_BUNDLE));
        String lastExecution="";
        if("last".equals(saved.startupMode)&&path.entry!=null&&AndroidTorProfile.isTor(saved.protocol)&&"auto".equals(path.execution)){
            lastExecution=lastTorExecution(context,path.entry.id,files.get(path.entry.id),saved,path.entryMode,path.execution);
            if(lastExecution.isEmpty())throw new IllegalStateException("Startup Last has no matching proved Tor execution. Choose Connect to run Compare both for this saved path.");
        }
        Attempt capture=new Attempt(saved.startupMode,null,path.entry,null,saved,path.ordinaryEntry,path.entryMode,saved.protocol,path.execution,"","",selected,nodes.activeId(),idle,preferences,files,lastExecution);
        synchronized(AndroidStartupPolicy.class){if(pending!=null)throw new IllegalStateException("Another startup permission request is pending.");pending=capture;}
        try{capture.requireCurrent(context,nodes,connection);return capture;}catch(Exception changed){capture.cancel();throw changed;}
    }

    static synchronized Attempt restore(String nonce){return nonce!=null&&nonce.matches("[0-9a-f]{32}")&&pending!=null&&!pending.retired&&nonce.equals(pending.nonce)?pending:null;}
    static synchronized void cancelPending(){if(pending!=null)pending.cancel();}

    static String startupMode(JSONObject profile)throws Exception {
        Object value=profile.opt("startup_mode");
        if(value==null)return "smart-auto";
        if(!(value instanceof String))throw new IllegalArgumentException("Startup behavior must be a saved choice.");
        String mode=((String)value).trim().toLowerCase(Locale.ROOT);
        if(mode.isEmpty())return "smart-auto";
        if(!Arrays.asList(CHOICES).contains(mode))throw new IllegalArgumentException("Unsupported saved startup behavior.");
        return mode;
    }

    /** Called only by the ordinary controller's proved-runtime callback. A test
     * callback has no receipt hook. The Home lock joins proof identity with the
     * atomic, secret-free record write, so Disconnect cannot bless an old owner. */
    static boolean recordProven(Context context,AndroidNodeStore nodes,File file,String session,String raw,String source){
        try{
            synchronized(AndroidHomeStateStore.class){
                AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
                SharedPreferences prefs=prefs(context);
                String selected=prefs.getString("selected_id",nodes.activeId());
                if(session==null||session.isEmpty()||!session.equals(home.sessionId)||!home.connected
                        ||!"connected".equals(home.phase)||!"passed".equals(home.pathProof)
                        ||raw==null||!raw.matches("[a-z0-9][a-z0-9-]{0,95}")||!raw.equals(home.runtimeMode)
                        ||!home.activeEntryId.isEmpty()||!home.activeExternalId.isEmpty()
                        ||!"router-vpn".equals(prefs.getString("selected_kind","router-vpn"))||prefs.getBoolean("multihop_on",false)
                        ||!selected.equals(home.activeNodeId)||!selected.equals(nodes.activeId())
                        ||!file.getCanonicalFile().equals(nodes.file(selected).getCanonicalFile()))return false;
                JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(AndroidPrivateFileStore.read(file,AndroidNodeStore.MAX_BUNDLE)));
                AndroidNodeStore.validateBundle(bundle);
                if(source==null||!source.equals(bundle.toString()))return false;
                JSONObject record=new JSONObject().put("schema",1).put("node_id",selected)
                        .put("profile_sha256",profileIdentity(bundle)).put("raw_id",raw);
                AndroidPrivateFileStore.write(new File(context.getApplicationContext().getFilesDir(),LAST_FILE),record.toString().getBytes(StandardCharsets.UTF_8),MAX_LAST);
                return true;
            }
        }catch(Exception unavailable){return false;}
    }

    /** Immutable, secret-free record prepared without native/Home locks. The
     * private stores have their own mutation locks and must never be read while
     * holding the runtime adoption transaction. This choice is historical;
     * it is neither current path proof nor a cached measurement. */
    static final class TorLast {
        private final String entryID,exitID,protocol,entryMode,record;
        private final Map<String,Object> preferences;
        private TorLast(String entryID,AndroidStandardExitStore.Entry exit,String entryMode,JSONObject record,Map<String,Object> preferences){
            this.entryID=entryID;exitID=exit.id;protocol=exit.protocol;this.entryMode=entryMode;this.record=record.toString();
            this.preferences=Collections.unmodifiableMap(new LinkedHashMap<>(preferences));
        }
    }

    static TorLast prepareTorExecution(Context context,File entryFile,AndroidStandardExitStore.Entry capturedExit,
                                       String entryMode,String requested,String selected,String entryDigest){
        try{
            if(AndroidMTUMeasurementGate.held()||entryFile==null||capturedExit==null||!AndroidTorProfile.isTor(capturedExit.protocol)
                    ||!Arrays.asList("local","server").contains(selected)||!Arrays.asList("local","server","auto").contains(requested)
                    ||!"auto".equals(requested)&&!requested.equals(selected))return null;
            Map<String,Object> preferences=selectionPreferences(context);
            SharedPreferences prefs=prefs(context);
            if(!"external".equals(prefs.getString("selected_kind","router-vpn"))||!capturedExit.id.equals(prefs.getString("selected_id","")))return null;
            AndroidNodeStore nodes=new AndroidNodeStore(context);AndroidStandardExitStore exits=new AndroidStandardExitStore(context);
            AndroidConnectionProfileStore.ExternalSelection path=new AndroidConnectionProfileStore(context,nodes,exits).currentExternalPath(capturedExit.id);
            if(path.entry==null||path.ordinaryEntry!=null||!path.entryMode.equals(entryMode)||!path.execution.equals(requested)
                    ||!entryFile.getCanonicalFile().equals(path.entry.file.getCanonicalFile())
                    ||!AndroidStandardExitStore.snapshot(capturedExit).equals(AndroidStandardExitStore.snapshot(path.exit)))return null;
            byte[] entry=AndroidPrivateFileStore.read(entryFile,AndroidNodeStore.MAX_BUNDLE);
            if(entryDigest==null||!entryDigest.equals(AndroidTorProfile.digest(entry)))return null;
            JSONObject record=new JSONObject().put("schema",1).put("entry_id",path.entry.id).put("exit_id",capturedExit.id)
                    .put("path_sha256",torPathIdentity(path.entry.id,entry,capturedExit,entryMode,requested)).put("selected_execution",selected);
            if(!preferences.equals(selectionPreferences(context)))return null;
            return new TorLast(path.entry.id,capturedExit,entryMode,record,preferences);
        }catch(Exception unavailable){return null;}
    }

    /** Called only inside the exact runtime's Connected adoption. Temporary and
     * restored paths never prepare a record. No store or native call can wait
     * under this Home lock; Disconnect cannot bless an earlier owner. */
    static boolean recordTorExecution(Context context,TorLast record,AndroidHomeStateStore.Snapshot capturedHome){
        try{
            if(record==null)return false;
            synchronized(AndroidHomeStateStore.class){
                AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(context);
                if(capturedHome==null||capturedHome.sessionId.isEmpty()||!capturedHome.sessionId.equals(home.sessionId)
                        ||capturedHome.pathGeneration!=home.pathGeneration||!home.connected||!"connected".equals(home.phase)||!"passed".equals(home.pathProof)
                        ||!"external".equals(home.logicalMode)||!record.exitID.equals(home.activeExternalId)||!record.protocol.equals(home.activeExternalProtocol)
                        ||!record.entryID.equals(home.activeEntryId)||!record.entryMode.equals(home.activeEntryMode)
                        ||AndroidHomeStateStore.emergencyDisconnectPending(context)||AndroidHomeStateStore.actualExitForCurrentSession(context).isEmpty()
                        ||!record.preferences.equals(selectionPreferences(context)))return false;
                AndroidPrivateFileStore.write(new File(context.getApplicationContext().getFilesDir(),TOR_LAST_FILE),record.record.getBytes(StandardCharsets.UTF_8),MAX_LAST);
                return true;
            }
        }catch(Exception unavailable){return false;}
    }

    private static String lastTorExecution(Context context,String entryID,byte[] entry,AndroidStandardExitStore.Entry exit,String mode,String requested){
        try{
            JSONObject saved=new JSONObject(AndroidTorProfile.strictText(AndroidPrivateFileStore.read(new File(context.getApplicationContext().getFilesDir(),TOR_LAST_FILE),MAX_LAST)));
            String selected=saved.getString("selected_execution");
            if(saved.length()!=5||saved.getInt("schema")!=1||!entryID.equals(saved.getString("entry_id"))||!exit.id.equals(saved.getString("exit_id"))
                    ||!torPathIdentity(entryID,entry,exit,mode,requested).equals(saved.getString("path_sha256"))
                    ||!Arrays.asList("local","server").contains(selected))return "";
            return selected;
        }catch(Exception absentOrStale){return "";}
    }

    private static String torPathIdentity(String entryID,byte[] entry,AndroidStandardExitStore.Entry exit,String mode,String requested)throws Exception{
        JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(entry));AndroidNodeStore.validateBundle(bundle);
        JSONObject external=new JSONObject(AndroidStandardExitStore.snapshot(exit));
        external.remove("startup_mode");external.remove("auto_connect");
        JSONObject identity=new JSONObject().put("entry_id",entryID).put("entry_sha256",profileIdentity(bundle))
                .put("exit",external).put("entry_mode",mode).put("execution",requested);
        return AndroidTorProfile.digest(canonical(identity).getBytes(StandardCharsets.UTF_8));
    }

    private static String lastRaw(Context context,String nodeID,JSONObject bundle){
        try{
            File file=new File(context.getApplicationContext().getFilesDir(),LAST_FILE);
            JSONObject saved=new JSONObject(AndroidTorProfile.strictText(AndroidPrivateFileStore.read(file,MAX_LAST)));
            String raw=saved.getString("raw_id");
            if(saved.length()!=4||saved.getInt("schema")!=1||!nodeID.equals(saved.getString("node_id"))
                    ||!profileIdentity(bundle).equals(saved.getString("profile_sha256"))||!raw.matches("[a-z0-9][a-z0-9-]{0,95}"))return "";
            return raw;
        }catch(Exception absentOrStale){return "";}
    }

    private static String profileIdentity(JSONObject source)throws Exception {
        JSONObject copy=new JSONObject(source.toString());
        // Startup controls choose when to reconnect, not how a raw path runs.
        // All actual node credentials, generated graphs and path policy remain
        // in the digest. Direct statistics are stored in a separate file.
        JSONObject profile=AndroidProfileSelection.selectedRouterProfile(copy);
        if(profile==null)throw new IllegalArgumentException("Missing selected Router profile.");
        profile.remove("startup_mode");profile.remove("auto_connect");
        byte[] bytes=MessageDigest.getInstance("SHA-256").digest(canonical(copy).getBytes(StandardCharsets.UTF_8));
        StringBuilder out=new StringBuilder(64);for(byte value:bytes)out.append(String.format(Locale.ROOT,"%02x",value&255));return out.toString();
    }

    private static String canonical(Object value)throws Exception {
        if(value instanceof JSONObject){JSONObject object=(JSONObject)value;List<String> keys=new ArrayList<>();for(java.util.Iterator<String> it=object.keys();it.hasNext();)keys.add(it.next());Collections.sort(keys);StringBuilder out=new StringBuilder("{");for(String key:keys){if(out.length()>1)out.append(',');out.append(JSONObject.quote(key)).append(':').append(canonical(object.get(key)));}return out.append('}').toString();}
        if(value instanceof JSONArray){JSONArray array=(JSONArray)value;StringBuilder out=new StringBuilder("[");for(int i=0;i<array.length();i++){if(i>0)out.append(',');out.append(canonical(array.get(i)));}return out.append(']').toString();}
        if(value instanceof String)return JSONObject.quote((String)value);
        return String.valueOf(value);
    }

    private static Map<String,Object> selectionPreferences(Context context){
        return AndroidConnectionSelection.preferences(context);
    }

    private static AndroidNodeStore.Node requiredNode(AndroidNodeStore nodes,String id)throws Exception{
        if(id==null||id.isEmpty())throw new IllegalStateException("A saved startup node is missing.");
        for(AndroidNodeStore.Node node:nodes.list())if(id.equals(node.id))return node;
        throw new IllegalStateException("A saved startup node is missing or invalid.");
    }

    private static void requireNoVPN(Context context){
        ConnectivityManager connectivity=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if(connectivity==null)throw new IllegalStateException("Android VPN ownership is unavailable; startup remains disconnected.");
        Network active=connectivity.getActiveNetwork();
        if(active!=null){NetworkCapabilities caps=connectivity.getNetworkCapabilities(active);if(caps==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))throw new IllegalStateException("An existing VPN owns the active network; automatic startup will not replace it.");}
        Network[] networks=connectivity.getAllNetworks();
        if(networks==null)throw new IllegalStateException("Android network ownership is unavailable.");
        for(Network network:networks){NetworkCapabilities caps=connectivity.getNetworkCapabilities(network);if(caps==null||caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))throw new IllegalStateException("An existing or changing VPN network prevents automatic startup.");}
    }

    private static SharedPreferences prefs(Context context){return context.getApplicationContext().getSharedPreferences(PREFS,Context.MODE_PRIVATE);}
    private AndroidStartupPolicy(){}
}
