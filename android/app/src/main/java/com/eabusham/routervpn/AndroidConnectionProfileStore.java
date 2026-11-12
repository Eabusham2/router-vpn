package com.eabusham.routervpn;

import android.content.Context;
import android.content.SharedPreferences;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Locale;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

/** App-private connection-choice profiles. Linked node secrets are referenced by ID, never copied. */
final class AndroidConnectionProfileStore {
    // Keep the established file location, but old readers must reject ordinary
    // entry references instead of interpreting their IDs as private Router nodes.
    static final int SCHEMA_VERSION=7, MAX_PROFILES=64, MAX_STORE=512*1024;
    private static final String FILE_NAME="connection-profiles-v4.json", LEGACY_FILE_NAME="connection-profiles-v1.json";
    private static final String PREFS="router-vpn-unified", MODE_KEY="mode", CUSTOM_KEY="custom_presets", SELECTED_KIND="selected_kind", SELECTED_ID="selected_id";
    private static final String MULTI_NODES="multihop_nodes";
    private static final String MULTI_ON="multihop_on", MULTI_ENTRY="multihop_entry", MULTI_EXIT="multihop_exit", MULTI_MODE="multihop_exit_mode", MULTI_ENTRY_KIND="multihop_entry_kind";
    private static final SecureRandom RANDOM=new SecureRandom();
    private static final String[] POLICY_KEYS={
            "home_lan_access","home_lan_cidrs","kill_switch","kill_switch_policy","ipv6_mode","base_tunnel","base_fallback","start_layer",
            "auto_require_encrypted","auto_require_obfuscation","mtu_policy","manual_mtu",
            "daita_enabled","daita_rate_kbps","jumbo_tun","socks_enabled","startup_mode","auto_connect","dns_mode","dns_protocol","dns_host",
            "dns_port","dns_server_name","dns_path","fastest_dns_host","fastest_dns_name","fastest_dns_latency_ms","dns_results","dns_bootstrap"
    };
    private static final String[] SELECTION_KEYS={SELECTED_KIND,SELECTED_ID,MODE_KEY,CUSTOM_KEY,MULTI_NODES,MULTI_ON,MULTI_ENTRY,MULTI_EXIT,MULTI_MODE,MULTI_ENTRY_KIND,"multihop_execution","multihop_entry_mode"};

    static final class Record {
        final String id,name,nodeKind,nodeId,mode,startLayer; final List<String> customLayers; final boolean autoRequireEncrypted,autoRequireObfuscation;
        Record(String id,String name,String nodeKind,String nodeId,String mode,String startLayer,List<String>layers,boolean autoRequireEncrypted,boolean autoRequireObfuscation){this.id=id;this.name=name;this.nodeKind=nodeKind;this.nodeId=nodeId;this.mode=mode;this.startLayer=startLayer;this.customLayers=layers;this.autoRequireEncrypted=autoRequireEncrypted;this.autoRequireObfuscation=autoRequireObfuscation;}
        String autoRequirementsSummary(){if("external".equals(nodeKind))return "AUTO n/a";if(autoRequireEncrypted&&autoRequireObfuscation)return "AUTO Encrypted+Obfuscation";if(autoRequireEncrypted)return "AUTO Encrypted";if(autoRequireObfuscation)return "AUTO Obfuscation";return "AUTO Off";}
        String startLayerSummary(){if("aes-256-gcm+xor-whitening".equals(startLayer))return "Start AES+XOR";if("aes-256-gcm".equals(startLayer))return "Start AES";return "Start Off";}
        @Override public String toString(){return name+" • "+mode+" • "+("external".equals(nodeKind)?"Custom":"Router")+" • "+startLayerSummary()+" • "+autoRequirementsSummary();}
    }

    private final Context context; private final AndroidNodeStore nodes; private final AndroidStandardExitStore exits; private final File file, legacyFile;
    AndroidConnectionProfileStore(Context context,AndroidNodeStore nodes,AndroidStandardExitStore exits){this.context=context.getApplicationContext();this.nodes=nodes;this.exits=exits;this.file=new File(this.context.getFilesDir(),FILE_NAME);this.legacyFile=new File(this.context.getFilesDir(),LEGACY_FILE_NAME);}

    synchronized List<Record> list() throws Exception { JSONArray rows=readRows();List<Record> out=new ArrayList<>();for(int i=0;i<rows.length();i++)out.add(toRecord(rows.getJSONObject(i)));return out; }
    synchronized Record add(String name) throws Exception { requireIdle("saving a connection profile");JSONArray rows=readRows();if(rows.length()>=MAX_PROFILES)throw new IllegalStateException("Connection profile limit reached.");JSONObject row=snapshot(cleanName(name),newId());rows.put(row);writeRows(rows);return toRecord(row); }
    /** Append a separately compiled future connection without touching active choices.
     * The retained candidate transaction supplies a final freshness check. */
    synchronized Record appendOrderedProposal(String name,List<AndroidNodeStore.ChainSource> sources,List<String> modes,Runnable requireCurrent) throws Exception {
        if(sources==null||modes==null||sources.size()!=modes.size()||sources.size()<2||sources.size()>8)throw new IllegalStateException("Incomplete candidate path.");
        requireCurrent.run();JSONArray rows=readRows();if(rows.length()>=MAX_PROFILES)throw new IllegalStateException("Connection profile limit reached.");
        JSONArray members=new JSONArray();for(int i=0;i<sources.size();i++)members.put(orderedSavedMember(sources.get(i),modes.get(i)));
        AndroidNodeStore.ChainSource last=sources.get(sources.size()-1);
        JSONObject row=new JSONObject().put("id",newId()).put("name",cleanName(name)).put("node_kind","router-vpn")
                .put("node_id",last.id).put("node_profile_id",last.profileId).put("policy",members.getJSONObject(members.length()-1).getJSONObject("policy"))
                .put("mode","shadowsocks").put("custom_layers",new JSONArray()).put("multihop_enabled",true).put("multihop_execution","local")
                .put(MULTI_ENTRY_KIND,"router-vpn").put("multihop_entry_id","").put("multihop_entry_mode","").put("multihop_exit_id","").put("multihop_exit_mode","").put(MULTI_NODES,members);
        validateOrderedRow(row,SCHEMA_VERSION);requireCurrent.run();rows.put(row);writeRows(rows);return toRecord(row);
    }

    synchronized Record update(String id,String name) throws Exception { requireIdle("updating a connection profile");if(!safeId(id))throw new IllegalArgumentException("Invalid connection profile id.");JSONArray rows=readRows();boolean found=false;JSONObject replacement=snapshot(cleanName(name),id);JSONArray next=new JSONArray();for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(id.equals(row.optString("id"))){next.put(replacement);found=true;}else next.put(row);}if(!found)throw new IllegalArgumentException("Connection profile was not found.");writeRows(next);return toRecord(replacement); }

    synchronized Record load(String id) throws Exception {
        requireIdle("loading a connection profile");
        return loadRow(find(id));
    }

    private Record loadRow(JSONObject row) throws Exception {
        return loadRow(row,null);
    }

    private interface PublicationValidation { void require() throws Exception; }

    private Record loadRow(JSONObject row,PublicationValidation validation) throws Exception {
        boolean ordered=row.has(MULTI_NODES);String kind=row.getString("node_kind"),nodeId=row.getString("node_id");
        String mode=normalizeMode(row.optString("mode","smart-auto"));List<String>layers=jsonStrings(row.optJSONArray("custom_layers"),32);
        boolean external="external".equals(kind),multi=row.optBoolean("multihop_enabled",false);String entry=row.optString("multihop_entry_id",""),exit=row.optString("multihop_exit_id","");String multiMode=ordered?"":external?row.optString("multihop_exit_mode",""):multi?normalizeMultiMode(row.optString("multihop_exit_mode","shadowsocks")):"shadowsocks";String execution=normalizeExecution(row.optString("multihop_execution","local"));
        String entryKind=normalizeEntryKind(row.optString(MULTI_ENTRY_KIND,"router-vpn"));boolean ordinary="external".equals(entryKind);
        String entryMode=ordered?"":ordinary?normalizeOrdinaryMode(row.optString("multihop_entry_mode","")):normalizeEntryMode(row.optString("multihop_entry_mode","wg"));
        AndroidStandardExitStore.Entry originalExternal=external?AndroidStandardExitStore.copy(exits.get(nodeId)):null,updatedExternal=null;
        AndroidStandardExitStore.Entry originalOrdinary=null,updatedOrdinary=null;
        if(external){
            AndroidStandardExitStore.validate(originalExternal);
            if(row.has("external_policy")){
                requireExternalIdentity(row,originalExternal);
                updatedExternal=AndroidStandardExitStore.copy(originalExternal);
                JSONObject policy=AndroidConnectionProfilePolicy.external(row.getJSONObject("external_policy"),originalExternal.protocol);
                if(AndroidTorProfile.isTor(originalExternal.protocol))updatedExternal.torPolicy=policy;else updatedExternal.policy=policy;
                AndroidStandardExitStore.validate(updatedExternal);
            }
            if(row.has("external_startup")){
                requireExternalIdentity(row,originalExternal);
                if(updatedExternal==null)updatedExternal=AndroidStandardExitStore.copy(originalExternal);
                AndroidStandardExitStore.applyStartupMetadata(updatedExternal,row.getJSONObject("external_startup"));
                AndroidStandardExitStore.validate(updatedExternal);
            }
        }
        if(multi&&!ordered){
            if(entry.isEmpty()||exit.isEmpty()||entry.equals(exit))throw new IllegalStateException("Saved multihop references a missing/invalid entry.");
            if(external){if(!exit.equals(nodeId)||!multiMode.equals(originalExternal.protocol))throw new IllegalStateException("Saved external multihop must retain its exact exit protocol.");}
            else if(findNode(exit)==null)throw new IllegalStateException("Saved multihop references a missing Router exit.");
            if(ordinary){
                if(!external&&(!exit.equals(nodeId)||!AndroidImportedRouterPath.supports(entryMode,multiMode)||!"local".equals(execution)))throw new IllegalStateException("An imported Router path must retain its exact Local final node.");
                originalOrdinary=AndroidStandardExitStore.copy(exits.get(entry));
                requireOrdinaryIdentity(row,originalOrdinary);
                updatedOrdinary=AndroidStandardExitStore.copy(originalOrdinary);
                updatedOrdinary.policy=AndroidConnectionProfilePolicy.external(row.getJSONObject("ordinary_entry_policy"),originalOrdinary.protocol);
                AndroidStandardExitStore.applyStartupMetadata(updatedOrdinary,row.getJSONObject("ordinary_entry_startup"));
                AndroidStandardExitStore.validate(updatedOrdinary);
            }else requireEntryMode(findNode(entry),entryMode);
        }else if(!ordered){if(ordinary)throw new IllegalStateException("An ordinary entry cannot be restored as a direct connection.");entry="";exit="";multiMode=external?originalExternal.protocol:"shadowsocks";}
        String preparedCustom=external?null:prepareCustomPresetJSON(mode,layers);
        Map<String,NodeUpdate> updates=new LinkedHashMap<>();
        if(ordered){
            stageOrderedNodes(updates,row);
            JSONArray selected=row.getJSONArray(MULTI_NODES);
            for(int i=0;i<selected.length();i++)if("external".equals(selected.getJSONObject(i).optString("node_kind"))){
                JSONObject middle=selected.getJSONObject(i);originalOrdinary=AndroidStandardExitStore.copy(exits.get(middle.getString("node_id")));
                updatedOrdinary=AndroidStandardExitStore.copy(originalOrdinary);
                updatedOrdinary.policy=AndroidConnectionProfilePolicy.external(middle.getJSONObject("policy"),originalOrdinary.protocol);
                AndroidNodeStore.ChainSource.requireImported(updatedOrdinary);
            }
        }
        else if(!external)stageNode(updates,nodeId,row.optJSONObject("policy"),row.optString("node_profile_id",""));
        if(multi&&!ordered){if(!ordinary)stageNode(updates,entry,row.optJSONObject("entry_policy"),row.optString("entry_profile_id",""));if(!external)stageNode(updates,exit,row.optJSONObject("exit_policy"),row.optString("exit_profile_id",""));}
        if(external)validateExternalGraph(updatedExternal!=null?updatedExternal:originalExternal,multi&&!ordinary?findNode(entry):null,updatedOrdinary,entryMode,execution);
        else if(multi&&ordinary){
            if(!entryMode.equals(AndroidExternalPolicy.protocol(updatedOrdinary.protocol)))throw new IllegalStateException("The imported entry transport changed.");
            JSONObject finalBundle=updates.containsKey(exit)?new JSONObject(AndroidTorProfile.strictText(updates.get(exit).updated))
                    :AndroidImportedRouterPath.finalBundle(nodes.file(exit));
            AndroidImportedRouterPath.compile(updatedOrdinary,finalBundle,multiMode,execution);
        }
        AndroidNodeStore.SelectionSnapshot originalSelection;Map<String,Object> originalPreferences;
        synchronized(prefs()){originalSelection=nodes.snapshotSelection();originalPreferences=snapshotPreferences();}
        Map<String,Object> nextPreferences=new LinkedHashMap<>(originalPreferences);
        nextPreferences.put(SELECTED_KIND,kind);nextPreferences.put(SELECTED_ID,nodeId);nextPreferences.put(MODE_KEY,external?"external":mode);
        nextPreferences.put(MULTI_NODES,ordered?orderedReferences(row.getJSONArray(MULTI_NODES)).toString():"");
        nextPreferences.put(MULTI_ON,multi);nextPreferences.put(MULTI_ENTRY,entry);nextPreferences.put(MULTI_EXIT,exit);nextPreferences.put(MULTI_MODE,multiMode);
        nextPreferences.put(MULTI_ENTRY_KIND,entryKind);nextPreferences.put("multihop_execution",execution);nextPreferences.put("multihop_entry_mode",entryMode);
        if(preparedCustom!=null)nextPreferences.put(CUSTOM_KEY,preparedCustom);
        PreferenceUpdate preferenceUpdate=new PreferenceUpdate(originalPreferences,nextPreferences);
        // All validation above is complete before any selection, node-file, preset or preference mutation.
        List<NodeUpdate> applied=new ArrayList<>();List<AndroidNodeStore.SelectionSnapshot> attemptedSelections=new ArrayList<>();boolean externalAttempted=false,ordinaryAttempted=false,selectionAttempted=false;
        synchronized(prefs()) {
        try{
            if(!preferenceUpdate.original.equals(snapshotPreferences()))throw new IllegalStateException("The selected connection changed before profile mutation.");
            requireIdle("loading a connection profile");
            // Both ordinary sources are captured before either row is written.
            // A later atomic save also guards each row against a competing editor.
            if(originalOrdinary!=null)requireExternalUnchanged(originalOrdinary);
            if(originalExternal!=null)requireExternalUnchanged(originalExternal);
            for(NodeUpdate update:updates.values()){
                if(!java.util.Arrays.equals(update.original,readLimited(nodes.file(update.id),AndroidNodeStore.MAX_BUNDLE)))throw new IllegalStateException("A linked Router node changed during profile validation.");
                applied.add(update);selectionAttempted=true;
                byte[] updatedBundle=update.updated;
                attemptedSelections.add(new AndroidNodeStore.SelectionSnapshot(update.id,updatedBundle));
                if(!update.id.equals(nodes.applyProfileBundle(update.id,update.original,updatedBundle).id))throw new IllegalStateException("Router node identity changed during connection-profile apply.");
            }
            if(updatedOrdinary!=null){ordinaryAttempted=true;exits.saveIfUnchanged(updatedOrdinary,AndroidStandardExitStore.snapshot(originalOrdinary));}
            if(updatedExternal!=null){externalAttempted=true;exits.saveIfUnchanged(updatedExternal,AndroidStandardExitStore.snapshot(originalExternal));}
            selectionAttempted=true;
            if(!external){attemptedSelections.add(new AndroidNodeStore.SelectionSnapshot(nodeId,readLimited(nodes.file(nodeId),AndroidNodeStore.MAX_BUNDLE)));nodes.select(nodeId);}
            else if(!originalSelection.id.isEmpty()){attemptedSelections.add(new AndroidNodeStore.SelectionSnapshot(originalSelection.id,readLimited(nodes.file(originalSelection.id),AndroidNodeStore.MAX_BUNDLE)));nodes.select(originalSelection.id);}
            else nodes.restoreSelection(originalSelection);
            publishPreferences(preferenceUpdate);
            if(validation!=null)validation.require();
        }catch(Exception failure){
            Exception rollback=null;
            synchronized(prefs()) {
            if(!ownsPreferences(preferenceUpdate)) {
                rollback=new IllegalStateException("A newer connection choice prevents profile rollback; its selection and sources were preserved.");
            } else {
            if(externalAttempted)try{restoreExternal(originalExternal,updatedExternal);}catch(Exception error){rollback=append(rollback,error);}
            if(ordinaryAttempted)try{restoreExternal(originalOrdinary,updatedOrdinary);}catch(Exception error){rollback=append(rollback,error);}
            for(int i=applied.size()-1;i>=0;i--)try{NodeUpdate update=applied.get(i);nodes.restoreProfileBundle(update.id,update.original,update.updated);}catch(Exception error){rollback=append(rollback,error);}
            if(selectionAttempted)try{nodes.restoreProfileSelection(originalSelection,attemptedSelections);}catch(Exception error){rollback=append(rollback,error);}
            try{rollbackPreferences(preferenceUpdate);}catch(Exception error){rollback=append(rollback,error);}
            }
            }
            IllegalStateException result=new IllegalStateException(rollback==null?"Could not load the connection profile; prior connection state was restored.":"Could not load the connection profile and rollback is incomplete; inspect the linked nodes before connecting.",failure);
            if(rollback!=null)result.addSuppressed(rollback);throw result;
        }
        }
        return toRecord(row);
    }

    synchronized Map<String,Object> orderedEditorPreferences() throws Exception {
        requireIdle("editing an ordered Router path");
        synchronized(prefs()) { return java.util.Collections.unmodifiableMap(snapshotPreferences()); }
    }

    /** Publish only choices from the editor's original complete sources. The
     * existing load transaction owns file/preference rollback and copies no keys. */
    synchronized AndroidNodeStore.ChainCapture selectOrderedPath(AndroidNodeStore.ChainCatalog catalog,
            List<AndroidNodeStore.ChainSource> sources,List<String> modes,Map<String,Object> originalPreferences) throws Exception {
        requireIdle("saving an ordered Router path");
        if(catalog==null||sources==null||modes==null||sources.size()<2||sources.size()>8||sources.size()!=modes.size())
            throw new IllegalStateException("Choose every member of the complete ordered path.");
        synchronized(prefs()) {
            if(originalPreferences==null||!originalPreferences.equals(snapshotPreferences()))throw new IllegalStateException("The selected connection changed while editing its ordered nodes.");
            return nodes.publishChainCatalog(catalog,()->{
                if(!originalPreferences.equals(snapshotPreferences()))throw new IllegalStateException("The ordered editor lost its original connection choice.");
                JSONArray members=new JSONArray();
                for(int i=0;i<sources.size();i++) {
                    AndroidNodeStore.ChainSource source=sources.get(i),original=catalog.source(source.id);
                    if(!java.util.Arrays.equals(source.bytes(),original.bytes()))throw new IllegalStateException("An ordered editor member differs from its original complete source.");
                    members.put(orderedSavedMember(source,modes.get(i)));
                }
                AndroidNodeStore.ChainSource control=sources.get(sources.size()-1);
                JSONObject row=new JSONObject().put("id",newId()).put("name","Ordered Router path").put("node_kind","router-vpn")
                        .put("node_id",control.id).put("node_profile_id",control.profileId).put("policy",members.getJSONObject(members.length()-1).getJSONObject("policy"))
                        .put("mode","smart-auto").put("custom_layers",new JSONArray()).put("multihop_enabled",true).put("multihop_execution","local")
                        .put(MULTI_ENTRY_KIND,"router-vpn").put("multihop_entry_id","").put("multihop_entry_mode","")
                        .put("multihop_exit_id","").put("multihop_exit_mode","").put(MULTI_NODES,members);
                validateOrderedRow(row,SCHEMA_VERSION);
                AndroidNodeStore.ChainCapture[] result=new AndroidNodeStore.ChainCapture[1];
                loadRow(row,()->result[0]=currentOrderedPath());
                return result[0];
            });
        }
    }

    synchronized void delete(String id) throws Exception { requireIdle("deleting a connection profile");if(!safeId(id))throw new IllegalArgumentException("Invalid connection profile id.");JSONArray rows=readRows(),next=new JSONArray();boolean found=false;for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(id.equals(row.optString("id")))found=true;else next.put(row);}if(!found)throw new IllegalArgumentException("Connection profile was not found.");writeRows(next); }

    private JSONObject snapshot(String name,String id) throws Exception {
        SharedPreferences p=prefs();String kind=p.getString(SELECTED_KIND,"router-vpn"),nodeId=p.getString(SELECTED_ID,nodes.activeId());if(nodeId==null||nodeId.isEmpty())throw new IllegalStateException("Select a Router or Custom node first.");
        if(p.getBoolean(MULTI_ON,false)&&!p.getString(MULTI_NODES,"").isEmpty())return snapshotOrdered(name,id);
        boolean external="external".equals(kind);AndroidStandardExitStore.Entry custom=external?AndroidStandardExitStore.copy(exits.get(nodeId)):null;
        NodePolicy policy=external?null:routerPolicy(nodeId);
        if(!external&&!"router-vpn".equals(kind))throw new IllegalStateException("Selected node kind is unsupported.");
        String mode=external?"external":normalizeMode(p.getString(MODE_KEY,"smart-auto"));List<String>layers=external?new ArrayList<>():customLayers(mode);boolean multi=p.getBoolean(MULTI_ON,false);String entry=p.getString(MULTI_ENTRY,""),exit=p.getString(MULTI_EXIT,"");String multiMode=external?custom.protocol:multi?normalizeMultiMode(p.getString(MULTI_MODE,"shadowsocks")):"shadowsocks";
        String execution=normalizeExecution(p.getString("multihop_execution","local")),entryKind=multi?normalizeEntryKind(p.getString(MULTI_ENTRY_KIND,"router-vpn")):"router-vpn";
        boolean ordinary="external".equals(entryKind);
        String entryMode=!multi?"wg":ordinary?normalizeOrdinaryMode(p.getString("multihop_entry_mode","")):normalizeEntryMode(p.getString("multihop_entry_mode","wg"));
        AndroidStandardExitStore.Entry ordinaryEntry=null;
        if(multi){
            if(entry==null||exit==null||entry.isEmpty()||exit.isEmpty()||entry.equals(exit))throw new IllegalStateException("Current multihop selection is incomplete or references a missing entry.");
            if(external){if(!exit.equals(nodeId)||!p.getString(MULTI_MODE,"").equals(custom.protocol))throw new IllegalStateException("Choose this exact external exit before saving.");}else if(findNode(exit)==null)throw new IllegalStateException("Current multihop exit is missing.");
            if(ordinary){if(!external&&(!exit.equals(nodeId)||!AndroidImportedRouterPath.supports(entryMode,multiMode)||!"local".equals(execution)))throw new IllegalStateException("The imported Router path changed its Local final node.");ordinaryEntry=AndroidStandardExitStore.copy(exits.get(entry));}
            else requireEntryMode(findNode(entry),entryMode);
        }
        else{entry="";exit="";multiMode=external?custom.protocol:"shadowsocks";}
        JSONObject row=new JSONObject().put("id",id).put("name",name).put("node_kind",kind).put("node_id",nodeId).put("mode",mode).put("custom_layers",new JSONArray(layers))
                .put("multihop_enabled",multi).put("multihop_entry_id",entry).put("multihop_exit_id",exit).put("multihop_exit_mode",multiMode).put(MULTI_ENTRY_KIND,entryKind).put("multihop_execution",execution).put("multihop_entry_mode",entryMode);
        if(policy!=null)row.put("policy",policy.choices).put("node_profile_id",policy.profileId);
        if(multi){
            if(ordinary)row.put("ordinary_entry_protocol",ordinaryEntry.protocol).put("ordinary_entry_public_ip",ordinaryEntry.expectedPublicIp)
                    .put("ordinary_entry_policy",AndroidConnectionProfilePolicy.external(ordinaryEntry.policy,ordinaryEntry.protocol))
                    .put("ordinary_entry_startup",AndroidStandardExitStore.startupMetadata(ordinaryEntry));
            else{NodePolicy entryPolicy=routerPolicy(entry);row.put("entry_policy",entryPolicy.choices).put("entry_profile_id",entryPolicy.profileId);}
            if(!external){NodePolicy exitPolicy=routerPolicy(exit);row.put("exit_policy",exitPolicy.choices).put("exit_profile_id",exitPolicy.profileId);}
        }
        if(external){AndroidStandardExitStore.validate(custom);validateExternalGraph(custom,multi&&!ordinary?findNode(entry):null,ordinaryEntry,entryMode,execution);row.put("external_protocol",custom.protocol).put("external_public_ip",custom.expectedPublicIp).put("external_policy",AndroidConnectionProfilePolicy.external(AndroidTorProfile.isTor(custom.protocol)?custom.torPolicy:custom.policy,custom.protocol)).put("external_startup",AndroidStandardExitStore.startupMetadata(custom));}
        if(!external&&multi&&ordinary){if(!entryMode.equals(AndroidExternalPolicy.protocol(ordinaryEntry.protocol)))throw new IllegalStateException("The imported entry transport changed.");AndroidImportedRouterPath.compile(ordinaryEntry,AndroidImportedRouterPath.finalBundle(nodes.file(exit)),multiMode,execution);}
        return row;
    }

    synchronized AndroidNodeStore.ChainCapture currentOrderedPath() throws Exception {
        return orderedPath(true);
    }

    synchronized AndroidNodeStore.ChainCapture orderedEditorPath() throws Exception {
        return orderedPath(false);
    }

    private AndroidNodeStore.ChainCapture orderedPath(boolean enabled) throws Exception {
        synchronized(prefs()) {
            SharedPreferences p=prefs();
            if(enabled&&!p.getBoolean(MULTI_ON,false)||!"router-vpn".equals(p.getString(SELECTED_KIND,"router-vpn"))
                    ||!"router-vpn".equals(p.getString(MULTI_ENTRY_KIND,"router-vpn"))
                    ||!"local".equals(p.getString("multihop_execution","local")))throw new IllegalStateException("Choose the original Local ordered Router path.");
            for(String key:new String[]{MULTI_ENTRY,MULTI_EXIT,MULTI_MODE,"multihop_entry_mode"})
                if(!p.getString(key,"").isEmpty())throw new IllegalStateException("An ordered path cannot also select a legacy pair.");
            AndroidNodeStore.ChainCapture captured=nodes.captureChain(p.getString(SELECTED_ID,nodes.activeId()));
            if(!sameJSONValue(new JSONArray(p.getString(MULTI_NODES,"")),AndroidNodeStore.orderedSelection(captured.control.profile())))
                throw new IllegalStateException("The ordered connection choice differs from its original control source.");
            captured.requireCurrent();return captured;
        }
    }

    private JSONObject snapshotOrdered(String name,String id) throws Exception {
        Map<String,Object> preferences=snapshotPreferences();
        AndroidNodeStore.ChainCapture captured=currentOrderedPath();
        NodePolicy control=routerPolicy(captured.control.id);
        JSONArray members=new JSONArray();
        for(int i=0;i<captured.members.size();i++) {
            members.put(orderedSavedMember(captured.members.get(i),captured.modes.get(i)));
        }
        String mode=normalizeMode(prefs().getString(MODE_KEY,"smart-auto"));
        JSONObject row=new JSONObject().put("id",id).put("name",name).put("node_kind","router-vpn")
                .put("node_id",captured.control.id).put("node_profile_id",control.profileId).put("policy",control.choices)
                .put("mode",mode).put("custom_layers",new JSONArray(customLayers(mode)))
                .put("multihop_enabled",true).put("multihop_execution","local").put(MULTI_ENTRY_KIND,"router-vpn")
                .put("multihop_entry_id","").put("multihop_entry_mode","").put("multihop_exit_id","").put("multihop_exit_mode","")
                .put(MULTI_NODES,members);
        validateOrderedRow(row,SCHEMA_VERSION);
        captured.requireCurrent();
        if(!preferences.equals(snapshotPreferences()))throw new IllegalStateException("The selected connection changed while saving every ordered source.");
        return row;
    }

    private JSONObject orderedSavedMember(AndroidNodeStore.ChainSource source,String mode) throws Exception {
        JSONObject result=new JSONObject().put("id",source.profileId).put("node_id",source.id).put("mode",mode);
        if(source.imported) {
            AndroidStandardExitStore.Entry entry=source.external();
            return result.put("node_kind","external").put("policy",AndroidConnectionProfilePolicy.external(entry.policy,entry.protocol)).put("expected_public_ip",entry.expectedPublicIp);
        }
        NodePolicy policy=routerPolicy(source.id);
        if(!source.profileId.equals(policy.profileId))throw new IllegalStateException("An ordered member changed its selected profile.");
        return result.put("policy",policy.choices);
    }

    private void stageOrderedNodes(Map<String,NodeUpdate> updates,JSONObject row) throws Exception {
        validateOrderedRow(row,SCHEMA_VERSION);
        JSONArray members=row.getJSONArray(MULTI_NODES);Set<String> proofs=new HashSet<>();long total=0;
        for(int i=0;i<members.length();i++) {
            JSONObject member=members.getJSONObject(i);String id=member.getString("node_id");
            if("external".equals(member.optString("node_kind"))) {
                AndroidStandardExitStore.Entry source=AndroidStandardExitStore.copy(exits.get(id));
                source.policy=AndroidConnectionProfilePolicy.external(member.getJSONObject("policy"),source.protocol);
                AndroidNodeStore.ChainSource.requireImported(source);
                if(!source.id.equals(member.getString("id"))||!source.expectedPublicIp.equals(member.getString("expected_public_ip")))throw new IllegalStateException("The saved custom middle node changed its original external identity.");
                AndroidExternalPolicy.Captured input=AndroidExternalPolicy.captureImportedEntry(source);
                io.nekohasekai.libbox.Libbox.routerNodeChainImportedMemberInput(input.source,input.capture);
                total+=AndroidStandardExitStore.snapshot(source).getBytes(StandardCharsets.UTF_8).length;
                continue;
            }
            stageNode(updates,id,member.getJSONObject("policy"),member.getString("id"));
            NodeUpdate update=updates.get(id);JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(update.updated));
            String proof=AndroidNodeStore.stableNodeIdentity(bundle);
            if(!proof.matches("[0-9a-f]{64}")||!proofs.add(proof))throw new IllegalStateException("An ordered profile lost an independent paired member.");
            JSONObject files=bundle.getJSONObject("profiles").optJSONObject(member.getString("mode"));
            if(files==null||files.length()==0)throw new IllegalStateException("A saved ordered member lost its exact selected transport assets.");
            total+=update.updated.length;
            if(total>AndroidNodeStore.MAX_CHAIN_SOURCE)throw new IllegalStateException("Complete saved ordered sources exceed their aggregate bound.");
        }
        String controlId=row.getString("node_id");NodeUpdate control=updates.get(controlId);
        JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(control.updated)),profile=selectedProfile(bundle);
        profile.put("multihop_enabled",true).put("multihop_execution","local").put(MULTI_NODES,orderedReferences(members));
        for(String key:new String[]{"multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode"})profile.remove(key);
        AndroidNodeStore.orderedSelection(profile);AndroidNodeStore.validateBundle(bundle);
        byte[] updated=bundle.toString().getBytes(StandardCharsets.UTF_8);
        if(!controlId.equals(AndroidNodeStore.deriveId(bundle,updated)))throw new IllegalStateException("Ordered restoration changed the original control identity.");
        updates.put(controlId,new NodeUpdate(controlId,control.original,updated));
        long complete=0;
        for(NodeUpdate member:updates.values())complete+=member.updated.length;
        if(complete>AndroidNodeStore.MAX_CHAIN_SOURCE)throw new IllegalStateException("Complete ordered sources with their final references exceed the aggregate bound.");
    }

    private static JSONArray orderedReferences(JSONArray members) throws Exception {
        JSONArray references=new JSONArray();
        for(int i=0;i<members.length();i++)references.put(new JSONObject().put("id",members.getJSONObject(i).getString("id")).put("mode",members.getJSONObject(i).getString("mode")));
        return references;
    }

    private static void validateOrderedRow(JSONObject row,int schema) throws Exception {
        if(schema<7||!"router-vpn".equals(row.getString("node_kind"))||!"router-vpn".equals(row.optString(MULTI_ENTRY_KIND,"router-vpn")))
            throw new IllegalStateException("This saved schema cannot own an ordered Router path.");
        for(String key:new String[]{"entry_policy","entry_profile_id","exit_policy","exit_profile_id","external_policy","external_startup",
                "ordinary_entry_protocol","ordinary_entry_public_ip","ordinary_entry_policy","ordinary_entry_startup"})
            if(row.has(key))throw new IllegalStateException("An ordered saved path cannot borrow a pair or imported source.");
        JSONArray members=row.getJSONArray(MULTI_NODES);Set<String> local=new HashSet<>();
        if(members.length()<2||members.length()>8)throw new IllegalStateException("A saved ordered path requires two to eight complete members.");
        for(int i=0;i<members.length();i++) {
            JSONObject member=members.getJSONObject(i);
            if("external".equals(member.optString("node_kind"))) {
                if(member.length()!=6||members.length()!=3||i!=1||!"shadowsocks".equals(member.getString("mode"))||!member.getString("id").equals(member.getString("node_id"))
                        ||!member.getString("id").matches("[A-Za-z0-9_-]{1,64}")||!local.add(member.getString("node_id"))||!(member.get("expected_public_ip") instanceof String))throw new IllegalStateException("A saved imported node requires its original middle position and external identity.");
                AndroidConnectionProfilePolicy.external(member.getJSONObject("policy"),"shadowsocks");continue;
            }
            if(member.length()!=4||!(member.get("id") instanceof String)||!(member.get("mode") instanceof String)
                    ||!(member.get("node_id") instanceof String)||!member.getString("node_id").matches("[0-9a-f]{32}")
                    ||!local.add(member.getString("node_id")))throw new IllegalStateException("An ordered saved member lost its distinct local source reference.");
            AndroidConnectionProfilePolicy.router(member.getJSONObject("policy"),POLICY_KEYS);
        }
        JSONObject control=new JSONObject().put("id",row.getString("node_profile_id")).put("node_kind",row.getString("node_kind"))
                .put("multihop_enabled",row.get("multihop_enabled")).put("multihop_execution",row.getString("multihop_execution"))
                .put(MULTI_NODES,orderedReferences(members));
        for(String key:new String[]{"multihop_entry_id","multihop_entry_mode","multihop_exit_id","multihop_exit_mode"})if(row.has(key))control.put(key,row.get(key));
        AndroidNodeStore.orderedSelection(control);
        JSONObject last=members.getJSONObject(members.length()-1);
        if(!row.getString("node_id").equals(last.getString("node_id"))||!sameJSONValue(row.getJSONObject("policy"),last.getJSONObject("policy")))
            throw new IllegalStateException("The saved ordered control differs from its exact final member policy.");
    }

    private static boolean sameJSONValue(Object left,Object right) throws Exception {
        if(left instanceof JSONObject&&right instanceof JSONObject) {
            JSONObject a=(JSONObject)left,b=(JSONObject)right;if(a.length()!=b.length())return false;
            for(Iterator<String> keys=a.keys();keys.hasNext();) {String key=keys.next();if(!b.has(key)||!sameJSONValue(a.get(key),b.get(key)))return false;}
            return true;
        }
        if(left instanceof JSONArray&&right instanceof JSONArray) {
            JSONArray a=(JSONArray)left,b=(JSONArray)right;if(a.length()!=b.length())return false;
            for(int i=0;i<a.length();i++)if(!sameJSONValue(a.get(i),b.get(i)))return false;return true;
        }
        return java.util.Objects.equals(left,right);
    }

    static final class ImportedRouterSelection {
        final AndroidStandardExitStore.Entry entry;
        final AndroidNodeStore.Node exit;
        final String exitMode, execution;
        ImportedRouterSelection(AndroidStandardExitStore.Entry entry,AndroidNodeStore.Node exit,String mode,String execution){
            this.entry=entry;this.exit=exit;this.exitMode=mode;this.execution=execution;
        }
    }

    synchronized ImportedRouterSelection currentImportedRouterPath()throws Exception{
        SharedPreferences p=prefs();
        if(!p.getBoolean(MULTI_ON,false)||!"router-vpn".equals(p.getString(SELECTED_KIND,"router-vpn"))
                ||!"external".equals(p.getString(MULTI_ENTRY_KIND,"router-vpn")))throw new IllegalStateException("Choose an imported entry and paired Router final node.");
        String finalId=p.getString(MULTI_EXIT,"");
        AndroidNodeStore.Node last=findNode(finalId);
        AndroidStandardExitStore.Entry first=AndroidStandardExitStore.copy(exits.get(p.getString(MULTI_ENTRY,"")));
        String mode=p.getString(MULTI_MODE,""),execution=normalizeExecution(p.getString("multihop_execution","local"));
        if(last==null||!finalId.equals(p.getString(SELECTED_ID,""))||!finalId.equals(nodes.activeId())||!AndroidExternalPolicy.protocol(first.protocol).equals(p.getString("multihop_entry_mode","")))
            throw new IllegalStateException("The imported path lost its selected final node or entry mode.");
        AndroidImportedRouterPath.compile(first,AndroidImportedRouterPath.finalBundle(last.file),mode,execution);
        return new ImportedRouterSelection(first,last,mode,execution);
    }

    synchronized void selectImportedRouterPath(AndroidStandardExitStore.Entry first,AndroidNodeStore.Node last)throws Exception{
        selectImportedRouterPath(first,last,"shadowsocks","");
    }

    synchronized void selectImportedRouterPath(AndroidStandardExitStore.Entry first,AndroidNodeStore.Node last,String mode)throws Exception{
        selectImportedRouterPath(first,last,mode,"");
    }

    synchronized void selectImportedRouterPath(AndroidStandardExitStore.Entry first,AndroidNodeStore.Node last,String mode,String expectedFinal)throws Exception{
        requireIdle("choosing an imported entry path");
        if(last==null)throw new IllegalArgumentException("Choose a paired Router final node.");
        AndroidStandardExitStore.Entry original=AndroidStandardExitStore.copy(first);
        String originalEntry=AndroidStandardExitStore.snapshot(original);
        byte[] originalFinal=readLimited(last.file,AndroidNodeStore.MAX_BUNDLE);
        if(expectedFinal==null||!expectedFinal.isEmpty()&&(!expectedFinal.matches("[0-9a-f]{64}")
                ||!expectedFinal.equals(AndroidTorProfile.digest(originalFinal))))throw new IllegalStateException("The final node changed after its transports were offered.");
        AndroidImportedRouterPath.compile(original,new JSONObject(AndroidTorProfile.strictText(originalFinal)),mode,"local");
        AndroidNodeStore.SelectionSnapshot selected;Map<String,Object> previous;
        synchronized(prefs()){selected=nodes.snapshotSelection();previous=snapshotPreferences();}
        Map<String,Object> next=new LinkedHashMap<>(previous);
        next.put(SELECTED_KIND,"router-vpn");next.put(SELECTED_ID,last.id);next.put(MODE_KEY,mode);next.put(MULTI_NODES,"");next.put(MULTI_ON,true);
        next.put(MULTI_ENTRY,original.id);next.put(MULTI_EXIT,last.id);next.put(MULTI_MODE,mode);next.put(MULTI_ENTRY_KIND,"external");
        next.put("multihop_execution","local");next.put("multihop_entry_mode",AndroidExternalPolicy.protocol(original.protocol));
        requireExternalUnchanged(original);
        if(!java.util.Arrays.equals(originalFinal,readLimited(last.file,AndroidNodeStore.MAX_BUNDLE)))throw new IllegalStateException("The paired final node changed before selection.");
        PreferenceUpdate preferenceUpdate=new PreferenceUpdate(previous,next);boolean attempted=false;
        synchronized(prefs()) {
        try{
            if(!preferenceUpdate.original.equals(snapshotPreferences()))throw new IllegalStateException("The selected connection changed before imported path mutation.");
            requireIdle("choosing an imported entry path");attempted=true;nodes.select(last.id);
            publishPreferences(preferenceUpdate);
            if(!originalEntry.equals(AndroidStandardExitStore.snapshot(exits.get(original.id)))
                    ||!java.util.Arrays.equals(originalFinal,readLimited(last.file,AndroidNodeStore.MAX_BUNDLE)))throw new IllegalStateException("A source changed during imported path selection.");
        }catch(Exception failure){
            synchronized(prefs()){
                if(ownsPreferences(preferenceUpdate)){
                    if(attempted)try{nodes.restoreProfileSelection(selected,java.util.Collections.singletonList(new AndroidNodeStore.SelectionSnapshot(last.id,originalFinal)));}catch(Exception rollback){failure.addSuppressed(rollback);}
                    try{rollbackPreferences(preferenceUpdate);}catch(Exception rollback){failure.addSuppressed(rollback);}
                }else failure.addSuppressed(new IllegalStateException("A newer connection choice prevents imported path rollback; its selection was preserved."));
            }
            throw failure;
        }
        }
    }

    static final class ExternalSelection {
        final AndroidNodeStore.Node entry;final AndroidStandardExitStore.Entry ordinaryEntry,exit;final String entryMode,execution;
        ExternalSelection(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,String entryMode,String execution){this(entry,null,exit,entryMode,execution);}
        ExternalSelection(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry ordinaryEntry,AndroidStandardExitStore.Entry exit,String entryMode,String execution){this.entry=entry;this.ordinaryEntry=ordinaryEntry;this.exit=exit;this.entryMode=entryMode;this.execution=execution;}
        boolean direct(){return entry==null&&ordinaryEntry==null;}
    }

    /** Select a complete external path without starting a VPN or changing any node secret. */
    synchronized void selectExternalPath(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,String entryMode)throws Exception{selectExternalPath(exit,entry,entryMode,"local");}

    synchronized void selectExternalPath(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,String entryMode,String execution)throws Exception{
        requireIdle("selecting an external path");
        AndroidStandardExitStore.Entry current=exits.get(exit.id);
        if(!AndroidStandardExitStore.snapshot(exit).equals(AndroidStandardExitStore.snapshot(current)))throw new IllegalStateException("The selected external node changed; select its path again.");
        if(entry!=null){AndroidNodeStore.Node currentEntry=findNode(entry.id);if(currentEntry==null||!java.util.Arrays.equals(readLimited(entry.file,AndroidNodeStore.MAX_BUNDLE),readLimited(currentEntry.file,AndroidNodeStore.MAX_BUNDLE)))throw new IllegalStateException("The selected entry changed.");requireEntryMode(currentEntry,entryMode);}
        validateExternalGraph(current,entry,entryMode,execution);
        Map<String,Object> original=snapshotPreferences(),next=new LinkedHashMap<>(original);
        next.put(SELECTED_KIND,"external");next.put(SELECTED_ID,current.id);next.put(MODE_KEY,"external");
        next.put(MULTI_NODES,"");next.put(MULTI_ON,entry!=null);next.put(MULTI_ENTRY,entry==null?"":entry.id);next.put(MULTI_EXIT,entry==null?"":current.id);
        next.put(MULTI_MODE,current.protocol);next.put(MULTI_ENTRY_KIND,"router-vpn");next.put("multihop_execution",execution);next.put("multihop_entry_mode",entry==null?"wg":entryMode);
        PreferenceUpdate preferenceUpdate=new PreferenceUpdate(original,next);
        try{
            requireIdle("selecting an external path");
            publishPreferences(preferenceUpdate);
        }catch(Exception failure){try{rollbackPreferences(preferenceUpdate);}catch(Exception rollback){IllegalStateException error=new IllegalStateException("External path selection failed and rollback is incomplete.",failure);error.addSuppressed(rollback);throw error;}throw failure;}
    }

    /** Ordinary predecessors retain their own private source and never acquire Router authority. */
    synchronized void selectOrdinaryTorPath(AndroidStandardExitStore.Entry exit,AndroidStandardExitStore.Entry ordinaryEntry)throws Exception{
        requireIdle("selecting an ordinary Tor path");
        if(exit==null||ordinaryEntry==null)throw new IllegalArgumentException("Choose both saved external nodes.");
        AndroidStandardExitStore.Entry current=AndroidStandardExitStore.copy(exits.get(exit.id)),currentEntry=AndroidStandardExitStore.copy(exits.get(ordinaryEntry.id));
        if(!AndroidStandardExitStore.snapshot(exit).equals(AndroidStandardExitStore.snapshot(current))||!AndroidStandardExitStore.snapshot(ordinaryEntry).equals(AndroidStandardExitStore.snapshot(currentEntry)))throw new IllegalStateException("An ordinary Tor source changed; select the path again.");
        String mode=AndroidExternalPolicy.protocol(currentEntry.protocol);
        validateExternalGraph(current,null,currentEntry,mode,"local");
        Map<String,Object> original=snapshotPreferences(),next=new LinkedHashMap<>(original);
        next.put(SELECTED_KIND,"external");next.put(SELECTED_ID,current.id);next.put(MODE_KEY,"external");
        next.put(MULTI_NODES,"");next.put(MULTI_ON,true);next.put(MULTI_ENTRY,currentEntry.id);next.put(MULTI_EXIT,current.id);next.put(MULTI_MODE,current.protocol);
        next.put(MULTI_ENTRY_KIND,"external");next.put("multihop_execution","local");next.put("multihop_entry_mode",mode);
        PreferenceUpdate preferenceUpdate=new PreferenceUpdate(original,next);
        try{
            requireIdle("selecting an ordinary Tor path");requireExternalUnchanged(currentEntry);requireExternalUnchanged(current);
            publishPreferences(preferenceUpdate);
        }catch(Exception failure){try{rollbackPreferences(preferenceUpdate);}catch(Exception rollback){IllegalStateException error=new IllegalStateException("Ordinary Tor path selection failed and rollback is incomplete.",failure);error.addSuppressed(rollback);throw error;}throw failure;}
    }

    synchronized ExternalSelection currentExternalPath(String id)throws Exception{
        SharedPreferences p=prefs();
        if(!"external".equals(p.getString(SELECTED_KIND,""))||!id.equals(p.getString(SELECTED_ID,"")))throw new IllegalStateException("Select the exact external node first.");
        AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(exits.get(id)),ordinaryEntry=null;AndroidNodeStore.Node entry=null;String mode="wg",execution=normalizeExecution(p.getString("multihop_execution","local"));
        if(p.getBoolean(MULTI_ON,false)){
            String entryID=p.getString(MULTI_ENTRY,"");
            if(!id.equals(p.getString(MULTI_EXIT,""))||!exit.protocol.equals(p.getString(MULTI_MODE,"")))throw new IllegalStateException("Choose this external node's exact path in Edit hops.");
            if(entryID.isEmpty()||entryID.equals(id))throw new IllegalStateException("An external path requires two distinct saved nodes.");
            if("external".equals(normalizeEntryKind(p.getString(MULTI_ENTRY_KIND,"router-vpn")))){ordinaryEntry=AndroidStandardExitStore.copy(exits.get(entryID));mode=normalizeOrdinaryMode(p.getString("multihop_entry_mode",""));}
            else{entry=findNode(entryID);mode=normalizeEntryMode(p.getString("multihop_entry_mode","wg"));requireEntryMode(entry,mode);}
        }
        validateExternalGraph(exit,entry,ordinaryEntry,mode,execution);return new ExternalSelection(entry,ordinaryEntry,exit,mode,execution);
    }

    /** A successful explicit Fastest adoption may publish its already-proved
     * selection. It changes no private node policy or engine configuration. */
    interface MeasuredSelection {ExternalSelection path();void requireBeforeSelection()throws Exception;void requireAfterSelection()throws Exception;}
    synchronized void selectMeasuredExternal(MeasuredSelection receipt)throws Exception{
        if(receipt==null)throw new IllegalArgumentException("An owned measured-path adoption is required.");
        receipt.requireBeforeSelection();ExternalSelection path=receipt.path();
        validateExternalGraph(path.exit,path.entry,path.ordinaryEntry,path.entryMode,path.execution);
        requireExternalUnchanged(path.exit);if(path.ordinaryEntry!=null)requireExternalUnchanged(path.ordinaryEntry);
        Map<String,Object> original=snapshotPreferences(),next=new LinkedHashMap<>(original);
        next.put(SELECTED_KIND,"external");next.put(SELECTED_ID,path.exit.id);next.put(MODE_KEY,"external");
        next.put(MULTI_NODES,"");next.put(MULTI_ON,!path.direct());next.put(MULTI_ENTRY,path.entry!=null?path.entry.id:path.ordinaryEntry!=null?path.ordinaryEntry.id:"");
        next.put(MULTI_EXIT,path.direct()?"":path.exit.id);next.put(MULTI_MODE,path.exit.protocol);
        next.put(MULTI_ENTRY_KIND,path.ordinaryEntry==null?"router-vpn":"external");next.put("multihop_execution",path.execution);
        next.put("multihop_entry_mode",path.direct()?"wg":path.entryMode);
        PreferenceUpdate preferenceUpdate=new PreferenceUpdate(original,next);
        try{
            receipt.requireBeforeSelection();
            publishPreferences(preferenceUpdate);
            if(!next.equals(snapshotPreferences()))throw new IllegalStateException("The measured selection did not persist exactly.");
            receipt.requireAfterSelection();
        }catch(Exception failure){
            // Roll back only our exact selection write. A concurrent newer
            // choice is not authority to overwrite the user's preferences.
            try{rollbackPreferences(preferenceUpdate);}catch(Exception rollback){failure.addSuppressed(rollback);}
            throw failure;
        }
    }

    private static final class NodeUpdate {
        final String id;final byte[] original,updated;
        NodeUpdate(String id,byte[] original,byte[] updated){this.id=id;this.original=original;this.updated=updated;}
    }

    private static final class NodePolicy {
        final String profileId;final JSONObject choices;
        NodePolicy(String profileId,JSONObject choices){this.profileId=profileId;this.choices=choices;}
    }

    private NodePolicy routerPolicy(String id)throws Exception{
        if(findNode(id)==null)throw new IllegalStateException("The saved Router node is no longer linked.");
        JSONObject profile=selectedProfile(readBundle(nodes.file(id))),policy=new JSONObject();
        if(profile==null)throw new IllegalStateException("The Router node has no selected profile.");
        AndroidNativeProfilePolicy.validateHomeDNS(profile);
        for(String key:POLICY_KEYS)if(profile.has(key))policy.put(key,profile.get(key));
        // Null in a saved Router policy captures the runtime default (absence).
        // An omitted saved field belongs to an older profile and is not ours to reset.
        // Never accept null from the linked runtime source itself.
        if(profile.has("daita_rate_kbps")&&profile.isNull("daita_rate_kbps"))throw new IllegalArgumentException("Router cover rate must be 0 or 32–192 kbps, or omitted for the runtime default.");
        if(!profile.has("daita_rate_kbps"))policy.put("daita_rate_kbps",JSONObject.NULL);
        String profileId=profile.optString("id","").trim();if(profileId.isEmpty()||profileId.length()>256)throw new IllegalStateException("The Router node has no bounded selected profile identity.");
        return new NodePolicy(profileId,AndroidConnectionProfilePolicy.router(policy,POLICY_KEYS));
    }

    private void stageNode(Map<String,NodeUpdate> updates,String id,JSONObject saved,String profileId)throws Exception{
        if(findNode(id)==null)throw new IllegalStateException("The saved Router node is no longer linked.");
        byte[] original=readLimited(nodes.file(id),AndroidNodeStore.MAX_BUNDLE);
        JSONObject bundle=new JSONObject(new String(original,StandardCharsets.UTF_8)),profile=selectedProfile(bundle);
        if(profile==null)throw new IllegalStateException("The Router node has no selected profile.");
        if(!profileId.isEmpty()&&!profileId.equals(profile.optString("id","").trim()))throw new IllegalStateException("The linked Router node's selected credential profile changed; update the saved connection profile.");
        if(saved==null)return; // Legacy rows referenced the hop without copying its policy.
        JSONObject policy=AndroidConnectionProfilePolicy.router(saved,POLICY_KEYS);
        // New captures own absence/defaults too. Older rows never captured the
        // expanded policy, so they may only replace the fields they recorded.
        if(!profileId.isEmpty())for(String key:POLICY_KEYS)if(!"daita_rate_kbps".equals(key)||policy.has(key))profile.remove(key);
        for(Iterator<String> keys=policy.keys();keys.hasNext();){
            String key=keys.next();
            if("daita_rate_kbps".equals(key)&&policy.isNull(key))profile.remove(key);
            else profile.put(key,policy.get(key));
        }
        AndroidNativeProfilePolicy.validateHomeDNS(profile);
        AndroidNodeStore.validateBundle(bundle);byte[] updatedBundle=bundle.toString().getBytes(StandardCharsets.UTF_8);
        if(!id.equals(AndroidNodeStore.deriveId(bundle,updatedBundle)))throw new IllegalStateException("This legacy Router node has no stable proof-bound identity. Re-import its current bundle before restoring policy.");
        NodeUpdate existing=updates.get(id);
        if(existing!=null&&!java.util.Arrays.equals(existing.updated,updatedBundle))throw new IllegalStateException("A saved path assigns conflicting policies to the same Router node.");
        if(existing==null)updates.put(id,new NodeUpdate(id,original,updatedBundle));
    }

    private static void requireEntryMode(AndroidNodeStore.Node entry,String mode)throws Exception{
        normalizeEntryMode(mode);if(entry==null)throw new IllegalStateException("The saved entry is no longer linked.");
        JSONObject bundle=readBundle(entry.file);AndroidNodeStore.validateBundle(bundle);
        if(bundle.getJSONObject("profiles").optJSONObject(mode)==null)throw new IllegalStateException("The saved entry no longer supplies its selected transport.");
    }

    private static void requireExternalIdentity(JSONObject row,AndroidStandardExitStore.Entry exit)throws Exception{
        if(!row.getString("external_protocol").equals(exit.protocol)||!row.getString("external_public_ip").equals(exit.expectedPublicIp))throw new IllegalStateException("The linked external node's protocol or public identity changed; update the saved connection profile.");
    }

    private static void requireOrdinaryIdentity(JSONObject row,AndroidStandardExitStore.Entry entry)throws Exception{
        AndroidStandardExitStore.validate(entry);
        if(!row.getString("multihop_entry_id").equals(entry.id)||!row.getString("ordinary_entry_protocol").equals(entry.protocol)
                ||!row.getString("ordinary_entry_public_ip").equals(entry.expectedPublicIp))throw new IllegalStateException("The linked ordinary entry's protocol or public identity changed; update the saved connection profile.");
    }

    private void requireExternalUnchanged(AndroidStandardExitStore.Entry original)throws Exception{
        if(!AndroidStandardExitStore.snapshot(original).equals(exits.storedSnapshot(original.id)))throw new IllegalStateException("A linked external node changed during profile validation.");
    }

    private void restoreExternal(AndroidStandardExitStore.Entry original,AndroidStandardExitStore.Entry updated)throws Exception{
        String before=AndroidStandardExitStore.snapshot(original),current=exits.storedSnapshot(original.id);
        if(before.equals(current))return; // The failed write did not publish.
        String ours=AndroidStandardExitStore.snapshot(updated);
        if(!ours.equals(current))throw new IllegalStateException("A concurrent external-node update prevents safe rollback; its source was preserved.");
        exits.saveIfUnchanged(original,ours);
    }

    private static void validateExternalGraph(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,String mode,String execution)throws Exception{
        validateExternalGraph(exit,entry,null,mode,execution);
    }

    static void validateExternalGraph(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry ordinaryEntry,String mode,String execution)throws Exception{
        AndroidStandardExitStore.validate(exit);AndroidStandardExitStore.validateExecution(exit,entry!=null,execution);
        JSONObject policy=AndroidConnectionProfilePolicy.external(AndroidTorProfile.isTor(exit.protocol)?exit.torPolicy:exit.policy,exit.protocol);
        if(ordinaryEntry!=null){
            AndroidStandardExitStore.validate(ordinaryEntry);
            if(entry!=null||!AndroidExternalPolicy.supports(ordinaryEntry.protocol)||!AndroidTorProfile.isTor(exit.protocol)
                    ||ordinaryEntry.id.equals(exit.id)||!"local".equals(execution)||!normalizeOrdinaryMode(mode).equals(AndroidExternalPolicy.protocol(ordinaryEntry.protocol)))throw new IllegalArgumentException("An ordinary entry requires its exact distinct Tor exit and Local transport.");
            AndroidTorProfile.compileOrdinary(ordinaryEntry,exit,"selection-validation",execution);
        }
        if(entry!=null)requireEntryMode(entry,mode);
        String dns=policy.optString("dns_mode","");
        if(entry==null&&(dns.isEmpty()||"home".equals(dns)))throw new IllegalArgumentException("Home AdGuard needs a selected Router VPN entry; choose it in Edit hops.");
    }

    private static final class PreferenceUpdate {
        final Map<String,Object> original,next;boolean attempted;
        PreferenceUpdate(Map<String,Object> original,Map<String,Object> next){this.original=new LinkedHashMap<>(original);this.next=new LinkedHashMap<>(next);}
    }
    // All Product and profile selection publishers share the same original
    // preference monitor as AndroidCustomPresetCommit. Editors may be staged
    // independently; their actual publication is serialized here.
    static void applySelection(SharedPreferences preferences,SharedPreferences.Editor editor){synchronized(preferences){editor.apply();}}
    private Map<String,Object> snapshotPreferences(){synchronized(prefs()){Map<String,?> current=prefs().getAll();Map<String,Object> result=new LinkedHashMap<>();for(String key:SELECTION_KEYS)if(current.containsKey(key)){Object value=current.get(key);if(MULTI_ON.equals(key)?!(value instanceof Boolean):!(value instanceof String))throw new IllegalStateException("Saved selection preferences have an invalid type.");result.put(key,value);}return result;}}
    private void publishPreferences(PreferenceUpdate update){synchronized(prefs()){
        if(!update.original.equals(snapshotPreferences()))throw new IllegalStateException("The selected connection changed before profile publication.");
        update.attempted=true;
        restorePreferences(update.next);
        if(!update.next.equals(snapshotPreferences()))throw new IllegalStateException("The selected connection changed during profile publication.");
    }}
    private boolean ownsPreferences(PreferenceUpdate update){synchronized(prefs()){
        Map<String,Object> current=snapshotPreferences();
        return update.original.equals(current)||(update.attempted&&update.next.equals(current));
    }}
    private void rollbackPreferences(PreferenceUpdate update){synchronized(prefs()){
        if(!ownsPreferences(update))throw new IllegalStateException("A newer connection choice prevents preference rollback; its selection was preserved.");
        if(update.attempted&&!update.original.equals(snapshotPreferences()))restorePreferences(update.original);
    }}
    private void restorePreferences(Map<String,Object> original){synchronized(prefs()){
        SharedPreferences.Editor edit=prefs().edit();for(String key:SELECTION_KEYS){if(!original.containsKey(key)){edit.remove(key);continue;}Object value=original.get(key);if(value instanceof String)edit.putString(key,(String)value);else if(value instanceof Boolean)edit.putBoolean(key,(Boolean)value);else if(value instanceof Integer)edit.putInt(key,(Integer)value);else if(value instanceof Long)edit.putLong(key,(Long)value);else if(value instanceof Float)edit.putFloat(key,(Float)value);else throw new IllegalStateException("Saved selection preferences have an invalid type.");}
        if(!edit.commit())throw new IllegalStateException("Could not restore previous connection preferences.");
    }}
    private static Exception append(Exception aggregate,Exception error){if(aggregate==null)return error;aggregate.addSuppressed(error);return aggregate;}

    private void requireIdle(String action){if(AndroidVpnMutationGuard.isBusy(context))throw new IllegalStateException("Disconnect Router VPN or let the active transition finish before "+action+"; live session identity and proof must remain immutable.");}
    private AndroidNodeStore.Node findNode(String id) throws Exception { for(AndroidNodeStore.Node n:nodes.list())if(n.id.equals(id))return n;return null; }
    private SharedPreferences prefs(){return context.getSharedPreferences(PREFS,Context.MODE_PRIVATE);}
    private JSONObject find(String id)throws Exception{if(!safeId(id))throw new IllegalArgumentException("Invalid connection profile id.");JSONArray rows=readRows();for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(id.equals(row.optString("id")))return row;}throw new IllegalArgumentException("Connection profile was not found.");}

    private JSONArray readRows() throws Exception {
        File source = file;
        boolean legacyPath = false;
        if (!file.exists()) {
            if (!legacyFile.exists()) return new JSONArray();
            source = legacyFile;
            legacyPath = true;
        }
        byte[] stored = AndroidPrivateFileStore.read(source, MAX_STORE);
        JSONObject root = new JSONObject(new String(stored, StandardCharsets.UTF_8));
        int schema = root.optInt("schema_version", 0);
        if (schema < 1 || schema > SCHEMA_VERSION) {
            throw new IllegalStateException("Unsupported connection profile store schema " + schema + ".");
        }
        JSONArray rows = root.optJSONArray("profiles");
        if (rows == null) rows = new JSONArray();
        if (rows.length() > MAX_PROFILES) throw new IllegalStateException("Too many saved connection profiles.");
        Set<String> ids = new HashSet<>();
        for (int i = 0; i < rows.length(); i++) {
            JSONObject row = rows.getJSONObject(i);
            String id = row.optString("id", "");
            cleanName(row.optString("name", ""));
            if (!safeId(id) || !ids.add(id)) {
                throw new IllegalStateException("Connection profile store contains invalid/duplicate ids.");
            }
            String kind = row.optString("node_kind", "");
            if (!"router-vpn".equals(kind) && !"external".equals(kind)) {
                throw new IllegalStateException("Connection profile node kind is invalid.");
            }
            if (row.optString("node_id", "").isEmpty()) {
                throw new IllegalStateException("Connection profile node id is missing.");
            }
            normalizeMode(row.optString("mode", "smart-auto"));
            jsonStrings(row.optJSONArray("custom_layers"), 32);
            if(row.has("multihop_enabled")&&!(row.get("multihop_enabled") instanceof Boolean))throw new IllegalStateException("Saved multihop enabled must be boolean.");
            if(row.has("custom_layers")&&!(row.get("custom_layers") instanceof JSONArray))throw new IllegalStateException("Saved CUSTOM layers must be a list.");
            boolean ordered=row.has(MULTI_NODES);
            if(ordered)validateOrderedRow(row,schema);
            if(!ordered&&"router-vpn".equals(kind)&&row.optBoolean("multihop_enabled",false))normalizeMultiMode(row.optString("multihop_exit_mode", "shadowsocks"));
            normalizeExecution(row.optString("multihop_execution","local"));
            if(row.has(MULTI_ENTRY_KIND)&&!(row.get(MULTI_ENTRY_KIND) instanceof String))throw new IllegalStateException("Saved entry kind must be a captured text choice.");
            String entryKind=normalizeEntryKind(row.optString(MULTI_ENTRY_KIND,"router-vpn"));
            boolean ordinary="external".equals(entryKind);
            if(ordinary){
                boolean routerFinal="router-vpn".equals(kind);
                if(!row.optBoolean("multihop_enabled",false)||!"local".equals(row.optString("multihop_execution","local"))
                        ||(routerFinal?schema<6||!row.getString("node_id").equals(row.optString("multihop_exit_id",""))
                        ||!AndroidImportedRouterPath.supports(row.optString("ordinary_entry_protocol",""),row.optString("multihop_exit_mode",""))
                        :schema<5||!row.has("external_policy")||!row.has("external_startup")||!AndroidTorProfile.isTor(row.optString("external_protocol",""))))
                    throw new IllegalStateException("Saved ordinary entry lost its complete Local path.");
                for(String key:new String[]{"ordinary_entry_protocol","ordinary_entry_public_ip"})if(!(row.get(key) instanceof String))throw new IllegalStateException("Saved ordinary entry lost its source identity.");
                String protocol=row.getString("ordinary_entry_protocol");
                if(!AndroidExternalPolicy.supports(protocol)||!normalizeOrdinaryMode(row.optString("multihop_entry_mode","")).equals(AndroidExternalPolicy.protocol(protocol)))throw new IllegalStateException("Saved ordinary entry changed its captured protocol.");
                AndroidConnectionProfilePolicy.external(row.getJSONObject("ordinary_entry_policy"),protocol);
                AndroidStandardExitStore.applyStartupMetadata(new AndroidStandardExitStore.Entry(),row.getJSONObject("ordinary_entry_startup"));
                for(String key:routerFinal?new String[]{"entry_policy","entry_profile_id"}:new String[]{"policy","node_profile_id","entry_policy","entry_profile_id","exit_policy","exit_profile_id"})
                    if(row.has(key))throw new IllegalStateException("An ordinary entry cannot restore private Router entry policy.");
                if(routerFinal&&(!row.has("policy")||!row.has("node_profile_id")||!row.has("exit_policy")||!row.has("exit_profile_id")))
                    throw new IllegalStateException("The imported path lost its independent paired final policy.");
            }else{
                if(!ordered)normalizeEntryMode(row.optString("multihop_entry_mode","wg"));
                for(String key:new String[]{"ordinary_entry_protocol","ordinary_entry_public_ip","ordinary_entry_policy","ordinary_entry_startup"})if(row.has(key))throw new IllegalStateException("Saved ordinary source cannot be reinterpreted as a Router entry.");
            }
            for(String reference:new String[]{"node_profile_id","entry_profile_id","exit_profile_id"})if(row.has(reference)){
                Object value=row.get(reference);if(!(value instanceof String)||((String)value).trim().isEmpty()||((String)value).length()>256)throw new IllegalStateException("Saved Router profile identity is invalid.");
            }
            for(String policyKey:new String[]{"policy","entry_policy","exit_policy"})if(row.has(policyKey)){
                JSONObject policy=row.getJSONObject(policyKey);
                Iterator<String> keys = policy.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    if (!allowedPolicyKey(key)) {
                        throw new IllegalStateException("Connection profile contains non-whitelisted node data: " + key);
                    }
                }
                if (policy.has("start_layer")) normalizeStartLayer(policy.optString("start_layer", "off"));
                AndroidConnectionProfilePolicy.router(policy,POLICY_KEYS);
            }
            if(row.has("external_policy")){
                if(!"external".equals(kind)||!(row.get("external_protocol") instanceof String)||!(row.get("external_public_ip") instanceof String))throw new IllegalStateException("Saved external policy lost its node identity.");
                AndroidConnectionProfilePolicy.external(row.getJSONObject("external_policy"),row.getString("external_protocol"));
                if(row.optBoolean("multihop_enabled",false)&&!row.getString("external_protocol").equals(row.getString("multihop_exit_mode")))throw new IllegalStateException("Saved external path protocol changed.");
            }
            if(row.has("external_startup")){
                if(!"external".equals(kind)||!row.has("external_policy"))throw new IllegalStateException("Saved external startup lost its captured node policy.");
                AndroidStandardExitStore.applyStartupMetadata(new AndroidStandardExitStore.Entry(),row.getJSONObject("external_startup"));
            }
        }
        if (legacyPath || schema < SCHEMA_VERSION) {
            writeRows(rows);
            AndroidPrivateFileStore.remove(legacyFile, MAX_STORE);
        } else if (legacyFile.exists()) {
            AndroidPrivateFileStore.remove(legacyFile, MAX_STORE);
        }
        return rows;
    }

    private void writeRows(JSONArray rows) throws Exception {
        byte[] raw = (new JSONObject()
                .put("schema_version", SCHEMA_VERSION)
                .put("profiles", rows)
                .toString(2) + "\n").getBytes(StandardCharsets.UTF_8);
        if (raw.length > MAX_STORE) throw new IllegalStateException("Connection profile store exceeds safety limit.");
        AndroidPrivateFileStore.write(file, raw, MAX_STORE);
    }



    private List<String> customLayers(String mode)throws Exception{if(mode==null||!mode.startsWith("custom:"))return new ArrayList<>();String name=mode.substring(7);JSONArray all=new JSONArray(prefs().getString(CUSTOM_KEY,"[]"));for(int i=0;i<all.length();i++){JSONObject p=all.optJSONObject(i);if(p!=null&&name.equals(p.optString("name","")))return jsonStrings(p.optJSONArray("layers"),32);}return new ArrayList<>();}
    private String prepareCustomPresetJSON(String mode,List<String>layers)throws Exception{if(mode==null||!mode.startsWith("custom:")||layers.isEmpty())return null;String name=mode.substring(7);if(name.trim().isEmpty()||name.length()>64)throw new IllegalArgumentException("CUSTOM profile name is invalid.");JSONArray all=new JSONArray(prefs().getString(CUSTOM_KEY,"[]")),next=new JSONArray();for(int i=0;i<all.length();i++){JSONObject p=all.optJSONObject(i);if(p!=null&&!name.equals(p.optString("name","")))next.put(p);}next.put(new JSONObject().put("name",name).put("layers",new JSONArray(layers)));return next.toString();}
    private static String normalizeEntryMode(String value) {
        if (!java.util.Arrays.asList("wg","awg2-fast","awg2-strong","wg-pq","awg2-pq","shadowsocks","hysteria2","naive-h2","naive-h3","ss-v2ray","split","max","reality-vision","reality-pq-vision","reality-xhttp","max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg").contains(value)) throw new IllegalArgumentException("Unknown saved entry transport.");
        return value;
    }
    private static String normalizeEntryKind(String value){if(!"router-vpn".equals(value)&&!"external".equals(value))throw new IllegalArgumentException("Unknown saved entry kind.");return value;}
    private static String normalizeOrdinaryMode(String value){if(!java.util.Arrays.asList("wireguard","amneziawg","socks5","http-connect","https-connect","shadowsocks","hysteria2","openvpn").contains(value))throw new IllegalArgumentException("Unknown saved ordinary entry transport.");return value;}
    private static String normalizeExecution(String value){if(!java.util.Arrays.asList("local","server","auto").contains(value))throw new IllegalArgumentException("Invalid saved multihop execution.");return value;}
    private static String normalizeMultiMode(String value){value=value==null?"":value.trim().toLowerCase(Locale.ROOT);if(value.isEmpty())value="shadowsocks";if(!"wg".equals(value)&&!"awg2-fast".equals(value)&&!"awg2-strong".equals(value)&&!"wg-pq".equals(value)&&!"awg2-pq".equals(value)&&!"shadowsocks".equals(value)&&!"hysteria2".equals(value)&&!"naive-h2".equals(value)&&!"naive-h3".equals(value)&&!"ss-v2ray".equals(value)&&!"split".equals(value)&&!"max".equals(value)&&!"reality-vision".equals(value)&&!"reality-pq-vision".equals(value)&&!"reality-xhttp".equals(value)&&!java.util.Arrays.asList("max-tls-wg","max-tls-awg","max-quic-wg","max-quic-awg").contains(value))throw new IllegalArgumentException("Multihop exit transport must be a supported native packet, proxy or Xray mode.");return value;}
    private static String normalizeStartLayer(String value){value=value==null?"":value.trim().toLowerCase(Locale.ROOT);if(value.isEmpty())value="off";if(!"off".equals(value)&&!"aes-256-gcm".equals(value)&&!"aes-256-gcm+xor-whitening".equals(value))throw new IllegalArgumentException("Start Layer must be Off, AES-256-GCM, or AES-256-GCM + XOR whitening.");return value;}
    private static boolean allowedPolicyKey(String key){for(String allowed:POLICY_KEYS)if(allowed.equals(key))return true;return false;}
    private static String cleanName(String value){value=value==null?"":value.trim();if(value.isEmpty()||value.length()>64)throw new IllegalArgumentException("Connection profile name must be 1–64 characters.");for(int i=0;i<value.length();i++)if(Character.isISOControl(value.charAt(i)))throw new IllegalArgumentException("Connection profile name contains a control character.");return value;}
    private static String normalizeMode(String value){value=value==null?"":value.trim().toLowerCase(Locale.ROOT);if(value.isEmpty())value="smart-auto";if(!value.matches("[a-z0-9._:-]{1,80}"))throw new IllegalArgumentException("Connection profile mode is invalid.");return value;}
    private static List<String> jsonStrings(JSONArray values,int max){List<String>out=new ArrayList<>();Set<String>seen=new HashSet<>();if(values==null)return out;if(values.length()>max)throw new IllegalArgumentException("Too many CUSTOM layers.");for(int i=0;i<values.length();i++){String v=values.optString(i,"").trim().toLowerCase(Locale.ROOT);if(v.isEmpty())continue;if(!v.matches("[a-z0-9._-]{1,64}"))throw new IllegalArgumentException("CUSTOM layer is invalid.");if(seen.add(v))out.add(v);}java.util.Collections.sort(out);return out;}
    private static Record toRecord(JSONObject row){JSONObject policy=row.optJSONObject("external".equals(row.optString("node_kind"))?"external_policy":"policy");boolean encrypted=policy!=null&&policy.optBoolean("auto_require_encrypted",false),obfuscated=policy!=null&&policy.optBoolean("auto_require_obfuscation",false);String startLayer=policy==null?"off":normalizeStartLayer(policy.optString("start_layer","off"));return new Record(row.optString("id",""),row.optString("name",""),row.optString("node_kind",""),row.optString("node_id",""),row.optString("mode","smart-auto"),startLayer,jsonStrings(row.optJSONArray("custom_layers"),32),encrypted,obfuscated);}
    private static JSONObject readBundle(File file)throws Exception{return new JSONObject(new String(readLimited(file,AndroidNodeStore.MAX_BUNDLE),StandardCharsets.UTF_8));}
    private static JSONObject selectedProfile(JSONObject bundle){return AndroidProfileSelection.selectedRouterProfile(bundle);}
    private static byte[] readLimited(File f,int max)throws Exception{return AndroidPrivateFileStore.read(f,max);}
    private static boolean safeId(String value){return value!=null&&value.matches("cp-[0-9a-f]{24}");}
    private static String newId(){return "cp-"+randomHex(12);}
    private static String randomHex(int n){byte[]b=new byte[n];RANDOM.nextBytes(b);StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format(Locale.ROOT,"%02x",x&255));return s.toString();}
}
