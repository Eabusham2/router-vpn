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
    static final int SCHEMA_VERSION=4, MAX_PROFILES=64, MAX_STORE=512*1024;
    private static final String FILE_NAME="connection-profiles-v4.json", LEGACY_FILE_NAME="connection-profiles-v1.json";
    private static final String PREFS="router-vpn-unified", MODE_KEY="mode", CUSTOM_KEY="custom_presets", SELECTED_KIND="selected_kind", SELECTED_ID="selected_id";
    private static final String MULTI_ON="multihop_on", MULTI_ENTRY="multihop_entry", MULTI_EXIT="multihop_exit", MULTI_MODE="multihop_exit_mode";
    private static final SecureRandom RANDOM=new SecureRandom();
    private static final String[] POLICY_KEYS={
            "home_lan_access","home_lan_cidrs","kill_switch","kill_switch_policy","ipv6_mode","base_tunnel","base_fallback","start_layer",
            "auto_require_encrypted","auto_require_obfuscation","mtu_policy","manual_mtu",
            "daita_enabled","jumbo_tun","socks_enabled","startup_mode","auto_connect","dns_mode","dns_protocol","dns_host",
            "dns_port","dns_server_name","dns_path","fastest_dns_host","fastest_dns_name","fastest_dns_latency_ms","dns_results","dns_bootstrap"
    };
    private static final String[] SELECTION_KEYS={SELECTED_KIND,SELECTED_ID,MODE_KEY,CUSTOM_KEY,MULTI_ON,MULTI_ENTRY,MULTI_EXIT,MULTI_MODE,"multihop_execution","multihop_entry_mode"};

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
    synchronized Record update(String id,String name) throws Exception { requireIdle("updating a connection profile");if(!safeId(id))throw new IllegalArgumentException("Invalid connection profile id.");JSONArray rows=readRows();boolean found=false;JSONObject replacement=snapshot(cleanName(name),id);JSONArray next=new JSONArray();for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(id.equals(row.optString("id"))){next.put(replacement);found=true;}else next.put(row);}if(!found)throw new IllegalArgumentException("Connection profile was not found.");writeRows(next);return toRecord(replacement); }

    synchronized Record load(String id) throws Exception {
        requireIdle("loading a connection profile");
        JSONObject row=find(id);String kind=row.getString("node_kind"),nodeId=row.getString("node_id");
        String mode=normalizeMode(row.optString("mode","smart-auto"));List<String>layers=jsonStrings(row.optJSONArray("custom_layers"),32);
        boolean external="external".equals(kind),multi=row.optBoolean("multihop_enabled",false);String entry=row.optString("multihop_entry_id",""),exit=row.optString("multihop_exit_id","");String multiMode=external?row.optString("multihop_exit_mode",""):multi?normalizeMultiMode(row.optString("multihop_exit_mode","shadowsocks")):"shadowsocks";String execution=normalizeExecution(row.optString("multihop_execution","local"));String entryMode=normalizeEntryMode(row.optString("multihop_entry_mode","wg"));
        AndroidStandardExitStore.Entry originalExternal=external?AndroidStandardExitStore.copy(exits.get(nodeId)):null,updatedExternal=null;
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
        if(multi){
            if(entry.isEmpty()||exit.isEmpty()||entry.equals(exit)||findNode(entry)==null)throw new IllegalStateException("Saved multihop references a missing/invalid entry.");
            if(external){if(!exit.equals(nodeId)||!multiMode.equals(originalExternal.protocol))throw new IllegalStateException("Saved external multihop must retain its exact exit protocol.");}
            else if(findNode(exit)==null)throw new IllegalStateException("Saved multihop references a missing Router exit.");
            requireEntryMode(findNode(entry),entryMode);
        }else{entry="";exit="";multiMode=external?originalExternal.protocol:"shadowsocks";}
        String preparedCustom=external?null:prepareCustomPresetJSON(mode,layers);
        Map<String,NodeUpdate> updates=new LinkedHashMap<>();
        if(!external)stageNode(updates,nodeId,row.optJSONObject("policy"),row.optString("node_profile_id",""));
        if(multi){stageNode(updates,entry,row.optJSONObject("entry_policy"),row.optString("entry_profile_id",""));if(!external)stageNode(updates,exit,row.optJSONObject("exit_policy"),row.optString("exit_profile_id",""));}
        if(external)validateExternalGraph(updatedExternal!=null?updatedExternal:originalExternal,multi?findNode(entry):null,entryMode,execution);
        AndroidNodeStore.SelectionSnapshot originalSelection=nodes.snapshotSelection();
        Map<String,Object> originalPreferences=snapshotPreferences();
        // All validation above is complete before any selection, node-file, preset or preference mutation.
        List<NodeUpdate> applied=new ArrayList<>();boolean externalAttempted=false,selectionAttempted=false;
        try{
            requireIdle("loading a connection profile");
            for(NodeUpdate update:updates.values()){
                if(!java.util.Arrays.equals(update.original,readLimited(nodes.file(update.id),AndroidNodeStore.MAX_BUNDLE)))throw new IllegalStateException("A linked Router node changed during profile validation.");
                applied.add(update);selectionAttempted=true;
                byte[] updatedBundle=update.updated;
                if(!update.id.equals(nodes.importBundle(updatedBundle).id))throw new IllegalStateException("Router node identity changed during connection-profile apply.");
            }
            if(updatedExternal!=null){
                if(!AndroidStandardExitStore.snapshot(originalExternal).equals(AndroidStandardExitStore.snapshot(exits.get(nodeId))))throw new IllegalStateException("The linked external node changed during profile validation.");
                externalAttempted=true;exits.save(updatedExternal);
            }
            selectionAttempted=true;
            if(!external)nodes.select(nodeId);
            else if(!originalSelection.id.isEmpty())nodes.select(originalSelection.id);
            else nodes.restoreSelection(originalSelection);
            SharedPreferences.Editor edit=prefs().edit().putString(SELECTED_KIND,kind).putString(SELECTED_ID,nodeId).putString(MODE_KEY,external?"external":mode)
                    .putBoolean(MULTI_ON,multi).putString(MULTI_ENTRY,entry).putString(MULTI_EXIT,exit).putString(MULTI_MODE,multiMode).putString("multihop_execution",execution).putString("multihop_entry_mode",entryMode);
            if(preparedCustom!=null)edit.putString(CUSTOM_KEY,preparedCustom);
            if(!edit.commit())throw new IllegalStateException("Could not persist loaded connection choices.");
        }catch(Exception failure){
            Exception rollback=null;
            if(externalAttempted)try{exits.save(originalExternal);}catch(Exception error){rollback=append(rollback,error);}
            for(int i=applied.size()-1;i>=0;i--)try{NodeUpdate update=applied.get(i);byte[] originalBundle=update.original;if(!update.id.equals(nodes.importBundle(originalBundle).id))throw new IllegalStateException("Restored Router node identity changed.");}catch(Exception error){rollback=append(rollback,error);}
            if(selectionAttempted)try{nodes.restoreSelection(originalSelection);}catch(Exception error){rollback=append(rollback,error);}
            try{restorePreferences(originalPreferences);}catch(Exception error){rollback=append(rollback,error);}
            IllegalStateException result=new IllegalStateException(rollback==null?"Could not load the connection profile; prior connection state was restored.":"Could not load the connection profile and rollback is incomplete; inspect the linked nodes before connecting.",failure);
            if(rollback!=null)result.addSuppressed(rollback);throw result;
        }
        return toRecord(row);
    }

    synchronized void delete(String id) throws Exception { requireIdle("deleting a connection profile");if(!safeId(id))throw new IllegalArgumentException("Invalid connection profile id.");JSONArray rows=readRows(),next=new JSONArray();boolean found=false;for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(id.equals(row.optString("id")))found=true;else next.put(row);}if(!found)throw new IllegalArgumentException("Connection profile was not found.");writeRows(next); }

    private JSONObject snapshot(String name,String id) throws Exception {
        SharedPreferences p=prefs();String kind=p.getString(SELECTED_KIND,"router-vpn"),nodeId=p.getString(SELECTED_ID,nodes.activeId());if(nodeId==null||nodeId.isEmpty())throw new IllegalStateException("Select a Router or Custom node first.");
        boolean external="external".equals(kind);AndroidStandardExitStore.Entry custom=external?AndroidStandardExitStore.copy(exits.get(nodeId)):null;
        NodePolicy policy=external?null:routerPolicy(nodeId);
        if(!external&&!"router-vpn".equals(kind))throw new IllegalStateException("Selected node kind is unsupported.");
        String mode=external?"external":normalizeMode(p.getString(MODE_KEY,"smart-auto"));List<String>layers=external?new ArrayList<>():customLayers(mode);boolean multi=p.getBoolean(MULTI_ON,false);String entry=p.getString(MULTI_ENTRY,""),exit=p.getString(MULTI_EXIT,"");String multiMode=external?custom.protocol:multi?normalizeMultiMode(p.getString(MULTI_MODE,"shadowsocks")):"shadowsocks";
        String execution=normalizeExecution(p.getString("multihop_execution","local")),entryMode=normalizeEntryMode(p.getString("multihop_entry_mode","wg"));
        if(multi){if(entry==null||exit==null||entry.isEmpty()||exit.isEmpty()||entry.equals(exit)||findNode(entry)==null)throw new IllegalStateException("Current multihop selection is incomplete or references a missing entry.");if(external){if(!exit.equals(nodeId)||!p.getString(MULTI_MODE,"").equals(custom.protocol))throw new IllegalStateException("Choose this exact external exit before saving.");}else if(findNode(exit)==null)throw new IllegalStateException("Current multihop exit is missing.");requireEntryMode(findNode(entry),entryMode);}
        else{entry="";exit="";multiMode=external?custom.protocol:"shadowsocks";}
        JSONObject row=new JSONObject().put("id",id).put("name",name).put("node_kind",kind).put("node_id",nodeId).put("mode",mode).put("custom_layers",new JSONArray(layers))
                .put("multihop_enabled",multi).put("multihop_entry_id",entry).put("multihop_exit_id",exit).put("multihop_exit_mode",multiMode).put("multihop_execution",execution).put("multihop_entry_mode",entryMode);
        if(policy!=null)row.put("policy",policy.choices).put("node_profile_id",policy.profileId);
        if(multi){NodePolicy entryPolicy=routerPolicy(entry);row.put("entry_policy",entryPolicy.choices).put("entry_profile_id",entryPolicy.profileId);if(!external){NodePolicy exitPolicy=routerPolicy(exit);row.put("exit_policy",exitPolicy.choices).put("exit_profile_id",exitPolicy.profileId);}}
        if(external){AndroidStandardExitStore.validate(custom);validateExternalGraph(custom,multi?findNode(entry):null,entryMode,execution);row.put("external_protocol",custom.protocol).put("external_public_ip",custom.expectedPublicIp).put("external_policy",AndroidConnectionProfilePolicy.external(AndroidTorProfile.isTor(custom.protocol)?custom.torPolicy:custom.policy,custom.protocol)).put("external_startup",AndroidStandardExitStore.startupMetadata(custom));}
        return row;
    }

    static final class ExternalSelection {
        final AndroidNodeStore.Node entry;final AndroidStandardExitStore.Entry exit;final String entryMode,execution;
        ExternalSelection(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,String entryMode,String execution){this.entry=entry;this.exit=exit;this.entryMode=entryMode;this.execution=execution;}
        boolean direct(){return entry==null;}
    }

    /** Select a complete external path without starting a VPN or changing any node secret. */
    synchronized void selectExternalPath(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,String entryMode)throws Exception{selectExternalPath(exit,entry,entryMode,"local");}

    synchronized void selectExternalPath(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,String entryMode,String execution)throws Exception{
        requireIdle("selecting an external path");
        AndroidStandardExitStore.Entry current=exits.get(exit.id);
        if(!AndroidStandardExitStore.snapshot(exit).equals(AndroidStandardExitStore.snapshot(current)))throw new IllegalStateException("The selected external node changed; select its path again.");
        if(entry!=null){AndroidNodeStore.Node currentEntry=findNode(entry.id);if(currentEntry==null||!java.util.Arrays.equals(readLimited(entry.file,AndroidNodeStore.MAX_BUNDLE),readLimited(currentEntry.file,AndroidNodeStore.MAX_BUNDLE)))throw new IllegalStateException("The selected entry changed.");requireEntryMode(currentEntry,entryMode);}
        validateExternalGraph(current,entry,entryMode,execution);
        Map<String,Object> original=snapshotPreferences();
        try{
            requireIdle("selecting an external path");
            if(!prefs().edit().putString(SELECTED_KIND,"external").putString(SELECTED_ID,current.id).putString(MODE_KEY,"external")
                    .putBoolean(MULTI_ON,entry!=null).putString(MULTI_ENTRY,entry==null?"":entry.id).putString(MULTI_EXIT,entry==null?"":current.id)
                    .putString(MULTI_MODE,current.protocol).putString("multihop_execution",execution).putString("multihop_entry_mode",entry==null?"wg":entryMode).commit())throw new IllegalStateException("Could not persist the selected external path.");
        }catch(Exception failure){try{restorePreferences(original);}catch(Exception rollback){IllegalStateException error=new IllegalStateException("External path selection failed and rollback is incomplete.",failure);error.addSuppressed(rollback);throw error;}throw failure;}
    }

    synchronized ExternalSelection currentExternalPath(String id)throws Exception{
        SharedPreferences p=prefs();
        if(!"external".equals(p.getString(SELECTED_KIND,""))||!id.equals(p.getString(SELECTED_ID,"")))throw new IllegalStateException("Select the exact external node first.");
        AndroidStandardExitStore.Entry exit=AndroidStandardExitStore.copy(exits.get(id));AndroidNodeStore.Node entry=null;String mode="wg",execution=normalizeExecution(p.getString("multihop_execution","local"));
        if(p.getBoolean(MULTI_ON,false)){
            String entryID=p.getString(MULTI_ENTRY,"");
            if(!id.equals(p.getString(MULTI_EXIT,""))||!exit.protocol.equals(p.getString(MULTI_MODE,"")))throw new IllegalStateException("Choose this external node's exact path in Edit hops.");
            entry=findNode(entryID);mode=normalizeEntryMode(p.getString("multihop_entry_mode","wg"));requireEntryMode(entry,mode);
        }
        validateExternalGraph(exit,entry,mode,execution);return new ExternalSelection(entry,exit,mode,execution);
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
        for(String key:POLICY_KEYS)if(profile.has(key))policy.put(key,profile.get(key));
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
        if(!profileId.isEmpty())for(String key:POLICY_KEYS)profile.remove(key);
        for(Iterator<String> keys=policy.keys();keys.hasNext();){String key=keys.next();profile.put(key,policy.get(key));}
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

    private static void validateExternalGraph(AndroidStandardExitStore.Entry exit,AndroidNodeStore.Node entry,String mode,String execution)throws Exception{
        AndroidStandardExitStore.validate(exit);AndroidStandardExitStore.validateExecution(exit,entry!=null,execution);
        JSONObject policy=AndroidConnectionProfilePolicy.external(AndroidTorProfile.isTor(exit.protocol)?exit.torPolicy:exit.policy,exit.protocol);
        if(entry!=null)requireEntryMode(entry,mode);
        String dns=policy.optString("dns_mode","");
        if(entry==null&&(dns.isEmpty()||"home".equals(dns)))throw new IllegalArgumentException("Home AdGuard needs a selected Router VPN entry; choose it in Edit hops.");
    }

    private Map<String,Object> snapshotPreferences(){Map<String,?> current=prefs().getAll();Map<String,Object> result=new LinkedHashMap<>();for(String key:SELECTION_KEYS)if(current.containsKey(key)){Object value=current.get(key);if(MULTI_ON.equals(key)?!(value instanceof Boolean):!(value instanceof String))throw new IllegalStateException("Saved selection preferences have an invalid type.");result.put(key,value);}return result;}
    private void restorePreferences(Map<String,Object> original){
        SharedPreferences.Editor edit=prefs().edit();for(String key:SELECTION_KEYS){if(!original.containsKey(key)){edit.remove(key);continue;}Object value=original.get(key);if(value instanceof String)edit.putString(key,(String)value);else if(value instanceof Boolean)edit.putBoolean(key,(Boolean)value);else if(value instanceof Integer)edit.putInt(key,(Integer)value);else if(value instanceof Long)edit.putLong(key,(Long)value);else if(value instanceof Float)edit.putFloat(key,(Float)value);else throw new IllegalStateException("Saved selection preferences have an invalid type.");}
        if(!edit.commit())throw new IllegalStateException("Could not restore previous connection preferences.");
    }
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
            if("router-vpn".equals(kind)&&row.optBoolean("multihop_enabled",false))normalizeMultiMode(row.optString("multihop_exit_mode", "shadowsocks"));
            normalizeExecution(row.optString("multihop_execution","local"));
            normalizeEntryMode(row.optString("multihop_entry_mode","wg"));
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
