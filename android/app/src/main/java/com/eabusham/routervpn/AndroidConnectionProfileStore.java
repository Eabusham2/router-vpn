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
import java.util.Set;

/** App-private connection-choice profiles. Linked node secrets are referenced by ID, never copied. */
final class AndroidConnectionProfileStore {
    static final int SCHEMA_VERSION=1, MAX_PROFILES=64, MAX_STORE=512*1024;
    private static final String FILE_NAME="connection-profiles-v1.json";
    private static final String PREFS="router-vpn-unified", MODE_KEY="mode", CUSTOM_KEY="custom_presets", SELECTED_KIND="selected_kind", SELECTED_ID="selected_id";
    private static final String MULTI_ON="multihop_on", MULTI_ENTRY="multihop_entry", MULTI_EXIT="multihop_exit", MULTI_MODE="multihop_exit_mode";
    private static final SecureRandom RANDOM=new SecureRandom();
    private static final String[] POLICY_KEYS={
            "home_lan_access","kill_switch_policy","ipv6_mode","base_tunnel","base_fallback",
            "auto_require_encrypted","auto_require_obfuscation","mtu_policy","manual_mtu",
            "daita_enabled","jumbo_tun","socks_enabled","dns_mode","dns_protocol","dns_host",
            "dns_port","dns_server_name","dns_path"
    };

    static final class Record {
        final String id,name,nodeKind,nodeId,mode; final List<String> customLayers; final boolean autoRequireEncrypted,autoRequireObfuscation;
        Record(String id,String name,String nodeKind,String nodeId,String mode,List<String>layers,boolean autoRequireEncrypted,boolean autoRequireObfuscation){this.id=id;this.name=name;this.nodeKind=nodeKind;this.nodeId=nodeId;this.mode=mode;this.customLayers=layers;this.autoRequireEncrypted=autoRequireEncrypted;this.autoRequireObfuscation=autoRequireObfuscation;}
        String autoRequirementsSummary(){if("external".equals(nodeKind))return "AUTO n/a";if(autoRequireEncrypted&&autoRequireObfuscation)return "AUTO Encrypted+Obfuscation";if(autoRequireEncrypted)return "AUTO Encrypted";if(autoRequireObfuscation)return "AUTO Obfuscation";return "AUTO Off";}
        @Override public String toString(){return name+" • "+mode+" • "+("external".equals(nodeKind)?"Custom":"Router")+" • "+autoRequirementsSummary();}
    }

    private final Context context; private final AndroidNodeStore nodes; private final AndroidStandardExitStore exits; private final File file;
    AndroidConnectionProfileStore(Context context,AndroidNodeStore nodes,AndroidStandardExitStore exits){this.context=context.getApplicationContext();this.nodes=nodes;this.exits=exits;this.file=new File(this.context.getFilesDir(),FILE_NAME);}

    synchronized List<Record> list() throws Exception { JSONArray rows=readRows();List<Record> out=new ArrayList<>();for(int i=0;i<rows.length();i++)out.add(toRecord(rows.getJSONObject(i)));return out; }
    synchronized Record add(String name) throws Exception { requireIdle("saving a connection profile");JSONArray rows=readRows();if(rows.length()>=MAX_PROFILES)throw new IllegalStateException("Connection profile limit reached.");JSONObject row=snapshot(cleanName(name),newId());rows.put(row);writeRows(rows);return toRecord(row); }
    synchronized Record update(String id,String name) throws Exception { requireIdle("updating a connection profile");if(!safeId(id))throw new IllegalArgumentException("Invalid connection profile id.");JSONArray rows=readRows();boolean found=false;JSONObject replacement=snapshot(cleanName(name),id);JSONArray next=new JSONArray();for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(id.equals(row.optString("id"))){next.put(replacement);found=true;}else next.put(row);}if(!found)throw new IllegalArgumentException("Connection profile was not found.");writeRows(next);return toRecord(replacement); }

    synchronized Record load(String id) throws Exception {
        requireIdle("loading a connection profile");
        JSONObject row=find(id);String kind=row.getString("node_kind"),nodeId=row.getString("node_id");
        String mode=normalizeMode(row.optString("mode","smart-auto"));List<String>layers=jsonStrings(row.optJSONArray("custom_layers"),32);
        boolean multi=row.optBoolean("multihop_enabled",false);String entry=row.optString("multihop_entry_id",""),exit=row.optString("multihop_exit_id","");String multiMode=normalizeMultiMode(row.optString("multihop_exit_mode","shadowsocks"));
        if(multi){
            if(!"router-vpn".equals(kind))throw new IllegalStateException("Android multihop connection profiles must use a Router VPN node, not an external-only selected node.");
            if(entry.isEmpty()||exit.isEmpty()||entry.equals(exit)||findNode(entry)==null||findNode(exit)==null)throw new IllegalStateException("Saved multihop references missing/invalid Router nodes.");
        }else{entry="";exit="";multiMode="shadowsocks";}
        String preparedCustom=prepareCustomPresetJSON(mode,layers);
        byte[] originalBundle=null,updatedBundle=null;
        if("router-vpn".equals(kind)){
            AndroidNodeStore.Node selected=findNode(nodeId);if(selected==null)throw new IllegalStateException("Saved Router node is no longer linked.");
            originalBundle=readLimited(selected.file,AndroidNodeStore.MAX_BUNDLE);
            JSONObject bundle=new JSONObject(new String(originalBundle,StandardCharsets.UTF_8)),profile=selectedProfile(bundle);if(profile==null)throw new IllegalStateException("Saved Router node bundle has no selected profile.");
            JSONObject policy=row.optJSONObject("policy");if(policy!=null)for(String key:POLICY_KEYS){if(policy.has(key))profile.put(key,policy.get(key));}
            updatedBundle=bundle.toString().getBytes(StandardCharsets.UTF_8);
            String updatedId=AndroidNodeStore.deriveId(bundle,updatedBundle);
            if(!nodeId.equals(updatedId))throw new IllegalStateException("This legacy Router node has no stable proof-bound identity, so applying saved policy would change its local node ID. Re-import a current Router VPN bundle before loading this connection profile.");
        }else if("external".equals(kind)){exits.get(nodeId);}else throw new IllegalStateException("Saved connection profile has an unsupported node kind.");

        // All validation above is complete before any selection, node-file, preset or preference mutation.
        if(updatedBundle!=null){AndroidNodeStore.Node applied=nodes.importBundle(updatedBundle);if(!nodeId.equals(applied.id))throw new IllegalStateException("Router node identity changed during connection-profile apply; refusing to continue.");}
        SharedPreferences.Editor edit=prefs().edit().putString(SELECTED_KIND,kind).putString(SELECTED_ID,nodeId).putString(MODE_KEY,mode)
                .putBoolean(MULTI_ON,multi).putString(MULTI_ENTRY,entry).putString(MULTI_EXIT,exit).putString(MULTI_MODE,multiMode);
        if(preparedCustom!=null)edit.putString(CUSTOM_KEY,preparedCustom);
        if(!edit.commit()){
            String rollbackDetail="";
            if(originalBundle!=null){
                try{AndroidNodeStore.Node restored=nodes.importBundle(originalBundle);if(!nodeId.equals(restored.id))throw new IllegalStateException("restored node identity changed");}
                catch(Exception rollbackError){rollbackDetail=" Rollback also failed: "+rollbackError.getMessage();}
            }
            throw new IllegalStateException("Could not persist the loaded connection profile; prior Router node state was restored."+rollbackDetail);
        }
        return toRecord(row);
    }

    synchronized void delete(String id) throws Exception { requireIdle("deleting a connection profile");if(!safeId(id))throw new IllegalArgumentException("Invalid connection profile id.");JSONArray rows=readRows(),next=new JSONArray();boolean found=false;for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(id.equals(row.optString("id")))found=true;else next.put(row);}if(!found)throw new IllegalArgumentException("Connection profile was not found.");writeRows(next); }

    private JSONObject snapshot(String name,String id) throws Exception {
        SharedPreferences p=prefs();String kind=p.getString(SELECTED_KIND,"router-vpn"),nodeId=p.getString(SELECTED_ID,nodes.activeId());if(nodeId==null||nodeId.isEmpty())throw new IllegalStateException("Select a Router or Custom node first.");
        JSONObject policy=null;if("router-vpn".equals(kind)){AndroidNodeStore.Node node=findNode(nodeId);if(node==null)throw new IllegalStateException("Selected Router node is not linked.");JSONObject profile=selectedProfile(readBundle(node.file));if(profile==null)throw new IllegalStateException("Selected Router node has no profile.");policy=new JSONObject();for(String key:POLICY_KEYS)if(profile.has(key))policy.put(key,profile.get(key));}
        else if("external".equals(kind)){exits.get(nodeId);}else throw new IllegalStateException("Selected node kind is unsupported.");
        String mode=normalizeMode(p.getString(MODE_KEY,"smart-auto"));List<String>layers=customLayers(mode);boolean multi=p.getBoolean(MULTI_ON,false);String entry=p.getString(MULTI_ENTRY,""),exit=p.getString(MULTI_EXIT,"");String multiMode=normalizeMultiMode(p.getString(MULTI_MODE,"shadowsocks"));
        if(multi){if(!"router-vpn".equals(kind))throw new IllegalStateException("Disable multihop before saving an external-only connection profile.");if(entry==null||exit==null||entry.isEmpty()||exit.isEmpty()||entry.equals(exit)||findNode(entry)==null||findNode(exit)==null)throw new IllegalStateException("Current multihop selection is incomplete or references missing nodes.");}
        else{entry="";exit="";multiMode="shadowsocks";}
        JSONObject row=new JSONObject().put("id",id).put("name",name).put("node_kind",kind).put("node_id",nodeId).put("mode",mode).put("custom_layers",new JSONArray(layers))
                .put("multihop_enabled",multi).put("multihop_entry_id",entry==null?"":entry).put("multihop_exit_id",exit==null?"":exit).put("multihop_exit_mode",multiMode);if(policy!=null)row.put("policy",policy);return row;
    }

    private void requireIdle(String action){if(AndroidVpnMutationGuard.isBusy(context))throw new IllegalStateException("Disconnect Router VPN or let the active transition finish before "+action+"; live session identity and proof must remain immutable.");}
    private AndroidNodeStore.Node findNode(String id) throws Exception { for(AndroidNodeStore.Node n:nodes.list())if(n.id.equals(id))return n;return null; }
    private SharedPreferences prefs(){return context.getSharedPreferences(PREFS,Context.MODE_PRIVATE);}
    private JSONObject find(String id)throws Exception{if(!safeId(id))throw new IllegalArgumentException("Invalid connection profile id.");JSONArray rows=readRows();for(int i=0;i<rows.length();i++){JSONObject row=rows.getJSONObject(i);if(id.equals(row.optString("id")))return row;}throw new IllegalArgumentException("Connection profile was not found.");}

    private JSONArray readRows() throws Exception {
        if (!file.exists()) return new JSONArray();
        byte[] stored = AndroidPrivateFileStore.read(file, MAX_STORE);
        JSONObject root = new JSONObject(new String(stored, StandardCharsets.UTF_8));
        if (root.optInt("schema_version", 0) != SCHEMA_VERSION) {
            throw new IllegalStateException("Unsupported connection profile store schema.");
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
            normalizeMultiMode(row.optString("multihop_exit_mode", "shadowsocks"));
            JSONObject policy = row.optJSONObject("policy");
            if (policy != null) {
                Iterator<String> keys = policy.keys();
                while (keys.hasNext()) {
                    String key = keys.next();
                    if (!allowedPolicyKey(key)) {
                        throw new IllegalStateException("Connection profile contains non-whitelisted node data: " + key);
                    }
                }
            }
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
    private static String normalizeMultiMode(String value){value=value==null?"":value.trim().toLowerCase(Locale.ROOT);if(value.isEmpty())value="shadowsocks";if(!"shadowsocks".equals(value)&&!"hysteria2".equals(value))throw new IllegalArgumentException("Multihop exit transport must be Shadowsocks or Hysteria2.");return value;}
    private static boolean allowedPolicyKey(String key){for(String allowed:POLICY_KEYS)if(allowed.equals(key))return true;return false;}
    private static String cleanName(String value){value=value==null?"":value.trim();if(value.isEmpty()||value.length()>64)throw new IllegalArgumentException("Connection profile name must be 1–64 characters.");for(int i=0;i<value.length();i++)if(Character.isISOControl(value.charAt(i)))throw new IllegalArgumentException("Connection profile name contains a control character.");return value;}
    private static String normalizeMode(String value){value=value==null?"":value.trim().toLowerCase(Locale.ROOT);if(value.isEmpty())value="smart-auto";if(!value.matches("[a-z0-9._:-]{1,80}"))throw new IllegalArgumentException("Connection profile mode is invalid.");return value;}
    private static List<String> jsonStrings(JSONArray values,int max){List<String>out=new ArrayList<>();Set<String>seen=new HashSet<>();if(values==null)return out;if(values.length()>max)throw new IllegalArgumentException("Too many CUSTOM layers.");for(int i=0;i<values.length();i++){String v=values.optString(i,"").trim().toLowerCase(Locale.ROOT);if(v.isEmpty())continue;if(!v.matches("[a-z0-9._-]{1,64}"))throw new IllegalArgumentException("CUSTOM layer is invalid.");if(seen.add(v))out.add(v);}java.util.Collections.sort(out);return out;}
    private static Record toRecord(JSONObject row){JSONObject policy=row.optJSONObject("policy");boolean encrypted=policy!=null&&policy.optBoolean("auto_require_encrypted",false),obfuscated=policy!=null&&policy.optBoolean("auto_require_obfuscation",false);return new Record(row.optString("id",""),row.optString("name",""),row.optString("node_kind",""),row.optString("node_id",""),row.optString("mode","smart-auto"),jsonStrings(row.optJSONArray("custom_layers"),32),encrypted,obfuscated);}
    private static JSONObject readBundle(File file)throws Exception{return new JSONObject(new String(readLimited(file,AndroidNodeStore.MAX_BUNDLE),StandardCharsets.UTF_8));}
    private static JSONObject selectedProfile(JSONObject bundle){JSONArray a=bundle.optJSONArray("routerProfiles");String id=bundle.optString("selectedRouterID","");if(a==null)return null;for(int i=0;i<a.length();i++){JSONObject p=a.optJSONObject(i);if(p!=null&&id.equals(p.optString("id","")))return p;}return a.length()>0?a.optJSONObject(0):null;}
    private static byte[] readLimited(File f,int max)throws Exception{return AndroidPrivateFileStore.read(f,max);}
    private static boolean safeId(String value){return value!=null&&value.matches("cp-[0-9a-f]{24}");}
    private static String newId(){return "cp-"+randomHex(12);}
    private static String randomHex(int n){byte[]b=new byte[n];RANDOM.nextBytes(b);StringBuilder s=new StringBuilder();for(byte x:b)s.append(String.format(Locale.ROOT,"%02x",x&255));return s.toString();}
}
