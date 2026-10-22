package com.eabusham.routervpn;

import org.json.JSONObject;

/** In-memory next-connection edit bound to one exact saved source and receipt. */
final class AndroidDNSSelectionDraft {
    static final class Path {
        final String entryID,entryMode;
        private final AndroidNodeStore nodes;
        private final java.io.File entryFile;
        private final String digest;
        private Path(AndroidNodeStore nodes,String entryID,String entryMode,java.io.File file,String digest){this.nodes=nodes;this.entryID=entryID;this.entryMode=entryMode;this.entryFile=file;this.digest=digest;}
        static Path direct(){return new Path(null,"","",null,"");}
        static Path capture(AndroidNodeStore nodes,AndroidHomeStateStore.Snapshot home)throws Exception{
            if(home==null||home.activeEntryId==null||home.activeEntryMode==null)throw changed();
            if(home.activeEntryId.isEmpty()){if(!home.activeEntryMode.isEmpty())throw changed();return direct();}
            if(!NativeSingBoxController.nativeMultihopEntry(home.activeEntryMode))throw changed();
            java.io.File file=nodes.file(home.activeEntryId).getCanonicalFile();byte[] bytes=AndroidPrivateFileStore.read(file,AndroidNodeStore.MAX_BUNDLE);
            JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(bytes));AndroidNodeStore.validateBundle(bundle);
            if(bundle.getJSONObject("profiles").optJSONObject(home.activeEntryMode)==null)throw changed();
            Path path=new Path(nodes,home.activeEntryId,home.activeEntryMode,file,AndroidTorProfile.digest(bytes));path.requireCurrent();return path;
        }
        void requireActive(AndroidHomeStateStore.Snapshot home)throws Exception{
            if(home==null||!entryID.equals(home.activeEntryId)||!entryMode.equals(home.activeEntryMode))throw changed();
            requireCurrent();
        }
        void requireCurrent()throws Exception{
            if(entryID.isEmpty()){if(!entryMode.isEmpty()||entryFile!=null||!digest.isEmpty())throw changed();return;}
            java.io.File current=nodes.file(entryID).getCanonicalFile();
            if(!entryFile.equals(current)||!digest.equals(AndroidTorProfile.digest(AndroidPrivateFileStore.read(current,AndroidNodeStore.MAX_BUNDLE))))throw changed();
        }
        private static IllegalStateException changed(){return new IllegalStateException("The measured Router VPN entry or its complete saved path changed. Retest before choosing DNS.");}
    }
    final String nodeID,requestID,sessionID,transport,rowID;
    private final Path path;
    private final String source,row;
    private AndroidDNSSelectionDraft(AndroidStandardExitStore.Entry saved,Path path,JSONObject receipt,String selected)throws Exception{
        this.path=java.util.Objects.requireNonNull(path);path.requireCurrent();
        nodeID=saved.id;requestID=receipt.getString("request_id");sessionID=receipt.getString("session_id");transport=receipt.getString("public_transport");
        AndroidDNSMeasurementReceipt.validate(receipt.toString(),requestID,nodeID,sessionID,transport,true);
        JSONObject choice=AndroidDNSMeasurementReceipt.publicChoice(receipt,selected);
        rowID=choice.getString("id");row=choice.toString();source=AndroidStandardExitStore.snapshot(saved);
    }
    static AndroidDNSSelectionDraft create(AndroidStandardExitStore.Entry saved,Path path,JSONObject currentReceipt,String rowID)throws Exception{
        return new AndroidDNSSelectionDraft(saved,path,currentReceipt,rowID);
    }
    void requireSource(AndroidStandardExitStore.Entry current)throws Exception{
        if(!nodeID.equals(current.id)||!source.equals(AndroidStandardExitStore.snapshot(current)))throw new IllegalStateException("The saved external node changed. Retest before creating another DNS draft.");
        path.requireCurrent();
    }
    void requireReceipt(JSONObject current)throws Exception{
        AndroidDNSMeasurementReceipt.validate(current.toString(),requestID,nodeID,sessionID,transport,true);
        if(!row.equals(AndroidDNSMeasurementReceipt.publicChoice(current,rowID).toString()))throw new IllegalStateException("The measured DNS choice changed.");
    }
    String description()throws Exception{
        JSONObject selected=new JSONObject(row);
        return AndroidDNSMeasurementReceipt.transportName(transport)+" · "+selected.getString("address")+":"+selected.getInt("port")+
                String.format(java.util.Locale.US," · %.1f ms",selected.getDouble("median_ms"));
    }
    AndroidStandardExitStore.Entry apply(AndroidStandardExitStore.Entry current)throws Exception{
        requireSource(current);
        AndroidStandardExitStore.Entry draft=AndroidStandardExitStore.copy(current);JSONObject selected=new JSONObject(row);
        boolean tor=AndroidTorProfile.isTor(draft.protocol);JSONObject policy=new JSONObject((tor?draft.torPolicy:draft.policy).toString());
        for(String key:new String[]{"dns_protocol","dns_host","dns_port","dns_server_name","dns_path","dns_bootstrap"})policy.remove(key);
        String protocol=tor?("tls".equals(transport)?"dot":"https".equals(transport)?"doh":transport):transport;
        policy.put("dns_mode","custom").put("dns_protocol",protocol).put("dns_host",selected.getString("address")).put("dns_port",selected.getInt("port"));
        if(!"tcp".equals(transport))policy.put("dns_server_name",selected.getString("server_name"));
        if("https".equals(transport))policy.put("dns_path",selected.getString("path"));
        if(tor)draft.torPolicy=policy;else draft.policy=policy;
        return draft;
    }
}
