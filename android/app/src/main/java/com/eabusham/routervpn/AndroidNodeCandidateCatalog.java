package com.eabusham.routervpn;

import android.content.Context;
import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChainCandidateCatalog;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

/** Private original sources plus a live publication guard. No caller supplies
 * a network address, proxy port, synthetic paired identity or native tag. */
final class AndroidNodeCandidateCatalog implements RouterNodeChainCandidateCatalog {
    static final class Row {
        final String localID, id, name, input, reason;
        Row(String localID,String id,String name,String input,String reason){this.localID=localID;this.id=id;this.name=name;this.input=input;this.reason=reason;}
    }
    volatile AndroidNodeChainSession session;
    volatile CommandServer server;
    final AndroidNodeStore.ChainCapture originalSource;
    final int prefix;
    final List<Row> rows;
    final String inventory, inventorySHA, signature;
    private volatile boolean invalidated;
    private volatile boolean savedSourcesInvalidated;
    private final AndroidNodeStore nodes;
    private final AndroidStandardExitStore external;

    AndroidNodeCandidateCatalog(Context context,AndroidNodeChainSession session,int prefix)throws Exception {
        this(context,source(session),prefix);
        bind(session);
    }
    /** Capture the immutable saved inventory before permission or a native
     * server exists. This grants no live candidate or connection authority. */
    static AndroidNodeCandidateCatalog captureSources(Context context,AndroidNodeStore.ChainCapture source,int prefix)throws Exception {
        return new AndroidNodeCandidateCatalog(context,source,prefix);
    }
    private static AndroidNodeStore.ChainCapture source(AndroidNodeChainSession session) {
        if(session==null)throw new IllegalStateException("The original ordered path is missing.");return session.source;
    }
    private AndroidNodeCandidateCatalog(Context context,AndroidNodeStore.ChainCapture source,int prefix)throws Exception {
        originalSource=source;this.prefix=prefix;
        if(source==null||prefix<0||prefix>=source.members.size())throw new IllegalStateException("The original saved packet prefix is missing.");
        source.requireCurrent();
        String mode=source.modes.get(prefix);
        if(!("wg".equals(mode)||"awg2-fast".equals(mode)||"awg2-strong".equals(mode)))throw new IllegalStateException("This prefix cannot time destination TCP connections; no score is available.");
        nodes=new AndroidNodeStore(context);external=new AndroidStandardExitStore(context);
        signature=currentSignature();
        Set<String> excluded=new HashSet<>(),proofs=new HashSet<>();
        for(int i=0;i<=prefix;i++){AndroidNodeStore.ChainSource member=source.members.get(i);excluded.add(member.id);if(!member.proofId.isEmpty())proofs.add(member.proofId);}
        List<Row> captured=new ArrayList<>();List<AndroidNodeStore.Node> available=new ArrayList<>(nodes.list());
        for(AndroidStandardExitStore.Entry entry:external.list())available.add(new AndroidNodeStore.Node(entry.id,entry.name,entry.server,null));
        available.sort(Comparator.comparing(value->value.id));Set<String> identities=new HashSet<>();JSONArray inputs=new JSONArray();
        for(AndroidNodeStore.Node node:available){
            if(excluded.contains(node.id))continue;
            String id=node.id,input="",reason="Unsupported saved transport or Start Layer; no TCP score";
            try {
                AndroidNodeStore.ChainSource candidate=nodes.candidateSource(node.id);id=candidate.profileId;
                if(!candidate.proofId.isEmpty()&&proofs.contains(candidate.proofId))continue;
                JSONObject profile=candidate.profile();
                String layer=profile.optString("start_layer","off");
                if(!layer.isEmpty()&&!"off".equals(layer))throw new IllegalStateException("Layered candidate is unsupported");
                input=AndroidNodeChainCapture.memberInput(candidate,"shadowsocks",profile);
                if(!Libbox.routerNodeChainCandidateInputSupported(input))throw new IllegalStateException("Unsupported original candidate source");
                // The shared constructor is authoritative for literal transport,
                // canonical single PSK and exact three-method admission.
                if(!identities.add(id))throw new IllegalStateException("Duplicate candidate identity");
                reason="";
            } catch(Exception unsupported) { input=""; }
            if(!input.isEmpty())inputs.put(input);
            captured.add(new Row(node.id,id,node.name,input,reason));
        }
        if(inputs.length()==0||inputs.length()>64)throw new IllegalStateException("No bounded eligible literal Shadowsocks 2022 candidate inventory is available.");
        rows=java.util.Collections.unmodifiableList(captured);
        inventory=new JSONObject().put("schema",1).put("revision",signature).put("inputs",inputs).toString();
        inventorySHA=digest(inventory);
        requireSourcesCurrent();
    }
    synchronized void bind(AndroidNodeChainSession original)throws Exception {
        if(session!=null||server!=null||original==null||original.source!=originalSource||invalidated)
            throw new IllegalStateException("The original captured catalog cannot bind another native session.");
        requireSourcesCurrent();
        CommandServer retained=original.candidateServer();
        // Retain even a binding that subsequently fails validation: a later
        // caller cannot adopt a replacement server with these captured inputs.
        session=original;server=retained;requireCurrent();
    }
    void requireSourcesCurrent()throws Exception {
        requireOriginalSourceCurrent();requireSavedSourcesCurrent();requireOriginalSourceCurrent();
        if(invalidated)throw new IllegalStateException("The original candidate catalog authority was retired.");
    }
    private void requireOriginalSourceCurrent()throws Exception {
        try{originalSource.requireCurrent();}
        catch(Exception changed){savedSourcesInvalidated=true;throw changed;}
    }
    private String currentSignature()throws Exception {
        try {
        long generation=AndroidNodeStore.publicationGeneration(), imported=AndroidStandardExitStore.publicationGeneration();
        String importedIdentity=importedFileIdentity();
        List<String> original=new ArrayList<>();
        for(AndroidNodeStore.Node node:nodes.list()){
            if(node.file==null)throw new IllegalStateException("Candidate source file changed");
            android.system.StructStat before=android.system.Os.lstat(node.file.getAbsolutePath());
            byte[] bytes=AndroidPrivateFileStore.read(node.file,AndroidNodeStore.MAX_BUNDLE);
            android.system.StructStat after=android.system.Os.lstat(node.file.getAbsolutePath());
            if(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino)throw new IllegalStateException("Candidate file was replaced during capture");
            original.add("router:"+node.id+":"+before.st_dev+":"+before.st_ino+":"+AndroidTorProfile.digest(bytes));
        }
        for(AndroidStandardExitStore.Entry entry:external.list())original.add("external:"+entry.id+":"+digest(AndroidStandardExitStore.snapshot(entry)));
        java.util.Collections.sort(original);
        if(generation!=AndroidNodeStore.publicationGeneration()||imported!=AndroidStandardExitStore.publicationGeneration()||!importedIdentity.equals(importedFileIdentity()))throw new IllegalStateException("Candidate publication changed");
        String current=digest(generation+":"+imported+":"+importedIdentity+":"+new JSONArray(original));
        if(signature!=null&&!signature.equals(current))savedSourcesInvalidated=true;
        return current;
        } catch(Exception changed){if(signature!=null)savedSourcesInvalidated=true;throw changed;}
    }
    // Imported rows share one private container. Preserve that exact file as
    // well as the store generation and each complete row: an out-of-store
    // same-byte replacement must not revive a captured measurement or Save.
    private String importedFileIdentity()throws Exception {
        java.io.File file=external.candidateSourceFile();
        android.system.StructStat before;
        try {before=android.system.Os.lstat(file.getAbsolutePath());}
        catch(android.system.ErrnoException missing){if(missing.errno==android.system.OsConstants.ENOENT)return "absent";throw missing;}
        byte[] bytes=AndroidPrivateFileStore.read(file,AndroidStandardExitStore.MAX_STORE);
        android.system.StructStat after=android.system.Os.lstat(file.getAbsolutePath());
        if(before.st_dev!=after.st_dev||before.st_ino!=after.st_ino)throw new IllegalStateException("Imported candidate file was replaced during capture");
        return before.st_dev + ":" + before.st_ino + ":" + AndroidTorProfile.digest(bytes);
    }
    @Override public String currentInventorySHA256(){
        try {requireOriginalSourceCurrent();AndroidNodeChainSession original=session;CommandServer nativeServer=server;if(invalidated||original==null||nativeServer==null||original.candidateServer()!=nativeServer||!signature.equals(currentSignature())){invalidated=true;return "";}requireOriginalSourceCurrent();original.requireCurrent();if(original!=session||nativeServer!=server||invalidated||savedSourcesInvalidated){invalidated=true;return "";}return inventorySHA;}
        catch(Exception changed){invalidated=true;return "";}
    }
    AndroidNodeStore.ChainSource source(String localID)throws Exception { requireCurrent();AndroidNodeStore.ChainSource source=nodes.candidateSource(localID);requireCurrent();return source; }
    void requireCurrent(){if(!inventorySHA.equals(currentInventorySHA256()))throw new IllegalStateException("The original prefix, network or saved candidate catalog changed.");}
    void requireSavedSourcesCurrent()throws Exception {
        if(savedSourcesInvalidated)throw new IllegalStateException("The observed original candidate source change cannot be undone by restoring bytes.");
        String observed=currentSignature();
        if(savedSourcesInvalidated||!signature.equals(observed))throw new IllegalStateException("The original saved candidate catalog changed; retest before saving.");
    }
    static String digest(String raw)throws Exception{return AndroidTorProfile.digest(raw.getBytes(StandardCharsets.UTF_8));}
}
