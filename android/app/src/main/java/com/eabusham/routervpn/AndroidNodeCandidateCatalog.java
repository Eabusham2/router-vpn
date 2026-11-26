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
    volatile io.nekohasekai.libbox.RouterNodeChainExecution executionOwner;
    final AndroidNodeStore.ChainCapture originalSource;
    final int prefix;
    final List<Row> rows;
    final String inventory, inventorySHA, signature, measurement;
    private volatile boolean invalidated;
    private volatile boolean savedSourcesInvalidated;
    private final AndroidNodeStore nodes;
    private final AndroidStandardExitStore external;

    static String candidateMeasurement(AndroidNodeChainCapture original,AndroidNodeStore.ChainCapture source,int position) throws Exception {
        if(!original.ownsSource(source)||position<0||position>=source.modes.size())return "";
        String mode=source.modes.get(position);
        if(java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(mode))return "routed-tcp-connect";
        if("local".equals(original.selectionExecution)) {
            if(original.socks!=null)return original.socks.plan.candidatePrefixMeasurement(position);
            if(original.connect!=null)return original.connect.plan.candidatePrefixMeasurement(position);
        }
        if(original.plan==null||!AndroidNodeChainCapture.responsePrefix(source.members,source.modes,position,original.selectionExecution))return "";
        return Libbox.routerNodeChainCandidatePrefixMeasurement(original.plan,position);
    }

    boolean connectedTypedResponse() throws Exception {
        AndroidNodeChainSession retained=session;
        if(retained==null||retained.candidatePrefix!=null||retained.execution!=null||executionOwner!=null
                ||!(retained.capture.socks!=null||retained.capture.connect!=null)
                ||prefix!=originalSource.members.size()-2||!"routed-candidate-response".equals(measurement))return false;
        requireCurrent();
        return "routed-candidate-response".equals(candidateMeasurement(retained.capture,originalSource,prefix));
    }

    AndroidNodeCandidateCatalog(Context context,AndroidNodeChainSession session,int prefix)throws Exception {
        this(context,source(session),prefix,candidateMeasurement(session.capture,source(session),prefix));
        bind(session);
    }
    /** Capture the immutable saved inventory before permission or a native
     * server exists. This grants no live candidate or connection authority. */
    static AndroidNodeCandidateCatalog captureSources(Context context,AndroidNodeStore.ChainCapture source,int prefix)throws Exception {
        if(source==null||prefix<0||prefix>=source.modes.size())throw new IllegalStateException("Missing original prefix source");
        String metric=java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(source.modes.get(prefix))?"routed-tcp-connect":
                AndroidNodeChainCapture.responsePrefix(source.members,source.modes,prefix,source.execution)
                        ? (source.members.get(source.members.size()-1).imported ? "routed-public-candidate-response" : "routed-candidate-response") : "";
        return new AndroidNodeCandidateCatalog(context,source,prefix,metric);
    }
    private static AndroidNodeStore.ChainCapture source(AndroidNodeChainSession session) {
        if(session==null)throw new IllegalStateException("The original ordered path is missing.");return session.source;
    }
    private AndroidNodeCandidateCatalog(Context context,AndroidNodeStore.ChainCapture source,int prefix,String metric)throws Exception {
        originalSource=source;this.prefix=prefix;
        if(source==null||prefix<0||prefix>=source.members.size())throw new IllegalStateException("The original saved packet prefix is missing.");
        source.requireCurrent();
        measurement=metric;
        boolean publicResponse="routed-public-candidate-response".equals(metric);
        if(publicResponse && (!java.util.List.of("local","server","auto").contains(source.execution) || !source.members.get(source.members.size()-1).imported))throw new IllegalStateException("A public exit response requires the original imported exit.");
        if(!publicResponse&&!"routed-candidate-response".equals(metric)&&!"routed-tcp-connect".equals(metric))throw new IllegalStateException("This prefix has no supported candidate measurement; no score is available.");
        nodes=new AndroidNodeStore(context);external=new AndroidStandardExitStore(context);
        signature=currentSignature();
        Set<String> excluded=new HashSet<>(),proofs=new HashSet<>();
        int lastExcluded = publicResponse || ("auto".equals(source.execution) || "server".equals(source.execution)) && "routed-candidate-response".equals(measurement) ? source.members.size()-1 : prefix;
        for(int i=0;i<=lastExcluded;i++){AndroidNodeStore.ChainSource member=source.members.get(i);excluded.add(member.id);excluded.add(member.profileId);if(!member.proofId.isEmpty())proofs.add(member.proofId);}
        List<Row> captured=new ArrayList<>();List<AndroidNodeStore.Node> available=new ArrayList<>(nodes.list());
        java.util.Map<String,AndroidStandardExitStore.Entry> imported=new java.util.HashMap<>();
        for(AndroidStandardExitStore.Entry entry:external.list()){
            imported.put(entry.id,entry);
            available.add(new AndroidNodeStore.Node(entry.id,entry.name,entry.server,null));
        }
        available.sort(Comparator.comparing(value->value.id));Set<String> identities=new HashSet<>();JSONArray inputs=new JSONArray();
        for(AndroidNodeStore.Node node:available){
            if(excluded.contains(node.id))continue;
            String id=node.id,input="",reason="Unsupported saved transport or Start Layer; no candidate score";
            try {
                AndroidNodeStore.ChainSource candidate=nodes.candidateSource(node.id,node.file==null?imported.get(node.id):null);id=candidate.profileId;
                if(excluded.contains(candidate.profileId)||!candidate.proofId.isEmpty()&&proofs.contains(candidate.proofId))continue;
                JSONObject profile=candidate.profile();
                Object rawLayer=profile.opt("start_layer");
                if(rawLayer!=null&&!(rawLayer instanceof String))throw new IllegalStateException("Candidate Start Layer must be an exact string");
                String layer=rawLayer==null?"off":(String)rawLayer;
                if(!java.util.Arrays.asList("","off","aes-256-gcm","aes-256-gcm+xor-whitening").contains(layer)
                        ||candidate.imported&&!layer.isEmpty()&&!"off".equals(layer))throw new IllegalStateException("Candidate Start Layer has no captured TCP owner");
                if(publicResponse) {
                    if(!candidate.imported)throw new IllegalStateException("Choose a saved literal imported Shadowsocks 2022 node.");
                    AndroidNodeChainCapture.requireLiteralImportedSS(candidate);
                }
                input=AndroidNodeChainCapture.memberInput(candidate,candidateMode(candidate),profile);
                if(!(publicResponse||"routed-candidate-response".equals(measurement)?Libbox.routerNodeChainCandidateInputSupportedForMeasurement(input,measurement):Libbox.routerNodeChainCandidateInputSupported(input)))throw new IllegalStateException("Unsupported original candidate source");
                // The shared constructor admits the exact paired SS stream closure,
                // or original imported SS2022, SOCKS5 or
                // HTTP(S) CONNECT source, or single original TCP OpenVPN remote.
                if(!identities.add(id))throw new IllegalStateException("Duplicate candidate identity");
                reason="";
            } catch(Exception unsupported) { input=""; }
            if(!input.isEmpty())inputs.put(input);
            captured.add(new Row(node.id,id,node.name,input,reason));
        }
        String offered=new JSONObject().put("schema",1).put("revision",signature).put("inputs",inputs).toString();
        if(offered.getBytes(StandardCharsets.UTF_8).length>40*1024*1024)
            throw new IllegalStateException("The complete saved candidate sources exceed the native source budget.");
        if(publicResponse) {
            inventory=Libbox.routerNodeChainFilterPublicCandidateInventory(AndroidNodeChainCapture.candidateSourceInput(source,prefix),prefix,offered);
            JSONObject verified=new JSONObject(inventory);
            if(verified.getInt("schema")!=1||!signature.equals(verified.getString("revision")))throw new IllegalStateException("The imported candidate catalog changed during verification.");
            JSONArray eligible=verified.getJSONArray("inputs");
            if(eligible.length()==0)throw new IllegalStateException("No independent literal imported Shadowsocks 2022 candidate has a captured public exit address.");
            int index=0;
            for(int i=0;i<captured.size();i++) {
                Row row=captured.get(i);
                if(row.input.isEmpty())continue;
                if(index<eligible.length()&&row.input.equals(eligible.getString(index))){index++;continue;}
                captured.set(i,new Row(row.localID,row.id,row.name,"","The imported candidate shares its identity, endpoint or cipher key with another node."));
            }
            if(index!=eligible.length())throw new IllegalStateException("The verified catalog replaced an original imported candidate.");
        }else {
            if(inputs.length()==0)throw new IllegalStateException("No saved candidate supports this prefix measurement. A private response requires a paired Shadowsocks2022 candidate with Start Layer off.");
            inventory=offered;
        }
        rows=java.util.Collections.unmodifiableList(captured);
        inventorySHA=digest(inventory);
        requireSourcesCurrent();
    }
    static String candidateMode(AndroidNodeStore.ChainSource source)throws Exception {
        if(!source.imported)return "shadowsocks";
        String mode=AndroidExternalPolicy.protocol(source.external().protocol);
        if(!java.util.Arrays.asList("shadowsocks","socks5","http-connect","https-connect","openvpn").contains(mode))
            throw new IllegalStateException("This saved transport has no supported candidate score.");
        return mode;
    }
    synchronized void bind(AndroidNodeChainSession original)throws Exception {
        if(session!=null||server!=null||original==null||original.source!=originalSource||invalidated)
            throw new IllegalStateException("The original captured catalog cannot bind another native session.");
        requireSourcesCurrent();
        CommandServer retained=original.candidateServer();
        // Retain even a binding that subsequently fails validation: a later
        // caller cannot adopt a replacement server with these captured inputs.
        session=original;server=retained;executionOwner=original.candidateExecutionOwner();
        if(executionOwner!=null)selectedPrefixID();
        requireCurrent();
    }
    String selectedPrefixID() throws Exception {
        if (session == null || executionOwner == null || session.source != originalSource
                || session.candidateExecutionOwner() != executionOwner || session.candidateServer() != server
                || !session.capture.ownsSelectedCandidatePrefix(originalSource, prefix))
            throw new IllegalStateException("This selected route has no retained packet stop at the requested position.");
        if (!"routed-tcp-connect".equals(measurement) && (!originalSource.execution.equals(executionOwner.requestedExecution())
                || !AndroidNodeChainCapture.selectedResponseWinner(originalSource.execution, executionOwner.execution())))
            throw new IllegalStateException("This response requires the original active Server or Compare selection.");
        return originalSource.members.get(prefix).profileId;
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
        try {requireOriginalSourceCurrent();AndroidNodeChainSession original=session;CommandServer nativeServer=server;if(invalidated||original==null||nativeServer==null||original.candidateServer()!=nativeServer||original.candidateExecutionOwner()!=executionOwner||!signature.equals(currentSignature())){invalidated=true;return "";}requireOriginalSourceCurrent();original.requireCurrent();if(original!=session||nativeServer!=server||invalidated||savedSourcesInvalidated){invalidated=true;return "";}return inventorySHA;}
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
