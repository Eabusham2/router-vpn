package com.eabusham.routervpn;

import android.content.Context;
import io.nekohasekai.libbox.CommandServer;
import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChain;
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
    final String inventory, inventorySHA, signature, measurement, responseMode;
    private final boolean preparedPurpose;
    private final AndroidNodeCandidateAppendSource appendSource;
    private final io.nekohasekai.libbox.RouterNodeChainExecution selectedPacketOwner;
    private volatile boolean invalidated;
    private volatile boolean savedSourcesInvalidated;
    private final AndroidNodeStore nodes;
    private final AndroidStandardExitStore external;

    static String candidateMeasurement(AndroidNodeChainCapture original,AndroidNodeStore.ChainCapture source,int position) throws Exception {
        if(!original.ownsSource(source)||position<0||position>=source.modes.size()-1)return "";
        String mode=source.modes.get(position);
        if(java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(mode))return "routed-tcp-connect";
        if("local".equals(original.selectionExecution)) {
            if(original.socks!=null)return original.socks.plan.candidatePrefixMeasurement(position);
            if(original.connect!=null)return original.connect.plan.candidatePrefixMeasurement(position);
            if(original.plan!=null)return Libbox.routerNodeChainConnectedCandidatePrefixMeasurement(original.plan,position);
        }
        if(original.plan==null||!AndroidNodeChainCapture.responsePrefix(source.members,source.modes,position,original.selectionExecution))return "";
        return Libbox.routerNodeChainCandidatePrefixMeasurement(original.plan,position);
    }

    static String candidateMeasurement(AndroidNodeChainSession session,int position) throws Exception {
        return candidateMeasurement(session,position,true);
    }
    private static String candidateMeasurement(AndroidNodeChainSession session,int position,boolean connected) throws Exception {
        AndroidNodeStore.ChainCapture source=source(session);
        if(!session.capture.ownsSource(source)||position<0||position>=source.modes.size()-1)return "";
        if(!selectedPacketResponseMode(session,position).isEmpty()
                ||connected&&!connectedResponseMode(session,position).isEmpty())return "routed-candidate-response";
        io.nekohasekai.libbox.RouterNodeChainExecution owner=session.candidateExecutionOwner();
        if(owner!=null&&owner.supportsSelectedFinalResponseCandidate(position))return "routed-candidate-response";
        return candidateMeasurement(session.capture,source,position);
    }
    private static String selectedPacketResponseMode(AndroidNodeChainSession session,int position)throws Exception {
        if(session==null||session.candidatePrefix!=null||position<0||position>=session.source.modes.size()-2)return "";
        var owner=session.candidateExecutionOwner();
        if(owner==null||!session.source.execution.equals(owner.requestedExecution())
                ||!AndroidNodeChainCapture.selectedResponseWinner(session.source.execution,owner.execution()))return "";
        String mode=owner.selectedPacketCandidateMode(position),winner=owner.execution();
        if(!NativeSingBoxController.nativeWireGuardFamily(mode)||!mode.equals(session.source.modes.get(position+1)))return "";
        return "local".equals(winner)&&owner.supportsCompareLocalPacketResponseCandidate(position)
                ||"server".equals(winner)&&owner.supportsServerPacketResponseCandidate(position)?mode:"";
    }
    private static String responseMode(AndroidNodeChainSession session,int position,boolean connected)throws Exception {
        String selected=selectedPacketResponseMode(session,position);
        return !selected.isEmpty()?selected:connected?connectedResponseMode(session,position):"";
    }
    boolean selectedPacketResponse()throws Exception {
        if(selectedPacketOwner==null||executionOwner!=selectedPacketOwner||session==null
                ||preparedPurpose||responseMode.isEmpty()||!"routed-candidate-response".equals(measurement))return false;
        requireCurrent();
        return responseMode.equals(selectedPacketResponseMode(session,prefix));
    }
    private static String connectedResponseMode(AndroidNodeChainSession session,int position) throws Exception {
        if(session==null||session.candidatePrefix!=null||session.execution!=null||session.temporaryMeasurement()||!"local".equals(session.source.execution)
                ||session.capture.plan==null||!session.capture.ownsSource(session.source))return "";
        if(position>=0&&position<session.source.modes.size()-2) {
            String successor=Libbox.routerNodeChainConnectedPacketSuccessorCandidateMode(session.capture.plan,position);
            return NativeSingBoxController.nativeWireGuardFamily(successor)&&successor.equals(session.source.modes.get(position+1))?successor:"";
        }
        String mode=Libbox.routerNodeChainConnectedFinalCandidateResponseMode(session.capture.plan,position);
        int last=session.source.modes.size()-1;
        return position==last-1 && session.source.modes.get(last).equals(mode) ? mode : "";
    }

    static String preparedResponseMode(AndroidNodeChainCapture original,AndroidNodeStore.ChainCapture source,int position) {
        if(original==null||source==null||!"local".equals(source.execution)||!original.ownsSource(source))return "";
        if(original.append!=null)return source.appendDraft()&&position==source.members.size()-1
                &&source.appendMode.equals(original.append.plan.candidateMode())&&source.appendKind.equals(original.append.plan.candidateKind())?source.appendMode:"";
        if(original.plan==null||position<0||position>=source.members.size()-1)return "";
        String mode=Libbox.routerNodeChainPreparedCandidateResponseMode(original.plan,position);
        return source.modes.get(position+1).equals(mode)?mode:"";
    }
    boolean preparedResponse()throws Exception {
        AndroidNodeChainSession retained=session;
        if(!preparedPurpose||responseMode.isEmpty()||retained==null||retained.execution!=null||executionOwner!=null
                ||retained.candidatePrefix==null||retained.candidateCatalog!=this
                ||retained.candidatePrefix.original!=retained.capture||retained.candidatePrefix.prefix!=prefix
                ||!inventory.equals(retained.candidatePrefix.inventory)
                ||!(appendSource==null?"routed-candidate-response":appendSource.measurement).equals(measurement))return false;
        requireCurrent();
        return responseMode.equals(retained.candidatePrefix.responseMode)
                &&responseMode.equals(retained.candidatePrefix.plan.candidateMode())
                &&responseMode.equals(preparedResponseMode(retained.capture,originalSource,prefix));
    }
    boolean preparedAppendResponse()throws Exception {
        return appendSource!=null&&originalSource.appendDraft()&&preparedResponse()
                &&session.capture.append==appendSource&&session.candidatePrefix.plan.isAppend()
                &&session.candidatePrefix.plan.appendPosition()==originalSource.members.size()
                &&appendSource.kind.equals(session.candidatePrefix.plan.candidateKind())
                &&measurement.equals(session.candidatePrefix.plan.candidateMeasurement());
    }
    boolean connectedPacketResponse() throws Exception {
        if(!NativeSingBoxController.nativeWireGuardFamily(responseMode)||session==null||prefix<0||prefix>=originalSource.members.size()-2
                ||!"routed-candidate-response".equals(measurement))return false;
        requireCurrent();
        return responseMode.equals(connectedResponseMode(session,prefix));
    }
    boolean connectedFinalResponse() throws Exception {
        AndroidNodeChainSession retained=session;
        if(retained==null
                ||prefix!=originalSource.members.size()-2||!"routed-candidate-response".equals(measurement))return false;
        requireCurrent();
        if(retained.candidatePrefix!=null)return false;
        if(executionOwner!=null) {
            selectedPrefixID();
            return executionOwner.supportsSelectedFinalResponseCandidate(prefix);
        }
        if(!responseMode.isEmpty())return responseMode.equals(connectedResponseMode(retained,prefix));
        if(retained.execution!=null||!(retained.capture.socks!=null||retained.capture.connect!=null||retained.capture.openVPN
                ||retained.capture.plan!=null&&retained.capture.plan.hasImportedEntry()))return false;
        return "routed-candidate-response".equals(candidateMeasurement(retained.capture,originalSource,prefix));
    }

    AndroidNodeCandidateCatalog(Context context,AndroidNodeChainSession session,int prefix)throws Exception {
        this(context,session,prefix,true);
    }
    AndroidNodeCandidateCatalog(Context context,AndroidNodeChainSession session,int prefix,boolean connected)throws Exception {
        this(context,source(session),prefix,candidateMeasurement(session,prefix,connected),responseMode(session,prefix,connected),session.capture.plan,false,null,session.candidateExecutionOwner());
        bind(session);
    }
    /** Capture the immutable saved inventory before permission or a native
     * server exists. This grants no live candidate or connection authority. */
    static AndroidNodeCandidateCatalog captureSources(Context context,AndroidNodeStore.ChainCapture source,AndroidNodeChainCapture original,int prefix)throws Exception {
        if(source==null||original==null||!original.ownsSource(source)||prefix<0||prefix>=source.modes.size())throw new IllegalStateException("Missing original prefix source");
        String responseMode=preparedResponseMode(original,source,prefix);
        String metric=original.append!=null?original.append.measurement:!responseMode.isEmpty()?"routed-candidate-response":java.util.Arrays.asList("wg","awg2-fast","awg2-strong").contains(source.modes.get(prefix))?"routed-tcp-connect":
                AndroidNodeChainCapture.responsePrefix(source.members,source.modes,prefix,source.execution)
                        ? (source.members.get(source.members.size()-1).imported ? "routed-public-candidate-response" : "routed-candidate-response") : "";
        return new AndroidNodeCandidateCatalog(context,source,prefix,metric,responseMode,original.plan,true,original.append,null);
    }
    private static AndroidNodeStore.ChainCapture source(AndroidNodeChainSession session) {
        if(session==null)throw new IllegalStateException("The original ordered path is missing.");return session.source;
    }
    private AndroidNodeCandidateCatalog(Context context,AndroidNodeStore.ChainCapture source,int prefix,String metric,String responseMode,RouterNodeChain originalPlan,boolean preparedPurpose,AndroidNodeCandidateAppendSource appendSource,io.nekohasekai.libbox.RouterNodeChainExecution selectedPacketOwner)throws Exception {
        originalSource=source;this.prefix=prefix;this.preparedPurpose=preparedPurpose;this.appendSource=appendSource;this.selectedPacketOwner=selectedPacketOwner;
        if(source==null||prefix<0||prefix>=source.members.size())throw new IllegalStateException("The original saved packet prefix is missing.");
        source.requireCurrent();
        measurement=metric;this.responseMode=responseMode;
        if(appendSource!=null) {
            appendSource.requireCurrent();
            if(!preparedPurpose||originalPlan!=null||appendSource.original!=source||!source.appendDraft()
                    ||!"local".equals(source.execution)||prefix!=source.members.size()-1
                    ||!appendSource.measurement.equals(metric)||!source.appendKind.equals(appendSource.kind)||!responseMode.equals(source.appendMode)
                    ||!responseMode.equals(appendSource.plan.candidateMode())
                    ||appendSource.plan.appendPosition()!=source.members.size())throw new IllegalStateException("The append catalog lost its original unfinished prefix.");
        } else if(source.appendDraft())throw new IllegalStateException("An unfinished prefix requires its separate append source.");
        else if(!responseMode.isEmpty()&&selectedPacketOwner!=null) {
            if(preparedPurpose||!"routed-candidate-response".equals(metric)
                    ||!source.execution.equals(selectedPacketOwner.requestedExecution())
                    ||!AndroidNodeChainCapture.selectedResponseWinner(source.execution,selectedPacketOwner.execution())
                    ||prefix>=source.members.size()-2||!responseMode.equals(source.modes.get(prefix+1))
                    ||!responseMode.equals(selectedPacketOwner.selectedPacketCandidateMode(prefix))
                    ||!("local".equals(selectedPacketOwner.execution())&&selectedPacketOwner.supportsCompareLocalPacketResponseCandidate(prefix)
                        ||"server".equals(selectedPacketOwner.execution())&&selectedPacketOwner.supportsServerPacketResponseCandidate(prefix)))
                throw new IllegalStateException("The packet response lost its exact selected execution.");
        }
        else if(!responseMode.isEmpty()) {
            if(!"local".equals(source.execution)||!"routed-candidate-response".equals(metric)||originalPlan==null
                    ||prefix>=source.members.size()-1||!responseMode.equals(source.modes.get(prefix+1)))
                throw new IllegalStateException("The response carrier requires its original successor position.");
            String expected=preparedPurpose?Libbox.routerNodeChainPreparedCandidateResponseMode(originalPlan,prefix):
                    prefix==source.members.size()-2?Libbox.routerNodeChainConnectedFinalCandidateResponseMode(originalPlan,prefix):
                    Libbox.routerNodeChainConnectedPacketSuccessorCandidateMode(originalPlan,prefix);
            if(!responseMode.equals(expected))throw new IllegalStateException("The original candidate measurement purpose changed.");
        }
        boolean publicResponse="routed-public-candidate-response".equals(metric);
        if(publicResponse && appendSource==null && (!java.util.List.of("local","server","auto").contains(source.execution) || !source.members.get(source.members.size()-1).imported))throw new IllegalStateException("A public exit response requires the original imported exit.");
        if(!publicResponse&&!"routed-candidate-response".equals(metric)&&!"routed-tcp-connect".equals(metric))throw new IllegalStateException("This prefix has no supported candidate measurement; no score is available.");
        nodes=new AndroidNodeStore(context);external=new AndroidStandardExitStore(context);
        signature=currentSignature();
        Set<String> excluded=new HashSet<>(),proofs=new HashSet<>();
        int lastExcluded = !responseMode.isEmpty() || publicResponse || ("auto".equals(source.execution) || "server".equals(source.execution)) && "routed-candidate-response".equals(measurement) ? source.members.size()-1 : prefix;
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
                input=AndroidNodeChainCapture.memberInput(candidate,measuredMode(candidate),profile);
                boolean supported;
                if(appendSource!=null)supported=appendSource.fits(input);
                else if(!responseMode.isEmpty()&&selectedPacketOwner!=null)
                    supported=selectedPacketOwner.selectedPacketCandidateInputFitsSource(prefix,input);
                else if(!responseMode.isEmpty() && preparedPurpose)
                    supported=Libbox.routerNodeChainPreparedCandidateInputFitsSource(originalPlan,prefix,input);
                else if(!responseMode.isEmpty() && prefix<source.members.size()-2)
                    supported=Libbox.routerNodeChainPacketSuccessorCandidateInputSupported(input,responseMode)
                            &&Libbox.routerNodeChainPacketSuccessorCandidateFitsSource(originalPlan,prefix,input);
                else if(!responseMode.isEmpty())supported=Libbox.routerNodeChainConnectedFinalCandidateFitsSource(originalPlan,prefix,input);
                else if(publicResponse||"routed-candidate-response".equals(measurement))
                    supported=Libbox.routerNodeChainCandidateInputSupportedForMeasurement(input,measurement);
                else supported=Libbox.routerNodeChainCandidateInputSupported(input);
                if(!supported)throw new IllegalStateException("Unsupported original candidate source");
                // The native validator retains the chosen paired response
                // carrier or the original imported TCP candidate source.
                if(!identities.add(id))throw new IllegalStateException("Duplicate candidate identity");
                reason="";
            } catch(Exception unsupported) { input=""; }
            if(!input.isEmpty())inputs.put(input);
            captured.add(new Row(node.id,id,node.name,input,reason));
        }
        JSONObject offeredSource=new JSONObject().put("schema",1).put("revision",signature).put("inputs",inputs);
        if(!responseMode.isEmpty())offeredSource.put("response_mode",responseMode);
        String offered=offeredSource.toString();
        if(offered.getBytes(StandardCharsets.UTF_8).length>40*1024*1024)
            throw new IllegalStateException("The complete saved candidate sources exceed the native source budget.");
        if(publicResponse&&appendSource==null) {
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
            if(inputs.length()==0)throw new IllegalStateException(publicResponse?"No independent literal imported Shadowsocks 2022 candidate has a captured public exit address.":"No saved candidate supports this prefix measurement. A private response requires a paired "+(responseMode.isEmpty()?"Shadowsocks 2022":AndroidOrderedPathSelection.finalModeTitle(responseMode))+" candidate with Start Layer off.");
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
    String measuredMode(AndroidNodeStore.ChainSource source)throws Exception {
        if(responseMode.isEmpty())return candidateMode(source);
        if(appendSource!=null){AndroidNodeCandidateAppendSource.requireCandidate(source,appendSource.kind,responseMode);return responseMode;}
        if(source.imported)throw new IllegalStateException("This response requires an original paired candidate.");
        return responseMode;
    }
    synchronized void bind(AndroidNodeChainSession original)throws Exception {
        if(session!=null||server!=null||original==null||original.source!=originalSource||invalidated)
            throw new IllegalStateException("The original captured catalog cannot bind another native session.");
        requireSourcesCurrent();
        CommandServer retained=original.candidateServer();
        // Retain even a binding that subsequently fails validation: a later
        // caller cannot adopt a replacement server with these captured inputs.
        session=original;server=retained;executionOwner=original.candidateExecutionOwner();
        if(executionOwner!=selectedPacketOwner)throw new IllegalStateException("The captured selected execution owner changed before binding.");
        if(executionOwner!=null)selectedPrefixID();
        requireCurrent();
    }
    String selectedPrefixID() throws Exception {
        if (session == null || executionOwner == null || session.source != originalSource
                || session.candidateExecutionOwner() != executionOwner || session.candidateServer() != server
                || !(session.capture.ownsSelectedCandidatePrefix(originalSource, prefix)
                    || "routed-candidate-response".equals(measurement) && (executionOwner.supportsSelectedFinalResponseCandidate(prefix)
                        ||!responseMode.isEmpty()&&responseMode.equals(selectedPacketResponseMode(session,prefix)))))
            throw new IllegalStateException("This selected route has no retained candidate prefix at the requested position.");
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
        try{originalSource.requireCurrent();if(appendSource!=null)appendSource.requireCurrent();}
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
