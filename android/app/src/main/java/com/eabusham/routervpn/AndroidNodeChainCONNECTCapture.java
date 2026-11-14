package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import io.nekohasekai.libbox.RouterNodeChainCONNECT;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

/** A distinct schema-four native owner. Its private source never passes
 * through the ordinary NodeChain launch parser or a generic native cast. */
final class AndroidNodeChainCONNECTCapture implements AutoCloseable {
    final RouterNodeChainCONNECT plan;
    final String source,config,sourceSHA256,configSHA256;
    static AndroidNodeChainCONNECTCapture compile(String source,List<String> members,List<String> identities)throws Exception {
        RouterNodeChainCONNECT plan=Libbox.newRouterNodeChainCONNECT(source);
        if(plan==null)throw new IllegalStateException("The typed CONNECT compiler returned no original owner.");
        try{return new AndroidNodeChainCONNECTCapture(plan,members,identities);}
        catch(Exception failure){try{plan.close();}catch(Exception cleanup){failure.addSuppressed(cleanup);}throw failure;}
    }
    private AndroidNodeChainCONNECTCapture(RouterNodeChainCONNECT plan,List<String> members,List<String> identities)throws Exception {
        this.plan=plan;source=bounded(plan.source(),AndroidNodeChainCapture.MAX_INPUT);config=bounded(plan.config(),4*1024*1024);
        sourceSHA256=plan.sourceSHA256();configSHA256=plan.configSHA256();
        Libbox.routerValidatePrivateNodeJSON(source);
        JSONObject value=new JSONObject(source),metadata=new JSONObject(bounded(plan.metadata(),1024*1024));
        if(value.length()!=4||value.getInt("schema")!=4||!"local".equals(value.getString("execution"))
                ||!same(value.getJSONArray("nodes"),members)||!same(value.getJSONArray("identity_sources"),identities)
                ||members.size()!=3||identities.size()!=3||!identities.get(1).isEmpty()
                ||!"routervpn-node-chain-connect-source".equals(metadata.getString("kind"))||metadata.getInt("schema")!=1
                ||sourceSHA256==null||!sourceSHA256.matches("[0-9a-f]{64}")
                ||!sourceSHA256.equals(metadata.getString("source_sha256"))
                ||!digest(config).equals(configSHA256)||!configSHA256.equals(metadata.getString("config_sha256")))
            throw new IllegalStateException("The typed CONNECT graph changed an original ordered member, identity or config.");
    }
    private static boolean same(JSONArray returned,List<String> original)throws Exception {
        if(returned.length()!=original.size())return false;
        for(int i=0;i<original.size();i++)if(!(returned.get(i) instanceof String)||!original.get(i).equals(returned.getString(i)))return false;
        return true;
    }
    private static String bounded(String text,int limit){
        if(text==null||text.isEmpty()||text.getBytes(StandardCharsets.UTF_8).length>limit)throw new IllegalStateException("The typed private source exceeds its original bound.");
        return text;
    }
    private static String digest(String text)throws Exception {
        StringBuilder result=new StringBuilder();for(byte value:MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8)))result.append(String.format(java.util.Locale.ROOT,"%02x",value&255));return result.toString();
    }
    @Override public void close()throws Exception{plan.close();}
}
