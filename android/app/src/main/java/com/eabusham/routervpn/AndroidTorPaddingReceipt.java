package com.eabusham.routervpn;

import io.nekohasekai.libbox.Libbox;
import org.json.JSONObject;

import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;

/** Validates memory-only native outgoing-cell receipts for one captured Tor
 * source. Receipt reads never create a proof or extend its actual lifetime. */
final class AndroidTorPaddingReceipt {
    private final boolean enabled;
    private final int rate;
    private final String sourceSHA, sessionSHA;
    private boolean failed;
    private Status previous;

    private static final class Status {
        final long generation,cells,bytes,observed,pathChecked,dnsChecked;
        Status(long generation,long cells,long bytes,long observed,long pathChecked,long dnsChecked){
            this.generation=generation;this.cells=cells;this.bytes=bytes;this.observed=observed;this.pathChecked=pathChecked;this.dnsChecked=dnsChecked;
        }
    }

    AndroidTorPaddingReceipt(String config,String profile,String session,String execution)throws Exception{
        JSONObject selected=new JSONObject(profile);
        Object requested=selected.opt("daita_enabled");
        if(requested!=null&&!(requested instanceof Boolean))throw unavailable();
        long savedRate=selected.has("daita_rate_kbps")?integer(selected,"daita_rate_kbps"):0;
        if(savedRate!=0&&(savedRate<32||savedRate>192)||!java.util.Arrays.asList("local","server").contains(execution))throw unavailable();
        enabled="local".equals(execution)&&Boolean.TRUE.equals(requested);
        rate=(int)(enabled&&savedRate==0?192:savedRate);
        sessionSHA=AndroidTorProfile.digest(session.getBytes(StandardCharsets.UTF_8));
        sourceSHA="local".equals(execution)?Libbox.routerTorPaddingSource(config,profile,session):"";
        if(sourceSHA==null||(enabled?!sourceSHA.matches("[0-9a-f]{64}"):!sourceSHA.isEmpty()))throw unavailable();
    }

    synchronized void accept(String text,long now)throws Exception{
        if(failed)throw unavailable();
        try{validate(text,now);}catch(Exception invalid){failed=true;throw unavailable();}
    }

    private void validate(String text,long now)throws Exception{
        if(text==null||now<=0)throw unavailable();
        if(!enabled){if(!text.isEmpty())throw unavailable();return;}
        if(text.isEmpty()||text.getBytes(StandardCharsets.UTF_8).length>4096)throw unavailable();
        JSONObject status=new JSONObject(text),receipt=status.getJSONObject("receipt");
        if(status.length()!=3||receipt.length()!=10
                ||!"outgoing".equals(receipt.get("direction"))||!"tor-link-cell".equals(receipt.get("accounting"))
                ||!sessionSHA.equals(receipt.get("session_sha256"))||!sourceSHA.equals(receipt.get("source_sha256"))
                ||integer(receipt,"rate_kbps")!=rate)throw unavailable();
        long generation=integer(receipt,"generation"),cells=integer(receipt,"channel_cells"),bytes=integer(receipt,"channel_cell_bytes");
        long observed=integer(receipt,"observed_at"),expires=integer(receipt,"expires_at");
        long path=integer(status,"path_checked_at"),dns=integer(status,"dns_checked_at");
        if(generation<=0||cells<=0||cells>Long.MAX_VALUE/514||bytes<cells*512||bytes>cells*514||(bytes&1)!=0
                ||observed<=0||observed>now||now-observed>5000||expires<=now||expires-observed>10000
                ||dns<=0||dns>path||path>now||expires>Math.addExact(dns,30000))throw unavailable();
        if(previous!=null&&(generation!=previous.generation||cells<previous.cells||bytes<previous.bytes||observed<previous.observed
                ||path<previous.pathChecked||dns<previous.dnsChecked))throw unavailable();
        previous=new Status(generation,cells,bytes,observed,path,dns);
    }

    private static long integer(JSONObject object,String key)throws Exception{
        Object value=object.get(key);
        if(!(value instanceof Number)||value instanceof Float||value instanceof Double)throw unavailable();
        return new BigDecimal(value.toString()).longValueExact();
    }

    private static IllegalStateException unavailable(){return new IllegalStateException("The captured Tor padding source, native cell receipt or fresh path and DNS proof is unavailable.");}
}
