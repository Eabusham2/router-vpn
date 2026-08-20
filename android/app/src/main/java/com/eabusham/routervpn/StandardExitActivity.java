package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;

/** Native custom standard-exit management and connection screen. */
public final class StandardExitActivity extends Activity {
    static final String EXTRA_EXIT_ID = "routervpn.standard_exit_id";
    private static final int PREPARE_STANDARD_EXIT = 2101;
    private static final String STATE_PENDING_ENTRY="pending_entry",STATE_PENDING_EXIT="pending_exit",STATE_PENDING_DIRECT="pending_direct",STATE_REQUESTED_HANDLED="requested_handled";
    private AndroidNodeStore nodeStore;
    private AndroidStandardExitStore exitStore;
    private NativeSingBoxController singBox;
    private AndroidStandardExitRuntime runtime;
    private TextView statusView, listView;
    private AndroidNodeStore.Node pendingEntry;
    private AndroidStandardExitStore.Entry pendingExit;
    private boolean pendingDirect;
    private boolean busy;
    private boolean requestedExitHandled;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        nodeStore = new AndroidNodeStore(this);
        exitStore = new AndroidStandardExitStore(this);
        AndroidRuntimeRegistry engines=AndroidRuntimeRegistry.get(this);
        singBox = engines.singBox;
        runtime = engines.standardExit;
        restorePending(state);
        setContentView(buildUi());
        refresh();
    }

    @Override protected void onResume() { super.onResume(); refresh(); openRequestedExitOnce(); }
    @Override protected void onDestroy() { super.onDestroy(); }
    @Override protected void onSaveInstanceState(Bundle out){
        super.onSaveInstanceState(out);
        if(pendingEntry!=null)out.putString(STATE_PENDING_ENTRY,pendingEntry.id);
        if(pendingExit!=null)out.putString(STATE_PENDING_EXIT,pendingExit.id);
        out.putBoolean(STATE_PENDING_DIRECT,pendingDirect);
        out.putBoolean(STATE_REQUESTED_HANDLED,requestedExitHandled);
    }

    private void restorePending(Bundle state){
        if(state==null)return;
        pendingDirect=state.getBoolean(STATE_PENDING_DIRECT,false);
        requestedExitHandled=state.getBoolean(STATE_REQUESTED_HANDLED,false);
        String entryId=state.getString(STATE_PENDING_ENTRY,""),exitId=state.getString(STATE_PENDING_EXIT,"");
        try{if(!entryId.isEmpty())for(AndroidNodeStore.Node n:nodeStore.list())if(entryId.equals(n.id)){pendingEntry=n;break;}}catch(Exception ignored){}
        try{if(!exitId.isEmpty())pendingExit=exitStore.get(exitId);}catch(Exception ignored){}
    }

    private void openRequestedExitOnce() {
        if (requestedExitHandled) return;
        String id = getIntent() == null ? "" : getIntent().getStringExtra(EXTRA_EXIT_ID);
        if (id == null || id.trim().isEmpty()) return;
        requestedExitHandled = true;
        try { showExitActions(exitStore.get(id.trim())); }
        catch (Exception error) { toast("External node unavailable: " + safe(error)); }
    }

    private View buildUi() {
        int pad = dp(18);
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(pad,pad,pad,pad);
        root.addView(text("Custom Standard Exits",28,true));
        root.addView(text("Save a private non-Router-VPN exit, then either connect to it directly or chain Router VPN WireGuard entry → external exit. Connected is withheld until the exact expected public exit IP is observed.",14,false), margins(0,dp(4),0,dp(12)));
        statusView=text("Disconnected",16,true); root.addView(statusView,margins(0,0,0,dp(10)));
        Button add=button("Add custom exit"); add.setOnClickListener(v->chooseProtocol()); root.addView(add);
        Button manage=button("Manage saved exits"); manage.setOnClickListener(v->showSavedExits(false,false)); root.addView(manage,margins(0,dp(8),0,0));
        Button direct=button("Connect direct external exit"); direct.setOnClickListener(v->showSavedExits(true,true)); root.addView(direct,margins(0,dp(8),0,0));
        Button hopped=button("Connect via Router VPN WireGuard entry → external exit"); hopped.setOnClickListener(v->showSavedExits(true,false)); root.addView(hopped,margins(0,dp(8),0,0));
        Button disconnect=button("Disconnect custom exit"); disconnect.setOnClickListener(v->{runtime.disconnect();busy=false;pendingDirect=false;pendingEntry=null;pendingExit=null;statusView.setText("Disconnected");refresh();}); root.addView(disconnect,margins(0,dp(8),0,0));
        Button vpnSettings=button("Open Android VPN settings / lockdown"); vpnSettings.setOnClickListener(v->startActivity(new Intent(android.provider.Settings.ACTION_VPN_SETTINGS))); root.addView(vpnSettings,margins(0,dp(8),0,0));
        listView=text("",14,false); root.addView(listView,margins(0,dp(16),0,0));
        root.addView(text(capabilityText(),13,false),margins(0,dp(16),0,dp(18)));
        ScrollView scroll=new ScrollView(this);scroll.addView(root);return scroll;
    }

    private void refresh() {
        if (listView == null) return;
        try {
            AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);
            busy="external".equals(home.logicalMode)&&"connecting".equals(home.phase);
            List<AndroidStandardExitStore.Entry> exits=exitStore.list();
            StringBuilder out=new StringBuilder("Saved standard exits: ").append(exits.size()).append('/').append(AndroidStandardExitStore.MAX_EXITS);
            for(AndroidStandardExitStore.Entry e:exits) out.append("\n• ").append(e.name).append(" — ").append(e.protocol).append(" — ").append(e.server).append(':').append(e.serverPort).append(" → expected ").append(e.expectedPublicIp);
            listView.setText(out.toString());
            if("external".equals(home.logicalMode)&&home.connected){String actual=AndroidHomeStateStore.actualExitForCurrentSession(this);statusView.setText("Connected • "+home.activeExternalName+" • "+home.activeExternalProtocol+" • exit "+(actual.isEmpty()?"unproven":actual));}
            else if(busy)statusView.setText("Custom-exit connection is in progress…");
            else {String state=singBox.getState();if("UP".equals(state)&&singBox.getMode().startsWith("standard-"))statusView.setText("Custom-exit VPN engine UP — unified session proof is being reconciled.");else statusView.setText("Disconnected");}
        } catch(Exception e){listView.setText("Custom exit store unavailable: "+safe(e));}
    }

    private String capabilityText() {
        StringBuilder s=new StringBuilder("Supported now:");
        for(AndroidStandardExitStore.Capability c:AndroidStandardExitStore.capabilities()) s.append("\n").append(c.supported?"✓ ":"— ").append(c.protocol).append(c.supported?"":" — "+c.reason);
        s.append("\n\nDirect custom exits require Android Always-on VPN plus ‘Block connections without VPN’; Router VPN refuses to start a direct external graph without that strict system lockdown. Hopped exits use the linked Router VPN WireGuard entry policy. Secrets stay in Android app-private storage and are never shown in this list. Custom exit servers and DNS endpoints currently require literal IPs so setup cannot leak pre-tunnel DNS.");
        return s.toString();
    }

    private void chooseProtocol() {
        String[] protocols={"WireGuard","SOCKS5","Shadowsocks","Hysteria2","OpenVPN — unavailable"};
        new AlertDialog.Builder(this).setTitle("Add custom exit protocol").setItems(protocols,(d,w)->{
            if(w==4){dialog("OpenVPN unavailable",AndroidStandardExitStore.capabilities().get(4).reason);return;}
            showAddForm(new String[]{"wireguard","socks5","shadowsocks","hysteria2"}[w]);
        }).setNegativeButton("Cancel",null).show();
    }

    private void showAddForm(String protocol) {
        LinearLayout form=new LinearLayout(this);form.setOrientation(LinearLayout.VERTICAL);int p=dp(10);form.setPadding(p,p,p,p);
        EditText name=field("Name",false),server=field("Server literal IP",false),port=field("Server port",false),expected=field("Expected public exit IP",false);
        port.setInputType(InputType.TYPE_CLASS_NUMBER);form.addView(name);form.addView(server);form.addView(port);form.addView(expected);
        List<EditText> extra=new ArrayList<>();
        if("socks5".equals(protocol)){extra.add(field("Username (optional)",false));extra.add(field("Password (optional)",true));}
        else if("shadowsocks".equals(protocol)){extra.add(field("Method, e.g. 2022-blake3-aes-256-gcm",false));extra.add(field("Password / PSK",true));}
        else if("hysteria2".equals(protocol)){extra.add(field("Password",true));extra.add(field("TLS server name / SNI",false));}
        else if("wireguard".equals(protocol)){extra.add(field("Interface addresses, comma-separated CIDRs",false));extra.add(field("Private key",true));extra.add(field("Peer public key",false));extra.add(field("Preshared key (optional)",true));extra.add(field("Allowed IPs, comma-separated CIDRs",false));EditText mtu=field("MTU (optional)",false);mtu.setInputType(InputType.TYPE_CLASS_NUMBER);extra.add(mtu);}
        for(EditText e:extra)form.addView(e);
        ScrollView scroll=new ScrollView(this);scroll.addView(form);
        new AlertDialog.Builder(this).setTitle("Add "+protocol+" exit").setView(scroll).setPositiveButton("Save",(d,w)->{
            try{AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.name=name.getText().toString();e.protocol=protocol;e.server=server.getText().toString();e.serverPort=parseInt(port,"Server port");e.expectedPublicIp=expected.getText().toString();int i=0;
                if("socks5".equals(protocol)){e.username=extra.get(i++).getText().toString();e.password=extra.get(i).getText().toString();}
                else if("shadowsocks".equals(protocol)){e.method=extra.get(i++).getText().toString();e.secret=extra.get(i).getText().toString();}
                else if("hysteria2".equals(protocol)){e.secret=extra.get(i++).getText().toString();e.tlsServerName=extra.get(i).getText().toString();}
                else{e.wgAddresses.addAll(csv(extra.get(i++).getText().toString()));e.wgPrivateKey=extra.get(i++).getText().toString();e.wgPeerPublicKey=extra.get(i++).getText().toString();e.wgPreSharedKey=extra.get(i++).getText().toString();e.wgAllowedIps.addAll(csv(extra.get(i++).getText().toString()));String m=extra.get(i).getText().toString().trim();e.wgMtu=m.isEmpty()?0:Integer.parseInt(m);}
                exitStore.save(e);toast("Saved "+e.name);refresh();
            }catch(Exception e){toast("Save failed: "+safe(e));}
        }).setNegativeButton("Cancel",null).show();
    }

    private void showSavedExits(boolean connect, boolean direct) {
        try {
            List<AndroidStandardExitStore.Entry> exits=exitStore.list();
            if(exits.isEmpty()){new AlertDialog.Builder(this).setTitle("No custom exits").setMessage("Add a WireGuard, SOCKS5, Shadowsocks or Hysteria2 exit first.").setPositiveButton("Add",(d,w)->chooseProtocol()).setNegativeButton("Cancel",null).show();return;}
            String[] labels=new String[exits.size()];for(int i=0;i<exits.size();i++){AndroidStandardExitStore.Entry e=exits.get(i);labels[i]=e.name+" — "+e.protocol+"\n"+e.server+":"+e.serverPort+" → "+e.expectedPublicIp;}
            String title=!connect?"Manage custom exits":direct?"Choose direct external exit":"Choose external exit after Router VPN entry";
            new AlertDialog.Builder(this).setTitle(title).setItems(labels,(d,w)->{if(connect){if(direct)requestDirect(exits.get(w));else chooseEntry(exits.get(w));}else showExitActions(exits.get(w));}).setPositiveButton(connect?"Cancel":"Add new",(d,w)->{if(!connect)chooseProtocol();}).setNegativeButton("Close",null).show();
        } catch(Exception e){toast(safe(e));}
    }

    private void showExitActions(AndroidStandardExitStore.Entry e) {
        String[] actions={"Connect direct","Connect through Router VPN entry","Delete"};
        new AlertDialog.Builder(this).setTitle(e.name+" — "+e.protocol).setMessage("Server: "+e.server+":"+e.serverPort+"\nExpected public IP: "+e.expectedPublicIp+"\nCredentials are stored privately and are not displayed.")
                .setItems(actions,(d,w)->{if(w==0)requestDirect(e);else if(w==1)chooseEntry(e);else new AlertDialog.Builder(this).setTitle("Delete "+e.name+"?").setMessage("Only this app-private custom exit will be removed.").setPositiveButton("Delete",(x,y)->{try{exitStore.remove(e.id);refresh();toast("Deleted "+e.name);}catch(Exception err){toast(safe(err));}}).setNegativeButton("Cancel",null).show();}).setNegativeButton("Close",null).show();
    }

    private void requestDirect(AndroidStandardExitStore.Entry exit) {
        if(activeOrTransitioning()){toast("Disconnect the current VPN session before starting another custom exit.");return;}
        pendingEntry=null;pendingExit=exit;pendingDirect=true;
        Intent permission=VpnService.prepare(this);
        if(permission!=null){statusView.setText("Waiting for Android VPN permission…");startActivityForResult(permission,PREPARE_STANDARD_EXIT);}else startPending();
    }

    private void chooseEntry(AndroidStandardExitStore.Entry exit) {
        if(activeOrTransitioning()){toast("Disconnect the current VPN session before starting another custom exit.");return;}
        try{List<AndroidNodeStore.Node> nodes=nodeStore.list();if(nodes.isEmpty()){dialog("Router VPN entry required","Link at least one Router VPN node first; the entry must contain standard WireGuard.");return;}String[]labels=new String[nodes.size()];for(int i=0;i<nodes.size();i++)labels[i]=nodes.get(i).name+(nodes.get(i).endpoint.isEmpty()?"":" — "+nodes.get(i).endpoint);new AlertDialog.Builder(this).setTitle("Choose Router VPN WireGuard entry").setMessage("Path: this device → Router VPN WireGuard entry → "+exit.name+" → Internet").setItems(labels,(d,w)->requestConnect(nodes.get(w),exit)).setNegativeButton("Cancel",null).show();}catch(Exception e){toast(safe(e));}
    }

    private void requestConnect(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit) {
        if(activeOrTransitioning()){toast("Disconnect the current VPN session before starting another custom exit.");return;}
        pendingEntry=entry;pendingExit=exit;pendingDirect=false;Intent permission=VpnService.prepare(this);if(permission!=null){statusView.setText("Waiting for Android VPN permission…");startActivityForResult(permission,PREPARE_STANDARD_EXIT);}else startPending();
    }

    private void startPending() {
        AndroidNodeStore.Node entry=pendingEntry;AndroidStandardExitStore.Entry exit=pendingExit;boolean direct=pendingDirect;
        pendingEntry=null;pendingExit=null;pendingDirect=false;if(exit==null)return;if(!direct&&entry==null)return;
        if(activeOrTransitioning()){toast("VPN state changed while permission was open; disconnect before starting the custom exit.");refresh();return;}
        busy=true;statusView.setText(direct?"Preparing direct external exit…":"Preparing Router VPN entry → external exit…");
        AndroidStandardExitRuntime.Callback cb=new AndroidStandardExitRuntime.Callback(){public void progress(String m){runOnUiThread(()->{if(!isFinishing())statusView.setText(m);});}public void finished(boolean ok,String m){runOnUiThread(()->{busy=false;if(!isFinishing()){statusView.setText(m);if(!ok)toast(m);refresh();}});}};
        if(direct)runtime.connectDirect(exit,cb);else runtime.connect(entry.file,exit,cb);
    }

    private boolean activeOrTransitioning(){AndroidHomeStateStore.Snapshot s=AndroidHomeStateStore.snapshot(this);return s.connected||"connecting".equals(s.phase)||"STARTING".equals(singBox.getState())||"STOPPING".equals(singBox.getState());}

    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(request!=PREPARE_STANDARD_EXIT)return;if(result==RESULT_OK)startPending();else{pendingEntry=null;pendingExit=null;pendingDirect=false;busy=false;statusView.setText("VPN permission denied; custom exit stayed disconnected.");}}

    private EditText field(String hint,boolean secret){EditText e=new EditText(this);e.setHint(hint);e.setSingleLine(true);if(secret)e.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);return e;}
    private static int parseInt(EditText e,String label){String v=e.getText().toString().trim();if(v.isEmpty())throw new IllegalArgumentException(label+" is required.");return Integer.parseInt(v);}
    private static List<String> csv(String text){List<String>r=new ArrayList<>();for(String p:text.split(",")){p=p.trim();if(!p.isEmpty())r.add(p);}return r;}
    private void dialog(String title,String message){new AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton("OK",null).show();}
    private void toast(String m){Toast.makeText(this,m==null?"Router VPN":m,Toast.LENGTH_LONG).show();}
    private static String safe(Throwable e){String m=e==null?"":e.getMessage();return m==null||m.trim().isEmpty()?"Router VPN custom exit error":m.trim();}
    private TextView text(String v,int sp,boolean bold){TextView x=new TextView(this);x.setText(v);x.setTextSize(sp);x.setTextColor(0xff14213d);if(bold)x.setTypeface(x.getTypeface(),android.graphics.Typeface.BOLD);return x;}
    private Button button(String v){Button b=new Button(this);b.setText(v);b.setAllCaps(false);return b;}
    private LinearLayout.LayoutParams margins(int l,int t,int r,int b){LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT);p.setMargins(l,t,r,b);return p;}
    private int dp(int v){return Math.round(v*getResources().getDisplayMetrics().density);}
}
