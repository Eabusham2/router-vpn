package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.net.VpnService;
import android.os.Bundle;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.ArrayAdapter;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import java.util.ArrayList;
import java.util.List;
import org.json.JSONArray;
import org.json.JSONObject;
import java.nio.charset.StandardCharsets;

/** Native custom standard-exit management and connection screen. */
public final class StandardExitActivity extends Activity {
    static final String EXTRA_EXIT_ID = "routervpn.standard_exit_id";
    static final String EXTRA_SELECT_PATH = "routervpn.select_external_path";
    private static final int PREPARE_STANDARD_EXIT = 2101;
    private static final String STATE_PENDING_ENTRY="pending_entry",STATE_PENDING_EXIT="pending_exit",STATE_PENDING_DIRECT="pending_direct",STATE_REQUESTED_HANDLED="requested_handled";
    private AndroidNodeStore nodeStore;
    private AndroidStandardExitStore exitStore;
    private NativeSingBoxController singBox;
    private AndroidStandardExitRuntime runtime;
    private TextView statusView, listView;
    private Button addButton, directButton, hoppedButton;
    private AndroidNodeStore.Node pendingEntry;
    private AndroidStandardExitStore.Entry pendingExit;
    private boolean pendingDirect;
    private String pendingEntryMode="wg",pendingExecution="local",pendingEntryDigest="",pendingExitDigest="",pendingRequestDigest="";
    private boolean busy;
    private boolean requestedExitHandled;
    private AndroidDNSMeasurementDialog dnsComparison;
    private volatile boolean destroyed;

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
    @Override protected void onDestroy() { destroyed=true;if(dnsComparison!=null)dnsComparison.close();super.onDestroy(); }
    @Override protected void onSaveInstanceState(Bundle out){
        super.onSaveInstanceState(out);
        if(pendingEntry!=null)out.putString(STATE_PENDING_ENTRY,pendingEntry.id);
        if(pendingExit!=null)out.putString(STATE_PENDING_EXIT,pendingExit.id);
        out.putBoolean(STATE_PENDING_DIRECT,pendingDirect);
        out.putBoolean(STATE_REQUESTED_HANDLED,requestedExitHandled);
        out.putString("pending_entry_mode",pendingEntryMode);
        out.putString("pending_execution",pendingExecution);out.putString("pending_request_digest",pendingRequestDigest);
        out.putString("pending_entry_digest",pendingEntryDigest);
        out.putString("pending_exit_digest",pendingExitDigest);
    }

    private void restorePending(Bundle state){
        if(state==null)return;
        pendingDirect=state.getBoolean(STATE_PENDING_DIRECT,false);
        requestedExitHandled=state.getBoolean(STATE_REQUESTED_HANDLED,false);
        pendingEntryMode=state.getString("pending_entry_mode","wg");
        pendingExecution=state.getString("pending_execution","local");pendingRequestDigest=state.getString("pending_request_digest","");
        pendingEntryDigest=state.getString("pending_entry_digest","");
        pendingExitDigest=state.getString("pending_exit_digest","");
        String entryId=state.getString(STATE_PENDING_ENTRY,""),exitId=state.getString(STATE_PENDING_EXIT,"");
        try{if(!entryId.isEmpty())for(AndroidNodeStore.Node n:nodeStore.list())if(entryId.equals(n.id)){pendingEntry=n;break;}}catch(Exception ignored){}
        try{if(!exitId.isEmpty())pendingExit=exitStore.get(exitId);}catch(Exception ignored){}
    }

    private void openRequestedExitOnce() {
        if (requestedExitHandled) return;
        String id = getIntent() == null ? "" : getIntent().getStringExtra(EXTRA_EXIT_ID);
        if (id == null || id.trim().isEmpty()) return;
        requestedExitHandled = true;
        try {
            AndroidStandardExitStore.Entry exit=exitStore.get(id.trim());
            if(selectionOnly())new AlertDialog.Builder(this).setCustomTitle(choiceHeader("External path","Choose a saved path. Return to the map and press Connect when ready."))
                    .setItems(new String[]{"Direct → "+exit.name,"Router VPN entry → "+exit.name},(d,w)->{if(w==0)requestDirect(exit);else chooseEntry(exit);}).setNegativeButton("Cancel",null).show();
            else showExitActions(exit);
        }
        catch (Exception error) { toast("External node unavailable: " + safe(error)); }
    }

    private boolean selectionOnly(){return getIntent()!=null&&getIntent().getBooleanExtra(EXTRA_SELECT_PATH,false);}

    private void rememberExternalPath(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,String mode)throws Exception{
        new AndroidConnectionProfileStore(this,nodeStore,exitStore).selectExternalPath(exit,entry,mode,pendingExecution);
    }

    private View buildUi() {
        int pad = dp(18);
        LinearLayout root = new LinearLayout(this); root.setOrientation(LinearLayout.VERTICAL); root.setPadding(pad,pad,pad,pad);
        root.addView(text("Custom Standard Exits",28,true));
        root.addView(text("Save a private external exit and connect directly or through a Router VPN entry. Your selected DNS and complete entry path must pass their native proofs before Connected. Tor proves its captured circuit; other custom exits also prove their expected public IP.",14,false), margins(0,dp(4),0,dp(12)));
        statusView=text("Disconnected",16,true); root.addView(statusView,margins(0,0,0,dp(10)));
        addButton=button("Add custom exit"); addButton.setOnClickListener(v->chooseProtocol()); root.addView(addButton);
        Button manage=button("Manage saved exits"); manage.setOnClickListener(v->showSavedExits(false,false)); root.addView(manage,margins(0,dp(8),0,0));
        directButton=button(selectionOnly()?"Select direct external path":"Connect direct external exit"); directButton.setOnClickListener(v->showSavedExits(true,true)); root.addView(directButton,margins(0,dp(8),0,0));
        hoppedButton=button(selectionOnly()?"Select Router VPN entry → external exit":"Connect via Router VPN entry → external exit"); hoppedButton.setOnClickListener(v->showSavedExits(true,false)); root.addView(hoppedButton,margins(0,dp(8),0,0));
        Button compareDNS=button("Compare DNS on connected external path");compareDNS.setOnClickListener(v->showDNSComparison(AndroidHomeStateStore.snapshot(this).activeExternalId));root.addView(compareDNS,margins(0,dp(8),0,0));
        Button disconnect=button("Disconnect custom exit"); disconnect.setOnClickListener(v->{
            clearPending();statusView.setText("Disconnecting; waiting for the captured runtime to stop…");disconnect.setEnabled(false);
            new Thread(()->{String failure="";try{runtime.disconnect();}catch(Exception error){failure="Teardown is not confirmed. Runtime ownership is retained; retry Disconnect.";}String result=failure;
                runOnUiThread(()->{if(isFinishing())return;disconnect.setEnabled(true);busy=false;refresh();if(!result.isEmpty())statusView.setText(result);});},"routervpn-exit-disconnect").start();
        }); root.addView(disconnect,margins(0,dp(8),0,0));
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
            boolean mutationBlocked=activeOrTransitioning();
            if(addButton!=null)addButton.setEnabled(!mutationBlocked);if(directButton!=null)directButton.setEnabled(!mutationBlocked);if(hoppedButton!=null)hoppedButton.setEnabled(!mutationBlocked);
            List<AndroidStandardExitStore.Entry> exits=exitStore.list();
            StringBuilder out=new StringBuilder("Saved standard exits: ").append(exits.size()).append('/').append(AndroidStandardExitStore.MAX_EXITS);
            for(AndroidStandardExitStore.Entry e:exits) out.append("\n• ").append(e.name).append(" — ").append(exitSummary(e));
            listView.setText(out.toString());
            if("external".equals(home.logicalMode)&&home.connected){String actual=AndroidHomeStateStore.actualExitForCurrentSession(this);statusView.setText("Connected • "+home.activeExternalName+" • "+home.activeExternalProtocol+" • exit "+(actual.isEmpty()?"unproven":actual));}
            else if(busy)statusView.setText("Custom-exit connection is in progress…");
            else {String state=singBox.getState();if("UP".equals(state)&&singBox.getMode().startsWith("standard-"))statusView.setText("Custom-exit VPN engine UP — unified session proof is being reconciled.");else if(mutationBlocked)statusView.setText("VPN transition or teardown is pending; runtime ownership is retained.");else statusView.setText("Disconnected");}
        } catch(Exception e){listView.setText("Custom exit store unavailable: "+safe(e));}
    }

    private String capabilityText() {
        StringBuilder s=new StringBuilder("Supported now:");
        for(AndroidStandardExitStore.Capability c:AndroidStandardExitStore.capabilities()) s.append("\n").append(c.supported?"✓ ":"— ").append(c.protocol).append(c.supported?"":" — "+c.reason);
        s.append("\n\nHTTP is HTTP CONNECT. HTTPS uses certificate-verified TLS/SNI. Direct custom exits and every Tor path require Android Always-on VPN plus ‘Block connections without VPN’. Tor uses one embedded VPN runtime with ordinary Tor, obfs4, meek, Snowflake, WebTunnel or a supported custom bridge block. Its exit can change; the native circuit and selected DNS are proved before Connected. Tor carries TCP; UDP and DoH3 DNS are rejected. Other supported native external exits retain their saved DNS, IPv6, LAN and MTU settings and prove the selected public exit before Connected. Choose the exact Router VPN entry mode and Start Layer for either path; the entry's private authenticated identity is also required. OpenVPN preserves its complete saved remote list and inline TLS settings within the same VPN. Secrets remain in app-private storage. External servers use literal IPs; a selected DNS hostname requires the explicit bootstrap saved in its settings. Tor transport hostnames use captured protected networking.");
        return s.toString();
    }

    private void chooseProtocol() {
        if(activeOrTransitioning()){toast("Disconnect/finish the current VPN session before adding or editing custom exits.");return;}
        String[] protocols={"WireGuard / AmneziaWG","SOCKS5","HTTP CONNECT","HTTPS CONNECT + TLS","Shadowsocks","Hysteria2","OpenVPN","Tor","Tor with bridges"};
        String[] ids={"wireguard","socks5","http","https","shadowsocks","hysteria2","openvpn","tor","tor-bridge"};
        new AlertDialog.Builder(this).setTitle("Add custom exit protocol").setItems(protocols,(d,w)->{
            if("wireguard".equals(ids[w]))new AlertDialog.Builder(this).setTitle("WireGuard family").setItems(new String[]{"WireGuard","AmneziaWG"},(choice,index)->showAddForm(index==0?"wireguard":"amneziawg")).setNegativeButton("Cancel",null).show();
            else showAddForm(ids[w]);
        }).setNegativeButton("Cancel",null).show();
    }

    private void showAddForm(String protocol) {
        if(activeOrTransitioning()){toast("Disconnect/finish the current VPN session before adding a custom exit.");return;}
        if("openvpn".equals(protocol)){showOpenVPNForm();return;}
        if("amneziawg".equals(protocol)){showAmneziaForm();return;}
        if(AndroidTorProfile.isTor(protocol)){showTorForm(protocol,null);return;}
        LinearLayout form=new LinearLayout(this);form.setOrientation(LinearLayout.VERTICAL);int p=dp(10);form.setPadding(p,p,p,p);
        EditText name=field("Name",false),server=field("Server literal IP",false),port=field("Server port",false),expected=field("Expected public exit IP",false);
        port.setInputType(InputType.TYPE_CLASS_NUMBER);form.addView(name);form.addView(server);form.addView(port);form.addView(expected);
        List<EditText> extra=new ArrayList<>();
        if("socks5".equals(protocol)||"http".equals(protocol)||"https".equals(protocol)){extra.add(field("Username (optional)",false));extra.add(field("Password (optional)",true));if("https".equals(protocol))extra.add(field("TLS server name / SNI for certificate verification",false));}
        else if("shadowsocks".equals(protocol)){extra.add(field("Method, e.g. 2022-blake3-aes-256-gcm",false));extra.add(field("Password / PSK",true));}
        else if("hysteria2".equals(protocol)){extra.add(field("Password",true));extra.add(field("TLS server name / SNI",false));}
        else if("wireguard".equals(protocol)){extra.add(field("Interface addresses, comma-separated CIDRs",false));extra.add(field("Private key",true));extra.add(field("Peer public key",false));extra.add(field("Preshared key (optional)",true));extra.add(field("Allowed IPs, comma-separated CIDRs",false));EditText mtu=field("MTU (optional)",false);mtu.setInputType(InputType.TYPE_CLASS_NUMBER);extra.add(mtu);}
        for(EditText e:extra)form.addView(e);
        ScrollView scroll=new ScrollView(this);scroll.addView(form);
        new AlertDialog.Builder(this).setTitle("Add "+protocol+" exit").setView(scroll).setPositiveButton("Save",(d,w)->{
            if(activeOrTransitioning()){toast("VPN state changed; disconnect/finish before saving a custom exit.");return;}
            try{AndroidStandardExitStore.Entry e=new AndroidStandardExitStore.Entry();e.name=name.getText().toString();e.protocol=protocol;e.server=server.getText().toString();e.serverPort=parseInt(port,"Server port");e.expectedPublicIp=expected.getText().toString();int i=0;
                if("socks5".equals(protocol)||"http".equals(protocol)||"https".equals(protocol)){e.username=extra.get(i++).getText().toString();e.password=extra.get(i++).getText().toString();if("https".equals(protocol))e.tlsServerName=extra.get(i).getText().toString();}
                else if("shadowsocks".equals(protocol)){e.method=extra.get(i++).getText().toString();e.secret=extra.get(i).getText().toString();}
                else if("hysteria2".equals(protocol)){e.secret=extra.get(i++).getText().toString();e.tlsServerName=extra.get(i).getText().toString();}
                else{e.wgAddresses.addAll(csv(extra.get(i++).getText().toString()));e.wgPrivateKey=extra.get(i++).getText().toString();e.wgPeerPublicKey=extra.get(i++).getText().toString();e.wgPreSharedKey=extra.get(i++).getText().toString();e.wgAllowedIps.addAll(csv(extra.get(i++).getText().toString()));String m=extra.get(i).getText().toString().trim();e.wgMtu=m.isEmpty()?0:Integer.parseInt(m);}
                AndroidStandardExitStore.validate(e);e.policy=AndroidExternalPolicy.editorPolicy(null);showExternalPolicyForm(e);
            }catch(Exception e){toast("Save failed: "+safe(e));}
        }).setNegativeButton("Cancel",null).show();
    }

    private void showTorForm(String protocol, AndroidStandardExitStore.Entry saved) {
        showTorDNSDraft(protocol,saved,null);
    }

    private void showTorDNSDraft(String protocol,AndroidStandardExitStore.Entry original,AndroidDNSSelectionDraft draft) {
        if(activeOrTransitioning()){toast("Disconnect before changing a Tor node.");return;}
        final AndroidStandardExitStore.Entry saved;
        final JSONObject policy;
        try{saved=draft==null?original:draft.apply(original);policy=AndroidTorProfile.editorPolicy(saved);}catch(Exception invalid){toast("The saved Tor settings could not be restored safely.");return;}
        LinearLayout form=new LinearLayout(this);form.setOrientation(LinearLayout.VERTICAL);int pad=dp(12);form.setPadding(pad,pad,pad,pad);
        EditText name=field("Display name",false);if(saved!=null)name.setText(saved.name);form.addView(name);
        Spinner transport=choice(new String[]{"obfs4","meek","Snowflake","WebTunnel","Custom bridge block"});
        EditText bridges=field("Paste bridge lines, one per line",false);bridges.setSingleLine(false);bridges.setMinLines(5);bridges.setMaxLines(12);
        bridges.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        bridges.setSaveEnabled(false);if(android.os.Build.VERSION.SDK_INT>=26)bridges.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        if("tor-bridge".equals(protocol)){
            form.addView(text("Bridge transport",14,true));form.addView(transport);form.addView(bridges);
            if(saved!=null){for(int i=0;i<AndroidTorProfile.TRANSPORTS.length;i++)if(AndroidTorProfile.TRANSPORTS[i].equals(saved.torTransport))transport.setSelection(i);bridges.setText(android.text.TextUtils.join("\n",saved.torBridges));}
            form.addView(text("Paste the complete supplied bridge block. Custom accepts supported bridge lines; it cannot run transport programs or scripts.",13,false));
        }
        Spinner dns=choice(new String[]{"Home AdGuard through captured Router VPN entry","Rescue DoH (Cloudflare)","Custom TCP DNS","Custom DoT","Custom DoH"});
        String dnsMode=policy.optString("dns_mode","home"),protocolDNS=policy.optString("dns_protocol",dnsMode);
        dns.setSelection("home".equals(dnsMode)?0:"rescue".equals(dnsMode)?1:"tcp".equals(protocolDNS)?2:("dot".equals(protocolDNS)||"tls".equals(protocolDNS))?3:4);
        form.addView(text("DNS policy",14,true));form.addView(dns);
        Spinner homeDNS=choice(new String[]{"Home UDP","Home TCP","Home DoT","Home DoH","Home DoH3"});
        homeDNS.setSelection("tcp".equals(protocolDNS)?1:"dot".equals(protocolDNS)?2:"doh".equals(protocolDNS)?3:"doh3".equals(protocolDNS)?4:0);
        form.addView(text("Home AdGuard transport",14,true));form.addView(homeDNS);
        EditText dnsHost=field("Custom DNS literal IP",false),dnsPort=field("Custom DNS port (blank uses protocol default)",false),dnsName=field("DoT / DoH certificate server name",false),dnsPath=field("DoH path (default /dns-query)",false);
        dnsHost.setText(policy.optString("dns_host",""));int savedPort=policy.optInt("dns_port",0);if(savedPort!=0)dnsPort.setText(Integer.toString(savedPort));dnsPort.setInputType(InputType.TYPE_CLASS_NUMBER);
        dnsName.setText(policy.optString("dns_server_name",""));dnsPath.setText(policy.optString("dns_path",""));
        form.addView(dnsHost);form.addView(dnsPort);form.addView(dnsName);form.addView(dnsPath);
        Runnable dnsFields=()->{int selected=dns.getSelectedItemPosition(),home=homeDNS.getSelectedItemPosition();homeDNS.setEnabled(selected==0);dnsHost.setEnabled(selected!=1);dnsPort.setEnabled(selected!=1);dnsName.setEnabled(selected>=3||selected==0&&home>=2);dnsPath.setEnabled(selected==4||selected==0&&home>=3);};
        android.widget.AdapterView.OnItemSelectedListener dnsListener=new android.widget.AdapterView.OnItemSelectedListener(){public void onNothingSelected(android.widget.AdapterView<?> parent){}public void onItemSelected(android.widget.AdapterView<?> parent,View view,int position,long id){dnsFields.run();}};
        dns.setOnItemSelectedListener(dnsListener);homeDNS.setOnItemSelectedListener(dnsListener);
        Spinner ipv6=choice(new String[]{"IPv6 off","IPv6 automatic","IPv6 on"});String ipPolicy=policy.optString("ipv6_mode","off");ipv6.setSelection("auto".equals(ipPolicy)?1:"on".equals(ipPolicy)?2:0);
        form.addView(text("IPv6",14,true));form.addView(ipv6);
        CheckBox blockLAN=new CheckBox(this);blockLAN.setText("Block private LAN ranges");blockLAN.setChecked(!policy.optBoolean("home_lan_access",false));form.addView(blockLAN);
        EditText lan=field("Private LAN CIDRs to block, comma separated (blank uses defaults)",false);JSONArray cidrs=policy.optJSONArray("home_lan_cidrs");if(cidrs!=null){List<String> values=new ArrayList<>();for(int i=0;i<cidrs.length();i++)values.add(cidrs.optString(i));lan.setText(android.text.TextUtils.join(", ",values));}form.addView(lan);
        EditText mtu=field("Manual interface MTU, 1280–9000 (blank uses automatic)",false);mtu.setInputType(InputType.TYPE_CLASS_NUMBER);if("manual".equals(policy.optString("mtu_policy"))||"fixed".equals(policy.optString("mtu_policy")))mtu.setText(Integer.toString(policy.optInt("manual_mtu",0)));form.addView(mtu);
        final ExternalStartupControls startup=new ExternalStartupControls(form,saved);
        final JSONObject initialEditor;
        try{initialEditor=readTorEditorPolicy(dns,homeDNS,dnsHost,dnsPort,dnsName,dnsPath,ipv6,blockLAN,lan,mtu);}
        catch(Exception invalid){toast("The saved Tor settings could not be restored safely.");return;}
        form.addView(text("Home AdGuard uses the paired Router VPN entry you select; leave its address blank to use that entry's saved AdGuard. Direct Tor needs an explicitly selected TCP, DoT, DoH or Rescue resolver. Application traffic stays on Tor. Every Tor path requires Android Always-on VPN and Block connections without VPN.",13,false));
        TextView error=text("",13,false);form.addView(error);ScrollView scroll=new ScrollView(this);scroll.addView(form);
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle(saved==null?"Add "+protocol:"Edit "+saved.name).setView(scroll).setPositiveButton("Save",null).setNegativeButton("Cancel",null).create();
        dialog.setOnShowListener(ignored->dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            if(activeOrTransitioning()){error.setText("VPN state changed; disconnect before saving.");return;}
            try{
                if(draft!=null)draft.requireSource(exitStore.get(draft.nodeID));
                AndroidStandardExitStore.Entry entry=new AndroidStandardExitStore.Entry();if(saved!=null)entry.id=saved.id;entry.name=name.getText().toString();entry.protocol=protocol;
                if("tor-bridge".equals(protocol)){entry.torTransport=AndroidTorProfile.TRANSPORTS[transport.getSelectedItemPosition()];String block=bridges.getText().toString();if(block.length()>65536)throw new IllegalArgumentException("Bridge block exceeds its bound.");for(String line:block.split("\\r?\\n")){String value=line.trim();if(!value.isEmpty())entry.torBridges.add(value);}if(entry.torBridges.isEmpty()||entry.torBridges.size()>8)throw new IllegalArgumentException("Enter one to eight bridge lines.");}
                JSONObject edited=readTorEditorPolicy(dns,homeDNS,dnsHost,dnsPort,dnsName,dnsPath,ipv6,blockLAN,lan,mtu);
                entry.torPolicy=AndroidTorProfile.editedPolicy(saved,initialEditor,edited);
                startup.apply(entry);
                exitStore.save(entry);refresh();toast("Saved "+entry.name);dialog.dismiss();
            }catch(Exception invalid){error.setText("Save failed. Check the complete bridge lines, selected DNS endpoint, private LAN ranges and MTU. The saved profile was not changed.");}
        }));
        dialog.setOnDismissListener(ignored->bridges.setText(""));dialog.show();
    }

    private static JSONObject readTorEditorPolicy(Spinner dns,Spinner homeDNS,EditText host,EditText port,EditText name,EditText path,
            Spinner ipv6,CheckBox blockLAN,EditText lan,EditText mtu)throws Exception{
        int selectedDNS=dns.getSelectedItemPosition();JSONObject p=new JSONObject().put("dns_mode",selectedDNS==0?"home":selectedDNS==1?"rescue":"custom");
        if(selectedDNS!=1){String protocol=selectedDNS==0?new String[]{"udp","tcp","dot","doh","doh3"}[homeDNS.getSelectedItemPosition()]:new String[]{"","","tcp","dot","doh"}[selectedDNS];p.put("dns_protocol",protocol).put("dns_host",host.getText().toString().trim());String portText=port.getText().toString().trim();p.put("dns_port",portText.isEmpty()?0:Integer.parseInt(portText));if("dot".equals(protocol)||"doh".equals(protocol)||"doh3".equals(protocol))p.put("dns_server_name",name.getText().toString().trim());if("doh".equals(protocol)||"doh3".equals(protocol))p.put("dns_path",path.getText().toString().trim());}
        p.put("ipv6_mode",new String[]{"off","auto","on"}[ipv6.getSelectedItemPosition()]).put("home_lan_access",!blockLAN.isChecked()).put("home_lan_cidrs",new JSONArray(csv(lan.getText().toString())));
        String mtuText=mtu.getText().toString().trim();p.put("mtu_policy",mtuText.isEmpty()?"auto":"manual");if(!mtuText.isEmpty())p.put("manual_mtu",Integer.parseInt(mtuText));return p;
    }

    private Spinner choice(String[] values){Spinner spinner=new Spinner(this);ArrayAdapter<String> adapter=new ArrayAdapter<>(this,android.R.layout.simple_spinner_item,values);adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item);spinner.setAdapter(adapter);return spinner;}
    private static String exitSummary(AndroidStandardExitStore.Entry entry){return AndroidTorProfile.isTor(entry.protocol)?AndroidTorProfile.summary(entry):entry.protocol+" — "+entry.server+":"+entry.serverPort+" → expected "+entry.expectedPublicIp;}

    private void showOpenVPNForm() {
        if(activeOrTransitioning()){toast("Disconnect before adding an OpenVPN exit.");return;}
        LinearLayout form=new LinearLayout(this);
        form.setOrientation(LinearLayout.VERTICAL);
        int padding=dp(12);form.setPadding(padding,padding,padding,padding);
        EditText name=field("Display name",false),expected=field("Expected public exit IP",false);
        EditText config=field("Paste complete inline .ovpn profile",false);
        config.setSingleLine(false);config.setMinLines(7);config.setMaxLines(12);
        config.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        config.setSaveEnabled(false);
        EditText username=field("Username (when required)",false),password=field("Password (when required)",true);
        username.setSaveEnabled(false);password.setSaveEnabled(false);
        if(android.os.Build.VERSION.SDK_INT>=android.os.Build.VERSION_CODES.O){
            config.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        }
        TextView error=text("",13,false);
        form.addView(name);form.addView(expected);form.addView(config);form.addView(username);form.addView(password);
        form.addView(text("The native client preserves the remote list and inline CA/client keys. Scripts, plugins and filesystem references are rejected. Next, choose the saved DNS and network settings; the selected entry, DNS and public exit are verified before Connected.",13,false));
        form.addView(error);
        ScrollView scroll=new ScrollView(this);scroll.addView(form);
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Add OpenVPN exit").setView(scroll)
                .setPositiveButton("Next",null).setNegativeButton("Cancel",null).create();
        dialog.setOnShowListener(ignored->dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            if(activeOrTransitioning()){error.setText("VPN state changed; disconnect before saving.");return;}
            try{
                AndroidStandardExitStore.Entry entry=new AndroidStandardExitStore.Entry();
                entry.name=name.getText().toString();entry.protocol="openvpn";
                entry.expectedPublicIp=expected.getText().toString();
                entry.openVPNConfig=config.getText().toString();
                entry.username=username.getText().toString();entry.password=password.getText().toString();
                // Validate with the same native compiler as the live runtime;
                // keep credentials private while collecting the full policy.
                AndroidStandardExitStore.validate(entry);
                entry.policy=AndroidExternalPolicy.editorPolicy(null);
                dialog.dismiss();showExternalPolicyForm(entry);
            }catch(Exception failure){error.setText("Save failed: "+safe(failure));}
        }));
        dialog.setOnDismissListener(ignored->{config.setText("");username.setText("");password.setText("");});
        dialog.show();
    }

    private void showAmneziaForm() {
        if(activeOrTransitioning()){toast("Disconnect before importing an AmneziaWG exit.");return;}
        LinearLayout form=new LinearLayout(this);form.setOrientation(LinearLayout.VERTICAL);int pad=dp(12);form.setPadding(pad,pad,pad,pad);
        EditText name=field("Display name",false),expected=field("Expected public exit IP",false),config=field("Paste complete AmneziaWG .conf profile",false);
        config.setSingleLine(false);config.setMinLines(8);config.setMaxLines(14);config.setSaveEnabled(false);
        config.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE|InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
        if(android.os.Build.VERSION.SDK_INT>=26)config.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        form.addView(name);form.addView(expected);form.addView(config);
        form.addView(text("Paste the complete client configuration supplied by this server. Its eleven obfuscation parameters, keys, addresses, keepalive and transport MTU stay together. The next screen shows the imported DNS selection and saved connection settings.",13,false));
        TextView error=text("",13,false);form.addView(error);ScrollView scroll=new ScrollView(this);scroll.addView(form);
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Import AmneziaWG exit").setView(scroll).setPositiveButton("Next",null).setNegativeButton("Cancel",null).create();
        dialog.setOnShowListener(ignored->dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            if(activeOrTransitioning()){error.setText("VPN state changed; disconnect before importing.");return;}
            try{
                AndroidStandardExitStore.Entry entry=AndroidExternalAmnezia.fromInline(config.getText().toString(),name.getText().toString(),expected.getText().toString());
                dialog.dismiss();showExternalPolicyForm(entry);
            }catch(Exception invalid){error.setText("Import failed. Check the complete AmneziaWG profile and expected public exit IP. No saved node was changed.");}
        }));
        dialog.setOnDismissListener(ignored->config.setText(""));dialog.show();
    }

    private void showSavedExits(boolean connect, boolean direct) {
        try {
            List<AndroidStandardExitStore.Entry> exits=exitStore.list();
            if(exits.isEmpty()){new AlertDialog.Builder(this).setTitle("No custom exits").setMessage("Add Tor, Tor bridges, WireGuard/AmneziaWG, SOCKS5, HTTP/HTTPS CONNECT, Shadowsocks, Hysteria2 or OpenVPN first.").setPositiveButton("Add",(d,w)->chooseProtocol()).setNegativeButton("Cancel",null).show();return;}
            String[] labels=new String[exits.size()];for(int i=0;i<exits.size();i++){AndroidStandardExitStore.Entry e=exits.get(i);labels[i]=e.name+"\n"+exitSummary(e);}
            String title=!connect?"Manage custom exits":direct?"Choose direct external exit":"Choose external exit after Router VPN entry";
            new AlertDialog.Builder(this).setTitle(title).setItems(labels,(d,w)->{if(connect){if(direct)requestDirect(exits.get(w));else chooseEntry(exits.get(w));}else showExitActions(exits.get(w));}).setPositiveButton(connect?"Cancel":"Add new",(d,w)->{if(!connect)chooseProtocol();}).setNegativeButton("Close",null).show();
        } catch(Exception e){toast(safe(e));}
    }

    private void showExitActions(AndroidStandardExitStore.Entry e) {
        boolean tor=AndroidTorProfile.isTor(e.protocol);
        boolean ordinary=AndroidExternalPolicy.supports(e.protocol);
        String[] actions=tor?new String[]{"Connect direct","Connect through Router VPN entry","Edit saved Tor settings","Compare DNS on this connected path","Delete"}:ordinary?new String[]{"Connect direct","Connect through Router VPN entry","Edit DNS, network and MTU settings","Compare DNS on this connected path","Delete"}:new String[]{"Connect direct","Connect through Router VPN entry","Delete"};
        new AlertDialog.Builder(this).setCustomTitle(choiceHeader(e.name+" — "+e.protocol,exitSummary(e)+"\nCredentials and bridge blocks remain private."))
                .setItems(actions,(d,w)->{if(w==0)requestDirect(e);else if(w==1)chooseEntry(e);else if(tor&&w==2)showTorForm(e.protocol,e);else if(ordinary&&w==2)showExternalPolicyForm(e);else if((tor||ordinary)&&w==3)showDNSComparison(e.id);else new AlertDialog.Builder(this).setTitle("Delete "+e.name+"?").setMessage("Only this app-private custom exit will be removed.").setPositiveButton("Delete",(x,y)->{if(activeOrTransitioning()){toast("VPN state changed; disconnect/finish before deleting a custom exit.");return;}try{exitStore.remove(e.id);refresh();toast("Deleted "+e.name);}catch(Exception err){toast(safe(err));}}).setNegativeButton("Cancel",null).show();}).setNegativeButton("Close",null).show();
    }

    private void showDNSComparison(String nodeID){
        AndroidHomeStateStore.Snapshot home=AndroidHomeStateStore.snapshot(this);
        if(nodeID==null||nodeID.isEmpty()||!home.connected||!"passed".equals(home.pathProof)||!nodeID.equals(home.activeExternalId)){
            toast("Connect and prove this external path before comparing its DNS resolvers.");return;
        }
        if(dnsComparison!=null)dnsComparison.close();
        try{
            AndroidStandardExitStore.Entry saved=AndroidStandardExitStore.copy(exitStore.get(nodeID));String homeSession=home.sessionId;AndroidDNSSelectionDraft.Path path=AndroidDNSSelectionDraft.Path.capture(nodeStore,home);
            dnsComparison=new AndroidDNSMeasurementDialog(this,nodeID,(measurement,rowID)->chooseMeasuredDNS(saved,path,homeSession,measurement,rowID));dnsComparison.show();
        }catch(Exception invalid){toast("The saved external node could not be captured for DNS comparison.");}
    }

    private void chooseMeasuredDNS(AndroidStandardExitStore.Entry source,AndroidDNSSelectionDraft.Path path,String homeSession,AndroidNativeDNSMeasurement measurement,String rowID)throws Exception{
        if(destroyed||isFinishing())throw new IllegalStateException("The DNS comparison screen was closed.");
        path.requireActive(AndroidHomeStateStore.snapshot(this));
        AndroidDNSSelectionDraft draft=AndroidDNSSelectionDraft.create(source,path,measurement.currentReceipt(),rowID);
        draft.requireSource(exitStore.get(draft.nodeID));
        new AlertDialog.Builder(this).setTitle("Use this DNS for the next connection?")
                .setMessage(draft.description()+"\n\nDisconnect this exact external session, then review its DNS fields and press Save. The next connection will use those explicit settings.")
                .setPositiveButton("Disconnect and edit",(d,w)->{
                    if(destroyed||isFinishing())return;
                    try{
                        path.requireActive(AndroidHomeStateStore.snapshot(this));
                        draft.requireReceipt(measurement.currentReceipt());draft.requireSource(exitStore.get(draft.nodeID));
                        if(!homeSession.equals(AndroidHomeStateStore.snapshot(this).sessionId))throw new IllegalStateException("The external session changed.");
                    }catch(Exception stale){toast("DNS draft discarded: "+safe(stale));return;}
                    if(dnsComparison!=null)dnsComparison.close();clearPending();busy=true;statusView.setText("Disconnecting the measured session before opening its DNS draft…");
                    new Thread(()->{String failure="";try{if(!runtime.disconnectAndDrainCaptured(homeSession))failure="The measured session changed; its DNS draft was discarded.";}catch(Exception pending){failure="Teardown is not confirmed. Retry Disconnect before editing DNS.";}final String result=failure;
                        runOnUiThread(()->{if(destroyed||isFinishing())return;busy=false;refresh();if(!result.isEmpty()){toast(result);return;}
                            try{if(activeOrTransitioning())throw new IllegalStateException("Another VPN session is active.");AndroidStandardExitStore.Entry current=exitStore.get(draft.nodeID);draft.requireSource(current);
                                if(AndroidTorProfile.isTor(current.protocol))showTorDNSDraft(current.protocol,current,draft);else showExternalDNSDraft(current,draft);
                            }catch(Exception stale){toast("DNS draft discarded: "+safe(stale));}
                        });},"routervpn-dns-next-connection").start();
                }).setNegativeButton("Keep current connection",null).show();
    }

    private final class ExternalStartupControls {
        private final Spinner mode;
        private final CheckBox enabled;
        private final String[] values={"smart-auto","auto","last","manual"};
        ExternalStartupControls(LinearLayout form,AndroidStandardExitStore.Entry entry){
            mode=choice(new String[]{"SMART AUTO — saved external path","AUTO — saved external path","Last mode — saved external protocol","Manual / stay disconnected"});
            int selected=0;if(entry!=null)for(int i=0;i<values.length;i++)if(values[i].equals(entry.startupMode))selected=i;mode.setSelection(selected);
            form.addView(text("Startup behavior",14,true));form.addView(mode);
            enabled=new CheckBox(StandardExitActivity.this);enabled.setText("Auto-connect this saved external path when the app starts");enabled.setChecked(entry!=null&&entry.autoConnect);form.addView(enabled);
            mode.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){public void onNothingSelected(android.widget.AdapterView<?> parent){}public void onItemSelected(android.widget.AdapterView<?> parent,View view,int position,long id){boolean manual=position==3;if(manual)enabled.setChecked(false);enabled.setEnabled(!manual);}});
            form.addView(text("Auto-connect is Off by default and runs once per cold app launch. Every automatic choice keeps this external protocol, the selected Router entry and Local / Server / Compare preference. Its native path and DNS must pass fresh proof; failure stays disconnected. Startup never selects a different protocol or a single-hop substitute.",13,false));
        }
        void apply(AndroidStandardExitStore.Entry entry){entry.startupMode=values[mode.getSelectedItemPosition()];entry.autoConnect=!"manual".equals(entry.startupMode)&&enabled.isChecked();}
    }

    private void showExternalPolicyForm(AndroidStandardExitStore.Entry saved) {
        showExternalDNSDraft(saved,null);
    }

    private void showExternalDNSDraft(AndroidStandardExitStore.Entry saved,AndroidDNSSelectionDraft draft) {
        if(activeOrTransitioning()){toast("Disconnect before editing external-node settings.");return;}
        final AndroidStandardExitStore.Entry captured;
        final JSONObject policy;
        final String storedSource;
        try{captured=draft==null?AndroidStandardExitStore.copy(saved):draft.apply(saved);policy=AndroidExternalPolicy.editorPolicy(captured);storedSource=exitStore.storedSnapshot(captured.id);if(saved.wasPersisted&&storedSource.isEmpty()||!storedSource.isEmpty()&&!storedSource.equals(AndroidStandardExitStore.snapshot(saved)))throw new IllegalStateException("The saved external node changed or was removed before opening its settings.");}
        catch(Exception invalid){toast("The saved external policy could not be restored safely.");return;}
        LinearLayout form=new LinearLayout(this);form.setOrientation(LinearLayout.VERTICAL);int pad=dp(12);form.setPadding(pad,pad,pad,pad);
        Spinner dns=choice(new String[]{"Home AdGuard through captured Router VPN entry","Rescue DoH (Cloudflare)","Custom UDP DNS","Custom TCP DNS","Custom DoT","Custom DoH","Custom DoH3","Previously saved legacy Fastest setting"});
        String mode=policy.optString("dns_mode","home"),protocol="custom".equals(mode)?policy.optString("dns_protocol",""):mode;
        int selected="home".equals(mode)?0:"rescue".equals(mode)?1:"fastest".equals(mode)?7:("dot".equals(protocol)||"tls".equals(protocol))?4:("doh".equals(protocol)||"https".equals(protocol))?5:("doh3".equals(protocol)||"h3".equals(protocol))?6:"tcp".equals(protocol)?3:2;
        dns.setSelection(selected);form.addView(text("DNS for this external connection",14,true));form.addView(dns);
        EditText host=field("Selected DNS IP or hostname",false),port=field("DNS port (blank keeps the protocol default)",false),name=field("Encrypted DNS certificate name",false),path=field("DoH / DoH3 path",false);
        host.setText(policy.optString("dns_host",""));int savedPort=policy.optInt("dns_port",0);if(savedPort>0)port.setText(Integer.toString(savedPort));port.setInputType(InputType.TYPE_CLASS_NUMBER);
        name.setText(policy.optString("dns_server_name",""));path.setText(policy.optString("dns_path",""));form.addView(host);form.addView(port);form.addView(name);form.addView(path);
        dns.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){public void onNothingSelected(android.widget.AdapterView<?> parent){}public void onItemSelected(android.widget.AdapterView<?> parent,View view,int position,long id){boolean custom=position>=2&&position<=6;host.setEnabled(custom);port.setEnabled(custom);name.setEnabled(position>=4&&position<=6);path.setEnabled(position==5||position==6);}});
        CheckBox bootstrapEnabled=new CheckBox(this);bootstrapEnabled.setText("Use an explicit bootstrap resolver for the selected DNS hostname");bootstrapEnabled.setChecked(policy.has("dns_bootstrap"));form.addView(bootstrapEnabled);
        Spinner bootstrapType=choice(new String[]{"UDP","TCP","DoT","DoH","DoH3"});form.addView(bootstrapType);
        EditText bootstrapHost=field("Bootstrap resolver literal IP",false),bootstrapPort=field("Bootstrap port",false),bootstrapName=field("Bootstrap certificate name",false),bootstrapPath=field("Bootstrap DoH path",false);
        bootstrapPort.setInputType(InputType.TYPE_CLASS_NUMBER);form.addView(bootstrapHost);form.addView(bootstrapPort);form.addView(bootstrapName);form.addView(bootstrapPath);
        try{if(policy.has("dns_bootstrap")){JSONObject server=policy.getJSONObject("dns_bootstrap").getJSONObject("server");String t=server.getString("type");bootstrapType.setSelection("tcp".equals(t)?1:"tls".equals(t)?2:"https".equals(t)?3:"h3".equals(t)?4:0);bootstrapHost.setText(server.getString("server"));bootstrapPort.setText(Integer.toString(server.getInt("server_port")));JSONObject tls=server.optJSONObject("tls");if(tls!=null)bootstrapName.setText(tls.optString("server_name",""));bootstrapPath.setText(server.optString("path",""));}}
        catch(Exception invalid){toast("The saved bootstrap resolver could not be restored; its settings were not changed.");return;}
        Spinner ipv6=choice(new String[]{"IPv6 on","IPv6 automatic","IPv6 off"});String ip=policy.optString("ipv6_mode","on");ipv6.setSelection("off".equals(ip)?2:"auto".equals(ip)?1:0);form.addView(text("IPv6",14,true));form.addView(ipv6);
        CheckBox blockLAN=new CheckBox(this);blockLAN.setText("Block private LAN ranges");blockLAN.setChecked(!policy.optBoolean("home_lan_access",true));form.addView(blockLAN);
        EditText lan=field("Private LAN CIDRs, comma separated (blank uses defaults)",false);JSONArray cidrs=policy.optJSONArray("home_lan_cidrs");if(cidrs!=null){List<String> values=new ArrayList<>();for(int i=0;i<cidrs.length();i++)values.add(cidrs.optString(i));lan.setText(android.text.TextUtils.join(", ",values));}form.addView(lan);
        EditText mtu=field("Fixed MTU 1280–9000 (blank: Auto baseline)",false);mtu.setInputType(InputType.TYPE_CLASS_NUMBER);if(!"auto".equals(policy.optString("mtu_policy","auto")))mtu.setText(Integer.toString(policy.optInt("manual_mtu",0)));form.addView(mtu);
        final ExternalStartupControls startup=new ExternalStartupControls(form,captured);
        Spinner exitLayer=choice(new String[]{"Off","AES-256-GCM","AES-256-GCM + XOR whitening"});
        String layerMode=policy.optString("start_layer","off");exitLayer.setSelection("aes-256-gcm".equals(layerMode)?1:"aes-256-gcm+xor-whitening".equals(layerMode)?2:0);
        EditText layerAPI=field("Provisioned private service API URL",false),layerPort=field("Provisioned AES port",false),layerKey=field("Provisioned AES-256-GCM key",true);layerPort.setInputType(InputType.TYPE_CLASS_NUMBER);
        if(AndroidStandardExitStore.serverExecutionProtocol(captured.protocol)){
            form.addView(text("Exit Start Layer",14,true));form.addView(exitLayer);form.addView(layerAPI);form.addView(layerPort);form.addView(layerKey);
            form.addView(text("Use the AES layer already provisioned on this same external server. Its private service address and key stay with this saved node. XOR whitening adds obfuscation to authenticated AES; it requires the provisioned whitening listener on port 8389.",13,false));
            if(captured.startLayer!=null){try{JSONObject transport=captured.startLayer.getJSONObject("transport");layerAPI.setText(captured.startLayer.getString("api"));layerPort.setText(Integer.toString(transport.getInt("server_port")));layerKey.setText(transport.getString("password"));}catch(Exception invalid){toast("The saved exit layer could not be restored; its settings were not changed.");return;}}
            exitLayer.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){public void onNothingSelected(android.widget.AdapterView<?> parent){}public void onItemSelected(android.widget.AdapterView<?> parent,View view,int position,long id){layerAPI.setEnabled(position!=0);layerPort.setEnabled(position!=0);layerKey.setEnabled(position!=0);}});
        }
        form.addView(text("Home uses the selected Router VPN entry's private AdGuard and requires that entry's authenticated proof. Direct connections need an explicit reachable resolver. Resolver hostnames use only the bootstrap you save here, through this path. Auto MTU is an unmeasured baseline until this external exit provides an authenticated packet-probe owner; saved measurements are not reused. A TCP-only transport rejects unsupported UDP and DoH3 settings.",13,false));
        EditText responseURL=field("This server's HTTPS response URL (required for Server / Compare both)",false),responseName=field("Response TLS server name (optional)",false);
        if(AndroidStandardExitStore.serverExecutionProtocol(captured.protocol)){
            responseURL.setText(captured.responseProbe.optString("url",""));responseName.setText(captured.responseProbe.optString("server_name",""));
            form.addView(text("Server / Compare both",14,true));form.addView(responseURL);form.addView(responseName);
            form.addView(text("Enter the HTTPS endpoint provided on this saved server's own public address. Its certificate is verified. Server execution also needs this exit paired in the Router VPN entry's private registry; Compare both measures Local and Server before choosing a proved path.",13,false));
        }
        EditText serverPeer=field("Public Server peer descriptor JSON (optional for Local)",false);
        if(AndroidStandardExitStore.packetExecutionProtocol(captured.protocol)){
            serverPeer.setSingleLine(false);serverPeer.setMinLines(4);
            serverPeer.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE);
            if(captured.serverPeer!=null)serverPeer.setText(captured.serverPeer.toString());
            form.addView(text("Separate WireGuard / AmneziaWG Server peer",14,true));form.addView(serverPeer);
            form.addView(text("Paste the public descriptor supplied when pairing this exit: public_key, addresses, mtu and optional persistent_keepalive_interval. This is the server-side client's identity, with different keys and assigned addresses from this device. Its private key and PSK stay on the Router entry. A matching HTTPS response probe is also required for Server / Compare.",13,false));
        }
        EditText openVPNPairing=field("Private OpenVPN pairing JSON (optional for Local)",false);
        EditText openVPNProbes=field("OpenVPN per-remote HTTPS response map JSON (optional)",false);
        EditText openVPNLayers=field("Private OpenVPN per-remote Start Layer map JSON (optional)",false);
        openVPNPairing.setSaveEnabled(false);openVPNLayers.setSaveEnabled(false);layerKey.setSaveEnabled(false);
        if(android.os.Build.VERSION.SDK_INT>=26){openVPNPairing.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);openVPNLayers.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);layerKey.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);}
        if("openvpn".equals(captured.protocol)){
            openVPNPairing.setSingleLine(false);openVPNPairing.setMinLines(5);
            openVPNPairing.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE);
            if(captured.openVPNPairing!=null)openVPNPairing.setText(captured.openVPNPairing.toString());
            form.addView(text("Independent OpenVPN Server identity",14,true));form.addView(openVPNPairing);
            form.addView(text("Paste this device's private pairing package supplied by your Router entry. It includes a dedicated local authentication key and a server descriptor. The server's OpenVPN password, certificate key and authentication key stay on the entry. Both OpenVPN profiles must use separate provider identities and the same verified remote policy. Leave blank for Local only.",13,false));
            openVPNProbes.setSingleLine(false);openVPNProbes.setMinLines(5);
            openVPNProbes.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE);
            if(captured.openVPNResponseProbes!=null)openVPNProbes.setText(captured.openVPNResponseProbes.toString());
            form.addView(text("Response endpoints for multiple remote hosts",14,true));form.addView(openVPNProbes);
            form.addView(text("For an OpenVPN profile with different remote hosts, paste every remote IP and its verified HTTPS response endpoint. Use this map instead of the single response URL above. Every original host must appear once; the map stays private with this node. Exit encryption for these hosts uses the separate per-remote Start Layer map below.",13,false));
            openVPNLayers.setSingleLine(false);openVPNLayers.setMinLines(5);
            openVPNLayers.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_FLAG_MULTI_LINE);
            if(captured.openVPNStartLayers!=null)openVPNLayers.setText(captured.openVPNStartLayers.toString());
            form.addView(text("Start Layers for multiple remote hosts",14,true));form.addView(openVPNLayers);
            form.addView(text("Choose AES or AES + XOR above, then paste one provisioned layer for every original remote IP. Each record needs the same selected mode and its own api and transport. Keep the single-service API, port and key fields empty. These keys stay private with this node. To turn the layer Off, clear this map as well.",13,false));
        }
        TextView error=text("",13,false);form.addView(error);ScrollView scroll=new ScrollView(this);scroll.addView(form);
        AlertDialog dialog=new AlertDialog.Builder(this).setTitle("Connection settings — "+captured.name).setView(scroll).setPositiveButton("Save",null).setNegativeButton("Cancel",null).create();
        dialog.setOnShowListener(ignored->dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
            if(activeOrTransitioning()){error.setText("VPN state changed; disconnect before saving.");return;}
            try{
                if(draft!=null)draft.requireSource(exitStore.get(draft.nodeID));
                AndroidStandardExitStore.Entry next=AndroidStandardExitStore.copy(captured);JSONObject p=new JSONObject(policy.toString());int n=dns.getSelectedItemPosition();
                // An unrelated settings edit must retain the exact Home/Fastest
                // resolver, transport and port already selected for this node.
                if(n!=selected||(n>=2&&n<=6))for(String key:new String[]{"dns_protocol","dns_host","dns_port","dns_server_name","dns_path"})p.remove(key);
                for(String key:new String[]{"dns_bootstrap","effective_mtu","manual_mtu"})p.remove(key);
                p.put("dns_mode",n==0?"home":n==1?"rescue":n==7?"fastest":"custom");
                if(n==selected&&n==0){if(!captured.policy.has("dns_mode"))p.remove("dns_mode");else if(captured.policy.optString("dns_mode","").isEmpty())p.put("dns_mode","");}
                if(n>=2&&n<=6){String transport=new String[]{"","","udp","tcp","tls","https","h3"}[n];String address=host.getText().toString().trim();if(address.isEmpty())throw new IllegalArgumentException("Enter the selected DNS address.");String number=port.getText().toString().trim();int value=number.isEmpty()?0:Integer.parseInt(number);if(value<0||value>65535)throw new IllegalArgumentException("DNS port must be 1–65535 or blank.");p.put("dns_protocol",transport).put("dns_host",address).put("dns_port",value);if(n>=4)p.put("dns_server_name",name.getText().toString().trim());if(n>=5)p.put("dns_path",path.getText().toString().trim());}
                if(n==7&&(p.optString("fastest_dns_host","").isEmpty()||!p.has("dns_results")&&!p.has("fastest_dns_latency_ms")))throw new IllegalArgumentException("This node has no legacy Fastest setting. Use a completed comparison to choose an explicit resolver for the next connection.");
                if(bootstrapEnabled.isChecked()){
                    if(n<2||n>6)throw new IllegalArgumentException("Bootstrap belongs to an explicitly selected DNS hostname.");
                    String t=new String[]{"udp","tcp","tls","https","h3"}[bootstrapType.getSelectedItemPosition()];String address=bootstrapHost.getText().toString().trim();AndroidNumericAddress.parse(address);
                    String number=bootstrapPort.getText().toString().trim();int value=number.isEmpty()?("tls".equals(t)?853:("https".equals(t)||"h3".equals(t))?443:53):Integer.parseInt(number);if(value<1||value>65535)throw new IllegalArgumentException("Bootstrap port must be 1–65535.");
                    JSONObject server=new JSONObject().put("type",t).put("tag","external-dns-bootstrap").put("server",address).put("server_port",value).put("detour","custom-exit");
                    if(bootstrapType.getSelectedItemPosition()>=2)server.put("tls",new JSONObject().put("enabled",true).put("server_name",bootstrapName.getText().toString().trim()));if(bootstrapType.getSelectedItemPosition()>=3){String route=bootstrapPath.getText().toString().trim();server.put("path",route.isEmpty()?"/dns-query":route);}
                    JSONObject query=policy.has("dns_bootstrap")?new JSONObject(policy.getJSONObject("dns_bootstrap").getJSONObject("query").toString()):new JSONObject().put("server","external-dns-bootstrap");p.put("dns_bootstrap",new JSONObject().put("server",server).put("query",query));
                }
                p.put("ipv6_mode",new String[]{"on","auto","off"}[ipv6.getSelectedItemPosition()]).put("home_lan_access",!blockLAN.isChecked()).put("home_lan_cidrs",new JSONArray(csv(lan.getText().toString())));
                String fixed=mtu.getText().toString().trim();p.put("mtu_policy",fixed.isEmpty()?"auto":"fixed");if(!fixed.isEmpty())p.put("manual_mtu",Integer.parseInt(fixed));AndroidExternalPolicy.checkPolicy(p);next.policy=p;
                if(AndroidStandardExitStore.serverExecutionProtocol(next.protocol)){
                    int selectedLayer=exitLayer.getSelectedItemPosition();String chosenLayer=new String[]{"off","aes-256-gcm","aes-256-gcm+xor-whitening"}[selectedLayer];p.put("start_layer",chosenLayer);next.startLayer=null;
                    boolean mappedLayers="openvpn".equals(next.protocol)&&!openVPNLayers.getText().toString().trim().isEmpty();
                    if(mappedLayers&&(!layerAPI.getText().toString().trim().isEmpty()||!layerPort.getText().toString().trim().isEmpty()||!layerKey.getText().toString().isEmpty()))throw new IllegalArgumentException("Use either a single-server exit layer or a complete per-remote layer map.");
                    if(selectedLayer!=0&&!mappedLayers){String tag=captured.startLayer==null?"provisioned-exit-layer":captured.startLayer.getJSONObject("transport").getString("tag");JSONObject transport=new JSONObject().put("type","shadowsocks").put("tag",tag).put("server",next.server).put("server_port",Integer.parseInt(layerPort.getText().toString().trim())).put("method","2022-blake3-aes-256-gcm").put("password",layerKey.getText().toString());next.startLayer=new JSONObject().put("mode",chosenLayer).put("api",layerAPI.getText().toString().trim()).put("transport",transport);}
                }
                if(AndroidStandardExitStore.serverExecutionProtocol(next.protocol)){
                    String url=responseURL.getText().toString().trim(),tls=responseName.getText().toString().trim();next.responseProbe=new JSONObject();
                    if(!url.isEmpty())next.responseProbe.put("url",url);if(!tls.isEmpty())next.responseProbe.put("server_name",tls);AndroidStandardExitStore.validateResponseProbe(next);
                }
                if(AndroidStandardExitStore.packetExecutionProtocol(next.protocol)){
                    next.serverPeer=AndroidStandardExitStore.parseServerPeer(serverPeer.getText().toString());
                    AndroidStandardExitStore.validateServerPeer(next);
                }
                if("openvpn".equals(next.protocol)){next.openVPNPairing=AndroidOpenVPN.pairing(next,openVPNPairing.getText().toString());next.openVPNResponseProbes=AndroidOpenVPN.responseProbes(next,openVPNProbes.getText().toString());next.openVPNStartLayers=AndroidOpenVPN.startLayers(next,openVPNLayers.getText().toString());AndroidOpenVPN.validateResponseProbes(next);}
                AndroidStandardExitStore.validateStartLayer(next);
                // Shared idle validation defers only the unresolved Home entry;
                // native transport, DNS shape and saved device policy stay required.
                startup.apply(next);
                AndroidExternalPolicy.validateDraft(next);
                exitStore.saveIfUnchanged(next,storedSource);dialog.dismiss();refresh();toast("Saved "+next.name+" connection settings");
            }catch(Exception invalid){error.setText("Save failed: "+safe(invalid));}
        }));dialog.setOnDismissListener(ignored->{openVPNPairing.setText("");openVPNLayers.setText("");layerKey.setText("");});dialog.show();
    }

    private void requestDirect(AndroidStandardExitStore.Entry exit) {
        if(activeOrTransitioning()){toast("Disconnect the current VPN session before starting another custom exit.");return;}
        try{capturePending(null,exit,true,"external");rememberExternalPath(null,exit,"wg");}catch(Exception invalid){clearPending();toast(safe(invalid));return;}
        if(selectionOnly()){clearPending();toast("External path selected. Press Connect when ready.");finish();return;}
        Intent permission=VpnService.prepare(this);
        if(permission!=null){statusView.setText("Waiting for Android VPN permission…");startActivityForResult(permission,PREPARE_STANDARD_EXIT);}else startPending();
    }

    private void chooseEntry(AndroidStandardExitStore.Entry exit) {
        if(activeOrTransitioning()){toast("Disconnect the current VPN session before starting another custom exit.");return;}
        try{List<AndroidNodeStore.Node> nodes=nodeStore.list();if(nodes.isEmpty()){dialog("Router VPN entry required","Link a Router VPN node first, then select its exact encrypted mode for this external exit.");return;}String[]labels=new String[nodes.size()];for(int i=0;i<nodes.size();i++)labels[i]=nodes.get(i).name+(nodes.get(i).endpoint.isEmpty()?"":" — "+nodes.get(i).endpoint);new AlertDialog.Builder(this).setCustomTitle(choiceHeader("Choose Router VPN entry","Path: this device → Router VPN entry → "+exit.name+" → Internet")).setItems(labels,(d,w)->{if(AndroidTorProfile.isTor(exit.protocol)||AndroidExternalPolicy.supports(exit.protocol))chooseNativeEntryMode(nodes.get(w),exit);else requestConnect(nodes.get(w),exit,"wg");}).setNegativeButton("Cancel",null).show();}catch(Exception e){toast(safe(e));}
    }

    private void chooseNativeEntryMode(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit){
        if(activeOrTransitioning()){toast("Disconnect before selecting the external entry.");return;}
        try{
            JSONObject bundle=new JSONObject(AndroidTorProfile.strictText(AndroidPrivateFileStore.read(entry.file,AndroidNodeStore.MAX_BUNDLE)));AndroidNodeStore.validateBundle(bundle);
            JSONObject profiles=bundle.getJSONObject("profiles");JSONArray modes=bundle.getJSONArray("modes");List<String> ids=new ArrayList<>(),labels=new ArrayList<>();
            for(int i=0;i<modes.length();i++){JSONObject mode=modes.getJSONObject(i);String id=mode.optString("id");if(NativeSingBoxController.nativeMultihopEntry(id)&&profiles.optJSONObject(id)!=null&&!ids.contains(id)){ids.add(id);labels.add(mode.optString("name",id)+" ["+id+"]");}}
            if(ids.isEmpty())throw new IllegalStateException("This saved entry has no supported native encrypted mode.");
            new AlertDialog.Builder(this).setCustomTitle(choiceHeader("Exact Router VPN entry mode","The complete selected encryption and Start Layer will be retained before "+exit.name+". Both entry identity and the selected external path must pass proof."))
                    .setItems(labels.toArray(new String[0]),(d,w)->chooseExecution(entry,exit,ids.get(w))).setNegativeButton("Cancel",null).show();
        }catch(Exception error){toast("The saved entry cannot provide a captured native external path.");}
    }

    private void chooseExecution(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,String mode){
        if(!AndroidStandardExitStore.serverExecutionProtocol(exit.protocol)){requestConnect(entry,exit,mode);return;}
        new AlertDialog.Builder(this).setCustomTitle(choiceHeader("External path execution","Local runs the exit on this device. Server uses an isolated paired session on the entry. Compare both measures both paths and keeps the lower valid average response time."))
                .setItems(new String[]{"Local","Server","Compare both"},(d,w)->requestConnect(entry,exit,mode,new String[]{"local","server","auto"}[w])).setNegativeButton("Cancel",null).show();
    }

    private void requestConnect(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,String entryMode){requestConnect(entry,exit,entryMode,"local");}

    private void requestConnect(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,String entryMode,String execution) {
        if(activeOrTransitioning()){toast("Disconnect the current VPN session before starting another custom exit.");return;}
        try{capturePending(entry,exit,false,entryMode,execution);rememberExternalPath(entry,exit,entryMode);}catch(Exception invalid){clearPending();toast(safe(invalid));return;}
        if(selectionOnly()){clearPending();toast("External path selected. Press Connect when ready.");finish();return;}
        Intent permission=VpnService.prepare(this);if(permission!=null){statusView.setText("Waiting for Android VPN permission…");startActivityForResult(permission,PREPARE_STANDARD_EXIT);}else startPending();
    }

    private void capturePending(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,boolean direct,String entryMode)throws Exception{capturePending(entry,exit,direct,entryMode,"local");}

    private void capturePending(AndroidNodeStore.Node entry,AndroidStandardExitStore.Entry exit,boolean direct,String entryMode,String execution)throws Exception{
        AndroidStandardExitStore.validateExecution(exit,!direct,execution);pendingExecution=execution;
        pendingEntry=entry;pendingExit=AndroidStandardExitStore.copy(exit);pendingDirect=direct;pendingEntryMode=entryMode;
        pendingExitDigest=AndroidTorProfile.digest(AndroidStandardExitStore.snapshot(pendingExit).getBytes(StandardCharsets.UTF_8));
        pendingEntryDigest=entry==null?"":AndroidTorProfile.digest(AndroidPrivateFileStore.read(entry.file,AndroidNodeStore.MAX_BUNDLE));
        pendingRequestDigest=requestDigest(direct,entryMode,execution,pendingEntryDigest,pendingExitDigest);
    }
    private static String requestDigest(boolean direct,String mode,String execution,String entry,String exit)throws Exception{return AndroidTorProfile.digest(("external-request-v1\n"+direct+"\n"+mode+"\n"+execution+"\n"+entry+"\n"+exit).getBytes(StandardCharsets.UTF_8));}

    private void clearPending(){pendingEntry=null;pendingExit=null;pendingDirect=false;pendingEntryMode="wg";pendingExecution="local";pendingEntryDigest="";pendingExitDigest="";pendingRequestDigest="";}

    private void startPending() {
        AndroidNodeStore.Node entry=pendingEntry;AndroidStandardExitStore.Entry exit=pendingExit;boolean direct=pendingDirect;String entryMode=pendingEntryMode,execution=pendingExecution,request=pendingRequestDigest,entryDigest=pendingEntryDigest,exitDigest=pendingExitDigest;
        clearPending();if(exit==null)return;if(!direct&&entry==null)return;
        if(activeOrTransitioning()){toast("VPN state changed while permission was open; disconnect before starting the custom exit.");refresh();return;}
        try{
            AndroidStandardExitStore.validateExecution(exit,!direct,execution);
            if(!request.equals(requestDigest(direct,entryMode,execution,entryDigest,exitDigest))||!exitDigest.equals(AndroidTorProfile.digest(AndroidStandardExitStore.snapshot(exitStore.get(exit.id)).getBytes(StandardCharsets.UTF_8)))
                    ||!exitDigest.equals(AndroidTorProfile.digest(AndroidStandardExitStore.snapshot(exit).getBytes(StandardCharsets.UTF_8)))
                    ||!direct&&!entryDigest.equals(AndroidTorProfile.digest(AndroidPrivateFileStore.read(entry.file,AndroidNodeStore.MAX_BUNDLE))))throw new IllegalStateException("Captured source changed.");
        }catch(Exception changed){toast("A captured node changed while Android permission was open. Select the path again.");refresh();return;}
        busy=true;statusView.setText(direct?"Preparing direct external exit…":"Preparing Router VPN entry → external exit…");
        AndroidStandardExitRuntime.Callback cb=new AndroidStandardExitRuntime.Callback(){public void progress(String m){runOnUiThread(()->{if(!isFinishing())statusView.setText(m);});}public void finished(boolean ok,String m){runOnUiThread(()->{busy=false;if(!isFinishing()){statusView.setText(m);if(!ok)toast(m);refresh();}});}};
        if(direct)runtime.connectDirect(exit,cb);else runtime.connect(entry.file,exit,entryMode,execution,cb);
    }

    private boolean activeOrTransitioning(){return busy||AndroidVpnMutationGuard.isBusy(this);}

    @Override protected void onActivityResult(int request,int result,Intent data){super.onActivityResult(request,result,data);if(request!=PREPARE_STANDARD_EXIT)return;if(result==RESULT_OK)startPending();else{clearPending();busy=false;statusView.setText("VPN permission denied; custom exit stayed disconnected.");}}

    private EditText field(String hint,boolean secret){EditText e=new EditText(this);e.setHint(hint);e.setSingleLine(true);if(secret)e.setInputType(InputType.TYPE_CLASS_TEXT|InputType.TYPE_TEXT_VARIATION_PASSWORD);return e;}
    private View choiceHeader(String title,String message){LinearLayout header=new LinearLayout(this);header.setOrientation(LinearLayout.VERTICAL);int pad=dp(16);header.setPadding(pad,pad,pad,dp(8));header.addView(text(title,18,true));header.addView(text(message,14,false));return header;}
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
