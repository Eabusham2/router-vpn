package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONObject;

import java.util.ArrayList;
import java.util.List;

/** Native daily-use product shell. MainActivity remains the engine-heavy Connect surface. */
public final class ProductActivity extends Activity {
    private AndroidNodeStore nodeStore;
    private AndroidStandardExitStore exitStore;
    private AndroidUnifiedNodeCatalog catalog;
    private RouterVpnNodeMapView mapView;
    private TextView summaryView, homeStateView;
    private String nodeSort = AndroidUnifiedNodeCatalog.SORT_CURRENT;

    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        nodeStore = new AndroidNodeStore(this);
        exitStore = new AndroidStandardExitStore(this);
        catalog = new AndroidUnifiedNodeCatalog(nodeStore, exitStore);
        setContentView(buildUi());
        refreshNodes();
        refreshHomeState();
        AndroidProductOnboarding.showIfNeeded(this);
    }

    @Override protected void onResume() { super.onResume(); refreshNodes(); refreshHomeState(); }

    private View buildUi() {
        int pad = dp(18);
        LinearLayout root = new LinearLayout(this);
        root.setOrientation(LinearLayout.VERTICAL);
        root.setPadding(pad, pad, pad, pad);

        root.addView(text("Router VPN", 28, true));
        root.addView(text("Native Android dashboard — install once, link Router VPN nodes and private external exits separately", 14, false), margins(0, dp(4), 0, dp(12)));

        HorizontalScrollView navScroll = new HorizontalScrollView(this);
        navScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout nav = new LinearLayout(this);
        nav.setOrientation(LinearLayout.HORIZONTAL);
        nav.addView(navButton("Home / Connect", v -> openConnect()));
        nav.addView(navButton("Nodes / Map", v -> showNodes()));
        nav.addView(navButton("Modes", v -> showModes()));
        nav.addView(navButton("DNS", v -> showDns()));
        nav.addView(navButton("Advanced", v -> showAdvanced()));
        nav.addView(navButton("Custom Exits", v -> openStandardExits()));
        nav.addView(navButton("Forwarding", v -> showForwarding()));
        nav.addView(navButton("Settings", v -> openSettings()));
        nav.addView(navButton("Help", v -> showHelp()));
        navScroll.addView(nav);
        root.addView(navScroll, margins(0, 0, 0, dp(12)));

        summaryView = text("No linked nodes yet.", 16, true);
        root.addView(summaryView, margins(0, dp(4), 0, dp(8)));

        homeStateView = text("Home / Connect state unavailable until a Router VPN node is selected.", 13, false);
        homeStateView.setTextIsSelectable(true);
        root.addView(homeStateView, margins(0, dp(4), 0, dp(4)));
        LinearLayout homeActions = new LinearLayout(this);
        homeActions.setOrientation(LinearLayout.VERTICAL);
        Button proveExit = button("Prove actual exit");
        proveExit.setOnClickListener(v -> {
            homeStateView.setText("Proving actual public VPN exit through the current Router VPN-owned Android VPN network…");
            AndroidHomeSummary.proveActualExit(this, nodeStore, (message,error) -> runOnUiThread(() -> { toast(message); refreshHomeState(); }));
        });
        Button emergency = button("Emergency Disconnect");
        emergency.setOnClickListener(v -> {
            homeStateView.setText("Emergency Disconnect requested; verifying Router VPN transports stop…");
            AndroidHomeSummary.emergencyDisconnect(this, (message,error) -> runOnUiThread(() -> { toast(message); refreshHomeState(); }));
        });
        homeActions.addView(proveExit);
        homeActions.addView(emergency);
        root.addView(homeActions, margins(0, dp(4), 0, dp(12)));

        root.addView(text("Nodes & Map", 20, true));
        root.addView(text("Router VPN and external nodes share one list. Only real latitude/longitude stored with a node is plotted; Router VPN never geolocates or guesses an address from an IP.", 13, false), margins(0, dp(2), 0, dp(8)));
        mapView = new RouterVpnNodeMapView(this);
        root.addView(mapView, new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT, dp(300)));

        HorizontalScrollView nodeOrderScroll = new HorizontalScrollView(this);
        nodeOrderScroll.setHorizontalScrollBarEnabled(false);
        LinearLayout nodeOrder = new LinearLayout(this);
        nodeOrder.setOrientation(LinearLayout.HORIZONTAL);
        nodeOrder.addView(navButton("Current / recent", v -> setNodeSort(AndroidUnifiedNodeCatalog.SORT_CURRENT)));
        nodeOrder.addView(navButton("Last used", v -> setNodeSort(AndroidUnifiedNodeCatalog.SORT_LAST_USED)));
        nodeOrder.addView(navButton("Lowest latency", v -> setNodeSort(AndroidUnifiedNodeCatalog.SORT_LATENCY)));
        nodeOrder.addView(navButton("Name", v -> setNodeSort(AndroidUnifiedNodeCatalog.SORT_NAME)));
        nodeOrder.addView(navButton("Select lowest measured", v -> selectLowestLatencyNode()));
        nodeOrderScroll.addView(nodeOrder);
        root.addView(nodeOrderScroll, margins(0, dp(8), 0, 0));

        Button connect = button("Open Router VPN Connect — WG / AWG / libbox / Xray / AUTO / SMART / CUSTOM / ALL"); connect.setOnClickListener(v -> openConnect()); root.addView(connect, margins(0, dp(14), 0, 0));
        Button pair = button("Pair home node from authenticated Setup Center"); pair.setOnClickListener(v -> showPairDialog()); root.addView(pair, margins(0, dp(8), 0, 0));
        Button nodes = button("Choose Router VPN or external node"); nodes.setOnClickListener(v -> showNodes()); root.addView(nodes, margins(0, dp(8), 0, 0));
        Button customExit = button("External exits — direct or Router VPN WG entry → exit"); customExit.setOnClickListener(v -> openStandardExits()); root.addView(customExit, margins(0, dp(8), 0, 0));
        root.addView(text("Forwarding/server administration stays on the authenticated private Setup Center surface; the Android client never exposes an admin token and never pretends a proxy-only path can perform arbitrary DNAT.", 13, false), margins(0, dp(18), 0, dp(16)));
        ScrollView scroll = new ScrollView(this); scroll.addView(root); return scroll;
    }

    private void refreshHomeState() { if (homeStateView != null) homeStateView.setText(AndroidHomeSummary.format(this, nodeStore)); }
    private void setNodeSort(String order) { nodeSort = order; refreshNodes(); toast("Node order: " + order.replace('-', ' ')); }

    private void selectLowestLatencyNode() {
        try {
            AndroidUnifiedNodeCatalog.Item best = catalog.lowestLatency();
            if (best == null) { toast("Run real latency measurements on at least two usable nodes first; current selection was kept."); return; }
            if (!best.isRouterVpn()) { toast("Lowest measured external exit is " + best.name + "; open it to connect with exact exit proof."); chooseCatalogItem(best); return; }
            nodeStore.select(best.id); nodeSort = AndroidUnifiedNodeCatalog.SORT_LATENCY; refreshNodes(); refreshHomeState(); toast("Selected lowest measured median-latency node: " + best.name);
        } catch (Exception error) { toast(safe(error)); }
    }

    private void refreshNodes() {
        if (catalog == null || mapView == null || summaryView == null) return;
        try {
            List<AndroidUnifiedNodeCatalog.Item> items = catalog.list(nodeSort); String activeId = nodeStore.activeId();
            List<RouterVpnNodeMapView.Marker> markers = new ArrayList<>(); AndroidUnifiedNodeCatalog.Item active = null;
            int routerCount=0,externalCount=0,externalWithoutCoordinates=0;
            for (AndroidUnifiedNodeCatalog.Item item:items){if(item.isRouterVpn())routerCount++;else{externalCount++;if(!item.hasCoordinates())externalWithoutCoordinates++;}if(item.isRouterVpn()&&item.id.equals(activeId))active=item;if(!item.hasCoordinates())continue;String label=item.isRouterVpn()?item.name:item.name+" — "+item.protocol;markers.add(new RouterVpnNodeMapView.Marker(item.kind+":"+item.id,label,item.latitude,item.longitude,item.isRouterVpn()&&item.id.equals(activeId)));}
            mapView.setMarkers(markers);
            String counts=routerCount+" Router VPN node"+(routerCount==1?"":"s")+" • "+externalCount+" external exit"+(externalCount==1?"":"s")+" • order "+nodeSort.replace('-',' '); if(externalWithoutCoordinates>0)counts+=" • "+externalWithoutCoordinates+" external list-only (no real coordinates)";
            if(active==null)summaryView.setText(items.isEmpty()?"No linked nodes — pair/import a Router VPN bundle or add an external custom exit.":counts+"\nChoose a Router VPN node for normal modes, or an external exit for direct/hopped custom-exit use.");else summaryView.setText("Active Router VPN: "+active.name+"\n"+active.subtitle()+"\n"+counts);
        } catch(Exception error){summaryView.setText("Node catalog unavailable: "+safe(error));mapView.setMarkers(new ArrayList<>());} refreshHomeState();
    }

    private void showPairDialog(){
        LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);fields.setPadding(dp(20),dp(4),dp(20),0);EditText host=new EditText(this);host.setHint("AI Board LAN IP / hostname");host.setSingleLine(true);EditText code=new EditText(this);code.setHint("6-digit one-time pairing code");code.setSingleLine(true);code.setInputType(InputType.TYPE_CLASS_NUMBER|InputType.TYPE_NUMBER_VARIATION_PASSWORD);fields.addView(host);fields.addView(code);
        new AlertDialog.Builder(this).setTitle("Pair Router VPN home node").setMessage("Create the short-lived code in the authenticated private Setup Center. Pairing is accepted only from private/local addresses, the code is one-time, and Router VPN does not enable Android-wide cleartext HTTP for this flow.").setView(fields).setPositiveButton("Pair",(dialog,which)->{summaryView.setText("Pairing with home Setup Center…");AndroidPairingClient.redeem(host.getText().toString(),code.getText().toString(),(bundle,error)->runOnUiThread(()->{if(error!=null){summaryView.setText("LAN pairing failed: "+safe(error));toast("LAN pairing failed: "+safe(error));return;}try{AndroidNodeStore.Node node=nodeStore.importBundle(bundle);refreshNodes();toast("Paired and selected "+node.name);}catch(Exception importError){summaryView.setText("Paired bundle rejected: "+safe(importError));toast("Paired bundle rejected: "+safe(importError));}}));}).setNegativeButton("Cancel",null).show();
    }

    private void showNodes(){
        try{List<AndroidUnifiedNodeCatalog.Item>items=catalog.list(nodeSort);if(items.isEmpty()){new AlertDialog.Builder(this).setTitle("Nodes / Map").setMessage("No nodes yet. Pair a home node with a one-time Setup Center code, import a Router VPN bundle in Connect, or add a private external WireGuard/SOCKS5/Shadowsocks/Hysteria2 exit.").setPositiveButton("Pair home node",(d,w)->showPairDialog()).setNeutralButton("Open Connect",(d,w)->openConnect()).setNegativeButton("Close",null).show();return;}String[]labels=new String[items.size()];for(int i=0;i<items.size();i++){AndroidUnifiedNodeCatalog.Item item=items.get(i);labels[i]=(item.isRouterVpn()?"Router VPN • ":"External • ")+item;}new AlertDialog.Builder(this).setTitle("Nodes / Map — "+nodeSort.replace('-',' ')).setMessage("Router VPN nodes become the active home node. External nodes open the direct/hopped custom-exit flow. External entries with no real coordinates remain list-only.").setItems(labels,(d,which)->chooseCatalogItem(items.get(which))).setPositiveButton("Pair another home node",(d,w)->showPairDialog()).setNegativeButton("Close",null).show();}catch(Exception error){toast(safe(error));}
    }

    private void chooseCatalogItem(AndroidUnifiedNodeCatalog.Item item){if(item.isRouterVpn()){try{nodeStore.select(item.id);refreshNodes();toast("Selected "+item.name);}catch(Exception error){toast(safe(error));}return;}Intent intent=new Intent(this,StandardExitActivity.class);intent.putExtra(StandardExitActivity.EXTRA_EXIT_ID,item.id);startActivity(intent);}
    private void showModes(){AndroidProductParity.showModes(this,nodeStore);} private void showDns(){AndroidProductParity.showDNS(this,nodeStore);}
    private void showAdvanced(){
        JSONObject p=activeRouterProfile();
        if(p==null){dialog("Advanced","No active Router VPN profile. External custom exits enforce their own full-device runtime and exact public-exit proof; direct Android external exits additionally require system lockdown.");return;}
        if("external".equalsIgnoreCase(p.optString("node_kind","router-vpn"))){dialog("Advanced","External exits own their protocol settings. Select a Router VPN home node to edit LAN, kill-switch, IPv6, WG/AWG base, MTU, DAITA-like, Jumbo TUN or SOCKS preferences.");return;}
        AndroidProfileSettingsDialog.show(this,nodeStore,this::refreshHomeState);
    }
    private void showForwarding(){dialog("Forwarding","Incoming forwarding is owned by the authenticated private home-node Setup Center/router-agent surface. This client does not expose an admin token or Docker/Portainer authority and does not fake DNAT in proxy-only/external modes. Use Setup Center Forwarding, then validate rules off-LAN.");}
    private void openSettings(){startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));} private void openStandardExits(){startActivity(new Intent(this,StandardExitActivity.class));}
    private void showHelp(){new AlertDialog.Builder(this).setTitle("Help").setMessage("App onboarding is separate from Setup Center onboarding and can be rerun here. Install Router VPN once and link private node data separately. Every connection still requires the actual selected-path/public-exit/DNS proof appropriate to that mode; unsupported graphs stay unavailable.").setPositiveButton("Run onboarding again",(d,w)->AndroidProductOnboarding.show(this,true)).setNeutralButton("Pair home node",(d,w)->showPairDialog()).setNegativeButton("Close",null).show();}
    private void openConnect(){getSharedPreferences("router-vpn",MODE_PRIVATE).edit().putBoolean("onboarding_done_v6",true).putInt("onboarding_step_v6",0).apply();startActivity(new Intent(this,MainActivity.class));}
    private JSONObject activeRouterProfile(){try{String active=nodeStore.activeId();if(active.isEmpty())return null;return AndroidUnifiedNodeCatalog.selectedProfile(nodeStore.file(active));}catch(Exception ignored){return null;}}
    private static String safe(Throwable error){String value=error==null?"":error.getMessage();return value==null||value.trim().isEmpty()?"Router VPN node error":value.trim();}
    private void dialog(String title,String message){new AlertDialog.Builder(this).setTitle(title).setMessage(message).setPositiveButton("OK",null).show();} private void toast(String message){Toast.makeText(this,message==null?"Router VPN":message,Toast.LENGTH_LONG).show();}
    private TextView text(String value,int sp,boolean bold){TextView v=new TextView(this);v.setText(value);v.setTextSize(sp);v.setTextColor(0xff14213d);if(bold)v.setTypeface(v.getTypeface(),android.graphics.Typeface.BOLD);return v;} private Button button(String value){Button b=new Button(this);b.setText(value);b.setAllCaps(false);return b;} private Button navButton(String value,View.OnClickListener listener){Button b=button(value);b.setOnClickListener(listener);return b;} private LinearLayout.LayoutParams margins(int l,int t,int r,int b){LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT);p.setMargins(l,t,r,b);return p;} private int dp(int value){return Math.round(value*getResources().getDisplayMetrics().density);}
}
