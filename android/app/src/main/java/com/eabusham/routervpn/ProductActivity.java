package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.res.ColorStateList;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.VpnService;
import android.os.Bundle;
import android.provider.Settings;
import android.text.InputType;
import android.view.Gravity;
import android.view.MotionEvent;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.Spinner;
import android.widget.TextView;
import android.widget.Toast;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

/** Unified native daily-use Android shell. The old engine console remains only as a diagnostic fallback. */
public final class ProductActivity extends Activity {
    private static final String PREFS="router-vpn-unified";
    private static final String MODE_KEY="mode";
    private static final String CUSTOM_KEY="custom_presets";
    private static final String SELECTED_KIND="selected_kind";
    private static final String SELECTED_ID="selected_id";
    private static final String MULTI_ON="multihop_on";
    private static final String MULTI_ENTRY="multihop_entry";
    private static final String MULTI_EXIT="multihop_exit";
    private static final String MULTI_MODE="multihop_exit_mode";

    private AndroidNodeStore nodeStore;
    private AndroidStandardExitStore exitStore;
    private AndroidUnifiedNodeCatalog catalog;
    private AndroidUnifiedConnectionController connection;
    private RouterVpnNodeMapView mapView;
    private LinearLayout sheet;
    private TextView nodeButton,statusView,modeHint,dnsHint,multihopHint;
    private Button connectButton;
    private CheckBox killSwitch,multihopToggle;
    private Spinner modeSpinner,dnsSpinner;
    private List<ModeChoice> modeChoices=new ArrayList<>();
    private float sheetTouchY;
    private boolean sheetExpanded;

    private static final class ModeChoice {
        final String id,title; final List<String> layers;
        ModeChoice(String id,String title){this(id,title,Collections.emptyList());}
        ModeChoice(String id,String title,List<String>layers){this.id=id;this.title=title;this.layers=layers==null?Collections.emptyList():layers;}
        @Override public String toString(){return title;}
    }
    private static final class CustomPreset {
        String name; List<String> layers;
        CustomPreset(String name,List<String>layers){this.name=name;this.layers=layers;}
    }

    @Override protected void onCreate(Bundle state){
        super.onCreate(state);
        nodeStore=new AndroidNodeStore(this);exitStore=new AndroidStandardExitStore(this);catalog=new AndroidUnifiedNodeCatalog(nodeStore,exitStore);connection=new AndroidUnifiedConnectionController(this,nodeStore);
        setContentView(buildUi());refreshAll();AndroidProductOnboarding.showIfNeeded(this);
    }
    @Override protected void onResume(){super.onResume();refreshAll();}
    @Override protected void onDestroy(){if(connection!=null)connection.close();super.onDestroy();}
    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){if(connection!=null&&connection.onActivityResult(requestCode,resultCode)){refreshConnectionLater();return;}super.onActivityResult(requestCode,resultCode,data);}

    private View buildUi(){
        LinearLayout root=new LinearLayout(this);root.setOrientation(LinearLayout.VERTICAL);root.setPadding(dp(10),dp(10),dp(10),dp(8));root.setBackgroundColor(Color.rgb(8,16,30));

        nodeButton=text("Add / select node",14,true);nodeButton.setTextColor(Color.WHITE);nodeButton.setPadding(dp(12),dp(9),dp(12),dp(9));nodeButton.setBackground(round(Color.rgb(24,38,62),16));nodeButton.setOnClickListener(v->showNodes());root.addView(nodeButton,margins(0,0,0,dp(8)));

        mapView=new RouterVpnNodeMapView(this);mapView.setOnMarkerClickListener(marker->{String raw=marker.id==null?"":marker.id;int cut=raw.indexOf(':');if(cut<=0)return;String kind=raw.substring(0,cut),id=raw.substring(cut+1);selectCatalog(kind,id);});
        LinearLayout.LayoutParams mapParams=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,0,0.56f);root.addView(mapView,mapParams);

        sheet=new LinearLayout(this);sheet.setOrientation(LinearLayout.VERTICAL);sheet.setPadding(dp(14),dp(5),dp(14),dp(12));sheet.setBackground(round(Color.rgb(17,27,45),24));
        sheet.setOnTouchListener((v,event)->{if(event.getAction()==MotionEvent.ACTION_DOWN){sheetTouchY=event.getY();return false;}if(event.getAction()==MotionEvent.ACTION_UP){float delta=event.getY()-sheetTouchY;if(Math.abs(delta)>dp(40)){sheetExpanded=delta<0;applySheetWeight();}return false;}return false;});
        LinearLayout.LayoutParams sheetParams=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,0,0.44f);sheetParams.setMargins(0,dp(8),0,0);root.addView(sheet,sheetParams);

        TextView handle=text("━━━━━━━━",16,true);handle.setTextColor(Color.rgb(112,126,148));handle.setGravity(Gravity.CENTER);sheet.addView(handle);
        LinearLayout statusRow=row();statusView=text("Disconnected",13,false);statusView.setTextColor(Color.rgb(173,190,214));statusView.setTextIsSelectable(true);statusView.setOnClickListener(v->showConnectionDetails());statusRow.addView(statusView,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button connectionDetails=smallButton("Details / proof");connectionDetails.setOnClickListener(v->showConnectionDetails());statusRow.addView(connectionDetails);sheet.addView(statusRow,margins(0,0,0,dp(7)));

        LinearLayout connectRow=row();connectButton=primaryButton("Connect");connectButton.setOnClickListener(v->connectOrDisconnect());connectRow.addView(connectButton,new LinearLayout.LayoutParams(0,dp(50),1f));killSwitch=new CheckBox(this);killSwitch.setText("Kill switch");killSwitch.setTextColor(Color.WHITE);killSwitch.setButtonTintList(ColorStateList.valueOf(Color.rgb(123,104,255)));killSwitch.setOnCheckedChangeListener((b,on)->{if(!b.isPressed())return;setQuickKillSwitch(on);});connectRow.addView(killSwitch);sheet.addView(connectRow);

        LinearLayout multiRow=row();multihopToggle=new CheckBox(this);multihopToggle.setText("Multihop");multihopToggle.setTextColor(Color.WHITE);multihopToggle.setButtonTintList(ColorStateList.valueOf(Color.rgb(55,145,255)));multihopToggle.setOnCheckedChangeListener((b,on)->{prefs().edit().putBoolean(MULTI_ON,on).apply();refreshMap();refreshMultihopSummary();});multiRow.addView(multihopToggle);multihopHint=text("Off",12,false);multihopHint.setTextColor(Color.rgb(173,190,214));multiRow.addView(multihopHint,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button hops=smallButton("Edit hops");hops.setOnClickListener(v->configureMultihop());multiRow.addView(hops);sheet.addView(multiRow,margins(0,dp(8),0,0));

        LinearLayout settingsRow=controlRow("Settings");Button settings=smallButton("Open settings");settings.setOnClickListener(v->showSettings());settingsRow.addView(settings);Button mtu=smallButton("Retest MTU");mtu.setOnClickListener(v->showMtuHelp());settingsRow.addView(mtu);sheet.addView(settingsRow,margins(0,dp(7),0,0));

        LinearLayout modeRow=controlRow("Mode");modeSpinner=new Spinner(this);modeSpinner.setPopupBackgroundDrawable(round(Color.rgb(29,43,68),12));modeRow.addView(modeSpinner,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button modeDetails=smallButton("Presets");modeDetails.setOnClickListener(v->AndroidProductParity.showModes(this,nodeStore));modeRow.addView(modeDetails);sheet.addView(modeRow,margins(0,dp(7),0,0));modeHint=text("SMART AUTO is the default.",11,false);modeHint.setTextColor(Color.rgb(145,160,184));sheet.addView(modeHint);

        LinearLayout dnsRow=controlRow("DNS");dnsSpinner=new Spinner(this);String[]dns={"Home AdGuard","Fastest measured","Custom","DoT","DoH","DoH3","Rescue"};dnsSpinner.setAdapter(new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,dns));dnsRow.addView(dnsSpinner,new LinearLayout.LayoutParams(0,LinearLayout.LayoutParams.WRAP_CONTENT,1f));Button dnsDetails=smallButton("Details");dnsDetails.setOnClickListener(v->AndroidProductParity.showDNS(this,nodeStore));dnsRow.addView(dnsDetails);sheet.addView(dnsRow,margins(0,dp(7),0,0));dnsHint=text("DNS changes the next tunnel resolver path; Connected still requires runtime DNS/path proof.",11,false);dnsHint.setTextColor(Color.rgb(145,160,184));sheet.addView(dnsHint);
        dnsSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){boolean ready;public void onNothingSelected(android.widget.AdapterView<?>p){}public void onItemSelected(android.widget.AdapterView<?>p,View v,int pos,long id){if(!ready){ready=true;return;}if(pos==0)setQuickDns("home");else if(pos==1)setQuickDns("fastest");else if(pos==6)setQuickDns("rescue");else AndroidProductParity.showDNS(ProductActivity.this,nodeStore);}});

        LinearLayout footer=row();Button nodes=smallButton("Nodes");nodes.setOnClickListener(v->showNodes());footer.addView(nodes);Button pair=smallButton("Add Router node");pair.setOnClickListener(v->showPairDialog());footer.addView(pair);Button custom=smallButton("Add custom / external");custom.setOnClickListener(v->openStandardExits());footer.addView(custom);Button help=smallButton("Help");help.setOnClickListener(v->showHelp());footer.addView(help);sheet.addView(footer,margins(0,dp(8),0,0));
        return root;
    }

    private void applySheetWeight(){LinearLayout.LayoutParams p=(LinearLayout.LayoutParams)sheet.getLayoutParams();p.weight=sheetExpanded?0.70f:0.44f;sheet.setLayoutParams(p);LinearLayout.LayoutParams m=(LinearLayout.LayoutParams)mapView.getLayoutParams();m.weight=sheetExpanded?0.30f:0.56f;mapView.setLayoutParams(m);}
    private void refreshAll(){refreshNodes();refreshModeChoices();refreshConnectionState();refreshSettingsState();refreshDnsSelection();refreshMultihopSummary();}
    private void refreshConnectionLater(){mapView.postDelayed(this::refreshAll,350);mapView.postDelayed(this::refreshAll,1300);mapView.postDelayed(this::refreshAll,3000);}

    private void connectOrDisconnect(){
        if(connection.isActiveOrTransitioning()){statusView.setText("Disconnecting…");connectButton.setText("Disconnecting…");connection.disconnect(callback());return;}
        AndroidUnifiedNodeCatalog.Item selected=selectedCatalogItem();
        if(selected==null){showNodes();return;}
        if(!selected.isRouterVpn()){Intent intent=new Intent(this,StandardExitActivity.class);intent.putExtra(StandardExitActivity.EXTRA_EXIT_ID,selected.id);startActivity(intent);return;}
        if(multihopToggle.isChecked()){
            try{AndroidNodeStore.Node entry=nodeById(prefs().getString(MULTI_ENTRY,"")),exit=nodeById(prefs().getString(MULTI_EXIT,""));String exitMode=prefs().getString(MULTI_MODE,"");if(entry==null||exit==null||exitMode.isEmpty()){configureMultihop();return;}statusView.setText("Preparing multihop…");connection.connectMultihop(entry,exit,exitMode,callback());}catch(Exception error){toast(safe(error));}return;
        }
        ModeChoice choice=currentMode();if(choice==null){refreshModeChoices();choice=currentMode();if(choice==null)return;}
        statusView.setText("Preparing "+choice.title+"…");connection.connect(choice.id,choice.layers,callback());
    }

    private AndroidUnifiedConnectionController.Callback callback(){return new AndroidUnifiedConnectionController.Callback(){public void progress(String message){runOnUiThread(()->{statusView.setText(message);connectButton.setText("Disconnect");});}public void finished(boolean ok,String message){runOnUiThread(()->{statusView.setText(message);if(!ok)toast(message);refreshAll();refreshConnectionLater();});}};}
    private void refreshConnectionState(){boolean active=connection!=null&&connection.isActiveOrTransitioning();connectButton.setText(active?"Disconnect":"Connect");statusView.setText(AndroidHomeSummary.format(this,nodeStore));}
    private void showConnectionDetails(){
        String truth=AndroidHomeSummary.format(this,nodeStore);
        new AlertDialog.Builder(this).setTitle("Connection details & proof").setMessage(truth+"\n\nConnected is not treated as a proved public exit until the current app-owned VPN network, selected-node path and current-session exit proof all agree.")
            .setPositiveButton("Prove actual exit",(d,w)->{statusView.setText("Proving actual public VPN exit for this session…");AndroidHomeSummary.proveActualExit(this,nodeStore,(message,error)->runOnUiThread(()->{statusView.setText(message);if(error!=null)toast(message);refreshAll();}));})
            .setNeutralButton("Emergency disconnect",(d,w)->{statusView.setText("Emergency disconnect requested…");AndroidHomeSummary.emergencyDisconnect(this,(message,error)->runOnUiThread(()->{statusView.setText(message);if(error!=null)toast(message);refreshAll();refreshConnectionLater();}));})
            .setNegativeButton("Close",null).show();
    }

    private void refreshModeChoices(){
        String wanted=prefs().getString(MODE_KEY,"smart-auto");List<ModeChoice> values=new ArrayList<>();values.add(new ModeChoice("smart-auto","SMART AUTO — recommended"));values.add(new ModeChoice("auto","AUTO — first proven path"));
        try{JSONObject root=activeBundle();JSONArray logical=root.optJSONArray("logicalModes");if(logical!=null)for(int i=0;i<logical.length();i++){JSONObject m=logical.optJSONObject(i);if(m==null)continue;String id=m.optString("id","");if(id.isEmpty())continue;values.add(new ModeChoice(id,m.optString("name",id)));}}catch(Exception ignored){}
        for(CustomPreset p:loadCustomPresets())values.add(new ModeChoice("custom:"+p.name,"CUSTOM • "+p.name,p.layers));values.add(new ModeChoice("custom:new","New CUSTOM preset…"));modeChoices=values;
        ArrayAdapter<ModeChoice> adapter=new ArrayAdapter<>(this,android.R.layout.simple_spinner_dropdown_item,values);modeSpinner.setAdapter(adapter);int index=0;for(int i=0;i<values.size();i++)if(values.get(i).id.equals(wanted)){index=i;break;}modeSpinner.setSelection(index,false);
        modeSpinner.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){boolean ready;public void onNothingSelected(android.widget.AdapterView<?>p){}public void onItemSelected(android.widget.AdapterView<?>p,View v,int pos,long id){if(!ready){ready=true;return;}if(pos<0||pos>=modeChoices.size())return;ModeChoice selected=modeChoices.get(pos);if("custom:new".equals(selected.id)){showCustomBuilder(null);return;}prefs().edit().putString(MODE_KEY,selected.id).apply();modeHint.setText(selected.id.startsWith("custom:")?"Saved visual CUSTOM preset • exact required layers":"Unavailable presets remain visible; the engine fails closed with the exact readiness/proof reason.");}});
    }
    private ModeChoice currentMode(){if(modeSpinner==null||modeChoices.isEmpty())return null;int i=modeSpinner.getSelectedItemPosition();return i>=0&&i<modeChoices.size()?modeChoices.get(i):modeChoices.get(0);}

    private void showCustomBuilder(CustomPreset editing){
        try{
            List<String> layers=allCatalogLayers();if(layers.isEmpty()){toast("No mode layers are available in the selected Router VPN bundle.");return;}
            LinearLayout body=new LinearLayout(this);body.setOrientation(LinearLayout.VERTICAL);body.setPadding(dp(18),dp(8),dp(18),0);EditText name=new EditText(this);name.setHint("Preset name");if(editing!=null)name.setText(editing.name);body.addView(name);TextView note=text("Select exact required layers. Router VPN tries only native Android stacks containing every selected layer and fails closed if no compatible path passes proof.",12,false);body.addView(note);
            boolean[] checked=new boolean[layers.size()];Set<String> old=editing==null?Collections.emptySet():new LinkedHashSet<>(editing.layers);for(int i=0;i<layers.size();i++)checked[i]=old.contains(layers.get(i));
            AlertDialog.Builder b=new AlertDialog.Builder(this).setTitle(editing==null?"New CUSTOM preset":"Edit CUSTOM • "+editing.name).setView(body).setMultiChoiceItems(layers.toArray(new CharSequence[0]),checked,(d,w,on)->checked[w]=on).setPositiveButton("Save",null).setNeutralButton(editing==null?"Cancel":"Delete",null).setNegativeButton("Cancel",null);
            AlertDialog dialog=b.create();dialog.setOnShowListener(x->{dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{String n=name.getText().toString().trim();List<String> selected=new ArrayList<>();for(int i=0;i<checked.length;i++)if(checked[i])selected.add(layers.get(i));if(n.isEmpty()||n.length()>64){toast("Preset name must be 1–64 characters.");return;}if(selected.isEmpty()){toast("CUSTOM requires at least one layer.");return;}saveCustomPreset(new CustomPreset(n,selected),editing==null?null:editing.name);prefs().edit().putString(MODE_KEY,"custom:"+n).apply();dialog.dismiss();refreshModeChoices();});if(editing!=null)dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v->{deleteCustomPreset(editing.name);prefs().edit().putString(MODE_KEY,"smart-auto").apply();dialog.dismiss();refreshModeChoices();});});dialog.show();
        }catch(Exception error){toast("CUSTOM builder unavailable: "+safe(error));}
    }

    private void refreshNodes(){
        if(catalog==null||mapView==null)return;try{List<AndroidUnifiedNodeCatalog.Item>items=catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT);String selectedKind=prefs().getString(SELECTED_KIND,"router-vpn"),selectedId=prefs().getString(SELECTED_ID,nodeStore.activeId());if(selectedId.isEmpty()&&!items.isEmpty()){AndroidUnifiedNodeCatalog.Item first=items.get(0);selectedKind=first.kind;selectedId=first.id;prefs().edit().putString(SELECTED_KIND,selectedKind).putString(SELECTED_ID,selectedId).apply();if(first.isRouterVpn())nodeStore.select(first.id);}List<RouterVpnNodeMapView.Marker>markers=new ArrayList<>();String entry=prefs().getString(MULTI_ENTRY,""),exit=prefs().getString(MULTI_EXIT,"");boolean multi=prefs().getBoolean(MULTI_ON,false);AndroidUnifiedNodeCatalog.Item chosen=null;for(AndroidUnifiedNodeCatalog.Item item:items){if(item.kind.equals(selectedKind)&&item.id.equals(selectedId))chosen=item;if(!item.hasCoordinates())continue;String role;if(multi&&item.id.equals(entry))role=RouterVpnNodeMapView.ROLE_ENTRY;else if(multi&&item.id.equals(exit))role=RouterVpnNodeMapView.ROLE_EXIT;else if(item.kind.equals(selectedKind)&&item.id.equals(selectedId))role=RouterVpnNodeMapView.ROLE_SELECTED;else if(!item.isRouterVpn())role=RouterVpnNodeMapView.ROLE_EXTERNAL;else role=RouterVpnNodeMapView.ROLE_NORMAL;markers.add(new RouterVpnNodeMapView.Marker(item.kind+":"+item.id,item.name,item.latitude,item.longitude,role));}mapView.setMarkers(markers);nodeButton.setText(chosen==null?"Add / select node":(chosen.isRouterVpn()?"Router • ":"Custom • ")+chosen.name+"  ▾");}catch(Exception error){nodeButton.setText("Node catalog unavailable");mapView.setMarkers(new ArrayList<>());}
    }
    private void refreshMap(){refreshNodes();}
    private AndroidUnifiedNodeCatalog.Item selectedCatalogItem(){try{String kind=prefs().getString(SELECTED_KIND,"router-vpn"),id=prefs().getString(SELECTED_ID,nodeStore.activeId());for(AndroidUnifiedNodeCatalog.Item item:catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT))if(item.kind.equals(kind)&&item.id.equals(id))return item;}catch(Exception ignored){}return null;}
    private void selectCatalog(String kind,String id){try{for(AndroidUnifiedNodeCatalog.Item item:catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT))if(item.kind.equals(kind)&&item.id.equals(id)){selectCatalog(item);return;}}catch(Exception error){toast(safe(error));}}
    private void selectCatalog(AndroidUnifiedNodeCatalog.Item item){prefs().edit().putString(SELECTED_KIND,item.kind).putString(SELECTED_ID,item.id).apply();if(item.isRouterVpn())try{nodeStore.select(item.id);}catch(Exception error){toast(safe(error));}refreshAll();}

    private void showNodes(){
        try{List<AndroidUnifiedNodeCatalog.Item>items=catalog.list(AndroidUnifiedNodeCatalog.SORT_CURRENT);if(items.isEmpty()){new AlertDialog.Builder(this).setTitle("Nodes").setMessage("No nodes yet. Add a Router node by secure LAN pairing, or add a Custom / external exit.").setPositiveButton("Add Router node",(d,w)->showPairDialog()).setNeutralButton("Add custom",(d,w)->openStandardExits()).setNegativeButton("Close",null).show();return;}String[]labels=new String[items.size()];for(int i=0;i<items.size();i++){AndroidUnifiedNodeCatalog.Item item=items.get(i);labels[i]=(item.isRouterVpn()?"Router • ":"Custom • ")+item.name+(item.hasCoordinates()?"":" • list only");}new AlertDialog.Builder(this).setTitle("Choose node").setMessage("One node is selected by default. Only real stored coordinates appear on the map; no IP geolocation/fake pins.").setItems(labels,(d,w)->selectCatalog(items.get(w))).setPositiveButton("Add Router node",(d,w)->showPairDialog()).setNeutralButton("Add custom",(d,w)->openStandardExits()).setNegativeButton("Close",null).show();}catch(Exception error){toast(safe(error));}
    }

    private void configureMultihop(){
        try{List<AndroidNodeStore.Node>nodes=nodeStore.list();if(nodes.size()<2){toast("Multihop needs at least two different Router VPN nodes.");return;}String[]labels=new String[nodes.size()];for(int i=0;i<nodes.size();i++)labels[i]=nodes.get(i).name;new AlertDialog.Builder(this).setTitle("Multihop entry").setItems(labels,(d,w)->chooseMultihopExit(nodes.get(w),nodes)).setNegativeButton("Cancel",null).show();}catch(Exception error){toast(safe(error));}
    }
    private void chooseMultihopExit(AndroidNodeStore.Node entry,List<AndroidNodeStore.Node>all){List<AndroidNodeStore.Node>exits=new ArrayList<>();for(AndroidNodeStore.Node n:all)if(!n.id.equals(entry.id))exits.add(n);String[]labels=new String[exits.size()];for(int i=0;i<exits.size();i++)labels[i]=exits.get(i).name;new AlertDialog.Builder(this).setTitle("Multihop exit").setMessage("Path will be entry → exit → Internet. Entry and exit must differ.").setItems(labels,(d,w)->chooseMultihopMode(entry,exits.get(w))).setNegativeButton("Cancel",null).show();}
    private void chooseMultihopMode(AndroidNodeStore.Node entry,AndroidNodeStore.Node exit){try{List<NativeSingBoxController.ModeInfo>modes=connection.supportedMultihopExitModes(exit);if(modes.isEmpty()){toast("That exit has no proven Android Shadowsocks/Hysteria2 multihop transport.");return;}String[]labels=new String[modes.size()];for(int i=0;i<modes.size();i++)labels[i]=modes.get(i).name+" ["+modes.get(i).id+"]";new AlertDialog.Builder(this).setTitle("Exit transport").setItems(labels,(d,w)->{prefs().edit().putBoolean(MULTI_ON,true).putString(MULTI_ENTRY,entry.id).putString(MULTI_EXIT,exit.id).putString(MULTI_MODE,modes.get(w).id).apply();multihopToggle.setChecked(true);refreshMultihopSummary();refreshMap();}).setNegativeButton("Cancel",null).show();}catch(Exception error){toast(safe(error));}}
    private void refreshMultihopSummary(){boolean on=prefs().getBoolean(MULTI_ON,false);multihopToggle.setChecked(on);if(!on){multihopHint.setText("Off");return;}try{AndroidNodeStore.Node entry=nodeById(prefs().getString(MULTI_ENTRY,"")),exit=nodeById(prefs().getString(MULTI_EXIT,""));multihopHint.setText(entry==null||exit==null?"Choose hops":entry.name+" → "+exit.name+" • "+prefs().getString(MULTI_MODE,""));}catch(Exception error){multihopHint.setText("Choose hops");}}
    private AndroidNodeStore.Node nodeById(String id)throws Exception{for(AndroidNodeStore.Node n:nodeStore.list())if(n.id.equals(id))return n;return null;}

    private void showSettings(){JSONObject p=activeRouterProfile();if(p==null){toast("Select a Router VPN node first.");return;}AndroidProfileSettingsDialog.show(this,nodeStore,this::refreshAll);}
    private void setQuickKillSwitch(boolean enabled){if(connection.isActiveOrTransitioning()){toast("Disconnect before changing persistent kill-switch policy.");refreshSettingsState();return;}try{JSONObject root=activeBundle(),p=selectedProfile(root);if(p==null)throw new IllegalStateException("Select a Router VPN node first.");p.put("kill_switch",enabled);p.put("kill_switch_policy",enabled?"on-connect":"off");nodeStore.importBundle(root.toString().getBytes(StandardCharsets.UTF_8));toast(enabled?"Kill switch enabled":"Kill switch disabled");}catch(Exception error){toast(safe(error));}refreshSettingsState();}
    private void refreshSettingsState(){JSONObject p=activeRouterProfile();boolean enabled=p!=null&&(!"off".equalsIgnoreCase(p.optString("kill_switch_policy","off"))||p.optBoolean("kill_switch",false));killSwitch.setChecked(enabled);}
    private void showMtuHelp(){new AlertDialog.Builder(this).setTitle("MTU").setMessage("Auto measured is the default. Retest is path/config-specific; a Fixed MTU applies until changed. The Android detailed settings retain the current effective MTU/source. A real retest requires the selected Router VPN path and remains proof-driven rather than a guessed number.").setPositiveButton("Open settings",(d,w)->showSettings()).setNegativeButton("Close",null).show();}

    private void setQuickDns(String mode){if(connection.isActiveOrTransitioning()){toast("Disconnect before changing DNS.");refreshDnsSelection();return;}try{JSONObject root=activeBundle(),p=selectedProfile(root);if(p==null)throw new IllegalStateException("Select a Router VPN node first.");if("fastest".equals(mode)&&p.optString("fastest_dns_host","").trim().isEmpty()){AndroidProductParity.showDNS(this,nodeStore);return;}p.put("dns_mode",mode);if("home".equals(mode)){p.put("dns_protocol","udp");p.put("dns_port",53);p.put("dns_host",p.optString("adguard_ipv4",p.optString("adguard_ipv6","")));}nodeStore.importBundle(root.toString().getBytes(StandardCharsets.UTF_8));toast("DNS set to "+mode+" for the next tunnel; runtime proof still required.");}catch(Exception error){toast(safe(error));}refreshDnsSelection();}
    private void refreshDnsSelection(){JSONObject p=activeRouterProfile();String mode=p==null?"home":p.optString("dns_mode","home").toLowerCase(Locale.US);String[]ids={"home","fastest","custom","dot","doh","doh3","rescue"};int index=0;for(int i=0;i<ids.length;i++)if(ids[i].equals(mode)){index=i;break;}dnsSpinner.setSelection(index,false);}

    private void showPairDialog(){LinearLayout fields=new LinearLayout(this);fields.setOrientation(LinearLayout.VERTICAL);fields.setPadding(dp(20),dp(4),dp(20),0);EditText host=new EditText(this);host.setHint("AI Board LAN IP / hostname");host.setSingleLine(true);EditText code=new EditText(this);code.setHint("6-digit one-time pairing code");code.setSingleLine(true);code.setInputType(InputType.TYPE_CLASS_NUMBER|InputType.TYPE_NUMBER_VARIATION_PASSWORD);fields.addView(host);fields.addView(code);new AlertDialog.Builder(this).setTitle("Add Router node").setMessage("Use the short-lived code from authenticated private Setup Center. Pairing stays LAN/private and one-time.").setView(fields).setPositiveButton("Pair",(dialog,which)->AndroidPairingClient.redeem(host.getText().toString(),code.getText().toString(),(bundle,error)->runOnUiThread(()->{if(error!=null){toast("Pairing failed: "+safe(error));return;}try{AndroidNodeStore.Node node=nodeStore.importBundle(bundle);prefs().edit().putString(SELECTED_KIND,"router-vpn").putString(SELECTED_ID,node.id).apply();refreshAll();toast("Added and selected "+node.name);}catch(Exception importError){toast("Bundle rejected: "+safe(importError));}}))).setNegativeButton("Cancel",null).show();}
    private void openStandardExits(){startActivity(new Intent(this,StandardExitActivity.class));}
    private void showHelp(){new AlertDialog.Builder(this).setTitle("Router VPN").setMessage("Map-first daily app: choose one Router or Custom node, Connect, optionally configure real multihop, then adjust Settings, Mode and DNS from the swipe-up control sheet. Tap Details / proof for the current-session public-exit proof or emergency disconnect. Connected means the selected native path passed the required proof; unsupported graphs remain unavailable.").setPositiveButton("Run onboarding again",(d,w)->AndroidProductOnboarding.show(this,true)).setNeutralButton("Android VPN settings",(d,w)->startActivity(new Intent(Settings.ACTION_VPN_SETTINGS))).setNegativeButton("Close",null).show();}

    private JSONObject activeBundle()throws Exception{String active=nodeStore.activeId();if(active==null||active.isEmpty())throw new IllegalStateException("Select a Router VPN node first.");try(FileInputStream in=new FileInputStream(nodeStore.file(active));ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]buf=new byte[8192];int n,total=0;while((n=in.read(buf))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Bundle exceeds safety limit.");out.write(buf,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private JSONObject activeRouterProfile(){try{return selectedProfile(activeBundle());}catch(Exception ignored){return null;}}
    private static JSONObject selectedProfile(JSONObject bundle){JSONArray a=bundle.optJSONArray("routerProfiles");String id=bundle.optString("selectedRouterID","");if(a==null)return null;for(int i=0;i<a.length();i++){JSONObject p=a.optJSONObject(i);if(p!=null&&id.equals(p.optString("id")))return p;}return a.length()>0?a.optJSONObject(0):null;}
    private List<String> allCatalogLayers()throws Exception{JSONObject root=activeBundle();JSONArray modes=root.optJSONArray("modes");Set<String>set=new LinkedHashSet<>();if(modes!=null)for(int i=0;i<modes.length();i++){JSONObject m=modes.optJSONObject(i);JSONArray l=m==null?null:m.optJSONArray("layers");if(l!=null)for(int j=0;j<l.length();j++){String v=l.optString(j,"").trim().toLowerCase(Locale.US);if(!v.isEmpty())set.add(v);}}return new ArrayList<>(set);}

    private List<CustomPreset> loadCustomPresets(){List<CustomPreset>out=new ArrayList<>();try{JSONArray a=new JSONArray(prefs().getString(CUSTOM_KEY,"[]"));for(int i=0;i<a.length();i++){JSONObject p=a.optJSONObject(i);if(p==null)continue;String name=p.optString("name","").trim();JSONArray l=p.optJSONArray("layers");List<String>layers=new ArrayList<>();if(l!=null)for(int j=0;j<l.length();j++){String v=l.optString(j,"").trim();if(!v.isEmpty())layers.add(v);}if(!name.isEmpty()&&!layers.isEmpty())out.add(new CustomPreset(name,layers));}}catch(Exception ignored){}return out;}
    private void saveCustomPreset(CustomPreset preset,String oldName){List<CustomPreset>all=loadCustomPresets();List<CustomPreset>next=new ArrayList<>();for(CustomPreset p:all)if((oldName==null||!p.name.equalsIgnoreCase(oldName))&&!p.name.equalsIgnoreCase(preset.name))next.add(p);next.add(preset);persistCustom(next);}
    private void deleteCustomPreset(String name){List<CustomPreset>next=new ArrayList<>();for(CustomPreset p:loadCustomPresets())if(!p.name.equalsIgnoreCase(name))next.add(p);persistCustom(next);}
    private void persistCustom(List<CustomPreset>values){JSONArray a=new JSONArray();for(CustomPreset p:values){JSONObject o=new JSONObject();try{o.put("name",p.name);o.put("layers",new JSONArray(p.layers));a.put(o);}catch(Exception ignored){}}prefs().edit().putString(CUSTOM_KEY,a.toString()).apply();}

    private SharedPreferences prefs(){return getSharedPreferences(PREFS,MODE_PRIVATE);}
    private LinearLayout row(){LinearLayout r=new LinearLayout(this);r.setOrientation(LinearLayout.HORIZONTAL);r.setGravity(Gravity.CENTER_VERTICAL);return r;}
    private LinearLayout controlRow(String title){LinearLayout r=row();TextView label=text(title,13,true);label.setTextColor(Color.WHITE);label.setGravity(Gravity.END);r.addView(label,new LinearLayout.LayoutParams(dp(72),LinearLayout.LayoutParams.WRAP_CONTENT));return r;}
    private TextView text(String value,int sp,boolean bold){TextView v=new TextView(this);v.setText(value);v.setTextSize(sp);v.setTextColor(Color.WHITE);if(bold)v.setTypeface(v.getTypeface(),Typeface.BOLD);return v;}
    private Button primaryButton(String value){Button b=smallButton(value);b.setTextSize(17);b.setTypeface(b.getTypeface(),Typeface.BOLD);b.setTextColor(Color.WHITE);b.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(95,78,220)));return b;}
    private Button smallButton(String value){Button b=new Button(this);b.setText(value);b.setAllCaps(false);b.setTextColor(Color.WHITE);b.setTextSize(12);b.setBackgroundTintList(ColorStateList.valueOf(Color.rgb(39,55,82)));return b;}
    private GradientDrawable round(int color,int radius){GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));return d;}
    private LinearLayout.LayoutParams margins(int l,int t,int r,int b){LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT);p.setMargins(l,t,r,b);return p;}
    private int dp(float value){return Math.round(value*getResources().getDisplayMetrics().density);}
    private static String safe(Throwable error){String value=error==null?"":error.getMessage();return value==null||value.trim().isEmpty()?"Router VPN error":value.trim();}
    private void toast(String message){Toast.makeText(this,message==null?"Router VPN":message,Toast.LENGTH_LONG).show();}
}
