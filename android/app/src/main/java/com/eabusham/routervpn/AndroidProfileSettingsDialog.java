package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Process;
import android.text.InputType;
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

/** Edits only non-secret Router VPN node policy fields in the private app store. */
final class AndroidProfileSettingsDialog {
    static void show(Activity activity, AndroidNodeStore store, Runnable onSaved) {
        try {
            if (hasLiveVpn(activity)) throw new IllegalStateException("Disconnect the active VPN before changing persistent Router VPN profile settings.");
            JSONObject bundle = loadBundle(store);
            JSONObject profile = selectedProfile(bundle);
            if (profile == null) throw new IllegalStateException("Pair/import and select a Router VPN node first.");
            if ("external".equalsIgnoreCase(profile.optString("node_kind", "router-vpn"))) throw new IllegalStateException("External exits own their protocol settings.");

            LinearLayout body = new LinearLayout(activity); body.setOrientation(LinearLayout.VERTICAL); int p=dp(activity,16); body.setPadding(p,p,p,p);
            TextView note = new TextView(activity); note.setText("Persistent settings for the selected Router VPN node. SMART AUTO, IPv6 On and Auto measured MTU are the unified defaults. A live VPN blocks mutation. Saved values are preferences for supported runtimes, not runtime proof."); body.addView(note);
            CheckBox lan=check(activity,"Allow home LAN access",profile.optBoolean("home_lan_access",true)); body.addView(lan);
            Spinner kill=spinner(activity,new String[]{"Off","On connect","Always / strict"},index(new String[]{"off","on-connect","always"},profile.optString("kill_switch_policy","off"))); body.addView(label(activity,"Kill switch policy")); body.addView(kill);
            Spinner ipv6=spinner(activity,new String[]{"On — default","Auto","Off"},index(new String[]{"on","auto","off"},profile.optString("ipv6_mode","on"))); body.addView(label(activity,"IPv6 policy")); body.addView(ipv6);
            Spinner base=spinner(activity,new String[]{"Auto","WireGuard","AmneziaWG"},index(new String[]{"auto","wg","awg"},profile.optString("base_tunnel","auto"))); body.addView(label(activity,"WG/AWG base preference")); body.addView(base);
            CheckBox fallback=check(activity,"Allow WG/AWG base fallback",profile.optBoolean("base_fallback",false)); body.addView(fallback);

            body.addView(label(activity,"AUTO / SMART AUTO filters"));
            CheckBox requireEncrypted=check(activity,"Require encrypted",profile.optBoolean("auto_require_encrypted",false)); body.addView(requireEncrypted);
            CheckBox requireObfuscation=check(activity,"Require obfuscation",profile.optBoolean("auto_require_obfuscation",false)); body.addView(requireObfuscation);
            TextView filterNote=label(activity,"Both filters are Off by default. Enabled filters remove non-matching candidates before AUTO tries them; SMART cannot simplify below the selected requirements."); body.addView(filterNote);

            Spinner mtu=spinner(activity,new String[]{"Auto measured — default","Fixed / manual","Runtime default"},index(new String[]{"auto","manual","default"},profile.optString("mtu_policy","auto"))); body.addView(label(activity,"MTU policy")); body.addView(mtu);
            EditText manual=new EditText(activity); manual.setHint("Fixed MTU 576–9000"); manual.setInputType(InputType.TYPE_CLASS_NUMBER); int m=profile.optInt("manual_mtu",0); if(m>0)manual.setText(String.valueOf(m)); body.addView(manual);
            CheckBox daita=check(activity,"DAITA-like traffic padding (bounded; supported modes only)",profile.optBoolean("daita_enabled",false)); body.addView(daita);
            CheckBox jumbo=check(activity,"Jumbo TUN / jumbo packet mode (compatible paths only)",profile.optBoolean("jumbo_tun",false)); body.addView(jumbo);
            CheckBox socks=check(activity,"Private in-tunnel SOCKS5 utility",profile.optBoolean("socks_enabled",false)); body.addView(socks);
            TextView effective=label(activity,"Current effective MTU: "+(profile.optInt("effective_mtu",0)>0?profile.optInt("effective_mtu",0)+" • "+profile.optString("effective_mtu_source","measured"):"not measured yet; Auto will use a valid path/config-specific value")); body.addView(effective);

            Button forwarding=new Button(activity); forwarding.setAllCaps(false); forwarding.setText("Port forwarding / Protected DMZ"); forwarding.setOnClickListener(v->new AlertDialog.Builder(activity).setTitle("Port forwarding / Protected DMZ").setMessage("Incoming forwarding is owned by the authenticated private home-node Setup Center/router-agent. It is available only to routable tunnel modes; proxy-only paths never claim arbitrary DNAT. Configure it there, then validate it off-LAN.").setPositiveButton("OK",null).show()); body.addView(forwarding);
            Button mtuRetest=new Button(activity); mtuRetest.setAllCaps(false); mtuRetest.setText("MTU / Retest current path…"); mtuRetest.setOnClickListener(v->new AlertDialog.Builder(activity).setTitle("MTU Retest").setMessage("A real MTU Retest is meaningful only on the current selected node/config/path. Keep Auto measured for normal use. If no live path-specific tester is available on this Android runtime, Router VPN must not invent a result; the next proven connection keeps the last valid measurement or runtime default truthfully.").setPositiveButton("OK",null).show()); body.addView(mtuRetest);
            Button connectionProfiles=new Button(activity);connectionProfiles.setAllCaps(false);connectionProfiles.setText("Connection profiles — Add / Load / Update / Delete");connectionProfiles.setOnClickListener(v->AndroidConnectionProfilesDialog.show(activity,store,new AndroidStandardExitStore(activity),onSaved));body.addView(connectionProfiles);
            TextView profileNote=label(activity,"Connection profiles reference the selected Router/Custom node and copy only non-secret mode, DNS, kill-switch, IPv6, MTU and multihop choices. Node keys, API tokens and external credentials stay in their private node stores.");body.addView(profileNote);

            ScrollView scroll=new ScrollView(activity);scroll.addView(body);
            AlertDialog dialog=new AlertDialog.Builder(activity).setTitle("Settings").setView(scroll).setPositiveButton("Save",null).setNegativeButton("Cancel",null).create();
            dialog.setOnShowListener(x->dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
                try {
                    if (hasLiveVpn(activity)) throw new IllegalStateException("VPN became active while settings were open; disconnect and try again.");
                    String[] killValues={"off","on-connect","always"}, ipv6Values={"on","auto","off"}, baseValues={"auto","wg","awg"}, mtuValues={"auto","manual","default"};
                    int manualValue=manual.getText().toString().trim().isEmpty()?0:Integer.parseInt(manual.getText().toString().trim()); String mtuPolicy=mtuValues[mtu.getSelectedItemPosition()];
                    if("manual".equals(mtuPolicy)&&(manualValue<576||manualValue>9000))throw new IllegalArgumentException("Fixed MTU must be 576–9000."); if(!"manual".equals(mtuPolicy))manualValue=0;
                    profile.put("home_lan_access",lan.isChecked());
                    profile.put("kill_switch_policy",killValues[kill.getSelectedItemPosition()]); profile.put("kill_switch",!"off".equals(killValues[kill.getSelectedItemPosition()]));
                    profile.put("ipv6_mode",ipv6Values[ipv6.getSelectedItemPosition()]);
                    profile.put("base_tunnel",baseValues[base.getSelectedItemPosition()]); profile.put("base_fallback",fallback.isChecked());
                    profile.put("auto_require_encrypted",requireEncrypted.isChecked()); profile.put("auto_require_obfuscation",requireObfuscation.isChecked());
                    profile.put("mtu_policy",mtuPolicy); profile.put("manual_mtu",manualValue);
                    profile.put("daita_enabled",daita.isChecked()); profile.put("jumbo_tun",jumbo.isChecked()); profile.put("socks_enabled",socks.isChecked());
                    if(!profile.has("startup_mode")||profile.optString("startup_mode","").trim().isEmpty())profile.put("startup_mode","smart-auto");
                    store.importBundle(bundle.toString().getBytes(StandardCharsets.UTF_8));
                    Toast.makeText(activity,"Settings saved for the next supported connection.",Toast.LENGTH_LONG).show(); dialog.dismiss(); if(onSaved!=null)onSaved.run();
                } catch(Throwable error){Toast.makeText(activity,"Settings save failed: "+safe(error),Toast.LENGTH_LONG).show();}
            }));
            dialog.show();
        } catch(Throwable error){
            new AlertDialog.Builder(activity).setTitle("Settings").setMessage("Router-node settings unavailable: "+safe(error)+"\n\nConnection profiles remain available for linked Router or Custom/external nodes while disconnected.")
                    .setPositiveButton("Connection profiles",(d,w)->AndroidConnectionProfilesDialog.show(activity,store,new AndroidStandardExitStore(activity),onSaved)).setNegativeButton("Close",null).show();
        }
    }

    private static boolean hasLiveVpn(Context context) {
        ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE); if(cm==null)return false;
        Network network=cm.getActiveNetwork(); if(network==null)return false;
        NetworkCapabilities caps=cm.getNetworkCapabilities(network); if(caps==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return false;
        if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.Q){int owner=caps.getOwnerUid();return owner==Process.myUid()||owner<0;}
        return true;
    }
    private static JSONObject loadBundle(AndroidNodeStore store)throws Exception{String id=store.activeId();if(id==null||id.isEmpty())throw new IllegalStateException("Select a Router VPN node first.");try(FileInputStream in=new FileInputStream(store.file(id));ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[8192];int n,total=0;while((n=in.read(b))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Private node bundle exceeds safety limit.");out.write(b,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private static JSONObject selectedProfile(JSONObject bundle){JSONArray a=bundle.optJSONArray("routerProfiles");String id=bundle.optString("selectedRouterID","");if(a==null)return null;for(int i=0;i<a.length();i++){JSONObject p=a.optJSONObject(i);if(p!=null&&id.equals(p.optString("id")))return p;}return a.length()>0?a.optJSONObject(0):null;}
    private static Spinner spinner(Activity a,String[]items,int selected){Spinner s=new Spinner(a);s.setAdapter(new ArrayAdapter<>(a,android.R.layout.simple_spinner_dropdown_item,items));s.setSelection(Math.max(0,Math.min(selected,items.length-1)));return s;}
    private static CheckBox check(Activity a,String text,boolean value){CheckBox c=new CheckBox(a);c.setText(text);c.setChecked(value);return c;}
    private static TextView label(Activity a,String text){TextView v=new TextView(a);v.setText(text);v.setPadding(0,dp(a,8),0,0);return v;}
    private static int index(String[]values,String value){for(int i=0;i<values.length;i++)if(values[i].equalsIgnoreCase(value))return i;return 0;}
    private static int dp(Activity a,int v){return Math.round(v*a.getResources().getDisplayMetrics().density);}
    private static String safe(Throwable e){String v=e==null?"":e.getMessage();return v==null||v.trim().isEmpty()?"Router VPN error":v.trim();}
    private AndroidProfileSettingsDialog(){}
}
