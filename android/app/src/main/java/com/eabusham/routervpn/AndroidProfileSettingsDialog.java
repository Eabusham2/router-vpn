package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.text.InputType;
import android.widget.ArrayAdapter;
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
            JSONObject bundle = loadBundle(store);
            JSONObject profile = selectedProfile(bundle);
            if (profile == null) throw new IllegalStateException("Pair/import and select a Router VPN node first.");
            if ("external".equalsIgnoreCase(profile.optString("node_kind", "router-vpn"))) throw new IllegalStateException("External exits own their protocol settings.");

            LinearLayout body = new LinearLayout(activity); body.setOrientation(LinearLayout.VERTICAL); int p=dp(activity,16); body.setPadding(p,p,p,p);
            TextView note = new TextView(activity); note.setText("Persistent settings for the selected Router VPN node. Disconnect before changing a live tunnel. Saved values are preferences for supported runtimes, not runtime proof."); body.addView(note);
            CheckBox lan=check(activity,"Allow home LAN access",profile.optBoolean("home_lan_access",true)); body.addView(lan);
            Spinner kill=spinner(activity,new String[]{"Off","On connect","Always / strict"},index(new String[]{"off","on-connect","always"},profile.optString("kill_switch_policy","off"))); body.addView(label(activity,"Kill switch policy")); body.addView(kill);
            Spinner ipv6=spinner(activity,new String[]{"Auto","On","Off"},index(new String[]{"auto","on","off"},profile.optString("ipv6_mode","auto"))); body.addView(label(activity,"IPv6 policy")); body.addView(ipv6);
            Spinner base=spinner(activity,new String[]{"Auto","WireGuard","AmneziaWG"},index(new String[]{"auto","wg","awg"},profile.optString("base_tunnel","auto"))); body.addView(label(activity,"WG/AWG base preference")); body.addView(base);
            CheckBox fallback=check(activity,"Allow WG/AWG base fallback",profile.optBoolean("base_fallback",false)); body.addView(fallback);
            Spinner mtu=spinner(activity,new String[]{"Default","Auto measured","Manual"},index(new String[]{"default","auto","manual"},profile.optString("mtu_policy","default"))); body.addView(label(activity,"MTU policy")); body.addView(mtu);
            EditText manual=new EditText(activity); manual.setHint("Manual MTU 576–9000"); manual.setInputType(InputType.TYPE_CLASS_NUMBER); int m=profile.optInt("manual_mtu",0); if(m>0)manual.setText(String.valueOf(m)); body.addView(manual);
            CheckBox daita=check(activity,"DAITA-like bounded cover traffic (supported modes only)",profile.optBoolean("daita_enabled",false)); body.addView(daita);
            CheckBox jumbo=check(activity,"Jumbo TUN (compatible TUN/proxy paths only)",profile.optBoolean("jumbo_tun",false)); body.addView(jumbo);
            CheckBox socks=check(activity,"Private in-tunnel SOCKS5 utility",profile.optBoolean("socks_enabled",false)); body.addView(socks);
            TextView effective=label(activity,"Current effective MTU: "+(profile.optInt("effective_mtu",0)>0?profile.optInt("effective_mtu",0)+" • "+profile.optString("effective_mtu_source","measured"):"default/not measured")); body.addView(effective);
            ScrollView scroll=new ScrollView(activity);scroll.addView(body);
            AlertDialog dialog=new AlertDialog.Builder(activity).setTitle("Advanced profile settings").setView(scroll).setPositiveButton("Save",null).setNegativeButton("Cancel",null).create();
            dialog.setOnShowListener(x->dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
                try {
                    String[] killValues={"off","on-connect","always"}, ipv6Values={"auto","on","off"}, baseValues={"auto","wg","awg"}, mtuValues={"default","auto","manual"};
                    int manualValue=manual.getText().toString().trim().isEmpty()?0:Integer.parseInt(manual.getText().toString().trim()); String mtuPolicy=mtuValues[mtu.getSelectedItemPosition()];
                    if("manual".equals(mtuPolicy)&&(manualValue<576||manualValue>9000))throw new IllegalArgumentException("Manual MTU must be 576–9000."); if(!"manual".equals(mtuPolicy))manualValue=0;
                    profile.put("home_lan_access",lan.isChecked()); profile.put("kill_switch_policy",killValues[kill.getSelectedItemPosition()]); profile.put("kill_switch",!"off".equals(killValues[kill.getSelectedItemPosition()])); profile.put("ipv6_mode",ipv6Values[ipv6.getSelectedItemPosition()]); profile.put("base_tunnel",baseValues[base.getSelectedItemPosition()]); profile.put("base_fallback",fallback.isChecked()); profile.put("mtu_policy",mtuPolicy); profile.put("manual_mtu",manualValue); profile.put("daita_enabled",daita.isChecked()); profile.put("jumbo_tun",jumbo.isChecked()); profile.put("socks_enabled",socks.isChecked());
                    store.importBundle(bundle.toString().getBytes(StandardCharsets.UTF_8));
                    Toast.makeText(activity,"Profile settings saved for the next supported connection.",Toast.LENGTH_LONG).show(); dialog.dismiss(); if(onSaved!=null)onSaved.run();
                } catch(Throwable error){Toast.makeText(activity,"Settings save failed: "+safe(error),Toast.LENGTH_LONG).show();}
            }));
            dialog.show();
        } catch(Throwable error){Toast.makeText(activity,"Settings unavailable: "+safe(error),Toast.LENGTH_LONG).show();}
    }

    private static JSONObject loadBundle(AndroidNodeStore store)throws Exception{String id=store.activeId();if(id==null||id.isEmpty())throw new IllegalStateException("Select a Router VPN node first.");try(FileInputStream in=new FileInputStream(store.file(id));ByteArrayOutputStream out=new ByteArrayOutputStream()){byte[]b=new byte[8192];int n,total=0;while((n=in.read(b))!=-1){total+=n;if(total>AndroidNodeStore.MAX_BUNDLE)throw new IllegalStateException("Private node bundle exceeds safety limit.");out.write(b,0,n);}return new JSONObject(new String(out.toByteArray(),StandardCharsets.UTF_8));}}
    private static JSONObject selectedProfile(JSONObject bundle){JSONArray a=bundle.optJSONArray("routerProfiles");String id=bundle.optString("selectedRouterID","");if(a==null)return null;for(int i=0;i<a.length();i++){JSONObject p=a.optJSONObject(i);if(p!=null&&id.equals(p.optString("id")))return p;}return a.length()>0?a.optJSONObject(0):null;}
    private static Spinner spinner(Activity a,String[]items,int selected){Spinner s=new Spinner(a);s.setAdapter(new ArrayAdapter<>(a,android.R.layout.simple_spinner_dropdown_item,items));s.setSelection(Math.max(0,Math.min(selected,items.length-1)));return s;}
    private static CheckBox check(Activity a,String text,boolean value){CheckBox c=new CheckBox(a);c.setText(text);c.setChecked(value);return c;} private static TextView label(Activity a,String text){TextView v=new TextView(a);v.setText(text);v.setPadding(0,dp(a,8),0,0);return v;}
    private static int index(String[]values,String value){for(int i=0;i<values.length;i++)if(values[i].equalsIgnoreCase(value))return i;return 0;} private static int dp(Activity a,int v){return Math.round(v*a.getResources().getDisplayMetrics().density);} private static String safe(Throwable e){String v=e==null?"":e.getMessage();return v==null||v.trim().isEmpty()?"Router VPN error":v.trim();}
    private AndroidProfileSettingsDialog(){}
}
