package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.net.Uri;
import android.net.VpnService;
import android.os.Bundle;
import android.provider.Settings;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import com.wireguard.android.backend.Tunnel;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

public final class MainActivity extends Activity {
    private static final int IMPORT_BUNDLE = 1001;
    private static final int PREPARE_NATIVE_WG = 1002;
    private static final int PREPARE_NATIVE_AWG = 1003;
    private static final String BUNDLE_FILE = "router-vpn-bundle.json";
    private static final String PREFS = "router-vpn";
    private static final String ONBOARDING_DONE = "onboarding_done_v3";
    private static final String ONBOARDING_STEP = "onboarding_step_v3";
    private static final int ONBOARDING_LAST_STEP = 10;

    private TextView statusView, endpointView, socksView, modesView, nativeStatusView;
    private Button nativeConnectButton, nativeDisconnectButton, awgConnectButton, awgDisconnectButton;
    private String socksAddress = "";
    private NativeWireGuardController wireGuard;
    private NativeAmneziaWGController amneziaWG;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        wireGuard = new NativeWireGuardController(this);
        amneziaWG = new NativeAmneziaWGController(this);
        setContentView(buildUi());
        loadSavedBundle();
        refreshNativeState();
        if (!prefs().getBoolean(ONBOARDING_DONE, false)) showOnboarding(false);
    }

    @Override protected void onDestroy() {
        if (wireGuard != null) wireGuard.close();
        if (amneziaWG != null) amneziaWG.close();
        super.onDestroy();
    }

    private View buildUi() {
        int pad = dp(20);
        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        content.setPadding(pad, pad, pad, pad);
        content.addView(text("Router VPN", 28, true));
        statusView = text("Import or pair a private Router VPN node.", 16, false);
        content.addView(statusView, margins(0, dp(12), 0, dp(12)));
        Button importButton = button("Import router bundle"); importButton.setOnClickListener(v -> openBundlePicker()); content.addView(importButton);
        nativeConnectButton = button("Connect native WireGuard"); nativeConnectButton.setOnClickListener(v -> requestNativeWireGuard()); content.addView(nativeConnectButton, margins(0, dp(8), 0, 0));
        nativeDisconnectButton = button("Disconnect native WireGuard"); nativeDisconnectButton.setOnClickListener(v -> disconnectNativeWireGuard()); content.addView(nativeDisconnectButton, margins(0, dp(8), 0, 0));
        awgConnectButton = button("Connect native AmneziaWG 2"); awgConnectButton.setOnClickListener(v -> requestNativeAmneziaWG()); content.addView(awgConnectButton, margins(0, dp(8), 0, 0));
        awgDisconnectButton = button("Disconnect native AmneziaWG 2"); awgDisconnectButton.setOnClickListener(v -> disconnectNativeAmneziaWG()); content.addView(awgDisconnectButton, margins(0, dp(8), 0, 0));
        Button copyButton = button("Copy SOCKS5 IP:port"); copyButton.setOnClickListener(v -> copySocks()); content.addView(copyButton, margins(0, dp(8), 0, 0));
        Button settingsButton = button("Open Android VPN settings"); settingsButton.setOnClickListener(v -> startActivity(new Intent(Settings.ACTION_VPN_SETTINGS))); content.addView(settingsButton, margins(0, dp(8), 0, 0));
        Button checksButton = button("Run setup check"); checksButton.setOnClickListener(v -> showSetupCheck()); content.addView(checksButton, margins(0, dp(8), 0, 0));
        Button onboardingButton = button("Run full onboarding again"); onboardingButton.setOnClickListener(v -> showOnboarding(true)); content.addView(onboardingButton, margins(0, dp(8), 0, 0));
        endpointView = section("Endpoint", "Not imported"); content.addView(endpointView, margins(0, dp(20), 0, 0));
        socksView = section("SOCKS5", "Not imported"); content.addView(socksView, margins(0, dp(12), 0, 0));
        nativeStatusView = section("Native Android VPN", "WireGuard / AmneziaWG states: checking"); content.addView(nativeStatusView, margins(0, dp(12), 0, 0));
        modesView = section("Modes in bundle", "Not imported"); content.addView(modesView, margins(0, dp(12), 0, 0));
        TextView limitation = section("Android capability boundary",
            "Raw WireGuard and AmneziaWG 2 now have real full-device Android VPN paths through their official embedded userspace backends. " +
            "This build does not fake a live all-mode VPN connection: Xray/sing-box layered modes, SMART AUTO/ALL/CUSTOM native execution, strict kill-switch semantics, multihop, and automatic reconnect are still unavailable and are not represented as connected. " +
            "Public auxiliary ports are OverTLS 14443 and ShadowsocksR 15443; loopback backend 14444 is never a WAN client port. SOCKS5 remains tunnel/LAN-only; never expose TCP 1080 to WAN.");
        content.addView(limitation, margins(0, dp(20), 0, dp(20)));
        ScrollView scroll = new ScrollView(this); scroll.addView(content); return scroll;
    }

    private SharedPreferences prefs() { return getSharedPreferences(PREFS, MODE_PRIVATE); }
    private void showOnboarding(boolean restart) {
        if (restart) prefs().edit().putBoolean(ONBOARDING_DONE, false).putInt(ONBOARDING_STEP, 0).apply();
        showOnboardingStep(Math.max(0, Math.min(ONBOARDING_LAST_STEP, prefs().getInt(ONBOARDING_STEP, 0))));
    }
    private void showOnboardingStep(final int step) {
        AlertDialog.Builder builder = new AlertDialog.Builder(this).setTitle("Router VPN setup — " + (step + 1) + "/" + (ONBOARDING_LAST_STEP + 1)).setMessage(onboardingText(step)).setNegativeButton("Close for now", (d,w) -> d.dismiss());
        if (step > 0) builder.setNeutralButton(step == 5 ? "Import bundle" : step == 9 ? "Run setup check" : "Back", null);
        builder.setPositiveButton(step == ONBOARDING_LAST_STEP ? "Finish" : "Next", null);
        AlertDialog dialog = builder.create();
        dialog.setOnShowListener(ignored -> {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v -> {
                if (step == ONBOARDING_LAST_STEP) { prefs().edit().putBoolean(ONBOARDING_DONE,true).putInt(ONBOARDING_STEP,0).apply(); dialog.dismiss(); Toast.makeText(this,"Onboarding complete",Toast.LENGTH_SHORT).show(); }
                else { int next=step+1; prefs().edit().putInt(ONBOARDING_STEP,next).apply(); dialog.dismiss(); showOnboardingStep(next); }
            });
            if (step > 0) dialog.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v -> {
                if (step == 5) { dialog.dismiss(); openBundlePicker(); }
                else if (step == 9) showSetupCheck();
                else { int previous=step-1; prefs().edit().putInt(ONBOARDING_STEP,previous).apply(); dialog.dismiss(); showOnboardingStep(previous); }
            });
        });
        dialog.show();
    }
    private String onboardingText(int step) {
        switch (step) {
            case 0: return "Complete path: home node → authenticated Setup Center → node import/pairing → Android VPN permission → native WireGuard/AmneziaWG → optional tests. Progress is saved; only Finish marks completion.";
            case 1: return "Deploy the home node in Portainer using server/portainer-current.yaml. Production server services stay exact-image/SHA pinned; ENDPOINT can remain blank for detection.";
            case 2: return "Verify router-vpn-init/finalize completed and long-running services are healthy before WAN exposure. Optional host check: sudo bash server/scripts/doctor-current.sh.";
            case 3: return "On your home LAN open http://AI_BOARD_IP:8786/. Setup Center is authenticated because it can expose private node material. Keep its permanent token router-local; use it only for the browser or a short-lived pairing code.";
            case 4: return "ASUS WAN forwarding is installed with the Setup Center helper. Public auxiliary transports are 14443 (OverTLS) and 15443 (ShadowsocksR). Never expose 1080, 8786, 8787, 14444, 9443, SSH, Portainer, AdGuard admin, or the Setup Center credential itself.";
            case 5: return "Link this Android app by importing router-vpn-bundle.json. One-time LAN pairing is also a supported backend path; the permanent Setup Center credential is never stored in the node bundle.";
            case 6: return "Android asks for system VPN consent the first time a native base tunnel starts. WireGuard and AmneziaWG each create a real Android VPN interface from the imported raw profile, including the profile's full routes and DNS.";
            case 7: return "Choose Connect native WireGuard or Connect native AmneziaWG 2. Only one base tunnel may be active at a time. A successful UP state comes from that backend, not from a fake UI toggle.";
            case 8: return "SOCKS5 is ordinary IP + port behind the tunnel. Layered Xray/sing-box, DAITA-like/Jumbo policy, strict kill switch, multihop, SMART AUTO/ALL/CUSTOM and reconnect remain capability-gated on Android until their runtime adapters pass end-to-end tests.";
            case 9: return "Run setup check here, doctor-current.sh on the AI Board, and /jffs/scripts/router-vpn-forward.sh status on ASUS. A base tunnel counts live only after its Android backend reports UP; generic UDP port checks do not prove a tunnel.";
            default: return "Finish keeps onboarding dismissed. Native Android WireGuard and AmneziaWG 2 are available; Xray/sing-box layered modes are still intentionally unavailable rather than faked.";
        }
    }

    private void showSetupCheck() { new AlertDialog.Builder(this).setTitle("Router VPN setup check").setMessage(setupCheckText()).setPositiveButton("OK",null).show(); }
    private String setupCheckText() {
        StringBuilder result = new StringBuilder();
        try (FileInputStream input = openFileInput(BUNDLE_FILE)) {
            JSONObject bundle = new JSONObject(new String(readLimited(input,32*1024*1024),StandardCharsets.UTF_8)); validateBundle(bundle);
            String endpoint=bundle.optString("endpoint","").trim(), socksHost=bundle.optString("socks5Host","").trim(); int socksPort=bundle.optInt("socks5Port",1080); JSONArray modes=bundle.optJSONArray("modes");
            result.append("✓ Router bundle imported\n"); result.append(endpoint.isEmpty()?"! Public endpoint is blank\n":"✓ Public endpoint configured\n"); result.append(!socksHost.isEmpty()&&socksPort>0?"✓ SOCKS5 IP + port configured\n":"✗ SOCKS5 settings incomplete\n");
            result.append(hasRawWireGuard(bundle)?"✓ Raw WireGuard profile available\n":"! Raw WireGuard profile missing\n"); result.append(hasRawAmneziaWG(bundle)?"✓ Raw AmneziaWG 2 profile available\n":"! Raw AmneziaWG 2 profile missing\n");
            boolean hasAll=hasMode(modes,"all"),hasSmart=hasMode(modes,"smart-auto"),hasCustom=hasMode(modes,"custom"); result.append(hasAll&&hasSmart&&hasCustom?"✓ Bundle catalogs ALL / SMART AUTO / CUSTOM\n":"! Utility mode catalog incomplete\n");
        } catch (Exception error) { result.append("✗ Import/link a Router VPN node first\n"); }
        Tunnel.State wgState=wireGuard==null?Tunnel.State.DOWN:wireGuard.getState(); org.amnezia.awg.backend.Tunnel.State awgState=amneziaWG==null?org.amnezia.awg.backend.Tunnel.State.DOWN:amneziaWG.getState();
        result.append(wgState==Tunnel.State.UP?"✓ Native Android WireGuard state is UP\n":"ℹ Native Android WireGuard state is "+wgState+"\n"); result.append(awgState==org.amnezia.awg.backend.Tunnel.State.UP?"✓ Native Android AmneziaWG state is UP\n":"ℹ Native Android AmneziaWG state is "+awgState+"\n");
        result.append("ℹ Server: server/scripts/doctor-current.sh\nℹ ASUS: /jffs/scripts/router-vpn-forward.sh status\nℹ Xray/sing-box layered native adapters remain unavailable and are not counted as live."); return result.toString();
    }

    private boolean hasRawWireGuard(JSONObject bundle) { JSONObject p=bundle.optJSONObject("profiles"),wg=p==null?null:p.optJSONObject("wg"); return wg!=null&&!wg.optString("wg.conf","").trim().isEmpty(); }
    private boolean hasRawAmneziaWG(JSONObject bundle) { JSONObject p=bundle.optJSONObject("profiles"); if(p==null)return false; JSONObject a=p.optJSONObject("awg2-fast"); if(a==null)a=p.optJSONObject("awg2-strong"); return a!=null&&!a.optString("awg.conf","").trim().isEmpty(); }
    private boolean hasMode(JSONArray modes,String id){ if(modes==null)return false; for(int i=0;i<modes.length();i++){JSONObject m=modes.optJSONObject(i);if(m!=null&&id.equals(m.optString("id","")))return true;}return false; }

    private void requestNativeWireGuard(){ if(amneziaWG.getState()==org.amnezia.awg.backend.Tunnel.State.UP){Toast.makeText(this,"Disconnect AmneziaWG before starting WireGuard",Toast.LENGTH_SHORT).show();return;} if(!getFileStreamPath(BUNDLE_FILE).isFile()){Toast.makeText(this,"Import/link a Router VPN node first",Toast.LENGTH_SHORT).show();return;} Intent p=VpnService.prepare(this); if(p!=null){statusView.setText("Waiting for Android VPN permission…");startActivityForResult(p,PREPARE_NATIVE_WG);}else connectNativeWireGuard(); }
    private void requestNativeAmneziaWG(){ if(wireGuard.getState()==Tunnel.State.UP){Toast.makeText(this,"Disconnect WireGuard before starting AmneziaWG",Toast.LENGTH_SHORT).show();return;} if(!getFileStreamPath(BUNDLE_FILE).isFile()){Toast.makeText(this,"Import/link a Router VPN node first",Toast.LENGTH_SHORT).show();return;} Intent p=VpnService.prepare(this); if(p!=null){statusView.setText("Waiting for Android VPN permission…");startActivityForResult(p,PREPARE_NATIVE_AWG);}else connectNativeAmneziaWG(); }
    private void connectNativeWireGuard(){setWireGuardBusy(true,"WireGuard state: connecting…");wireGuard.connect(getFileStreamPath(BUNDLE_FILE),(state,message,error)->runOnUiThread(()->{setWireGuardBusy(false,"WireGuard state: "+state+"\n"+message);statusView.setText(error==null&&state==Tunnel.State.UP?"Native Android WireGuard connected.":message);if(error!=null)Toast.makeText(this,message,Toast.LENGTH_LONG).show();refreshNativeState();}));}
    private void connectNativeAmneziaWG(){setAwgBusy(true,"AmneziaWG state: connecting…");amneziaWG.connect(getFileStreamPath(BUNDLE_FILE),(state,message,error)->runOnUiThread(()->{setAwgBusy(false,"AmneziaWG state: "+state+"\n"+message);statusView.setText(error==null&&state==org.amnezia.awg.backend.Tunnel.State.UP?"Native Android AmneziaWG 2 connected.":message);if(error!=null)Toast.makeText(this,message,Toast.LENGTH_LONG).show();refreshNativeState();}));}
    private void disconnectNativeWireGuard(){setWireGuardBusy(true,"WireGuard state: disconnecting…");wireGuard.disconnect((state,message,error)->runOnUiThread(()->{setWireGuardBusy(false,"WireGuard state: "+state+"\n"+message);statusView.setText(message);if(error!=null)Toast.makeText(this,message,Toast.LENGTH_LONG).show();refreshNativeState();}));}
    private void disconnectNativeAmneziaWG(){setAwgBusy(true,"AmneziaWG state: disconnecting…");amneziaWG.disconnect((state,message,error)->runOnUiThread(()->{setAwgBusy(false,"AmneziaWG state: "+state+"\n"+message);statusView.setText(message);if(error!=null)Toast.makeText(this,message,Toast.LENGTH_LONG).show();refreshNativeState();}));}
    private void refreshNativeState(){if(nativeStatusView==null||wireGuard==null||amneziaWG==null)return;Tunnel.State w=wireGuard.getState();org.amnezia.awg.backend.Tunnel.State a=amneziaWG.getState();nativeStatusView.setText("Native Android VPN\nWireGuard state: "+w+"\nAmneziaWG 2 state: "+a+"\nRaw base tunnels are native; layered mode engines remain unavailable.");nativeDisconnectButton.setEnabled(w==Tunnel.State.UP);awgDisconnectButton.setEnabled(a==org.amnezia.awg.backend.Tunnel.State.UP);nativeConnectButton.setEnabled(a!=org.amnezia.awg.backend.Tunnel.State.UP);awgConnectButton.setEnabled(w!=Tunnel.State.UP);}
    private void setWireGuardBusy(boolean busy,String text){nativeConnectButton.setEnabled(!busy);nativeDisconnectButton.setEnabled(!busy);nativeStatusView.setText("Native Android VPN\n"+text);if(!busy)refreshNativeState();}
    private void setAwgBusy(boolean busy,String text){awgConnectButton.setEnabled(!busy);awgDisconnectButton.setEnabled(!busy);nativeStatusView.setText("Native Android VPN\n"+text);if(!busy)refreshNativeState();}

    private void openBundlePicker(){Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType("application/json");startActivityForResult(i,IMPORT_BUNDLE);}
    @Override protected void onActivityResult(int requestCode,int resultCode,Intent data){super.onActivityResult(requestCode,resultCode,data);if(requestCode==PREPARE_NATIVE_WG){if(resultCode==RESULT_OK)connectNativeWireGuard();else statusView.setText("Android VPN permission was not granted; native WireGuard stayed disconnected.");return;}if(requestCode==PREPARE_NATIVE_AWG){if(resultCode==RESULT_OK)connectNativeAmneziaWG();else statusView.setText("Android VPN permission was not granted; native AmneziaWG stayed disconnected.");return;}if(requestCode!=IMPORT_BUNDLE||resultCode!=RESULT_OK||data==null)return;Uri uri=data.getData();if(uri==null)return;try(InputStream input=getContentResolver().openInputStream(uri)){if(input==null)throw new IllegalStateException("Unable to open selected file");byte[] bytes=readLimited(input,32*1024*1024);JSONObject bundle=new JSONObject(new String(bytes,StandardCharsets.UTF_8));validateBundle(bundle);try(FileOutputStream output=openFileOutput(BUNDLE_FILE,MODE_PRIVATE)){output.write(bytes);}renderBundle(bundle);Toast.makeText(this,"Router node imported",Toast.LENGTH_SHORT).show();if(!prefs().getBoolean(ONBOARDING_DONE,false))showOnboarding(false);}catch(Exception error){statusView.setText("Import failed: "+error.getMessage());}}
    private void loadSavedBundle(){try(FileInputStream input=openFileInput(BUNDLE_FILE)){JSONObject bundle=new JSONObject(new String(readLimited(input,32*1024*1024),StandardCharsets.UTF_8));validateBundle(bundle);renderBundle(bundle);}catch(Exception ignored){statusView.setText("No private Router VPN node linked yet.");}}
    private void validateBundle(JSONObject bundle){if(!bundle.has("profiles")||!bundle.has("modes"))throw new IllegalArgumentException("This is not a Router VPN node bundle");if(!hasRawWireGuard(bundle)&&!hasRawAmneziaWG(bundle))throw new IllegalArgumentException("Router VPN node bundle has no native raw WireGuard/AmneziaWG profile");}
    private void renderBundle(JSONObject bundle){String endpoint=bundle.optString("endpoint","").trim(),socksHost=bundle.optString("socks5Host","10.77.0.1").trim();int socksPort=bundle.optInt("socks5Port",1080);socksAddress=socksHost+":"+socksPort;endpointView.setText("Endpoint\n"+(endpoint.isEmpty()?"Choose/configure in client":endpoint));socksView.setText("SOCKS5\n"+socksAddress+"\nAuthentication: none (tunnel/LAN only)");JSONArray modes=bundle.optJSONArray("modes");StringBuilder names=new StringBuilder();if(modes!=null)for(int i=0;i<modes.length();i++){JSONObject item=modes.optJSONObject(i);if(item==null)continue;if(names.length()>0)names.append('\n');names.append(item.optString("name",item.optString("id","unknown")));}modesView.setText("Modes in bundle\n"+(names.length()==0?"None":names));String eligible=(hasRawWireGuard(bundle)?"WireGuard ":"")+(hasRawAmneziaWG(bundle)?"AmneziaWG 2":"");statusView.setText("Private node stored in Android app-private storage. Native base tunnel(s): "+eligible.trim()+".");refreshNativeState();}
    private void copySocks(){if(socksAddress.isEmpty()){Toast.makeText(this,"Import the router bundle first",Toast.LENGTH_SHORT).show();return;}ClipboardManager c=(ClipboardManager)getSystemService(Context.CLIPBOARD_SERVICE);c.setPrimaryClip(ClipData.newPlainText("Router VPN SOCKS5",socksAddress));Toast.makeText(this,"Copied "+socksAddress,Toast.LENGTH_SHORT).show();}
    private static byte[] readLimited(InputStream input,int maxBytes)throws Exception{ByteArrayOutputStream output=new ByteArrayOutputStream();byte[] buffer=new byte[8192];int total=0,read;while((read=input.read(buffer))!=-1){total+=read;if(total>maxBytes)throw new IllegalArgumentException("Bundle is larger than 32 MB");output.write(buffer,0,read);}return output.toByteArray();}
    private TextView text(String value,int sp,boolean bold){TextView view=new TextView(this);view.setText(value);view.setTextSize(sp);if(bold)view.setTypeface(view.getTypeface(),android.graphics.Typeface.BOLD);return view;}
    private TextView section(String heading,String value){TextView view=text(heading+"\n"+value,16,false);view.setPadding(dp(14),dp(14),dp(14),dp(14));view.setBackgroundColor(0xffeeeeee);return view;}
    private Button button(String label){Button button=new Button(this);button.setText(label);button.setAllCaps(false);button.setGravity(Gravity.CENTER);return button;}
    private LinearLayout.LayoutParams margins(int left,int top,int right,int bottom){LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(LinearLayout.LayoutParams.MATCH_PARENT,LinearLayout.LayoutParams.WRAP_CONTENT);p.setMargins(left,top,right,bottom);return p;}
    private int dp(int value){return Math.round(value*getResources().getDisplayMetrics().density);}
}
