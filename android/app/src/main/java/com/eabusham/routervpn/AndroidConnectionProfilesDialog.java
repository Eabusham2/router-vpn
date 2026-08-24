package com.eabusham.routervpn;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Context;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.os.Build;
import android.os.Process;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.Spinner;
import android.widget.TextView;

import java.util.ArrayList;
import java.util.List;

/** Native Android Add / Load / Update / Delete UI for complete connection-choice profiles. */
final class AndroidConnectionProfilesDialog {
    static void show(Activity activity,AndroidNodeStore nodes,AndroidStandardExitStore exits,Runnable onChanged){new Controller(activity,nodes,exits,onChanged).show();}

    private static final class Controller {
        final Activity activity; final AndroidConnectionProfileStore store; final Runnable onChanged;
        final EditText name; final Spinner profiles; final TextView status; final ArrayAdapter<AndroidConnectionProfileStore.Record> adapter; final List<AndroidConnectionProfileStore.Record> records=new ArrayList<>();
        Controller(Activity activity,AndroidNodeStore nodes,AndroidStandardExitStore exits,Runnable onChanged){this.activity=activity;this.store=new AndroidConnectionProfileStore(activity,nodes,exits);this.onChanged=onChanged;name=new EditText(activity);profiles=new Spinner(activity);status=new TextView(activity);adapter=new ArrayAdapter<>(activity,android.R.layout.simple_spinner_dropdown_item,records);profiles.setAdapter(adapter);}

        void show(){
            LinearLayout body=new LinearLayout(activity);body.setOrientation(LinearLayout.VERTICAL);int p=dp(16);body.setPadding(p,p,p,p);
            TextView note=new TextView(activity);note.setText("Save/load the selected Router or Custom node plus current Mode/CUSTOM layers, DNS, kill switch, IPv6, WG/AWG base/fallback, AUTO encryption/obfuscation requirements, MTU, DAITA/Jumbo/SOCKS policy where supported, and multihop choices. Linked node keys, API tokens and external credentials are never copied into these profiles. Load restores choices only; Connect still has to establish and prove the real VPN path.");body.addView(note);
            name.setHint("Profile name");body.addView(name);body.addView(profiles);
            LinearLayout row=new LinearLayout(activity);row.setOrientation(LinearLayout.HORIZONTAL);
            Button add=button("Add"),load=button("Load"),update=button("Update"),delete=button("Delete"),refresh=button("Refresh");row.addView(add);row.addView(load);row.addView(update);row.addView(delete);row.addView(refresh);body.addView(row);status.setPadding(0,dp(8),0,0);body.addView(status);
            boolean live=hasLiveVpn(activity);name.setEnabled(!live);profiles.setEnabled(!live);add.setEnabled(!live);load.setEnabled(!live);update.setEnabled(!live);delete.setEnabled(!live);
            profiles.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener(){public void onNothingSelected(android.widget.AdapterView<?>p){}public void onItemSelected(android.widget.AdapterView<?>p,android.view.View v,int pos,long id){if(pos>=0&&pos<records.size())name.setText(records.get(pos).name);}});
            add.setOnClickListener(v->write(false));update.setOnClickListener(v->write(true));load.setOnClickListener(v->load());delete.setOnClickListener(v->delete());refresh.setOnClickListener(v->refresh());
            refresh();if(live)status.setText("Disconnect Router VPN before Add / Load / Update / Delete. Refresh remains available while connected.");new AlertDialog.Builder(activity).setTitle("Connection profiles").setView(body).setPositiveButton("Close",null).show();
        }

        void refresh(){try{records.clear();records.addAll(store.list());adapter.notifyDataSetChanged();if(!records.isEmpty())profiles.setSelection(0);status.setText(records.size()+" saved connection profile(s).");}catch(Throwable error){status.setText("Refresh failed: "+safe(error));}}
        AndroidConnectionProfileStore.Record selected(){int i=profiles.getSelectedItemPosition();return i>=0&&i<records.size()?records.get(i):null;}
        void write(boolean updating){try{if(hasLiveVpn(activity))throw new IllegalStateException("Disconnect Router VPN before changing connection profiles.");String clean=name.getText().toString().trim();AndroidConnectionProfileStore.Record result;if(updating){AndroidConnectionProfileStore.Record current=selected();if(current==null)throw new IllegalStateException("Select a saved profile first.");result=store.update(current.id,clean);}else result=store.add(clean);status.setText((updating?"Updated ":"Added ")+result.name+" • "+result.mode);refresh();if(onChanged!=null)onChanged.run();}catch(Throwable error){status.setText((updating?"Update":"Add")+" failed: "+safe(error));}}
        void load(){try{if(hasLiveVpn(activity))throw new IllegalStateException("Disconnect Router VPN before loading a connection profile.");AndroidConnectionProfileStore.Record current=selected();if(current==null)throw new IllegalStateException("Select a saved profile first.");AndroidConnectionProfileStore.Record result=store.load(current.id);status.setText("Loaded "+result.name+" • "+result.mode+". Connect separately to prove the path.");if(onChanged!=null)onChanged.run();}catch(Throwable error){status.setText("Load failed: "+safe(error));}}
        void delete(){try{if(hasLiveVpn(activity))throw new IllegalStateException("Disconnect Router VPN before deleting a connection profile.");AndroidConnectionProfileStore.Record current=selected();if(current==null)throw new IllegalStateException("Select a saved profile first.");store.delete(current.id);status.setText("Deleted "+current.name+".");refresh();if(onChanged!=null)onChanged.run();}catch(Throwable error){status.setText("Delete failed: "+safe(error));}}
        Button button(String text){Button b=new Button(activity);b.setAllCaps(false);b.setText(text);b.setMinWidth(0);b.setMinimumWidth(0);return b;}
        int dp(int value){return Math.round(value*activity.getResources().getDisplayMetrics().density);}
    }
    private static boolean hasLiveVpn(Context context){ConnectivityManager cm=(ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);if(cm==null)return false;Network network=cm.getActiveNetwork();if(network==null)return false;NetworkCapabilities caps=cm.getNetworkCapabilities(network);if(caps==null||!caps.hasTransport(NetworkCapabilities.TRANSPORT_VPN))return false;if(Build.VERSION.SDK_INT>=Build.VERSION_CODES.Q){int owner=caps.getOwnerUid();return owner==Process.myUid()||owner<0;}return true;}
    private static String safe(Throwable e){String v=e==null?"":e.getMessage();return v==null||v.trim().isEmpty()?"Router VPN error":v.trim();}
    private AndroidConnectionProfilesDialog(){}
}
