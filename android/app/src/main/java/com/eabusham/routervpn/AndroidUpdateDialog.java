package com.eabusham.routervpn;

import android.Manifest;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.provider.Settings;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;

import java.lang.ref.WeakReference;
import java.text.DateFormat;
import java.util.Date;

/** Reachable updates remain visible even when system notifications are denied. */
final class AndroidUpdateDialog {
    static final int NOTIFICATION_PERMISSION = 7612;

    static void showHelpActions(Activity activity) {
        new AlertDialog.Builder(activity).setTitle("Help and updates")
                .setItems(new String[]{"Updates", "Android VPN settings"},(dialog,index)->{
                    if(index==0)show(activity);
                    else activity.startActivity(new Intent(Settings.ACTION_VPN_SETTINGS));
                }).setNegativeButton("Close",null).show();
    }

    static void show(Activity activity) {
        new UpdateView(activity).show();
    }

    private static final class UpdateView {
        final Activity activity;
        final AlertDialog dialog;
        final TextView status;
        final Button check, download, notifications;

        UpdateView(Activity activity) {
        this.activity=activity;
        LinearLayout body=new LinearLayout(activity);body.setOrientation(LinearLayout.VERTICAL);
        int pad=(int)(16*activity.getResources().getDisplayMetrics().density);body.setPadding(pad,pad,pad,pad);
        status=new TextView(activity);status.setTextIsSelectable(true);body.addView(status);
        check=new Button(activity);check.setAllCaps(false);check.setText("Check for updates");body.addView(check);
        download=new Button(activity);download.setAllCaps(false);download.setText("Download APK");body.addView(download);
        notifications=new Button(activity);notifications.setAllCaps(false);body.addView(notifications);
        TextView note=new TextView(activity);
        note.setText("The published release metadata is checked against this installed source. An upgrade requires the same signing identity as the installed app; a new production key cannot replace an APK signed by an unrelated debug key. Download opens Android's browser; Android confirms installation and checks the package signature. Router VPN does not silently replace or uninstall the app. Notifications are optional; this screen works without them.");
        body.addView(note);
        ScrollView scroll=new ScrollView(activity);scroll.addView(body);
        dialog=new AlertDialog.Builder(activity).setTitle("Router VPN updates").setView(scroll).setPositiveButton("Close",null).create();
        dialog.setOnShowListener(ignored->render());
        check.setOnClickListener(ignored->joinCheck());
        download.setOnClickListener(ignored->{
            // Re-read source, expiry and exact asset identity at the user action;
            // a copied label from an older build is not download authorization.
            AndroidUpdateSnapshot update=RouterVpnUpdateProvider.availableUpdate(activity);
            if(update==null){render();toast(activity,"Check again before opening an update.");return;}
            try { activity.startActivity(new Intent(Intent.ACTION_VIEW,Uri.parse(update.apkURL))); }
            catch(RuntimeException unavailable){toast(activity,"Android could not open the APK download.");}
        });
        notifications.setOnClickListener(ignored->requestNotifications(activity));
        }

        void render() {
            if(activity.isFinishing()||activity.isDestroyed()||!dialog.isShowing())return;
            AndroidUpdateSnapshot update=RouterVpnUpdateProvider.availableUpdate(activity);
            String message="Installed source: "+RouterVpnUpdateProvider.installedSource(activity)+"\n\n"+RouterVpnUpdateProvider.checkMessage(activity);
            if(update!=null)message+="\n\nAvailable: "+update.target+"\n"+update.deliveryLabel()+"\nVersion code: "+update.versionCode+"\nSigning certificate SHA-256: "+update.certificateSHA256+"\nAPK size: "+update.apkBytes+" bytes\nPublished SHA-256: "+update.apkDigest+"\nMetadata verified: "+DateFormat.getDateTimeInstance().format(new Date(update.verifiedAt));
            status.setText(message);download.setEnabled(update!=null);check.setEnabled(!RouterVpnUpdateProvider.isChecking());
            download.setText(update==null?"Download APK":"production-signed".equals(update.signing)?"Download production APK":"Download debug APK");
            check.setText(RouterVpnUpdateProvider.isChecking()?"Checking…":"Check for updates");
            notifications.setText(notificationPermissionMissing(activity)?"Allow update notifications":"Notification settings");
        }

        void joinCheck() {
            check.setEnabled(false);check.setText("Checking…");
            // The process-owned worker must not retain an Activity or dismissed
            // dialog while GitHub is slow. UI listeners own this view; discovery
            // holds only a weak reference and renders only a still-visible owner.
            WeakReference<UpdateView> owner=new WeakReference<>(this);
            RouterVpnUpdateProvider.requestCheck(activity.getApplicationContext(),()->{
                UpdateView current=owner.get();
                if(current==null)return;
                current.activity.runOnUiThread(()->{UpdateView visible=owner.get();if(visible!=null)visible.render();});
            });
        }

        void show() {
            dialog.show();
            // Join startup discovery so its completion also refreshes this screen.
            if(RouterVpnUpdateProvider.isChecking())joinCheck();
        }
    }

    static boolean onPermissionResult(Activity activity,int requestCode) {
        if(requestCode!=NOTIFICATION_PERMISSION)return false;
        if(!notificationPermissionMissing(activity))RouterVpnUpdateProvider.notifyAvailableUpdate(activity.getApplicationContext());
        toast(activity,notificationPermissionMissing(activity)?"Updates remain available in Help → More → Updates.":"Update notifications are enabled.");
        return true;
    }

    private static boolean notificationPermissionMissing(Activity activity) {
        return Build.VERSION.SDK_INT>=33&&activity.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS)!=PackageManager.PERMISSION_GRANTED;
    }

    private static void requestNotifications(Activity activity) {
        if(notificationPermissionMissing(activity)) {
            boolean asked=activity.getSharedPreferences("router_vpn_updates",Activity.MODE_PRIVATE).getBoolean("notification_permission_requested",false);
            if(!asked||activity.shouldShowRequestPermissionRationale(Manifest.permission.POST_NOTIFICATIONS)) {
                activity.getSharedPreferences("router_vpn_updates",Activity.MODE_PRIVATE).edit().putBoolean("notification_permission_requested",true).apply();
                activity.requestPermissions(new String[]{Manifest.permission.POST_NOTIFICATIONS},NOTIFICATION_PERMISSION);
                return;
            }
        }
        try {
            Intent intent=Build.VERSION.SDK_INT>=26?new Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS).putExtra(Settings.EXTRA_APP_PACKAGE,activity.getPackageName())
                    :new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+activity.getPackageName()));
            activity.startActivity(intent);
        }catch(RuntimeException unavailable){toast(activity,"Open Android app settings to change notifications.");}
    }

    private static void toast(Activity activity,String text){Toast.makeText(activity,text,Toast.LENGTH_LONG).show();}
}
