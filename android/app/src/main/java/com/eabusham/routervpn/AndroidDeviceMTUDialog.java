package com.eabusham.routervpn;

import android.app.AlertDialog;

final class AndroidDeviceMTUDialog {
    static void show(android.app.Activity activity) {
        try {
            if (AndroidVpnMutationGuard.isBusy(activity)) throw new IllegalStateException("Disconnect before changing the device MTU.");
            AndroidDeviceMTU capture=AndroidDeviceMTU.capture(activity);
            android.widget.EditText field=new android.widget.EditText(activity);
            field.setInputType(android.text.InputType.TYPE_CLASS_NUMBER);
            field.setHint("1280–9000");
            if(capture.value>0)field.setText(Integer.toString(capture.value));
            AlertDialog form=new AlertDialog.Builder(activity).setTitle("Device MTU for all connections")
                    .setMessage("Set the client interface MTU for every connection. Auto MTU and Retest resume with each profile when you choose Use profile settings.")
                    .setView(field).setNegativeButton("Cancel",null).setNeutralButton("Use profile settings",null).setPositiveButton("Set fixed MTU",null).create();
            form.setOnShowListener(d->{
                form.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener(v->{
                    try{int mtu=Integer.parseInt(field.getText().toString());AndroidDeviceMTU.requireRange(mtu);savePolicy(activity,capture,mtu,form);}
                    catch(NumberFormatException invalid){field.setError("Enter an integer between 1280 and 9000.");}
                    catch(Exception failed){field.setError(failed.getMessage());}
                });
                form.getButton(AlertDialog.BUTTON_NEUTRAL).setOnClickListener(v->{
                    try{savePolicy(activity,capture,0,form);}catch(Exception failed){field.setError(failed.getMessage());}
                });
            });
            form.show();
        } catch(Exception error){android.widget.Toast.makeText(activity,error.getMessage(),android.widget.Toast.LENGTH_LONG).show();}
    }
    private static void savePolicy(android.app.Activity activity,AndroidDeviceMTU original,int mtu,AlertDialog form) {
        if(AndroidVpnMutationGuard.isBusy(activity))throw new IllegalStateException("Disconnect before changing the device MTU.");
        AndroidDeviceMTU.save(activity,original,mtu);form.dismiss();
    }
}
