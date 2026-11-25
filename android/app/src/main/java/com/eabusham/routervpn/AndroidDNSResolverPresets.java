package com.eabusham.routervpn;

import android.app.Activity;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.Spinner;

import java.util.ArrayList;
import java.util.List;

final class AndroidDNSResolverPresets {
    private AndroidDNSResolverPresets() {}

    static Spinner resolverPresetChooser(Activity activity, EditText host, EditText server) {
        Spinner preset = new Spinner(activity);
        List<String> labels = new ArrayList<>();
        labels.add("Manual/current");
        for (AndroidDNSResolverCatalog.ResolverPreset resolver : AndroidDNSResolverCatalog.PRESETS) labels.add(resolver.toString());
        preset.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item, labels.toArray(new String[0])));
        preset.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            public void onNothingSelected(android.widget.AdapterView<?> parent) {}
            public void onItemSelected(android.widget.AdapterView<?> parent, View view, int position, long id) {
                if (!preset.isEnabled() || position <= 0 || position > AndroidDNSResolverCatalog.PRESETS.size()) return;
                AndroidDNSResolverCatalog.ResolverPreset resolver = AndroidDNSResolverCatalog.PRESETS.get(position - 1);
                host.setText(resolver.host);
                server.setText(resolver.serverName);
            }
        });
        return preset;
    }

}
