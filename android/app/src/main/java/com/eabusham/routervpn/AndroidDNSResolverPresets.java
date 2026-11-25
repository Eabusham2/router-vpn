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

    private static final class ResolverPreset {
        final String name, host, serverName;
        ResolverPreset(String name, String host, String serverName) { this.name=name; this.host=host; this.serverName=serverName; }
        @Override public String toString(){ return name + " — " + host; }
    }
    private static final ResolverPreset[] PRESETS = new ResolverPreset[]{
            new ResolverPreset("Cloudflare IPv4","1.1.1.1","cloudflare-dns.com"),
            new ResolverPreset("Cloudflare IPv4 secondary","1.0.0.1","cloudflare-dns.com"),
            new ResolverPreset("Cloudflare IPv6","2606:4700:4700::1111","cloudflare-dns.com"),
            new ResolverPreset("Cloudflare IPv6 secondary","2606:4700:4700::1001","cloudflare-dns.com"),
            new ResolverPreset("Google IPv4","8.8.8.8","dns.google"),
            new ResolverPreset("Google IPv4 secondary","8.8.4.4","dns.google"),
            new ResolverPreset("Google IPv6","2001:4860:4860::8888","dns.google"),
            new ResolverPreset("Google IPv6 secondary","2001:4860:4860::8844","dns.google"),
            new ResolverPreset("Quad9 IPv4","9.9.9.9","dns.quad9.net"),
            new ResolverPreset("Quad9 IPv4 secondary","149.112.112.112","dns.quad9.net"),
            new ResolverPreset("Quad9 IPv6","2620:fe::fe","dns.quad9.net"),
            new ResolverPreset("Quad9 IPv6 secondary","2620:fe::9","dns.quad9.net")
    };

    static Spinner resolverPresetChooser(Activity activity, EditText host, EditText server) {
        Spinner preset = new Spinner(activity);
        List<String> labels = new ArrayList<>();
        labels.add("Manual/current");
        for (ResolverPreset resolver : PRESETS) labels.add(resolver.toString());
        preset.setAdapter(new ArrayAdapter<>(activity, android.R.layout.simple_spinner_dropdown_item, labels.toArray(new String[0])));
        preset.setOnItemSelectedListener(new android.widget.AdapterView.OnItemSelectedListener() {
            public void onNothingSelected(android.widget.AdapterView<?> parent) {}
            public void onItemSelected(android.widget.AdapterView<?> parent, View view, int position, long id) {
                if (!preset.isEnabled() || position <= 0 || position > PRESETS.length) return;
                ResolverPreset resolver = PRESETS[position - 1];
                host.setText(resolver.host);
                server.setText(resolver.serverName);
            }
        });
        return preset;
    }

    static String serverName(String host) {
        for (ResolverPreset resolver : PRESETS) if (resolver.host.equalsIgnoreCase(host)) return resolver.serverName;
        return "";
    }
}
