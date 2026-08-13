package com.eabusham.routervpn;

import android.content.Context;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.RectF;
import android.util.AttributeSet;
import android.view.View;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Offline native coordinate view. Callers provide only coordinates present in linked node data. */
final class RouterVpnNodeMapView extends View {
    static final class Marker {
        final String id, name;
        final double latitude, longitude;
        final boolean selected;
        Marker(String id, String name, double latitude, double longitude, boolean selected) {
            this.id = id; this.name = name; this.latitude = latitude; this.longitude = longitude; this.selected = selected;
        }
    }

    private final Paint background = paint(Color.rgb(14, 24, 43), 1f);
    private final Paint grid = paint(Color.rgb(45, 61, 87), 1f);
    private final Paint axis = paint(Color.rgb(88, 116, 164), 1.5f);
    private final Paint pin = paint(Color.rgb(98, 213, 255), 1f);
    private final Paint selectedPin = paint(Color.rgb(123, 104, 255), 1f);
    private final Paint text = paint(Color.WHITE, 1f);
    private List<Marker> markers = Collections.emptyList();

    RouterVpnNodeMapView(Context context) { this(context, null); }
    RouterVpnNodeMapView(Context context, AttributeSet attrs) {
        super(context, attrs);
        text.setTextSize(sp(12));
        setMinimumHeight((int) dp(260));
        setContentDescription("Router VPN node map using stored coordinates only");
    }

    void setMarkers(List<Marker> value) {
        markers = value == null ? Collections.emptyList() : new ArrayList<>(value);
        invalidate();
    }

    @Override protected void onDraw(Canvas canvas) {
        super.onDraw(canvas);
        float pad = dp(14);
        RectF world = new RectF(pad, pad, getWidth() - pad, getHeight() - pad);
        canvas.drawRoundRect(world, dp(14), dp(14), background);
        for (int lon = -120; lon <= 120; lon += 60) {
            float x = world.left + (lon + 180f) / 360f * world.width();
            canvas.drawLine(x, world.top, x, world.bottom, lon == 0 ? axis : grid);
        }
        for (int lat = -60; lat <= 60; lat += 30) {
            float y = world.top + (90f - lat) / 180f * world.height();
            canvas.drawLine(world.left, y, world.right, y, lat == 0 ? axis : grid);
        }
        if (markers.isEmpty()) {
            text.setTextAlign(Paint.Align.CENTER);
            canvas.drawText("No real node coordinates in linked bundles", world.centerX(), world.centerY(), text);
            text.setTextAlign(Paint.Align.LEFT);
            return;
        }
        for (Marker marker : markers) {
            if (!Double.isFinite(marker.latitude) || !Double.isFinite(marker.longitude)) continue;
            if (marker.latitude < -90 || marker.latitude > 90 || marker.longitude < -180 || marker.longitude > 180) continue;
            float x = world.left + (float) ((marker.longitude + 180d) / 360d) * world.width();
            float y = world.top + (float) ((90d - marker.latitude) / 180d) * world.height();
            float r = dp(marker.selected ? 8 : 6);
            canvas.drawCircle(x, y, r, marker.selected ? selectedPin : pin);
            String label = marker.name == null || marker.name.trim().isEmpty() ? "Router VPN node" : marker.name.trim();
            if (label.length() > 22) label = label.substring(0, 21) + "…";
            canvas.drawText(label, x + r + dp(4), y - dp(4), text);
        }
    }

    private Paint paint(int color, float widthDp) {
        Paint p = new Paint(Paint.ANTI_ALIAS_FLAG); p.setColor(color); p.setStrokeWidth(dp(widthDp)); return p;
    }
    private float dp(float value) { return value * getResources().getDisplayMetrics().density; }
    private float sp(float value) { return value * getResources().getDisplayMetrics().scaledDensity; }
}
