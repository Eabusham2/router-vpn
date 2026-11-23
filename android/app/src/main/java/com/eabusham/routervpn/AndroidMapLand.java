package com.eabusham.routervpn;

import android.content.res.AssetManager;
import android.graphics.Canvas;
import android.graphics.Paint;
import android.graphics.Path;
import android.graphics.RectF;
import android.util.Log;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

/** Offline geography. The same checked-in coastlines ship with the Apple apps. */
final class AndroidMapLand {
    private static final String ASSET = "routervpn-land-110m.json";
    private static final int SCALE = 10_000;
    private static Path cachedOutline;
    private final Path outline;
    private final Paint fill = new Paint(Paint.ANTI_ALIAS_FLAG);
    private final Paint coastline = new Paint(Paint.ANTI_ALIAS_FLAG);

    AndroidMapLand(AssetManager assets) {
        outline = load(assets);
        fill.setColor(0xff20394b);
        coastline.setColor(0xff42647a);
        coastline.setStyle(Paint.Style.STROKE);
        coastline.setStrokeWidth(0); // One screen pixel at every map size.
    }

    private static synchronized Path load(AssetManager assets) {
        if (cachedOutline != null) return cachedOutline;
        try (InputStream input = assets.open(ASSET)) {
            ByteArrayOutputStream bytes = new ByteArrayOutputStream();
            byte[] buffer = new byte[8192];
            int count;
            while ((count = input.read(buffer)) != -1) {
                if (bytes.size() + count > 512 * 1024) throw new IOException("Map asset too large");
                bytes.write(buffer, 0, count);
            }
            cachedOutline = parse(new JSONObject(new String(bytes.toByteArray(), StandardCharsets.UTF_8)));
        } catch (IOException | JSONException invalidAsset) {
            Log.w("RouterVPN", "Bundled world outlines are unavailable", invalidAsset);
        }
        return cachedOutline;
    }

    private static Path parse(JSONObject geometry) throws JSONException {
        if (geometry.getInt("schema") != 1 || geometry.getInt("scale") != SCALE)
            throw new JSONException("Unsupported map geometry");
        JSONArray rings = geometry.getJSONArray("rings");
        if (rings.length() < 1 || rings.length() > 1024) throw new JSONException("Invalid ring count");
        Path path = new Path();
        path.setFillType(Path.FillType.EVEN_ODD);
        int vertices = 0;
        for (int i = 0; i < rings.length(); i++) {
            JSONArray ring = rings.getJSONArray(i);
            vertices += ring.length();
            if (ring.length() < 4 || vertices > 30_000) throw new JSONException("Invalid ring size");
            int firstLon = 0, firstLat = 0;
            for (int j = 0; j < ring.length(); j++) {
                JSONArray point = ring.getJSONArray(j);
                int lon = point.getInt(0), lat = point.getInt(1);
                if (point.length() != 2 || lon < -180 * SCALE || lon > 180 * SCALE || lat < -90 * SCALE || lat > 90 * SCALE)
                    throw new JSONException("Invalid land coordinate");
                float x = (lon + 180 * SCALE) / (360f * SCALE), y = (90 * SCALE - lat) / (180f * SCALE);
                if (j == 0) {
                    firstLon = lon;
                    firstLat = lat;
                    path.moveTo(x, y);
                } else if (j == ring.length() - 1) {
                    if (lon != firstLon || lat != firstLat) throw new JSONException("Open land ring");
                    path.close();
                } else {
                    path.lineTo(x, y);
                }
            }
        }
        return path;
    }

    void draw(Canvas canvas, RectF world) {
        if (outline == null || world.width() <= 0 || world.height() <= 0) return;
        int saved = canvas.save();
        canvas.translate(world.left, world.top);
        canvas.scale(world.width(), world.height());
        canvas.drawPath(outline, fill);
        canvas.drawPath(outline, coastline);
        canvas.restoreToCount(saved);
    }
}
