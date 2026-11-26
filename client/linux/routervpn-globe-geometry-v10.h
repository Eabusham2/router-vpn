/* Native projection, offline Natural Earth outlines and route geometry. */
static void linux_globe_project_v10(double lat, double lon, double *x, double *y) {
    *x = (lon / 180.0) * .92 * cos(lat * G_PI / 180.0 * .55);
    *y = -(lat / 90.0) * .86;
}

static void linux_globe_scale_v10(double width, double height, double *sx, double *sy) {
    // Fit the 360-by-180-degree world without stretching it as the window resizes.
    // Geometry, routes, markers and hit testing all share this centered viewport.
    *sy = fmax(0.0, fmin((width / 2.0 - 18.0) / 2.0, height / 2.0 - 16.0));
    *sx = *sy * 2.0;
}

static void linux_globe_xy_v10(double lat, double lon, double width, double height, double *x, double *y) {
    double sx, sy;
    linux_globe_scale_v10(width, height, &sx, &sy);
    linux_globe_project_v10(lat, lon, x, y);
    *x = width / 2.0 + *x * sx;
    *y = height / 2.0 + *y * sy;
}

static JsonArray *linux_globe_array_v10(JsonNode *node) {
    return node && JSON_NODE_HOLDS_ARRAY(node) ? json_node_get_array(node) : NULL;
}

static gboolean linux_globe_integer_v10(JsonNode *node, gint64 *value) {
    if (!node || !JSON_NODE_HOLDS_VALUE(node) || json_node_get_value_type(node) != G_TYPE_INT64) return FALSE;
    *value = json_node_get_int(node);
    return TRUE;
}

static cairo_path_t *linux_globe_land_load_v10(const char *package_root) {
    g_autofree char *path = g_build_filename(package_root, "client", "shared", "map", "routervpn-land-110m.json", NULL);
    g_autoptr(GMappedFile) file = g_mapped_file_new(path, FALSE, NULL);
    g_autoptr(JsonParser) parser = json_parser_new();
    if (!file || g_mapped_file_get_length(file) > 512 * 1024 ||
        !json_parser_load_from_data(parser, g_mapped_file_get_contents(file), g_mapped_file_get_length(file), NULL)) return NULL;
    JsonNode *root = json_parser_get_root(parser);
    if (!root || !JSON_NODE_HOLDS_OBJECT(root)) return NULL;
    JsonObject *geometry = json_node_get_object(root);
    gint64 schema, scale;
    if (!linux_globe_integer_v10(json_object_get_member(geometry, "schema"), &schema) || schema != 1 ||
        !linux_globe_integer_v10(json_object_get_member(geometry, "scale"), &scale) || scale != 10000) return NULL;
    JsonArray *rings = linux_globe_array_v10(json_object_get_member(geometry, "rings"));
    if (!rings || !json_array_get_length(rings) || json_array_get_length(rings) > 1024) return NULL;
    cairo_surface_t *surface = cairo_recording_surface_create(CAIRO_CONTENT_ALPHA, NULL);
    cairo_t *cr = cairo_create(surface);
    cairo_path_t *outline = NULL;
    guint vertices = 0;
    for (guint i = 0; i < json_array_get_length(rings); i++) {
        JsonArray *ring = linux_globe_array_v10(json_array_get_element(rings, i));
        guint count = ring ? json_array_get_length(ring) : 0;
        if (count < 4 || count > 30000 - vertices) goto done;
        vertices += count;
        gint64 first_lon = 0, first_lat = 0;
        for (guint j = 0; j < count; j++) {
            JsonArray *point = linux_globe_array_v10(json_array_get_element(ring, j));
            gint64 lon, lat;
            if (!point || json_array_get_length(point) != 2 ||
                !linux_globe_integer_v10(json_array_get_element(point, 0), &lon) || lon < -180 * scale || lon > 180 * scale ||
                !linux_globe_integer_v10(json_array_get_element(point, 1), &lat) || lat < -90 * scale || lat > 90 * scale) goto done;
            double x, y;
            linux_globe_project_v10((double)lat / scale, (double)lon / scale, &x, &y);
            if (!j) {
                first_lon = lon; first_lat = lat;
                cairo_move_to(cr, x * 1024, y * 1024);
            } else if (j + 1 == count) {
                if (lon != first_lon || lat != first_lat) goto done;
                cairo_close_path(cr);
            } else {
                cairo_line_to(cr, x * 1024, y * 1024);
            }
        }
    }
    if (cairo_status(cr) == CAIRO_STATUS_SUCCESS) outline = cairo_copy_path(cr);
done:
    cairo_destroy(cr);
    cairo_surface_destroy(surface);
    return outline;
}

static void linux_globe_land_draw_v10(cairo_t *cr, const cairo_path_t *land, double width, double height) {
    double sx, sy;
    linux_globe_scale_v10(width, height, &sx, &sy);
    if (!land || sx <= 0 || sy <= 0) return;
    sx /= 1024; sy /= 1024;
    cairo_save(cr);
    cairo_translate(cr, width / 2, height / 2);
    cairo_scale(cr, sx, sy);
    cairo_append_path(cr, land);
    cairo_set_fill_rule(cr, CAIRO_FILL_RULE_EVEN_ODD);
    cairo_set_source_rgb(cr, .12, .24, .31);
    cairo_fill_preserve(cr);
    cairo_set_source_rgb(cr, .27, .43, .51);
    cairo_set_line_width(cr, .8 / fmax(sx, sy));
    cairo_stroke(cr);
    cairo_restore(cr);
}

typedef struct { double x, y; } LinuxGlobePoint;
typedef struct {
    LinuxGlobePoint start, end, before, after;
    double crossing;
    gboolean wrapped;
} LinuxGlobeLeg;

static LinuxGlobeLeg linux_globe_leg_v10(double lat1, double lon1, double lat2, double lon2, double w, double h) {
    LinuxGlobeLeg leg = {0};
    linux_globe_xy_v10(lat1, lon1, w, h, &leg.start.x, &leg.start.y);
    linux_globe_xy_v10(lat2, lon2, w, h, &leg.end.x, &leg.end.y);
    double delta = lon2 - lon1;
    if (fabs(delta) <= 180) return leg;
    double edge = delta < 0 ? 180 : -180;
    delta += 2 * edge;
    if (delta == 0) {
        // Both endpoints lie on the same meridian, shown at opposite edges.
        linux_globe_xy_v10(lat2, lon1, w, h, &leg.end.x, &leg.end.y);
        return leg;
    }
    leg.wrapped = TRUE;
    leg.crossing = (edge - lon1) / delta;
    double lat = lat1 + leg.crossing * (lat2 - lat1);
    linux_globe_xy_v10(lat, edge, w, h, &leg.before.x, &leg.before.y);
    linux_globe_xy_v10(lat, -edge, w, h, &leg.after.x, &leg.after.y);
    return leg;
}

static void linux_globe_leg_path_v10(cairo_t *cr, LinuxGlobeLeg leg) {
    cairo_move_to(cr, leg.start.x, leg.start.y);
    if (leg.wrapped) {
        if (leg.crossing > 0) cairo_line_to(cr, leg.before.x, leg.before.y);
        if (leg.crossing == 1) return;
        cairo_move_to(cr, leg.after.x, leg.after.y);
    }
    cairo_line_to(cr, leg.end.x, leg.end.y);
}

static LinuxGlobePoint linux_globe_packet_v10(LinuxGlobeLeg leg, double fraction) {
    LinuxGlobePoint start = leg.start, end = leg.end;
    if (fraction <= 0) return start;
    if (fraction >= 1) return end;
    if (leg.wrapped) {
        if (fraction <= leg.crossing) {
            end = leg.before;
            fraction /= leg.crossing;
        } else {
            start = leg.after;
            fraction = (fraction - leg.crossing) / (1 - leg.crossing);
        }
    }
    return (LinuxGlobePoint){start.x + (end.x - start.x) * fraction, start.y + (end.y - start.y) * fraction};
}
