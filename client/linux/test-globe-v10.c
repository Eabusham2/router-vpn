static void test_offline_land(const char *root) {
    cairo_path_t *land = linux_globe_land_load_v10(root);
    g_assert_nonnull(land);
    const int samples[][3] = {{-99,40,1},{-55,-12,1},{135,-25,1},{25,0,1},{80,25,1},
                               {-40,30,0},{-140,0,0},{80,-30,0},{51,42,0}};
    for (int width = 640; width <= 1280; width *= 2) {
        int height = width / 2;
        cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
        cairo_t *cr = cairo_create(surface);
        linux_globe_land_draw_v10(cr, land, width, height);
        cairo_surface_flush(surface);
        unsigned char *data = cairo_image_surface_get_data(surface);
        for (guint i = 0; i < G_N_ELEMENTS(samples); i++) {
            double x, y;
            linux_globe_xy_v10(samples[i][1], samples[i][0], width, height, &x, &y);
            const guint32 *row = (const guint32 *)(data + (int)y * cairo_image_surface_get_stride(surface));
            g_assert_cmpint((row[(int)x] >> 24) > 0, ==, samples[i][2]);
        }
        cairo_matrix_t matrix; cairo_get_matrix(cr, &matrix);
        g_assert_true(matrix.xx == 1 && matrix.yy == 1 && matrix.x0 == 0 && matrix.y0 == 0);
        cairo_destroy(cr); cairo_surface_destroy(surface);
    }
    cairo_path_destroy(land);
}

static void test_globe_leg(double lon1, double lon2) {
    double width = 800, height = 420;
    LinuxGlobeLeg leg = linux_globe_leg_v10(20, lon1, 30, lon2, width, height);
    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, width, height);
    cairo_t *cr = cairo_create(surface);
    linux_globe_leg_path_v10(cr, leg);
    cairo_path_t *path = cairo_copy_path(cr);
    guint segments = 0;
    double x = 0;
    for (int j = 0; j < path->num_data; j += path->data[j].header.length) {
        cairo_path_data_t *p = path->data + j;
        if (p->header.type == CAIRO_PATH_LINE_TO) {
            segments++;
            g_assert_cmpfloat(fabs(x - p[1].point.x), <, width / 8);
        }
        x = p[1].point.x;
    }
    g_assert_cmpuint(segments, ==, leg.wrapped && leg.crossing > 0 && leg.crossing < 1 ? 2 : 1);
    for (guint i = 0; i <= 10; i++) {
        LinuxGlobePoint packet = linux_globe_packet_v10(leg, i / 10.0);
        g_assert_true(isfinite(packet.x) && isfinite(packet.y));
        g_assert_cmpfloat(fabs(packet.x - width / 2), >, width / 3);
        double expected_y = leg.start.y + (leg.end.y - leg.start.y) * i / 10.0;
        g_assert_cmpfloat(fabs(packet.y - expected_y), <, .000001);
        if (leg.wrapped && i > 0 && i < 10) {
            gboolean first_side = i / 10.0 <= leg.crossing;
            g_assert_cmpint(packet.x > width / 2, ==, first_side ? lon1 > 0 : lon2 > 0);
        }
    }
    cairo_path_destroy(path); cairo_destroy(cr); cairo_surface_destroy(surface);
}

static void test_globe_paint(App *app, LinuxGlobeV10 *g, const char *root, const char *png) {
    MapNode nodes[] = {{.id="a",.name="Fiji",.latitude=-17.77,.longitude=178.45,.has_coordinates=TRUE},
                       {.id="b",.name="Samoa",.latitude=-13.83,.longitude=-171.75,.has_coordinates=TRUE},
                       {.id="c",.name="Honolulu",.latitude=21.31,.longitude=-157.86,.has_coordinates=TRUE}};
    app->nodes = g_ptr_array_new();
    for (guint i=0; i<G_N_ELEMENTS(nodes); i++) g_ptr_array_add(app->nodes, &nodes[i]);
    g_hash_table_add(g->external_ids, g_strdup("b"));
    g->land = linux_globe_land_load_v10(root);
    g_object_set_data(G_OBJECT(app->window), "linux-globe-v10", g);
    cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 1100, 580);
    cairo_t *cr = cairo_create(surface);
    g->phase = .22;
    linux_globe_paint_v10(app, cr, 1100, 580);
    cairo_surface_flush(surface);
    LinuxGlobeLeg leg = linux_globe_leg_v10(nodes[0].latitude, nodes[0].longitude,
        nodes[1].latitude, nodes[1].longitude, 1100, 580);
    LinuxGlobePoint dot = linux_globe_packet_v10(leg, g->phase * 2);
    const guint32 *row = (const guint32 *)(cairo_image_surface_get_data(surface) +
        (int)dot.y * cairo_image_surface_get_stride(surface));
    g_assert_cmphex(row[(int)dot.x], ==, 0xffffffffU);
    if (png) g_assert_cmpint(cairo_surface_write_to_png(surface, png), ==, CAIRO_STATUS_SUCCESS);
    cairo_destroy(cr); cairo_surface_destroy(surface);
    cairo_path_destroy(g->land); g->land = NULL;
    g_ptr_array_unref(app->nodes); app->nodes = NULL;
}

static void test_globe_frames(const char *root, const char *png) {
    App app = {0};
    // State lookup and route ownership use GObject data, no display or network.
    app.window = (GtkWidget *)g_object_new(G_TYPE_OBJECT, NULL);
    LinuxTelemetryV9 t = {.app = &app};
    LinuxAsyncActionsV16 actions = {.app = &app};
    LinuxGlobeV10 g = {.app = &app, .route_ids = g_ptr_array_new_with_free_func(g_free),
                       .external_ids = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, NULL)};
    g_object_set_data(G_OBJECT(app.window), "linux-telemetry-v9", &t);
    g_object_set_data(G_OBJECT(app.window), "linux-async-actions-v16", &actions);
    const char *capture = "{\"connected\":true,\"active_route_id\":\"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff\","
                          "\"actual_entry_id\":\"a\",\"actual_exit_id\":\"c\",\"active_node_ids\":[\"a\",\"b\",\"c\"]}";
    g_autoptr(JsonNode) original = parse_json(capture), replacement = parse_json(capture);
    t.map_status = json_node_get_object(original);
    t.controller_status = json_object_new();
    json_object_set_boolean_member(t.controller_status, "connected", TRUE);
    for (guint fault = 0; fault < 7; fault++) {
        t.map_status = json_node_get_object(original);
        linux_globe_load_route(&g, t.map_status, NULL);
        g_assert_cmpuint(g.route_ids->len, ==, 3);
        if (fault == 0) test_globe_paint(&app, &g, root, png);
        linux_globe_tick_v10(&g);
        g_assert_cmpfloat(g.phase, >, 0);
        // An equivalent refresh and expiry of its measured RTT preserve packet animation.
        t.map_status = json_node_get_object(replacement);
        g.path_ms = 15; double original_phase = g.phase;
        linux_globe_tick_v10(&g);
        g_assert_true(g.connected && g.phase > original_phase && g.path_ms == 0);
        if (fault == 0) t.map_status = NULL;
        if (fault == 1) json_object_set_string_member(t.map_status, "active_route_id", "different");
        if (fault == 2) {
            JsonArray *ids = json_object_get_array_member(t.map_status, "active_node_ids");
            json_array_remove_element(ids, 1); json_array_remove_element(ids, 1);
            json_array_add_string_element(ids, "new-middle"); json_array_add_string_element(ids, "c");
        }
        if (fault == 3) json_object_set_boolean_member(t.controller_status, "connected", FALSE);
        if (fault == 4) actions.closed = TRUE;
        if (fault == 5) atomic_store(&controller_exit_pending, TRUE);
        if (fault == 6) json_object_set_boolean_member(t.map_status, "connected", FALSE);
        if (fault == 0) {
            // A queued GTK repaint may precede the next animation timeout.
            app.nodes = g_ptr_array_new();
            cairo_surface_t *surface = cairo_image_surface_create(CAIRO_FORMAT_ARGB32, 640, 320);
            cairo_t *cr = cairo_create(surface);
            linux_globe_paint_v10(&app, cr, 640, 320);
            g_assert_false(g.connected);
            cairo_destroy(cr); cairo_surface_destroy(surface); g_ptr_array_unref(app.nodes); app.nodes = NULL;
        }
        linux_globe_tick_v10(&g);
        g_assert_false(g.connected);
        g_assert_true(g.phase == 0 && g.path_ms == 0 && g.route_owner == NULL && g.route_ids->len == 0);
        g_clear_pointer(&replacement, json_node_free);
        replacement = parse_json(capture); actions.closed = FALSE;
        atomic_store(&controller_exit_pending, FALSE);
        json_object_set_boolean_member(t.controller_status, "connected", TRUE);
    }
    json_object_unref(t.controller_status);
    g_ptr_array_unref(g.route_ids); g_hash_table_unref(g.external_ids); g_object_unref(app.window);
}

static void test_globe_v10(const char *root, const char *png) {
    test_offline_land(root);
    test_globe_leg(170, -166); test_globe_leg(-170, 166);
    test_globe_leg(180, -180); test_globe_leg(-180, 180);
    test_globe_leg(180, -169); test_globe_leg(165, -180);
    test_globe_leg(151, 168);
    test_globe_frames(root, png);
    puts("Linux shipping globe: offline land and interior water at two sizes, seven route and packet cases, seven local owner retirements PASS");
}
