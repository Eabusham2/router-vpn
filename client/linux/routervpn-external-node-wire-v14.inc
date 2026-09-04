/* Compose the typed external-node creator into the existing Linux map-first
 * node row without rewriting the mature unified shell source.
 *
 * The unified state contract deliberately keeps App *app as its first member.
 * The Add/manage callback passes that state pointer to make_button(), so this
 * wrapper can recover the App pointer only for that exact label and give the new
 * button the normal App* callback contract. Every other button is unchanged.
 */
#include "routervpn-external-node-v14.inc"

static GtkWidget *routervpn_make_button_external_v14(const char *label, GCallback callback, gpointer data) {
    if (g_strcmp0(label, "Add / manage nodes") != 0) return make_button(label, callback, data);
    GtkWidget *row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    gtk_box_pack_start(GTK_BOX(row), make_button(label, callback, data), FALSE, FALSE, 0);
    App *app = data != NULL ? *((App **)data) : NULL;
    GtkWidget *external = make_button("Add external node…", G_CALLBACK(on_linux_external_node_v14), app);
    gtk_widget_set_tooltip_text(external, "Create WireGuard, SOCKS5, HTTP/HTTPS CONNECT, Shadowsocks or Hysteria2 nodes. OpenVPN and Tor use their dedicated hardened flows.");
    gtk_box_pack_start(GTK_BOX(row), external, FALSE, FALSE, 0);
    return row;
}

#define make_button routervpn_make_button_external_v14
