/* Native last-relay measurement prerequisite: an authenticated one-use BEGIN_DIR stream on
 * the exact circuit of a retained external stream. No RTT, score, external
 * connection, DNS lookup, circuit selection or circuit construction occurs.
 * All state and hooks run on Tor's existing main event loop. */
#include "core/or/or.h"
#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/mainloop/netstatus.h"
#include "core/or/channel.h"
#include "core/or/circuitlist.h"
#include "core/or/circuituse.h"
#include "core/or/connection_edge.h"
#include "core/or/cpath_build_state_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/entry_connection_st.h"
#include "core/or/extend_info_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/conflux_util.h"
#include "core/or/relay_msg_st.h"
#include "core/or/socks_request_st.h"
#include "feature/control/control.h"
#include "feature/control/control_cmd.h"
#include "feature/control/control_cmd_args_st.h"
#include "feature/control/control_connection_st.h"
#include "feature/control/control_proto.h"
#include "feature/control/routervpn_lastrelay.h"
#include "lib/crypt_ops/crypto_digest.h"
#include "lib/crypt_ops/crypto_util.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"

#define LAST_SUFFIX ".lastrelay.routervpn.invalid"
#define LAST_REQUEST "GET /tor/robots.txt HTTP/1.0\r\n\r\n"
#define LAST_RESPONSE_LIMIT 8192
#define LAST_MAX_HOPS 8
#define LAST_MAX_TTL_MS 10000

static struct {
  control_connection_t *owner;
  tor_timer_t *timer;
  origin_circuit_t *circuit;
  entry_connection_t *anchor, *stream;
  crypt_path_t *last;
  uint64_t generation, anchor_id, stream_id, stream_global, expires;
  uint32_t circuit_id;
  uint16_t relay_stream;
  uint8_t end_reason;
  unsigned request_bytes, response_bytes;
  bool active, used, connected, ended;
  const char *reason;
  char session[65], source[65], nonce[65], username[65], password[65];
  char hostname[128], path[DIGEST256_LEN], exit[DIGEST_LEN];
} probe;
static uint64_t highwater;

static bool
hex(const char *s, size_t length)
{
  if (!s || strlen(s) != length)
    return false;
  for (size_t i = 0; i < length; ++i)
    if (!((s[i] >= '0' && s[i] <= '9') ||
          (s[i] >= 'a' && s[i] <= 'f')))
      return false;
  return true;
}

static bool
number(const char *s, uint64_t lower, uint64_t upper, uint64_t *out)
{
  uint64_t value = 0;
  if (!s || !*s || (*s == '0' && s[1]))
    return false;
  for (; *s; ++s) {
    if (*s < '0' || *s > '9' || value > (upper - (*s - '0')) / 10)
      return false;
    value = value * 10 + (*s - '0');
  }
  if (value < lower || value > upper)
    return false;
  *out = value;
  return true;
}

static bool
owner_open(control_connection_t *owner)
{
  return owner && owner->is_owning_control_connection &&
         owner->base_.state == CONTROL_CONN_STATE_OPEN &&
         !owner->base_.marked_for_close;
}

static bool
credentials(const entry_connection_t *entry, const char *username,
            const char *password)
{
  const socks_request_t *s = entry->socks_request;
  size_t length = strlen(username);
  return s && s->socks_version == 5 &&
         s->command == SOCKS_COMMAND_CONNECT &&
         (entry->entry_cfg.isolation_flags & ISO_SOCKSAUTH) &&
         s->usernamelen == length && s->passwordlen == 64 &&
         s->username && s->password &&
         tor_memeq(s->username, username, length) &&
         tor_memeq(s->password, password, 64);
}

static bool
path(origin_circuit_t *origin, const char *username, const char *password,
     char digest[DIGEST256_LEN])
{
  if (!origin)
    return false;
  circuit_t *circ = TO_CIRCUIT(origin);
  size_t ulen = strlen(username);
  if (circ->marked_for_close ||
      circ->state != CIRCUIT_STATE_OPEN ||
      circ->purpose != CIRCUIT_PURPOSE_C_GENERAL ||
      CIRCUIT_IS_CONFLUX(circ) || !circ->n_chan ||
      !CHANNEL_IS_OPEN(circ->n_chan) || !origin->build_state ||
      origin->build_state->onehop_tunnel || origin->build_state->is_internal ||
      origin->unusable_for_new_conns || !origin->isolation_values_set ||
      !origin->isolation_any_streams_attached ||
      (origin->isolation_flags_mixed & ISO_SOCKSAUTH) ||
      origin->socks_username_len != ulen || origin->socks_password_len != 64 ||
      !origin->socks_username || !origin->socks_password ||
      !tor_memeq(origin->socks_username, username, ulen) ||
      !tor_memeq(origin->socks_password, password, 64) || !origin->cpath)
    return false;
  char identities[LAST_MAX_HOPS * DIGEST_LEN];
  crypt_path_t *hop = origin->cpath;
  unsigned count = 0;
  do {
    if (count >= LAST_MAX_HOPS || hop->state != CPATH_STATE_OPEN ||
        !hop->extend_info || fast_mem_is_zero(hop->extend_info->identity_digest,
                                           DIGEST_LEN) || !hop->next)
      return false;
    memcpy(identities + count * DIGEST_LEN,
           hop->extend_info->identity_digest, DIGEST_LEN);
    ++count;
    hop = hop->next;
  } while (hop != origin->cpath);
  if (count < 3 || origin->build_state->desired_path_len != (int)count)
    return false;
  return crypto_digest256(digest, identities, count * DIGEST_LEN,
                          DIGEST_SHA256) == 0;
}

static entry_connection_t *
entry(uint64_t id, entry_connection_t *expected)
{
  if (!id || !expected)
    return NULL;
  connection_t *base = connection_get_by_global_id(id);
  return base && base->type == CONN_TYPE_AP &&
         TO_ENTRY_CONN(base) == expected ? expected : NULL;
}

static bool
capture_current(void)
{
  if (!probe.active || !owner_open(probe.owner) ||
      net_is_disabled() || !is_participating_on_network() ||
      monotime_absolute_usec() >= probe.expires)
    return false;
  entry_connection_t *anchor = entry(probe.anchor_id, probe.anchor);
  origin_circuit_t *circ = circuit_get_by_global_id(probe.circuit_id);
  if (!anchor || ENTRY_TO_CONN(anchor)->marked_for_close ||
      ENTRY_TO_CONN(anchor)->state != AP_CONN_STATE_OPEN ||
      !anchor->socks_request->has_finished || !circ || circ != probe.circuit ||
      ENTRY_TO_EDGE_CONN(anchor)->on_circuit != TO_CIRCUIT(circ) ||
      ENTRY_TO_EDGE_CONN(anchor)->cpath_layer != probe.last ||
      !credentials(anchor, probe.username, probe.password))
    return false;
  bool belongs = false;
  for (edge_connection_t *e = circ->p_streams; e; e = e->next_stream)
    belongs |= e == ENTRY_TO_EDGE_CONN(anchor);
  char digest[DIGEST256_LEN];
  return belongs && path(circ, probe.username, probe.password, digest) &&
         tor_memeq(digest, probe.path, DIGEST256_LEN) &&
         circ->cpath->prev == probe.last &&
         tor_memeq(probe.last->extend_info->identity_digest,
                   probe.exit, DIGEST_LEN);
}

static void
retire(const char *reason)
{
  probe.active = false;
  probe.reason = reason;
  probe.expires = 0;
  if (probe.timer)
    timer_disable(probe.timer);
  entry_connection_t *stream = entry(probe.stream_id, probe.stream);
  if (stream && !ENTRY_TO_CONN(stream)->marked_for_close) {
    connection_edge_end(ENTRY_TO_EDGE_CONN(stream), END_STREAM_REASON_MISC);
    connection_mark_unattached_ap(stream, END_STREAM_REASON_MISC);
    connection_close_immediate(ENTRY_TO_CONN(stream));
  }
  memwipe(probe.username, 0, sizeof(probe.username));
  memwipe(probe.password, 0, sizeof(probe.password));
  /* The pointer remains captured until Tor's actual connection-close hook.
   * A new capture cannot replace a stream that is still draining. */
}

static void
schedule(void)
{
  if (!probe.active)
    return;
  uint64_t now = monotime_absolute_usec();
  uint64_t delay = probe.expires > now ? probe.expires - now : 1;
  delay = MIN(delay, UINT64_C(100000));
  delay = ((delay + 99) / 100) * 100;
  struct timeval timeout = { 0, (long)delay };
  timer_schedule(probe.timer, &timeout);
}

static void
tick(tor_timer_t *timer, void *arg, const struct monotime_t *now)
{
  (void)timer; (void)arg; (void)now;
  if (!capture_current())
    retire("expired-or-path");
  else
    schedule();
}

bool
routervpn_lastrelay_current(entry_connection_t *stream)
{
  return stream && stream->routervpn_lastrelay && probe.used &&
         entry(probe.stream_id, probe.stream) == stream && capture_current() &&
         !ENTRY_TO_CONN(stream)->marked_for_close &&
         ENTRY_TO_EDGE_CONN(stream)->on_circuit == TO_CIRCUIT(probe.circuit) &&
         ENTRY_TO_EDGE_CONN(stream)->cpath_layer == probe.last &&
         credentials(stream, probe.username, probe.password);
}

void
routervpn_lastrelay_fail(entry_connection_t *stream, const char *reason)
{
  if (stream == entry(probe.stream_id, probe.stream))
    retire(reason);
  else if (stream && !ENTRY_TO_CONN(stream)->marked_for_close)
    connection_mark_unattached_ap(stream, END_STREAM_REASON_CANT_ATTACH);
}

void routervpn_lastrelay_invalidate(void) { retire("configuration"); }

void
routervpn_lastrelay_owner_closed(control_connection_t *owner)
{
  if (probe.owner == owner) {
    retire("owner");
    probe.owner = NULL;
  }
}

void
routervpn_lastrelay_connection_closed(entry_connection_t *connection)
{
  if (connection == probe.stream &&
      ENTRY_TO_CONN(connection)->global_identifier == probe.stream_id) {
    probe.stream = NULL;
    probe.stream_id = 0;
    if (!probe.ended)
      retire("stream");
  }
  if (connection == probe.anchor &&
      ENTRY_TO_CONN(connection)->global_identifier == probe.anchor_id) {
    retire("anchor");
    probe.anchor = NULL;
  }
}

void
routervpn_lastrelay_free_all(void)
{
  retire("shutdown");
  timer_free(probe.timer);
  memwipe(&probe, 0, sizeof(probe));
  highwater = 0;
}

bool
routervpn_lastrelay_reserved(const char *address)
{
  char canonical[256];
  strlcpy(canonical, address, sizeof(canonical));
  size_t length = strlen(canonical);
  while (length && canonical[length-1] == '.')
    canonical[--length] = 0;
  return !strcasecmp(canonical, LAST_SUFFIX+1) ||
         !strcasecmpend(canonical, LAST_SUFFIX);
}

/* Reserved addresses are consumed before address mapping, DNS or ordinary
 * routing. Bad/expired/replayed capabilities can never become normal CONNECT. */
int
routervpn_lastrelay_attach(entry_connection_t *stream,
                         origin_circuit_t *override,
                         crypt_path_t *override_hop)
{
  const char *address = stream->socks_request->address;
  if (!routervpn_lastrelay_reserved(address))
    return -2;
  stream->routervpn_lastrelay = 1;
  if (override || override_hop || !capture_current() || probe.used ||
      strcmp(address, probe.hostname) || stream->socks_request->port != 1 ||
      ENTRY_TO_CONN(stream)->linked ||
      ENTRY_TO_EDGE_CONN(stream)->on_circuit ||
      !credentials(stream, probe.username, probe.password)) {
    connection_mark_unattached_ap(stream, END_STREAM_REASON_CANT_ATTACH);
    return -1;
  }
  if (!stream->original_dest_address)
    stream->original_dest_address = tor_strdup(address);
  if (!connection_edge_compatible_with_circuit(stream, probe.circuit)) {
    connection_mark_unattached_ap(stream, END_STREAM_REASON_CANT_ATTACH);
    return -1;
  }
  probe.used = true;
  probe.stream = stream;
  probe.stream_id = ENTRY_TO_CONN(stream)->global_identifier;
  probe.stream_global = probe.stream_id;
  stream->use_begindir = 1;
  stream->want_onehop = 0;
  stream->may_use_optimistic_data = 0;
  ENTRY_TO_CONN(stream)->state = AP_CONN_STATE_CIRCUIT_WAIT;
  int result = connection_ap_handshake_attach_chosen_circuit(stream,
                                             probe.circuit, probe.last);
  if (result <= 0 || !routervpn_lastrelay_current(stream)) {
    retire("attach");
    return -1;
  }
  probe.relay_stream = ENTRY_TO_EDGE_CONN(stream)->stream_id;
  return result;
}

int
routervpn_lastrelay_send(edge_connection_t *edge, const char *data, size_t n)
{
  entry_connection_t *stream = EDGE_TO_ENTRY_CONN(edge);
  if (!routervpn_lastrelay_current(stream) || !probe.connected ||
      probe.ended || n > sizeof(LAST_REQUEST)-1-probe.request_bytes ||
      memcmp(data, LAST_REQUEST + probe.request_bytes, n)) {
    routervpn_lastrelay_fail(stream, "request");
    return -1;
  }
  probe.request_bytes += (unsigned)n;
  return 0;
}

int
routervpn_lastrelay_receive(edge_connection_t *edge, const relay_msg_t *msg,
                          circuit_t *circ, crypt_path_t *hop)
{
  entry_connection_t *stream = EDGE_TO_ENTRY_CONN(edge);
  if (!routervpn_lastrelay_current(stream) || circ != edge->on_circuit ||
      hop != probe.last || msg->stream_id != edge->stream_id || probe.ended) {
    routervpn_lastrelay_fail(stream, "reply-owner");
    return -1;
  }
  switch (msg->command) {
    case RELAY_COMMAND_CONNECTED:
      if (probe.connected || edge->base_.state != AP_CONN_STATE_CONNECT_WAIT)
        break;
      probe.connected = true;
      return 0;
    case RELAY_COMMAND_DATA:
      if (!probe.connected || edge->base_.state != AP_CONN_STATE_OPEN ||
          probe.request_bytes != sizeof(LAST_REQUEST)-1 ||
          msg->length > LAST_RESPONSE_LIMIT-probe.response_bytes)
        break;
      probe.response_bytes += msg->length;
      return 0;
    case RELAY_COMMAND_END:
      if (msg->length < 1)
        break;
      probe.ended = true;
      probe.end_reason = msg->body[0];
      /* No success/latency is manufactured. The client still validates the
       * bounded HTTP response; NOTDIRECTORY and every failed END are final. */
      probe.reason = "relay-end";
      return 0;
    case RELAY_COMMAND_SENDME:
      if (probe.connected)
        return 0;
      break;
    default:
      break;
  }
  routervpn_lastrelay_fail(stream, "reply-protocol");
  return -1;
}

static void
status(control_connection_t *owner)
{
  if (probe.active && !capture_current())
    retire("expired-or-path");
  char *reply;
  char fingerprint[HEX_DIGEST_LEN+1], digest[HEX_DIGEST256_LEN+1];
  base16_encode(fingerprint, sizeof(fingerprint), probe.exit, DIGEST_LEN);
  base16_encode(digest, sizeof(digest), probe.path, DIGEST256_LEN);
  tor_strlower(fingerprint);
  tor_strlower(digest);
  uint64_t now = monotime_absolute_usec();
  uint64_t ttl = probe.active && probe.expires > now ?
                 (probe.expires-now)/1000 : 0;
  const char *state = probe.active ?
      (probe.ended ? "ended" : probe.connected ? "connected" :
       probe.used ? "connecting" : "armed") :
      (probe.stream_id ? "draining" : "stopped");
  tor_asprintf(&reply, "version=1 state=%s reason=%s session=%s source=%s "
      "generation=%"PRIu64" anchor=%"PRIu64" circuit=%"PRIu32" "
      "exit=%s path_sha256=%s address=%s port=1 expires_ms=%"PRIu64" "
      "request_bytes=%u response_bytes=%u stream=%"PRIu64" relay_stream=%u "
      "end_reason=%u",
      state, probe.reason ? probe.reason : "captured", probe.session,
      probe.source, probe.generation, probe.anchor_id, probe.circuit_id,
      fingerprint, digest, probe.hostname, ttl,
      probe.request_bytes, probe.response_bytes, probe.stream_global,
      (unsigned)probe.relay_stream, (unsigned)probe.end_reason);
  control_write_reply(owner, 250, ' ', reply);
  tor_free(reply);
}

/* The locator comes from a retained actual SOCKS socket, never from a UI node
 * name or a global most-recent stream. The selected-DNS numeric target and
 * private isolation must both match. Discovery itself grants no measurement. */
static int
lookup_anchor(control_connection_t *owner, const control_cmd_args_t *args)
{
  if (smartlist_len(args->args) != 9)
    goto syntax;
  const char *session = smartlist_get(args->args, 1);
  const char *source = smartlist_get(args->args, 2);
  const char *username = smartlist_get(args->args, 3);
  const char *password = smartlist_get(args->args, 4);
  const char *client_text = smartlist_get(args->args, 5);
  const char *target_text = smartlist_get(args->args, 7);
  uint64_t client_port, target_port;
  tor_addr_t client, target;
  char client_string[TOR_ADDR_BUF_LEN], target_string[TOR_ADDR_BUF_LEN];
  if (!hex(session, 64) || !hex(source, 64) ||
      !(hex(username, 32) || hex(username, 64)) || !hex(password, 64) ||
      !number(smartlist_get(args->args, 6), 1, 65535, &client_port) ||
      !number(smartlist_get(args->args, 8), 1, 65535, &target_port) ||
      tor_addr_parse(&client, client_text) < 0 ||
      tor_addr_parse(&target, target_text) < 0 ||
      !tor_addr_is_loopback(&client) || tor_addr_is_internal(&target, 0) ||
      !tor_addr_to_str(client_string, &client, sizeof(client_string), 0) ||
      !tor_addr_to_str(target_string, &target, sizeof(target_string), 0) ||
      strcmp(client_string, client_text) || strcmp(target_string, target_text))
    goto syntax;
  smartlist_t *connections = get_connection_array();
  if (!connections || smartlist_len(connections) > 4096 ||
      net_is_disabled() || !is_participating_on_network())
    goto unavailable;
  entry_connection_t *found = NULL;
  origin_circuit_t *found_circuit = NULL;
  char digest[DIGEST256_LEN];
  SMARTLIST_FOREACH_BEGIN(connections, connection_t *, base) {
    if (base->type != CONN_TYPE_AP || base->marked_for_close ||
        base->linked || base->state != AP_CONN_STATE_OPEN ||
        base->port != client_port || !tor_addr_eq(&base->addr, &client))
      continue;
    entry_connection_t *anchor = TO_ENTRY_CONN(base);
    edge_connection_t *edge = ENTRY_TO_EDGE_CONN(anchor);
    if (anchor->routervpn_lastrelay || anchor->use_begindir ||
        !credentials(anchor, username, password) ||
        !anchor->socks_request->has_finished ||
        anchor->socks_request->port != target_port ||
        strcmp(anchor->socks_request->address, target_text) ||
        !anchor->original_dest_address ||
        strcmp(anchor->original_dest_address, target_text) ||
        !edge->on_circuit || !CIRCUIT_IS_ORIGIN(edge->on_circuit))
      continue;
    origin_circuit_t *circ = TO_ORIGIN_CIRCUIT(edge->on_circuit);
    if (!path(circ, username, password, digest) ||
        edge->cpath_layer != circ->cpath->prev)
      continue;
    bool belongs = false;
    for (edge_connection_t *e = circ->p_streams; e; e = e->next_stream)
      belongs |= e == edge;
    if (!belongs)
      continue;
    if (found)
      goto unavailable;
    found = anchor;
    found_circuit = circ;
  } SMARTLIST_FOREACH_END(base);
  if (!found)
    goto unavailable;
  /* Recompute only from the unique captured native circuit. */
  if (!path(found_circuit, username, password, digest))
    goto unavailable;
  char fingerprint[HEX_DIGEST_LEN+1], path_text[HEX_DIGEST256_LEN+1];
  base16_encode(fingerprint, sizeof(fingerprint),
      found_circuit->cpath->prev->extend_info->identity_digest, DIGEST_LEN);
  base16_encode(path_text, sizeof(path_text), digest, DIGEST256_LEN);
  tor_strlower(fingerprint);
  tor_strlower(path_text);
  char *reply;
  tor_asprintf(&reply, "version=1 session=%s source=%s anchor=%"PRIu64" "
      "circuit=%"PRIu32" exit=%s path_sha256=%s client_ip=%s client_port=%"PRIu64" "
      "target_ip=%s target_port=%"PRIu64,
      session, source, ENTRY_TO_CONN(found)->global_identifier,
      found_circuit->global_identifier, fingerprint, path_text,
      client_string, client_port, target_string, target_port);
  control_write_reply(owner, 250, ' ', reply);
  tor_free(reply);
  return 0;
 syntax:
  control_write_reply(owner, 512, ' ', "Invalid last-relay anchor locator");
  return 0;
 unavailable:
  control_write_reply(owner, 551, ' ', "Last-relay anchor is absent, ambiguous or retired");
  return 0;
}

int
routervpn_lastrelay_command(control_connection_t *owner,
                           const control_cmd_args_t *args)
{
  const int count = smartlist_len(args->args);
  const char *action = count ? smartlist_get(args->args, 0) : "";
  if (!owner_open(owner)) {
    control_write_reply(owner, 551, ' ', "Last-relay probe requires its owning controller");
    return 0;
  }
  if (!strcmp(action, "ANCHOR"))
    return lookup_anchor(owner, args);
  if (!strcmp(action, "INFO") && count == 1) {
    char *reply;
    tor_asprintf(&reply, "version=1 transport=begindir min_ttl_ms=100 "
        "max_ttl_ms=10000 max_response_bytes=8192 generation_highwater=%"PRIu64,
        highwater);
    control_write_reply(owner, 250, ' ', reply);
    tor_free(reply);
    return 0;
  }
  uint64_t generation;
  if (count < 4 || !hex(smartlist_get(args->args, 1), 64) ||
      !hex(smartlist_get(args->args, 2), 64) ||
      !number(smartlist_get(args->args, 3), 1, INT64_MAX, &generation))
    goto syntax;
  const char *session = smartlist_get(args->args, 1);
  const char *source = smartlist_get(args->args, 2);
  if (!strcmp(action, "CAPTURE") && count == 9) {
    uint64_t ttl, anchor_id;
    const char *username = smartlist_get(args->args, 6);
    const char *password = smartlist_get(args->args, 7);
    const char *nonce = smartlist_get(args->args, 8);
    if (!number(smartlist_get(args->args, 4), 100, LAST_MAX_TTL_MS, &ttl) ||
        !number(smartlist_get(args->args, 5), 1, INT64_MAX, &anchor_id) ||
        !(hex(username, 32) || hex(username, 64)) || !hex(password, 64) ||
        !hex(nonce, 64))
      goto syntax;
    if (probe.active && !capture_current())
      retire("expired-or-path");
    if (probe.active || probe.stream_id || generation <= highwater ||
        net_is_disabled() || !is_participating_on_network())
      goto unavailable;
    connection_t *base = connection_get_by_global_id(anchor_id);
    if (!base || base->type != CONN_TYPE_AP || base->marked_for_close ||
        base->state != AP_CONN_STATE_OPEN || base->linked)
      goto unavailable;
    entry_connection_t *anchor = TO_ENTRY_CONN(base);
    edge_connection_t *edge = ENTRY_TO_EDGE_CONN(anchor);
    if (anchor->routervpn_lastrelay || anchor->use_begindir ||
        !anchor->socks_request->has_finished || !credentials(anchor, username, password) ||
        !edge->on_circuit || !CIRCUIT_IS_ORIGIN(edge->on_circuit))
      goto unavailable;
    origin_circuit_t *circ = TO_ORIGIN_CIRCUIT(edge->on_circuit);
    char digest[DIGEST256_LEN];
    if (!path(circ, username, password, digest) ||
        edge->cpath_layer != circ->cpath->prev)
      goto unavailable;
    bool belongs = false;
    for (edge_connection_t *e = circ->p_streams; e; e = e->next_stream)
      belongs |= e == edge;
    if (!belongs)
      goto unavailable;
    tor_timer_t *timer = probe.timer;
    memwipe(&probe, 0, sizeof(probe));
    probe.timer = timer ? timer : timer_new(tick, NULL);
    probe.owner = owner;
    probe.active = true;
    probe.generation = highwater = generation;
    probe.anchor_id = anchor_id;
    probe.anchor = anchor;
    probe.circuit = circ;
    probe.circuit_id = circ->global_identifier;
    probe.last = circ->cpath->prev;
    memcpy(probe.exit, probe.last->extend_info->identity_digest, DIGEST_LEN);
    memcpy(probe.path, digest, DIGEST256_LEN);
    strlcpy(probe.session, session, sizeof(probe.session));
    strlcpy(probe.source, source, sizeof(probe.source));
    strlcpy(probe.nonce, nonce, sizeof(probe.nonce));
    strlcpy(probe.username, username, sizeof(probe.username));
    strlcpy(probe.password, password, sizeof(probe.password));
    tor_snprintf(probe.hostname, sizeof(probe.hostname), "%"PRIu64".%.32s.%.32s" LAST_SUFFIX,
                 generation, nonce, nonce+32);
    probe.expires = monotime_absolute_usec() + ttl * 1000;
    schedule();
    status(owner);
    return 0;
  }
  if ((!strcmp(action, "STATUS") || !strcmp(action, "CLOSE")) && count == 5) {
    if (probe.owner != owner || generation != probe.generation ||
        strcmp(session, probe.session) || strcmp(source, probe.source) ||
        strcmp(smartlist_get(args->args, 4), probe.nonce))
      goto unavailable;
    if (!strcmp(action, "CLOSE"))
      retire("controller");
    status(owner);
    return 0;
  }
 syntax:
  control_write_reply(owner, 512, ' ', "Invalid last-relay capture command");
  return 0;
 unavailable:
  control_write_reply(owner, 551, ' ', "Last-relay capture is not eligible or current");
  return 0;
}
