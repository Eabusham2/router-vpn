/* Native prerequisite tests. Circuit construction/keys, time and peer socket
 * endpoints are fixtures. Tor's command parser, stream attachment, cell
 * encoder, three-hop crypto, queues, response dispatch and close hooks run.
 * No public network or client-origin latency result is fabricated here. */
#define CHANNEL_OBJECT_PRIVATE
#define CIRCUITLIST_PRIVATE
#define CRYPT_PATH_PRIVATE
#define TOR_TIMERS_PRIVATE
#define RELAY_PRIVATE
#define MAINLOOP_PRIVATE
#include "core/or/or.h"
#include "app/config/config.h"
#include "core/mainloop/connection.h"
#include "core/mainloop/mainloop.h"
#include "core/mainloop/netstatus.h"
#include "core/or/channel.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/circuitmux_ewma.h"
#include "core/or/connection_edge.h"
#include "core/or/crypt_path.h"
#include "core/or/relay.h"
#include "core/or/relay_msg.h"
#include "core/or/scheduler.h"
#include "core/crypto/relay_crypto.h"
#include "core/or/cell_st.h"
#include "core/or/cell_queue_st.h"
#include "core/or/cpath_build_state_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/entry_connection_st.h"
#include "core/or/extend_info_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "core/or/socks_request_st.h"
#include "feature/client/addressmap.h"
#include "feature/control/control.h"
#include "feature/control/control_cmd.h"
#include "feature/control/control_proto.h"
#include "feature/control/control_connection_st.h"
#include "feature/control/routervpn_lastrelay.h"
#include "feature/dircommon/dir_connection_st.h"
#include "feature/dircommon/directory.h"
#include "feature/hibernate/hibernate.h"
#include "lib/buf/buffers.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include "test/test.h"

#define SESSION "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SOURCE "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define USER "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define PASSWORD "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define NONCE "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
#define TOKEN "1.eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.lastrelay.routervpn.invalid"
#define ID SESSION " " SOURCE " 1 " NONCE
#define REQUEST "GET /tor/robots.txt HTTP/1.0\r\n\r\n"
#define RESPONSE "HTTP/1.0 200 OK\r\nContent-Length: 28\r\n\r\nUser-agent: *\r\nDisallow: /\r\n"

channel_t *new_fake_channel(void);
void free_fake_channel(channel_t *);

typedef struct fixture {
  control_connection_t owner, stranger;
  origin_circuit_t *origin;
  or_circuit_t *relay[3];
  channel_t *out, *in;
  entry_connection_t *anchor;
  smartlist_t *peers;
  int64_t clock;
  int code, errors, peer_mode;
  unsigned begins, requests, replies;
  bool wiped;
  const char *variant;
  char *reply;
} fixture_t;
static fixture_t *fixture;

static int awake(void) { return 0; }
static int writable(channel_t *channel) { (void)channel; return 32; }
static void queued(channel_t *channel) { (void)channel; }
static void
reply(control_connection_t *owner, int code, int sep, const char *text)
{
  (void)owner; (void)sep;
  fixture->code = code;
  tor_free(fixture->reply);
  fixture->reply = tor_strdup(text);
}

static edge_connection_t *
find_stream(edge_connection_t *first, streamid_t id)
{
  for (edge_connection_t *e = first; e; e = e->next_stream)
    if (e->stream_id == id)
      return e;
  return NULL;
}

static void
unpack(channel_t *channel, packed_cell_t *packed, cell_t *cell)
{
  memset(cell, 0, sizeof(*cell));
  unsigned offset = channel->wide_circ_ids ? 5 : 3;
  cell->circ_id = channel->wide_circ_ids ?
      ntohl(get_uint32(packed->body)) : ntohs(get_uint16(packed->body));
  cell->command = (uint8_t)packed->body[offset-1];
  memcpy(cell->payload, packed->body+offset, CELL_PAYLOAD_SIZE);
}

static int
receive_wire(channel_t *channel, packed_cell_t *packed)
{
  fixture_t *f = fixture;
  cell_t cell;
  unpack(channel, packed, &cell);
  for (int i = 1; i >= 0; --i) {
    char recognized = 0;
    crypt_path_t *hop = NULL;
    if (relay_decrypt_cell(TO_CIRCUIT(f->relay[i]), &cell,
                          CELL_DIRECTION_IN, &hop, &recognized) != 0)
      ++f->errors;
  }
  char recognized = 0;
  crypt_path_t *hop = NULL;
  if (relay_decrypt_cell(TO_CIRCUIT(f->origin), &cell,
                        CELL_DIRECTION_IN, &hop, &recognized) != 0 ||
      !recognized || hop != f->origin->cpath->prev) {
    ++f->errors;
    return -1;
  }
  relay_msg_t msg;
  if (relay_msg_decode_cell_in_place(RELAY_CELL_FORMAT_V0, &cell, &msg)) {
    ++f->errors;
    return -1;
  }
  edge_connection_t *edge = find_stream(f->origin->p_streams, msg.stream_id);
  if (!edge || connection_edge_process_relay_cell(&msg,
             TO_CIRCUIT(f->origin), edge, hop) < 0) {
    ++f->errors;
    return -1;
  }
  ++f->replies;
  return 1;
}

static int
send_wire(channel_t *channel, packed_cell_t *packed)
{
  fixture_t *f = fixture;
  cell_t cell;
  unpack(channel, packed, &cell);
  if (cell.circ_id != 101 ||
      (cell.command != CELL_RELAY && cell.command != CELL_RELAY_EARLY)) {
    ++f->errors;
    return -1;
  }
  uint8_t encrypted[CELL_PAYLOAD_SIZE];
  memcpy(encrypted, cell.payload, sizeof(encrypted));
  for (unsigned i = 0; i < 3; ++i) {
    char recognized = 0;
    crypt_path_t *hop = NULL;
    if (relay_decrypt_cell(TO_CIRCUIT(f->relay[i]), &cell,
                          CELL_DIRECTION_OUT, &hop, &recognized) != 0 ||
        hop || !!recognized != (i == 2)) {
      ++f->errors;
      return -1;
    }
  }
  relay_msg_t msg;
  if (relay_msg_decode_cell_in_place(RELAY_CELL_FORMAT_V0, &cell, &msg) ||
      !memcmp(encrypted, cell.payload, sizeof(encrypted))) {
    ++f->errors;
    return -1;
  }
  if (msg.command == RELAY_COMMAND_BEGIN_DIR) {
    ++f->begins;
    if (msg.length || !msg.stream_id)
      ++f->errors;
  } else if (msg.command == RELAY_COMMAND_DATA) {
    ++f->requests;
    if (msg.length != sizeof(REQUEST)-1 ||
        memcmp(msg.body, REQUEST, sizeof(REQUEST)-1))
      ++f->errors;
  } else if (msg.command != RELAY_COMMAND_END) {
    ++f->errors;
  }
  if (f->peer_mode == 2) {
    /* Deliberately pending peer: tests inject actual encrypted relay cells. */
  } else if (f->peer_mode == 1) {
    edge_connection_t *edge = find_stream(f->relay[2]->n_streams, msg.stream_id);
    if (connection_edge_process_relay_cell(&msg, TO_CIRCUIT(f->relay[2]),
                                           edge, NULL) < 0)
      ++f->errors;
  } else if (msg.command == RELAY_COMMAND_BEGIN_DIR) {
    if (relay_send_command_from_edge(msg.stream_id, TO_CIRCUIT(f->relay[2]),
          RELAY_COMMAND_CONNECTED, NULL, 0, NULL) < 0)
      ++f->errors;
  } else if (msg.command == RELAY_COMMAND_DATA) {
    if (relay_send_command_from_edge(msg.stream_id, TO_CIRCUIT(f->relay[2]),
          RELAY_COMMAND_DATA, RESPONSE, sizeof(RESPONSE)-1, NULL) < 0)
      ++f->errors;
  }
  return 1;
}

static void flush(void)
{
  channel_flush_from_first_active_circuit(fixture->out, 16);
  channel_flush_from_first_active_circuit(fixture->in, 16);
}

static entry_connection_t *
new_entry(const char *host, uint16_t port)
{
  /* Real loopback TCP endpoints: ANCHOR reads the accepted socket's peer
   * tuple, matching the retained client's actual LocalAddr, not a guessed ID. */
  tor_socket_t pair[2];
  tor_socket_t listener = tor_open_socket(AF_INET, SOCK_STREAM, 0);
  struct sockaddr_in server, client;
  memset(&server, 0, sizeof(server));
  server.sin_family = AF_INET;
  server.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  socklen_t length = sizeof(server);
  tor_assert(SOCKET_OK(listener));
  tor_assert(bind(listener, (struct sockaddr *)&server, sizeof(server)) == 0);
  tor_assert(tor_getsockname(listener, (struct sockaddr *)&server, &length) == 0);
  tor_assert(listen(listener, 1) == 0);
  pair[1] = tor_open_socket(AF_INET, SOCK_STREAM, 0);
  tor_assert(SOCKET_OK(pair[1]));
  tor_assert(tor_connect_socket(pair[1], (struct sockaddr *)&server,
                              sizeof(server)) == 0);
  length = sizeof(client);
  pair[0] = tor_accept_socket(listener, (struct sockaddr *)&client, &length);
  tor_assert(SOCKET_OK(pair[0]));
  tor_close_socket(listener);
  entry_connection_t *entry = entry_connection_new(CONN_TYPE_AP, AF_INET);
  connection_t *base = ENTRY_TO_CONN(entry);
  base->s = pair[0];
  set_socket_nonblocking(pair[0]);
  set_socket_nonblocking(pair[1]);
  smartlist_add(fixture->peers, (void *)(uintptr_t)pair[1]);
  base->address = tor_strdup("127.0.0.1");
  tor_addr_parse(&base->addr, "127.0.0.1");
  base->port = ntohs(client.sin_port);
  base->state = AP_CONN_STATE_SOCKS_WAIT;
  entry->entry_cfg.isolation_flags = ISO_SOCKSAUTH;
  entry->entry_cfg.session_group = 41;
  entry->entry_cfg.ipv4_traffic = 1;
  entry->socks_request->listener_type = CONN_TYPE_AP_LISTENER;
  entry->socks_request->socks_version = 5;
  entry->socks_request->command = SOCKS_COMMAND_CONNECT;
  strlcpy(entry->socks_request->address, host,
          sizeof(entry->socks_request->address));
  entry->socks_request->port = port;
  entry->socks_request->username = tor_memdup(USER, 64);
  entry->socks_request->password = tor_memdup(PASSWORD, 64);
  entry->socks_request->usernamelen = entry->socks_request->passwordlen = 64;
  tor_assert(connection_add(base) == 0);
  return entry;
}

static void command_for(control_connection_t *owner, const char *body)
{
  char *copy = tor_strdup(body);
  size_t length = strlen(copy);
  owner->current_cmd = (char *)"ROUTERVPN_LASTRELAY";
  fixture->code = 0;
  handle_control_command(owner, (uint32_t)length, copy);
  fixture->wiped = true;
  for (size_t i = 0; i < length; ++i)
    fixture->wiped &= copy[i] == 0;
  tor_free(copy);
}
static void command(const char *body) { command_for(&fixture->owner, body); }
static void capture_generation(unsigned generation, unsigned ttl)
{
  char *body;
  tor_asprintf(&body, "CAPTURE " SESSION " " SOURCE " %u %u %"PRIu64" "
               USER " " PASSWORD " " NONCE,
               generation, ttl, ENTRY_TO_CONN(fixture->anchor)->global_identifier);
  command(body);
  tor_free(body);
}

static void capture(unsigned ttl) { capture_generation(1, ttl); }

static uint64_t value(const char *name)
{
  char *key;
  tor_asprintf(&key, "%s=", name);
  const char *found = strstr(fixture->reply ? fixture->reply : "", key);
  tor_free(key);
  return found ? strtoull(strchr(found, '=')+1, NULL, 10) : UINT64_MAX;
}

static void advance(unsigned milliseconds)
{
  fixture->clock += (int64_t)milliseconds * 1000000;
  monotime_set_mock_time_nsec(fixture->clock);
  monotime_coarse_set_mock_time_nsec(fixture->clock);
  timers_run_pending();
}

static void *setup(const struct testcase_t *test)
{
  (void)test;
  fixture_t *f = fixture = tor_malloc_zero(sizeof(*f));
  f->variant = test->setup_data;
  tor_init_connection_lists();
  f->peers = smartlist_new();
  f->owner.base_.state = f->stranger.base_.state = CONTROL_CONN_STATE_OPEN;
  f->owner.is_owning_control_connection = f->stranger.is_owning_control_connection = 1;
  get_options_mutable()->DisableNetwork = 0;
  set_network_participation(true);
  f->clock = monotime_absolute_nsec()+1000000000;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(f->clock);
  monotime_coarse_set_mock_time_nsec(f->clock);
  timers_initialize();
  cmux_ewma_set_options(NULL, NULL);
  MOCK(control_write_reply, reply);
  MOCK(scheduler_channel_has_waiting_cells, queued);
  MOCK(we_are_hibernating, awake);
  f->out = new_fake_channel();
  f->in = new_fake_channel();
  f->out->wide_circ_ids = f->in->wide_circ_ids = 1;
  f->out->write_packed_cell = send_wire;
  f->in->write_packed_cell = receive_wire;
  f->out->num_cells_writeable = f->in->num_cells_writeable = writable;
  origin_circuit_t *origin = f->origin = origin_circuit_new();
  origin->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
  origin->base_.state = CIRCUIT_STATE_OPEN;
  origin->build_state = tor_malloc_zero(sizeof(cpath_build_state_t));
  origin->build_state->desired_path_len = 3;
  for (unsigned i = 0; i < 3; ++i) {
    char key[CPATH_KEY_MATERIAL_LEN];
    crypto_rand(key, sizeof(key));
    crypt_path_t *hop = tor_malloc_zero(sizeof(*hop));
    hop->magic = CRYPT_PATH_MAGIC;
    hop->state = CPATH_STATE_OPEN;
    hop->package_window = hop->deliver_window = CIRCWINDOW_START;
    hop->extend_info = tor_malloc_zero(sizeof(extend_info_t));
    memset(hop->extend_info->identity_digest, '1'+i, DIGEST_LEN);
    relay_crypto_init(RELAY_CRYPTO_ALG_TOR1, &hop->pvt_crypto, key, sizeof(key));
    cpath_extend_linked_list(&origin->cpath, hop);
    f->relay[i] = or_circuit_new(0, NULL);
    f->relay[i]->base_.state = CIRCUIT_STATE_OPEN;
    f->relay[i]->base_.purpose = CIRCUIT_PURPOSE_OR;
    relay_crypto_init(RELAY_CRYPTO_ALG_TOR1, &f->relay[i]->crypto, key, sizeof(key));
  }
  circuit_set_n_circid_chan(TO_CIRCUIT(origin), 101, f->out);
  circuit_set_p_circid_chan(f->relay[2], 501, f->in);
  f->anchor = new_entry("1.1.1.1", 443);
  ENTRY_TO_CONN(f->anchor)->state = AP_CONN_STATE_OPEN;
  f->anchor->socks_request->has_finished = 1;
  f->anchor->original_dest_address = tor_strdup("1.1.1.1");
  edge_connection_t *edge = ENTRY_TO_EDGE_CONN(f->anchor);
  edge->on_circuit = TO_CIRCUIT(origin);
  edge->cpath_layer = origin->cpath->prev;
  edge->stream_id = 30;
  edge->package_window = edge->deliver_window = STREAMWINDOW_START;
  origin->p_streams = edge;
  connection_edge_update_circuit_isolation(f->anchor, origin, 0);
  origin->isolation_any_streams_attached = 1;
  return f;
}

static int teardown(const struct testcase_t *test, void *argument)
{
  (void)test;
  fixture_t *f = argument;
  routervpn_lastrelay_owner_closed(&f->owner);
  smartlist_t *connections = get_connection_array();
  SMARTLIST_FOREACH_BEGIN(connections, connection_t *, base) {
    if (CONN_IS_EDGE(base)) {
      TO_EDGE_CONN(base)->edge_has_sent_end = 1;
      TO_EDGE_CONN(base)->end_reason = END_STREAM_REASON_MISC;
      if (base->type == CONN_TYPE_AP)
        TO_ENTRY_CONN(base)->socks_request->has_finished = 1;
    }
    if (!base->marked_for_close) {
      connection_close_immediate(base);
      connection_mark_for_close(base);
    }
  } SMARTLIST_FOREACH_END(base);
  close_closeable_connections();
  routervpn_lastrelay_free_all();
  circuit_free_(TO_CIRCUIT(f->origin));
  for (unsigned i = 0; i < 3; ++i)
    circuit_free_(TO_CIRCUIT(f->relay[i]));
  free_fake_channel(f->out);
  free_fake_channel(f->in);
  SMARTLIST_FOREACH(f->peers, void *, p, tor_close_socket((tor_socket_t)(uintptr_t)p));
  smartlist_free(f->peers);
  circuitmux_ewma_free_all();
  timers_shutdown();
  monotime_disable_test_mocking();
  UNMOCK(control_write_reply);
  UNMOCK(scheduler_channel_has_waiting_cells);
  UNMOCK(we_are_hibernating);
  tor_free(f->reply);
  tor_free(f);
  fixture = NULL;
  return 1;
}
static const struct testcase_setup_t tests_setup = { setup, teardown };

static void test_native_wire(void *arg)
{
  fixture_t *f = arg;
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  tt_assert(f->wiped);
  tt_assert(strstr(f->reply, TOKEN));
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, 1);
  tt_assert(stream->use_begindir);
  tt_assert(!stream->want_onehop);
  tt_assert(!stream->may_use_optimistic_data);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  tt_int_op(f->begins, OP_EQ, 1);
  tt_int_op(ENTRY_TO_CONN(stream)->state, OP_EQ, AP_CONN_STATE_OPEN);
  tt_ptr_op(ENTRY_TO_EDGE_CONN(stream)->on_circuit, OP_EQ, TO_CIRCUIT(f->origin));
  tt_ptr_op(ENTRY_TO_EDGE_CONN(stream)->cpath_layer, OP_EQ, f->origin->cpath->prev);
  buf_clear(ENTRY_TO_CONN(stream)->outbuf);
  connection_stop_writing(ENTRY_TO_CONN(stream));
  buf_add(ENTRY_TO_CONN(stream)->inbuf, REQUEST, sizeof(REQUEST)-1);
  tt_int_op(connection_edge_process_inbuf(ENTRY_TO_EDGE_CONN(stream), 1), OP_EQ, 0);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  tt_int_op(f->requests, OP_EQ, 1);
  tt_int_op(buf_datalen(ENTRY_TO_CONN(stream)->outbuf), OP_EQ, sizeof(RESPONSE)-1);
  char body[sizeof(RESPONSE)];
  memset(body, 0, sizeof(body));
  buf_peek(ENTRY_TO_CONN(stream)->outbuf, body, sizeof(RESPONSE)-1);
  tt_str_op(body, OP_EQ, RESPONSE);
  command("STATUS " ID);
  tt_int_op(f->code, OP_EQ, 250);
  tt_u64_op(value("request_bytes"), OP_EQ, sizeof(REQUEST)-1);
  tt_u64_op(value("response_bytes"), OP_EQ, sizeof(RESPONSE)-1);
  tt_u64_op(value("stream"), OP_EQ, ENTRY_TO_CONN(stream)->global_identifier);
  command("CLOSE " ID);
  tt_assert(strstr(f->reply, "state=draining"));
  tt_assert(ENTRY_TO_CONN(stream)->marked_for_close);
  close_closeable_connections();
  command("CLOSE " ID);
  tt_assert(strstr(f->reply, "state=stopped"));
  tt_assert(!ENTRY_TO_CONN(f->anchor)->marked_for_close);
 done: ;
}

static void test_expiry_replay(void *arg)
{
  fixture_t *f = arg;
  capture(100);
  tt_int_op(f->code, OP_EQ, 250);
  advance(100);
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, -1);
  tt_assert(ENTRY_TO_CONN(stream)->marked_for_close);
  tt_ptr_op(ENTRY_TO_EDGE_CONN(stream)->on_circuit, OP_EQ, NULL);
  tt_int_op(f->begins, OP_EQ, 0);
  capture(3000);
  tt_int_op(f->code, OP_EQ, 551);
  command("CLOSE " ID);
  tt_int_op(f->code, OP_EQ, 250);
  tt_assert(strstr(f->reply, "state=stopped"));
 done: ;
}

static void test_owner_and_nonce(void *arg)
{
  fixture_t *f = arg;
  f->owner.is_owning_control_connection = 0;
  capture(3000);
  tt_int_op(f->code, OP_EQ, 551);
  f->owner.is_owning_control_connection = 1;
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  command_for(&f->stranger, "CLOSE " ID);
  tt_int_op(f->code, OP_EQ, 551);
  entry_connection_t *wrong = new_entry(TOKEN, 1);
  wrong->socks_request->password[0] = 'f';
  tt_int_op(connection_ap_handshake_rewrite_and_attach(wrong, NULL, NULL), OP_EQ, -1);
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, 1);
  entry_connection_t *again = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(again, NULL, NULL), OP_EQ, -1);
  tt_ptr_op(ENTRY_TO_EDGE_CONN(again)->on_circuit, OP_EQ, NULL);
  routervpn_lastrelay_owner_closed(&f->stranger);
  tt_assert(!ENTRY_TO_CONN(stream)->marked_for_close);
  routervpn_lastrelay_owner_closed(&f->owner);
  tt_assert(ENTRY_TO_CONN(stream)->marked_for_close);
  tt_assert(!ENTRY_TO_CONN(f->anchor)->marked_for_close);
 done: ;
}

static void test_real_rejection(void *arg)
{
  fixture_t *f = arg;
  f->peer_mode = 1;
  get_options_mutable()->BridgeRelay = 0;
  get_options_mutable()->DirCache = 0;
  get_options_mutable()->ClientOnly = !strcmp(f->variant, "client");
  get_options_mutable()->ORPort_set = 1;
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, 1);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  tt_int_op(f->begins, OP_EQ, 1);
  tt_assert(ENTRY_TO_CONN(stream)->marked_for_close);
  tt_assert(ENTRY_TO_CONN(stream)->state != AP_CONN_STATE_OPEN);
  tt_int_op(stream->num_circuits_launched, OP_EQ, 0);
  tt_int_op(f->requests, OP_EQ, 0);
  tt_assert(!ENTRY_TO_CONN(f->anchor)->marked_for_close);
  command("STATUS " ID);
#ifdef HAVE_MODULE_RELAY
  tt_u64_op(value("end_reason"), OP_EQ, !strcmp(f->variant, "client") ?
      END_STREAM_REASON_EXITPOLICY : END_STREAM_REASON_NOTDIRECTORY);
#else
  /* The shipping client has no relay module. Its peer cannot serve BEGIN_DIR,
   * and the genuine early native rejection is EXITPOLICY. */
  tt_u64_op(value("end_reason"), OP_EQ, END_STREAM_REASON_EXITPOLICY);
#endif
 done: ;
}

static void locate(const char *user, const char *client, unsigned client_port,
                   const char *target, unsigned target_port)
{
  char *body;
  tor_asprintf(&body, "ANCHOR " SESSION " " SOURCE " %s " PASSWORD
      " %s %u %s %u", user, client, client_port, target, target_port);
  command(body);
  tor_free(body);
}

static void test_anchor_lookup(void *arg)
{
  fixture_t *f = arg;
  connection_t *base = ENTRY_TO_CONN(f->anchor);
  struct sockaddr_in actual;
  socklen_t actual_length = sizeof(actual);
  tor_socket_t socket = (tor_socket_t)(uintptr_t)smartlist_get(f->peers, 0);
  tt_int_op(tor_getsockname(socket, (struct sockaddr *)&actual, &actual_length),
            OP_EQ, 0);
  tt_uint_op(ntohs(actual.sin_port), OP_EQ, base->port);
  locate(USER, "127.0.0.1", ntohs(actual.sin_port), "1.1.1.1", 443);
  tt_int_op(f->code, OP_EQ, 250);
  tt_assert(f->wiped);
  tt_u64_op(value("anchor"), OP_EQ, base->global_identifier);
  tt_u64_op(value("circuit"), OP_EQ, f->origin->global_identifier);
  tt_assert(strstr(f->reply, "exit=3333333333333333333333333333333333333333"));
  tt_assert(strstr(f->reply, "target_ip=1.1.1.1 target_port=443"));
  tt_int_op(f->begins, OP_EQ, 0);
  command("INFO");
  tt_u64_op(value("generation_highwater"), OP_EQ, 0);

  locate(USER, "127.0.0.1", base->port == 65535 ? 65534 : base->port+1,
         "1.1.1.1", 443);
  tt_int_op(f->code, OP_EQ, 551);
  locate(USER, "127.0.0.1", base->port, "1.0.0.1", 443);
  tt_int_op(f->code, OP_EQ, 551);
  locate(USER, "127.0.0.1", base->port, "1.1.1.1", 80);
  tt_int_op(f->code, OP_EQ, 551);
  locate(SOURCE, "127.0.0.1", base->port, "1.1.1.1", 443);
  tt_int_op(f->code, OP_EQ, 551);
  locate(USER, "127.0.0.1", base->port, "external.example", 443);
  tt_int_op(f->code, OP_EQ, 512);
  locate(USER, "127.0.0.1", base->port, "192.168.1.1", 443);
  tt_int_op(f->code, OP_EQ, 512);
  locate(USER, "1.1.1.1", base->port, "1.1.1.1", 443);
  tt_int_op(f->code, OP_EQ, 512);
  f->owner.is_owning_control_connection = 0;
  locate(USER, "127.0.0.1", base->port, "1.1.1.1", 443);
  f->owner.is_owning_control_connection = 1;
  tt_int_op(f->code, OP_EQ, 551);

  /* Deliberately duplicate registry metadata to prove ambiguous discovery
   * refuses instead of taking the first/most recent eligible stream. */
  entry_connection_t *duplicate = new_entry("1.1.1.1", 443);
  ENTRY_TO_CONN(duplicate)->port = base->port;
  ENTRY_TO_CONN(duplicate)->state = AP_CONN_STATE_OPEN;
  duplicate->socks_request->has_finished = 1;
  duplicate->original_dest_address = tor_strdup("1.1.1.1");
  edge_connection_t *edge = ENTRY_TO_EDGE_CONN(duplicate);
  edge->on_circuit = TO_CIRCUIT(f->origin);
  edge->cpath_layer = f->origin->cpath->prev;
  edge->stream_id = 31;
  edge->next_stream = f->origin->p_streams;
  f->origin->p_streams = edge;
  locate(USER, "127.0.0.1", base->port, "1.1.1.1", 443);
  tt_int_op(f->code, OP_EQ, 551);
 done: ;
}

static void test_ineligible_path(void *arg)
{
  fixture_t *f = arg;
  f->origin->build_state->onehop_tunnel = 1;
  capture(3000);
  f->origin->build_state->onehop_tunnel = 0;
  tt_int_op(f->code, OP_EQ, 551);
  f->origin->build_state->is_internal = 1;
  capture(3000);
  f->origin->build_state->is_internal = 0;
  tt_int_op(f->code, OP_EQ, 551);
  uint8_t conflux_nonce[32] = { 1 };
  f->origin->base_.conflux_pending_nonce = conflux_nonce;
  f->origin->base_.purpose = CIRCUIT_PURPOSE_CONFLUX_UNLINKED;
  capture(3000);
  f->origin->base_.conflux_pending_nonce = NULL;
  f->origin->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
  tt_int_op(f->code, OP_EQ, 551);
  f->origin->unusable_for_new_conns = 1;
  capture(3000);
  f->origin->unusable_for_new_conns = 0;
  tt_int_op(f->code, OP_EQ, 551);
  f->origin->socks_password[0] = 'f';
  capture(3000);
  f->origin->socks_password[0] = PASSWORD[0];
  tt_int_op(f->code, OP_EQ, 551);
  f->origin->p_streams = NULL;
  capture(3000);
  f->origin->p_streams = ENTRY_TO_EDGE_CONN(f->anchor);
  tt_int_op(f->code, OP_EQ, 551);
  f->origin->build_state->desired_path_len = 1;
  capture(3000);
  f->origin->build_state->desired_path_len = 3;
  tt_int_op(f->code, OP_EQ, 551);
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  tt_int_op(f->begins, OP_EQ, 0);
 done: ;
}

static void test_live_retire(void *arg)
{
  fixture_t *f = arg;
  capture(100);
  tt_int_op(f->code, OP_EQ, 250);
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, 1);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  uint64_t stream_id = ENTRY_TO_CONN(stream)->global_identifier;
  uint64_t anchor_id = ENTRY_TO_CONN(f->anchor)->global_identifier;
  if (!strcmp(f->variant, "expiry")) {
    advance(100);
  } else if (!strcmp(f->variant, "path")) {
    f->origin->cpath->prev->extend_info->identity_digest[0] ^= 1;
    advance(10);
    command("STATUS " ID);
  } else if (!strcmp(f->variant, "circuit")) {
    ENTRY_TO_EDGE_CONN(f->anchor)->on_circuit = TO_CIRCUIT(f->relay[0]);
    command("STATUS " ID);
    ENTRY_TO_EDGE_CONN(f->anchor)->on_circuit = TO_CIRCUIT(f->origin);
  } else if (!strcmp(f->variant, "configuration")) {
    routervpn_lastrelay_invalidate();
  } else if (!strcmp(f->variant, "isolation")) {
    f->anchor->socks_request->password[0] = 'f';
    command("STATUS " ID);
  } else if (!strcmp(f->variant, "membership")) {
    ENTRY_TO_EDGE_CONN(stream)->next_stream = NULL;
    command("STATUS " ID);
    ENTRY_TO_EDGE_CONN(stream)->next_stream = ENTRY_TO_EDGE_CONN(f->anchor);
  } else if (!strcmp(f->variant, "retry")) {
    tt_int_op(connection_ap_detach_retriable(stream, f->origin,
               END_STREAM_REASON_TIMEOUT), OP_EQ, -1);
  } else {
    tt_abort_msg("unknown native lifetime case");
  }
  tt_assert(ENTRY_TO_CONN(stream)->marked_for_close);
  tt_assert(!SOCKET_OK(ENTRY_TO_CONN(stream)->s));
  tt_assert(!ENTRY_TO_CONN(f->anchor)->marked_for_close);
  tt_int_op(stream->num_circuits_launched, OP_EQ, 0);
  command("STATUS " ID);
  tt_assert(strstr(f->reply, "state=draining"));
  tt_u64_op(value("expires_ms"), OP_EQ, 0);
  tt_u64_op(value("anchor"), OP_EQ, anchor_id);
  tt_u64_op(value("stream"), OP_EQ, stream_id);
  close_closeable_connections();
  command("CLOSE " ID);
  tt_assert(strstr(f->reply, "state=stopped"));
  tt_u64_op(value("anchor"), OP_EQ, anchor_id);
  tt_u64_op(value("stream"), OP_EQ, stream_id);
 done: ;
}

static void test_anchor_close(void *arg)
{
  fixture_t *f = arg;
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, 1);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  uint64_t anchor_id = ENTRY_TO_CONN(f->anchor)->global_identifier;
  uint64_t stream_id = ENTRY_TO_CONN(stream)->global_identifier;
  connection_edge_end(ENTRY_TO_EDGE_CONN(f->anchor), END_STREAM_REASON_DONE);
  connection_mark_unattached_ap(f->anchor, END_STREAM_REASON_DONE);
  connection_close_immediate(ENTRY_TO_CONN(f->anchor));
  f->anchor = NULL;
  close_closeable_connections();
  command("STATUS " ID);
  tt_int_op(f->code, OP_EQ, 250);
  tt_u64_op(value("anchor"), OP_EQ, anchor_id);
  tt_u64_op(value("stream"), OP_EQ, stream_id);
  tt_assert(strstr(f->reply, "state=stopped"));
  command("CLOSE " ID);
  tt_int_op(f->code, OP_EQ, 250);
  tt_u64_op(value("anchor"), OP_EQ, anchor_id);
 done: ;
}

static void test_reserved_no_fallback(void *arg)
{
  fixture_t *f = arg;
  const char *addresses[] = {
    TOKEN, TOKEN ".", "1.EEEEEEEEEEEEEEEEEEEEEEEEEEEEEEEE.eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee.lastrelay.routervpn.invalid",
    "x.lastrelay.routervpn.invalid", "lastrelay.routervpn.invalid"
  };
  for (size_t i = 0; i < ARRAY_LENGTH(addresses); ++i) {
    entry_connection_t *bad = new_entry(addresses[i], 1);
    tt_int_op(connection_ap_handshake_rewrite_and_attach(bad, NULL, NULL), OP_EQ, -1);
    tt_assert(ENTRY_TO_CONN(bad)->marked_for_close);
    tt_assert(bad->routervpn_lastrelay);
    tt_ptr_op(ENTRY_TO_EDGE_CONN(bad)->on_circuit, OP_EQ, NULL);
    tt_int_op(bad->num_circuits_launched, OP_EQ, 0);
  }
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  addressmap_init();
  addressmap_register("alias.example", tor_strdup(TOKEN), TIME_MAX,
                      ADDRMAPSRC_CONTROLLER, 0, 0, 0);
  entry_connection_t *alias = new_entry("alias.example", 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(alias, NULL, NULL), OP_EQ, -1);
  tt_assert(ENTRY_TO_CONN(alias)->marked_for_close);
  tt_ptr_op(ENTRY_TO_EDGE_CONN(alias)->on_circuit, OP_EQ, NULL);
  tt_int_op(f->begins, OP_EQ, 0);
  tt_int_op(alias->num_circuits_launched, OP_EQ, 0);
  entry_connection_t *valid = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(valid, NULL, NULL), OP_EQ, 1);
 done:
  addressmap_free_all();
}

#ifdef HAVE_MODULE_DIRCACHE
static void test_real_directory(void *arg)
{
  fixture_t *f = arg;
  f->peer_mode = 1;
  get_options_mutable()->ClientOnly = 0;
  get_options_mutable()->ORPort_set = 1;
  get_options_mutable()->BridgeRelay = 1;
  get_options_mutable()->DirCache = 1;
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, 1);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  tt_int_op(ENTRY_TO_CONN(stream)->state, OP_EQ, AP_CONN_STATE_OPEN);
  edge_connection_t *remote = find_stream(f->relay[2]->n_streams,
                                          ENTRY_TO_EDGE_CONN(stream)->stream_id);
  tt_assert(remote);
  connection_t *directory = TO_CONN(remote)->linked_conn;
  tt_assert(directory);
  tt_int_op(directory->type, OP_EQ, CONN_TYPE_DIR);
  tt_int_op(directory->state, OP_EQ, DIR_CONN_STATE_SERVER_COMMAND_WAIT);
  tt_assert(!SOCKET_OK(TO_CONN(remote)->s));
  tt_assert(!SOCKET_OK(directory->s));
  buf_clear(ENTRY_TO_CONN(stream)->outbuf);
  connection_stop_writing(ENTRY_TO_CONN(stream));
  buf_add(ENTRY_TO_CONN(stream)->inbuf, REQUEST, sizeof(REQUEST)-1);
  tt_int_op(connection_edge_process_inbuf(ENTRY_TO_EDGE_CONN(stream), 1), OP_EQ, 0);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  tt_u64_op(buf_move_all(directory->inbuf, TO_CONN(remote)->outbuf), OP_EQ, sizeof(REQUEST)-1);
  tt_int_op(connection_dir_process_inbuf(TO_DIR_CONN(directory)), OP_EQ, 0);
  tt_int_op(directory->state, OP_EQ, DIR_CONN_STATE_SERVER_WRITING);
  size_t bytes = buf_move_all(TO_CONN(remote)->inbuf, directory->outbuf);
  tt_assert(bytes > 28 && bytes < 8192);
  tt_int_op(connection_edge_process_inbuf(remote, 1), OP_EQ, 0);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  tt_u64_op(buf_datalen(ENTRY_TO_CONN(stream)->outbuf), OP_EQ, bytes);
  char response[8193];
  buf_peek(ENTRY_TO_CONN(stream)->outbuf, response, bytes);
  response[bytes] = 0;
  tt_assert(!strncmp(response, "HTTP/1.0 200 OK\r\n", 17));
  tt_assert(strstr(response, "Content-Length: 28\r\n"));
  tt_assert(strstr(response, "\r\n\r\nUser-agent: *\r\nDisallow: /\r\n"));
  command("STATUS " ID);
  tt_u64_op(value("request_bytes"), OP_EQ, sizeof(REQUEST)-1);
  tt_u64_op(value("response_bytes"), OP_EQ, bytes);
  tt_u64_op(value("end_reason"), OP_EQ, 0);
  /* Drive the real directory finish and linked EOF handlers. The retained
   * client socket must receive the complete HTTP response and then EOF. */
  tt_int_op(connection_dir_finished_flushing(TO_DIR_CONN(directory)), OP_EQ, 0);
  close_closeable_connections();
  tt_ptr_op(TO_CONN(remote)->linked_conn, OP_EQ, NULL);
  tt_int_op(connection_edge_reached_eof(remote), OP_EQ, 0);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  tt_assert(ENTRY_TO_CONN(stream)->marked_for_close);
  command("STATUS " ID);
  tt_u64_op(value("end_reason"), OP_EQ, END_STREAM_REASON_DONE);
  tt_assert(strstr(f->reply, "state=ended"));
  tt_int_op(connection_flush(ENTRY_TO_CONN(stream)), OP_EQ, 0);
  close_closeable_connections();
  tor_socket_t client = (tor_socket_t)(uintptr_t)smartlist_get(f->peers, 1);
  char delivered[8193];
  tt_int_op(read_all_from_socket(client, delivered, bytes), OP_EQ, (int)bytes);
  delivered[bytes] = 0;
  tt_str_op(delivered, OP_EQ, response);
  tt_int_op(tor_socket_recv(client, delivered, 1, 0), OP_EQ, 0);
  command("STATUS " ID);
  tt_assert(strstr(f->reply, "state=ended"));
  tt_u64_op(value("response_bytes"), OP_EQ, bytes);
  command("CLOSE " ID);
  tt_assert(strstr(f->reply, "state=stopped"));
 done: ;
}
#endif

static void test_reply_protocol(void *arg)
{
  fixture_t *f = arg;
  f->peer_mode = 2; /* The remote test peer withholds automatic responses. */
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, 1);
  flush();
  tt_int_op(ENTRY_TO_CONN(stream)->state, OP_EQ, AP_CONN_STATE_CONNECT_WAIT);
  edge_connection_t *edge = ENTRY_TO_EDGE_CONN(stream);
  uint8_t first_command = RELAY_COMMAND_CONNECTED;
  const char *first_body = NULL;
  size_t first_size = 0;
  if (!strcmp(f->variant, "early-data")) {
    first_command = RELAY_COMMAND_DATA;
    first_body = "x";
    first_size = 1;
  } else if (!strcmp(f->variant, "empty-end")) {
    first_command = RELAY_COMMAND_END;
  } else if (!strcmp(f->variant, "connected-body")) {
    /* BEGIN_DIR clients must ignore CONNECTED payload, per Tor protocol. */
    first_body = "ignored payload";
    first_size = strlen(first_body);
  }
  tt_int_op(relay_send_command_from_edge(edge->stream_id,
      TO_CIRCUIT(f->relay[2]), first_command, first_body, first_size, NULL), OP_EQ, 0);
  flush();
  if (!strcmp(f->variant, "connected-body")) {
    tt_int_op(f->errors, OP_EQ, 0);
    tt_int_op(ENTRY_TO_CONN(stream)->state, OP_EQ, AP_CONN_STATE_OPEN);
    tt_assert(routervpn_lastrelay_current(stream));
    goto done;
  }
  if (!strcmp(f->variant, "duplicate-connected")) {
    tt_int_op(f->errors, OP_EQ, 0);
    tt_int_op(relay_send_command_from_edge(edge->stream_id,
        TO_CIRCUIT(f->relay[2]), RELAY_COMMAND_CONNECTED, NULL, 0, NULL), OP_EQ, 0);
    flush();
  } else if (!strcmp(f->variant, "wrong-hop")) {
    tt_int_op(f->errors, OP_EQ, 0);
    buf_add(ENTRY_TO_CONN(stream)->inbuf, REQUEST, sizeof(REQUEST)-1);
    tt_int_op(connection_edge_process_inbuf(edge, 1), OP_EQ, 0);
    flush();
    tt_int_op(f->requests, OP_EQ, 1);
    relay_msg_t msg;
    memset(&msg, 0, sizeof(msg));
    msg.command = RELAY_COMMAND_DATA;
    msg.stream_id = edge->stream_id;
    msg.body = (const uint8_t *)"x";
    msg.length = 1;
    tt_int_op(connection_edge_process_relay_cell(&msg,
        TO_CIRCUIT(f->origin), edge, f->origin->cpath), OP_EQ, 0);
  }
  tt_assert(ENTRY_TO_CONN(stream)->marked_for_close);
  tt_assert(!routervpn_lastrelay_current(stream));
  tt_int_op(stream->num_circuits_launched, OP_EQ, 0);
  command("STATUS " ID);
  tt_u64_op(value("response_bytes"), OP_EQ, 0);
  tt_u64_op(value("expires_ms"), OP_EQ, 0);
 done: ;
}

static void test_request_bound(void *arg)
{
  fixture_t *f = arg;
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, 1);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  const char *wrong = "GET /tor/server/all HTTP/1.0\r\n\r\n";
  buf_add(ENTRY_TO_CONN(stream)->inbuf, wrong, strlen(wrong));
  tt_int_op(connection_edge_process_inbuf(ENTRY_TO_EDGE_CONN(stream), 1), OP_EQ, 0);
  flush();
  tt_int_op(f->requests, OP_EQ, 0);
  tt_assert(ENTRY_TO_CONN(stream)->marked_for_close);
  tt_assert(!ENTRY_TO_CONN(f->anchor)->marked_for_close);
  command("STATUS " ID);
  tt_u64_op(value("request_bytes"), OP_EQ, 0);
  tt_u64_op(value("response_bytes"), OP_EQ, 0);
 done: ;
}

static void test_response_bound(void *arg)
{
  fixture_t *f = arg;
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  entry_connection_t *stream = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(stream, NULL, NULL), OP_EQ, 1);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  f->peer_mode = 2;
  buf_add(ENTRY_TO_CONN(stream)->inbuf, REQUEST, sizeof(REQUEST)-1);
  tt_int_op(connection_edge_process_inbuf(ENTRY_TO_EDGE_CONN(stream), 1), OP_EQ, 0);
  flush();
  tt_int_op(f->requests, OP_EQ, 1);
  char bytes[498];
  memset(bytes, 'x', sizeof(bytes));
  size_t remaining = 8192;
  while (remaining) {
    size_t length = MIN(remaining, sizeof(bytes));
    tt_int_op(relay_send_command_from_edge(ENTRY_TO_EDGE_CONN(stream)->stream_id,
        TO_CIRCUIT(f->relay[2]), RELAY_COMMAND_DATA, bytes, length, NULL), OP_EQ, 0);
    flush();
    tt_int_op(f->errors, OP_EQ, 0);
    remaining -= length;
  }
  tt_assert(routervpn_lastrelay_current(stream));
  command("STATUS " ID);
  tt_u64_op(value("response_bytes"), OP_EQ, 8192);
  tt_int_op(relay_send_command_from_edge(ENTRY_TO_EDGE_CONN(stream)->stream_id,
      TO_CIRCUIT(f->relay[2]), RELAY_COMMAND_DATA, "x", 1, NULL), OP_EQ, 0);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  tt_assert(ENTRY_TO_CONN(stream)->marked_for_close);
  command("STATUS " ID);
  tt_u64_op(value("response_bytes"), OP_EQ, 8192);
  tt_u64_op(value("expires_ms"), OP_EQ, 0);
 done: ;
}


static void test_generation_retirement(void *arg)
{
  fixture_t *f = arg;
  capture(3000);
  tt_int_op(f->code, OP_EQ, 250);
  command("CLOSE " ID);
  tt_assert(strstr(f->reply, "state=stopped"));
  capture_generation(2, 3000);
  tt_int_op(f->code, OP_EQ, 250);
  entry_connection_t *old = new_entry(TOKEN, 1);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(old, NULL, NULL), OP_EQ, -1);
  tt_assert(ENTRY_TO_CONN(old)->marked_for_close);
  tt_ptr_op(ENTRY_TO_EDGE_CONN(old)->on_circuit, OP_EQ, NULL);
  command("CLOSE " ID);
  tt_int_op(f->code, OP_EQ, 551);
  char *new_token;
  tor_asprintf(&new_token, "2%s", TOKEN+1);
  entry_connection_t *current = new_entry(new_token, 1);
  tor_free(new_token);
  tt_int_op(connection_ap_handshake_rewrite_and_attach(current, NULL, NULL), OP_EQ, 1);
  flush();
  tt_int_op(f->errors, OP_EQ, 0);
  tt_assert(routervpn_lastrelay_current(current));
  command("CLOSE " SOURCE " " SOURCE " 2 " NONCE);
  tt_int_op(f->code, OP_EQ, 551);
  tt_assert(routervpn_lastrelay_current(current));
  command("CLOSE " SESSION " " SOURCE " 2 " NONCE);
  tt_int_op(f->code, OP_EQ, 250);
  tt_assert(ENTRY_TO_CONN(current)->marked_for_close);
 done: ;
}

#define TEST(name) { #name, test_##name, TT_FORK, &tests_setup, NULL }
#define REPLY(name) { "reply_" name, test_reply_protocol, TT_FORK, &tests_setup, (void *)name }
#define RETIRE(name) { "retire_" name, test_live_retire, TT_FORK, &tests_setup, (void *)name }
struct testcase_t routervpn_lastrelay_tests[] = {
  TEST(native_wire), TEST(expiry_replay), TEST(owner_and_nonce), TEST(generation_retirement),
  { "real_client_exitpolicy", test_real_rejection, TT_FORK, &tests_setup, (void *)"client" },
  { "real_relay_notdirectory", test_real_rejection, TT_FORK, &tests_setup, (void *)"no-directory" },
  TEST(anchor_lookup), TEST(ineligible_path),
  TEST(anchor_close), TEST(reserved_no_fallback), TEST(request_bound), TEST(response_bound),
  REPLY("early-data"), REPLY("empty-end"), REPLY("connected-body"),
  REPLY("duplicate-connected"), REPLY("wrong-hop"),
  RETIRE("expiry"), RETIRE("path"), RETIRE("circuit"), RETIRE("configuration"),
  RETIRE("isolation"), RETIRE("membership"), RETIRE("retry"),
#ifdef HAVE_MODULE_DIRCACHE
  TEST(real_directory),
#endif
  END_OF_TESTCASES
};
