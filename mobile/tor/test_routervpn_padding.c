/* Executable tests compiled inside the exact patched Tor source tree. The
 * production encoder, encryption, queue, timer and channel accounting run.
 * The fixture supplies a monotonic clock, live network state, a controlled
 * transport and control-reply sink. It never substitutes a successful cell. */
#define CHANNEL_OBJECT_PRIVATE
#define CIRCUITLIST_PRIVATE
#define CRYPT_PATH_PRIVATE
#define TOR_TIMERS_PRIVATE
#define RELAY_PRIVATE

#include "core/or/or.h"
#include "app/config/config.h"
#include "core/mainloop/netstatus.h"
#include "core/or/channel.h"
#include "core/or/circuitbuild.h"
#include "core/or/circuitlist.h"
#include "core/or/circuitmux_ewma.h"
#include "core/or/crypt_path.h"
#include "core/or/relay.h"
#include "core/or/scheduler.h"
#include "core/crypto/relay_crypto.h"
#include "core/or/cell_st.h"
#include "core/or/cell_queue_st.h"
#include "core/or/cpath_build_state_st.h"
#include "core/or/crypt_path_st.h"
#include "core/or/or_circuit_st.h"
#include "core/or/origin_circuit_st.h"
#include "feature/control/control.h"
#include "feature/control/control_cmd.h"
#include "feature/control/control_proto.h"
#include "feature/control/control_connection_st.h"
#include "feature/control/routervpn_padding.h"
#include "feature/hibernate/hibernate.h"
#include "lib/crypt_ops/crypto_rand.h"
#include "lib/evloop/timers.h"
#include "lib/time/compat_time.h"
#include "test/test.h"

#define SESSION "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
#define SOURCE "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
#define USERNAME "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
#define DESKTOP_USERNAME "cccccccccccccccccccccccccccccccc"
#define PASSWORD "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
#define IDENTITY SESSION " " SOURCE " "

channel_t *new_fake_channel(void);
void free_fake_channel(channel_t *chan);

typedef struct fixture_t {
  control_connection_t owner;
  control_connection_t stranger;
  channel_t *channel;
  origin_circuit_t *origin[2];
  or_circuit_t *relay[2][3];
  int64_t clock_nsec;
  char *reply;
  int code;
  unsigned written;
  unsigned wire_errors;
  unsigned by_circuit[2];
  int write_failure;
  int writeable;
  bool wiped;
} fixture_t;

static fixture_t *fixture;

static int
not_hibernating(void)
{
  return 0;
}

static void
capture_reply(control_connection_t *conn, int code, int separator,
              const char *text)
{
  (void)conn; (void)separator;
  fixture->code = code;
  tor_free(fixture->reply);
  fixture->reply = tor_strdup(text);
}

static void
queued_for_scheduler(channel_t *channel)
{
  (void)channel; /* The test explicitly drives the real channel flush. */
}

static int
transport_writeable(channel_t *channel)
{
  (void)channel;
  return fixture->writeable;
}

static int
transport_write(channel_t *channel, packed_cell_t *packed)
{
  fixture_t *f = fixture;
  if (f->write_failure)
    return -1;
  cell_t cell;
  memset(&cell, 0, sizeof(cell));
  unsigned offset = channel->wide_circ_ids ? 5 : 3;
  cell.circ_id = channel->wide_circ_ids ?
      ntohl(get_uint32(packed->body)) : ntohs(get_uint16(packed->body));
  cell.command = (uint8_t)packed->body[offset - 1];
  memcpy(cell.payload, packed->body + offset, CELL_PAYLOAD_SIZE);
  unsigned which = cell.circ_id == 101 ? 0 : 1;
  if ((cell.circ_id != 101 && cell.circ_id != 102) ||
      (cell.command != CELL_RELAY && cell.command != CELL_RELAY_EARLY) ||
      !packed->routervpn_padding_generation) {
    ++f->wire_errors;
    return -1;
  }
  uint8_t encrypted[CELL_PAYLOAD_SIZE];
  memcpy(encrypted, cell.payload, sizeof(encrypted));
  for (unsigned i = 0; i < 3; ++i) {
    char recognized = 0;
    crypt_path_t *layer = NULL;
    if (relay_decrypt_cell(TO_CIRCUIT(f->relay[which][i]), &cell,
                          CELL_DIRECTION_OUT, &layer, &recognized) != 0 ||
        layer != NULL || !!recognized != (i == 2)) {
      ++f->wire_errors;
      return -1;
    }
  }
  relay_header_t header;
  relay_header_unpack(&header, cell.payload);
  if (header.command != RELAY_COMMAND_DROP || header.stream_id != 0 ||
      header.length != 0 || !memcmp(encrypted, cell.payload, sizeof(encrypted))) {
    ++f->wire_errors;
    return -1;
  }
  ++f->written;
  ++f->by_circuit[which];
  return 1;
}

static void
command_for(control_connection_t *owner, const char *command)
{
  tor_free(fixture->reply);
  fixture->code = 0;
  char *copy = tor_strdup(command);
  size_t length = strlen(copy);
  owner->current_cmd = (char *)"ROUTERVPN_PADDING";
  handle_control_command(owner, (uint32_t)length, copy);
  fixture->wiped = true;
  for (size_t i = 0; i < length; ++i)
    fixture->wiped = fixture->wiped && copy[i] == 0;
  tor_free(copy);
}

static void
command(const char *body)
{
  command_for(&fixture->owner, body);
}

static void
start(unsigned generation, unsigned rate, unsigned ttl)
{
  char *body;
  tor_asprintf(&body, "START " IDENTITY "%u %u %u " USERNAME " " PASSWORD,
               generation, rate, ttl);
  command(body);
  tor_free(body);
}

static uint64_t
value(const char *key)
{
  char *needle;
  tor_asprintf(&needle, "%s=", key);
  const char *found = strstr(fixture->reply ? fixture->reply : "", needle);
  uint64_t result = found ? strtoull(found + strlen(needle), NULL, 10) : UINT64_MAX;
  tor_free(needle);
  return result;
}

static void
advance(unsigned milliseconds, bool flush)
{
  fixture->clock_nsec += (int64_t)milliseconds * 1000000;
  monotime_set_mock_time_nsec(fixture->clock_nsec);
  monotime_coarse_set_mock_time_nsec(fixture->clock_nsec);
  timers_run_pending();
  if (flush)
    channel_flush_from_first_active_circuit(fixture->channel, 8);
}

static void *
setup(const struct testcase_t *test)
{
  (void)test;
  fixture_t *f = tor_malloc_zero(sizeof(*f));
  fixture = f;
  f->owner.base_.state = f->stranger.base_.state = CONTROL_CONN_STATE_OPEN;
  f->owner.is_owning_control_connection = 1;
  f->stranger.is_owning_control_connection = 1;
  f->writeable = 32;
  get_options_mutable()->DisableNetwork = 0;
  set_network_participation(true);
  f->clock_nsec = monotime_absolute_nsec() + 1000000000;
  monotime_enable_test_mocking();
  monotime_set_mock_time_nsec(f->clock_nsec);
  monotime_coarse_set_mock_time_nsec(f->clock_nsec);
  timers_initialize();
  cmux_ewma_set_options(NULL, NULL);
  MOCK(control_write_reply, capture_reply);
  MOCK(scheduler_channel_has_waiting_cells, queued_for_scheduler);
  MOCK(we_are_hibernating, not_hibernating);
  f->channel = new_fake_channel();
  f->channel->wide_circ_ids = 1;
  f->channel->write_packed_cell = transport_write;
  f->channel->num_cells_writeable = transport_writeable;
  for (unsigned n = 0; n < 2; ++n) {
    origin_circuit_t *origin = f->origin[n] = origin_circuit_new();
    origin->base_.purpose = CIRCUIT_PURPOSE_C_GENERAL;
    origin->base_.state = CIRCUIT_STATE_OPEN;
    origin->build_state = tor_malloc_zero(sizeof(cpath_build_state_t));
    origin->build_state->desired_path_len = 3;
    origin->isolation_values_set = 1;
    origin->isolation_any_streams_attached = 1;
    origin->socks_username = tor_memdup(USERNAME, 64);
    origin->socks_password = tor_memdup(PASSWORD, 64);
    origin->socks_username_len = origin->socks_password_len = 64;
    for (unsigned i = 0; i < 3; ++i) {
      char key[CPATH_KEY_MATERIAL_LEN];
      crypto_rand(key, sizeof(key));
      crypt_path_t *hop = tor_malloc_zero(sizeof(*hop));
      hop->magic = CRYPT_PATH_MAGIC;
      hop->state = CPATH_STATE_OPEN;
      relay_crypto_init(RELAY_CRYPTO_ALG_TOR1, &hop->pvt_crypto,
                        key, sizeof(key));
      cpath_extend_linked_list(&origin->cpath, hop);
      f->relay[n][i] = or_circuit_new(0, NULL);
      relay_crypto_init(RELAY_CRYPTO_ALG_TOR1, &f->relay[n][i]->crypto,
                        key, sizeof(key));
    }
    circuit_set_n_circid_chan(TO_CIRCUIT(origin), 101 + n, f->channel);
  }
  return f;
}

static int
teardown(const struct testcase_t *test, void *argument)
{
  (void)test;
  fixture_t *f = argument;
  routervpn_padding_owner_closed(&f->owner);
  routervpn_padding_owner_closed(&f->stranger);
  for (unsigned n = 0; n < 2; ++n) {
    circuit_free_(TO_CIRCUIT(f->origin[n]));
    for (unsigned i = 0; i < 3; ++i)
      circuit_free_(TO_CIRCUIT(f->relay[n][i]));
  }
  routervpn_padding_free_all();
  free_fake_channel(f->channel);
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

static const struct testcase_setup_t padding_setup = { setup, teardown };

static void
test_commands(void *argument)
{
  fixture_t *f = argument;
  command("INFO");
  tt_int_op(f->code, OP_EQ, 250);
  tt_assert(strstr(f->reply, "direction=outgoing"));
  tt_u64_op(value("generation_highwater"), OP_EQ, 0);
  f->owner.is_owning_control_connection = 0;
  start(1, 32, 10000);
  tt_int_op(f->code, OP_EQ, 551);
  f->owner.is_owning_control_connection = 1;
  f->owner.base_.state = 0;
  start(1, 32, 10000);
  tt_int_op(f->code, OP_EQ, 551);
  f->owner.base_.state = CONTROL_CONN_STATE_OPEN;
  get_options_mutable()->DisableNetwork = 1;
  start(1, 32, 10000);
  tt_int_op(f->code, OP_EQ, 551);
  get_options_mutable()->DisableNetwork = 0;
  const char *bad[] = {
    "START " IDENTITY "1 31 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "1 193 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "1 0 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "1 +32 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "1 032 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "1 32.0 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "1 32 99 " USERNAME " " PASSWORD,
    "START " IDENTITY "1 32 10001 " USERNAME " " PASSWORD,
    "START " IDENTITY "1 32 1000 " USERNAME " x",
    "START " IDENTITY "0 32 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "01 32 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "9223372036854775808 32 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "184467440737095516169 32 1000 " USERNAME " " PASSWORD,
    "START " IDENTITY "1 32 1000 " USERNAME " " PASSWORD " extra",
    "START a " SOURCE " 1 32 1000 " USERNAME " " PASSWORD,
    "START " SESSION " Bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb 1 32 1000 " USERNAME " " PASSWORD,
    "STATUS " IDENTITY "1 extra",
    "INFO extra",
    "",
  };
  for (unsigned i = 0; i < ARRAY_LENGTH(bad); ++i) {
    command(bad[i]);
    tt_int_op(f->code, OP_NE, 250);
    tt_assert(f->wiped);
    tt_assert(!strstr(f->reply, PASSWORD));
  }
  start(1, 32, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  tt_assert(f->wiped);
  tt_assert(strstr(f->reply, "state=running"));
  command_for(&f->stranger, "STOP " IDENTITY "1");
  tt_int_op(f->code, OP_EQ, 551);
  command("STATUS " IDENTITY "1");
  tt_assert(strstr(f->reply, "state=running"));
 done: ;
}

static void
test_desktop_username(void *argument)
{
  fixture_t *f = argument;
  f->origin[0]->socks_username_len = 32;
  /* The other circuit has the same prefix but the mobile/server 64-char
   * username. It must not borrow this desktop owner's cover budget. */
  command("START " IDENTITY "1 192 10000 " DESKTOP_USERNAME " " PASSWORD);
  tt_int_op(f->code, OP_EQ, 250);
  advance(100, true);
  tt_int_op(f->wire_errors, OP_EQ, 0);
  tt_int_op(f->by_circuit[0], OP_EQ, 1);
  tt_int_op(f->by_circuit[1], OP_EQ, 0);
  command("STOP " IDENTITY "1");
  tt_assert(strstr(f->reply, "state=stopped"));
  f->origin[0]->socks_username[31] = 'e';
  command("START " IDENTITY "2 192 10000 " DESKTOP_USERNAME " " PASSWORD);
  tt_int_op(f->code, OP_EQ, 250);
  advance(100, true);
  command("STOP " IDENTITY "2");
  tt_u64_op(value("queued_cells"), OP_EQ, 0);
  const unsigned lengths[] = {31, 33, 63, 65};
  for (unsigned i = 0; i < ARRAY_LENGTH(lengths); ++i) {
    char username[66];
    memset(username, 'c', sizeof(username));
    username[lengths[i]] = 0;
    char *body;
    tor_asprintf(&body, "START " IDENTITY "3 192 10000 %s " PASSWORD,
                 username);
    command(body);
    tor_free(body);
    tt_int_op(f->code, OP_EQ, 512);
  }
  command("START " IDENTITY "3 192 10000 " DESKTOP_USERNAME " " DESKTOP_USERNAME);
  tt_int_op(f->code, OP_EQ, 512);
 done: ;
}

static void
test_encrypted_budget(void *argument)
{
  fixture_t *f = argument;
  start(1, 192, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  for (unsigned i = 0; i < 1000; ++i)
    advance(1, true);
  command("STATUS " IDENTITY "1");
  tt_int_op(f->wire_errors, OP_EQ, 0);
  tt_int_op(f->written, OP_GT, 25);
  tt_u64_op(value("channel_cell_bytes"), OP_LE, 192000 / 8);
  tt_u64_op(value("queued_cells"), OP_EQ, f->written);
  tt_u64_op(value("channel_cells"), OP_EQ, f->written);
  tt_u64_op(value("channel_cell_bytes"), OP_EQ, f->written * 514);
  tt_int_op(f->by_circuit[0], OP_GT, 0);
  tt_int_op(f->by_circuit[1], OP_GT, 0);
  tt_int_op(abs((int)f->by_circuit[0] - (int)f->by_circuit[1]), OP_LE, 1);
  unsigned before = f->written;
  advance(2000, true); /* A late timer does not catch up with a burst. */
  tt_int_op(f->written, OP_EQ, before + 1);
  command("RENEW " IDENTITY "1 10000");
  tt_int_op(f->code, OP_EQ, 250);
  for (unsigned i = 0; i < 15; ++i)
    advance(1, true);
  tt_int_op(f->written, OP_EQ, before + 1); /* Renewal has no fresh budget. */
  command("STOP " IDENTITY "1");
  tt_assert(strstr(f->reply, "state=stopped"));
  before = f->written;
  advance(5000, true);
  tt_int_op(f->written, OP_EQ, before);
  f->channel->wide_circ_ids = 0;
  start(2, 32, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  for (unsigned i = 0; i < 1000; ++i)
    advance(1, true);
  command("STATUS " IDENTITY "2");
  tt_u64_op(value("channel_cells"), OP_GE, 4);
  tt_u64_op(value("channel_cell_bytes"), OP_LE, 32000 / 8);
  tt_u64_op(value("channel_cell_bytes"), OP_EQ,
            (f->written - before) * 512);
  tt_int_op(f->wire_errors, OP_EQ, 0);
 done: ;
}

static void
test_stop_expiry_generation(void *argument)
{
  fixture_t *f = argument;
  start(1, 192, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  advance(200, false);
  command("STOP " IDENTITY "1");
  tt_assert(strstr(f->reply, "state=stopping"));
  tt_u64_op(value("pending_cells"), OP_EQ, 1);
  start(2, 192, 10000);
  tt_int_op(f->code, OP_EQ, 551);
  advance(1000, false);
  command("STATUS " IDENTITY "1");
  tt_u64_op(value("queued_cells"), OP_EQ, 1);
  advance(1, true);
  command("STOP " IDENTITY "1");
  tt_assert(strstr(f->reply, "state=stopped"));
  tt_u64_op(value("channel_cells"), OP_EQ, 1);
  start(1, 192, 10000);
  tt_int_op(f->code, OP_EQ, 551);
  start(2, 192, 100);
  tt_int_op(f->code, OP_EQ, 250);
  command("STOP " IDENTITY "1");
  tt_int_op(f->code, OP_EQ, 551);
  command("RENEW " IDENTITY "1 10000");
  tt_int_op(f->code, OP_EQ, 551);
  command("STOP " SOURCE " " SOURCE " 2");
  tt_int_op(f->code, OP_EQ, 551);
  advance(101, true);
  command("STATUS " IDENTITY "2");
  tt_assert(strstr(f->reply, "state=stopped"));
  tt_assert(strstr(f->reply, "reason=expired"));
  tt_u64_op(value("queued_cells"), OP_EQ, 0);
  command("RENEW " IDENTITY "2 10000");
  tt_int_op(f->code, OP_EQ, 551);
  start(3, 192, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  routervpn_padding_owner_closed(&f->owner);
  advance(1000, true);
  tt_int_op(f->written, OP_EQ, 1);
  command("RENEW " IDENTITY "3 10000");
  tt_int_op(f->code, OP_EQ, 551);
  command_for(&f->stranger, "START " IDENTITY "3 192 10000 " USERNAME " " PASSWORD);
  tt_int_op(f->code, OP_EQ, 551);
  command_for(&f->stranger, "START " IDENTITY "4 192 10000 " USERNAME " " PASSWORD);
  tt_int_op(f->code, OP_EQ, 250);
  command("STOP " IDENTITY "3");
  tt_int_op(f->code, OP_EQ, 551);
  advance(50, true);
  tt_int_op(f->written, OP_EQ, 2);
 done: ;
}

static void
test_eligible_circuits(void *argument)
{
  fixture_t *f = argument;
  /* The second circuit has another captured SOCKS owner throughout. */
  f->origin[1]->socks_username[0] = 'e';
  origin_circuit_t *o = f->origin[0];
  circuit_t *c = TO_CIRCUIT(o);
  for (unsigned fault = 0; fault < 16; ++fault) {
    switch (fault) {
      case 0: o->socks_username[0] = 'e'; break;
      case 1: o->socks_password[0] = 'e'; break;
      case 2: o->socks_username_len = 63; break;
      case 3: o->isolation_flags_mixed = ISO_SOCKSAUTH; break;
      case 4: o->isolation_values_set = 0; break;
      case 5: o->isolation_any_streams_attached = 0; break;
      case 6: o->build_state->onehop_tunnel = 1; break;
      case 7: o->build_state->is_internal = 1; break;
      case 8: c->state = CIRCUIT_STATE_BUILDING; break;
      case 9: c->purpose = CIRCUIT_PURPOSE_C_HSDIR_GET; break;
      case 10: c->circuit_blocked_on_n_chan = 1; break;
      case 11: o->unusable_for_new_conns = 1; break;
      case 12: o->cpath->next->state = CPATH_STATE_AWAITING_KEYS; break;
      case 13: f->writeable = 0; break;
      case 14: c->marked_for_close = 1; break;
      case 15: f->channel->state = CHANNEL_STATE_MAINT; break;
    }
    start(fault + 1, 192, 10000);
    tt_int_op(f->code, OP_EQ, 250);
    advance(300, true);
    char *body;
    tor_asprintf(&body, "STOP " IDENTITY "%u", fault + 1);
    command(body);
    tor_free(body);
    tt_u64_op(value("queued_cells"), OP_EQ, 0);
    tt_int_op(f->written, OP_EQ, 0);
    o->socks_username[0] = 'c';
    o->socks_password[0] = 'd';
    o->socks_username_len = 64;
    o->isolation_flags_mixed = 0;
    o->isolation_values_set = o->isolation_any_streams_attached = 1;
    o->build_state->onehop_tunnel = o->build_state->is_internal = 0;
    c->state = CIRCUIT_STATE_OPEN;
    c->purpose = CIRCUIT_PURPOSE_C_GENERAL;
    c->circuit_blocked_on_n_chan = 0;
    c->marked_for_close = 0;
    o->unusable_for_new_conns = 0;
    o->cpath->next->state = CPATH_STATE_OPEN;
    f->writeable = 32;
    f->channel->state = CHANNEL_STATE_OPEN;
  }
  start(17, 192, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  advance(100, true);
  tt_int_op(f->written, OP_EQ, 1);
  tt_int_op(f->by_circuit[0], OP_EQ, 1);
  tt_int_op(f->by_circuit[1], OP_EQ, 0);
 done:
  c->marked_for_close = 0;
  f->channel->state = CHANNEL_STATE_OPEN;
}

static void
test_queue_conservation(void *argument)
{
  fixture_t *f = argument;
  start(1, 192, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  for (unsigned i = 0; i < 50; ++i)
    advance(100, false);
  command("STATUS " IDENTITY "1");
  tt_u64_op(value("queued_cells"), OP_EQ, 1);
  tt_u64_op(value("pending_cells"), OP_EQ, 1);
  tt_u64_op(value("channel_cells"), OP_EQ, 0);
  command("STOP " IDENTITY "1");
  tt_assert(strstr(f->reply, "state=stopping"));
  for (unsigned i = 0; i < 2; ++i)
    circuit_clear_cell_queue(TO_CIRCUIT(f->origin[i]), f->channel);
  command("STATUS " IDENTITY "1");
  tt_assert(strstr(f->reply, "state=stopped"));
  tt_u64_op(value("queued_cells"), OP_EQ, 1);
  tt_u64_op(value("dropped_cells"), OP_EQ, 1);
  tt_u64_op(value("dropped_cell_bytes"), OP_EQ, 514);
  tt_u64_op(value("channel_cells"), OP_EQ, 0);
  /* An ordinary cell has no cover receipt and cannot claim a padded path. */
  packed_cell_t *ordinary = packed_cell_new();
  tt_u64_op(ordinary->routervpn_padding_generation, OP_EQ, 0);
  packed_cell_free(ordinary);
  command("STATUS " IDENTITY "1");
  tt_u64_op(value("dropped_cells"), OP_EQ, 1);
 done: ;
}

static void
test_disabled_and_reconfiguration(void *argument)
{
  fixture_t *f = argument;
  start(1, 192, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  get_options_mutable()->DisableNetwork = 1;
  advance(100, true);
  command("STATUS " IDENTITY "1");
  tt_assert(strstr(f->reply, "reason=disabled"));
  tt_u64_op(value("queued_cells"), OP_EQ, 0);
  get_options_mutable()->DisableNetwork = 0;
  command("RENEW " IDENTITY "1 10000");
  tt_int_op(f->code, OP_EQ, 551);
  start(2, 192, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  set_network_participation(false);
  advance(100, true);
  command("STATUS " IDENTITY "2");
  tt_assert(strstr(f->reply, "reason=disabled"));
  tt_u64_op(value("queued_cells"), OP_EQ, 0);
  set_network_participation(true);
  start(3, 192, 10000);
  tt_int_op(f->code, OP_EQ, 250);
  char *args = tor_strdup("ThisOptionDoesNotExist=1");
  f->owner.current_cmd = (char *)"SETCONF";
  handle_control_command(&f->owner, (uint32_t)strlen(args), args);
  tor_free(args);
  tt_int_op(f->code, OP_NE, 250);
  command("STATUS " IDENTITY "3");
  tt_assert(strstr(f->reply, "reason=configuration"));
  advance(1000, true);
  tt_int_op(f->written, OP_EQ, 0);
 done:
  get_options_mutable()->DisableNetwork = 0;
  set_network_participation(true);
}

#define CASE(name) { #name, test_##name, TT_FORK, &padding_setup, NULL }
struct testcase_t routervpn_padding_tests[] = {
  CASE(commands),
  CASE(desktop_username),
  CASE(encrypted_budget),
  CASE(stop_expiry_generation),
  CASE(eligible_circuits),
  CASE(queue_conservation),
  CASE(disabled_and_reconfiguration),
  END_OF_TESTCASES
};
