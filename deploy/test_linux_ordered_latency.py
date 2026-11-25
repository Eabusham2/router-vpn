#!/usr/bin/env python3
"""Exercise shipping GTK ordered-latency callbacks and original loopback jobs.

--source-only checks source linkage, never claims GTK/native acceptance. The
mandatory Linux workflow uses --self-test and requires real GTK/json-glib/Xvfb.
"""
from __future__ import annotations
import argparse
import contextlib
import copy
import hashlib
import http.server
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.parse

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "client/linux/routervpn-ordered-latency-v1.inc"
FIXTURE = ROOT / "client/linux/test-ordered-latency-v1.c"
CAPTURE = dict(session_id="session-123-456", profile_id="exit-a", profile_token="a"*64,
               source_sha256="b"*64, config_sha256="c"*64, generation_sha256="d"*64)
NODES = [dict(node_id=f"node-{i}", position=i, label="Cumulative path through custom node 2 of 3 → Cloudflare edge" if i == 1 else f"Cumulative path through node {i+1} of 3", role=("entry","intermediate","exit")[i],
              kind="public-path" if i == 1 else "private-node",
              measurement="routed-https-response-after-tls" if i == 1 else "routed-private-response-including-connection") for i in range(3)]


def receipt(position, request="e"*32, *, old=False):
    node = NODES[position]
    return dict(schema=1, source_sha256=CAPTURE["source_sha256"], config_sha256=CAPTURE["config_sha256"],
                generation_sha256="f"*64 if old else CAPTURE["generation_sha256"], node_id=node["node_id"], position=position,
                request_id=request, measured_at=int(time.time()*1000)-10000,
                result=dict(node_id=node["node_id"], kind=node["kind"], role=node["role"], ready=True,
                            label="Cumulative path through custom node 2 of 3 → Cloudflare edge" if position == 1 else f"Cumulative path through node {position+1} of 3",
                            benchmark=dict(schema=1, attempts=50, failed=0, measurement=node["measurement"],
                                           endpoint="https://speed.cloudflare.com/__down?bytes=1" if position == 1 else "",
                                           trimmed_mean_ms=3.0, distribution=dict(samples=50, min_ms=1.0, median_ms=3.0,
                                                                                average_ms=3.0, p90_ms=4.0, max_ms=5.0, jitter_ms=0.5))))


def info():
    return dict(schema=1, capture=copy.deepcopy(CAPTURE), nodes=copy.deepcopy(NODES), history=[receipt(0, old=True)],
                status=dict(request_id="", stage="idle", complete=True, drained=True, results=[]))


def ordinary_fixture(count):
    nodes = [dict(node_id=f"node-{i}", position=i, label=f"Cumulative path through node {i+1} of {count}",
                  role="entry" if i == 0 else "exit" if i == count-1 else "intermediate",
                  kind="private-node", measurement="routed-private-response-including-connection") for i in range(count)]
    receipts = []
    for position, node in enumerate(nodes):
        saved = receipt(0)
        saved.update(node_id=node["node_id"], position=position)
        saved["result"].update(node_id=node["node_id"], role=node["role"], kind=node["kind"],
                               label=f"Cumulative path through node {position+1} of {count}")
        receipts.append(saved)
    return dict(info=dict(schema=1, capture=copy.deepcopy(CAPTURE), nodes=nodes, history=[copy.deepcopy(receipts[0])],
                          status=dict(request_id="", stage="idle", complete=True, drained=True, results=[])), receipts=receipts)


def connect_fixture(count):
    value = ordinary_fixture(count)
    position = count-2
    node = copy.deepcopy(NODES[1])
    node.update(node_id=f"node-{position}", position=position,
                label=f"Cumulative path through custom node {position+1} of {count} → Cloudflare edge")
    value['info']['nodes'][position] = node
    saved = receipt(1)
    saved.update(node_id=node['node_id'], position=position)
    saved['result'].update(node_id=node['node_id'], label=node['label'])
    value['receipts'][position] = saved
    return value


def independent_imported_fixture(count):
    value = ordinary_fixture(count)
    history = []
    for position in range(1, count - 1):
        node = copy.deepcopy(NODES[1])
        node.update(node_id=f"node-{position}", position=position,
                    label=f"Cumulative path through custom node {position+1} of {count} → Cloudflare edge")
        saved = receipt(1, request=f"{position+901:032x}")
        saved.update(node_id=node['node_id'], position=position)
        saved['result'].update(node_id=node['node_id'], label=node['label'])
        value['info']['nodes'][position] = node
        value['receipts'][position] = saved
        history.append(copy.deepcopy(saved))
    value['info']['history'] = history
    if count > 8: value['info']['capture']['extended_local_nodes'] = count
    return value


def paired_extended_fixture(count):
    value = ordinary_fixture(count)
    value['info']['capture']['extended_local_nodes'] = count
    value['info']['history'] = copy.deepcopy(value['receipts'])
    return value


def mixed_extended_fixture(count, packet_prefixes):
    value = paired_extended_fixture(count)
    imported = independent_imported_fixture(count)
    for position in range(packet_prefixes, count - 1):
        value['info']['nodes'][position] = imported['info']['nodes'][position]
        value['receipts'][position] = imported['receipts'][position]
    value['info']['capture']['paired_prefix_nodes'] = packet_prefixes
    value['info']['history'] = copy.deepcopy(value['receipts'])
    return value


def local_roles_fixture(count):
    value = paired_extended_fixture(count)
    imported = independent_imported_fixture(count)
    roles = ['public-path' if 0 < i < count-1 and i % 4 >= 2 else 'private-node' for i in range(count)]
    for position, kind in enumerate(roles):
        if kind == 'public-path':
            value['info']['nodes'][position] = imported['info']['nodes'][position]
            value['receipts'][position] = imported['receipts'][position]
    value['info']['capture']['local_roles_json'] = json.dumps(roles, separators=(',', ':'))
    value['info']['history'] = copy.deepcopy(value['receipts'])
    return value


def selected_fixture(execution, count, public=()):
    value = ordinary_fixture(count) if count else dict(info=info(), receipts=[receipt(i) for i in range(3)])
    if public:
        imported = independent_imported_fixture(count)
        for position in public:
            value['info']['nodes'][position] = imported['info']['nodes'][position]
            value['receipts'][position] = imported['receipts'][position]
        value['info']['history'] = [copy.deepcopy(value['receipts'][position]) for position in public]
    for node in value['info']['nodes']:
        node['label'] = node['label'].replace('Cumulative path', 'Cumulative '+execution+' path')
    for saved in [*value['receipts'], *value['info']['history']]:
        saved['result']['label'] = saved['result']['label'].replace('Cumulative path', 'Cumulative '+execution+' path')
    capture = value['info']['capture']
    selected = dict(schema=1, source_sha256=capture['source_sha256'], config_sha256=capture['config_sha256'],
                    generation_sha256=capture['generation_sha256'], selected_execution=execution,
                    nodes=[{key: node[key] for key in ('node_id', 'position', 'role', 'kind')} for node in value['info']['nodes']])
    if public:
        selected['multiple_imported'] = dict(schema=6, original_source_sha256='7'*64,
            public=[dict(position=p, tag=f'test-public-{p}', source_sha256=f'{p:064x}') for p in public])
    if count > 8: capture['extended_original_nodes'] = count
    capture['selected_capture'] = json.dumps(selected, separators=(',', ':'), ensure_ascii=False)
    value['execution'] = execution
    return value


def custom_entry_fixture():
    value = info()
    entry = value["nodes"][0]
    entry.update(kind="public-path", measurement=value["nodes"][1]["measurement"],
                 label="Cumulative path through custom node 1 of 3 → Cloudflare edge")
    saved = receipt(1)
    saved.update(node_id=entry["node_id"], position=0)
    saved["result"].update(node_id=entry["node_id"], role="entry", label=entry["label"])
    value["history"] = [saved]
    return value


def fixture_data():
    return {'info': info(), 'custom_entry': custom_entry_fixture(), **{f'receipt{i}': receipt(i) for i in range(3)},
            'ordinary': [ordinary_fixture(count) for count in range(2, 9)],
            'paired_extended': [paired_extended_fixture(count) for count in (9, 16, 96)],
            'mixed_extended': [mixed_extended_fixture(count, packet_prefixes) for count, packet_prefixes in
                               ((9,1),(9,2),(9,7),(16,1),(16,2),(16,8),(16,14),(96,2),(96,94))],
            'local_roles': [local_roles_fixture(count) for count in (9,16,96)],
            'connect': [connect_fixture(count) for count in range(3, 9)],
            'independent': [independent_imported_fixture(count) for count in (*range(3, 9),9,16)],
            'invalid_selected_roles': [selected_fixture('server',9,slots)['info']['capture']
                                       for slots in (range(2,8),[1,2,5,6,7])],
            'selected': [selected_fixture(execution, count) for execution in ('local','server') for count in (0,2,3,4,5,6,7,8)] +
                        [selected_fixture(execution,count,positions) for execution in ('local','server')
                         for count,positions in ((4,[1]),(5,[1,3]),(8,[1,4,6]),(9,range(1,8)),(16,range(1,15)),
                                                 (9,[1,2,3,5,6,7]),(16,range(1,14)))]}


def receipt_model(directory, data):
    # The slice is byte-for-byte production helpers, with no GTK/process mocks
    # inside receipt validation. Native widgets and owned HTTP remain below.
    source = SOURCE.read_text()
    first = 'static const char *linux_ol_string_v1('
    last = 'static void linux_ol_message_v1('
    assert source.count(first) == source.count(last) == 1
    block = source[source.index(first):source.index(last)]
    flags = shlex.split(subprocess.check_output(['pkg-config', '--cflags', '--libs', 'json-glib-1.0'], text=True))
    fixture = ROOT/'client/linux/test-ordered-latency-receipts-v1.c'
    controls = {
        'imported-position': ('public_path && count >= 3 && position > 0 && position < count - 1', 'public_path && count >= 3 && position == count - 2'),
        'connect-length': ('public_path && count >= 3 && position > 0 && position < count - 1', 'public_path && count == 3 && position == 1'),
        'selected-labels': ('"Cumulative path", "Cumulative local path", "Cumulative server path"', '"Cumulative path"'),
        'selected-capture': ('!linux_ol_selected_node_v1(capture, node, count)', 'FALSE'),
        'selected-receipt': ('if (g_strcmp0(linux_ol_string_v1(result, "label"), linux_ol_string_v1(node, "label"))) return FALSE;', 'if (FALSE) return FALSE;'),
        'private-budget': ('double maximum = public_path ? 5000 : 2000;', 'double maximum = position == 1 ? 5000 : 2000;'),
        'path-length': ('g_snprintf(label, sizeof(label), "%s through node %d of %d", prefixes[i], position+1, count);', 'g_snprintf(label, sizeof(label), "%s through node %d of %d", prefixes[i], position+1, ((void)count, 3));'),
        'extended-family': ('paired ? 1 : imported ? 0 : -1;', 'paired ? 1 : ((void)imported, 0);'),
        'mixed-family': ('(mixed ? 2 : -1)', '((void)mixed, 2)'),
        'extended-indexed-source': (' || json_array_get_object_element(original_nodes, (guint)position) != n', ''),
        'local-role-owner': ('if (mapped && g_strcmp0(kind, json_array_get_string_element(roles, (guint)i))) return -1;', 'if (mapped && ((void)roles, FALSE)) return -1;'),
        'local-role-canonical': ('public && private_interior && !strcmp(text, canonical->str) ? json_node_copy(root) : NULL;', 'public && private_interior ? json_node_copy(root) : NULL;'),
    }
    for name, change in [('shipping', None), *controls.items()]:
        text = block
        if change:
            before, after = change
            assert text.count(before) == 1, name
            text = text.replace(before, after, 1)
        include = directory/(name+'-validators.inc'); include.write_text(text)
        binary = directory/(name+'-receipt-model')
        run(['cc', '-O1', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function',
             '-DROUTERVPN_ORDERED_VALIDATORS="'+str(include)+'"', fixture, '-o', binary, *flags, '-lm'])
        run([binary, data], broken=change is not None)
        if change: print('Rejected changed shipping C receipt validator: '+name, flush=True)


def extended_throughput(directory, flags, native_originals=None, model_only=False):
    from test_macos_performance_measurement import extended_throughput_fixture, native_throughput_pairs, selected_private_throughput
    performance = (ROOT/'client/linux/routervpn-performance-v17.inc').read_text()
    helpers = SOURCE.read_text()
    block = helpers[helpers.index('static const char *linux_ol_string_v1('):helpers.index('static JsonNode *linux_ol_selected_v1(')]
    block += performance[performance.index('typedef struct {'):performance.index('static void linux_performance_response_v17(')]
    globe = (ROOT/'client/linux/routervpn-globe-v10.inc').read_text()
    ordered = (ROOT/'client/linux/routervpn-ordered-nodes-v1.inc').read_text()
    depth = next(line for line in ordered.splitlines() if line.startswith('enum { ROUTERVPN_PHYSICAL_TRAVERSAL_DEPTH = '))
    block += '\n'+depth+'\n'
    block += globe[globe.index('static JsonArray *linux_globe_active_ids_v10('):globe.index('static void linux_globe_load_route(')]
    block += globe[globe.index('static void linux_globe_hop_color('):globe.index('static void linux_globe_role_color_v10(')]
    projection = directory/'performance.inc'; projection.write_text(block)
    cases = []
    for count, fault in [(9, ''), (16, ''), (9, 'server'), (9, 'missing'), (9, 'duplicate'), (9, 'source'), (16, 'reorder'), (16, 'short'), (16, 'borrowed')]:
        original, result = extended_throughput_fixture(count)
        if fault == 'borrowed':
            original = dict(original, ordered_nodes=3); del original['ordered_local_source']
        if fault == 'server': original['execution'] = 'server'
        if fault == 'missing': del original['ordered_local_source']
        if fault == 'duplicate': original['ordered_local_source']['node_ids'][1] = original['entry_id']
        if fault == 'source': result['ordered_local_source'] = dict(result['ordered_local_source'], config_sha256='f'*64)
        if fault == 'reorder': result['hops'][2], result['hops'][3] = result['hops'][3], result['hops'][2]
        if fault == 'short': result['hops'].pop()
        cases.append(dict(preflight=original, result=result, requests=1 if fault in ('server','missing','duplicate') else 2, adopt=not fault))
    for count, winner, fault in ((9,'local',''), (16,'server',''), (9,'server','generation'), (9,'local','winner'), (16,'server','mixed')):
        original, result = extended_throughput_fixture(count)
        for value in (original, result):
            source = value.pop('ordered_local_source')
            value['ordered_original_source'] = dict(source, generation_sha256='d'*64, selected_execution=winner)
            value['execution'] = winner
        for row in result['hops']:
            for label in ('latency_label','speed_label'):
                row[label] = row[label].replace('Cumulative path', 'Cumulative '+winner+' path')
        if fault == 'generation': result['ordered_original_source']['generation_sha256'] = 'e'*64
        if fault == 'winner': result['execution'] = 'server'
        if fault == 'mixed': original['ordered_local_source'] = original['ordered_original_source']
        cases.append(dict(preflight=original, result=result, requests=1 if fault == 'mixed' else 2, adopt=not fault))
    for count, fault in ((9,''), (16,''), (96,''), (9,'false'), (9,'string'), (9,'missing'), (9,'public'), (16,'mixed-labels'), (16,'selected')):
        original, result = copy.deepcopy(extended_throughput_fixture(count))
        for value in (original, result): value['ordered_local_source']['paired_wireguard'] = True
        for row in result['hops']:
            for label in ('latency_label','speed_label'): row[label] = row[label].replace(' to the public benchmark','')
        if fault == 'false': original['ordered_local_source']['paired_wireguard'] = False
        if fault == 'string': original['ordered_local_source']['paired_wireguard'] = 'true'
        if fault == 'missing': result['ordered_local_source'] = dict(result['ordered_local_source']); result['ordered_local_source'].pop('paired_wireguard')
        if fault in ('public','mixed-labels'):
            positions = range(1,count-1) if fault == 'public' else (count-2,)
            for position in positions:
                for label in ('latency_label','speed_label'):
                    result['hops'][position][label] = result['hops'][position][label].replace(f'of {count}',f'of {count} to the public benchmark')
        if fault == 'selected':
            for value in (original, result): value['ordered_original_source'] = dict(value.pop('ordered_local_source'), generation_sha256='d'*64, selected_execution='local')
        cases.append(dict(preflight=original, result=result, requests=1 if fault in ('false','string','selected') else 2, adopt=not fault))
    for count, packet_prefixes, fault in ((9,1,''),(9,2,''),(16,2,''),(16,8,''),(96,94,''),
            (9,2,'false'),(9,2,'string'),(9,2,'float'),(9,2,'zero'),(9,2,'no-import'),
            (16,2,'both'),(16,2,'selected'),(16,2,'missing'),(16,2,'changed'),
            (16,2,'private-as-public'),(16,2,'public-as-private')):
        original, result = copy.deepcopy(extended_throughput_fixture(count))
        for value in (original, result): value['ordered_local_source']['paired_prefix_nodes'] = packet_prefixes
        for position in range(1, packet_prefixes):
            for label in ('latency_label','speed_label'):
                result['hops'][position][label] = result['hops'][position][label].replace(' to the public benchmark','')
        malformed = {'false':False,'string':'2','float':2.0,'zero':0,'no-import':count-1}
        if fault in malformed: original['ordered_local_source']['paired_prefix_nodes'] = malformed[fault]
        if fault == 'both': original['ordered_local_source']['paired_wireguard'] = True
        if fault == 'selected':
            for value in (original, result): value['ordered_original_source'] = dict(value.pop('ordered_local_source'), generation_sha256='d'*64, selected_execution='local')
        if fault == 'missing':
            result['ordered_local_source'] = dict(result['ordered_local_source']); result['ordered_local_source'].pop('paired_prefix_nodes')
        if fault == 'changed': result['ordered_local_source'] = dict(result['ordered_local_source'], paired_prefix_nodes=packet_prefixes+1)
        if fault == 'private-as-public':
            for label in ('latency_label','speed_label'):
                result['hops'][1][label] = result['hops'][1][label].replace(f'of {count}',f'of {count} to the public benchmark')
        if fault == 'public-as-private':
            for label in ('latency_label','speed_label'):
                result['hops'][packet_prefixes][label] = result['hops'][packet_prefixes][label].replace(' to the public benchmark','')
        cases.append(dict(preflight=original, result=result, requests=1 if fault in (*malformed,'both','selected') else 2, adopt=not fault))
    for count, fault in ((9,''),(16,''),(96,''),(9,'whitespace'),(9,'null'),(9,'list'),
            (9,'short'),(9,'all-public'),(9,'all-private'),(9,'packet-marker'),(9,'paired-marker'),
            (9,'selected'),(16,'missing'),(16,'changed'),(16,'private-as-public'),(16,'public-as-private')):
        roles = ['public-path' if 0 < i < count-1 and i % 4 >= 2 else 'private-node' for i in range(count)]
        original, result = (copy.deepcopy(value) for value in extended_throughput_fixture(count, roles=roles))
        source = original['ordered_local_source']
        if fault == 'whitespace': source['local_roles_json'] = ' '+source['local_roles_json']
        if fault == 'null': source['local_roles_json'] = None
        if fault == 'list': source['local_roles_json'] = roles
        if fault == 'short': source['local_roles_json'] = json.dumps(roles[:-1], separators=(',', ':'))
        if fault in ('all-public','all-private'):
            wrong = ['private-node' if i in (0,count-1) or fault == 'all-private' else 'public-path' for i in range(count)]
            source['local_roles_json'] = json.dumps(wrong, separators=(',', ':'))
        if fault == 'packet-marker': source['paired_prefix_nodes'] = 1
        if fault == 'paired-marker': source['paired_wireguard'] = True
        if fault == 'selected':
            original['ordered_original_source'] = dict(original.pop('ordered_local_source'), generation_sha256='d'*64, selected_execution='local')
        if fault == 'missing': result['ordered_local_source'].pop('local_roles_json')
        if fault == 'changed':
            roles[1], roles[2] = roles[2], roles[1]
            result['ordered_local_source']['local_roles_json'] = json.dumps(roles, separators=(',', ':'))
        if fault == 'private-as-public':
            for key in ('latency_label','speed_label'):
                result['hops'][count-3][key] = result['hops'][count-3][key].replace(f'of {count}',f'of {count} to the public benchmark')
        if fault == 'public-as-private':
            for key in ('latency_label','speed_label'):
                result['hops'][count-2][key] = result['hops'][count-2][key].replace(' to the public benchmark','')
        preflight_bad = fault in ('whitespace','null','list','short','all-public','all-private','packet-marker','paired-marker','selected')
        cases.append(dict(preflight=original, result=result, requests=1 if preflight_bad else 2, adopt=not fault))
    for winner in ('local', 'server'):
        for fault in ('', 'first-private', 'second-private', 'lost', 'swapped', 'local-marker', 'label'):
            original, result = selected_private_throughput(16, winner, fault)
            cases.append(dict(preflight=original, result=result,
                              requests=1 if fault in ('first-private','local-marker') else 2, adopt=fault in ('', 'second-private')))
    for count, (preflight, result) in native_throughput_pairs(native_originals).items():
        assert len(json.loads(result)['hops']) == count
        cases.append(dict(preflight=json.loads(preflight), result=json.loads(result), requests=2, adopt=True))
    path=directory/'throughput.json'; path.write_text(json.dumps(cases))
    binary=directory/'performance'
    run(['cc','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-DROUTERVPN_PERFORMANCE_SOURCE="'+str(projection)+'"',
         ROOT/'client/linux/test-extended-throughput.c','-o',binary,*flags,'-lm'])
    run([binary,'--model-only',path])
    if not model_only: run(['xvfb-run','-a',binary,path])


def sources():
    paths = [SOURCE, FIXTURE, ROOT/"client/linux/test-ordered-latency-receipts-v1.c", Path(__file__), ROOT/"client/linux/routervpn-http-job-v16.h",
             ROOT/"client/linux/routervpn-controller-auth-v1.h", ROOT/"client/linux/routervpn-performance-v17.inc",
             ROOT/"client/linux/routervpn-telemetry-v9.inc", ROOT/"client/linux/routervpn-globe-v10.inc",
             ROOT/"client/linux/routervpn-ordered-nodes-v1.inc", ROOT/"client/linux/test-extended-throughput.c", ROOT/"client/linux/build-native-app.sh",
             ROOT/".github/workflows/linux-native-app.yml"]
    for path in paths:
        if path.is_symlink() or not path.is_file(): raise AssertionError("Lost original GTK source: "+str(path))
    return {str(path.relative_to(ROOT)):hashlib.sha256(path.read_bytes()).hexdigest() for path in paths}


def check_sources():
    before = sources(); source = SOURCE.read_text(); build = (ROOT/"client/linux/build-native-app.sh").read_text()
    performance = (ROOT/"client/linux/routervpn-performance-v17.inc").read_text()
    telemetry = (ROOT/"client/linux/routervpn-telemetry-v9.inc").read_text()
    workflow = (ROOT/".github/workflows/linux-native-app.yml").read_text()
    assert '#include "routervpn-ordered-latency-v1.inc"' in performance
    assert '"50 responses per hop"' in performance and 'linux_ordered_latency_open_v1(p->app)' in performance
    assert '*actions[10]' in performance and 'id<10' in performance and 'i<10' in performance
    assert 'ORDERED_LATENCY_INC="$ROOT/client/linux/routervpn-ordered-latency-v1.inc"' in build
    assert build.count('"$ORDERED_LATENCY_INC"') == 2
    assert build.index('G_CALLBACK(linux_ordered_latency_parent_delete_v1)') < build.index('G_CALLBACK(on_delete)', build.index('install_new ='))
    assert 'g_object_get_data(G_OBJECT(w),"ordered-latency-state")!=NULL' in telemetry
    assert 'python3 deploy/test_linux_ordered_latency.py --self-test' in workflow
    assert workflow.count("'deploy/test_linux_ordered_latency.py'") == 2
    for required in ('s->job_generation[kind] == s->generation', '!(s->complete && s->drained)',
                     'linux_ol_same_capture_v1(capture,', 'linux_ol_receipt_v1(json_node_get_object(record), capture, node, (int)json_array_get_length(json_node_get_array(s->nodes)), TRUE, json_node_get_array(s->nodes))',
                     's->jobs[i] != NULL', 'gtk_window_close(GTK_WINDOW(parent))',
                     'if (s->complete && s->drained) return TRUE;', 'rv_http_free_v16(s->jobs[i])',
                     'g_date_time_format(date, "%Y-%m-%d %H:%M:%S %Z")'):
        assert required in source, required
    assert 'gtk_dialog_run(' not in source and 'gtk_tree_sortable_set_sort_column_id' not in source
    assert '/api/profile/latency' not in source and '/api/profile/fastest' not in source
    assert '#include "routervpn-http-job-v16.h"' in FIXTURE.read_text()
    print("Linux ordered latency source linkage: PASS (GTK execution not claimed)", flush=True)
    return before


def run(args, *, broken=False, timeout=60):
    result = subprocess.run([str(a) for a in args], text=True, capture_output=True, timeout=timeout)
    if broken:
        if result.returncode == 0 or "Ordered latency check failed:" not in result.stdout+result.stderr:
            raise AssertionError("Mutated original guard lacked its causal fixture failure:\n"+result.stdout+result.stderr)
    elif result.returncode:
        raise RuntimeError(result.stdout+result.stderr)
    else:
        print(result.stdout.strip(), flush=True)
    return result


@contextlib.contextmanager
def controller(scenario):
    lock = threading.Lock()
    state = dict(request="", position=1, admitted=False, cancelled=False, polls=0, failures=[], bodies=[], cancels=[])
    def view(stage="measuring", complete=False, drained=False, saved=False):
        value=info(); request=state["request"];position=state["position"]
        value.update(request_id=request,node_id=NODES[position]["node_id"],position=position)
        value["status"]=dict(request_id=request,stage=stage,complete=complete,drained=drained,results=[])
        if saved:value["receipt"]=receipt(position,request)
        return value
    class Handler(http.server.BaseHTTPRequestHandler):
        protocol_version="HTTP/1.1"
        def log_message(self,*_):pass
        def reply(self,code,value):
            raw=json.dumps(value).encode()
            try:
                self.send_response(code);self.send_header("Content-Type","application/json");self.send_header("Content-Length",str(len(raw)));self.send_header("Connection","close");self.end_headers();self.wfile.write(raw)
            except (BrokenPipeError,ConnectionResetError):pass
        def do_GET(self):
            parsed=urllib.parse.urlsplit(self.path)
            if parsed.path!="/api/speed-lab/ordered-latency":state["failures"].append("foreign GET");return self.reply(400,{})
            request=urllib.parse.parse_qs(parsed.query).get("request_id",[""])[0]
            if not request:return self.reply(200,info())
            with lock:
                if request!=state["request"]:return self.reply(404,{"error":"not yet admitted"})
                state["polls"]+=1
                if scenario=="poll-error" and state["polls"]==1:return self.reply(503,{})
                if scenario=="stale" and state["polls"]==1:
                    value=view();value["capture"]["generation_sha256"]="9"*64;return self.reply(200,value)
                if not state["cancelled"] and scenario in ("saved","partial","missing-receipt"):
                    value=view("complete",True,True,scenario!="missing-receipt")
                    if scenario=="partial":value["receipt"]["result"]["benchmark"]["distribution"]["samples"]=49
                    return self.reply(200,value)
                if state["cancelled"]:
                    if scenario in ("commit-race","replacement-commit"):return self.reply(200,view("complete",True,True,True))
                    return self.reply(200,view("cancelled",True,state["polls"]>=3))
                return self.reply(200,view("finishing",False,False))
        def do_POST(self):
            try:
                length=int(self.headers.get("Content-Length","0"));assert 0<length<4096
                body=json.loads(self.rfile.read(length));assert set(body)=={"capture","node_id","position","request_id"}
                assert body["capture"]==CAPTURE;position=body["position"];assert type(position)is int and 0<=position<=2
                assert body["node_id"]==NODES[position]["node_id"]
                request=body["request_id"];assert isinstance(request,str) and len(request)==32 and set(request)<=set("0123456789abcdef")
                assert self.path in ("/api/speed-lab/ordered-latency","/api/speed-lab/ordered-latency/cancel")
            except (AssertionError,KeyError,ValueError) as e:
                state["failures"].append(str(e) or "request identity");return self.reply(400,{})
            if self.path.endswith("/cancel"):
                with lock:
                    if state["request"] and state["request"]!=request:state["failures"].append("cancel crossed owners");return self.reply(409,{})
                    state.update(request=request,position=position,cancelled=True);state["bodies"].append(body);state["cancels"].append(request)
                    if scenario in ("commit-race","replacement-commit"):return self.reply(200,view("complete",True,True,True))
                    return self.reply(202 if state["admitted"] else 200,view("cancelled",True,not state["admitted"]))
            if scenario=="early":time.sleep(.4)
            with lock:
                if state["request"] and state["request"]!=request:state["failures"].append("Start crossed owners");return self.reply(409,{})
                state.update(request=request,position=position);state["bodies"].append(body)
                if state["cancelled"]:return self.reply(409,{"error":"queued Start tombstoned"})
                state["admitted"]=True
                return self.reply(503,{}) if scenario=="http-error" else self.reply(202,view("starting",False,False))
    class Server(http.server.ThreadingHTTPServer):
        allow_reuse_address=True
        daemon_threads=False
    server=Server(("127.0.0.1",8788),Handler);thread=threading.Thread(target=server.serve_forever);thread.start()
    try:yield state
    finally:
        server.shutdown();server.server_close();thread.join()
        if state["failures"]:raise AssertionError(state["failures"])


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--source-only',action='store_true');parser.add_argument('--self-test',action='store_true');parser.add_argument('--receipt-model',action='store_true');args=parser.parse_args()
    if args.source_only and (args.self_test or args.receipt_model):parser.error("source-only cannot claim native self-test")
    if args.self_test and args.receipt_model:parser.error("receipt-model cannot replace the full GTK self-test")
    before=check_sources()
    if args.source_only:return
    with tempfile.TemporaryDirectory(prefix='routervpn-c-ordered-receipts-') as temporary:
        directory=Path(temporary);data=directory/'fixture.json';data.write_text(json.dumps(fixture_data()))
        receipt_model(directory,data)
    if args.receipt_model:
        assert sources()==before,'original C receipt source changed during validation'
        return
    missing=[name for name in ('pkg-config','cc','xvfb-run') if not shutil.which(name)]
    if missing:raise RuntimeError("Actual GTK validation unavailable; missing "+', '.join(missing))
    flags=shlex.split(subprocess.check_output(['pkg-config','--cflags','--libs','gtk+-3.0','libcurl','json-glib-1.0'],text=True))
    with tempfile.TemporaryDirectory(prefix='routervpn-gtk-ordered-') as temporary:
        directory=Path(temporary);data=directory/'fixture.json';data.write_text(json.dumps(fixture_data()))
        def compile_to(name,text=None,live=False):
            command=['cc','-O1','-Wall','-Wextra','-Werror','-Wno-unused-function','-I'+str(SOURCE.parent)]
            if text is not None:
                include=directory/(name+'.inc');include.write_text(text);command.append('-DROUTERVPN_ORDERED_SOURCE="'+str(include)+'"')
            if live:command.append('-DROUTERVPN_ORDERED_LIVE')
            binary=directory/name;run([*command,FIXTURE,'-o',binary,*flags,'-lm','-pthread']);return binary
        extended_throughput(directory, flags)
        binary=compile_to('shipping');run(['xvfb-run','-a',binary,data])
        source=SOURCE.read_text();mutations={
            'unbound-public-entry': ('if (g_strcmp0(linux_ol_string_v1(node, "kind"), kinds[i]) ||', 'if ((i != 1 && g_strcmp0(linux_ol_string_v1(node, "kind"), kinds[i])) ||'),
            # Selected capture membership and uniform path labels independently
            # prevent a mixed inventory. Mutate both at initial admission.
            'mixed-inventory': (
                'if (!linux_ol_selected_node_v1(capture, json_node_get_object(n), (int)json_array_get_length(nodes))) return FALSE;\n            if (i > 0 && linux_ol_label_kind_v1',
                'if (FALSE && linux_ol_label_kind_v1'),
            'native-drain':('!JSON_NODE_HOLDS_OBJECT(record) || !complete || !drained ||','!JSON_NODE_HOLDS_OBJECT(record) || !complete ||'),
            'http-join':('for (int i = 0; i < OL_JOBS_V1; i++) if (s->jobs[i] != NULL) return FALSE;','/* mutation: unfinished workers ignored */'),
            'capture-owner':('if (g_strcmp0(linux_ol_string_v1(a, keys[i]), linux_ol_string_v1(b, keys[i])) != 0) return FALSE;','if (FALSE) return FALSE;'),
            'partial-fifty':('linux_ol_number_v1(d, "samples", 50, 50, TRUE)','linux_ol_number_v1(d, "samples", 49, 50, TRUE)'),
        }
        for name,(original,replacement) in mutations.items():
            assert source.count(original)==1,name
            mutant=compile_to(name,source.replace(original,replacement,1));run(['xvfb-run','-a',mutant,data],broken=True)
            print('Rejected broken GTK ordered-latency guard: '+name,flush=True)
        live=compile_to('live',live=True)
        for scenario in ('early','accepted','saved','commit-race','http-error','poll-error','stale','partial','missing-receipt','replacement-commit'):
            with controller(scenario) as state:
                run(['xvfb-run','-a',live,scenario],timeout=25)
                assert state['bodies'] and len({b['request_id'] for b in state['bodies']})==1
                if scenario!='saved':assert state['cancels'] and len(set(state['cancels']))==1
                if scenario=='early':assert not state['admitted']
            print('Real GTK/libcurl ordered-latency scenario: '+scenario,flush=True)
    assert sources()==before,'original GTK source changed during validation'
    print('GTK ordered latency: shipping callbacks,6 compiled controls,10 real HTTP scenarios PASS',flush=True)

if __name__=='__main__':main()
