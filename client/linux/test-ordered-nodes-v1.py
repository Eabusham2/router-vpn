#!/usr/bin/env python3
"""Execute the shipping GTK ordered editor and profile callbacks.

Real GTK widgets/signals and on-disk GKeyFile persistence; the authenticated
controller response is a boundary double, never native tunnel acceptance.
"""
from pathlib import Path
import os
import argparse
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent


def block(source, marker):
    start = source.index(marker)
    brace = source.index('{', start)
    depth, end = 1, brace + 1
    while depth:
        depth += (source[end] == '{') - (source[end] == '}')
        end += 1
    return source[start:end]


def public_source_helpers():
    core = (HERE/'routervpn-gtk-product.c').read_text()
    source = (HERE/'routervpn-external-source-v24.inc').read_text()
    return block(core, 'static JsonNode *copy_public_source_value_v24(') + '\n' + '\n'.join(
        block(source, marker) for marker in ('static gboolean external_source_id_v24(',
            'static gboolean external_source_token_v24(', 'static JsonObject *external_source_profile_v24(')
    )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--model-only', action='store_true', help='Run pure source inventory/serialization checks; does not claim GTK callbacks.')
    args = parser.parse_args()
    build = (HERE/'build-native-app.sh').read_text()
    assert '"$ORDERED_INC"' in build.split('SHIPPED=(', 1)[1].split(')', 1)[0]
    profiles = (HERE/'routervpn-connection-profiles-v11.inc').read_text()
    assert profiles.count('#include "routervpn-ordered-nodes-v1.inc"') == 1
    assert 'linux_ordered_connect_v1(state)' in block(profiles, 'static void linux_profile_connect_v11(')
    assert 'linux_profile_choose_hops_v11' in block(profiles, 'static void linux_install_connection_profiles_v11(')
    original = (HERE/'routervpn-ordered-nodes-v1.inc').read_text()
    controls = [
        ('connect-mode', 'g_strdup(linux_ordered_imported_v1(profile) ? linux_ordered_imported_mode_v1(profile) : "wg")', 'g_strdup(linux_ordered_imported_v1(profile) ? (strcmp(linux_ordered_imported_mode_v1(profile), "https-connect") == 0 ? "http-connect" : linux_ordered_imported_mode_v1(profile)) : "wg")', 'CONNECT Add substituted its exact saved transport'),
        ('connect-protocol', 'strcmp(mode, linux_ordered_imported_mode_v1(profile)) == 0', '(strcmp(mode, linux_ordered_imported_mode_v1(profile)) == 0 || strcmp(mode, "http-connect") == 0 || strcmp(mode, "https-connect") == 0)', 'CONNECT selection borrowed a different saved protocol'),
        ('connect-final', ' || g_strcmp0(g_ptr_array_index(editor->modes, i), "http-connect") == 0 || g_strcmp0(g_ptr_array_index(editor->modes, i), "https-connect") == 0', '', 'CONNECT final chooser admitted Hysteria2'),
        ('socks-mode', 'g_strdup(linux_ordered_imported_v1(profile) ? linux_ordered_imported_mode_v1(profile) : "wg")', 'g_strdup(linux_ordered_imported_v1(profile) ? "shadowsocks" : "wg")', 'SOCKS Add substituted its saved transport'),
        ('final-mode', 'strcmp(linux_ordered_string_v1(payload, "mode"), linux_ordered_string_v1(json_array_get_object_element(nodes, json_array_get_length(nodes) - 1), "mode")) != 0', 'FALSE', 'different final mode borrowed committed receipt'),
        ('source-token', 'strcmp(linux_ordered_string_v1(profile, "profile_token"), linux_ordered_string_v1(selection->tokens, id)) != 0', 'FALSE', 'replaced middle source connected'),
        ('generation', 'owned->generation == generation &&', '(void)generation,', 'late choice applied'),
        ('prefix-mode', 'editor->modes->pdata[target] = mode;', 'editor->modes->pdata[index] = mode;', 'mode did not travel with member'),
        ('capability', 'linux_ordered_flag_v1(json_node_get_object(capabilities), "ordered_nodes_supported")', 'TRUE', 'unavailable native capability connected'),
        ('final-pin', '!linux_ordered_final_v1(mode) || strcmp(id, control) != 0', '!linux_ordered_final_v1(mode)', 'foreign final accepted'),
        ('expected-inventory', 'json_object_set_object_member(body, "expected_profile_tokens", json_object_ref(selection->tokens));', 'json_object_set_object_member(body, "expected_profile_tokens", json_object_new());', 'original source inventory missing'),
        ('disk-receipt', 'if (!persisted) { linux_ordered_selection_free_v1(selection);', 'if (FALSE && !persisted) { linux_ordered_selection_free_v1(selection);', 'failed write acquired replacement receipt'),
        ('load-current-graph', 'if (linux_ordered_flag_v1(profile, "multihop_enabled")) {', 'if (FALSE) {', 'Load lost complete current graph'),
        ('response-inventory', 'if (supplied == NULL || json_object_get_size(supplied) != json_array_get_length(nodes)) return NULL;', 'if (supplied == NULL) return NULL;', 'extra committed source receipt accepted'),
    ]
    if args.model_only: controls = [c for c in controls if c[0] in {'connect-protocol', 'connect-final', 'final-mode', 'source-token', 'final-pin', 'expected-inventory', 'disk-receipt', 'load-current-graph', 'response-inventory'}]
    flags = subprocess.check_output(['pkg-config', '--cflags', '--libs', 'gtk+-3.0', 'json-glib-1.0'], text=True).split()
    with tempfile.TemporaryDirectory(prefix='routervpn-gtk-ordered-') as temporary:
        root = Path(temporary)
        (root/'ordered-source-helpers.h').write_text(public_source_helpers())
        (root/'test.c').write_text((HERE/'test-ordered-nodes-v1.c').read_text())
        for name, before, after, witness in [('shipping', '', '', '')] + controls:
            source = original
            if before:
                expected = 2 if name == 'expected-inventory' else 1
                assert source.count(before) == expected, name
                source = source.replace(before, after, 1)
            (root/'routervpn-ordered-nodes-v1.inc').write_text(source)
            (root/'routervpn-connection-profiles-v11.inc').write_text(profiles)
            binary = root/name
            subprocess.run(['gcc', '-O1', '-Wall', '-Wextra', '-Werror', '-Wno-unused-function', '-Wno-misleading-indentation',
                '-I'+str(root), '-I'+str(HERE), str(root/'test.c'), '-o', str(binary), *flags], check=True, timeout=90)
            command = [str(binary), str(root)]
            if args.model_only: command.append('--model-only')
            elif not os.environ.get('DISPLAY'): command = ['xvfb-run', '-a', *command]
            result = subprocess.run(command, text=True, capture_output=True, timeout=45)
            output = result.stdout + result.stderr
            if name == 'shipping':
                assert result.returncode == 0, output
                assert 'CRITICAL' not in output and 'WARNING' not in output, output
                print(output.strip())
            else:
                assert result.returncode == 1 and witness in output, f'{name}: {output}'
                print('GTK ordered causal control '+name+': rejected')


if __name__ == '__main__':
    main()
