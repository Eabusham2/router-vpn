#!/usr/bin/env python3
"""Run the selected Server/Compare desktop candidate controller on its native host."""
import argparse
import hashlib
import json
from pathlib import Path
import tempfile

import test_desktop_socks_execution_controller as common

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = common.PACKAGE
RESPONSE_FINAL_LAYOUTS = ('private-penultimate/4', 'private-penultimate/9', 'private-penultimate/16',
                          'all-imported/4', 'all-imported/9', 'all-imported/16',
                          'earlier-private/5', 'earlier-private/9', 'earlier-private/16')
RESPONSE_DEEP_LAYOUTS = ('private-penultimate/16', 'all-imported/16', 'earlier-private/16')
RESPONSE_INTERMEDIATE_LAYOUTS = ('4/1', '9/6', '16/8', '16/13')
CASES = {
    'TestDesktopSelectedServerUnregisteredCannotBeSaved': (),
    'TestDesktopSelectedServerResponseConnected': ('server/server', 'auto/server', 'auto/local'),
    'TestDesktopSelectedThroughputPublicController': ('server-server','auto-local','auto-server'),
    'TestDesktopSelectedThroughputCancellationJoinsOriginal': (),
    'TestDesktopSelectedThroughputTerminalOwnership': ('provisional','copied-result','changed-result','returned-request'),
    'TestDesktopSelectedThroughputRejectsForeignRows': ('unjoined','fifty','winner','swapped','missing-final','wrong-size','bad-duration','bad-rate'),
    'TestDesktopSelectedCandidateHTTPRetainsSparsePrefixAndSelectedWinner': (
        'server/server', 'auto/local', 'auto/server'),
    'TestDesktopSelectedCandidateMetadataRejectsForeignOriginals': (
        'source', 'config', 'preparation-source', 'preparation-config', 'epoch', 'requested',
        'execution', 'position', 'prefix', 'target-id', 'target-source', 'extra-target-field',
        'missing', 'extra', 'duplicate', 'whitespace', 'request', 'generation', 'inventory',
        'capture', 'revision'),
    'TestDesktopSelectedCandidateCancellationJoinsWithoutStart': (
        'factory-failure', 'metadata-refusal', 'cancel-before-metadata'),
    'TestDesktopSelectedCandidatePendingRetirementPreservesForeignMetadata': (),
    'TestDesktopSelectedCandidateResultRetirement': ('original', 'same-bytes-foreign-inode',
                                                   'modified-original-bytes', 'missing-original'),
    'TestDesktopSelectedMeasurementWorkspaceRetirement': ('selected-latency', 'selected-throughput', 'selected-candidate',
                                                         'typed-candidate', 'foreign-lookalikes'),
    'TestDesktopSelectedPrivateResponseHTTPPreservesCompleteSourceAndNamedProfile': RESPONSE_FINAL_LAYOUTS,
    'TestDesktopSelectedPrivateResponseCancelBeforeStartRetainsIssuedSource': RESPONSE_DEEP_LAYOUTS,
    'TestDesktopSelectedPrivateResponseConnectedServerWinnerHasNoPrivateOffer': RESPONSE_DEEP_LAYOUTS,
    'TestDesktopSelectedIntermediateResponseHTTPPreservesOriginalSuffixAndNamedLoad': RESPONSE_INTERMEDIATE_LAYOUTS,
    'TestDesktopSelectedIntermediateResponseRejectsChangedOriginalSuffixBeforeSave': (),
    'TestDesktopSelectedIntermediateResponseCancelCannotBorrowAnotherEligibleStop': (),
}
DRAFT_CASES = {
    'TestDesktopSelectedServerResponseDraft': ('server/server', 'auto/server', 'auto/local'),
    'TestDesktopSelectedDraftCapturesFullUnsavedPacketSource': (
        'paired/server', 'paired/auto', 'sparse/server', 'sparse/auto'),
    'TestDesktopSelectedDraftRejectsMismatchedSourceAndPurpose': (
        'closed-prefix', 'saved-endpoint', 'no-execution', 'wrong-selected', 'missing-token',
        'changed-token', 'stream-interior', 'final', 'truncated-suffix'),
    'TestDesktopSelectedDraftRetainsWinnerThroughOriginalDownAndChoose': (
        'server/server', 'auto/local', 'auto/server', 'held-native-down', 'changed-review-network'),
    'TestSelectedPrivateResponseNamedProfileRetainsCompare': (),
    'TestSelectedPrivatePenultimateResponseNamedProfileRetainsCompare': RESPONSE_FINAL_LAYOUTS,
    'TestSelectedPrivatePenultimateResponseDraftServerWinnerClosesWithoutScores': ('-1', '2', '14'),
    'TestSelectedPrivateResponseDraftCancelBeforeStartRetainsSourceWithoutEpoch': RESPONSE_DEEP_LAYOUTS,
    'TestDesktopSelectedIntermediateResponseDraftRetainsOriginalSuffixThroughDownSaveAndLoad': RESPONSE_INTERMEDIATE_LAYOUTS,
    'TestDesktopSelectedIntermediateResponseDraftServerWinnerClosesWithoutScores': (),
    'TestDesktopSelectedIntermediateResponseDraftPrestartCancelRetainsExactStopWithoutEpoch': (),
    'TestSelectedPrivateResponseDraftUsePreservesUnsavedPath': ('3/1', '4/1', '4/2', '9/6', '16/8', '16/14'),
    'TestSelectedPrivateResponseDraftUseStartsFreshMeasurement': (),
    'TestSelectedPrivateResponseDraftUseExtendsMultiplePrivateHops': ('6-before', '6-between', '6-after', '16-before', '16-between', '16-after'),
    'TestSelectedPrivateResponseDraftUseRejectsChangedOwner': ('source', 'network', 'epoch', 'cancelled', 'expired', 'file-candidate', 'file-final'),
    'TestSelectedPrivateResponseDraftUseMultiplePrivateAndCapacity': (),
    'TestOrderedCandidateDraftUseKeepsOriginalFinalAndSuffix': ('3/1', '4/1', '6/2', '9/7'),
}
TYPED_ENTRY_OUTCOMES = tuple(family+'/'+outcome for family in ('socks', 'connect')
                            for outcome in ('server', 'compare-local', 'compare-server'))
TYPED_ENTRY_CASES = {'TestDesktopSelectedTypedEntryConnected': TYPED_ENTRY_OUTCOMES,
                     'TestDesktopSelectedTypedEntryOriginalDraft': TYPED_ENTRY_OUTCOMES}
PHASES = {'connected': CASES, 'draft': DRAFT_CASES, 'typed-entry': TYPED_ENTRY_CASES}
REQUIRED_INPUTS = (
    'deploy/build-native-runtime.py', 'deploy/test_desktop_socks_execution_controller.py',
    'deploy/test_desktop_selected_candidate_controller.py', 'deploy/test_desktop_selected_candidate_controller_runner.py',
    '.github/workflows/multihop-contract.yml', 'go.mod',
    'cmd/client/connection_profile_node_chain.go', 'cmd/client/desktop_node_chain_execution_host.go',
    'cmd/client/desktop_node_chain_execution_launch.go', 'cmd/client/desktop_node_chain_execution_session.go',
    'cmd/client/desktop_node_chain_policy_dispatch.go', 'cmd/client/desktop_node_chain_execution_restore.go', 'cmd/client/desktop_node_chain_execution_owned_test.go',
    'cmd/client/desktop_multiple_imported_selected_latency_test.go', 'cmd/client/desktop_selected_latency_capture.go',
    'cmd/client/multihop_native_launch.go', 'cmd/client/ordered_candidate_prefix_runtime.go',
    'cmd/client/ordered_candidate_prefix_source.go', 'cmd/client/ordered_candidate_preparation.go',
    'cmd/client/ordered_candidate_preparation_cancel.go', 'cmd/client/ordered_candidate_preparation_api.go', 'cmd/client/ordered_candidate_preparation_draft.go',
    'cmd/client/ordered_candidate_preparation_lifecycle.go', 'cmd/client/ordered_candidate_preparation_profile.go',
    'cmd/client/ordered_candidate_preparation_run.go', 'cmd/client/ordered_candidate_preparation_view.go',
    'cmd/client/ordered_candidate_selected_draft.go', 'cmd/client/ordered_candidate_selected_draft_test.go',
    'cmd/client/ordered_candidate_selected_response_source.go', 'cmd/client/ordered_candidate_selected_response_draft_use_test.go',
    'cmd/client/ordered_candidate_draft_final_test.go',
    'cmd/client/desktop_selected_private_response_http_test.go', 'cmd/client/desktop_selected_intermediate_response_http_test.go',
    'cmd/client/desktop_node_chain_candidate_catalog.go', 'cmd/client/desktop_node_chain_candidates.go',
    'cmd/client/desktop_node_chain_measurement.go', 'cmd/client/desktop_node_chain_typed_candidate_catalog.go',
    'cmd/client/desktop_selected_candidate_catalog.go', 'cmd/client/desktop_selected_candidate_observation.go',
    'cmd/client/desktop_selected_candidates.go', 'cmd/client/desktop_selected_candidates_test.go',
    'cmd/client/ordered_candidate_server_response_test.go',
    'cmd/client/desktop_selected_typed_entry_test.go',
    'cmd/client/desktop_native_workspace.go', 'cmd/client/desktop_selected_workspace_test.go',
    'cmd/client/desktop_selected_latency_exchange.go', 'cmd/client/ordered_candidates.go',
    'cmd/client/ordered_candidates_profile.go', 'internal/mobilemultihop/node_chain_execution_candidates.go',
    'internal/mobilemultihop/node_chain_execution_remote_candidates.go',
    'internal/mobilemultihop/node_chain_multiple_imported_execution_candidates_test.go',
    'mobile/desktop/node_chain_execution_candidate.go.tmpl', 'mobile/desktop/node_chain_execution_candidate_test.go.tmpl',
    'mobile/desktop_test/selected_candidate_fixture.go.tmpl',
)


def source_identity():
    paths = common.BUILDER.inputs()
    missing = set(ROOT / name for name in REQUIRED_INPUTS).difference(paths)
    if missing:
        raise ValueError('Selected candidate controller inputs missing: ' + ', '.join(sorted(path.relative_to(ROOT).as_posix() for path in missing)))
    # Use the native builder's complete ordered input set and digest format.
    value = hashlib.sha256()
    for path in paths:
        if path.is_symlink() or not path.is_file():
            raise ValueError('Selected candidate controller source is not a regular original file: ' + str(path))
        value.update(path.relative_to(ROOT).as_posix().encode() + b'\0' + path.read_bytes())
    return value.hexdigest()


def verify_original(image, image_digest, source_digest):
    if image.is_symlink() or not image.is_file() or hashlib.sha256(image.read_bytes()).hexdigest() != image_digest:
        raise ValueError('Selected candidate controller image changed')
    if source_identity() != source_digest:
        raise ValueError('Selected candidate controller source changed')


def run(go='go', receipt=None, without_race=False, phase='connected'):
    cases = PHASES[phase]
    result = {'schema': 1, 'phase': phase, 'status': 'failed', 'records': [], 'race': not without_race,
              'scope': 'Shipping desktop controller, HTTP, selected inventory, MTU and mailbox retirement. The child process and kernel are modeled.'}
    try:
        executable, environment, target = common.native_environment(go, without_race)
        identity = source_identity()
        result.update(target=target, compiler=executable, toolchain=common.BUILDER.TOOLCHAIN, source_sha256=identity)
        with tempfile.TemporaryDirectory(prefix='routervpn-selected-candidate-controller-') as directory:
            image = Path(directory) / ('controller.test.exe' if target.startswith('windows/') else 'controller.test')
            compile_command, digest = common.compile_image(executable, environment, image, without_race)
            result['compile'] = {'command': compile_command, 'image_sha256': digest}
            for root, children in cases.items():
                verify_original(image, digest, identity)
                command = [executable, 'tool', 'test2json', '-p', PACKAGE, str(image), '-test.v=test2json',
                           '-test.count=1', '-test.timeout=120s', '-test.run=^' + root + '$']
                completed = common.invoke(command, environment, ROOT/'cmd/client', 135)
                row = {'root': root, 'command': command, 'returncode': completed.returncode, 'image_sha256': digest,
                       'output_sha256': hashlib.sha256(completed.stdout.encode()).hexdigest()}
                result['records'].append(row)
                if receipt:
                    Path(str(receipt) + '.' + root + '.jsonl').write_text(completed.stdout)
                if completed.returncode or completed.stderr.strip():
                    raise ValueError('Selected candidate controller failed: ' + root + '\n' + (completed.stderr or completed.stdout)[-1600:])
                expected = common.expected({root: children})
                common.BUILDER.verify_imported_native_verdicts(completed.stdout, PACKAGE, expected)
                verify_original(image, digest, identity)
                row['tests'] = len(expected)
            if sum(row['tests'] for row in result['records']) != len(common.expected(cases)):
                raise ValueError('Selected candidate controller omitted a required case')
        result['status'] = 'passed'
    except BaseException as error:
        result['error'] = repr(error)
        raise
    finally:
        if receipt:
            Path(receipt).write_text(json.dumps(result, indent=2, sort_keys=True) + '\n')
        print(json.dumps(result, sort_keys=True), flush=True)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--go', default='go')
    parser.add_argument('--receipt', type=Path)
    parser.add_argument('--without-race', action='store_true')
    parser.add_argument('--phase', choices=PHASES, default='connected')
    args = parser.parse_args()
    run(args.go, args.receipt, args.without_race, args.phase)
