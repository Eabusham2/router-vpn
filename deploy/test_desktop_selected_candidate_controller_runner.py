#!/usr/bin/env python3
"""Check receipt inventory, compilation and run bounds for the selected candidate controller."""
import contextlib
import io
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import test_desktop_selected_candidate_controller as gate


def events(root):
    def event(action, test=None):
        value = {'Action': action, 'Package': gate.PACKAGE}
        if test is not None:
            value['Test'] = test
        return value

    rows = [event('start'), event('run', root)]
    for child in (gate.CASES | gate.DRAFT_CASES | gate.TYPED_ENTRY_CASES)[root]:
        rows.extend((event('run', root + '/' + child), event('pass', root + '/' + child)))
    return rows + [event('pass', root), event('pass')]


def output(rows):
    return '\n'.join(json.dumps(row) for row in rows)


class SelectedCandidateControllerGateTests(unittest.TestCase):
    def test_each_original_test_and_package_verdict_is_required_once(self):
        counts = {'TestDesktopSelectedCandidateHTTPRetainsSparsePrefixAndSelectedWinner': 3,
                  'TestDesktopSelectedCandidateMetadataRejectsForeignOriginals': 21,
                  'TestDesktopSelectedCandidateCancellationJoinsWithoutStart': 3,
                  'TestDesktopSelectedCandidatePendingRetirementPreservesForeignMetadata': 0,
                  'TestDesktopSelectedCandidateResultRetirement': 4,
                  'TestDesktopSelectedDraftCapturesFullUnsavedPacketSource': 4,
                  'TestDesktopSelectedTypedEntryConnected': 6,
                  'TestDesktopSelectedTypedEntryOriginalDraft': 6,
                  'TestDesktopSelectedDraftRejectsMismatchedSourceAndPurpose': 9,
                  'TestDesktopSelectedDraftRetainsWinnerThroughOriginalDownAndChoose': 5,
                  'TestDesktopSelectedThroughputPublicController': 3,
                  'TestDesktopSelectedThroughputCancellationJoinsOriginal': 0,
                  'TestDesktopSelectedThroughputTerminalOwnership': 4,
                  'TestDesktopSelectedThroughputRejectsForeignRows': 8,
                  'TestDesktopSelectedMeasurementWorkspaceRetirement': 5,
                  'TestDesktopSelectedPrivateResponseHTTPPreservesCompleteSourceAndNamedProfile': 9,
                  'TestDesktopSelectedPrivateResponseCancelBeforeStartRetainsIssuedSource': 3,
                  'TestDesktopSelectedPrivateResponseConnectedServerWinnerHasNoPrivateOffer': 3,
                  'TestDesktopSelectedIntermediateResponseHTTPPreservesOriginalSuffixAndNamedLoad': 4,
                  'TestDesktopSelectedIntermediateResponseRejectsChangedOriginalSuffixBeforeSave': 0,
                  'TestDesktopSelectedIntermediateResponseCancelCannotBorrowAnotherEligibleStop': 0,
                  'TestSelectedPrivateResponseNamedProfileRetainsCompare': 0,
                  'TestSelectedPrivatePenultimateResponseNamedProfileRetainsCompare': 9,
                  'TestSelectedPrivatePenultimateResponseDraftServerWinnerClosesWithoutScores': 3,
                  'TestSelectedPrivateResponseDraftCancelBeforeStartRetainsSourceWithoutEpoch': 3,
                  'TestDesktopSelectedIntermediateResponseDraftRetainsOriginalSuffixThroughDownSaveAndLoad': 4,
                  'TestDesktopSelectedIntermediateResponseDraftServerWinnerClosesWithoutScores': 0,
                  'TestDesktopSelectedIntermediateResponseDraftPrestartCancelRetainsExactStopWithoutEpoch': 0,
                  'TestSelectedPrivateResponseDraftUsePreservesUnsavedPath': 6,
                  'TestSelectedPrivateResponseDraftUseStartsFreshMeasurement': 0,
                  'TestSelectedPrivateResponseDraftUseRejectsChangedOwner': 7,
                  'TestSelectedPrivateResponseDraftUseRejectsSecondPrivateAndCapacity': 0,
                  'TestOrderedCandidateDraftUseKeepsOriginalFinalAndSuffix': 4}
        self.assertEqual(set(gate.CASES).intersection(gate.DRAFT_CASES), set())
        self.assertEqual(len(gate.common.expected(gate.CASES)), 86)
        self.assertEqual(len(gate.common.expected(gate.DRAFT_CASES)), 69)
        self.assertEqual(len(gate.common.expected(gate.TYPED_ENTRY_CASES)), 14)
        cases = gate.CASES | gate.DRAFT_CASES | gate.TYPED_ENTRY_CASES
        self.assertEqual({root: len(children) for root, children in cases.items()}, counts)
        for root, children in cases.items():
            expected = gate.common.expected({root: children})
            self.assertEqual(len(expected), 1 + len(children))
            rows = events(root)
            verify = lambda raw: gate.common.BUILDER.verify_imported_native_verdicts(raw, gate.PACKAGE, expected)
            verify(output(rows))
            for i, event in enumerate(rows):
                for label, changed in [('omitted', rows[:i] + rows[i+1:]), ('duplicate', rows[:i] + [event] + rows[i:]),
                                       ('skip', rows[:i] + [dict(event, Action='skip')] + rows[i+1:])]:
                    with self.subTest(root=root, event=event, fault=label), self.assertRaises(ValueError):
                        verify(output(changed))
            with self.assertRaises(ValueError):
                verify(output([rows[0], dict(rows[1], Test=root+'/foreign'), *rows[2:]]))
            with self.assertRaises(ValueError):
                verify(output(rows).replace('"Action": "start"', '"Action":"run","Action":"start"', 1))

    def exercise(self, target, fault=None, phase="connected"):
        cases = gate.PHASES[phase]
        commands, images = [], []
        roots = iter(cases)
        digest = ['original']
        environment = {'CAPTURED': 'same'}
        def invoke(command, env, cwd, timeout):
            self.assertIs(env, environment)
            commands.append(command)
            if command[1:3] == ['test', '-c']:
                self.assertEqual((cwd, timeout), (gate.ROOT, 240))
                self.assertEqual('-race' in command, target != 'windows/arm64')
                self.assertIn('-mod=readonly', command)
                self.assertFalse(any(item.startswith('-vet=') for item in command))
                image = Path(command[command.index('-o')+1])
                image.write_bytes(b'original controller test')
                images.append(image)
                return subprocess.CompletedProcess(command, int(fault == 'compile'), '', '')
            root = next(roots)
            self.assertEqual((cwd, timeout), (gate.ROOT/'cmd/client', 135))
            self.assertEqual(command, ['go', 'tool', 'test2json', '-p', gate.PACKAGE, str(images[0]),
                                      '-test.v=test2json', '-test.count=1', '-test.timeout=120s', '-test.run=^'+root+'$'])
            rows = events(root)
            if fault == 'image':
                images[0].write_bytes(b'changed')
            elif fault == 'source':
                digest[0] = 'changed'
            elif fault == 'missing':
                rows = rows[:-1]
            elif fault == 'timeout':
                raise subprocess.TimeoutExpired(command, timeout)
            return subprocess.CompletedProcess(command, int(fault == 'status'), output(rows), 'warning' if fault == 'stderr' else '')
        with tempfile.TemporaryDirectory() as directory:
            receipt = Path(directory)/'receipt.json'
            with patch.object(gate.common, 'native_environment', return_value=('go', environment, target)), \
                 patch.object(gate, 'source_identity', side_effect=lambda: digest[0]), \
                 patch.object(gate.common, 'invoke', side_effect=invoke), contextlib.redirect_stdout(io.StringIO()):
                if fault:
                    with self.assertRaises((ValueError, subprocess.TimeoutExpired)):
                        gate.run(receipt=receipt, without_race=target == 'windows/arm64', phase=phase)
                else:
                    gate.run(receipt=receipt, without_race=target == 'windows/arm64', phase=phase)
            result = json.loads(receipt.read_text())
            self.assertEqual(result['status'], 'failed' if fault else 'passed')
            if not fault:
                self.assertEqual([row['root'] for row in result['records']], list(cases))
                self.assertEqual(sum(row['tests'] for row in result['records']), len(gate.common.expected(cases)))
                self.assertEqual(len(list(Path(directory).glob('*.jsonl'))), len(cases))
        return commands

    def test_native_targets_and_original_bounds(self):
        for phase, cases in gate.PHASES.items():
            for system in ('linux', 'windows', 'darwin'):
                for arch in ('amd64', 'arm64'):
                    with self.subTest(phase=phase, system=system, arch=arch):
                        self.assertEqual(len(self.exercise(system+'/'+arch, phase=phase)), 1+len(cases))
            for fault in ('compile', 'status', 'stderr', 'timeout', 'missing', 'source', 'image'):
                with self.subTest(phase=phase, fault=fault):
                    self.assertLessEqual(len(self.exercise('linux/amd64', fault, phase)), 2)

    def test_complete_builder_sources_and_image_identity(self):
        paths = gate.common.BUILDER.inputs()
        self.assertEqual(gate.source_identity(), gate.common.BUILDER.digest())
        for name in gate.REQUIRED_INPUTS:
            path = gate.ROOT/name
            self.assertIn(path, paths)
            with self.subTest(missing=name), patch.object(gate.common.BUILDER, 'inputs', return_value=[item for item in paths if item != path]), self.assertRaises(ValueError):
                gate.source_identity()


if __name__ == '__main__':
    unittest.main()
