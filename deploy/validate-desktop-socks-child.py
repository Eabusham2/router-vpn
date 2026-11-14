#!/usr/bin/env python3
"""Compile and exercise exact generated desktop SOCKS child/Box owners on Linux.

This is a component source gate. It cannot establish installed TUN, WFP/PF,
Windows/Darwin process admission, or public application availability.
"""
from pathlib import Path
from collections import Counter
import argparse
import hashlib
import importlib.util
import json
import os
import platform
import re
import shutil
import stat
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
sys.dont_write_bytecode = True
SUITE = "desktop-socks-child"
SOURCE_PROJECTION_SCRIPT = "deploy/test_desktop_socks_child_sources.py"
SOURCE_PROJECTION_CLASS = "DesktopSOCKSChildProjection"
PACKAGE = {"cmd": "github.com/sagernet/sing-box/cmd/sing-box",
           "box": "github.com/sagernet/sing-box"}
TARGET = {"cmd": "./cmd/sing-box", "box": "."}
HEX40 = re.compile(r"[0-9a-f]{40}")
INVENTORY = {'child': {'command_roots': ['TestRouterVPNDesktopSOCKSCommandExactSourceReplay',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture',
                             'TestRouterVPNDesktopSOCKSConstructionKeepsLocalRegistry',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeOriginalGeneration',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeLateFactoryJoin',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeEnteredProofJoin',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRetainsFailedJoin',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeActivityJoin',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeMeasurementExcludesMTU',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsCandidateAuthority',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandKeepsCapturedArguments',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRequiresOriginalParent',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandDarwinOriginalManifest'],
           'command_cases': ['TestRouterVPNDesktopSOCKSCommandExactSourceReplay',
                             'TestRouterVPNDesktopSOCKSCommandExactSourceReplay/linux',
                             'TestRouterVPNDesktopSOCKSCommandExactSourceReplay/windows',
                             'TestRouterVPNDesktopSOCKSCommandExactSourceReplay/darwin',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/missing',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/ordinary',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/raw-source',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/unknown',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/session',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/source',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/config',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/target',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/restore',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/graph',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/graph-rehash',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/cancelled',
                             'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/nil-caller',
                             'TestRouterVPNDesktopSOCKSConstructionKeepsLocalRegistry',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement/source',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement/policy',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement/context',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement/capture',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement/registry',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement/config',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement/receipt',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement/cancelled',
                             'TestRouterVPNDesktopSOCKSConstructionRejectsReplacement/nil-caller',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeOriginalGeneration',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeLateFactoryJoin',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeEnteredProofJoin',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRetainsFailedJoin',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity/session',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity/source',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity/config',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity/network',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity/engine',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity/host',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity/source-object',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity/registry',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeActivityJoin',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeMeasurementExcludesMTU',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsCandidateAuthority',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsCandidateAuthority/node-chain-candidate-request.json',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsCandidateAuthority/node-chain-candidate-source.json',
                             'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsCandidateAuthority/node-chain-candidate-live.json',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandKeepsCapturedArguments',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandKeepsCapturedArguments/linux',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandKeepsCapturedArguments/windows',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandKeepsCapturedArguments/darwin',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/physical-transfer-sha256',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/physical-mtu',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/journal-parent-handle',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/journal-parent-image',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/journal-pipe',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/journal-capture-sha256',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/linux-parent-channel',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/linux-parent-directory',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/linux-parent-capture',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/family-',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRefusesMixedDarwinFlags/family-foreign',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandRequiresOriginalParent',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandDarwinOriginalManifest',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandDarwinOriginalManifest/configured',
                             'TestRouterVPNDesktopNodeChainSOCKSCommandDarwinOriginalManifest/restored'],
           'box_roots': ['TestRouterVPNDesktopNodeChainSOCKSPhysicalActualBox',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalExactTargets'],
           'box_cases': ['TestRouterVPNDesktopNodeChainSOCKSPhysicalActualBox',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/middle-user',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/middle-password',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/middle-detour',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/final-detour',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/dns',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/physical-source',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/mtu',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/interface',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalExactTargets',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalExactTargets/linux',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalExactTargets/windows',
                         'TestRouterVPNDesktopNodeChainSOCKSPhysicalExactTargets/darwin'],
           'controls': [{'name': 'original-factory-join',
                         'path': 'mobile/desktop/node_chain_socks_runtime.go.tmpl',
                         'before': 'select{case<-state.done:case<-ctx.Done():return ctx.Err()}',
                         'after': '// causal omission of original entered startup join',
                         'root': 'TestRouterVPNDesktopNodeChainSOCKSRuntimeLateFactoryJoin',
                         'cases': ['TestRouterVPNDesktopNodeChainSOCKSRuntimeLateFactoryJoin'],
                         'witness': 'original entered factory was abandoned',
                         'package': 'cmd',
                         'run': '^TestRouterVPNDesktopNodeChainSOCKSRuntimeLateFactoryJoin$'},
                        {'name': 'original-proof-join',
                         'path': 'mobile/desktop/node_chain_socks_runtime.go.tmpl',
                         'before': 'select{case<-state.done:case<-ctx.Done():return ctx.Err()}',
                         'after': '// causal omission of original entered startup join',
                         'root': 'TestRouterVPNDesktopNodeChainSOCKSRuntimeEnteredProofJoin',
                         'cases': ['TestRouterVPNDesktopNodeChainSOCKSRuntimeEnteredProofJoin'],
                         'witness': 'original entered proof was abandoned',
                         'package': 'cmd',
                         'run': '^TestRouterVPNDesktopNodeChainSOCKSRuntimeEnteredProofJoin$'},
                        {'name': 'failed-proof-retention',
                         'path': 'mobile/desktop/node_chain_socks_runtime.go.tmpl',
                         'before': 'if state.proof!=nil{if '
                                   'err:=state.proof.CloseContext(ctx);err!=nil{return err}}',
                         'after': 'if state.proof!=nil{_ = state.proof.CloseContext(ctx)}',
                         'root': 'TestRouterVPNDesktopNodeChainSOCKSRuntimeRetainsFailedJoin',
                         'cases': ['TestRouterVPNDesktopNodeChainSOCKSRuntimeRetainsFailedJoin'],
                         'witness': 'failed original proof join was erased',
                         'package': 'cmd',
                         'run': '^TestRouterVPNDesktopNodeChainSOCKSRuntimeRetainsFailedJoin$'},
                        {'name': 'original-caller-local-registry',
                         'path': 'mobile/desktop/node_chain_socks_runtime.go.tmpl',
                         'before': 'if err:=owner.construction.current(ctx);err!=nil{return err}',
                         'after': '// causal omission of original private constructor registry '
                                  'observation',
                         'root': 'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity',
                         'cases': ['TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity',
                                   'TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity/registry'],
                         'witness': 'foreign typed child owner remained current',
                         'package': 'cmd',
                         'run': '^TestRouterVPNDesktopNodeChainSOCKSRuntimeRejectsForeignIdentity$/^registry$'},
                        {'name': 'original-measurement-hold',
                         'path': 'mobile/desktop/node_chain_socks_mtu.go.tmpl',
                         'before': 'if '
                                   'owner==nil||owner.measurementHold.Load()||owner.current(ctx)!=nil{return '
                                   'nil,routerVPNExternalFailure}',
                         'after': 'if owner==nil||owner.current(ctx)!=nil{return '
                                  'nil,routerVPNExternalFailure}',
                         'root': 'TestRouterVPNDesktopNodeChainSOCKSRuntimeMeasurementExcludesMTU',
                         'cases': ['TestRouterVPNDesktopNodeChainSOCKSRuntimeMeasurementExcludesMTU'],
                         'witness': 'MTU acquired while original measurement owned the graph',
                         'package': 'cmd',
                         'additional_replacements': [{'before': 'if '
                                                                'err:=owner.current(ctx);err!=nil||owner.measurementHold.Load(){activity.release();return '
                                                                'nil,errors.Join(err,routerVPNExternalFailure)}',
                                                      'after': 'if '
                                                               'err:=owner.current(ctx);err!=nil{activity.release();return '
                                                               'nil,errors.Join(err,routerVPNExternalFailure)}'}],
                         'run': '^TestRouterVPNDesktopNodeChainSOCKSRuntimeMeasurementExcludesMTU$'},
                        {'name': 'original-physical-source',
                         'path': 'mobile/desktop/node_chain_socks_construction.go.tmpl',
                         'before': ' || meta.SourceSHA256 != source',
                         'after': '',
                         'root': 'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture',
                         'cases': ['TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture',
                                   'TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture/source'],
                         'witness': 'typed child adopted foreign source, caller or staged graph',
                         'package': 'cmd',
                         'run': '^TestRouterVPNDesktopSOCKSCommandRefusesChangedCapture$/^source$'},
                        {'name': 'typed-whole-box-before-acquisition',
                         'path': 'mobile/chain/socks_box.go.tmpl',
                         'before': 'if routerVPNNodeChainOptionsDigest(ctx, options) != original.digest '
                                   '{',
                         'after': 'if false { // causal omission of original whole Box options',
                         'root': 'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift',
                         'cases': ['TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift',
                                   'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/middle-user',
                                   'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/middle-password',
                                   'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/middle-detour',
                                   'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/final-detour',
                                   'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/dns',
                                   'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/physical-source',
                                   'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/mtu',
                                   'TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift/interface'],
                         'witness': 'changed typed graph reached original native construction',
                         'package': 'box',
                         'run': '^TestRouterVPNDesktopNodeChainSOCKSPhysicalRejectsGraphDrift$'}],
           'source_files': ['deploy/prepare-desktop-external.py',
                            'deploy/test_desktop_socks_child_sources.py',
                            'deploy/test_node_heartbeat_context.py',
                            'internal/mobilemultihop/desktop_node_chain_socks_ready.go',
                            'internal/mobilemultihop/desktop_node_chain_socks_ready_test.go',
                            'mobile/desktop/mtu_node.go.tmpl',
                            'mobile/desktop/node_chain_socks_box_darwin.go.tmpl',
                            'mobile/desktop/node_chain_socks_box_linux.go.tmpl',
                            'mobile/desktop/node_chain_socks_box_physical.go.tmpl',
                            'mobile/desktop/node_chain_socks_box_physical_test.go.tmpl',
                            'mobile/desktop/node_chain_socks_command.go.tmpl',
                            'mobile/desktop/node_chain_socks_command_test.go.tmpl',
                            'mobile/desktop/node_chain_socks_construction.go.tmpl',
                            'mobile/desktop/node_chain_socks_construction_test.go.tmpl',
                            'mobile/desktop/node_chain_socks_control_darwin.go.tmpl',
                            'mobile/desktop/node_chain_socks_control_linux.go.tmpl',
                            'mobile/desktop/node_chain_socks_control_other.go.tmpl',
                            'mobile/desktop/node_chain_socks_measurement.go.tmpl',
                            'mobile/desktop/node_chain_socks_mtu.go.tmpl',
                            'mobile/desktop/node_chain_socks_physical_darwin.go.tmpl',
                            'mobile/desktop/node_chain_socks_physical_linux.go.tmpl',
                            'mobile/desktop/node_chain_socks_physical_other.go.tmpl',
                            'mobile/desktop/node_chain_socks_physical_windows.go.tmpl',
                            'mobile/desktop/node_chain_socks_retirement_darwin.go.tmpl',
                            'mobile/desktop/node_chain_socks_run_darwin.go.tmpl',
                            'mobile/desktop/node_chain_socks_run_nonlinux.go.tmpl',
                            'mobile/desktop/node_chain_socks_runtime.go.tmpl',
                            'mobile/desktop/node_chain_socks_runtime_test.go.tmpl',
                            'mobile/desktop/node_command_run_linux.go.tmpl',
                            'mobile/desktop/node_physical_darwin.go.tmpl'],
           'limits': {'compile_seconds': 600, 'case_seconds': 90, 'process_seconds': 100},
           'scope': 'actual generated child/Box source and component ownership; no native device '
                    'acceptance',
           'dependencies': ['pending Windows staged source retirement11; mtu_node '
                            'base544f47551d84a0daf6b0aa5644641067cb7f5424',
                            'pending macosprocess NodeChainSOCKSFamily and '
                            'NodeChainSOCKSTransferSHA2563'],
           'regressions': ['original node chain runtime/MTU command cases',
                           'original selected-prefix runtime/physical cases',
                           'actual heartbeat13+5 original causal controls']},
 'regressions': [{'name': 'original-ordered-runtime',
                  'package': 'cmd',
                  'selector': '^TestRouterVPNDesktopNodeChain(MTUProofHandoff|MTURejectsUnjoinedCanceledAndForeignReaders|HeartbeatRejectsCurrentReaderSubstitution|ActualLoopRequiresCurrentProofAndReader)$',
                  'cases': ['TestRouterVPNDesktopNodeChainMTUProofHandoff',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders/join',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders/cancel',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders/returned-reader',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders/network',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders/session',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders/source',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders/config',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders/proof-failure',
                            'TestRouterVPNDesktopNodeChainMTURejectsUnjoinedCanceledAndForeignReaders/ceiling',
                            'TestRouterVPNDesktopNodeChainHeartbeatRejectsCurrentReaderSubstitution',
                            'TestRouterVPNDesktopNodeChainActualLoopRequiresCurrentProofAndReader',
                            'TestRouterVPNDesktopNodeChainActualLoopRequiresCurrentProofAndReader/exact',
                            'TestRouterVPNDesktopNodeChainActualLoopRequiresCurrentProofAndReader/cancel',
                            'TestRouterVPNDesktopNodeChainActualLoopRequiresCurrentProofAndReader/reader-substitution']},
                 {'name': 'original-execution-runtime',
                  'package': 'cmd',
                  'selector': '^TestRouterVPNDesktopNodeChainExecution(Runtime|MTU)',
                  'cases': ['TestRouterVPNDesktopNodeChainExecutionRuntimeKeepsActualProjection',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeRetainsFailedCleanup',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeRejectsReplacedOwners',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeJoinsLateConstructor',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup',
                            'TestRouterVPNDesktopNodeChainExecutionMTUCloseJoinsActivity',
                            'TestRouterVPNDesktopNodeChainExecutionMTUHeartbeatKeepsDistinctGenerations',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeRetainsFailedCleanup/remote-join',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeRetainsFailedCleanup/gate-retire',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeRejectsReplacedOwners/foreign-projection',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeRejectsReplacedOwners/preparation-identity',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeRejectsReplacedOwners/host',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeRejectsReplacedOwners/readback',
                            'TestRouterVPNDesktopNodeChainExecutionRuntimeRejectsReplacedOwners/late-readback',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup/success',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup/unchanged-rollback',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup/cancel-before-native',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup/cancel-after-native',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup/proof-failure',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup/pause-failure',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup/unentered',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup/missing-finish',
                            'TestRouterVPNDesktopNodeChainExecutionMTUDispatchKeepsCleanup/foreign-owner',
                            'TestRouterVPNDesktopNodeChainExecutionMTUHeartbeatKeepsDistinctGenerations/command-counter',
                            'TestRouterVPNDesktopNodeChainExecutionMTUHeartbeatKeepsDistinctGenerations/native-reader',
                            'TestRouterVPNDesktopNodeChainExecutionMTUHeartbeatKeepsDistinctGenerations/native-nonce',
                            'TestRouterVPNDesktopNodeChainExecutionMTUHeartbeatKeepsDistinctGenerations/controller',
                            'TestRouterVPNDesktopNodeChainExecutionMTUHeartbeatKeepsDistinctGenerations/inbound'],
                  'attribute': 'ORDERED_EXECUTION_COMMAND_VERDICTS'},
                 {'name': 'original-ordered-physical',
                  'package': 'box',
                  'selector': '^TestRouterVPNDesktopNodeChainPhysical',
                  'cases': ['TestRouterVPNDesktopNodeChainPhysicalCapturesActualBox',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsSubstitutedBox',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsSubstitutedBox/middle-key',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsSubstitutedBox/dns',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsSubstitutedBox/physical-source',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsSubstitutedBox/mtu',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsSubstitutedBox/interface',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/awg2-fast/wg',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/awg2-fast/wg/different-original-mode',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/awg2-strong/wg',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/awg2-strong/wg/different-original-mode',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/wg/awg2-fast',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/wg/awg2-fast/different-original-mode',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/wg/awg2-strong',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/wg/awg2-strong/different-original-mode',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/wg/awg2-fast/wg',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/wg/awg2-fast/wg/different-original-mode',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/wg/awg2-strong/wg',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/wg/awg2-strong/wg/different-original-mode',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/awg2-fast/awg2-strong/wg',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/awg2-fast/awg2-strong/wg/different-original-mode',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/awg2-strong/wg/awg2-fast',
                            'TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox/awg2-strong/wg/awg2-fast/different-original-mode',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsChangedModeProof',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsChangedModeProof/unsupported-prefix',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsChangedModeProof/mode-alias',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsChangedModeProof/final-as-prefix',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsChangedModeProof/wrong-original-mode',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsChangedModeProof/wrong-final',
                            'TestRouterVPNDesktopNodeChainPhysicalRejectsChangedModeProof/wrong-position',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaCapturesActualBox',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaCapturesActualBox/wg',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaCapturesActualBox/awg2-fast',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaCapturesActualBox/awg2-strong',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaKeepsTypedScope',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaKeepsTypedScope/linux',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaKeepsTypedScope/windows',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaKeepsTypedScope/darwin',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaKeepsTypedScope/layer',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaKeepsTypedScope/mode',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaKeepsTypedScope/position',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaKeepsTypedScope/target',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaRejectsSubstitutedBox',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaRejectsSubstitutedBox/password',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaRejectsSubstitutedBox/sni',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaRejectsSubstitutedBox/mask',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaRejectsSubstitutedBox/detour',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaRejectsSubstitutedBox/dns',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaRejectsSubstitutedBox/mtu',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaRejectsSubstitutedBox/physical-source',
                            'TestRouterVPNDesktopNodeChainPhysicalHysteriaRejectsSubstitutedBox/interface'],
                  'attribute': 'ORDERED_PHYSICAL_VERDICTS'},
                 {'name': 'original-prefix-runtime',
                  'package': 'cmd',
                  'selector': '^TestRouterVPNDesktopCandidatePrefixRuntime',
                  'cases': ['TestRouterVPNDesktopCandidatePrefixRuntimeClosedFifty',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeHeartbeatFailureStages',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeHeartbeatFailureStages/owner-state',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeHeartbeatFailureStages/owner-current',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeHeartbeatFailureStages/mtu-binding',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeHeartbeatFailureStages/ready-validation',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeHeartbeatFailureStages/publication',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeHeartbeatFailureStages/redaction',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/reader',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/config',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/source-inode',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/native-mtu',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/capture',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/position',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/path',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/application',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/dns',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/stale-ready',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/stale-pulse',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/wrong-pulse',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/missing-pulse',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRejectsSubstitution/generation',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeRetainsPartialJoin',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeJoinsWorkerBeforeGate',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeJoinsWorkerBeforeGate/cancel',
                            'TestRouterVPNDesktopCandidatePrefixRuntimeJoinsWorkerBeforeGate/retire'],
                  'attribute': 'CANDIDATE_PREFIX_RUNTIME_VERDICTS'},
                 {'name': 'original-prefix-physical',
                  'package': 'box',
                  'selector': '^TestRouterVPNDesktopCandidatePrefixPhysical',
                  'cases': ['TestRouterVPNDesktopCandidatePrefixPhysicalCapturesClosedBox',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalRejectsChangedBox',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalRejectsChangedBox/prefix-key',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalRejectsChangedBox/dns',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalRejectsChangedBox/physical-source',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalRejectsChangedBox/mtu',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalRejectsChangedBox/application-gate',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalKeepsTypedTarget',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalKeepsTypedTarget/linux',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalKeepsTypedTarget/windows',
                            'TestRouterVPNDesktopCandidatePrefixPhysicalKeepsTypedTarget/darwin'],
                  'attribute': 'CANDIDATE_PREFIX_PHYSICAL_VERDICTS'}],
 'projections': {'mobile/desktop/mtu_node.go.tmpl': 'cmd/sing-box/routervpn_mtu_node.go',
                 'mobile/desktop/node_chain_socks_box_darwin.go.tmpl': 'routervpn_desktop_node_chain_socks_box_darwin.go',
                 'mobile/desktop/node_chain_socks_box_linux.go.tmpl': 'routervpn_desktop_node_chain_socks_box_linux.go',
                 'mobile/desktop/node_chain_socks_box_physical.go.tmpl': 'routervpn_desktop_node_chain_socks_box_physical.go',
                 'mobile/desktop/node_chain_socks_box_physical_test.go.tmpl': 'routervpn_desktop_node_chain_socks_box_physical_test.go',
                 'mobile/desktop/node_chain_socks_command.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_command.go',
                 'mobile/desktop/node_chain_socks_command_test.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_command_test.go',
                 'mobile/desktop/node_chain_socks_construction.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_construction.go',
                 'mobile/desktop/node_chain_socks_construction_test.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_construction_test.go',
                 'mobile/desktop/node_chain_socks_control_darwin.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_control_darwin.go',
                 'mobile/desktop/node_chain_socks_control_linux.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_control_linux.go',
                 'mobile/desktop/node_chain_socks_control_other.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_control_other.go',
                 'mobile/desktop/node_chain_socks_measurement.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_measurement.go',
                 'mobile/desktop/node_chain_socks_mtu.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_mtu.go',
                 'mobile/desktop/node_chain_socks_physical_darwin.go.tmpl': 'routervpn/desktoppt/node_chain_socks_physical_darwin.go',
                 'mobile/desktop/node_chain_socks_physical_linux.go.tmpl': 'routervpn/desktoppt/node_chain_socks_physical_linux.go',
                 'mobile/desktop/node_chain_socks_physical_other.go.tmpl': 'routervpn/desktoppt/node_chain_socks_physical_other.go',
                 'mobile/desktop/node_chain_socks_physical_windows.go.tmpl': 'routervpn/desktoppt/node_chain_socks_physical_windows.go',
                 'mobile/desktop/node_chain_socks_retirement_darwin.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_retirement_darwin.go',
                 'mobile/desktop/node_chain_socks_run_darwin.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_run_darwin.go',
                 'mobile/desktop/node_chain_socks_run_nonlinux.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_run_nonlinux.go',
                 'mobile/desktop/node_chain_socks_runtime.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_runtime.go',
                 'mobile/desktop/node_chain_socks_runtime_test.go.tmpl': 'cmd/sing-box/routervpn_node_chain_socks_runtime_test.go',
                 'mobile/desktop/node_command_run_linux.go.tmpl': 'cmd/sing-box/routervpn_node_command_run_linux.go',
                 'mobile/desktop/node_physical_darwin.go.tmpl': 'routervpn/desktoppt/node_physical_darwin.go',
                 'mobile/chain/socks_box.go.tmpl': 'routervpn_node_chain_socks.go'}}
CHILD = INVENTORY["child"]
REGRESSIONS = INVENTORY["regressions"]
PROJECTIONS = INVENTORY["projections"]
CONTROLS = CHILD["controls"]
HEARTBEAT_ROOTS = ("TestActualHeartbeatContext", "TestActualOpenVPNHeartbeatFreshness")
HEARTBEAT_CASES = (
    HEARTBEAT_ROOTS[0], *(HEARTBEAT_ROOTS[0]+"/"+name for name in (
        "live", "shorter-parent", "parent-stop", "graph-stop", "unowned-graph-stop", "expired-read")),
    HEARTBEAT_ROOTS[1], *(HEARTBEAT_ROOTS[1]+"/"+name for name in (
        "native-held", "observer-held", "stale-native", "tuple-change", "parent-stop", "graph-stop", "query-expiry")),
)
HEARTBEAT_CONTROLS = (
    "Original no-deadline caller rejected by actual native receipt admission",
    "Actual enclosing loop rejected terminal periodic expiry",
    "Actual enclosing loop rejected stale observation publication",
    "Actual enclosing loop rejected missing post-query observation",
    "Actual enclosing loop rejected extended original freshness",
)
PROJECTION_TESTS = tuple("test_"+name for name in (
    "actual_original_preparer_copies_every_native_adapter",
    "actual_preparer_refuses_changed_platform_package",
    "command_enumeration_retains_separate_packages",
    "original_heartbeat_extracts_complete_shipping_body",
))
FORBIDDEN = ("WARNING: DATA RACE", "panic:", "fatal error:", "[build failed]",
             "signal:", "test timed out", "runtime: out of memory")


# Additive fifty-response component coverage; every original child/Box case
# and causal control remains mandatory with unchanged execution bounds.
_fifty_roots = ["TestRouterVPNDesktopSOCKSFiftyOperationSchema", "TestRouterVPNDesktopSOCKSFiftyBorrowedOperationHTTP"]
_fifty_cases = [_fifty_roots[0]] + [_fifty_roots[0]+"/"+x for x in ("old-operation", "old-node", "old-position", "old-bytes", "schema", "operation", "node", "negative-position", "foreign-position", "throughput-bytes")] + [_fifty_roots[1], _fifty_roots[1]+"/complete", _fifty_roots[1]+"/failed-fiftieth", _fifty_roots[1]+"/failed-first-close"]
INVENTORY["child"]["command_roots"].extend(_fifty_roots)
INVENTORY["child"]["command_cases"].extend(_fifty_cases)
INVENTORY["child"]["source_files"].extend(["mobile/desktop/node_chain_socks_measurement_test.go.tmpl", "internal/hopmeasure/ordered_latency.go", "internal/hopmeasure/measure.go"])
INVENTORY["projections"]["mobile/desktop/node_chain_socks_measurement_test.go.tmpl"] = "cmd/sing-box/routervpn_node_chain_socks_measurement_test.go"

def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    sys.modules[name] = result
    spec.loader.exec_module(result)
    return result


COMMON = module("desktop_child_trusted_common", ROOT/"deploy/validate-linux-hy2-source.py")
CLOCK = module("desktop_child_trusted_process", ROOT/"deploy/test_focused_multihop_clocks.py")
git = COMMON.git
execute = CLOCK.execute
image_identity = COMMON.image_identity


def selection(source, source_sha, output):
    if not HEX40.fullmatch(source_sha):
        raise ValueError("Exact child candidate commit is required")
    path = output.parent/"selection.json"
    if path.is_symlink() or not path.is_file():
        raise ValueError("Original child selection is missing")
    raw = path.read_bytes()
    receipt = json.loads(raw)
    if receipt.get("schema") != 1 or receipt.get("suite") != SUITE or receipt.get("source_sha") != source_sha or receipt.get("validation_scope") != "read-only-source-candidate":
        raise ValueError("Child selection changed original suite or source")
    for key in ("validator_sha", "validator_tree", "base_sha", "base_tree", "source_sha", "source_tree"):
        if not isinstance(receipt.get(key), str) or not HEX40.fullmatch(receipt[key]):
            raise ValueError("Child selection lost original Git identity")
    for tree, sha, tree_sha in ((source, source_sha, receipt["source_tree"]),
                                (ROOT, receipt["validator_sha"], receipt["validator_tree"])):
        if git(tree, "rev-parse", "HEAD") != sha or git(tree, "rev-parse", "HEAD^{tree}") != tree_sha or git(tree, "status", "--porcelain", "--untracked-files=all", "--ignored=matching"):
            raise ValueError("Child source or trusted validator is not the exact pristine checkout")
    return receipt, raw


def original_test_parents(cases):
    # The physical fixture passes strings.Join(modes, "/") to one t.Run.
    # These eight mode paths are siblings; only different-original-mode is
    # nested. Bind that finite source hierarchy instead of inventing parents
    # from a slash that belongs to a table entry's name.
    root = "TestRouterVPNDesktopNodeChainPhysicalAWGModesAndOriginalBox"
    mode_cases = (
        "awg2-fast/wg", "awg2-strong/wg", "wg/awg2-fast", "wg/awg2-strong",
        "wg/awg2-fast/wg", "wg/awg2-strong/wg",
        "awg2-fast/awg2-strong/wg", "awg2-strong/wg/awg2-fast",
    )
    expected = set(cases)
    parents = {}
    for name in expected:
        ancestors = [other for other in expected if name.startswith(other+"/")]
        parents[name] = max(ancestors, key=len) if ancestors else None
    for modes in mode_cases:
        name = root+"/"+modes
        if name in expected:
            if root not in expected:
                raise ValueError("Physical mode case lost its original root")
            parents[name] = root
    return parents


def require_verdict(text, status, package, cases, *, control=None):
    expected = set(cases)
    if not expected or len(expected) != len(cases):
        raise ValueError("Child required inventory is empty or duplicated")
    failures = expected if control is not None else set()
    parents = original_test_parents(cases)
    leaves = expected-set(parents.values())
    wanted_status = 1 if control is not None else 0
    if status != wanted_status or any(word in text for word in FORBIDDEN):
        raise ValueError("Child verdict had an unrelated process, build, race or timeout failure")
    started, ended, outputs = set(), set(), {}
    package_started = terminal = False
    for line in text.splitlines():
        if not line.strip():
            continue
        try:
            event = json.loads(line)
        except ValueError as error:
            raise ValueError("Child verdict contains unframed output") from error
        if not isinstance(event, dict):
            raise ValueError("Child verdict contains a non-event")
        action, test = event.get("Action"), event.get("Test")
        if action == "build-output":
            if package_started or started or terminal or event.get("ImportPath") != package+".test" or not isinstance(event.get("Output"), str):
                raise ValueError("Child verdict has foreign or late build output")
            continue
        if event.get("Package") != package or terminal:
            raise ValueError("Child verdict has foreign or late package events")
        if test:
            if not isinstance(test, str) or test not in expected or not package_started:
                raise ValueError("Child verdict used a foreign test or lost its package")
            if action == "run":
                if test in started:
                    raise ValueError("Child verdict repeated an original test")
                # The declared direct parent must still be active; its own
                # start already required its original ancestor to be active.
                parent = parents[test]
                if parent is not None and (parent not in started or parent in ended):
                    raise ValueError("Child verdict lost an active original ancestor")
                started.add(test)
            elif action == "output":
                if test not in started or test in ended or not isinstance(event.get("Output"), str):
                    raise ValueError("Child output lost its active original test")
                outputs[test] = outputs.get(test, "") + event["Output"]
            elif action in ("pass", "fail"):
                children = {name for name, parent in parents.items() if parent == test}
                if test not in started or test in ended or not children.issubset(ended) or action != ("fail" if test in failures else "pass"):
                    raise ValueError("Child verdict is wrong, repeated or precedes its children")
                ended.add(test)
            else:
                raise ValueError("Child verdict has an unknown or skipped test action")
        elif action == "start":
            if package_started or started:
                raise ValueError("Child verdict repeated its package start")
            package_started = True
        elif action == "output":
            if not package_started or not isinstance(event.get("Output"), str):
                raise ValueError("Child package output lost its original start")
            if control is not None and control["witness"] in event["Output"]:
                raise ValueError("Child control witness escaped its original leaf")
        elif action in ("pass", "fail"):
            if not package_started or started != expected or ended != expected or action != ("fail" if control is not None else "pass"):
                raise ValueError("Child package ended without its complete original verdict")
            terminal = True
        else:
            raise ValueError("Child verdict has an unknown package action")
    if not terminal or started != expected or ended != expected:
        raise ValueError("Child verdict omitted required original cases")
    if control is not None:
        for name in expected:
            if outputs.get(name, "").count(control["witness"]) != (1 if name in leaves else 0):
                raise ValueError("Child control lost its exact original leaf witness")


def require_projection(text, status):
    lines = [line.strip() for line in text.replace("\r\n", "\n").replace("\r", "\n").splitlines() if line.strip()]
    names = []
    for line in lines:
        match = re.fullmatch(r"(test_[A-Za-z0-9_]+) \((?:__main__\.)?"+re.escape(SOURCE_PROJECTION_CLASS)+r"\.[A-Za-z0-9_]+\) \.\.\. ok", line)
        if match:
            names.append(match[1])
    summaries = [line for line in lines if re.fullmatch(r"Ran 4 tests in [0-9]+(?:\.[0-9]+)?s", line)]
    if status or len(lines) != len(PROJECTION_TESTS)+3 or lines[len(PROJECTION_TESTS)] != "-"*70 or Counter(names) != Counter(PROJECTION_TESTS) or len(summaries) != 1 or lines[-1] != "OK" or lines.count("OK") != 1 or any(word in text for word in ("... FAIL", "... ERROR", "... skipped", "Traceback")):
        raise ValueError("Actual desktop child projection tests did not all pass")


def require_heartbeat(text, status):
    runs = re.findall(r"(?m)^=== RUN\s+(\S+)\s*$", text)
    passed = re.findall(r"(?m)^\s*--- PASS: (\S+) \([^\n]*\)$", text)
    markers = [line.strip() for line in text.splitlines() if line.strip() in HEARTBEAT_CONTROLS]
    if status or Counter(runs) != Counter(HEARTBEAT_CASES) or Counter(passed) != Counter(HEARTBEAT_CASES) or tuple(markers) != HEARTBEAT_CONTROLS or any(word in text for word in (*FORBIDDEN, "--- FAIL:", "--- SKIP:")):
        raise ValueError("Original heartbeat lost its 13 leaves, two roots or five causal controls")


def mutate(raw, control):
    changed = raw
    for part in (control, *control.get("additional_replacements", ())):
        if not part["before"] or changed.count(part["before"]) != 1:
            raise ValueError("Original child control seam changed: "+control["name"])
        changed = changed.replace(part["before"], part["after"], 1)
    if changed == raw:
        raise ValueError("Child causal overlay did not change its original source")
    return changed


def bind_projection(source, core, relative, projected):
    original, actual = source/relative, core/projected
    if original.is_symlink() or actual.is_symlink() or not original.is_file() or not actual.is_file() or original.read_bytes() != actual.read_bytes():
        raise ValueError("Child lost exact native projection: "+projected)
    return hashlib.sha256(actual.read_bytes()).hexdigest()


def native_tree(root):
    result = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            raise ValueError("Native source contains a linked entry: "+relative.as_posix())
        if path.is_file():
            result[relative.as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    if not result:
        raise ValueError("Native source tree is empty")
    return result


def checked_sources(gate, source, core, xray):
    _, records = gate.NODE.checked_sources(core)
    records = dict(records)
    for relative, projected in PROJECTIONS.items():
        records["child/"+projected] = bind_projection(source, core, relative, projected)
    originals, derived = gate.NODE.PREP.daemon_capture_sources(core)
    if originals != derived:
        raise ValueError("Child lost original daemon capture hooks")
    for name, relative in gate.NODE.PREP.DAEMON_CAPTURE_TEMPLATES.items():
        records["child-daemon/"+relative] = bind_projection(source, core, "mobile/chain_execution/"+name, relative)
    for regression in REGRESSIONS:
        attribute = regression.get("attribute")
        if attribute and tuple(getattr(gate.NODE, attribute)) != tuple(regression["cases"]):
            raise ValueError("Child regression lost original required inventory: "+regression["name"])
    return {"checked": records, "core": native_tree(core), "xray": native_tree(xray)}


def prepare_worker(source, core, xray):
    if platform.system() != "Linux":
        raise ValueError("Original child source preparation requires Linux")
    gate = COMMON.load_gate(source)
    COMMON.prepare(gate, core, xray, dict(os.environ))



class OwnedWorkspace:
    """Retain the original private build tree whenever child join is unproved."""
    def __init__(self, parent):
        self.path = Path(tempfile.mkdtemp(prefix="routervpn-focused-desktop-child-", dir=parent))
        observed = self.path.lstat()
        self.identity = (observed.st_dev, observed.st_ino)
        self.active = set()
        self.unproved = False
        self.removed = False

    def begin_command(self):
        if self.removed or self.unproved or self.active:
            raise ValueError("Original child workspace has pending or unproved ownership")
        token = object()
        self.active.add(token)
        return token

    def complete_command(self, token, joined):
        if token not in self.active:
            raise ValueError("Child completion does not own the original command")
        self.active.remove(token)
        if joined is not True:
            self.unproved = True

    def execute(self, command, cwd, env, log, bound):
        token = self.begin_command()
        result = execute(command, cwd, env, log, bound)
        self.complete_command(token, result[2])
        return result

    def cleanup(self):
        result = dict(path=str(self.path), original_device=self.identity[0],
                      original_inode=self.identity[1], removed=False)
        if self.removed:
            return dict(result, removed=True)
        if self.unproved or self.active:
            return dict(result, retained_reason="original-process-join-unproved")
        try:
            observed = self.path.lstat()
        except FileNotFoundError:
            return dict(result, retained_reason="original-directory-missing")
        except OSError as error:
            return dict(result, retained_reason="original-directory-unobservable",
                        cleanup_error=type(error).__name__)
        if self.path.is_symlink() or not stat.S_ISDIR(observed.st_mode) or (observed.st_dev, observed.st_ino) != self.identity:
            return dict(result, retained_reason="original-directory-replaced")
        # shutil's FD-safe traversal does not follow links into another tree.
        # Linux is the sole supported target of this bounded validator.
        if not shutil.rmtree.avoids_symlink_attacks:
            return dict(result, retained_reason="owned-directory-removal-unavailable")
        try:
            shutil.rmtree(self.path)
        except OSError as error:
            return dict(result, retained_reason="original-directory-cleanup-failed",
                        cleanup_error=type(error).__name__)
        self.removed = True
        return dict(result, removed=True)


def child_command_suites():
    """Keep the original SOCKS command inventory in its original invocation."""
    return [dict(name="typed-child", package="cmd",
                 selector="^("+"|".join(CHILD["command_roots"])+")$",
                 cases=CHILD["command_cases"], process_seconds=100)]


def validate(source, source_sha, output, go="go"):
    if platform.system() != "Linux" or platform.machine() not in ("x86_64", "aarch64", "arm64"):
        raise ValueError("Native Linux child validation host is required")
    source, output = Path(source).resolve(strict=True), Path(output).absolute()
    if output.is_symlink() or output.exists() or source == output or source in output.parents:
        raise ValueError("Child output must be fresh and outside its candidate")
    metadata, original_selection = selection(source, source_sha, output)
    original_source = CLOCK.snapshot(source)
    output.mkdir(mode=0o700)
    env = dict(os.environ, CGO_ENABLED="1", GOTOOLCHAIN="local", GOWORK="off", GOFLAGS="",
               GOMAXPROCS="2", GOGC="100", GOMEMLIMIT="2GiB", PYTHONDONTWRITEBYTECODE="1")
    if os.path.sep in go:
        go = str(Path(go).resolve(strict=True))
        env["PATH"] = str(Path(go).parent)+os.pathsep+env.get("PATH", "")
    receipt = dict(schema=1, suite=SUITE, selection=metadata,
        scope="generated-child-and-box-component-source-only",
        installed_native_accepted=False, windows_native_accepted=False,
        darwin_native_accepted=False, public_native_admission=False, phases=[])
    workspace = None
    def save():
        (output/"progress.json").write_text(json.dumps(receipt, indent=2)+"\n")
    def run(name, command, cwd, captured, timeout):
        command = list(map(str, command))
        log = output/(name+".log")
        started = time.monotonic()
        invoke = workspace.execute if workspace is not None else execute
        try:
            status, timed_out, joined = invoke(command, cwd, captured, log, timeout)
        except Exception as error:
            receipt["phases"].append(dict(name=name, command=command, timeout=timeout,
                seconds=time.monotonic()-started, error=type(error).__name__))
            save()
            raise
        raw = log.read_bytes()
        receipt["phases"].append(dict(name=name, command=command, timeout=timeout,
            seconds=time.monotonic()-started, status=status, timed_out=timed_out,
            process_group_joined=joined, output_sha256=hashlib.sha256(raw).hexdigest()))
        save()
        if timed_out or not joined:
            raise RuntimeError("Original child validation group timed out or did not join")
        return status, raw.decode("utf-8", errors="strict")
    status, text = run("pinned-go", [go, "env", "GOVERSION"], source, env, 30)
    if status or text.strip() != "go1.26.3":
        raise ValueError("Child validation requires the original pinned compiler")
    status, text = run("source-projection", [sys.executable, source/SOURCE_PROJECTION_SCRIPT, "-v"], source, env, 60)
    require_projection(text, status)
    status, text = run("original-heartbeat", [sys.executable, source/"deploy/test_node_heartbeat_context.py"], source, env, 600)
    require_heartbeat(text, status)
    gate = COMMON.load_gate(source)
    parent = Path(os.environ.get("RUNNER_TEMP", tempfile.gettempdir())).resolve(strict=True)
    if source == parent or source in parent.parents or output == parent or output in parent.parents:
        raise ValueError("Owned child build workspace must be outside source and artifacts")
    workspace = OwnedWorkspace(parent)
    try:
        work = workspace.path
        core, xray = work/"core", work/"xray"
        status, text = run("canonical-desktop-preparation",
            [sys.executable, Path(__file__), "--prepare-worker", source, core, xray], source, env, 600)
        if status:
            raise ValueError("Original pinned desktop preparation failed")
        before = checked_sources(gate, source, core, xray)
        (output/"native-source-before.json").write_text(json.dumps(before, sort_keys=True)+"\n")
        compiler, captured, architecture = gate.NODE.selected_compiler(go, core, env)
        captured["CGO_ENABLED"] = "1"
        receipt.update(target="linux/"+architecture, compiler=str(compiler), toolchain=gate.BUILD.TOOLCHAIN,
            native_source_sha256=hashlib.sha256(json.dumps(before, sort_keys=True).encode()).hexdigest(),
            resource_limits=dict(parallel_packages=1, GOMAXPROCS=2, GOGC=100, GOMEMLIMIT="2GiB"))
        flags = ["-race", "-p=1", "-mod=readonly", "-tags="+",".join(gate.NODE.TAGS), "-ldflags=-checklinkname=0"]
        images, identities = {}, {}
        for family in ("cmd", "box"):
            image = work/(family+".test")
            status, text = run(family+"-build", [compiler, "test", "-c", *flags, "-o", image, TARGET[family]], core, captured, 600)
            if status or any(word in text for word in FORBIDDEN):
                raise ValueError("Actual original child image failed to compile: "+family)
            images[family], identities[family] = image, image_identity(image)
        suites = [
            *child_command_suites(),
            dict(name="typed-box", package="box", selector="^("+"|".join(CHILD["box_roots"])+")$", cases=CHILD["box_cases"], process_seconds=100),
            *REGRESSIONS,
        ]
        for suite in suites:
            family = suite["package"]
            if image_identity(images[family]) != identities[family]:
                raise ValueError("Original child image was replaced before execution")
            status, text = run(suite["name"], [compiler, "tool", "test2json", "-t", "-p", PACKAGE[family],
                images[family], "-test.v=test2json", "-test.run="+suite["selector"],
                "-test.count=1", "-test.timeout=90s"], core, captured, suite.get("process_seconds", 105))
            require_verdict(text, status, PACKAGE[family], suite["cases"])
            if image_identity(images[family]) != identities[family]:
                raise ValueError("Original child image changed during execution")
        mutations = []
        for control in CONTROLS:
            family = control["package"]
            projected = PROJECTIONS[control["path"]]
            target = core/projected
            raw = target.read_text()
            if raw.encode() != (source/control["path"]).read_bytes():
                raise ValueError("Control is not the exact original projected source")
            changed = mutate(raw, control)
            replacement, overlay = work/(control["name"]+".go"), work/(control["name"]+".json")
            replacement.write_text(changed)
            overlay.write_text(json.dumps({"Replace": {str(target): str(replacement)}}))
            status, text = run("control-"+control["name"], [compiler, "test", *flags, "-json",
                "-overlay="+str(overlay), "-run="+control["run"], "-count=1", "-timeout=90s",
                TARGET[family]], core, captured, 600)
            require_verdict(text, status, PACKAGE[family], control["cases"], control=control)
            if target.read_text() != raw or (source/control["path"]).read_bytes() != raw.encode():
                raise ValueError("Child overlay modified original source")
            mutations.append(dict(name=control["name"], source=control["path"], projected=projected,
                mutated_sha256=hashlib.sha256(changed.encode()).hexdigest(), witness=control["witness"],
                failed_cases=control["cases"]))
        after = checked_sources(gate, source, core, xray)
        (output/"native-source-after.json").write_text(json.dumps(after, sort_keys=True)+"\n")
        if after != before or any(image_identity(images[name]) != identities[name] for name in images):
            raise ValueError("Child gate changed original source closure or compiled images")
        if selection(source, source_sha, output)[1] != original_selection or CLOCK.snapshot(source) != original_source:
            raise ValueError("Child gate changed the pristine original candidate")
        receipt.update(cases={suite["name"]: suite["cases"] for suite in suites},
            heartbeat_cases=list(HEARTBEAT_CASES), heartbeat_controls=list(HEARTBEAT_CONTROLS),
            causal_controls=mutations, source_files_unchanged=len(original_source),
            images={name: dict(bytes=value[2], sha256=value[-1]) for name, value in identities.items()})
    finally:
        receipt["workspace"] = workspace.cleanup()
        save()
    if not receipt["workspace"]["removed"]:
        raise RuntimeError("Original child workspace cleanup is not proven")
    receipt["completed"] = True
    save()
    (output/"receipt.json").write_text(json.dumps(receipt, indent=2)+"\n")
    return receipt


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--prepare-worker":
        prepare_worker(*(Path(value).resolve() for value in sys.argv[2:]))
        return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--source-sha", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--go", default="go")
    args = parser.parse_args()
    result = validate(args.source, args.source_sha, args.output, args.go)
    print(json.dumps({key: result[key] for key in ("suite", "target", "completed", "scope",
        "installed_native_accepted", "windows_native_accepted", "darwin_native_accepted")}, sort_keys=True))


if __name__ == "__main__":
    main()
