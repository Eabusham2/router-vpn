#!/usr/bin/env python3
"""Bind a read-only hosted validation to its trusted base and exact candidate.

The validator checkout is the parent of this helper's deploy directory. A
candidate may equal that captured base or be exactly one single-parent commit
above it. No ref is updated and no candidate code is executed by this helper.
"""
from pathlib import Path
import argparse
import hashlib
import json
import os
import platform
import sys
import stat
import re
import subprocess
import tempfile
import unittest
from unittest import mock

REPOSITORY = "Eabusham2/router-vpn"
WORKFLOW_REF = "refs/heads/main"
HEX40 = re.compile(r"[0-9a-f]{40}")
ALLOWLISTS = {
    "socks-preclose": frozenset({
        "deploy/prepare-mobile-external-policy.py",
        "deploy/prepare-mobile-node-chain.py",
        "deploy/test_node_chain_preparation.py",
        "mobile/chain/execution_close.go.tmpl",
        "mobile/chain/socks_box.go.tmpl",
        "mobile/chain/socks_close_native_test.go.tmpl",
        "mobile/chain/socks_native_test.go.tmpl",
        "mobile/chain/socks_owner.go.tmpl",
        "mobile/chain_execution/instance_capture.go.tmpl",
        "mobile/chain_execution/instance_close.go.tmpl",
    }),
    "connect-source": frozenset({
        "internal/mobilemultihop/node_chain_imported_connect.go",
        "internal/mobilemultihop/node_chain_connect_source.go",
        "internal/mobilemultihop/node_chain_graph.go",
        "internal/mobilemultihop/node_chain_connect_physical.go",
        "internal/mobilemultihop/desktop_egress.go",
        "internal/mobilemultihop/node_chain_connect_source_test.go",
    }),
    "connect-runtime": frozenset({
        'internal/mobilemultihop/desktop_egress.go',
        'internal/mobilemultihop/node_chain.go',
        'internal/mobilemultihop/node_chain_connect_physical.go',
        'internal/mobilemultihop/node_chain_connect_runtime.go',
        'internal/mobilemultihop/node_chain_connect_runtime_test.go',
        'internal/mobilemultihop/node_chain_connect_source.go',
        'internal/mobilemultihop/node_chain_connect_source_test.go',
        'internal/mobilemultihop/node_chain_graph.go',
        'internal/mobilemultihop/node_chain_imported_connect.go',
        'internal/mobilemultihop/node_chain_runtime.go',
        'internal/mobilemultihop/node_chain_socks_runtime.go',
    }),
    "darwin-socks-installed": frozenset({
        'client/macos/RouterVPNConnectionProfiles.swift',
        'cmd/client/connection_profile_node_chain.go',
        'cmd/client/connection_profile_setup.go',
        'cmd/client/desktop_external_latency_test.go',
        'cmd/client/desktop_external_linux_host.go',
        'cmd/client/desktop_external_linux_lifecycle.go',
        'cmd/client/desktop_external_mtu.go',
        'cmd/client/desktop_imported_linux_host.go',
        'cmd/client/desktop_imported_linux_lifecycle.go',
        'cmd/client/desktop_imported_owned.go',
        'cmd/client/desktop_macos_process_arguments.go',
        'cmd/client/desktop_macos_process_arguments_test.go',
        'cmd/client/desktop_native_workspace.go',
        'cmd/client/desktop_node_candidate_prefix_linux.go',
        'cmd/client/desktop_node_chain_darwin.go',
        'cmd/client/desktop_node_chain_darwin_baseline.go',
        'cmd/client/desktop_node_chain_darwin_native_test.go',
        'cmd/client/desktop_node_chain_darwin_peer_native_test.go',
        'cmd/client/desktop_node_chain_darwin_test.go',
        'cmd/client/desktop_node_chain_dispatch.go',
        'cmd/client/desktop_node_chain_host.go',
        'cmd/client/desktop_node_chain_launch.go',
        'cmd/client/desktop_node_chain_linux.go',
        'cmd/client/desktop_node_chain_measurement.go',
        'cmd/client/desktop_node_chain_owned.go',
        'cmd/client/desktop_node_chain_policy_dispatch.go',
        'cmd/client/desktop_node_chain_socks_darwin_baseline_test.go',
        'cmd/client/desktop_node_chain_socks_darwin_native_test.go',
        'cmd/client/desktop_node_chain_socks_darwin_test.go',
        'cmd/client/desktop_node_chain_socks_parent_linux_test.go',
        'cmd/client/desktop_node_chain_socks_parent_test.go',
        'cmd/client/desktop_node_chain_socks_persistence_test.go',
        'cmd/client/desktop_node_host_linux.go',
        'cmd/client/desktop_node_host_linux_active.go',
        'cmd/client/desktop_node_host_linux_proof.go',
        'cmd/client/desktop_node_host_linux_ready.go',
        'cmd/client/desktop_node_host_linux_start.go',
        'cmd/client/desktop_node_journal_windows.go',
        'cmd/client/desktop_node_linux_transaction.go',
        'cmd/client/desktop_node_mtu.go',
        'cmd/client/desktop_node_mtu_darwin.go',
        'cmd/client/desktop_node_mtu_darwin_test.go',
        'cmd/client/desktop_node_mtu_linux.go',
        'cmd/client/desktop_node_owned.go',
        'cmd/client/desktop_node_process.go',
        'cmd/client/desktop_node_process_windows.go',
        'cmd/client/desktop_node_protection.go',
        'cmd/client/desktop_protection_selection.go',
        'cmd/client/mtu_node_chain_snapshot.go',
        'cmd/client/multihop.go',
        'cmd/client/multihop_execution.go',
        'cmd/client/multihop_native_capture.go',
        'cmd/client/multihop_native_dns_runtime.go',
        'cmd/client/multihop_native_launch.go',
        'cmd/client/multihop_native_restore.go',
        'cmd/client/multihop_native_routes.go',
        'cmd/client/multihop_node_chain_selection.go',
        'cmd/client/multihop_node_chain_socks_capture.go',
        'cmd/client/multihop_node_chain_socks_capture_test.go',
        'cmd/client/multihop_node_chain_socks_selection.go',
        'cmd/client/multihop_node_chain_socks_selection_test.go',
        'cmd/client/multihop_startup.go',
        'cmd/client/ordered_candidate_preparation_lifecycle.go',
        'cmd/client/ordered_candidate_preparation_runtime.go',
        'cmd/client/profile_public_view.go',
        'cmd/client/startup_node_chain.go',
        'deploy/prepare-desktop-external.py',
        'deploy/test_darwin_socks_child_tun.py',
        'deploy/test_darwin_socks_child_tun_runner.py',
        'deploy/test_desktop_connection_profile_modes.py',
        'deploy/test_desktop_node_physical.py',
        'deploy/test_desktop_node_routing_runner.py',
        'deploy/test_desktop_socks_child_sources.py',
        'deploy/test_macos_node_chain_host.py',
        'deploy/test_macos_node_chain_host_runner.py',
        'deploy/test_macos_socks_node_chain_host.py',
        'deploy/test_macos_socks_node_chain_host_runner.py',
        'deploy/test_node_heartbeat_context.py',
        'internal/macosprocess/node_chain_socks_transfer.go',
        'internal/macosprocess/node_chain_socks_transfer_test.go',
        'internal/macosprocess/scope.go',
        'internal/mobilemultihop/desktop_node_chain_socks_policy.go',
        'internal/mobilemultihop/desktop_node_chain_socks_ready.go',
        'internal/mobilemultihop/desktop_node_chain_socks_ready_test.go',
        'internal/mobilemultihop/node_chain_socks_integrity.go',
        'internal/mobilemultihop/node_chain_socks_integrity_test.go',
        'internal/mobilemultihop/node_chain_socks_source.go',
        'mobile/desktop/external.go.tmpl',
        'mobile/desktop/mtu_node.go.tmpl',
        'mobile/desktop/mtu_node_test.go.tmpl',
        'mobile/desktop/node_box_physical.go.tmpl',
        'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl',
        'mobile/desktop/node_chain_command_runtime_test.go.tmpl',
        'mobile/desktop/node_chain_imported_test.go.tmpl',
        'mobile/desktop/node_chain_socks_box_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_box_linux.go.tmpl',
        'mobile/desktop/node_chain_socks_box_physical.go.tmpl',
        'mobile/desktop/node_chain_socks_box_physical_test.go.tmpl',
        'mobile/desktop/node_chain_socks_command.go.tmpl',
        'mobile/desktop/node_chain_socks_command_darwin_native_test.go.tmpl',
        'mobile/desktop/node_chain_socks_command_test.go.tmpl',
        'mobile/desktop/node_chain_socks_construction.go.tmpl',
        'mobile/desktop/node_chain_socks_construction_test.go.tmpl',
        'mobile/desktop/node_chain_socks_control_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_control_linux.go.tmpl',
        'mobile/desktop/node_chain_socks_control_other.go.tmpl',
        'mobile/desktop/node_chain_socks_measurement.go.tmpl',
        'mobile/desktop/node_chain_socks_middle_test.go.tmpl',
        'mobile/desktop/node_chain_socks_mtu.go.tmpl',
        'mobile/desktop/node_chain_socks_peer_test.go.tmpl',
        'mobile/desktop/node_chain_socks_physical_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_physical_linux.go.tmpl',
        'mobile/desktop/node_chain_socks_physical_other.go.tmpl',
        'mobile/desktop/node_chain_socks_physical_windows.go.tmpl',
        'mobile/desktop/node_chain_socks_process_test.go.tmpl',
        'mobile/desktop/node_chain_socks_retirement_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_run_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_run_nonlinux.go.tmpl',
        'mobile/desktop/node_chain_socks_runtime.go.tmpl',
        'mobile/desktop/node_chain_socks_runtime_test.go.tmpl',
        'mobile/desktop/node_command_run_linux.go.tmpl',
        'mobile/desktop/node_max_peer_windows_test.go.tmpl',
        'mobile/desktop/node_network.go.tmpl',
        'mobile/desktop/node_network_test.go.tmpl',
        'mobile/desktop/node_physical_darwin.go.tmpl',
        'mobile/desktop/node_pq_peer_test.go.tmpl',
        'mobile/desktop/node_pq_peer_windows_test.go.tmpl',
        'modes/kill-switch-platform.py',
        'modes/test_darwin_owned_pf.py',
    }),
    "android-policy-fixtures": frozenset({
        "android/test_android_tor_form.py",
        "android/test_android_external_policy.py",
        "android/test_android_external_entries.py",
        "android/test_android_imported_router.py",
    }),
    "darwin-socks-child": frozenset({
        'deploy/prepare-desktop-external.py',
        'deploy/test_darwin_socks_child_tun.py',
        'deploy/test_darwin_socks_child_tun_runner.py',
        'deploy/test_desktop_node_physical.py',
        'deploy/test_desktop_node_routing_runner.py',
        'deploy/test_desktop_socks_child_sources.py',
        'deploy/test_node_heartbeat_context.py',
        'internal/macosprocess/node_chain_socks_transfer.go',
        'internal/macosprocess/node_chain_socks_transfer_test.go',
        'internal/macosprocess/scope.go',
        'internal/mobilemultihop/desktop_node_chain_socks_policy.go',
        'internal/mobilemultihop/desktop_node_chain_socks_ready.go',
        'internal/mobilemultihop/desktop_node_chain_socks_ready_test.go',
        'internal/mobilemultihop/node_chain_socks_integrity.go',
        'internal/mobilemultihop/node_chain_socks_integrity_test.go',
        'internal/mobilemultihop/node_chain_socks_source.go',
        'mobile/desktop/external.go.tmpl',
        'mobile/desktop/mtu_node.go.tmpl',
        'mobile/desktop/mtu_node_test.go.tmpl',
        'mobile/desktop/node_box_physical.go.tmpl',
        'mobile/desktop/node_chain_command_darwin_native_test.go.tmpl',
        'mobile/desktop/node_chain_command_runtime_test.go.tmpl',
        'mobile/desktop/node_chain_imported_test.go.tmpl',
        'mobile/desktop/node_chain_socks_box_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_box_linux.go.tmpl',
        'mobile/desktop/node_chain_socks_box_physical.go.tmpl',
        'mobile/desktop/node_chain_socks_box_physical_test.go.tmpl',
        'mobile/desktop/node_chain_socks_command.go.tmpl',
        'mobile/desktop/node_chain_socks_command_darwin_native_test.go.tmpl',
        'mobile/desktop/node_chain_socks_command_test.go.tmpl',
        'mobile/desktop/node_chain_socks_construction.go.tmpl',
        'mobile/desktop/node_chain_socks_construction_test.go.tmpl',
        'mobile/desktop/node_chain_socks_control_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_control_linux.go.tmpl',
        'mobile/desktop/node_chain_socks_control_other.go.tmpl',
        'mobile/desktop/node_chain_socks_measurement.go.tmpl',
        'mobile/desktop/node_chain_socks_middle_test.go.tmpl',
        'mobile/desktop/node_chain_socks_mtu.go.tmpl',
        'mobile/desktop/node_chain_socks_peer_test.go.tmpl',
        'mobile/desktop/node_chain_socks_physical_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_physical_linux.go.tmpl',
        'mobile/desktop/node_chain_socks_physical_other.go.tmpl',
        'mobile/desktop/node_chain_socks_physical_windows.go.tmpl',
        'mobile/desktop/node_chain_socks_process_test.go.tmpl',
        'mobile/desktop/node_chain_socks_retirement_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_run_darwin.go.tmpl',
        'mobile/desktop/node_chain_socks_run_nonlinux.go.tmpl',
        'mobile/desktop/node_chain_socks_runtime.go.tmpl',
        'mobile/desktop/node_chain_socks_runtime_test.go.tmpl',
        'mobile/desktop/node_command_run_linux.go.tmpl',
        'mobile/desktop/node_max_peer_windows_test.go.tmpl',
        'mobile/desktop/node_network.go.tmpl',
        'mobile/desktop/node_network_test.go.tmpl',
        'mobile/desktop/node_physical_darwin.go.tmpl',
        'mobile/desktop/node_pq_peer_test.go.tmpl',
        'mobile/desktop/node_pq_peer_windows_test.go.tmpl',
        'modes/kill-switch-platform.py',
        'modes/test_darwin_owned_pf.py',
    }),
    "desktop-socks-child": frozenset({
        "deploy/prepare-desktop-external.py",
        "deploy/test_desktop_node_physical.py",
        "deploy/test_desktop_node_routing_runner.py",
        "deploy/test_desktop_socks_child_sources.py",
        "deploy/test_node_heartbeat_context.py",
        "internal/macosprocess/node_chain_socks_transfer_test.go",
        "internal/macosprocess/node_chain_socks_transfer.go",
        "internal/macosprocess/scope.go",
        "internal/mobilemultihop/desktop_node_chain_socks_ready_test.go",
        "internal/mobilemultihop/desktop_node_chain_socks_ready.go",
        "mobile/desktop/external.go.tmpl",
        "mobile/desktop/mtu_node_test.go.tmpl",
        "mobile/desktop/mtu_node.go.tmpl",
        "mobile/desktop/node_box_physical.go.tmpl",
        "mobile/desktop/node_chain_command_runtime_test.go.tmpl",
        "mobile/desktop/node_chain_socks_box_darwin.go.tmpl",
        "mobile/desktop/node_chain_socks_box_linux.go.tmpl",
        "mobile/desktop/node_chain_socks_box_physical_test.go.tmpl",
        "mobile/desktop/node_chain_socks_box_physical.go.tmpl",
        "mobile/desktop/node_chain_socks_command_test.go.tmpl",
        "mobile/desktop/node_chain_socks_command.go.tmpl",
        "mobile/desktop/node_chain_socks_construction_test.go.tmpl",
        "mobile/desktop/node_chain_socks_construction.go.tmpl",
        "mobile/desktop/node_chain_socks_control_darwin.go.tmpl",
        "mobile/desktop/node_chain_socks_control_linux.go.tmpl",
        "mobile/desktop/node_chain_socks_control_other.go.tmpl",
        "mobile/desktop/node_chain_socks_measurement.go.tmpl",
        "mobile/desktop/node_chain_socks_mtu.go.tmpl",
        "mobile/desktop/node_chain_socks_physical_darwin.go.tmpl",
        "mobile/desktop/node_chain_socks_physical_linux.go.tmpl",
        "mobile/desktop/node_chain_socks_physical_other.go.tmpl",
        "mobile/desktop/node_chain_socks_physical_windows.go.tmpl",
        "mobile/desktop/node_chain_socks_retirement_darwin.go.tmpl",
        "mobile/desktop/node_chain_socks_run_darwin.go.tmpl",
        "mobile/desktop/node_chain_socks_run_nonlinux.go.tmpl",
        "mobile/desktop/node_chain_socks_runtime_test.go.tmpl",
        "mobile/desktop/node_chain_socks_runtime.go.tmpl",
        "mobile/desktop/node_command_run_linux.go.tmpl",
        "mobile/desktop/node_max_peer_windows_test.go.tmpl",
        "mobile/desktop/node_network_test.go.tmpl",
        "mobile/desktop/node_network.go.tmpl",
        "mobile/desktop/node_physical_darwin.go.tmpl",
        "mobile/desktop/node_pq_peer_test.go.tmpl",
        "mobile/desktop/node_pq_peer_windows_test.go.tmpl",
    }),
    "desktop-socks-editor": frozenset({
        "client/RouterVPN-Windows-ProfileSettings.ps1",
        "client/RouterVPN-Windows-UnifiedShell.ps1",
        "client/linux/routervpn-ordered-nodes-v1.inc",
        "client/linux/test-ordered-nodes-v1.c",
        "client/linux/test-ordered-nodes-v1.py",
        "client/test-windows-ordered-editor.ps1",
        "deploy/test_desktop_connection_profile_modes.py",
        "deploy/test_desktop_connection_profile_modes_runner.py",
    }),
    "desktop-socks-parent": frozenset({
        "cmd/client/connection_profile_node_chain.go",
        "cmd/client/connection_profile_setup.go",
        "cmd/client/desktop_external_latency_test.go",
        "cmd/client/desktop_external_linux_host.go",
        "cmd/client/desktop_external_linux_lifecycle.go",
        "cmd/client/desktop_external_mtu.go",
        "cmd/client/desktop_imported_linux_host.go",
        "cmd/client/desktop_imported_linux_lifecycle.go",
        "cmd/client/desktop_imported_owned.go",
        "cmd/client/desktop_macos_process_arguments.go",
        "cmd/client/desktop_macos_process_arguments_test.go",
        "cmd/client/desktop_native_workspace.go",
        "cmd/client/desktop_node_candidate_prefix_linux.go",
        "cmd/client/desktop_node_chain_darwin.go",
        "cmd/client/desktop_node_chain_darwin_baseline.go",
        "cmd/client/desktop_node_chain_darwin_test.go",
        "cmd/client/desktop_node_chain_dispatch.go",
        "cmd/client/desktop_node_chain_host.go",
        "cmd/client/desktop_node_chain_launch.go",
        "cmd/client/desktop_node_chain_linux.go",
        "cmd/client/desktop_node_chain_measurement.go",
        "cmd/client/desktop_node_chain_owned.go",
        "cmd/client/desktop_node_chain_policy_dispatch.go",
        "cmd/client/desktop_node_chain_socks_darwin_baseline_test.go",
        "cmd/client/desktop_node_chain_socks_darwin_test.go",
        "cmd/client/desktop_node_chain_socks_parent_linux_test.go",
        "cmd/client/desktop_node_chain_socks_parent_test.go",
        "cmd/client/desktop_node_chain_socks_persistence_test.go",
        "cmd/client/desktop_node_host_linux.go",
        "cmd/client/desktop_node_host_linux_active.go",
        "cmd/client/desktop_node_host_linux_proof.go",
        "cmd/client/desktop_node_host_linux_ready.go",
        "cmd/client/desktop_node_host_linux_start.go",
        "cmd/client/desktop_node_journal_windows.go",
        "cmd/client/desktop_node_linux_transaction.go",
        "cmd/client/desktop_node_mtu.go",
        "cmd/client/desktop_node_mtu_darwin.go",
        "cmd/client/desktop_node_mtu_darwin_test.go",
        "cmd/client/desktop_node_mtu_linux.go",
        "cmd/client/desktop_node_owned.go",
        "cmd/client/desktop_node_process.go",
        "cmd/client/desktop_node_process_windows.go",
        "cmd/client/desktop_node_protection.go",
        "cmd/client/desktop_protection_selection.go",
        "cmd/client/mtu_node_chain_snapshot.go",
        "cmd/client/multihop.go",
        "cmd/client/multihop_execution.go",
        "cmd/client/multihop_native_capture.go",
        "cmd/client/multihop_native_dns_runtime.go",
        "cmd/client/multihop_native_launch.go",
        "cmd/client/multihop_native_restore.go",
        "cmd/client/multihop_native_routes.go",
        "cmd/client/multihop_node_chain_selection.go",
        "cmd/client/multihop_node_chain_socks_capture.go",
        "cmd/client/multihop_node_chain_socks_capture_test.go",
        "cmd/client/multihop_node_chain_socks_selection.go",
        "cmd/client/multihop_node_chain_socks_selection_test.go",
        "cmd/client/multihop_startup.go",
        "cmd/client/ordered_candidate_preparation_lifecycle.go",
        "cmd/client/ordered_candidate_preparation_runtime.go",
        "cmd/client/profile_public_view.go",
        "cmd/client/startup_node_chain.go",
        "internal/macosprocess/node_chain_socks_transfer.go",
        "internal/macosprocess/node_chain_socks_transfer_test.go",
        "internal/macosprocess/scope.go",
        "internal/mobilemultihop/desktop_node_chain_socks_ready.go",
        "internal/mobilemultihop/desktop_node_chain_socks_ready_test.go",
        "modes/kill-switch-platform.py",
        "modes/test_darwin_owned_pf.py",
    }),
    "desktop-socks-policy": frozenset({
        "internal/mobilemultihop/desktop_node_chain_policy.go",
        "internal/mobilemultihop/desktop_node_chain_socks_policy.go",
        "internal/mobilemultihop/desktop_node_chain_socks_policy_test.go",
        "internal/mobilemultihop/desktop_node_cover.go",
        "internal/mobilemultihop/desktop_physical_policy.go",
        "internal/mobilemultihop/node_chain_projection.go",
        "internal/mobilemultihop/node_chain_socks_runtime.go",
        "internal/mobilemultihop/node_chain_socks_source.go",
    }),
    "windows-source-retirement": frozenset({
        "deploy/test_desktop_node_physical.py",
        "deploy/test_desktop_node_routing_runner.py",
        "mobile/desktop/external.go.tmpl",
        "mobile/desktop/mtu_node.go.tmpl",
        "mobile/desktop/mtu_node_test.go.tmpl",
        "mobile/desktop/node_box_physical.go.tmpl",
        "mobile/desktop/node_max_peer_windows_test.go.tmpl",
        "mobile/desktop/node_network.go.tmpl",
        "mobile/desktop/node_network_test.go.tmpl",
        "mobile/desktop/node_pq_peer_test.go.tmpl",
        "mobile/desktop/node_pq_peer_windows_test.go.tmpl",
    }),
    "desktop-socks-capture": frozenset({
        "cmd/client/multihop_node_chain_socks_capture.go",
        "cmd/client/multihop_node_chain_socks_capture_test.go",
    }),
    "ios-sdk": frozenset({
        "android/build-sing-box-libbox.sh",
        "deploy/prepare-desktop-external.py",
        "deploy/prepare-mobile-node-chain.py",
        "deploy/test_desktop_tor_preparation.py",
        "deploy/test_ios_external_connection_profiles.py",
        "deploy/test_ios_node_chain_editor.py",
        "deploy/test_ios_node_chain_identity.py",
        "deploy/test_ios_node_chain_launch.py",
        "deploy/test_ios_node_chain_profiles.py",
        "deploy/test_ios_node_chain_socks_capture.py",
        "deploy/test_ios_node_chain_socks_host.py",
        "deploy/test_ios_node_chain_socks_profiles.py",
        "deploy/test_ios_node_chain_startup.py",
        "deploy/test_ios_startup_policy.py",
        "deploy/test_ios_tor_connection_profiles.py",
        "deploy/test_node_chain_preparation.py",
        "ios/RouterVPN/App/IOSConnectionProfilesView.swift",
        "ios/RouterVPN/App/IOSExternalNodeBuilderView.swift",
        "ios/RouterVPN/App/IOSImportedSOCKSSource.swift",
        "ios/RouterVPN/App/IOSMultihopView.swift",
        "ios/RouterVPN/App/IOSNodeChainEditor.swift",
        "ios/RouterVPN/App/IOSNodeChainEditorAdmission.swift",
        "ios/RouterVPN/App/IOSNodeChainEditorView.swift",
        "ios/RouterVPN/App/IOSNodeChainSOCKSCapture.swift",
        "ios/RouterVPN/App/IOSNodeChainSOCKSLaunch.swift",
        "ios/RouterVPN/App/IOSNodeChainSOCKSProviderCapture.swift",
        "ios/RouterVPN/App/IOSRuntimeSelection.swift",
        "ios/RouterVPN/App/IOSStartupPolicy.swift",
        "ios/RouterVPN/App/IOSStrategySupport.swift",
        "ios/RouterVPN/App/RouterVPNModel.swift",
        "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift",
        "ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift",
        "ios/RouterVPN/PacketTunnel/RouterVPNMTUSession.swift",
        "ios/RouterVPN/PacketTunnel/RouterVPNNodeChainSOCKSHost.swift",
        "ios/RouterVPN/prepare-libbox.sh",
        "ios/RouterVPN/project.yml",
        "mobile/chain/box.go.tmpl",
        "mobile/chain/socks_box.go.tmpl",
        "mobile/chain/socks_bridge.go.tmpl",
        "mobile/chain/socks_bridge_test.go.tmpl",
        "mobile/chain/socks_lifecycle.go.tmpl",
        "mobile/chain/socks_lifecycle_test.go.tmpl",
        "mobile/chain/socks_measurement.go.tmpl",
        "mobile/chain/socks_measurement_test.go.tmpl",
        "mobile/chain/socks_mtu.go.tmpl",
        "mobile/chain/socks_mtu_box.go.tmpl",
        "mobile/chain/socks_mtu_box_test.go.tmpl",
        "mobile/chain/socks_mtu_test.go.tmpl",
        "mobile/chain/socks_native_test.go.tmpl",
        "mobile/chain/socks_owner.go.tmpl",
        "mobile/chain/socks_scope.go.tmpl",
        "mobile/chain/socks_server.go.tmpl",
        "mobile/desktop/node_chain_socks_middle_test.go.tmpl",
        "mobile/desktop/node_imported_peer_linux_test.go.tmpl",
    }),
    "ordered-clock": frozenset({
        "internal/mobilemultihop/node_chain_execution_proof.go",
        "internal/mobilemultihop/node_chain_execution_runtime.go",
        "internal/mobilemultihop/node_chain_execution_proof_clock_test.go",
    }),
    "legacy-clock": frozenset({
        "internal/mobilemultihop/runtime.go",
        "internal/mobilemultihop/plan.go",
        "internal/mobilemultihop/runtime_proof_clock_test.go",
    }),
    "android-tor": frozenset({"android/test_android_tor_profile.py"}),
    "android-prefix-owner": frozenset({"android/test_android_node_candidate_preparation_owner.py"}),
    "macos-profiles": frozenset({
        "client/macos/RouterVPNConnectionProfiles.swift",
        "deploy/test_desktop_connection_profile_modes.py",
    }),
    "ios-socks-host": frozenset({
        "deploy/test_ios_external_connection_profiles.py",
        "deploy/test_ios_node_chain_editor.py",
        "deploy/test_ios_node_chain_identity.py",
        "deploy/test_ios_node_chain_launch.py",
        "deploy/test_ios_node_chain_profiles.py",
        "deploy/test_ios_node_chain_socks_capture.py",
        "deploy/test_ios_node_chain_socks_host.py",
        "deploy/test_ios_node_chain_socks_profiles.py",
        "deploy/test_ios_node_chain_startup.py",
        "deploy/test_ios_startup_policy.py",
        "deploy/test_ios_tor_connection_profiles.py",
        "ios/RouterVPN/App/IOSConnectionProfilesView.swift",
        "ios/RouterVPN/App/IOSExternalNodeBuilderView.swift",
        "ios/RouterVPN/App/IOSImportedSOCKSSource.swift",
        "ios/RouterVPN/App/IOSMultihopView.swift",
        "ios/RouterVPN/App/IOSNodeChainEditor.swift",
        "ios/RouterVPN/App/IOSNodeChainEditorAdmission.swift",
        "ios/RouterVPN/App/IOSNodeChainEditorView.swift",
        "ios/RouterVPN/App/IOSNodeChainSOCKSCapture.swift",
        "ios/RouterVPN/App/IOSNodeChainSOCKSLaunch.swift",
        "ios/RouterVPN/App/IOSNodeChainSOCKSProviderCapture.swift",
        "ios/RouterVPN/App/IOSRuntimeSelection.swift",
        "ios/RouterVPN/App/IOSStartupPolicy.swift",
        "ios/RouterVPN/App/IOSStrategySupport.swift",
        "ios/RouterVPN/App/RouterVPNModel.swift",
        "ios/RouterVPN/PacketTunnel/PacketTunnelProvider.swift",
        "ios/RouterVPN/PacketTunnel/RouterVPNLibboxEngine.swift",
        "ios/RouterVPN/PacketTunnel/RouterVPNMTUSession.swift",
        "ios/RouterVPN/PacketTunnel/RouterVPNNodeChainSOCKSHost.swift",
    }),
    "android-socks-host": frozenset({
        "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeCandidatePrefixCapture.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainCapture.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainExecutionCapture.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainSession.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedPathSelection.java",
        "android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java",
        "android/test_android_connection_profiles.py",
        "android/test_android_layered_service_compile.py",
        "android/test_android_node_chain_capture.py",
        "android/test_android_node_chain_execution_runtime.py",
        "android/test_android_node_chain_runtime.py",
        "android/test_android_node_chain_socks_runtime.py",
        ".github/workflows/android-multihop-contract.yml",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainSOCKSCapture.java",
        "android/app/src/main/java/com/eabusham/routervpn/ProductActivity.java",
        "android/test_android_node_candidate_prefix_host.py",
        "android/test_android_runtime_contract.py",
        "deploy/test_android_multihop_workflow.py",
    }),
    "socks-native-mtu": frozenset({
        "android/build-sing-box-libbox.sh",
        "deploy/prepare-desktop-external.py",
        "deploy/prepare-mobile-node-chain.py",
        "deploy/test_desktop_tor_preparation.py",
        "deploy/test_node_chain_preparation.py",
        "ios/RouterVPN/prepare-libbox.sh",
        "mobile/chain/box.go.tmpl",
        "mobile/chain/socks_box.go.tmpl",
        "mobile/chain/socks_bridge.go.tmpl",
        "mobile/chain/socks_bridge_test.go.tmpl",
        "mobile/chain/socks_lifecycle.go.tmpl",
        "mobile/chain/socks_lifecycle_test.go.tmpl",
        "mobile/chain/socks_measurement.go.tmpl",
        "mobile/chain/socks_measurement_test.go.tmpl",
        "mobile/chain/socks_mtu.go.tmpl",
        "mobile/chain/socks_mtu_box.go.tmpl",
        "mobile/chain/socks_mtu_box_test.go.tmpl",
        "mobile/chain/socks_mtu_test.go.tmpl",
        "mobile/chain/socks_native_test.go.tmpl",
        "mobile/chain/socks_owner.go.tmpl",
        "mobile/chain/socks_scope.go.tmpl",
        "mobile/chain/socks_server.go.tmpl",
        "mobile/desktop/node_chain_socks_middle_test.go.tmpl",
        "mobile/desktop/node_imported_peer_linux_test.go.tmpl",
    }),
    "android-sdk": frozenset({
        "android/test_android_tor_form.py",
        "android/test_android_external_policy.py",
        "android/test_android_external_entries.py",
        "android/test_android_imported_router.py",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidConnectionProfileStore.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeCandidatePrefixCapture.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainCapture.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainExecutionCapture.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeChainSession.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidNodeStore.java",
        "android/app/src/main/java/com/eabusham/routervpn/AndroidOrderedPathSelection.java",
        "android/app/src/main/java/com/eabusham/routervpn/LayeredVpnService.java",
        "android/build-sing-box-libbox.sh",
        "android/test_android_connection_profiles.py",
        "android/test_android_layered_service_compile.py",
        "android/test_android_node_chain_capture.py",
        "android/test_android_node_chain_execution_runtime.py",
        "android/test_android_node_chain_runtime.py",
        "android/test_android_node_chain_socks_runtime.py",
        "deploy/prepare-desktop-external.py",
        "deploy/prepare-mobile-node-chain.py",
        "deploy/test_desktop_tor_preparation.py",
        "deploy/test_node_chain_preparation.py",
        "ios/RouterVPN/prepare-libbox.sh",
        "mobile/chain/box.go.tmpl",
        "mobile/chain/socks_box.go.tmpl",
        "mobile/chain/socks_bridge.go.tmpl",
        "mobile/chain/socks_bridge_test.go.tmpl",
        "mobile/chain/socks_lifecycle.go.tmpl",
        "mobile/chain/socks_lifecycle_test.go.tmpl",
        "mobile/chain/socks_measurement.go.tmpl",
        "mobile/chain/socks_measurement_test.go.tmpl",
        "mobile/chain/socks_mtu.go.tmpl",
        "mobile/chain/socks_mtu_box.go.tmpl",
        "mobile/chain/socks_mtu_box_test.go.tmpl",
        "mobile/chain/socks_mtu_test.go.tmpl",
        "mobile/chain/socks_native_test.go.tmpl",
        "mobile/chain/socks_owner.go.tmpl",
        "mobile/chain/socks_scope.go.tmpl",
        "mobile/chain/socks_server.go.tmpl",
        "mobile/desktop/node_chain_socks_middle_test.go.tmpl",
        "mobile/desktop/node_imported_peer_linux_test.go.tmpl",
    }),
    "socks-run": frozenset({
        "android/build-sing-box-libbox.sh",
        "deploy/prepare-desktop-external.py",
        "deploy/prepare-mobile-external-policy.py",
        "deploy/prepare-mobile-node-chain.py",
        "deploy/test_desktop_tor_preparation.py",
        "deploy/test_desktop_windows_identity_runner.py",
        "deploy/test_node_chain_preparation.py",
        "internal/mobilemultihop/desktop_node_chain_socks_policy.go",
        "internal/mobilemultihop/node_chain_socks_integrity.go",
        "internal/mobilemultihop/node_chain_socks_integrity_test.go",
        "internal/mobilemultihop/node_chain_socks_source.go",
        "ios/RouterVPN/prepare-libbox.sh",
        "mobile/chain/box.go.tmpl",
        "mobile/chain/execution_close.go.tmpl",
        "mobile/chain/socks_box.go.tmpl",
        "mobile/chain/socks_bridge.go.tmpl",
        "mobile/chain/socks_bridge_test.go.tmpl",
        "mobile/chain/socks_close_native_test.go.tmpl",
        "mobile/chain/socks_lifecycle.go.tmpl",
        "mobile/chain/socks_lifecycle_test.go.tmpl",
        "mobile/chain/socks_measurement.go.tmpl",
        "mobile/chain/socks_measurement_test.go.tmpl",
        "mobile/chain/socks_mtu.go.tmpl",
        "mobile/chain/socks_mtu_box.go.tmpl",
        "mobile/chain/socks_mtu_box_test.go.tmpl",
        "mobile/chain/socks_mtu_test.go.tmpl",
        "mobile/chain/socks_native_test.go.tmpl",
        "mobile/chain/socks_owner.go.tmpl",
        "mobile/chain/socks_run_test.go.tmpl",
        "mobile/chain/socks_scope.go.tmpl",
        "mobile/chain/socks_server.go.tmpl",
        "mobile/chain_execution/instance_capture.go.tmpl",
        "mobile/chain_execution/instance_close.go.tmpl",
        "mobile/desktop/node_chain_imported_test.go.tmpl",
        "mobile/desktop/node_chain_socks_middle_test.go.tmpl",
        "mobile/desktop/node_chain_socks_process_test.go.tmpl",
        "mobile/desktop/node_imported_peer_linux_test.go.tmpl",
    }),
    "socks-bridge": frozenset({
        "android/build-sing-box-libbox.sh",
        "deploy/prepare-desktop-external.py",
        "deploy/prepare-mobile-node-chain.py",
        "deploy/test_desktop_tor_preparation.py",
        "deploy/test_node_chain_preparation.py",
        "ios/RouterVPN/prepare-libbox.sh",
        "mobile/chain/box.go.tmpl",
        "mobile/chain/socks_box.go.tmpl",
        "mobile/chain/socks_bridge.go.tmpl",
        "mobile/chain/socks_bridge_test.go.tmpl",
        "mobile/chain/socks_lifecycle.go.tmpl",
        "mobile/chain/socks_lifecycle_test.go.tmpl",
        "mobile/chain/socks_measurement.go.tmpl",
        "mobile/chain/socks_measurement_test.go.tmpl",
        "mobile/chain/socks_native_test.go.tmpl",
        "mobile/chain/socks_owner.go.tmpl",
        "mobile/chain/socks_scope.go.tmpl",
        "mobile/chain/socks_server.go.tmpl",
        "mobile/desktop/node_chain_socks_middle_test.go.tmpl",
        "mobile/desktop/node_imported_peer_linux_test.go.tmpl",
    }),
    "socks-runtime": frozenset({
        "internal/mobilemultihop/node_chain_socks_runtime.go",
        "internal/mobilemultihop/node_chain_socks_runtime_test.go",
        "internal/mobilemultihop/node_chain.go",
        "internal/mobilemultihop/node_chain_runtime.go",
        "internal/mobilemultihop/node_chain_measurement.go",
    }),
    "socks-mtu": frozenset({
        "internal/mobilemultihop/node_chain_socks_mtu.go",
        "internal/mobilemultihop/node_chain_socks_mtu_test.go",
    }),
    "darwin-hy2": frozenset({
        "mobile/desktop/node_chain_peer_linux_test.go.tmpl",
        "cmd/client/desktop_node_chain_hysteria_darwin_native_test.go",
        "cmd/client/desktop_node_chain_darwin_peer_native_test.go",
        "cmd/client/desktop_node_chain_darwin_native_test.go",
        "deploy/test_macos_node_chain_host.py",
        "deploy/test_macos_node_chain_host_runner.py",
        "deploy/prepare-desktop-external.py",
        "deploy/test_macos_node_candidate_prefix_host_runner.py",
    }),
    "socks-owner": frozenset({
        "mobile/chain/socks_owner.go.tmpl",
        "deploy/test_desktop_tor_preparation.py",
        "mobile/desktop/node_chain_socks_middle_test.go.tmpl",
        "mobile/desktop/node_imported_peer_linux_test.go.tmpl",
        "deploy/prepare-mobile-node-chain.py",
        "deploy/prepare-desktop-external.py",
    }),
    "socks-source": frozenset({
        "internal/mobilemultihop/desktop_node_chain_socks_policy.go",
        "internal/mobilemultihop/node_chain_socks_integrity.go",
        "internal/mobilemultihop/node_chain_socks_integrity_test.go",
        "internal/mobilemultihop/node_chain_imported_socks.go",
        "internal/mobilemultihop/node_chain_socks_source.go",
        "internal/mobilemultihop/node_chain_socks_source_test.go",
    }),
    "linux-hy2": frozenset({
        "mobile/desktop/node_chain_peer_linux_test.go.tmpl",
        "mobile/desktop/node_chain_hysteria_final_test.go.tmpl",
        "cmd/client/desktop_node_chain_linux_tun_native_test.go",
        "cmd/client/desktop_node_chain_linux_hysteria_tun_native_test.go",
        "deploy/test_linux_node_host_tun.py",
        "deploy/test_linux_node_host_tun_runner.py",
        "deploy/test_macos_node_chain_host_runner.py",
    }),
}
REGULAR_MODES = {"100644", "100755"}


def git(root, *arguments):
    command = ["git", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null",
               "-c", "core.untrackedCache=false", "-c", "core.fileMode=true", "-C", str(root), *arguments]
    environment = dict(os.environ, GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=os.devnull)
    result = subprocess.run(command, check=False, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=30, env=environment)
    if result.returncode:
        raise ValueError("source identity Git read failed: " + arguments[0])
    return result.stdout


def exact_sha(value, label):
    if not isinstance(value, str) or HEX40.fullmatch(value) is None:
        raise ValueError(label + " must be exactly forty lowercase hexadecimal characters")
    return value



def checkout_failure_diagnostics(root, status):
    """Bounded read-only observations; never relax the failed identity decision."""
    def bounded(raw):
        rows=raw.decode("utf-8","backslashreplace").splitlines()
        return dict(total_lines=len(rows),sha256=hashlib.sha256(raw).hexdigest(),
                    lines=[row[:2048] for row in rows[:40]],
                    truncated=len(rows)>40 or any(len(row)>2048 for row in rows[:40]))
    def observe(*arguments):
        try:return bounded(git(root,*arguments))
        except (OSError,ValueError,subprocess.SubprocessError):
            return dict(unavailable=True)
    changed=[]
    try:
        changed=[path.decode("utf-8","strict") for path in
                 git(root,"diff","--name-only","-z","HEAD","--").split(b"\0") if path][:40]
    except (OSError,ValueError,UnicodeError,subprocess.SubprocessError):
        pass
    return dict(schema=1,checkout=Path(root).name,platform=sys.platform,
                os_name=os.name,machine=platform.machine(),release=platform.release(),
                forced_file_mode=not windows_mode_projection(),status=bounded(status),
                git_version=observe("--version"),
                local_checkout_settings=observe("config","--local","--get-regexp",
                    r"^core\.(filemode|autocrlf|eol|safecrlf|symlinks|ignorecase)$"),
                raw_tracked_diff=observe("diff","--raw","--abbrev=40","--no-renames","HEAD","--"),
                changed_tracked_eol=observe("ls-files","--eol","--",*changed) if changed else
                    dict(total_lines=0,lines=[],truncated=False))



def windows_mode_projection():
    # Windows Git checkouts cannot represent the commit's POSIX executable bit.
    # This is a host property, never candidate configuration or a CLI exemption.
    return os.name == "nt"


def original_windows_tracked_files(root, expected):
    """Verify every committed mode/index object and unfiltered worktree byte."""
    committed = {}
    for entry in git(root, "ls-tree", "-r", "-z", "--full-tree", expected).split(b"\0"):
        if not entry:
            continue
        header, path = entry.split(b"\t", 1)
        mode, kind, blob = header.decode("ascii").split()
        if mode not in REGULAR_MODES or kind != "blob" or path in committed:
            raise ValueError("Windows source identity requires original regular tracked files")
        exact_sha(blob, "tracked source blob")
        committed[path] = (mode, blob)
    indexed = {}
    for entry in git(root, "ls-files", "--stage", "-z").split(b"\0"):
        if not entry:
            continue
        header, path = entry.split(b"\t", 1)
        mode, blob, stage = header.decode("ascii").split()
        if stage != "0" or path in indexed:
            raise ValueError("Windows source identity refuses ambiguous index stages")
        indexed[path] = (mode, blob)
    if indexed != committed:
        raise ValueError("Windows source index mode or object differs from captured commit")
    for raw_path, (_, blob) in committed.items():
        path = raw_path.decode("utf-8", "strict")
        target = root/path
        # A regular leaf under a substituted symlink/junction is not original.
        if (not path or Path(path).is_absolute() or ".." in Path(path).parts or
                target.resolve(strict=True) != target):
            raise ValueError("Windows tracked source path is not original: " + path)
        for component in (target, *target.parents):
            if component == root:
                break
            if component.is_symlink() or getattr(component, "is_junction", lambda: False)():
                raise ValueError("Windows tracked source path is linked: " + path)
        before = target.lstat()
        if not stat.S_ISREG(before.st_mode):
            raise ValueError("Windows tracked source is not regular: " + path)
        digest = hashlib.sha1(b"blob " + str(before.st_size).encode("ascii") + b"\0")
        with target.open("rb") as opened:
            captured = os.fstat(opened.fileno())
            if (captured.st_dev, captured.st_ino, captured.st_size, captured.st_mtime_ns) != (
                    before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                raise ValueError("Windows tracked source changed during capture: " + path)
            for chunk in iter(lambda: opened.read(1024*1024), b""):
                digest.update(chunk)
            after = os.fstat(opened.fileno())
        current = target.lstat()
        if ((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) !=
                (captured.st_dev, captured.st_ino, captured.st_size, captured.st_mtime_ns) or
                (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns) !=
                (captured.st_dev, captured.st_ino, captured.st_size, captured.st_mtime_ns) or
                not stat.S_ISREG(current.st_mode) or digest.hexdigest() != blob):
            raise ValueError("Windows tracked source bytes differ from captured Git blob: " + path)


def original_checkout(path, expected):
    path = Path(path)
    if path.is_symlink() or not path.is_dir():
        raise ValueError("source identity requires an original checkout directory")
    root = path.resolve(strict=True)
    top = git(root, "rev-parse", "--show-toplevel").decode("utf-8").strip()
    if Path(top).resolve(strict=True) != root:
        raise ValueError("source identity requires the complete checkout root")
    if git(root, "rev-parse", "--verify", "HEAD^{commit}").decode().strip() != expected:
        raise ValueError("checkout HEAD differs from its captured exact commit")
    index = git(root, "ls-files", "-v", "-z").split(b"\0")
    if any(entry and not entry.startswith(b"H ") for entry in index):
        raise ValueError("source identity refuses hidden index observation flags")
    # Ignored files also cannot silently become dependencies of the fixture.
    # All compiler outputs and Python bytecode belong outside these checkouts.
    if windows_mode_projection():
        original_windows_tracked_files(root, expected)
        # Only filesystem execute-bit projection is unobservable on Windows.
        # Commit/index modes and all raw bytes were checked above; dirty,
        # untracked and ignored paths still fail the original status gate.
        status = git(root, "-c", "core.fileMode=false", "status", "--porcelain=v1",
                     "--untracked-files=all", "--ignored=matching", "--ignore-submodules=none")
    else:
        status = git(root, "status", "--porcelain=v1", "--untracked-files=all", "--ignored=matching", "--ignore-submodules=none")
    if status:
        diagnostics = checkout_failure_diagnostics(root, status)
        raise ValueError("source identity refuses a dirty or untracked checkout; diagnostics=" +
                         json.dumps(diagnostics, sort_keys=True, ensure_ascii=True))
    return root


def commit_parents(root, commit):
    raw = git(root, "cat-file", "-p", commit)
    header = raw.split(b"\n\n", 1)[0]
    return [line[7:].decode("ascii") for line in header.splitlines() if line.startswith(b"parent ")]


def changed_files(root, base, source, suite):
    raw = git(root, "diff-tree", "--no-commit-id", "--no-renames", "--no-ext-diff",
              "--no-textconv", "--raw", "-r", "-z", "--full-index", base, source)
    fields = raw.split(b"\0")
    if fields[-1] != b"" or (len(fields)-1) % 2:
        raise ValueError("source identity received an incomplete raw tree diff")
    changes = []
    for index in range(0, len(fields)-1, 2):
        header = fields[index].decode("ascii").split()
        path = fields[index+1].decode("utf-8")
        if len(header) != 5 or not header[0].startswith(":"):
            raise ValueError("source identity received an ambiguous tree change")
        old_mode, new_mode, old_blob, new_blob, status = header
        old_mode = old_mode[1:]
        if path not in ALLOWLISTS[suite]:
            raise ValueError("candidate changed a path outside its exact suite allowlist")
        if status == "A":
            if old_mode != "000000" or new_mode != "100644" or old_blob != "0"*40:
                raise ValueError("new candidate files must be regular non-executable files")
        elif status == "M":
            if old_mode not in REGULAR_MODES or new_mode != old_mode:
                raise ValueError("candidate changed a file type or existing mode")
        else:
            raise ValueError("candidate deletion, rename, copy or type replacement is forbidden")
        exact_sha(old_blob, "old blob")
        exact_sha(new_blob, "new blob")
        if git(root, "cat-file", "-t", new_blob).strip() != b"blob":
            raise ValueError("candidate source is not an original regular blob")
        actual = root/path
        if actual.is_symlink() or not actual.is_file():
            raise ValueError("candidate worktree substituted a nonregular source")
        observed = hashlib.sha1(b"blob " + str(actual.stat().st_size).encode() + b"\0" +
                                actual.read_bytes()).hexdigest()
        if observed != new_blob:
            raise ValueError("candidate worktree bytes differ from the selected Git blob")
        changes.append(dict(path=path, status=status, old_mode=old_mode, new_mode=new_mode,
                            old_blob=old_blob, new_blob=new_blob))
    if len({change["path"] for change in changes}) != len(changes):
        raise ValueError("candidate repeated a changed source path")
    return sorted(changes, key=lambda change: change["path"])


def capture_identity(*, source, validator, source_sha, base_sha, suite, repository, workflow_ref):
    if repository != REPOSITORY or workflow_ref != WORKFLOW_REF:
        raise ValueError("focused validation is restricted to the original repository main workflow")
    if suite not in ALLOWLISTS:
        raise ValueError("focused validation requires an exact supported suite")
    exact_sha(source_sha, "source SHA")
    exact_sha(base_sha, "captured validator SHA")
    validator = original_checkout(validator, base_sha)
    source = original_checkout(source, source_sha)
    if source == validator or source.is_relative_to(validator) or validator.is_relative_to(source):
        raise ValueError("candidate and trusted validator require separate checkouts")
    if source_sha == base_sha:
        relation, changes = "base", []
    else:
        if commit_parents(source, source_sha) != [base_sha]:
            raise ValueError("candidate must have exactly the captured base as its single parent")
        relation = "single-parent"
        changes = changed_files(source, base_sha, source_sha, suite)
    base_tree = git(validator, "rev-parse", base_sha+"^{tree}").decode().strip()
    source_tree = git(source, "rev-parse", source_sha+"^{tree}").decode().strip()
    exact_sha(base_tree, "validator tree")
    exact_sha(source_tree, "candidate tree")
    if git(source, "rev-parse", base_sha+"^{tree}").decode().strip() != base_tree:
        raise ValueError("candidate parent differs from the original validator tree")
    # Recheck both original worktrees after all commit/blob observations.
    original_checkout(validator, base_sha)
    original_checkout(source, source_sha)
    return dict(schema=1, validation_scope="read-only-source-candidate", suite=suite,
                repository=repository, workflow_ref=workflow_ref,
                validator_sha=base_sha, validator_tree=base_tree,
                base_sha=base_sha, base_tree=base_tree, source_sha=source_sha,
                source_tree=source_tree, relation=relation, changes=changes)


def write_selection(path, metadata, *, source, validator):
    path = Path(path).absolute()
    if path.exists() or path.is_symlink():
        raise ValueError("selection metadata requires a fresh output file")
    for parent in path.parents:
        if parent.is_symlink():
            raise ValueError("selection metadata cannot traverse a linked directory")
    resolved = path.resolve()
    for root in (Path(source).resolve(strict=True), Path(validator).resolve(strict=True)):
        if resolved == root or resolved.is_relative_to(root):
            raise ValueError("selection metadata must remain outside both captured checkouts")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as output:
        json.dump(metadata, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())


class IdentityTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="focused-source-identity-")
        self.addCleanup(self.temporary.cleanup)
        self.work = Path(self.temporary.name)
        self.validator, self.source = self.work/"validator", self.work/"candidate"
        self.validator.mkdir()
        self.command(self.validator, "init", "-b", "main")
        self.configure(self.validator)
        for path in ("internal/mobilemultihop/node_chain_execution_proof.go",
                     "internal/mobilemultihop/node_chain_execution_runtime.go",
                     "internal/mobilemultihop/runtime.go", "internal/mobilemultihop/plan.go",
                     "android/test_android_tor_profile.py",
                     "android/test_android_node_candidate_preparation_owner.py", "deploy/trusted-validator.py",
                     ".github/workflows/trusted.yml", ".gitignore"):
            target = self.validator/path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("original source\n" if path != ".gitignore" else "*.ignored\n")
        (self.validator/"internal/mobilemultihop/plan.go").chmod(0o755)
        self.base = self.commit(self.validator, "original trusted source")
        self.command(self.work, "clone", "--no-hardlinks", str(self.validator), str(self.source))
        self.configure(self.source)

    def command(self, root, *args):
        result = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "-C", str(root), *args],
                                check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
        return result.stdout.decode().strip()

    def configure(self, root):
        self.command(root, "config", "user.name", "Identity fixture")
        self.command(root, "config", "user.email", "identity-fixture@example.invalid")
        self.command(root, "config", "core.fileMode", "true")
        self.command(root, "config", "commit.gpgsign", "false")

    def commit(self, root, message):
        self.command(root, "add", "-A")
        self.command(root, "commit", "-m", message)
        return self.command(root, "rev-parse", "HEAD")

    def edit(self, path, body="checked candidate\n"):
        target = self.source/path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(body)

    def capture(self, suite="ordered-clock", **overrides):
        args = dict(source=self.source, validator=self.validator,
                    source_sha=self.command(self.source, "rev-parse", "HEAD"), base_sha=self.base,
                    suite=suite, repository=REPOSITORY, workflow_ref=WORKFLOW_REF)
        args.update(overrides)
        return capture_identity(**args)

    def test_exact_base_and_deterministic_output(self):
        first = self.capture()
        self.assertEqual(first["relation"], "base")
        self.assertEqual(first["changes"], [])
        self.assertEqual(first, self.capture())
        destination = self.work/"outputs"/"selection.json"
        write_selection(destination, first, source=self.source, validator=self.validator)
        self.assertEqual(json.loads(destination.read_text()), first)
        with self.assertRaisesRegex(ValueError, "fresh"):
            write_selection(destination, first, source=self.source, validator=self.validator)

    def test_each_suite_accepts_only_its_exact_single_parent_files(self):
        for suite, paths in ALLOWLISTS.items():
            with self.subTest(suite=suite):
                self.command(self.source, "reset", "--hard", self.base)
                self.command(self.source, "clean", "-fdx")
                for path in paths: self.edit(path)
                child = self.commit(self.source, "bounded "+suite)
                captured = self.capture(suite)
                self.assertEqual(captured["relation"], "single-parent")
                self.assertEqual(captured["source_sha"], child)
                self.assertEqual({row["path"] for row in captured["changes"]}, paths)
                self.assertEqual(captured["validator_sha"], self.base)

    def test_existing_executable_mode_is_preserved_but_new_executable_is_refused(self):
        self.edit("internal/mobilemultihop/plan.go")
        self.commit(self.source, "preserved original executable mode")
        self.assertEqual(self.capture("legacy-clock")["changes"][0]["new_mode"], "100755")
        self.command(self.source, "reset", "--hard", self.base)
        self.edit("internal/mobilemultihop/runtime_proof_clock_test.go")
        (self.source/"internal/mobilemultihop/runtime_proof_clock_test.go").chmod(0o755)
        self.commit(self.source, "new executable refused")
        with self.assertRaisesRegex(ValueError, "non-executable"): self.capture("legacy-clock")

    def test_deletion_mode_change_and_symlink_are_refused(self):
        path = "internal/mobilemultihop/node_chain_execution_proof.go"
        for mutation in ("delete", "mode", "symlink"):
            with self.subTest(mutation=mutation):
                self.command(self.source, "reset", "--hard", self.base)
                self.command(self.source, "clean", "-fdx")
                target = self.source/path
                if mutation == "delete": target.unlink()
                elif mutation == "mode": target.chmod(0o755)
                else:
                    target.unlink(); target.symlink_to("node_chain_execution_runtime.go")
                self.commit(self.source, mutation)
                with self.assertRaises(ValueError): self.capture()

    def test_foreign_validator_workflow_and_other_suite_changes_are_refused(self):
        for path in ("deploy/trusted-validator.py", ".github/workflows/trusted.yml",
                     "android/test_android_tor_profile.py", "README.md"):
            with self.subTest(path=path):
                self.command(self.source, "reset", "--hard", self.base)
                self.command(self.source, "clean", "-fdx")
                self.edit(path)
                self.commit(self.source, "foreign path")
                with self.assertRaisesRegex(ValueError, "allowlist"): self.capture()

    def test_distant_child_merge_and_wrong_parent_are_refused(self):
        self.edit("internal/mobilemultihop/node_chain_execution_proof.go")
        first = self.commit(self.source, "first")
        self.edit("internal/mobilemultihop/node_chain_execution_runtime.go")
        second = self.commit(self.source, "second")
        with self.assertRaisesRegex(ValueError, "single parent"): self.capture()
        tree = self.command(self.source, "rev-parse", second+"^{tree}")
        merge = self.command(self.source, "commit-tree", tree, "-p", self.base, "-p", first, "-m", "merge refused")
        self.command(self.source, "reset", "--hard", merge)
        with self.assertRaisesRegex(ValueError, "single parent"): self.capture()
        with self.assertRaisesRegex(ValueError, "captured exact commit"):
            self.capture(base_sha=first)

    def test_tracked_untracked_ignored_and_validator_dirt_are_refused(self):
        for where, path in ((self.source, "internal/mobilemultihop/runtime.go"),
                            (self.source, "untracked.py"), (self.source, "hidden.ignored"),
                            (self.validator, "deploy/trusted-validator.py")):
            with self.subTest(where=where.name, path=path):
                for root in (self.source, self.validator):
                    self.command(root, "reset", "--hard", self.base)
                    self.command(root, "clean", "-fdx")
                (where/path).write_text("uncaptured bytes\n")
                with self.assertRaisesRegex(ValueError, "dirty or untracked"): self.capture()

    def test_hidden_index_flags_and_disabled_mode_observation_cannot_hide_dirt(self):
        path = "internal/mobilemultihop/node_chain_execution_proof.go"
        for flag in ("assume-unchanged", "skip-worktree"):
            with self.subTest(flag=flag):
                self.command(self.source, "update-index", "--"+flag, path)
                self.edit(path, "uncaptured masked source\n")
                with self.assertRaisesRegex(ValueError, "index observation flags"): self.capture()
                self.command(self.source, "update-index", "--no-"+flag, path)
                self.command(self.source, "reset", "--hard", self.base)
        self.command(self.source, "config", "core.fileMode", "false")
        (self.source/path).chmod(0o755)
        with self.assertRaisesRegex(ValueError, "dirty or untracked"): self.capture()

    def test_exact_sha_repository_ref_and_suite_are_required(self):
        for override in ({"source_sha": self.base.upper()}, {"source_sha": "main"},
                         {"source_sha": self.base[:-1]}, {"base_sha": "0"*39},
                         {"repository": "another/router-vpn"}, {"workflow_ref": "refs/heads/topic"},
                         {"suite": "all"}):
            with self.subTest(override=override), self.assertRaises(ValueError): self.capture(**override)

    def test_changed_files_cannot_be_reassigned_to_a_different_suite(self):
        self.edit("android/test_android_tor_profile.py")
        self.commit(self.source, "Tor fixture only")
        self.assertEqual(len(self.capture("android-tor")["changes"]), 1)
        for suite in ("ordered-clock", "legacy-clock"):
            with self.subTest(suite=suite), self.assertRaisesRegex(ValueError, "allowlist"): self.capture(suite)

    def test_exact_checkout_roots_and_external_output_are_required(self):
        linked = self.work/"linked-candidate"
        linked.symlink_to(self.source, target_is_directory=True)
        for source in (linked, self.source/"internal", self.validator):
            with self.subTest(source=str(source)), self.assertRaises(ValueError):
                self.capture(source=source)
        metadata = self.capture()
        for output in (self.source/"selection.json", self.validator/"selection.json"):
            with self.subTest(output=str(output)), self.assertRaisesRegex(ValueError, "outside"):
                write_selection(output, metadata, source=self.source, validator=self.validator)
        output_link = self.work/"linked-output"
        output_link.symlink_to(self.work, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "linked"):
            write_selection(output_link/"selection.json", metadata, source=self.source, validator=self.validator)



    def test_dirty_diagnostic_reports_actual_modes_eol_and_only_safe_settings(self):
        path="internal/mobilemultihop/node_chain_execution_proof.go"
        self.command(self.source,"config","core.fileMode","false")
        self.command(self.source,"config","core.autocrlf","false")
        self.command(self.source,"config","http.extraheader","private-header-must-not-print")
        before_tree=self.command(self.source,"rev-parse","HEAD^{tree}")
        (self.source/path).chmod(0o755)
        with self.assertRaisesRegex(ValueError,"dirty or untracked checkout") as caught:
            self.capture()
        record=json.loads(str(caught.exception).split("; diagnostics=",1)[1])
        self.assertEqual(record["checkout"],"candidate")
        self.assertTrue(record["forced_file_mode"])
        self.assertTrue(any(path in row for row in record["status"]["lines"]))
        self.assertTrue(any("100644 100755" in row for row in record["raw_tracked_diff"]["lines"]))
        self.assertTrue(any("core.filemode false" in row for row in record["local_checkout_settings"]["lines"]))
        self.assertTrue(any(path in row for row in record["changed_tracked_eol"]["lines"]))
        self.assertTrue(record["git_version"]["lines"][0].startswith("git version "))
        self.assertNotIn("private-header-must-not-print",str(caught.exception))
        self.assertEqual(self.command(self.source,"rev-parse","HEAD^{tree}"),before_tree)
        self.assertEqual((self.source/path).stat().st_mode & 0o111,0o111)

    def test_dirty_diagnostic_bounds_paths_without_contents_or_acceptance(self):
        for number in range(65):
            (self.source/("untracked-%03d.ignored"%number)).write_text("private-file-contents-must-not-print")
        with self.assertRaisesRegex(ValueError,"dirty or untracked checkout") as caught:
            self.capture()
        record=json.loads(str(caught.exception).split("; diagnostics=",1)[1])
        self.assertEqual(record["status"]["total_lines"],65)
        self.assertEqual(len(record["status"]["lines"]),40)
        self.assertTrue(record["status"]["truncated"])
        self.assertNotIn("private-file-contents-must-not-print",str(caught.exception))
        self.assertEqual(len(list(self.source.glob("untracked-*.ignored"))),65)
        self.assertEqual(self.command(self.source,"rev-parse","HEAD"),self.base)



    def test_windows_mode_projection_preserves_commit_index_and_all_raw_bytes(self):
        executable = "internal/mobilemultihop/plan.go"
        self.edit("internal/mobilemultihop/node_chain_execution_proof.go")
        child = self.commit(self.source, "real single parent candidate")
        for root in (self.validator, self.source):
            self.command(root, "config", "core.fileMode", "false")
            (root/executable).chmod(0o644)
        with mock.patch(__name__+".windows_mode_projection", return_value=True):
            result = self.capture()
        self.assertEqual(result["source_sha"], child)
        self.assertEqual(result["relation"], "single-parent")
        for root in (self.validator, self.source):
            self.assertTrue(self.command(root, "ls-files", "--stage", "--", executable).startswith("100755 "))
            self.assertEqual((root/executable).stat().st_mode & 0o111, 0)
            # The original forced POSIX observation would reject this projection.
            self.assertIn(executable, git(root, "status", "--porcelain=v1").decode())

    def test_windows_same_bytes_different_index_mode_and_object_are_refused(self):
        executable = "internal/mobilemultihop/plan.go"
        original = (self.source/executable).read_bytes()
        for change in ("mode", "object"):
            with self.subTest(change=change):
                self.command(self.source, "reset", "--hard", self.base)
                if change == "mode":
                    self.command(self.source, "update-index", "--chmod=-x", executable)
                else:
                    self.edit(executable, "different staged object\n")
                    self.command(self.source, "add", executable)
                    (self.source/executable).write_bytes(original)
                with mock.patch(__name__+".windows_mode_projection", return_value=True):
                    with self.assertRaisesRegex(ValueError, "index mode or object"):
                        self.capture()
                self.assertEqual((self.source/executable).read_bytes(), original)

    def test_windows_raw_bytes_eol_and_hidden_index_flags_remain_strict(self):
        path = "internal/mobilemultihop/node_chain_execution_proof.go"
        for change in ("same-size", "crlf", "assume-unchanged", "skip-worktree"):
            with self.subTest(change=change):
                self.command(self.source, "reset", "--hard", self.base)
                if change in ("assume-unchanged", "skip-worktree"):
                    self.command(self.source, "update-index", "--"+change, path)
                elif change == "crlf":
                    self.command(self.source, "config", "core.autocrlf", "true")
                original = (self.source/path).read_bytes()
                (self.source/path).write_bytes(original.replace(b"original", b"altered!") if change == "same-size"
                                               else original.replace(b"\n", b"\r\n"))
                with mock.patch(__name__+".windows_mode_projection", return_value=True):
                    with self.assertRaisesRegex(ValueError, "bytes differ|index observation flags"):
                        self.capture()
                if change in ("assume-unchanged", "skip-worktree"):
                    self.command(self.source, "update-index", "--no-"+change, path)
                self.command(self.source, "config", "core.autocrlf", "false")

    def test_windows_symlinked_leaf_and_parent_are_refused(self):
        target = self.source/"internal/mobilemultihop/node_chain_execution_proof.go"
        original = target.read_bytes()
        outside = self.work/"outside.go"
        outside.write_bytes(original)
        target.unlink()
        target.symlink_to(outside)
        with mock.patch(__name__+".windows_mode_projection", return_value=True):
            with self.assertRaisesRegex(ValueError, "path is not original|path is linked"):
                self.capture()
        target.unlink()
        self.command(self.source, "reset", "--hard", self.base)
        parent = self.source/"internal/mobilemultihop"
        moved = self.work/"outside-directory"
        parent.rename(moved)
        parent.symlink_to(moved, target_is_directory=True)
        with mock.patch(__name__+".windows_mode_projection", return_value=True):
            with self.assertRaisesRegex(ValueError, "path is not original|path is linked"):
                self.capture()

    def test_windows_ignored_and_untracked_outputs_are_still_refused(self):
        for name in ("untracked.py", "hidden.ignored"):
            with self.subTest(name=name):
                target = self.source/name
                target.write_text("unexpected build input\n")
                with mock.patch(__name__+".windows_mode_projection", return_value=True):
                    with self.assertRaisesRegex(ValueError, "dirty or untracked"):
                        self.capture()
                target.unlink()

    def test_windows_committed_mode_change_and_new_executable_still_fail(self):
        for path, change in (("internal/mobilemultihop/plan.go", "existing"),
                             ("internal/mobilemultihop/runtime_proof_clock_test.go", "new")):
            with self.subTest(change=change):
                self.command(self.source, "reset", "--hard", self.base)
                self.command(self.source, "clean", "-fdx")
                if change == "existing":
                    (self.source/path).chmod(0o644)
                else:
                    self.edit(path)
                    (self.source/path).chmod(0o755)
                self.commit(self.source, "forbidden committed mode")
                for root in (self.validator, self.source):
                    (root/"internal/mobilemultihop/plan.go").chmod(0o644)
                if change == "new":
                    (self.source/path).chmod(0o644)
                with mock.patch(__name__+".windows_mode_projection", return_value=True):
                    with self.assertRaisesRegex(ValueError, "existing mode|non-executable"):
                        self.capture("legacy-clock")


    def test_actual_cli_binds_its_validator_checkout_and_workflow_sha(self):
        helper = self.validator/"deploy"/"focused_source_identity.py"
        helper.write_bytes(Path(__file__).read_bytes())
        self.base = self.commit(self.validator, "capture the original trusted validator")
        self.command(self.source, "fetch", "origin")
        self.command(self.source, "reset", "--hard", self.base)
        environment = dict(os.environ, GITHUB_REPOSITORY=REPOSITORY, GITHUB_REF=WORKFLOW_REF,
                           GITHUB_SHA=self.base, PYTHONDONTWRITEBYTECODE="1")
        output = self.work/"cli-selection.json"
        arguments = ["python3", str(helper), "--suite", "ordered-clock", "--source", str(self.source),
                     "--source-sha", self.base, "--base-sha", self.base, "--output", str(output)]
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr.decode())
        self.assertEqual(json.loads(output.read_text())["validator_sha"], self.base)
        output.unlink()
        environment["GITHUB_SHA"] = "0"*40
        result = subprocess.run(arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                env=environment, timeout=30)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(output.exists())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--suite", choices=tuple(ALLOWLISTS))
    parser.add_argument("--source", type=Path)
    parser.add_argument("--source-sha")
    parser.add_argument("--base-sha")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.self_test:
        if any((args.suite, args.source, args.source_sha, args.base_sha, args.output)):
            parser.error("self-tests cannot select candidate inputs")
        result = unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(IdentityTests))
        return 0 if result.wasSuccessful() else 1
    if any(value is None for value in (args.suite, args.source, args.source_sha, args.base_sha, args.output)):
        parser.error("suite, source, source-sha, base-sha and fresh output are required")
    if os.environ.get("GITHUB_SHA") != args.base_sha:
        raise ValueError("captured workflow SHA differs from the original validator base")
    validator = Path(__file__).resolve().parents[1]
    metadata = capture_identity(source=args.source, validator=validator, source_sha=args.source_sha,
                                base_sha=args.base_sha, suite=args.suite,
                                repository=os.environ.get("GITHUB_REPOSITORY"),
                                workflow_ref=os.environ.get("GITHUB_REF"))
    write_selection(args.output, metadata, source=args.source, validator=validator)
    print(json.dumps(metadata, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
