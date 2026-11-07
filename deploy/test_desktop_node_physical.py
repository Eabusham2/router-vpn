#!/usr/bin/env python3
"""Execute the exact Node compiler, native startup, IPC and encrypted peers.

The generated Box/lower/command bytes are shipping source. Privileged permits
and TUN are explicit composition boundaries; this does not claim kernel WFP,
live node/DNS proof, legacy transfer or physical-device acceptance. Windows
factory cases still execute the actual captured interface/DHCP and handoff path.
"""
from pathlib import Path
import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import platform
import re
import signal
import shutil
import stat
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("desktop_node_bootstrap", ROOT / "deploy/test_windows_physical_bootstrap.py")
BOOT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BOOT)
PREP = BOOT.PREP
TAGS = tuple(value for value in BOOT.TAGS if value not in ("routervpn_native_pq", "routervpn_windows_physical_composition"))
OPENVPN_CAPACITY_PARENT = "TestRouterVPNOpenVPNConnectedCapacityUserspace"
OPENVPN_CAPACITY_VERDICTS = (OPENVPN_CAPACITY_PARENT,) + tuple(
    OPENVPN_CAPACITY_PARENT + "/" + network + "/" + outcome
    for network in ("tcp", "udp") for outcome in ("success", "wrong-password"))
OPENVPN_CAPACITY_SUITE = ("openvpn-connected-capacity", "./protocol/routervpnamnezia",
                          "^" + OPENVPN_CAPACITY_PARENT + "$", OPENVPN_CAPACITY_VERDICTS)
MTU_CONTEXT_VERDICTS = {
    "mtu-operation-context": [
        "TestContextOperationAdmissionAndStatusDoNotLeaveWaiters",
        "TestContextOwnerRequiredWithoutLegacyFallback", "TestContextCaptureLateResultCannotAdmitMutation",
        "TestContextOriginalCleanupDeadlineCannotBeRenewed", "TestContextRollbackUsesReturnedTransactionAfterUnpublishedCandidate",
        "TestContextAdmissionCallbackAndWorkerPublishOneGeneration", "TestContextMailboxAdmissionDoesNotOwnAcceptedWorkerLifetime",
        "TestContextLateAdmissionAcknowledgementDrainsWithoutMutation",
        "TestContextLegacyControllerUsesConstructedAvailability",
        *["TestContextLegacyControllerUsesConstructedAvailability/" + name for name in ("legacy-owner", "context-owner")],
        "TestContextUnavailableCaptureRejectsStrictConstructorAndAdmission",
        *["TestContextUnavailableCaptureRejectsStrictConstructorAndAdmission/" + name for name in ("constructor", "run", "start", "admission", "separate-admission")],
        "TestContextAvailableCaptureFailureNeverFallsBack",
        *["TestContextAvailableCaptureFailureNeverFallsBack/" + name for name in ("native-error", "late-cancel")],
        *["TestContextOperationAdmissionAndStatusDoNotLeaveWaiters/" + name for name in ("start", "status", "cancel", "close")],
        *["TestContextRollbackUsesReturnedTransactionAfterUnpublishedCandidate/" + name for name in ("cancel-after-mutation", "failed-candidate", "replaced-owner")]],
    "mtu-owner-context": [
        "TestDesktopMTUContextCaptureOwnsDeadlineAndPreservesHealthyReader", "TestDesktopMTUContextRollbackOnlyRetainsOriginalPendingReader",
        "TestDesktopMTUContextCaptureAvailabilityPreservesOriginalOwner",
        *["TestDesktopMTUContextCaptureOwnsDeadlineAndPreservesHealthyReader/" + name for name in ("owner", "lease")],
        *["TestDesktopMTUContextRollbackOnlyRetainsOriginalPendingReader/" + name for name in ("original", "new-caller", "new-reader")]],
    "mtu-manager-context": [
        "TestRouterVPNTunContextRejectsLatePublicationAfterUnusedClose", "TestRouterVPNTunContextAdmissionLocksDoNotConstructLate",
        *["TestRouterVPNTunContextAdmissionLocksDoNotConstructLate/" + name for name in ("lifecycle", "access")]],
    "mtu-cleanup-context": ["TestRouterVPNTunContextRestoresOnlyWithOriginalCleanupAllowance", "TestRouterVPNTunContextControllerRestoresAfterUnusedCloseCancellation",
        *["TestRouterVPNTunContextRestoresOnlyWithOriginalCleanupAllowance/" + name for name in ("restores", "expired-cleanup")]],
    "mtu-startup-context": ["TestRouterVPNDesktopMTUStartupContextLifecycleDeadline"],
    "mtu-finalization-context": ["TestRouterVPNMTUFinalizationContextPreservesOriginalCleanup", *["TestRouterVPNMTUFinalizationContextPreservesOriginalCleanup/" + name for name in ("readback", "physical-rebind", "mixed-failure", "cleanup-expired")]],
}
STARTUP_CONTEXT_VERDICTS = {
    "native-startup-inbound": ["TestRouterVPNDesktopNetworkStartupKeepsOriginalBudget", *["TestRouterVPNDesktopNetworkStartupKeepsOriginalBudget/" + leaf for leaf in ("held-lock", "deadline", "lifetime")]],
    "native-startup-box": ["TestRouterVPNDesktopStartupKeepsCallerAndLifetime", *["TestRouterVPNDesktopStartupKeepsCallerAndLifetime/" + leaf for leaf in ("original", "expired", "late-success", "missing-reader", "no-deadline")]],
    "native-startup-command": ["TestRouterVPNRawCommandOriginalStartupDeadline", *["TestRouterVPNRawCommandOriginalStartupDeadline/" + leaf for leaf in ("cli-bound", "shorter-caller", "expired")]],
}
STARTUP_TRANSPORT_VERDICTS = {
    "native-startup-transport": [name for stem, leaves in (
        ("TestRouterVPNDesktopStartupEnvelopeControlsOriginalCommand", ("missing", "substituted", "late-success")),
        ("TestRouterVPNDesktopStartupEnvelopeControlsOriginalTor", ("missing", "substituted", "late-success")),
        ("TestRouterVPNDesktopHeartbeatKeepsObservationBudget", ("healthy", "pure-expiry", "mixed-loss")),
        ("TestRouterVPNDesktopTorProcessKeepsOriginalStartup", ("held-launch", "held-authentication", "original-authentication-deadline", "healthy-lifetime"))) for name in (stem, *(stem + "/" + leaf for leaf in leaves))],
    "native-startup-codec": ["TestDesktopStartupAdmissionKeepsOriginalDeadline", *["TestDesktopStartupAdmissionKeepsOriginalDeadline/" + leaf for leaf in
        ("original", "duplicate", "unknown", "substituted-session", "substituted-source", "substituted-config", "wrong-kind", "expired", "shorter-caller")]],
}
TOR_REGISTRATION_VERDICTS = {
    "tor-registration-owner": ["TestRouterVPNPhysicalRegistrationKeepsOriginalCaller", *["TestRouterVPNPhysicalRegistrationKeepsOriginalCaller/" + leaf for leaf in ("held-lock", "expired", "no-deadline", "late-publication", "live")]],
    "tor-registration-policy": ["TestRouterVPNLinuxPhysicalPolicyRegistrationContext", *["TestRouterVPNLinuxPhysicalPolicyRegistrationContext/" + leaf for leaf in ("held-policy-owner", "foreign-source")]],
    "tor-registration-box": ["TestRouterVPNDesktopTorPhysicalRegistrationContext", *["TestRouterVPNDesktopTorPhysicalRegistrationContext/" + leaf for leaf in ("expired", "no-deadline", "live")]],
}
LAYER_CASES = tuple(mode + "/" + layer for mode in ("shadowsocks", "hysteria2", "wg", "awg2-fast", "awg2-strong")
                    for layer in ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening")
                    if mode in ("shadowsocks", "hysteria2") or layer != "off")
LAYER_ALLOCATION_CASES = tuple("paired-listeners/" + case for case in (
    "retained-pair", "collision-bound", "access-denied-bound", "fatal-error", "foreign-pair",
    "candidate-selection", "retry-both-protocols", "udp-collision-bound", "udp-access-denied-bound",
    "udp-fatal-error", "udp-foreign-pair", "partial-close-error"))
HYSTERIA2_CREDENTIAL_CASES = (
    "off/hysteria-password", "off/hysteria-trust", "off/hysteria-salamander",
    "aes-256-gcm/hysteria-password", "aes-256-gcm+xor-whitening/hysteria-password",
    "aes-256-gcm/aes-key", "aes-256-gcm+xor-whitening/aes-key",
    "aes-256-gcm/hysteria-trust", "aes-256-gcm+xor-whitening/hysteria-trust",
    "aes-256-gcm/hysteria-salamander", "aes-256-gcm+xor-whitening/hysteria-salamander")
HYSTERIA2_IDENTITY_CASES = tuple(layer + "/" + identity for layer in ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening")
                                for identity in ("ip-absent", "ip-empty", "ip-wrong-certificate"))
HYSTERIA2_COVER_CASES = tuple(layer + "/" + fault for layer in ("aes-256-gcm", "aes-256-gcm+xor-whitening")
                             for fault in ("owned", "wrong-node", "drop-cover"))
HYSTERIA2_SUITES = (
    ("hysteria2-credentials", "./protocol/routervpnamnezia",
     "^TestRouterVPNDesktopNodeHysteria2(WrongCredential|WrongWhitening)$",
     ("TestRouterVPNDesktopNodeHysteria2WrongCredential", "TestRouterVPNDesktopNodeHysteria2WrongWhitening")),
    ("hysteria2-identity", "./protocol/routervpnamnezia",
     "^TestRouterVPNDesktopNodeHysteria2(LayerTLSIdentity|ReferenceCapture)$",
     ("TestRouterVPNDesktopNodeHysteria2LayerTLSIdentity", "TestRouterVPNDesktopNodeHysteria2ReferenceCapture")),
    ("hysteria2-cover", "./protocol/routervpnamnezia",
     "^TestRouterVPNDesktopNodeHysteria2(LayerCover|OuterCannotBypassFinal)$",
     ("TestRouterVPNDesktopNodeHysteria2LayerCover", "TestRouterVPNDesktopNodeHysteria2OuterCannotBypassFinal")),
)
NETWORK_CONTEXT_TESTS = tuple("TestRouterVPNDesktopNetwork" + name for name in (
    "ReceiptOriginalContext", "ReceiptHeldLifecycle", "ContextClaimRetainsGuard", "ReceiptUnavailable"))
NETWORK_CONTEXT_LEAVES = tuple(NETWORK_CONTEXT_TESTS[0] + "/" + name for name in (
    "live", "guard-cancel", "interface-cancel", "receipt-cancel", "changed-index"))

NATIVE_MTU_TEST = "TestRouterVPNNativeLinuxMTUTransactionNamespace"
LINUX_LAYERED_ENTRY_SUITE = ("linux-layered-external-entry", "./routervpn/desktoppt", "^TestRouterVPNExternalPhysicalLinuxLayeredEntryOwnsOnlyOriginalRoot$",
    ("TestRouterVPNExternalPhysicalLinuxLayeredEntryOwnsOnlyOriginalRoot", *("TestRouterVPNExternalPhysicalLinuxLayeredEntryOwnsOnlyOriginalRoot/" + case for case in ("wg-entry-hysteria2-aes", "wg-entry-hysteria2-aes-xor"))))
LINUX_SS_ENTRY_SUITE = ("linux-ss-external-entry", "./routervpn/desktoppt", "^TestRouterVPNExternalPhysicalLinuxSSEntryOwnsOriginalTCPAndUDP$",
    ("TestRouterVPNExternalPhysicalLinuxSSEntryOwnsOriginalTCPAndUDP", *("TestRouterVPNExternalPhysicalLinuxSSEntryOwnsOriginalTCPAndUDP/" + case for case in ("tcp", "udp", "cancelled"))))
SS_ENTRY_REFERENCE_ROOT = "TestRouterVPNDesktopInstalledSSEntryLoopbackTwoHopReference"
SS_ENTRY_REFERENCE_SUITE = ("ss-entry-two-hop-reference", "./protocol/routervpnamnezia", "^(" + SS_ENTRY_REFERENCE_ROOT + "|TestRouterVPNDesktopSSEntryAuthenticationWitness)$",
    ("TestRouterVPNDesktopSSEntryAuthenticationWitness", SS_ENTRY_REFERENCE_ROOT, *(SS_ENTRY_REFERENCE_ROOT + "/method%d-method%d" % (entry, final) for entry in range(3) for final in range(3)),
     *(SS_ENTRY_REFERENCE_ROOT + "/negative/" + fault for fault in ("entry-key", "entry-method", "final-key", "final-method", "final-route", "dns-route"))))
LINUX_SS_CONNECT_ROOT = "TestRouterVPNExternalPhysicalLinuxSSCONNECTOwnsOnlyOriginalTCP"
LINUX_SS_CONNECT_SUITE = ("linux-ss-connect-entry", "./routervpn/desktoppt", "^" + LINUX_SS_CONNECT_ROOT + "$",
    (LINUX_SS_CONNECT_ROOT, *(LINUX_SS_CONNECT_ROOT + "/" + case for case in ("ss-entry-http", "ss-entry-https"))))
SS_CONNECT_REFERENCE_ROOT = "TestRouterVPNDesktopInstalledSSCONNECTLoopbackReference"
SS_CONNECT_REFERENCE_SUITE = ("ss-connect-two-hop-reference", "./protocol/routervpnamnezia", "^" + SS_CONNECT_REFERENCE_ROOT + "$",
    (SS_CONNECT_REFERENCE_ROOT, *(SS_CONNECT_REFERENCE_ROOT + "/method%d-%s" % (method, protocol) for method in range(3) for protocol in ("http-connect", "https-connect")),
     *(SS_CONNECT_REFERENCE_ROOT + "/negative/" + fault for fault in ("entry-key", "entry-method", "username", "password", "server-name", "trust", "final-route", "dns-route"))))
SS_INDEPENDENT_LAYERS_ROOT = "TestRouterVPNDesktopSSIndependentLayersReference"
SS_INDEPENDENT_LAYERS_PROCESS_ROOT = "TestRouterVPNDesktopSSIndependentLayersProviderProcess"
SS_INDEPENDENT_LAYERS_SUITE = ("ss-independent-layers-reference", "./protocol/routervpnamnezia", "^(" + SS_INDEPENDENT_LAYERS_ROOT + "|" + SS_INDEPENDENT_LAYERS_PROCESS_ROOT + ")$",
    (SS_INDEPENDENT_LAYERS_ROOT, *(SS_INDEPENDENT_LAYERS_ROOT + "/method%d-method%d/layer%d-layer%d" % (entry, final, first, last)
      for entry in range(3) for final in range(3) for first in range(3) for last in range(3)),
     *(SS_INDEPENDENT_LAYERS_ROOT + "/negative/" + fault for fault in ("entry-key", "final-key", "entry-layer-key", "final-layer-key", "entry-whitening", "final-whitening", "entry-private", "final-private", "dns-route")), SS_INDEPENDENT_LAYERS_PROCESS_ROOT, *(SS_INDEPENDENT_LAYERS_PROCESS_ROOT + "/layer%d-layer%d" % (entry, final) for entry in range(3) for final in range(3))))

SS_HYSTERIA_REFERENCE_ROOT = "TestRouterVPNDesktopInstalledSSHysteriaLoopbackReference"
SS_HYSTERIA_LAYERS_ROOT = "TestRouterVPNDesktopSSHysteriaIndependentLayersReference"
SS_HYSTERIA_REFERENCE_SUITE = ("ss-hysteria-two-hop-reference", "./protocol/routervpnamnezia", "^(" + SS_HYSTERIA_REFERENCE_ROOT + "|" + SS_HYSTERIA_LAYERS_ROOT + ")$",
    (SS_HYSTERIA_REFERENCE_ROOT, *(SS_HYSTERIA_REFERENCE_ROOT + "/method%d-hysteria2" % method for method in range(3)),
     *(SS_HYSTERIA_REFERENCE_ROOT + "/negative/" + fault for fault in ("entry-key", "entry-method", "password", "server-name", "trust", "final-route", "dns-route")), SS_HYSTERIA_LAYERS_ROOT,
     *(SS_HYSTERIA_LAYERS_ROOT + "/method%d/layer%d-layer%d" % (method, entry, final) for method in range(3) for entry in range(3) for final in range(3)),
     *(SS_HYSTERIA_LAYERS_ROOT + "/negative/" + fault for fault in ("entry-key", "entry-method", "password", "server-name", "trust", "final-route", "dns-route", "entry-layer-key", "final-layer-key", "entry-whitening", "final-whitening"))))
STANDARD_MTU_SUITE = ("standard-mtu-original-reader", "./cmd/sing-box",
                      "^TestRouterVPNStandardMTUActualBox(KeepsOriginalReader|RequiresNativeClaim)$",
                      ("TestRouterVPNStandardMTUActualBoxKeepsOriginalReader", "TestRouterVPNStandardMTUActualBoxRequiresNativeClaim",
                       *("TestRouterVPNStandardMTUActualBoxRequiresNativeClaim/"+case for case in
                         ("unstarted-native", "foreign-reader", "cancelled", "unbounded", "guard-loss", "wrong-tag", "invalid-receipt"))))
# FD10 intentionally accepts only a root-owned, size-locked original memfd.
# Retire the unstarted reader under that real privilege boundary; admission
# and foreign-reader refusal above remain ordinary unprivileged tests.
STANDARD_MTU_RETIRE_SUITE = ("standard-mtu-retire-original-reader", "./cmd/sing-box",
                            "^TestRouterVPNStandardMTUActualBoxRetiresUnstartedReader$",
                            ("TestRouterVPNStandardMTUActualBoxRetiresUnstartedReader",
                             *("TestRouterVPNStandardMTUActualBoxRetiresUnstartedReader/"+case for case in ("original", "cancelled-retry"))))
STANDARD_MTU_NATIVE_SUITE = ("standard-mtu-claim-retirement", "./cmd/sing-box",
                             "^TestRouterVPNStandardMTUNativeClaimFailureNamespace$",
                             ("TestRouterVPNStandardMTUNativeClaimFailureNamespace",
                              *("TestRouterVPNStandardMTUNativeClaimFailureNamespace/"+case for case in ("post-grant-failure", "post-grant-cancel"))))
STANDARD_PARENT_SUITE = ("standard-parent-retirement", "./cmd/sing-box",
                         "^TestRouterVPNStandardParentRetirementMilestone$",
                         ("TestRouterVPNStandardParentRetirementMilestone",
                          *("TestRouterVPNStandardParentRetirementMilestone/"+case for case in
                            ("pre-ready", "pre-ready-expired", "post-ready-expired", "post-ready-retry", "normal-stop"))))
STANDARD_PARENT_NATIVE_SUITE = ("standard-idle-parent-loss", "./cmd/sing-box",
                                "^TestRouterVPNStandardIdleParentNamespace$",
                                ("TestRouterVPNStandardIdleParentNamespace",
                                 "TestRouterVPNStandardIdleParentNamespace/idle-after-startup-expiry"))
STANDARD_RESOLVED_SUITE = ("standard-resolved-observation", "./cmd/sing-box", "^TestRouterVPNResolvedFixedCommandObservation$",
                          ("TestRouterVPNResolvedFixedCommandObservation", *("TestRouterVPNResolvedFixedCommandObservation/"+case for case in
                           ("success", "lost-parent", "lost-daemon", "local-refusal", "wrong-local-name", "wrong-policy", "lost-send", "late-parent", "cancelled"))))
NATIVE_MTU_CASES = ("full-search-and-winner", "failed-candidate-and-original-restore", "cancelled-work-and-fresh-stop")
NATIVE_MTU_MODEL_TESTS = tuple("TestRouterVPNTun" + name for name in ("ReplacementAndRollback", "FailureDoesNotStartAnOverlappingReader", "InvalidationAndStaleCapture", "MutationIsSerialized", "TransactionRetainsOriginalAndPartialCandidateEvidence", "TransactionPreservesFailedConstructionAndRetry", "TransactionBoundsHistoryBeforeAcquisition", "TransactionCancelledAcquisitionAndNativeClose", "BorrowedPlatformKeepsCapturedRollback", "FullSearchRetainsEveryOriginalAttempt"))
# Admission and cleanup context cases have their own mandatory exact suites.
# Keep this transaction inventory disjoint when new manager tests are added.
NATIVE_MTU_MODEL_SUITE = ("mtu-transaction-model", "./adapter/inbound",
                        "^(" + "|".join(NATIVE_MTU_MODEL_TESTS) + ")$", NATIVE_MTU_MODEL_TESTS)

NATIVE_RESOLVER_TESTS = tuple("TestRouterVPNNativeLinuxResolver" + name for name in (
    "DaemonCapability", "CredentialRefusals", "MutationNeedsOriginalReply", "LateReplyRetry",
    "RejectsReplacedCapability", "OriginalWireSerial", "RetireRequiresBound", "StartupBound",
    "OriginalUnixConnection", "ObservedBusAbsence", "DefinitelyUnsentRetires", "ClosesDecodedFDArrays", "NamedBusNamespace", "ResolvedAuthorityOriginalBroker", "ResolvedAuthorityPropertyCodec", "ResolvedAuthoritySignalIdentity", "ResolvedAnchorWireCodec", "ResolvedServerMonitor", "ResolvedServerPIDMapping", "ResolvedRootDSErrors"))
NATIVE_RESOLVER_LEAVES = {
    "ResolvedRootDSErrors": ("synthetic", "strict", "wrong-mode", "no-source", "foreign", "timeout", "downgrade-no-trust"),
    "ResolvedServerPIDMapping": ("native-original", "same", "nested", "wrong-proc", "missing", "duplicate", "zero", "overflow"),
    "ResolvedServerMonitor": ("original", "foreign-pid", "foreign-uid", "renamed-socket", "cancelled", "incomplete", "extra-frame", "oversized"),
    "ResolvedAnchorWireCodec": ("anchor-ds", "anchor-dnskey", "anchor-ad-only", "anchor-network", "anchor-cache", "anchor-name", "anchor-index", "anchor-type", "anchor-revoked"),
    "ResolvedAuthorityOriginalBroker": ("local-hosts", "local-synthetic", "no-local-source", "remote-error", "network-origin", "cache-origin", "unauthenticated", "policy-port", "physical-owner", "daemon-signal", "foreign-signal", "anchor-ds", "anchor-dnskey", "anchor-absent", "anchor-ad-only", "anchor-network", "anchor-cache", "anchor-name", "anchor-index", "anchor-type", "anchor-revoked", "anchor-policy-change", "anchor-error", "root-ds-positive", "root-ds-synthetic", "root-ds-strict", "root-ds-wrong-mode", "root-ds-no-source", "root-ds-foreign-error", "root-ds-downgrade-no-trust", "root-ds-policy-change"),
    "NamedBusNamespace": ("original-authenticated", "replaced-endpoint", "untrusted-ancestor", "cancelled-original-child", "resolved-authority", "resolved-authority-namespace", "resolved-authority-daemon-namespace"),
    "CredentialRefusals": ("missing-processfd", "invalid-processfd", "foreign-namespace", "unreceived-file"),
    "MutationNeedsOriginalReply": ("bus-no-reply", "foreign-owner", "wrong-serial", "transport-only"),
    "LateReplyRetry": ("success", "daemon-error"),
    "RejectsReplacedCapability": ("pidfd-pointer", "pidfd-descriptor", "proc-pointer", "namespace-pointer", "image-pointer"),
    "StartupBound": ("native-ten-second-cap", "inherited-earlier-bound", "cancelled-original"),
    "ObservedBusAbsence": ("missing", "present-not-socket"),
    "ClosesDecodedFDArrays": tuple(shape + "/matched-" + matched for shape in
        ("array", "variant-array", "dictionary-array", "structure-array", "dictionary-key", "dictionary-value")
        for matched in ("false", "true")),
}

NATIVE_DBUS_TESTS = ("TestRouterVPNDBusReceivedRightsRetireOnError", "TestRouterVPNDBusFDAndOrdinaryContainerTypes")
NATIVE_DBUS_CASES = ("invalid-index", "advertised-count", "zero-count", "unreferenced",
                     "malformed-body", "invalid-header", "partial-header", "partial-body")

NATIVE_DNS_CASES = ("ipv4-host-without-dns", "ipv4-host-with-explicit-dns",
                    "ipv6-host-without-dns", "ipv6-fallback")

NATIVE_LIFECYCLE_ADMISSION_TESTS = ("TestRouterVPNNativeLinuxLifecycleAdmissionHeldCaller", "TestRouterVPNNativeLinuxLifecycleAdmissionRechecksQueuedIdentity", "TestRouterVPNNativeLinuxLifecycleAdmissionRejectsLateIdentity", "TestRouterVPNNativeLinuxRetirementLateCloseKeepsOriginalMilestone", "TestRouterVPNNativeLinuxUpdateRetainsOriginalLifetimeAndCaller")
NATIVE_LIFECYCLE_ADMISSION_VERDICTS = [*NATIVE_LIFECYCLE_ADMISSION_TESTS, *[root+"/"+action for root in NATIVE_LIFECYCLE_ADMISSION_TESTS[:2] for action in ("retire", "start", "update", "reset")], *[NATIVE_LIFECYCLE_ADMISSION_TESTS[2]+"/"+action for action in ("retire", "update")]]

NATIVE_ADDRESS_RETIREMENT_TESTS = ("TestRouterVPNNativeLinuxPartialAddressRetirement", "TestRouterVPNNativeLinuxAddressBoundaryRejectsForeignEffects", "TestRouterVPNNativeLinuxAddressPolicyNetlink")
NATIVE_ADDRESS_RETIREMENT_VERDICTS = [NATIVE_ADDRESS_RETIREMENT_TESTS[0], *[NATIVE_ADDRESS_RETIREMENT_TESTS[0]+"/"+name for name in ("partial-add-refusal", "cancel-after-add", "link-up-addrconf", "link-up-eui64-random", "dad-completion")], NATIVE_ADDRESS_RETIREMENT_TESTS[1], *[NATIVE_ADDRESS_RETIREMENT_TESTS[1]+"/"+name for name in ("global", "wrong-protocol", "missing-protocol", "label", "finite-lifetime", "pre-existing", "changed-policy", "same-name-replacement", "eexist", "address-aba", "missing-notification", "cancel-after-link-up", "eui64-ethernet", "eui64-already-up", "eui64-still-down", "eui64-type-change", "eui64-missing-policy", "eui64-disappeared-policy", "eui64-wrong-address-flags", "eui64-stable-change", "eui64-index-change", "eui64-flags-change", "eui64-token-change", "unchanged-still-down")], NATIVE_ADDRESS_RETIREMENT_TESTS[2], *[NATIVE_ADDRESS_RETIREMENT_TESTS[2]+"/"+name for name in ("eui64-down", "random-up", "none", "absent", "duplicate", "invalid", "truncated", "token", "invalid-token")]]

NATIVE_ADDRESS_RETIREMENT_TESTS += ("TestRouterVPNNativeLinuxAutomaticAddressWait", "TestRouterVPNNativeLinuxAddressWatchWake")
NATIVE_ADDRESS_RETIREMENT_VERDICTS += [name for root, leaves in (
    ("TestRouterVPNNativeLinuxAutomaticAddressWait", ("delayed", "cancel-then-retire", "missing", "foreign", "duplicate", "dad-failed", "changed-readback")),
    ("TestRouterVPNNativeLinuxAddressWatchWake", ("queued", "wake", "cancel", "joined"))) for name in (root, *(root + "/" + leaf for leaf in leaves))]

NATIVE_ADDRESS_RETIREMENT_TESTS += ("TestRouterVPNNativeLinuxAddressRetirementClosedEvents",)
NATIVE_ADDRESS_RETIREMENT_VERDICTS += ["TestRouterVPNNativeLinuxAddressRetirementClosedEvents", *["TestRouterVPNNativeLinuxAddressRetirementClosedEvents/" + leaf for leaf in (
    "first-close", "late-final-ipv4", "late-final-ipv6", "late-final-linklocal", "duplicate-first", "duplicate-final", "owned-add", "foreign-address", "changed-native", "before-close", "file-open", "guard-open")]]

NATIVE_CLOSED_EVENT_ROOT = "TestRouterVPNNativeLinuxRoutingRetirementClosedEventDiagnostics"
NATIVE_CLOSED_EVENT_CASES = ("first-close", "late-final", "late-final-ipv6", "late-final-linklocal", "duplicate-first", "duplicate-final", "owned-add", "foreign-first", "foreign-final", "changed-native", "changed-address-policy", "disjoint")
NATIVE_CLOSED_EVENT_VERDICTS = (NATIVE_CLOSED_EVENT_ROOT, *(NATIVE_CLOSED_EVENT_ROOT + "/" + case for case in NATIVE_CLOSED_EVENT_CASES))

NATIVE_RETIREMENT_CASES = (
    "complete-original-retirement", "partial-address-before-ready", "foreign-address", "address-aba", "fresh-stop-after-startup-cancel", "definite-add-refusal",
    "persistent-disjoint-route", "same-selector-aba", "foreign-wildcard-match", "replaced-file-object")

XRAY_MODES = ("reality-vision", "reality-pq-vision", "reality-xhttp")
XRAY_CASES = tuple(mode + "/" + layer for mode in XRAY_MODES
                   for layer in ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening"))
XRAY_CREDENTIAL_CASES = (*XRAY_CASES, "reality-pq-vision/off/xray-pq-key", "reality-xhttp/off/xray-pq-key",
                         "reality-vision/off/xray-user", "reality-vision/aes-256-gcm/aes-key",
                         "reality-vision/aes-256-gcm+xor-whitening/aes-key")
NAIVE_MODES = ("naive-h2", "naive-h3")
NAIVE_CASES = tuple(mode + "/" + layer for mode in NAIVE_MODES
                    for layer in ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening"))
NAIVE_CREDENTIAL_CASES = (*NAIVE_CASES, *(mode + "/" + case for mode in NAIVE_MODES for case in (
    "off/naive-user", "off/naive-server-name", "off/naive-certificate", "aes-256-gcm/aes-key", "aes-256-gcm+xor-whitening/aes-key")))
COMPOSITE_MODES = ("split", "max", "ss-v2ray")
COMPOSITE_CASES = tuple(mode + "/" + layer for mode in COMPOSITE_MODES
                       for layer in ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening"))
COMPOSITE_ALLOCATION_CASES = ("retained-udp-owner", *("distinct-ports/" + case for case in (
    "retained-distinct-peer", "same-port-retries", "same-port-bound", "allocation-bound", "access-denied-bound",
    "unrelated-error", "foreign-address", "nil-owner", "cleanup-failure", "invalid-capture")))
COMPOSITE_CREDENTIAL_CASES = (
    *(case + "/" + fault for case in COMPOSITE_CASES for fault in (("sip003-key" if case.startswith("ss-v2ray/") else "xray-reality-key"), "hysteria-password")),
    *(case + "/aes-key" for case in COMPOSITE_CASES if not case.endswith("/off")),
    "max/off/xray-pq-key", "split/off/xray-user", "split/off/hysteria-trust", "split/off/hysteria-salamander",
    *("ss-v2ray/off/" + fault for fault in ("sip003-host", "sip003-path", "sip003-server-name", "sip003-certificate")))

SIP003_LAYERS = ('off', 'aes-256-gcm', 'aes-256-gcm+xor-whitening')
SIP003_PROOF_CASES = tuple(layer + '/' + case for layer in SIP003_LAYERS for case in ('owned', 'wrong-node', 'drop-cover'))
SIP003_CREDENTIAL_CASES = tuple(layer + '/' + fault for layer in SIP003_LAYERS for fault in (
    'sip003-key', 'sip003-host', 'sip003-path', 'sip003-server-name', 'sip003-certificate',
    'hysteria-password', 'hysteria-trust', 'hysteria-salamander')) + tuple(layer + '/aes-key' for layer in SIP003_LAYERS[1:])
SIP003_IDENTITY_CASES = ('owned', 'not-started', 'cancelled', 'closed', 'owner-replaced', 'tcp-replaced', 'udp-replaced', 'tcp-missing', 'udp-missing', 'split', 'max')


def layer_reference_sources():
    return [ROOT / "go.mod", *([ROOT / "go.sum"] if (ROOT / "go.sum").exists() else []),
            *(path for path in sorted((ROOT / "cmd/start-layer-relay").glob("*.go")) if not path.name.endswith("_test.go"))]


def checked_sources(source):
    source = PREP.checked_vendor(Path(source))
    records = PREP.MTU.RETAINED.verify(source)
    inbound = source / "protocol/tun/inbound.go"
    if inbound.is_symlink() or not inbound.is_file() or PREP.DESKTOP_MTU.inbound_retirement_patch(inbound.read_bytes()) != inbound.read_bytes():
        raise ValueError("Native MTU inbound lost its complete captured lifecycle/context projection")
    records["protocol/tun/inbound.go"] = hashlib.sha256(inbound.read_bytes()).hexdigest()
    projection = ROOT / "deploy/test_desktop_tun_retirement_projection.py"
    if projection.is_symlink() or not projection.is_file():
        raise ValueError("Native retirement projection regression lost its original source")
    records["gate/deploy/test_desktop_tun_retirement_projection.py"] = hashlib.sha256(projection.read_bytes()).hexdigest()
    if platform.system() == "Linux":
        records.update(PREP.DESKTOP_MTU.verify_linux_retirement_source(source))
    # Bind both complete pinned endpoint files and the shared strict error
    # classifier. A compiled baseline may not silently restore an unpatched
    # server or borrow an unrelated helper with a matching filename.
    close_policy = PREP.RELAY.OPENVPN_CLOSE
    records.update(close_policy.verify(source))
    for path in close_policy.inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError("OpenVPN close policy lost its original source authority")
        records['gate/' + path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    records.update(PREP.RELAY.OBSERVATION.verify(source))
    copies = PREP.pt_copies()
    PREP.preflight_pt_files(source, copies)
    for name, relative in PREP.PEER_TEMPLATES.items():
        copies[relative] = (ROOT / "mobile/desktop" / name).read_bytes()
    for name, relative in (("manager.go", "adapter/inbound/routervpn_mtu.go"), ("manager_test.go", "adapter/inbound/routervpn_mtu_test.go"), ("manager_native_linux_test.go", "adapter/inbound/routervpn_mtu_native_linux_test.go"), ("box.go", "routervpn_mtu.go"), ("box_test.go", "routervpn_mtu_test.go"), ("tun.go", "protocol/tun/routervpn_mtu.go"), ("tun_native_linux_test.go", "protocol/tun/routervpn_mtu_native_linux_test.go"), ("desktop_transaction_native_linux_test.go", "routervpn_mtu_transaction_native_linux_test.go")):
        copies[relative] = (ROOT / "mobile/mtu" / (name + ".tmpl")).read_bytes()
    for path in sorted((ROOT / "mobile/desktop").glob("*.go.tmpl")):
        if path.name.startswith(("node", "mtu", "external", "standard")) and path.name not in PREP.PT_TEMPLATES and path.name not in PREP.BOX_TEMPLATES and path.name not in PREP.PEER_TEMPLATES:
            copies["cmd/sing-box/routervpn_" + path.name.removesuffix(".tmpl")] = path.read_bytes()
    for name in ('sing_tun_monitor_context.go.tmpl', 'sing_tun_monitor_context_test.go.tmpl', 'sing_tun_network.go.tmpl', 'sing_tun_network_linux.go.tmpl', 'sing_tun_network_inventory_linux.go.tmpl', 'sing_tun_retirement_linux.go.tmpl', 'sing_tun_retirement_socket_linux.go.tmpl', 'sing_tun_retirement_linux_test.go.tmpl', 'sing_tun_retirement_native_linux_test.go.tmpl', 'sing_tun_resolver_linux.go.tmpl', 'sing_tun_resolver_linux_test.go.tmpl', 'sing_tun_dns_test.go.tmpl', 'sing_tun_network_linux_test.go.tmpl', 'sing_tun_network_windows.go.tmpl', 'sing_tun_network_darwin.go.tmpl', 'sing_tun_network_darwin_test.go.tmpl', 'sing_tun_route_darwin_test.go.tmpl'):
        copies['routervpn-desktop-tun/routervpn_' + name.removesuffix('.tmpl')] = (ROOT / 'mobile/desktop' / name).read_bytes()
    for name in ('desktop_network_receipt.go', 'desktop_network_wire.go', 'desktop_network_darwin_wire.go', 'desktop_network_retirement.go', 'desktop_network_retirement_limit_test.go', 'desktop_network_dump_linux.go', 'desktop_network_lock.go'):
        copies['routervpn-desktop-tun/routervpn_' + name] = (ROOT / 'internal/desktopnetwork' / name).read_bytes().replace(b'package desktopnetwork\n', b'package tun\n', 1)
    for package in PREP.RELAY.PACKAGES:
        for path in sorted((ROOT / "internal" / package).glob("*.go")):
            if path.name.endswith("_test.go"):
                continue
            raw = PREP.RELAY.OBSERVATION.rewrite(path.read_bytes())
            for name in PREP.RELAY.PACKAGES:
                raw = raw.replace(('"router-vpn/internal/' + name + '"').encode(),
                    ('"github.com/sagernet/sing-box/experimental/libbox/routervpn/' + name + '"').encode())
            copies["experimental/libbox/routervpn/" + package + "/" + path.name] = raw
    for package in PREP.PURE:
        for path in sorted((ROOT / "internal" / package).glob("*.go")):
            if not path.name.endswith("_test.go"):
                copies["routervpn/" + package + "/" + path.name] = PREP.relocated_shared_source(path.read_bytes())
    for path in sorted((ROOT / "mobile/amnezia").glob("*.tmpl")):
        copies["protocol/routervpnamnezia/" + path.name.removesuffix(".tmpl")] = path.read_bytes()
    for path in sorted((ROOT / "mobile/composite").glob("*.tmpl")):
        copies["protocol/routervpncomposite/" + path.name.removesuffix(".tmpl")] = path.read_bytes()
    for name, target in PREP.RELAY.WHITENING.STREAM.TEMPLATES.items():
        copies["protocol/shadowsocks/" + target] = (ROOT / "mobile/startwhitening" / name).read_bytes()
    for path in sorted((ROOT / "internal/startwhitening").glob("*.go")):
        copies["experimental/libbox/routervpn/startwhitening/" + path.name] = path.read_bytes()
    copies["service/routervpnperformance/service.go"] = (ROOT / "mobile/performance/service.go.tmpl").read_bytes()
    copies["service/routervpnperformance/service_test.go"] = (ROOT / "mobile/performance/service_test.go.tmpl").read_bytes()
    copies["routervpn_services.go"] = (ROOT / "mobile/performance/box.go.tmpl").read_bytes()
    for relative, expected in copies.items():
        target = source / relative
        if target.is_symlink() or not target.is_file() or target.read_bytes() != expected:
            raise ValueError("Node native source differs from shipping bytes: " + relative)
        records[relative] = hashlib.sha256(expected).hexdigest()
    registry = source / "include/registry.go"
    if registry.is_symlink() or not registry.is_file():
        raise ValueError("Node composite lost its shipping native outbound registry")
    original_registry = registry.read_text(encoding="utf-8")
    registered = PREP.RELAY.COMPOSITE.insert_once(original_registry,
        '\t"github.com/sagernet/sing-box/protocol/group"', '\t"github.com/sagernet/sing-box/protocol/routervpncomposite"')
    registered = PREP.RELAY.COMPOSITE.insert_once(registered,
        '\tgroup.RegisterURLTest(registry)', '\troutervpncomposite.RegisterOutbound(registry)')
    if registered != original_registry:
        raise ValueError("Node composite is missing from the actual shipping native registry")
    records["include/registry.go"] = hashlib.sha256(registry.read_bytes()).hexdigest()
    box = source / "box.go"
    if box.is_symlink() or PREP.node_capture_source(box.read_text(encoding="utf-8")) != box.read_bytes():
        raise ValueError("Node source snapshot is absent or moved from actual Box construction")
    records["box.go"] = hashlib.sha256(box.read_bytes()).hexdigest()
    ss = source / "protocol/shadowsocks/outbound.go"
    if ss.is_symlink() or PREP.RELAY.WHITENING.STREAM.patch(ss.read_text(encoding="utf-8")).encode() != ss.read_bytes():
        raise ValueError("Node native Shadowsocks stream/packet owner differs from its exact pinned source")
    records["protocol/shadowsocks/outbound.go"] = hashlib.sha256(ss.read_bytes()).hexdigest()
    native_xray = source / "protocol/routervpnxray/outbound.go"
    if native_xray.is_symlink() or native_xray.read_bytes() != (ROOT / "mobile/applexray/outbound.go.tmpl").read_bytes():
        raise ValueError("Node native Xray instance lost its exact captured socket owner")
    records["protocol/routervpnxray/outbound.go"] = hashlib.sha256(native_xray.read_bytes()).hexdigest()
    # Naive uses the pinned native outbound and real inbound/UoT reference,
    # without a patched transport copy. Reject changed or extra implementation
    # files before compiling either the baseline or deliberate Go overlays.
    naive_paths = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", PREP.PIN, "--", "protocol/naive", "common/uot"], cwd=source, text=True).splitlines()
    expected_naive = {relative for relative in naive_paths if relative.endswith(".go")}
    actual_naive = {path.relative_to(source).as_posix() for directory in ("protocol/naive", "common/uot") for path in (source / directory).rglob("*.go")}
    if not expected_naive or actual_naive != expected_naive:
        raise ValueError("Node Naive native implementation differs from its pinned file set")
    for relative in sorted(expected_naive):
        path = source / relative
        expected = subprocess.check_output(["git", "show", PREP.PIN + ":" + relative], cwd=source)
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise ValueError("Node Naive native implementation differs from its pinned source: " + relative)
        records[relative] = hashlib.sha256(expected).hexdigest()
    # SIP003 uses the pinned actual TLS/WebSocket/mux plugin. Bind every
    # implementation file before applying explicit negative-control overlays.
    sip_paths = subprocess.check_output(["git", "ls-tree", "-r", "--name-only", PREP.PIN, "--", "transport/sip003", "transport/v2raywebsocket"], cwd=source, text=True).splitlines()
    expected_sip = {relative for relative in sip_paths if relative.endswith(".go")}
    actual_sip = {path.relative_to(source).as_posix() for directory in ("transport/sip003", "transport/v2raywebsocket") for path in (source / directory).rglob("*.go")}
    if not expected_sip or actual_sip != expected_sip:
        raise ValueError("Node SIP003 transport differs from its pinned file set")
    for relative in sorted(expected_sip):
        path = source / relative
        expected = subprocess.check_output(["git", "show", PREP.PIN + ":" + relative], cwd=source)
        if path.is_symlink() or not path.is_file() or path.read_bytes() != expected:
            raise ValueError("Node SIP003 transport differs from its pinned source: " + relative)
        records[relative] = hashlib.sha256(expected).hexdigest()
    for name in ("go.mod", "go.sum"):
        path = source / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Node native dependency record is not a retained regular file")
        records[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in sorted((source / "protocol/routervpnamnezia").glob("*.go")):
        if path.is_symlink():
            raise ValueError("Linked encrypted peer/native implementation")
        records[path.relative_to(source).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    # A local Go replacement is not covered by go mod verify. Preserve the
    # complete, reverse-h1-verified backend and its exact native regression in
    # every before/after node source capture, alongside the selected go.mod.
    timers = PREP.RELAY.AMNEZIA.TIMERS
    timers.verify_tree(source / timers.COPY)
    for path in sorted((source / timers.COPY).rglob('*')):
        if path.is_file():
            records[path.relative_to(source).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in timers.inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError("AWG timer source authority is not a captured regular file")
        records['gate/' + path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    scheduler = PREP.RELAY.AMNEZIA.SCHEDULER
    scheduler.verify_tree(source / scheduler.COPY)
    for path in sorted((source / scheduler.COPY).rglob('*')):
        if path.is_file():
            records[path.relative_to(source).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in scheduler.inputs():
        if path.is_symlink() or not path.is_file():
            raise ValueError("gVisor scheduler/forwarder authority is not a captured regular file")
        records['gate/' + path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    for path in layer_reference_sources():
        if path.is_symlink() or not path.is_file():
            raise ValueError("Node layer reference lost its exact shipping source")
        records["layer-reference/" + path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    records["runner"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    records["cronet-packaging"] = hashlib.sha256((ROOT / "deploy/build-native-runtime.py").read_bytes()).hexdigest()
    for key, name in (("namespace-launcher", "test_desktop_socket_uid.py"),
                      ("routing-runner", "test_desktop_node_routing_runner.py")):
        path = ROOT / "deploy" / name
        if path.is_symlink() or not path.is_file():
            raise ValueError("Node routing gate lost its owned runner: " + name)
        records[key] = hashlib.sha256(path.read_bytes()).hexdigest()
    return source, records


def run(command, *, cwd, env, timeout):
    if platform.system() == "Windows":
        return BOOT.IDENTITY.run(command, cwd=cwd, env=env, timeout=timeout)
    process = subprocess.Popen([str(value) for value in command], cwd=cwd, env=env,
                               stdout=subprocess.PIPE, stderr=subprocess.STDOUT, start_new_session=True)
    try:
        raw, _ = process.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        raw, _ = process.communicate(timeout=10)
        raise RuntimeError("Node test process group timed out and was joined:\n" + raw[-16384:].decode("utf-8", errors="replace"))
    return process.returncode, raw.decode("utf-8", errors="replace")


def namespace_runner():
    spec = importlib.util.spec_from_file_location("node_routing_owned_namespace", ROOT / "deploy/test_desktop_socket_uid.py")
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    return runner


@contextlib.contextmanager
def routing_fixture_image(binary):
    # sudo can traverse the private compiler workspace, but root in the fresh
    # user namespace cannot use initial-namespace DAC capabilities to do so.
    # Expose only an exact read/execute-only copy; the original workspace and
    # every other compiled image retain their original private permissions.
    original = retained_binary(binary)
    owner = binary.lstat()
    if owner.st_uid != os.geteuid() or owner.st_mode & 0o022 or not owner.st_mode & 0o111:
        raise ValueError("The native routing fixture is not its owned executable")
    with tempfile.TemporaryDirectory(prefix="routervpn-routing-receipt-", dir="/tmp") as directory:
        workspace = Path(directory)
        staged = workspace / "routing.test"
        with binary.open("rb") as source, staged.open("xb") as target:
            shutil.copyfileobj(source, target)
        staged.chmod(0o555)
        workspace.chmod(0o711)
        receipt = retained_binary(staged)
        root = workspace.lstat()
        directory_identity = (root.st_dev, root.st_ino, root.st_uid, root.st_gid, root.st_mode)

        def verify():
            current = workspace.lstat()
            if (current.st_dev, current.st_ino, current.st_uid, current.st_gid, current.st_mode) != directory_identity or \
                    not stat.S_ISDIR(current.st_mode) or current.st_uid != os.geteuid() or stat.S_IMODE(current.st_mode) != 0o711:
                raise ValueError("The native routing staging directory changed ownership or permissions")
            copied = staged.lstat()
            if copied.st_uid != owner.st_uid or copied.st_gid != root.st_gid or stat.S_IMODE(copied.st_mode) != 0o555 or \
                    retained_binary(staged) != receipt or receipt[2] != original[2]:
                raise ValueError("The native routing staged image differs from its exact compiled fixture")
            if retained_binary(binary) != original or binary.lstat().st_uid != owner.st_uid or binary.lstat().st_gid != owner.st_gid:
                raise ValueError("The native routing source image changed during staged execution")

        verify()
        try:
            yield staged
        finally:
            verify()


def linux_routing_receipt_test(binary, *, cwd, env, duration, selector="^TestRouterVPNNativeLinuxRouting"):
    if selector not in ("^TestRouterVPNNativeLinuxRouting", "^TestRouterVPNNativeLinuxResolver", "^TestRouterVPNNativeLinuxMTUTransactionNamespace$", STANDARD_MTU_RETIRE_SUITE[2], STANDARD_MTU_NATIVE_SUITE[2], STANDARD_PARENT_SUITE[2], STANDARD_PARENT_NATIVE_SUITE[2]):
        raise ValueError("Native privilege cannot execute another fixture selector")
    if platform.system() != "Linux" or env.get("GOOS") != "linux":
        raise ValueError("The native routing receipt fixture requires native Linux")
    # Elevate only this already-compiled fixture. Its unchanged Go parent
    # retains the actual network/user handles, creates the fresh namespaces
    # and verifies both before any route mutation. The shared launcher owns
    # and joins the full process group, including privileged descendants.
    runner = namespace_runner()
    sudo = runner.privilege_tool()
    captured = dict(env)
    for name in ("ROUTERVPN_NATIVE_ROUTING_RECEIPT_CHILD", "ROUTERVPN_ROUTING_PARENT_NET", "ROUTERVPN_ROUTING_PARENT_USER", "ROUTERVPN_NATIVE_ROUTING_RETIREMENT_CASE", "ROUTERVPN_NATIVE_RESOLVER_NAMED_CASE", "ROUTERVPN_NATIVE_MTU_TRANSACTION_CASE", "ROUTERVPN_STANDARD_MTU_CLAIM_FAILURE"):
        captured.pop(name, None)
    with routing_fixture_image(binary) as staged:
        command = [str(staged), "-test.run=" + selector, "-test.count=1",
                   "-test.timeout=" + str(duration) + "s", "-test.v"]
        if sudo is not None:
            command = [sudo, "-n", "--", *command]
        try:
            return 0, runner.run(command, cwd=cwd, env=captured, timeout=duration + 15, sudo=sudo)
        except subprocess.CalledProcessError as error:
            output = error.output or b""
            return error.returncode, output.decode("utf-8", errors="replace") if isinstance(output, bytes) else output


@contextlib.contextmanager
def stage(label):
    started = time.monotonic()
    print("Node source gate start: " + label, flush=True)
    try:
        yield
    except BaseException:
        print("Node source gate failed: " + label + " (%.3fs)" % (time.monotonic() - started), flush=True)
        raise
    else:
        print("Node source gate finished: " + label + " (%.3fs)" % (time.monotonic() - started), flush=True)


def retained_binary(path):
    windows = platform.system() == "Windows"

    def identity(record):
        if not stat.S_ISREG(record.st_mode) or record.st_nlink != 1:
            raise ValueError("Node baseline executable is not its owned regular file")
        result = (record.st_dev, record.st_ino, record.st_mode, record.st_nlink,
                  record.st_size, record.st_mtime_ns, record.st_ctime_ns)
        if windows:
            # Both CPython views expose native creation time and attributes.
            # A regular-looking name surrogate must not become an owned image.
            native = tuple(getattr(record, field, None) for field in
                           ("st_birthtime_ns", "st_file_attributes", "st_reparse_tag"))
            if any(not isinstance(value, int) for value in native) or native[1] & stat.FILE_ATTRIBUTE_REPARSE_POINT or native[2]:
                raise ValueError("Node baseline executable lacks a non-reparse native file identity")
            result += native
        return result

    def same_object(named, handled):
        if not windows:
            return named == handled
        # CPython 3.12.10's win32_xstat adds execute bits for .exe paths and
        # aliases path ctime to birthtime. Its fstat uses the handle's raw mode
        # and FileBasicInfo.ChangeTime. Compare like native fields across those
        # views, while retaining EACH complete original tuple for readback.
        handle_mode = handled[2] | (0o111 if path.suffix.lower() == ".exe" else 0)
        return (named[:2], named[2], named[3:6], named[7:]) == (
            handled[:2], handle_mode, handled[3:6], handled[7:])

    before = path.lstat()
    named = identity(before)
    digest = hashlib.sha256()
    with path.open("rb") as opened:
        handled = identity(os.fstat(opened.fileno()))
        if not same_object(named, handled):
            raise ValueError("Node baseline executable changed while opening its original file "
                             "(path=%r; handle=%r)" % (named, handled))
        for block in iter(lambda: opened.read(1024 * 1024), b""):
            digest.update(block)
        if identity(os.fstat(opened.fileno())) != handled or identity(path.lstat()) != named:
            raise ValueError("Node baseline executable changed during its file readback")
    return named, handled, digest.hexdigest()


class BaselineBinaries:
    """Own one compiled image per package for this exact source/build capture.

    Selectors still execute in separate processes with their original deadlines.
    Mutants never use this cache: each overlay must compile its distinct defect.
    The complete shipping inventory is checked at entry and exit by execute();
    every recorded input is also read back around each baseline invocation.
    """
    def __init__(self, source, workspace, build, captured, records):
        self.source, self.workspace = source, workspace
        self.build, self.captured = build, captured
        self.original_build = tuple(str(value) for value in build)
        self.original_environment = dict(captured)
        self.records = dict(records)
        self.binaries = {}

    def check_inputs(self):
        if tuple(str(value) for value in self.build) != self.original_build or self.captured != self.original_environment:
            raise ValueError("Node baseline changed its captured compiler arguments or environment")
        for relative, expected in self.records.items():
            if relative == "runner":
                path = Path(__file__)
            elif relative == "cronet-packaging":
                path = ROOT / "deploy/build-native-runtime.py"
            elif relative == "namespace-launcher":
                path = ROOT / "deploy/test_desktop_socket_uid.py"
            elif relative == "routing-runner":
                path = ROOT / "deploy/test_desktop_node_routing_runner.py"
            elif relative.startswith("layer-reference/"):
                path = ROOT / relative.removeprefix("layer-reference/")
            elif relative.startswith("gate/"):
                path = ROOT / relative.removeprefix("gate/")
            else:
                path = self.source / relative
            if path.is_symlink() or not path.is_file() or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                raise ValueError("Node baseline changed a captured source input: " + relative)

    def verify(self, package):
        self.check_inputs()
        binary, receipt = self.binaries[package]
        if retained_binary(binary) != receipt:
            raise ValueError("Node baseline executable changed from its original compiled image")
        return binary

    def binary(self, package):
        if package not in self.binaries:
            self.check_inputs()
            suffix = ".exe" if self.captured["GOOS"] == "windows" else ""
            binary = self.workspace / ("baseline-%d.test" % len(self.binaries) + suffix)
            if binary.exists() or binary.is_symlink():
                raise ValueError("Node baseline compilation does not own its new output path")
            with stage("compile baseline " + package):
                status, output = run([*self.build, "-o", binary, package], cwd=self.source, env=self.captured, timeout=600)
                if status:
                    raise ValueError("Node baseline native compilation failed: " + package + "\n" + output[-32768:])
                self.check_inputs()
                self.binaries[package] = binary, retained_binary(binary)
        return self.verify(package)

    def execute(self, name, package, selector, duration):
        privileged = {"native-routing-receipt": ("github.com/sagernet/sing-tun", "^TestRouterVPNNativeLinuxRouting"), "native-resolver-lifetime": ("github.com/sagernet/sing-tun", "^TestRouterVPNNativeLinuxResolver"), "native-mtu-transaction": (".", "^TestRouterVPNNativeLinuxMTUTransactionNamespace$"), STANDARD_MTU_RETIRE_SUITE[0]: STANDARD_MTU_RETIRE_SUITE[1:3], STANDARD_MTU_NATIVE_SUITE[0]: STANDARD_MTU_NATIVE_SUITE[1:3], STANDARD_PARENT_SUITE[0]: STANDARD_PARENT_SUITE[1:3], STANDARD_PARENT_NATIVE_SUITE[0]: STANDARD_PARENT_NATIVE_SUITE[1:3]}
        if name in privileged and (package, selector) != privileged[name]:
            raise ValueError("Node routing privilege cannot execute another package or selector")
        binary = self.binary(package)
        with stage("execute baseline " + name):
            if name == "native-routing-receipt":
                status, output = linux_routing_receipt_test(binary, cwd=self.source, env=self.captured, duration=duration)
            elif name in ("native-resolver-lifetime", "native-mtu-transaction", STANDARD_MTU_RETIRE_SUITE[0], STANDARD_MTU_NATIVE_SUITE[0], STANDARD_PARENT_SUITE[0], STANDARD_PARENT_NATIVE_SUITE[0]):
                status, output = linux_routing_receipt_test(binary, cwd=self.source, env=self.captured, duration=duration, selector=selector)
            else:
                status, output = run([binary, "-test.run=" + selector, "-test.count=1", "-test.timeout=" + str(duration) + "s", "-test.v"],
                                     cwd=self.source, env=self.captured, timeout=duration + 15)
            self.verify(package)
        return status, output


def selected_compiler(go, source, env):
    status, output = run([go, "env", "-json", "GOROOT", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"], cwd=source, env=env, timeout=30)
    if status:
        raise ValueError("Node native toolchain selection failed:\n" + output[-8192:])
    identity = json.loads(output)
    system = platform.system().lower()
    if identity.get("GOVERSION") != "go1.26.3" or identity.get("GOHOSTOS") != system or system not in ("linux", "windows") or identity.get("GOHOSTARCH") not in ("amd64", "arm64"):
        raise ValueError("Node composition requires the pinned actual Linux or Windows compiler")
    arch = identity["GOHOSTARCH"]
    if env.get("GOOS", system) != system or env.get("GOARCH", arch) != arch:
        raise ValueError("Node composition cannot execute cross-compiled evidence")
    root = Path(identity["GOROOT"])
    compiler = root / "bin" / ("go.exe" if system == "windows" else "go")
    if not root.is_absolute() or not compiler.is_file():
        raise ValueError("Node composition lost its selected compiler")
    captured = dict(env, GOROOT=str(root), GOTOOLCHAIN="local", GOOS=system, GOARCH=arch, GOFLAGS="", GOWORK="off")
    # Packaging's module/library helpers invoke `go` by name. They must use
    # this verified compiler after automatic toolchain selection is disabled.
    path_keys = [key for key in captured if key == "PATH" or (system == "windows" and key.upper() == "PATH")]
    if len(path_keys) > 1:
        raise ValueError("Node compiler has ambiguous executable search paths")
    ambient_path = captured.pop(path_keys[0]) if path_keys else os.defpath
    captured["PATH"] = str(compiler.parent) + os.pathsep + ambient_path
    status, again = run([compiler, "env", "-json", "GOROOT", "GOVERSION", "GOHOSTOS", "GOHOSTARCH"], cwd=source, env=captured, timeout=30)
    if status or json.loads(again) != identity:
        raise ValueError("Node native compiler changed during selection")
    return compiler, captured, arch


def build_layer_reference(compiler, workspace, captured, race):
    binary = workspace / ("start-layer-relay.exe" if captured["GOOS"] == "windows" else "start-layer-relay")
    status, output = run([compiler, "build", "-mod=readonly", "-trimpath", *race, "-o", binary, "./cmd/start-layer-relay"],
                         cwd=ROOT, env=captured, timeout=300)
    if status or binary.is_symlink() or not binary.is_file():
        raise ValueError("Node actual shipping whitening peer did not build:\n" + output[-16384:])
    captured["ROUTER_VPN_WHITENING_TEST_BINARY"] = str(binary)
    captured.pop("ROUTERVPN_NODE_LAYER_REFERENCE_CHILD", None)
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest()


def stage_naive_library(compiler, source, workspace, captured):
    # Use packaging's exact target, module revision, checksum and bounds. The
    # tests load this retained explicit path; Cronet's ambient search is never
    # an availability or provenance fallback.
    spec = importlib.util.spec_from_file_location("node_cronet_packaging", ROOT / "deploy/build-native-runtime.py")
    native = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(native)
    target = captured["GOOS"] + "/" + captured["GOARCH"]
    name = native.library_name(target)
    if captured["GOOS"] not in ("linux", "windows") or not name:
        raise ValueError("Node Naive fixture needs its actual native-library target")
    library = workspace / name
    if library.exists() or library.is_symlink() or (workspace / "CRONET-LICENSE").exists():
        raise ValueError("Node Naive library stage is not owned by this invocation")
    status, output = run([compiler, "mod", "verify"], cwd=source, env=captured, timeout=300)
    if status:
        raise ValueError("Node Naive native dependencies failed checksum verification:\n" + output[-8192:])
    module_path = "github.com/sagernet/cronet-go/lib/" + target.replace("/", "_")
    info = native.module(source, module_path, captured)
    if info["Version"] != native.CRONET_VERSION or not Path(info["Dir"]).is_absolute():
        raise ValueError("Node Naive native module changed its captured revision")
    original = Path(info["Dir"]) / name
    original_bytes = native.regular(original, native.MAX_LIBRARY)
    original_digest = hashlib.sha256(original_bytes).hexdigest()
    native.stage_cronet(source, workspace, target, captured)
    if native.regular(library, native.MAX_LIBRARY) != original_bytes or native.regular(original, native.MAX_LIBRARY) != original_bytes:
        raise ValueError("Node Naive library changed during its packaging capture")
    captured.update(ROUTERVPN_NODE_CRONET_LIBRARY=str(library), ROUTERVPN_NODE_CRONET_SHA256=original_digest,
                    ROUTERVPN_NODE_CRONET_BYTES=str(len(original_bytes)))
    return library, original, original_digest, len(original_bytes)


def verify_naive_library(receipt):
    library, original, expected, size = receipt
    for path in (library, original):
        if path.is_symlink() or not path.is_file() or path.stat().st_size != size or hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError("Node Naive library changed during actual encrypted execution")


def xray_reference_sources(source):
    PREP.RELAY.XRAY.checkout(source, PREP.RELAY.XRAY.XRAY_PIN, "github.com/xtls/xray-core")
    records = {}
    for path in (*sorted(source.rglob("*.go")), source / "go.mod", source / "go.sum"):
        if path.is_symlink() or not path.is_file():
            raise ValueError("Xray reference lost its retained prepared source")
        records[path.relative_to(source).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return records


def build_xray_reference(compiler, source, workspace, captured, race):
    status, output = run([compiler, "list", "-m", "-mod=readonly", "-json", "github.com/xtls/xray-core"],
                         cwd=source, env=captured, timeout=30)
    if status:
        raise ValueError("Node reference lost its captured Xray dependency:\n" + output[-8192:])
    xray = Path(json.loads(output).get("Dir", ""))
    if not xray.is_absolute() or xray.is_symlink():
        raise ValueError("Node Xray reference has no exact prepared dependency directory")
    records = xray_reference_sources(xray)
    binary = workspace / ("xray-reference.exe" if captured["GOOS"] == "windows" else "xray-reference")
    status, output = run([compiler, "build", "-mod=readonly", "-trimpath", *race, "-ldflags=-checklinkname=0", "-o", binary, "./main"],
                         cwd=xray, env=captured, timeout=600)
    if status or binary.is_symlink() or not binary.is_file() or xray_reference_sources(xray) != records:
        raise ValueError("Node actual pinned Xray reference did not build from its captured source:\n" + output[-16384:])
    captured["ROUTER_VPN_XRAY_TEST_BINARY"] = str(binary)
    return binary, hashlib.sha256(binary.read_bytes()).hexdigest(), xray, records


def mutation_in_function(raw, signature, before, after):
    """Keep one actual receiver/method boundary when contextual siblings exist."""
    marker = "\n" + signature
    if raw.count(marker) != 1:
        raise ValueError("Node native mutation lost its exact function: " + signature)
    return BOOT.IDENTITY.function_mutant(raw, signature, before, after)


def mutants(source, windows):
    def changed(relative, before, after, count=1):
        raw = (source / relative).read_text(encoding="utf-8")
        if count != 1:
            if raw.count(before) != count:
                raise ValueError("Node native mutation lost its exact source count: " + relative)
            return raw.replace(before, after)
        return BOOT.IDENTITY.replace_once(raw, before, after)
    def changed_function(relative, signature, before, after):
        raw = (source / relative).read_text(encoding="utf-8")
        return mutation_in_function(raw, signature, before, after)
    lower = "routervpn/desktoppt/node_physical.go"
    network = "routervpn/desktoppt/node_network.go"
    box = "routervpn_desktop_node_box_physical.go"
    admission = "cmd/sing-box/routervpn_node_command_admission.go"
    transfer = "cmd/sing-box/routervpn_node_command_physical.go"
    readiness = "cmd/sing-box/routervpn_node_command_ready.go"
    selected_dns = "routervpn_desktop_node_box_dns.go"
    node_command = "cmd/sing-box/routervpn_mtu_node.go"
    result = [
        ("sip003-cover-without-captured-composite", "service/routervpnperformance/service.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeSIP003RetainedProof", "off/owned",
         "SIP003 cover lost independent TCP proof, UDP owner or truthful native boundary", changed_function("service/routervpnperformance/service.go",
         "func (s *Service) resolve(tag string, seen map[string]bool) (adapter.Outbound, string, error) {",
         "if composite, ok := out.(*routervpncomposite.Outbound); ok {", "if composite, ok := out.(*routervpncomposite.Outbound); false && ok {")),
        ("sip003-cover-borrowed-tcp", "protocol/routervpncomposite/outbound.go", "./protocol/routervpncomposite", "TestNativeCompositePerformanceRequiresExactSIP003Owners", "tcp-replaced",
         "cover capability inferred a mode/type, unopened lane or replaced lifecycle", changed_function("protocol/routervpncomposite/outbound.go",
         "func (h *Outbound) RouterVPNPerformanceIdentity() string {",
         "|| currentTCP != tcp ||", "|| false && currentTCP != tcp ||")),
        ("sip003-cover-borrowed-udp", "protocol/routervpncomposite/outbound.go", "./protocol/routervpncomposite", "TestNativeCompositePerformanceRequiresExactSIP003Owners", "udp-replaced",
         "cover capability inferred a mode/type, unopened lane or replaced lifecycle", changed_function("protocol/routervpncomposite/outbound.go",
         "func (h *Outbound) RouterVPNPerformanceIdentity() string {",
         "|| currentUDP != udp {", "|| false && currentUDP != udp {")),
        ("sip003-cover-type-label", "service/routervpnperformance/service.go", "./service/routervpnperformance", "TestNativePerformanceCannotAdmitCompositeByTypeName", "",
         "a composite type label replaced the captured concrete two-lane owner", changed_function("service/routervpnperformance/service.go",
         "func (s *Service) resolve(tag string, seen map[string]bool) (adapter.Outbound, string, error) {",
         "switch out.Type() {", 'switch out.Type() {\n\tcase "routervpn-composite":\n\t\treturn out, identity, nil')),
        ("sip003-uncaptured-transport", "transport/sip003/v2ray.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeCompositeTraffic", "ss-v2ray/off",
         "simultaneous composite traffic omitted one retained native lane grant", changed("transport/sip003/v2ray.go",
         "v2ray.NewClientTransport(context.Background(), dialer, serverAddr, transportOptions, tlsClient)",
         "v2ray.NewClientTransport(context.Background(), N.SystemDialer, serverAddr, transportOptions, tlsClient)")),
        ("sip003-ignored-certificate", "transport/sip003/v2ray.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeCompositeWrongCredential", "ss-v2ray/off/sip003-certificate",
         "wrong composite branch credential delivered authenticated payload", changed("transport/sip003/v2ray.go",
         "tlsClient, err = tls.NewClient(ctx, logger.NOP(), serverAddr.AddrString(), tlsOptions)",
         "tlsOptions.Insecure = true\n\t\ttlsClient, err = tls.NewClient(ctx, logger.NOP(), serverAddr.AddrString(), tlsOptions)")),
        ("sip003-ignored-websocket-host", "transport/sip003/v2ray.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeCompositeWrongCredential", "ss-v2ray/off/sip003-host",
         "wrong composite branch credential delivered authenticated payload", changed("transport/sip003/v2ray.go",
         '"Host": []string{host}', '"Host": []string{func() string { _ = host; return "captured-sip003.test" }()}')),
        ("sip003-ignored-websocket-path", "transport/sip003/v2ray.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeCompositeWrongCredential", "ss-v2ray/off/sip003-path",
         "wrong composite branch credential delivered authenticated payload", changed("transport/sip003/v2ray.go",
         "Path: path,", 'Path: func() string { _ = path; return "/captured-shadowsocks" }(),')),
        ("composite-tcp-substituted-udp", "protocol/routervpncomposite/outbound.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeCompositeTraffic", "split/off",
         "simultaneous composite traffic omitted one retained native lane grant", changed("protocol/routervpncomposite/outbound.go",
         "return h.tcp, nil", "return h.udp, nil")),
        ("composite-udp-substituted-tcp", "protocol/routervpncomposite/outbound.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeCompositeTraffic", "split/off",
         "simultaneous composite traffic omitted one retained native lane grant", changed("protocol/routervpncomposite/outbound.go",
         "return h.udp, nil", "return h.tcp, nil")),
        ("composite-uncaptured-tcp", "protocol/routervpnxray/outbound.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeCompositeTraffic", "max/off",
         "simultaneous composite traffic omitted one retained native lane grant", changed("protocol/routervpnxray/outbound.go",
         "conn, err := b.dialer.DialContext(cctx, N.NetworkTCP, M.ParseSocksaddr(b.server.String()))",
         "conn, err := (&net.Dialer{}).DialContext(cctx, N.NetworkTCP, b.server.String())")),
        ("uncaptured-naive-physical-dial", "protocol/naive/outbound.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeNaiveTraffic", "naive-h2/off",
         "layered graph bypassed its captured socket grants", changed("protocol/naive/outbound.go",
         "Dialer:                   outboundDialer,", "Dialer:                   N.SystemDialer,")),
        ("downgraded-naive-h3", "protocol/naive/outbound.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeNaiveTraffic", "naive-h3/off",
         "layered encrypted payload escaped or lost its exact native lower", changed("protocol/naive/outbound.go",
         "QUIC:                     options.QUIC,", "QUIC:                     false,")),
        ("caller-owned-xray-dns", "protocol/routervpnxray/outbound.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeXrayTraffic", "reality-vision/off",
         "selected Home DNS did not traverse the actual layered graph", changed("protocol/routervpnxray/outbound.go",
         "h.connections.BeginDial(ctx)", "h.connections.Begin(ctx)", count=2)),
        ("uncaptured-xray-physical-dial", "protocol/routervpnxray/outbound.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeXrayTraffic", "reality-vision/off",
         "layered graph bypassed its captured socket grants", changed("protocol/routervpnxray/outbound.go",
         "conn, err := b.dialer.DialContext(cctx, N.NetworkTCP, M.ParseSocksaddr(b.server.String()))",
         "conn, err := (&net.Dialer{}).DialContext(cctx, N.NetworkTCP, b.server.String())")),
        ("lost-hysteria2-original-ip-identity", "experimental/libbox/routervpn/mobilemultihop/node_profile.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeHysteria2LayerTLSIdentity", "aes-256-gcm/ip-absent",
         "original IP-SAN identity did not survive its transport detour", changed("experimental/libbox/routervpn/mobilemultihop/node_profile.go",
         'tls["server_name"] = out["server"]', 'tls["server_name"] = ""')),
        ("ignored-hysteria2-tls-identity", "protocol/hysteria2/outbound.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeHysteria2WrongCredential", "off/hysteria-trust",
         "wrong captured Hysteria credential delivered encrypted payload", changed("protocol/hysteria2/outbound.go",
         "tlsConfig, err := tls.NewClient(ctx, logger, tlsServerAddress, tlsOptions)",
         "tlsOptions.Insecure = true\n\ttlsConfig, err := tls.NewClient(ctx, logger, tlsServerAddress, tlsOptions)")),
        ("missing-node-whitening", "protocol/routervpnwhitening/outbound.go", "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeEncryptedLayerTraffic", "shadowsocks/aes-256-gcm\\+xor-whitening",
         "layered encrypted payload escaped or lost its exact native lower", changed("protocol/routervpnwhitening/outbound.go",
         "return h.owner.Open(ctx, h.key, network == N.NetworkUDP,",
         "return h.owner.Open(ctx, [32]byte{}, network == N.NetworkUDP,")),
        ("truncated-shadowsocks-ciphertext", "protocol/shadowsocks/outbound.go", "./protocol/shadowsocks", "TestRouterVPNShadowsocksCompleteCiphertextPacket", "DialContext",
         "actual SS exact-size plaintext read lost complete ciphertext", changed("protocol/shadowsocks/outbound.go",
         "return bufio.NewBindPacketConn(routerVPNGuardPacket(outConn, h.method), destination), nil",
         "return bufio.NewBindPacketConn(h.method.DialPacketConn(outConn), destination), nil")),
        ("private-input-before-journal-auth", node_command, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandJournalBeforePrivateInputs", "",
         "private node input preceded actual parent authentication", changed(node_command,
         "\tif journal != nil {\n\t\tif err := journal.authenticate(parent, files); err != nil {\n\t\t\treturn err\n\t\t}\n\t}\n", "")),
        ("late-handshake-phase", lower, "./protocol/routervpnamnezia", "TestRouterVPNDesktopNodeEncryptedPreReadyHandshake", "awg2-fast",
         "actual eager encrypted Box startup", changed(lower, "!owner.SocketCurrent()", "!owner.Current()")),
        ("uncaptured-peer-tuple", lower, "./routervpn/desktoppt", "TestRouterVPNNodePhysicalHandshakePhaseAndExactPolicy", "",
         "node handshake admitted an uncaptured application or outer tuple", changed(lower, "closed || !allowed || owner == nil", "closed || (!allowed && false) || owner == nil")),
        ("substituted-box-source", box, ".", "TestRouterVPNDesktopNodePhysicalBoxRejectsSubstitutedGraph", "credential",
         "substituted native graph acquired a node lower factory", changed(box, "routerVPNNodeOptionsDigest(s.ctx, compiled) != s.routerVPNNodeOptions", "false && routerVPNNodeOptionsDigest(s.ctx, compiled) != s.routerVPNNodeOptions")),
        ("forgot-restored-tun-mtu", box, ".", "TestRouterVPNDesktopNodePhysicalBoxRestoresCapturedMTU", "1392",
         "actual node TUN ownership", changed(box, "expectedMTU = restored", "expectedMTU = capture.ConfiguredMTU")),
        ("equal-source-other-owner", network, "./routervpn/desktoppt", "TestRouterVPNNodePhysicalHandshakePhaseAndExactPolicy", "",
         "another compiler owner adopted this native generation", changed(network, "n.policy != policy", "false && n.policy != policy")),
        ("foreign-handoff-reply", admission, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandAdmissionRejectsForeignReplies", "source",
         "foreign handoff acknowledgement activated native sockets", changed(admission, "actual != expected", "false && actual != expected")),
        ("ignored-native-stop", admission, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandAdmissionExactStop", "after-ready",
         "exact captured stop did not retire pending native admission", changed(admission,
         "\t\tif bounded.Err() != nil || a.state.Load() != 1 || a.files.stopRequested(a.metadata.SessionID, a.metadata.ConfigSHA256) ||\n",
         "\t\tif bounded.Err() != nil || a.state.Load() != 1 || (false && a.files.stopRequested(a.metadata.SessionID, a.metadata.ConfigSHA256)) ||\n")),
        ("unbound-private-predecessor", transfer, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandTransferInput", "wrong-hash",
         "command accepted missing, changed or unbound predecessor input", changed(transfer, "hex.EncodeToString(sum[:]) != digest", "hex.EncodeToString(sum[:]) != digest && false")),
        ("unjoined-native-outcome", network, "./routervpn/desktoppt", "TestRouterVPNNodePhysicalRetirementKeepsExactJoinedSource", "partial-before-admission",
         "unjoined node acquired or queried a retained protection result", changed(network, "n.closed && n.retired", "(n.closed || true) && n.retired")),
        ("failed-cleanup-receipt", transfer, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandRetirementReceipt", "owner-failed",
         "retirement did not preserve its explicit outcome", changed(transfer, "if err != nil || ctx.Err() != nil {", "if ctx.Err() != nil {")),
        ("skipped-selected-dns", readiness, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandReadyRequiresFreshDNS", "exact",
         "actual DNS capability did not precede its exact readiness receipt", changed(readiness, "elapsed, err := owner.MeasureSelectedDNS(ctx)", "elapsed, err := time.Millisecond, error(nil)")),
        ("adopted-replaced-dns-tun", selected_dns, ".", "TestRouterVPNDesktopNodePhysicalDNSCapturedOwner", "tun-replaced",
         "Node DNS proof adopted a failed or replaced native path", changed(selected_dns, "same := owner.inbound == inbound", "same := true")),
    ]
    if windows:
        factory = "routervpn/desktoppt/node_physical_windows.go"
        result.append(("changed-prepared-baseline", factory, "./routervpn/desktoppt", "TestRouterVPNNodePhysicalWindowsAdmissionRejectsChangedOwners", "baseline-changed",
                       "failed node handoff admitted eager sockets or discarded partial source", changed(factory, "currentBaseline != baseline", "false && currentBaseline != baseline")))
        result.append(("dropped-restored-mtu-source", transfer, "./cmd/sing-box", "TestRouterVPNDesktopNodePhysicalCommandRestoredMTU", "exact",
                       "captured live MTU did not recompile the original private graph", changed(transfer,
                       "mobilemultihop.NewDesktopNodePolicyWithMTU(original, session, runtime.GOOS, restoredMTU)",
                       "mobilemultihop.NewDesktopNodePolicyWithMTU(original, session, runtime.GOOS, 0)")))
    else:
        factory = "routervpn/desktoppt/node_physical_linux.go"
        test = "TestRouterVPNNodePhysicalUnixCapturesPolicyAndRetainsLateOwner"
        result.extend((
            ("unix-changed-interface", factory, "./routervpn/desktoppt", test, "wg/lan-off/ipv6-off/always/index",
             "Unix Node admitted a changed interface, cancellation or partial source",
             changed(factory, "return actual != nil && actual.Index == index", "return actual != nil && (actual.Index == index || actual.Index != index)")),
            ("unix-substituted-private-tuple", factory, "./routervpn/desktoppt", test, "wg/lan-off/ipv6-off/always/live",
             "Unix Node constructor changed exact private outer tuples or allowed selected Home DNS",
             changed(factory, "uint16(destination.Port)", "uint16(destination.Port+1)")),
            ("unix-dropped-partial-source", factory, "./routervpn/desktoppt", test, "wg/lan-off/ipv6-off/always/partial",
             "Unix Node factory dropped or replaced its exact returned source",
             changed(factory, "return nil, owned, err", "return nil, nil, err")),
        ))
        lifecycle = "routervpn/desktoppt/linux_physical_lifecycle.go"
        joined_source = lifecycle
        result.extend((
            ('linux-node-joined-original-guardian', joined_source, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleJoinedSourcePreservesOriginalPreparation', '',
             'joined receipt substituted or erased the admitted native source', changed(joined_source,
             'captured.guardian != nil && (record.Original == nil || *record.Original != *captured.guardian)',
             'captured.guardian != nil && false && (record.Original == nil || *record.Original != *captured.guardian)')),
            ('linux-node-baseline-before-guardian', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleCreatesBaselineBeforeGuardian', 'callback-error',
             'failed or cancelled baseline reached native guardian construction', changed(lifecycle,
             'if err := baseline(ctx, capture); err != nil {', 'if err := baseline(ctx, capture); false {')),
            ('linux-node-exact-policy-pointer', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleRejectsMissingOrReusedCapability', '',
             'Linux admission accepted an equivalent replacement policy object', changed(lifecycle, 'owner.policy != policy || owner.admit == nil', 'owner.admit == nil')),
            ('linux-node-native-prepared-owner', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleBracketsAdmissionAndRetainsSource', 'always/before-owner',
             'Linux admission did not retain its selected policy between pre-TUN native observations', BOOT.IDENTITY.replace_once(changed(lifecycle, 'before.Owner != sourceIdentity ||', '(before.Owner != sourceIdentity && false) ||'), 'uint32(guardian.Guardian.ProcessID) != before.Owner.ProcessID', 'false')),
            ('linux-node-callback-refusal', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleBracketsAdmissionAndRetainsSource', 'always/callback-error',
             'Linux lifecycle admitted an unobserved, changed, failed or cancelled baseline', changed(lifecycle, 'if err = owner.admit(ctx, LinuxPhysicalPrepared{Protection: before, Guardian: guardian, Policy: identity.policy}); err != nil {\n\t\t\treturn owned, err\n\t\t}', 'if err = owner.admit(ctx, LinuxPhysicalPrepared{Protection: before, Guardian: guardian, Policy: identity.policy}); false {\n\t\t\treturn owned, err\n\t\t}')),
            ('linux-node-post-admission-record', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleBracketsAdmissionAndRetainsSource', 'always/after-baseline',
             'Linux lifecycle admitted an unobserved, changed, failed or cancelled baseline', changed(lifecycle, 'after != before || afterGuardian != guardian', '(after != before && false) || afterGuardian != guardian')),
            ('linux-node-partial-source-retention', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleBracketsAdmissionAndRetainsSource', 'always/partial',
             'Linux lifecycle discarded its exact returned native owner', changed(lifecycle, 'if err != nil {\n\t\t\treturn owned, err\n\t\t}\n\t\tretainer, ok := owned.(linuxProtectionRetainer)', 'if err != nil {\n\t\t\treturn nil, err\n\t\t}\n\t\tretainer, ok := owned.(linuxProtectionRetainer)')),
            ('linux-node-post-admission-guardian', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleBracketsAdmissionAndRetainsSource', 'always/after-guardian-birth',
             'Linux lifecycle admitted an unobserved, changed, failed or cancelled baseline', changed(lifecycle, 'afterGuardian != guardian', '(afterGuardian != guardian && false)')),
            ('linux-node-retired-original-guardian', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleRetirementRequiresSuccessfulJoinAndSameRecord', 'guardian-guardian-birth',
             'Linux lifecycle adopted a changed retired guardian process', changed(lifecycle, 'captured.guardian != nil && retired != *captured.guardian', '(captured.guardian != nil && retired != *captured.guardian && false)')),
            ('linux-node-retired-original-record', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleRetirementRequiresSuccessfulJoinAndSameRecord', 'baseline',
             'Linux lifecycle adopted a changed retired native baseline', changed(lifecycle, 'captured.prepared != nil && record != *captured.prepared || ctx.Err() != nil', '(captured.prepared != nil && record != *captured.prepared && false) || ctx.Err() != nil')),
            ('linux-node-retention-joined-teardown', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleRetainedCapabilityOwnsDisconnectAndTeardown', 'always',
             'early teardown discarded baseline mutation authority', changed(lifecycle,
             'if !valid {\n\t\treturn captured, errors.New("Linux cleanup preceded its exact native source join")',
             'if !valid && false {\n\t\treturn captured, errors.New("Linux cleanup preceded its exact native source join")')),
            ('linux-node-partial-retention-kept', lifecycle, './routervpn/desktoppt', 'TestRouterVPNNodeLinuxLifecycleKeepsPartialRetentionUntilSourceJoin', '',
             'joined source leaked its partial retained endpoint', changed(lifecycle,
             'owner.retention = retention', 'if err == nil { owner.retention = retention }')),
        ))
    if platform.system() == "Linux":
        native_ledger = 'routervpn-desktop-tun/routervpn_sing_tun_network_linux.go'
        result.append(('linux-routing-foreign-goto', native_ledger, 'github.com/sagernet/sing-tun',
                       'TestRouterVPNNativeLinuxRoutingResolutionRejectsForeign', 'foreign-goto',
                       'native delta changed its original-owner admission', changed(native_ledger,
                       'if captured, ok := t.routervpnNetwork.objects[old.Key()]; !ok || captured != old {',
                       'if captured, ok := t.routervpnNetwork.objects[old.Key()]; false && (!ok || captured != old) {')))
        partial_owner = 'cmd/sing-box/routervpn_external.go'
        result.append(('linux-retirement-partial-dependencies', partial_owner, './cmd/sing-box',
                       'TestRouterVPNRawCommandNativePartialDependenciesRetention', 'external',
                       'failed original native deletion reported complete cleanup', changed(partial_owner,
                       'func routerVPNClosePartialNativeContext(ctx context.Context, partials []io.Closer) error {\n\tif ctx == nil {',
                       'func routerVPNClosePartialNativeContext(ctx context.Context, partials []io.Closer) error {\n\tif ctx == nil || ctx != nil {')))
        dns_source = 'routervpn-desktop-tun/tun.go'
        result.append(('linux-dns-ipv4-host-panic', dns_source, 'github.com/sagernet/sing-tun',
                       'TestRouterVPNNativeLinuxRoutingDNSAddressBoundary', 'ipv4-host-without-dns',
                       'unusable DNS address panicked instead of preserving native cleanup', changed(dns_source,
                       'return nil, E.New("no IPv4 server configured and no usable next address in ", o.Inet4Address[0], " for DNS")',
                       'return nil, E.New("no IPv4 server configured and no usable next address in ", o.Inet6Address[0], " for DNS")')))
        retirement = 'routervpn-desktop-tun/routervpn_sing_tun_retirement_linux.go'
        result.extend((
            ('linux-retirement-delayed-original-close', retirement, 'github.com/sagernet/sing-tun',
             NATIVE_CLOSED_EVENT_ROOT, 'late-final-ipv6',
             'original once-only close notification did not complete retirement', changed(retirement,
             'if s.created && s.closed && s.fileClosed && (s.guard == nil || s.guardClosed) &&',
             'if implicit && s.created && s.closed && s.fileClosed && (s.guard == nil || s.guardClosed) &&')),
            ('linux-retirement-duplicate-original-close', retirement, 'github.com/sagernet/sing-tun',
             NATIVE_CLOSED_EVENT_ROOT, 'duplicate-first',
             'original rejected event lost its exact bounded classification', changed(retirement,
             't.routervpnLinuxImplicitRoute(event.object) && !s.closedRouteObserved[key]',
             't.routervpnLinuxImplicitRoute(event.object)')),
            ('linux-retirement-changed-address-close', retirement, 'github.com/sagernet/sing-tun',
             NATIVE_CLOSED_EVENT_ROOT, 'changed-address-policy',
             'original rejected event lost its exact bounded classification', changed(retirement,
             't.routervpnLinuxImplicitRoute(event.object) && !s.closedRouteObserved[key]',
             '!s.closedRouteObserved[key]')),
            ('linux-retirement-wildcard-selector', retirement, 'github.com/sagernet/sing-tun',
             'TestRouterVPNNativeLinuxRoutingRetirementRejectsForeignDuplicateAndWildcard', 'marked-wildcard-match',
             'ambiguous kernel selector was deleted', changed(retirement,
             'if !routervpnLinuxDeleteDisjoint(call.object, object) {',
             'if false && !routervpnLinuxDeleteDisjoint(call.object, object) {')),
            ('linux-retirement-original-stream', retirement, 'github.com/sagernet/sing-tun',
             'TestRouterVPNNativeLinuxRoutingRetirementEventContinuityAndDisjointForeignChange', 'away-and-back',
             'snapshot hid original routing replacement', changed(retirement,
             's.events = append(s.events, events...)',
             'if expected != nil { s.events = append(s.events, events...) }')),
            ('linux-retirement-failed-close-retention', retirement, 'github.com/sagernet/sing-tun',
             'TestRouterVPNNativeLinuxRoutingRetirementRejectsForeignDuplicateAndWildcard', 'duplicate',
             'failed native cleanup dropped original authority', changed(retirement,
             'if err := t.routervpnLinuxRetireCalls(ctx, ""); err != nil {\n\t\t\treturn "", err',
             'if err := t.routervpnLinuxRetireCalls(ctx, ""); err != nil {\n\t\t\t_ = s.file.Close()\n\t\t\treturn "", err')),
        ))
        result.extend(native_resolver_mutants(source))
    return result


def native_resolver_mutants(source):
    def changed(relative, before, after, count=1):
        raw = (source / relative).read_text(encoding="utf-8")
        if raw.count(before) != count:
            raise ValueError("Native resolver mutation lost its original source boundary: " + relative)
        return raw.replace(before, after)
    resolver = "routervpn-desktop-tun/routervpn_sing_tun_resolver_linux.go"
    decoder = "routervpn-desktop-dbus/decoder.go"
    transport = "routervpn-desktop-dbus/transport_unix.go"
    return [
        ("linux-resolver-original-reply", resolver, "github.com/sagernet/sing-tun",
         "TestRouterVPNNativeLinuxResolverMutationNeedsOriginalReply", "bus-no-reply",
         "unknown daemon mutation became native cleanup", changed(resolver,
         "p.response && p.sender == p.destination && r.pending == p",
         "p.response && r.pending == p")),
        ("linux-dbus-native-fd-container", decoder, "github.com/godbus/dbus/v5",
         "TestRouterVPNDBusFDAndOrdinaryContainerTypes", "", "valid original container omitted",
         changed(decoder, "dec.routervpnTypeFor(", "typeFor(", 5)),
        ("linux-dbus-received-fd-retirement", transport, "github.com/godbus/dbus/v5",
         "TestRouterVPNDBusReceivedRightsRetireOnError", "invalid-index",
         "native descriptors leaked after rejected frame", changed(transport,
         "if !transferred { t.rdr.routervpnCloseRights() }", "if !transferred { }")),
    ]


def require_native_verdicts(output, names, label):
    # These exact suites use no subprocess Go-test output. Every declared parent
    # and leaf must start and pass once; no unselected or duplicated verdict can
    # substitute for original descriptor/lifetime coverage.
    runs = re.findall(r"(?m)^=== RUN\s+(\S+)\s*$", output)
    passed = re.findall(r"(?m)^\s*--- PASS: (\S+) \([^\n]*\)$", output)
    if sorted(runs) != sorted(names) or sorted(passed) != sorted(names) or any(
            failure in output for failure in ("--- FAIL:", "--- SKIP:", "DATA RACE", "panic:")):
        raise ValueError("Node " + label + " gate omitted, duplicated or replaced an original lifetime verdict")


def execute_baseline_suite(baselines, suite):
    name, package, selector, required = suite
    # Encrypted graph/layer and selected-DNS cases alone consumed 89.58 s on
    # Windows before the required pre-ready cases began. Keep those aggregate
    # bounds and every per-operation bound; each disjoint HY2 phase keeps 90 s.
    duration = 180 if name in ("encrypted", "composite-credentials", "sip003-retained") else 90
    if name == OPENVPN_CAPACITY_SUITE[0]:
        duration = 60
    status, output = baselines.execute(name, package, selector, duration)
    print(output, end="" if output.endswith("\n") else "\n", flush=True)
    if status or any("--- PASS: " + test + " (" not in output for test in required) or "--- SKIP:" in output or "DATA RACE" in output:
        raise ValueError("Node " + name + " omitted a required native boundary")
    if name == OPENVPN_CAPACITY_SUITE[0]:
        require_native_verdicts(output, OPENVPN_CAPACITY_VERDICTS, "OpenVPN authenticated live capacity")
    if name == "native-lifecycle-admission":
        require_native_verdicts(output, NATIVE_LIFECYCLE_ADMISSION_VERDICTS, "native lifecycle admission")
    if name == 'native-retirement-bound':
        root = 'TestDesktopNetworkRetirementKeepsSeparateBound'
        require_native_verdicts(output, [root] + [root + '/' + case for case in ('complete-history', 'oversized-writer', 'oversized-parser', 'ready-stays-bounded')], 'native retirement evidence bound')
    if name in (LINUX_SS_ENTRY_SUITE[0], SS_ENTRY_REFERENCE_SUITE[0], LINUX_SS_CONNECT_SUITE[0], SS_CONNECT_REFERENCE_SUITE[0], SS_HYSTERIA_REFERENCE_SUITE[0], SS_INDEPENDENT_LAYERS_SUITE[0]):
        require_native_verdicts(output, required, "original SS2022 entry and final")
    if name == LINUX_LAYERED_ENTRY_SUITE[0]:
        require_native_verdicts(output, required, "Linux original layered entry")
    if name in (STANDARD_RESOLVED_SUITE[0], STANDARD_MTU_SUITE[0], STANDARD_MTU_RETIRE_SUITE[0], STANDARD_MTU_NATIVE_SUITE[0], STANDARD_PARENT_SUITE[0], STANDARD_PARENT_NATIVE_SUITE[0]):
        require_native_verdicts(output, required, "standard service original MTU reader")
    if name == "native-address-retirement":
        require_native_verdicts(output, NATIVE_ADDRESS_RETIREMENT_VERDICTS, "native partial address retirement")
    if name == "native-routing-receipt":
        for full in NATIVE_CLOSED_EVENT_VERDICTS:
            runs = re.findall(r"(?m)^=== RUN\s+" + re.escape(full) + r"\s*$", output)
            passed = re.findall(r"(?m)^\s*--- PASS: " + re.escape(full) + r" \([^\n]*\)$", output)
            if len(runs) != 1 or len(passed) != 1:
                raise ValueError("Node routing gate omitted or duplicated an original closed-event diagnostic verdict: " + full)
        for case in ("", *NATIVE_DNS_CASES):
            full = "TestRouterVPNNativeLinuxRoutingDNSAddressBoundary" + ("/" + case if case else "")
            if len(re.findall(r"(?m)^\s*--- PASS: " + re.escape(full) + r" \([^\n]*\)$", output)) != 1:
                raise ValueError("Node routing gate omitted or duplicated a captured DNS address verdict: " + full)
        for case in NATIVE_RETIREMENT_CASES:
            full = "TestRouterVPNNativeLinuxRoutingRetirementNamespace/" + case
            if len(re.findall(r"(?m)^\s*--- PASS: " + re.escape(full) + r" \([^\n]*\)$", output)) != 1:
                raise ValueError("Node routing gate omitted or duplicated an actual original-TUN retirement leaf: " + case)
    if name == "native-identity-context":
        root = "TestRouterVPNNativeIdentityObservationPreservesHealthyOwner"
        require_native_verdicts(output, [root] + [root + "/" + case for case in ("engine-lock", "physical-read", "genuine-replacement", "mixed-loss-cancel", "held-cleanup")], "native identity observation")
    if name == "command-observation-context":
        parents = ["TestRouterVPNDesktopNetworkProjectionContextPreservesObservationErrors",
                   "TestRouterVPNDesktopNativeNetworkProjectionCancelsHeldOwnerLock",
                   "TestRouterVPNDesktopStopInterruptsOriginalNetworkObserver"]
        names = parents + [parents[0] + "/" + case for case in ("cancelled", "deadline", "unavailable", "identity", "success")]
        names += [root + "/" + case for root in parents[1:] for case in ("external", "tor")]
        require_native_verdicts(output, names, "command observation and Stop")
    if name == "tor-observation-context":
        require_native_verdicts(output, ["TestRouterVPNDesktopTorObservationRevokesWithoutJoiningCleanup"], "Tor observation revocation")
    if name == "owned-socket-observation-context":
        names = ["TestDesktopBrokerContextExpiryDoesNotRetireOriginal", "TestDesktopBrokerContextRequiresExplicitObserver",
                 "TestDesktopBrokerConfirmedLossSurvivesRacedCallerCancellation", "TestServerTorCurrentContextExpiresWithoutRetiringLease",
                 "TestServerTorCurrentContextKeepsCancellationSeparateFromIdentityLoss", "TestServerTorConfirmedLossSurvivesRacedCallerCancellation",
                 "TestObservationCancellationCannotHideConfirmedOwnerLoss", "TestObservationExpiryRequiresOriginalCaller",
                 "TestPaddingNativeReceiptContextPreservesOwnerOnObserverExpiry"]
        names += [names[-1] + "/" + leaf for leaf in ("lease-lock", "owner-observation", "proof-observation", "success")]
        require_native_verdicts(output, names, "owned socket and padding observations")
    if name.startswith("manager-context-"):
        names = ["TestRouterVPNManagerObservationRetainsCaller"]
        if name == "manager-context-inbound":
            names.append("TestRouterVPNManagerInventoryRetainsCaller")
        require_native_verdicts(output, names, "native manager observation")
    if name == "network-context":
        require_native_verdicts(output, NETWORK_CONTEXT_TESTS + NETWORK_CONTEXT_LEAVES, "original network observation")
    if name in TOR_REGISTRATION_VERDICTS:
        require_native_verdicts(output, TOR_REGISTRATION_VERDICTS[name], "original Tor factory registration")
    if name in STARTUP_TRANSPORT_VERDICTS:
        require_native_verdicts(output, STARTUP_TRANSPORT_VERDICTS[name], "original supervised startup transport")
    if name in STARTUP_CONTEXT_VERDICTS:
        require_native_verdicts(output, STARTUP_CONTEXT_VERDICTS[name], "original native startup deadline")
    if name in MTU_CONTEXT_VERDICTS:
        require_native_verdicts(output, MTU_CONTEXT_VERDICTS[name], "original MTU operation and cleanup")
    if name == "mtu-command-context":
        parents = ["TestRouterVPNDesktopMTUCallerContextWaits", "TestRouterVPNDesktopMTUMailboxKeepsOriginalDeadline",
                   "TestRouterVPNDesktopMTUCacheExpiredSaveIsNotACommit", "TestRouterVPNDesktopMTURestoreContextCancelsAndReprovesOriginal"]
        names = parents + [parents[0] + "/" + case for case in ("start", "record", "commit", "cancel", "cache")]
        names += [parents[1] + "/" + case for case in ("accepted-worker", "already-expired")]
        require_native_verdicts(output, names, "MTU caller deadline and captured cleanup")
    if name == "physical-mutation-context":
        root = "TestRouterVPNPhysicalTunnelOriginalMutationContext"
        names = [root] + [root + "/" + family + "/" + phase + "/" + operation for family in ("tor", "external")
                          for phase in ("admission", "acknowledgement", "native-failure") for operation in ("bind", "retire")]
        require_native_verdicts(output, names, "physical mutation caller context")
    if name == "mtu-startup-budget":
        require_native_verdicts(output, ["TestRouterVPNMTUStartupReceiptKeepsOriginalOperation"], "MTU startup budget")
    if name == "tor-mtu-release":
        root = "TestRouterVPNDesktopTorMTUReleaseWithHeldOwner"
        require_native_verdicts(output, [root, root + "/ordinary", root + "/inherited-measurement"], "Tor MTU release")
    if name == "external-lease-observation":
        root = "TestOpenVPNLeaseObservationKeepsGenuineFailureAlongsideCancellation"
        require_native_verdicts(output, [root, root + "/OK", root + "/Service_Unavailable"], "external lease observation")
    if name == "tor-mtu-heartbeat":
        root = "TestRouterVPNDesktopTorMTUHeartbeatAdoptsCompleteReceipt"
        names = ["TestRouterVPNDesktopTorMTUHeartbeatRejectsRegressedOrUnregisteredReadback", root]
        names += [root + "/previous-" + prior + "/" + outcome for prior in ("false", "true")
                  for outcome in ("network-failure", "cancel-after-readback", "cancel-after-network", "network-name", "network-index", "network-mtu", "revision-changed", "cancel-after-recheck", "success")]
        require_native_verdicts(output, names, "Tor MTU heartbeat")
    if name == "native-mtu-transaction":
        require_native_verdicts(output, [NATIVE_MTU_TEST] + [NATIVE_MTU_TEST + "/" + case for case in NATIVE_MTU_CASES], "MTU transaction")
    if name == "mtu-transaction-model":
        names = list(NATIVE_MTU_MODEL_TESTS) + ["TestRouterVPNTunTransactionRetainsOriginalAndPartialCandidateEvidence/" + case for case in ("candidate", "rollback")] + ["TestRouterVPNTunFullSearchRetainsEveryOriginalAttempt/" + case for case in ("full-search-and-winner", "failed-candidate-and-original-restore", "cancel-after-provisional-winner")]
        require_native_verdicts(output, names, "MTU manager")
    if name == "native-resolver-lifetime":
        names = list(NATIVE_RESOLVER_TESTS) + ["TestRouterVPNNativeLinuxResolver" + root + "/" + leaf
                for root, leaves in NATIVE_RESOLVER_LEAVES.items() for leaf in leaves]
        require_native_verdicts(output, names, "resolver")
    if name == "native-dbus-rights":
        names = list(NATIVE_DBUS_TESTS) + [NATIVE_DBUS_TESTS[0] + "/" + case for case in NATIVE_DBUS_CASES]
        require_native_verdicts(output, names, "D-Bus descriptor")
    if name == "hysteria2-credentials" and any("--- PASS: TestRouterVPNDesktopNodeHysteria2WrongCredential/" + case + " (" not in output for case in HYSTERIA2_CREDENTIAL_CASES):
        raise ValueError("Node Hysteria2 gate omitted a captured protocol, trust or layer credential negative")
    groups = ()
    if name == "hysteria2-identity":
        groups = (("LayerTLSIdentity", HYSTERIA2_IDENTITY_CASES),
                  ("ReferenceCapture", ("unchanged", "ip-absent", "ip-empty", "wrong-ip", "unknown-identity", "other-mode", "whitening", "wrong-layer", "wrong-mode")))
    elif name == "hysteria2-cover":
        groups = (("LayerCover", HYSTERIA2_COVER_CASES),
                  ("OuterCannotBypassFinal", ("aes-256-gcm", "aes-256-gcm+xor-whitening")))
    for group, cases in groups:
        if any("--- PASS: TestRouterVPNDesktopNodeHysteria2" + group + "/" + case + " (" not in output for case in cases):
            raise ValueError("Node Hysteria2 gate omitted original IP trust or final encrypted cover ownership")
    return output


def execute(source, go="go", *, prospective=False, env=None, bootstrap_only=False):
    if prospective:
        raise ValueError("Node native source gate does not admit a prospective OS predicate")
    source, before = checked_sources(source)
    compiler, captured, arch = selected_compiler(go, source, dict(os.environ if env is None else env))
    windows = platform.system() == "Windows"
    if not windows:
        with stage("verify complete native retirement preparation"):
            status, output = run([sys.executable, ROOT / "deploy/test_desktop_tun_retirement_projection.py", "--source", source],
                                 cwd=ROOT, env=captured, timeout=30)
            if status:
                raise ValueError("Native retirement preparation regression failed:\n" + output[-16384:])
    if not windows:
        status, output = run([sys.executable, ROOT / "deploy/test_desktop_node_routing_runner.py"],
                             cwd=ROOT, env=captured, timeout=30)
        if status:
            raise ValueError("Node routing runner checks failed:\n" + output[-16384:])
    if platform.system() == "Linux" and not bootstrap_only:
        with stage("actual WG/AWG original packet delivery drain"):
            status, output = run([sys.executable, ROOT / "deploy/test_mobile_wireguard_stack.py", source], cwd=ROOT, env=captured, timeout=600)
            if status:
                raise ValueError("WireGuard stack delivery drain failed:\n" + output[-24000:])
        with stage("actual imported entry and paired final native composition"):
            status, output = run([sys.executable, ROOT / "deploy/test_mobile_imported_entry.py", source, "--native-peers"], cwd=ROOT, env=captured, timeout=1200)
            if status:
                raise ValueError("Imported entry native composition failed:\n" + output[-24000:])
    race = [] if bootstrap_only or windows and arch == "arm64" else ["-race"]
    captured["CGO_ENABLED"] = "1" if race else "0"
    suites = [
        ("tor-registration-owner", "./routervpn/desktoppt", "^TestRouterVPNPhysicalRegistrationKeepsOriginalCaller$", ("TestRouterVPNPhysicalRegistrationKeepsOriginalCaller",)),
        ("native-startup-inbound", "./protocol/tun", "^TestRouterVPNDesktopNetworkStartupKeepsOriginalBudget$", ("TestRouterVPNDesktopNetworkStartupKeepsOriginalBudget",)),
        ("native-startup-box", ".", "^TestRouterVPNDesktopStartupKeepsCallerAndLifetime$", ("TestRouterVPNDesktopStartupKeepsCallerAndLifetime",)),
        ("mtu-operation-context", "./experimental/libbox/routervpn/mobilemtu", "^TestContext", tuple(name for name in MTU_CONTEXT_VERDICTS["mtu-operation-context"] if "/" not in name)),
        ("mtu-owner-context", "./cmd/sing-box", "^TestDesktopMTUContext", tuple(name for name in MTU_CONTEXT_VERDICTS["mtu-owner-context"] if "/" not in name)),
        ("mtu-manager-context", "./adapter/inbound", "^TestRouterVPNTunContext(RejectsLatePublicationAfterUnusedClose|AdmissionLocksDoNotConstructLate)$", tuple(name for name in MTU_CONTEXT_VERDICTS["mtu-manager-context"] if "/" not in name)),
        ("mtu-finalization-context", ".", "^TestRouterVPNMTUFinalizationContextPreservesOriginalCleanup$", ("TestRouterVPNMTUFinalizationContextPreservesOriginalCleanup",)),
        ("mtu-startup-context", "./protocol/tun", "^TestRouterVPNDesktopMTUStartupContextLifecycleDeadline$", tuple(MTU_CONTEXT_VERDICTS["mtu-startup-context"])),
        ("mtu-command-context", "./cmd/sing-box", "^TestRouterVPNDesktopMTU(CallerContextWaits|MailboxKeepsOriginalDeadline|CacheExpiredSaveIsNotACommit|RestoreContextCancelsAndReprovesOriginal)$",
         ("TestRouterVPNDesktopMTUCallerContextWaits", "TestRouterVPNDesktopMTUMailboxKeepsOriginalDeadline",
          "TestRouterVPNDesktopMTUCacheExpiredSaveIsNotACommit", "TestRouterVPNDesktopMTURestoreContextCancelsAndReprovesOriginal")),
        ("physical-mutation-context", "./routervpn/desktoppt", "^TestRouterVPNPhysicalTunnelOriginalMutationContext$", ("TestRouterVPNPhysicalTunnelOriginalMutationContext",)),
        ("external-lease-observation", "./experimental/libbox/routervpn/mobilemultihop", "^TestOpenVPNLeaseObservationKeepsGenuineFailureAlongsideCancellation$",
         ("TestOpenVPNLeaseObservationKeepsGenuineFailureAlongsideCancellation",)),
        ("tor-mtu-release", ".", "^TestRouterVPNDesktopTorMTUReleaseWithHeldOwner$",
         ("TestRouterVPNDesktopTorMTUReleaseWithHeldOwner",)),
        ("tor-mtu-heartbeat", "./cmd/sing-box", "^TestRouterVPNDesktopTorMTUHeartbeat",
         ("TestRouterVPNDesktopTorMTUHeartbeatRejectsRegressedOrUnregisteredReadback", "TestRouterVPNDesktopTorMTUHeartbeatAdoptsCompleteReceipt")),
        ("ss-packet", "./protocol/shadowsocks", "^TestRouterVPNShadowsocks",
         ("TestRouterVPNShadowsocksCompleteCiphertextPacket", "TestRouterVPNShadowsocksPacketWrongKey")),
        ("command", "./cmd/sing-box", "^TestRouterVPNDesktopNodePhysicalCommand",
         tuple("TestRouterVPNDesktopNodePhysicalCommand" + name for name in ("SourceBoundary", "Hysteria2CompleteStartSource", "XrayCompleteStartSource", "NaiveCompleteStartSource", "CompositeCompleteStartSource", "RestoredMTU", "TransferInput", "RetirementReceipt", "ReadyRequiresFreshDNS", "ReadyRequiresCapturedCover", "AdmissionExactHandshake", "AdmissionRejectsForeignReplies", "AdmissionExactStop", "AdmissionCancellationAndReplacement", "AdmissionCloseRetiresEnteredCallback", "AdmissionClosePreservesFailure", "AdmissionEveryCloseJoins", "JournalBeforePrivateInputs", "PublicRequiresJournal"))),
        ("factory", "./routervpn/desktoppt", "^TestRouterVPNNodePhysical" if windows else "^TestRouterVPNNode(Physical|LinuxLifecycle)",
         tuple("TestRouterVPNNodePhysical" + name for name in ("SeparateRegistriesAndUnpreparedRejection", "HandshakePhaseAndExactPolicy", "FactoryCancellationJoinsPartialOwner", "RetirementKeepsExactJoinedSource", "AdmissionRetainsExactPolicy", "AdmissionCapturesExactPredecessor", "JournalAdmissionCapturesDurableBarrier")) +
         (tuple("TestRouterVPNNodePhysicalWindows" + name for name in ("CapturesPreparedOwner", "AdmissionRejectsChangedOwners", "CloseJoinsAdmission")) if windows else
          tuple("TestRouterVPNNodePhysicalUnix" + name for name in ("CapturesPolicyAndRetainsLateOwner", "RejectsUncapturedSourceBeforeConstructor", "CloseJoinsLateFactoryAndRetriesSource")) +
          tuple("TestRouterVPNNodeLinuxLifecycle" + name for name in ("RejectsMissingOrReusedCapability", "BracketsAdmissionAndRetainsSource", "RetirementRequiresSuccessfulJoinAndSameRecord", "JoinsCancelledLateConstructor", "RetainedCapabilityOwnsDisconnectAndTeardown", "KeepsPartialRetentionUntilSourceJoin", "CreatesBaselineBeforeGuardian")))),
        ("box", ".", "^TestRouterVPNDesktop(NodePhysical|LinuxNodeCover)" if platform.system() == "Linux" else "^TestRouterVPNDesktopNodePhysical",
         tuple("TestRouterVPNDesktopNodePhysicalBox" + name for name in ("RejectsSubstitutedGraph", "RequiresPreparedOwner", "RetainsMTUAndExactRollback", "RestoresCapturedMTU")) +
         ("TestRouterVPNDesktopNodePhysicalDNSCapturedOwner", "TestRouterVPNDesktopNodePhysicalDNSRetirementCancelsQuery") +
         (("TestRouterVPNDesktopLinuxNodeCoverRejectsIncompleteNativeOwner", "TestRouterVPNDesktopLinuxNodeCoverCannotAdoptReplacementOrEmptySet") if platform.system() == "Linux" else ())),
        ("encrypted", "./protocol/routervpnamnezia", "^TestRouterVPNDesktopNodeEncrypted",
         ("TestRouterVPNDesktopNodeEncryptedPreReadyHandshake", "TestRouterVPNDesktopNodeEncryptedWrongPeerRejected", "TestRouterVPNDesktopNodeEncryptedConfiguredCoverStartup", "TestRouterVPNDesktopNodeEncryptedSelectedDNSIsFresh",
          "TestRouterVPNDesktopNodeEncryptedLayerTraffic", "TestRouterVPNDesktopNodeEncryptedLayerWrongCredential", "TestRouterVPNDesktopNodeEncryptedRouterHealthLayers") +
         (("TestRouterVPNDesktopNodeEncryptedPlainWireGuard", "TestRouterVPNDesktopNodeEncryptedPlainAmnezia", "TestRouterVPNDesktopNodeEncryptedAmneziaReferenceCapture") if platform.system() == "Linux" else ())),
        *HYSTERIA2_SUITES,
        ("xray-traffic", "./protocol/routervpnamnezia", "^TestRouterVPNDesktopNodeXrayTraffic$",
         ("TestRouterVPNDesktopNodeXrayTraffic",)),
        ("xray-credentials", "./protocol/routervpnamnezia", "^TestRouterVPNDesktopNodeXrayWrongCredential$",
         ("TestRouterVPNDesktopNodeXrayWrongCredential",)),
        ("naive-traffic", "./protocol/routervpnamnezia", "^TestRouterVPNDesktopNodeNaiveTraffic$",
         ("TestRouterVPNDesktopNodeNaiveTraffic",)),
        ("naive-credentials", "./protocol/routervpnamnezia", "^TestRouterVPNDesktopNodeNaiveWrongCredential$",
         ("TestRouterVPNDesktopNodeNaiveWrongCredential",)),
        ("composite-traffic", "./protocol/routervpnamnezia", "^TestRouterVPNDesktopNodeCompositeTraffic$",
         ("TestRouterVPNDesktopNodeCompositeTraffic",)),
        ("composite-credentials", "./protocol/routervpnamnezia", "^TestRouterVPNDesktopNodeCompositeWrongCredential$",
         ("TestRouterVPNDesktopNodeCompositeWrongCredential",)),
        ("sip003-retained", "./protocol/routervpnamnezia", "^TestRouterVPNDesktopNodeSIP003(RetainedProof|RetainedWrongCredential|WrongWhitening|OuterCannotBypassFinal)$",
         tuple("TestRouterVPNDesktopNodeSIP003" + suffix for suffix in ("RetainedProof", "RetainedWrongCredential", "WrongWhitening", "OuterCannotBypassFinal"))),
        ("sip003-cover-identity", "./protocol/routervpncomposite", "^TestNativeCompositePerformance(RequiresExactSIP003Owners|ObservationKeepsCaller)$",
         ("TestNativeCompositePerformanceRequiresExactSIP003Owners", "TestNativeCompositePerformanceObservationKeepsCaller")),
        ("cover-lifecycle", "./service/routervpnperformance", "^TestNativePerformance",
         tuple("TestNativePerformance" + suffix for suffix in ("NoIOUntilExplicitActivation", "StopsOnReplacementAndNetworkChange", "CannotUsePlaintextOrWrongNode", "DestinationCannotBeReplaced", "CapturedOptionsAndCancelledActivation", "CannotAdmitCompositeByTypeName"))),
    ]
    suites.append(("owned-socket-observation-context", "./routervpn/mobiletor",
                   "^Test(DesktopBroker(ContextExpiryDoesNotRetireOriginal|ContextRequiresExplicitObserver|ConfirmedLossSurvivesRacedCallerCancellation)|ServerTor(CurrentContextExpiresWithoutRetiringLease|CurrentContextKeepsCancellationSeparateFromIdentityLoss|ConfirmedLossSurvivesRacedCallerCancellation)|Observation(CancellationCannotHideConfirmedOwnerLoss|ExpiryRequiresOriginalCaller)|PaddingNativeReceiptContextPreservesOwnerOnObserverExpiry)$",
                   ("TestDesktopBrokerContextExpiryDoesNotRetireOriginal", "TestDesktopBrokerContextRequiresExplicitObserver", "TestDesktopBrokerConfirmedLossSurvivesRacedCallerCancellation",
                    "TestServerTorCurrentContextExpiresWithoutRetiringLease", "TestServerTorCurrentContextKeepsCancellationSeparateFromIdentityLoss", "TestServerTorConfirmedLossSurvivesRacedCallerCancellation",
                    "TestObservationCancellationCannotHideConfirmedOwnerLoss", "TestObservationExpiryRequiresOriginalCaller", "TestPaddingNativeReceiptContextPreservesOwnerOnObserverExpiry")))
    suites.append(("command-observation-context", "./cmd/sing-box",
                   "^TestRouterVPNDesktop(NetworkProjectionContextPreservesObservationErrors|NativeNetworkProjectionCancelsHeldOwnerLock|StopInterruptsOriginalNetworkObserver)$",
                   ("TestRouterVPNDesktopNetworkProjectionContextPreservesObservationErrors", "TestRouterVPNDesktopNativeNetworkProjectionCancelsHeldOwnerLock", "TestRouterVPNDesktopStopInterruptsOriginalNetworkObserver")))
    suites.append(("tor-observation-context", ".", "^TestRouterVPNDesktopTorObservationRevokesWithoutJoiningCleanup$", ("TestRouterVPNDesktopTorObservationRevokesWithoutJoiningCleanup",)))
    suites.append(("native-identity-context", ".", "^TestRouterVPNNativeIdentityObservationPreservesHealthyOwner$", ("TestRouterVPNNativeIdentityObservationPreservesHealthyOwner",)))
    for manager in ("inbound", "outbound", "endpoint", "service", "dns"):
        package = "./dns" if manager == "dns" else "./adapter/" + manager
        names = ("TestRouterVPNManagerObservationRetainsCaller",)
        if manager == "inbound":
            names += ("TestRouterVPNManagerInventoryRetainsCaller",)
        suites.append(("manager-context-" + manager, package, "^TestRouterVPNManager(Observation|Inventory)RetainsCaller$", names))
    suites.append(("network-context", "./protocol/tun", "^TestRouterVPNDesktopNetwork(ReceiptOriginalContext|ReceiptHeldLifecycle|ContextClaimRetainsGuard|ReceiptUnavailable)$", NETWORK_CONTEXT_TESTS))
    suites.append(("native-monitor-context", "github.com/sagernet/sing-tun", "^TestRouterVPNNativeMonitorOriginalContext$", ("TestRouterVPNNativeMonitorOriginalContext",)))
    if platform.system() == "Linux":
        suites.append(("native-startup-transport", "./cmd/sing-box", "^TestRouterVPNDesktop(StartupEnvelopeControlsOriginal(Command|Tor)|HeartbeatKeepsObservationBudget|TorProcessKeepsOriginalStartup)$", tuple(name for name in STARTUP_TRANSPORT_VERDICTS["native-startup-transport"] if "/" not in name)))
        suites.append(("native-startup-codec", "./experimental/libbox/routervpn/mobilemultihop", "^TestDesktopStartupAdmissionKeepsOriginalDeadline$", ("TestDesktopStartupAdmissionKeepsOriginalDeadline",)))
        suites.append(("tor-registration-policy", "./routervpn/desktoppt", "^TestRouterVPNLinuxPhysicalPolicyRegistrationContext$", ("TestRouterVPNLinuxPhysicalPolicyRegistrationContext",)))
        suites.append(("tor-registration-box", ".", "^TestRouterVPNDesktopTorPhysicalRegistrationContext$", ("TestRouterVPNDesktopTorPhysicalRegistrationContext",)))
        if not bootstrap_only:
            suites.append(OPENVPN_CAPACITY_SUITE)
        suites.append(LINUX_LAYERED_ENTRY_SUITE)
        suites.append(LINUX_SS_ENTRY_SUITE)
        suites.append(SS_ENTRY_REFERENCE_SUITE)
        suites.append(LINUX_SS_CONNECT_SUITE)
        suites.append(SS_CONNECT_REFERENCE_SUITE)
        suites.append(SS_HYSTERIA_REFERENCE_SUITE)
        suites.append(SS_INDEPENDENT_LAYERS_SUITE)
        suites.append(STANDARD_MTU_SUITE)
        suites.append(STANDARD_MTU_RETIRE_SUITE)
        suites.append(STANDARD_MTU_NATIVE_SUITE)
        suites.append(STANDARD_RESOLVED_SUITE)
        suites.append(STANDARD_PARENT_SUITE)
        suites.append(STANDARD_PARENT_NATIVE_SUITE)
        suites.append(('native-retirement-bound', 'github.com/sagernet/sing-tun', '^TestDesktopNetworkRetirementKeepsSeparateBound$', ('TestDesktopNetworkRetirementKeepsSeparateBound',)))
        suites.append(("native-startup-command", "./cmd/sing-box", "^TestRouterVPNRawCommandOriginalStartupDeadline$", ("TestRouterVPNRawCommandOriginalStartupDeadline",)))
        suites.append(("mtu-cleanup-context", "./adapter/inbound", "^TestRouterVPNTunContext(RestoresOnlyWithOriginalCleanupAllowance|ControllerRestoresAfterUnusedCloseCancellation)$", ("TestRouterVPNTunContextRestoresOnlyWithOriginalCleanupAllowance", "TestRouterVPNTunContextControllerRestoresAfterUnusedCloseCancellation")))
        suites.append(("native-mtu-transaction", ".", "^TestRouterVPNNativeLinuxMTUTransactionNamespace$", (NATIVE_MTU_TEST,)))
        suites.append(NATIVE_MTU_MODEL_SUITE)
        suites.append(("mtu-startup-budget", "./protocol/tun", "^TestRouterVPNMTUStartupReceiptKeepsOriginalOperation$", ("TestRouterVPNMTUStartupReceiptKeepsOriginalOperation",)))
        suites.append(("native-resolver-lifetime", "github.com/sagernet/sing-tun", "^TestRouterVPNNativeLinuxResolver", NATIVE_RESOLVER_TESTS))
        suites.append(("native-dbus-rights", "github.com/godbus/dbus/v5", "^TestRouterVPNDBus", NATIVE_DBUS_TESTS))
        suites.append(("native-routing-receipt", "github.com/sagernet/sing-tun", "^TestRouterVPNNativeLinuxRouting",
                       ("TestRouterVPNNativeLinuxRoutingResolutionRejectsForeign", "TestRouterVPNNativeLinuxRoutingReceiptNamespace",
                        "TestRouterVPNNativeLinuxRoutingConcurrentAddressProof", "TestRouterVPNNativeLinuxRoutingConcurrentAddressRejectsForeign",
                        "TestRouterVPNNativeLinuxRoutingConcurrentAddressOwnerFences", "TestRouterVPNNativeLinuxRoutingConcurrentAddressAtomicLedger",
                        "TestRouterVPNNativeLinuxRoutingOriginalOwnerDiagnostics", "TestRouterVPNNativeLinuxRoutingBoundedInventory",
                        "TestRouterVPNNativeLinuxRoutingInventoryFraming", "TestRouterVPNNativeLinuxRoutingDNSAddressBoundary",
"TestRouterVPNNativeLinuxRoutingRetirementKernelWildcardSelectors","TestRouterVPNNativeLinuxRoutingRetirementBindsActualDefaultRoutes","TestRouterVPNNativeLinuxRoutingRetirementBindsActualRuleWire","TestRouterVPNNativeLinuxRoutingRetirementOriginalCallsAndFreshStopContext","TestRouterVPNNativeLinuxRoutingRetirementRetryRetainsOriginalMilestones","TestRouterVPNNativeLinuxRoutingRetirementRejectsForeignDuplicateAndWildcard","TestRouterVPNNativeLinuxRoutingRetirementEventContinuityAndDisjointForeignChange","TestRouterVPNNativeLinuxRoutingRetirementRacingABAHasNoSuccessReceipt","TestRouterVPNNativeLinuxRoutingRetirementPartialStartupAndDefiniteRefusal","TestRouterVPNNativeLinuxRoutingRetirementNarrowerOriginalRuleFirst","TestRouterVPNNativeLinuxRoutingRetirementNoConstructorAndUnindexed","TestRouterVPNNativeLinuxRoutingRetirementHistoryBoundRetainsCapability","TestRouterVPNNativeLinuxRoutingRetirementSocket","TestRouterVPNNativeLinuxRoutingRetirementNamespace", "TestRouterVPNNativeLinuxRoutingReceiptKeepsOriginalLifetimeAndCallerBudget", "TestRouterVPNNativeLinuxRoutingReceiptHeldOperation", "TestRouterVPNNativeLinuxRoutingObserverHeldOperation", "TestRouterVPNNativeLinuxRoutingInterfaceCancelledCaller")))
        suites.append(("native-lifecycle-admission", "github.com/sagernet/sing-tun", "^("+"|".join(NATIVE_LIFECYCLE_ADMISSION_TESTS)+")$", NATIVE_LIFECYCLE_ADMISSION_TESTS))
        suites.append(("native-address-retirement", "github.com/sagernet/sing-tun", "^("+"|".join(NATIVE_ADDRESS_RETIREMENT_TESTS)+")$", NATIVE_ADDRESS_RETIREMENT_TESTS))
        suites.append(("wireguard-layers", "./protocol/routervpnamnezia",
                       "^TestRouterVPNDesktopNodeWireGuard(Layers|LayerCapture|LayerCover|OuterCannotBypassFinal)$",
                       tuple("TestRouterVPNDesktopNodeWireGuard" + name for name in
                             ("Layers", "LayerCapture", "LayerCover", "OuterCannotBypassFinal"))))
        for mode in ("awg2-fast", "awg2-strong"):
            suites.append(("amnezia-layers-" + mode, "./protocol/routervpnamnezia",
                           "^TestRouterVPNDesktopNodeAmnezia(Layers|LayerCapture|LayerCover|OuterCannotBypassFinal)$/^" + mode + "$",
                           tuple("TestRouterVPNDesktopNodeAmnezia" + name for name in
                                 ("Layers", "LayerCapture", "LayerCover", "OuterCannotBypassFinal"))))
    with tempfile.TemporaryDirectory(prefix="routervpn-node-physical-") as directory:
        workspace = Path(directory)
        with stage("prepare shipping Start Layer reference"):
            relay, relay_digest = build_layer_reference(compiler, workspace, captured, race)
        with stage("prepare pinned Xray reference"):
            xray_binary, xray_digest, xray_source, xray_records = build_xray_reference(compiler, source, workspace, captured, race)
        with stage("prepare pinned Naive library"):
            naive_library = stage_naive_library(compiler, source, workspace, captured)
        tags = TAGS + (("routervpn_openvpn_remote_test",) if platform.system() == "Linux" and not bootstrap_only else ())
        build = [compiler, "test", "-c", "-mod=readonly", "-tags=" + ",".join(tags), *race, "-ldflags=-checklinkname=0"]
        suffix = ".exe" if windows else ""
        baselines = BaselineBinaries(source, workspace, build, captured, before)
        for name, package, selector, required in suites:
            output = execute_baseline_suite(baselines, (name, package, selector, required))
            if name == "encrypted" and any("--- PASS: TestRouterVPNDesktopNodeEncryptedPreReadyHandshake/" + mode + " (" not in output for mode in ("wg", "awg2-fast", "awg2-strong")):
                raise ValueError("Node encrypted gate omitted a complete base profile")
            if name == "encrypted" and any("--- PASS: TestRouterVPNDesktopNodeEncryptedLayerTraffic/" + case + " (" not in output for case in (*LAYER_CASES, *LAYER_ALLOCATION_CASES)):
                raise ValueError("Node encrypted gate omitted an admitted graph/Start Layer")
            if name == "encrypted" and any("--- PASS: TestRouterVPNDesktopNodeEncryptedRouterHealthLayers/" + layer + " (" not in output for layer in ("off", "aes-256-gcm", "aes-256-gcm+xor-whitening", "hy2-off", "hy2-aes", "hy2-whitening")):
                raise ValueError("Node encrypted gate omitted captured Router health and selected DNS for a Start Layer")
            if name == "encrypted" and platform.system() == "Linux" and any("--- PASS: TestRouterVPNDesktopNodeEncryptedPlainWireGuard/" + case + " (" not in output for case in ("proved", "wrong-peer", "wrong-psk")):
                raise ValueError("Node encrypted gate omitted plain WireGuard selected DNS, identity or captured-key rejection")
            if name == "encrypted" and platform.system() == "Linux":
                required_awg = tuple(mode + "/" + fault for mode in ("awg2-fast", "awg2-strong")
                                     for fault in ("proved", "wrong-peer", "wrong-psk", "wrong-header", "wrong-padding"))
                if any("--- PASS: TestRouterVPNDesktopNodeEncryptedPlainAmnezia/" + case + " (" not in output for case in required_awg):
                    raise ValueError("Node encrypted gate omitted AWG2 exact parameters, selected DNS, identity or real credential/padding rejection")
                capture_cases = ("captured", "wrong-mode", "missing", "extra", "overlap", "wg-header", "wrong-client", "noncanonical-key", "self-peer", "private-alias-self-peer", "wrong-node")
                if any("--- PASS: TestRouterVPNDesktopNodeEncryptedAmneziaReferenceCapture/" + case + " (" not in output for case in capture_cases):
                    raise ValueError("Node encrypted gate omitted AWG2 captured source and canonical identity rejection")
            if name == "wireguard-layers":
                layers = ("aes-256-gcm", "aes-256-gcm+xor-whitening")
                traffic = tuple(layer + "/" + fault for layer in layers
                                for fault in ("proved", "wrong-peer", "wrong-psk", "wrong-aes")) + (layers[1] + "/wrong-whitening",)
                capture = ("captured", "whitening", "whitening-negative", "wrong-node", "wrong-client", "foreign-relay", "loopback-relay",
                           "plain-layer", "unknown-layer", "whitening-on-aes", "short-aes", "same-psk", "same-private-key", "self-peer")
                cover = tuple(layer + "/" + fault for layer in layers for fault in ("owned", "wrong-node", "drop-cover"))
                for group, cases in (("Layers", traffic), ("LayerCapture", capture), ("LayerCover", cover), ("OuterCannotBypassFinal", layers)):
                    if any("--- PASS: TestRouterVPNDesktopNodeWireGuard" + group + "/" + case + " (" not in output for case in cases):
                        raise ValueError("Node WireGuard layer gate omitted exact peer, PSK, AES/whitening, final DNS/cover or physical-route ownership")
            if name.startswith("amnezia-layers-"):
                mode = name.removeprefix("amnezia-layers-")
                if mode not in ("awg2-fast", "awg2-strong"):
                    raise ValueError("AWG layer gate lost its original mode")
                layers = ("aes-256-gcm", "aes-256-gcm+xor-whitening")
                traffic = tuple(layer + "/" + fault for layer in layers
                                for fault in ("proved", "wrong-peer", "wrong-psk", "wrong-header", "wrong-padding", "wrong-aes")) + (layers[1] + "/wrong-whitening",)
                capture = ("captured", "whitening", "whitening-negative", "wrong-node", "wrong-client", "foreign-relay", "loopback-relay",
                           "plain-layer", "unknown-layer", "whitening-on-aes", "short-aes", "same-psk", "same-private-key", "self-peer", "private-alias-self-peer",
                           "wrong-mode", "missing", "extra", "overlap", "wg-header", "noncanonical-key")
                cover = tuple(layer + "/" + fault for layer in layers for fault in ("owned", "wrong-node", "drop-cover"))
                for group, cases in (("Layers", traffic), ("LayerCapture", capture), ("LayerCover", cover), ("OuterCannotBypassFinal", layers)):
                    if any("--- PASS: TestRouterVPNDesktopNodeAmnezia" + group + "/" + mode + "/" + case + " (" not in output for case in cases):
                        raise ValueError("Node AWG layer gate omitted complete parameters, canonical identity, layer credentials, final DNS/cover or physical-route ownership")
            if name == "xray-traffic" and any("--- PASS: TestRouterVPNDesktopNodeXrayTraffic/" + case + " (" not in output for case in XRAY_CASES):
                raise ValueError("Node Xray gate omitted a complete graph/Start Layer")
            if name == "xray-credentials" and any("--- PASS: TestRouterVPNDesktopNodeXrayWrongCredential/" + case + " (" not in output for case in XRAY_CREDENTIAL_CASES):
                raise ValueError("Node Xray gate omitted a captured REALITY, PQ, user or layer credential negative")
            if name == "naive-traffic" and any("--- PASS: TestRouterVPNDesktopNodeNaiveTraffic/" + case + " (" not in output for case in NAIVE_CASES):
                raise ValueError("Node Naive gate omitted a complete HTTP version/Start Layer")
            if name == "naive-credentials" and any("--- PASS: TestRouterVPNDesktopNodeNaiveWrongCredential/" + case + " (" not in output for case in NAIVE_CREDENTIAL_CASES):
                raise ValueError("Node Naive gate omitted a captured user, password, certificate or layer credential negative")
            if name == "sip003-retained":
                for group, cases in (("RetainedProof", SIP003_PROOF_CASES), ("RetainedWrongCredential", SIP003_CREDENTIAL_CASES),
                                     ("OuterCannotBypassFinal", SIP003_LAYERS[1:])):
                    if any("--- PASS: TestRouterVPNDesktopNodeSIP003" + group + "/" + case + " (" not in output for case in cases):
                        raise ValueError("Node SIP003 gate omitted independent encrypted proof, selected DNS, cover or captured credential rejection")
            if name == "sip003-cover-identity" and any("--- PASS: TestNativeCompositePerformanceRequiresExactSIP003Owners/" + case + " (" not in output for case in SIP003_IDENTITY_CASES):
                raise ValueError("Node SIP003 cover capability omitted a captured lifecycle or lane replacement control")
            if name == "composite-traffic" and any("--- PASS: TestRouterVPNDesktopNodeCompositeTraffic/" + case + " (" not in output for case in (*COMPOSITE_CASES, *COMPOSITE_ALLOCATION_CASES)):
                raise ValueError("Node composite gate omitted simultaneous original TCP/UDP branches or a Start Layer")
            if name == "composite-credentials" and any("--- PASS: TestRouterVPNDesktopNodeCompositeWrongCredential/" + case + " (" not in output for case in COMPOSITE_CREDENTIAL_CASES):
                raise ValueError("Node composite gate omitted an independent TCP, UDP or shared Start Layer credential negative")
        for label, relative, package, test, subtest, witness, replacement in mutants(source, windows):
            changed = workspace / (label + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (label + ".json")
            overlay.write_text(json.dumps({"Replace": {str(source / relative): str(changed)}}), encoding="utf-8")
            binary = workspace / (label + ".test" + suffix)
            with stage("compile control " + label):
                status, output = run([*build, "-overlay=" + str(overlay), "-o", binary, package], cwd=source, env=captured, timeout=600)
                if status:
                    raise ValueError("Node negative control failed to compile: " + label + "\n" + output[-16384:])
            selector = "^" + test + "$" + ("/^" + subtest + "$" if subtest else "")
            with stage("execute control " + label):
                status, output = run([binary, "-test.run=" + selector, "-test.count=1", "-test.timeout=45s", "-test.v"], cwd=source, env=captured, timeout=55)
            if status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or any(value in output for value in ("--- SKIP:", "DATA RACE", "panic: test timed out")):
                raise ValueError("Node negative control missed its precise production defect: " + label + "\n" + output[-16384:])
            print("Rejected native Node production mutant: " + label, flush=True)
        if relay.is_symlink() or hashlib.sha256(relay.read_bytes()).hexdigest() != relay_digest:
            raise ValueError("Node shipping whitening reference changed during actual execution")
        if xray_binary.is_symlink() or hashlib.sha256(xray_binary.read_bytes()).hexdigest() != xray_digest or xray_reference_sources(xray_source) != xray_records:
            raise ValueError("Node pinned Xray reference changed during actual execution")
        verify_naive_library(naive_library)
    if checked_sources(source)[1] != before:
        raise ValueError("Node native source changed during actual execution")
    print("Exact native Node startup, captured IPC, retained TUN/MTU rollback, real WG/AWG/Shadowsocks/Hysteria2/REALITY Vision/PQ/XHTTP/Naive H2/H3/split/raw-MAX plus AES/XOR encrypted TCP/UDP, fresh selected DNS and wrong-key controls passed. OS permits/TUN remain explicit fixtures; kernel composition and both-direction host activation remain separate.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, nargs="?")
    parser.add_argument("--go", default="go")
    parser.add_argument("--standalone", action="store_true")
    args = parser.parse_args()
    if args.standalone:
        if args.source is not None:
            parser.error("--standalone owns a fresh prepared Windows core")
        BOOT.standalone(args.go, native_test=execute)
    else:
        if args.source is None:
            parser.error("a prepared native core or --standalone is required")
        execute(args.source, args.go)
