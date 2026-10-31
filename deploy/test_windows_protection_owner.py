#!/usr/bin/env python3
"""Prove retained protection preparation against the actual Windows kernel.

The fixture uses a fresh private directory for each case. It creates no Firewall
rule, changes no profile, and never opens the production recovery directory.
Native files, security descriptors, process tokens and deletion handles remain
real; metadata-only comparisons are never accepted as native owner authority.
"""
from pathlib import Path
import argparse
import ctypes
import hashlib
import importlib.util
import json
import os
import platform
import tempfile

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "windows_protection_native_toolchain", ROOT / "deploy/test_desktop_windows_identity.py")
NATIVE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(NATIVE)
TARGET = ROOT / "internal/windowsprotection"
PACKAGE = "./internal/windowsprotection"
REQUIRED = (
    "TestWindowsProtectionOwnerRecordRoundTrip",
    "TestWindowsProtectionOwnerRecordInvalidFields",
    "TestWindowsProtectionOwnerRecordStrictEncoding",
    "TestWindowsProtectionOwnerRecordSID",
    "TestWindowsProtectionOwnerRecordDigest",
    "TestWindowsProtectionPreparedOwnerActualLifecycle",
    "TestWindowsProtectionPreparedOwnerPinsNamespaceAndFile",
    "TestWindowsProtectionPreparedOwnerPreservesRecoveryRecord",
    "TestWindowsProtectionPreparedOwnerRejectsChangedIdentity",
    "TestWindowsProtectionPreparedOwnerRejectsChangedRecord",
    "TestWindowsProtectionPreparedOwnerCancellationAndConcurrentDiscard",
    "TestWindowsProtectionPreparedOwnerDiscardRetriesSameHandle",
    "TestWindowsProtectionPreparedOwnerRejectsUntrustedOrExistingState",
    "TestWindowsProtectionCapturedObjectsRejectHardlinks",
    "TestWindowsProtectionCapturedAncestorsRejectRename",
)
JOURNAL_REQUIRED = (
    "TestWindowsProtectionJournalCanonicalLifecycle",
    "TestWindowsProtectionJournalRejectsChangedIdentity",
    "TestWindowsProtectionJournalStrictEncoding",
    "TestWindowsProtectionJournalRetirementSemantics",
    "TestWindowsProtectionJournalRejectsUnprovedTransitions",
    "TestWindowsProtectionJournalSlotRecoveryDoesNotGuessCommit",
    "TestWindowsProtectionJournalRejectsForeignOrReorderedSlots",
    "TestWindowsProtectionJournalRecoveryCopiesCapturedTargets",
    "TestWindowsProtectionJournalRejectsUncheckedControllerReplacement",
    "TestWindowsProtectionJournalRetainsCapturedProfileRevision",
    "TestWindowsProtectionJournalLegacyBytesStayUnbound",
    "TestWindowsProtectionJournalRejectsMissingOrMixedBinding",
)
JOURNAL_STORE_REQUIRED = (
    "TestWindowsProtectionJournalHeaderIdentity",
    "TestWindowsProtectionJournalHeaderStrictEncoding",
    "TestWindowsProtectionJournalStoreActualLifecycle",
    "TestWindowsProtectionJournalStoreExclusiveAndNamespace",
    "TestWindowsProtectionJournalStoreRejectsReplacedFiles",
    "TestWindowsProtectionJournalStoreOriginalUserAndData",
    "TestWindowsProtectionJournalStoreTornSlotIsReadOnly",
    "TestWindowsProtectionJournalStorePendingWriteRetriesSameOwner",
    "TestWindowsProtectionJournalStoreRejectsCreatorAndCancellation",
    "TestWindowsProtectionJournalStoreInitialAuthorityAndACL",
    "TestWindowsProtectionJournalStoreConcurrentClose",
    "TestWindowsProtectionJournalStoreRejectsUnboundTarget",
    "TestWindowsProtectionJournalStartupAbsentWithoutCreation",
    "TestWindowsProtectionJournalStartupExistingAndIncomplete",
    "TestWindowsProtectionJournalStartupRejectsChangedObservation",
)
JOURNAL_COMMIT_REQUIRED = (
    "TestJournalCommitExactRoundTrip",
    "TestJournalCommitCaptureRejectsUnownedHead",
    "TestJournalCommitRequestBindsWholeCapture",
    "TestJournalCommitDerivesExactIntentWithoutAliasing",
    "TestJournalCommitReplyBindsActualEngineAndNonce",
    "TestJournalCommitPreservesProfileBytesAndIntentBound",
    "TestJournalCommitRejectsNoncanonicalFrames",
)
JOURNAL_CHANNEL_REQUIRED = (
    "TestWindowsProtectionJournalChannelActualCommit",
    "TestWindowsProtectionJournalChannelRejectsForgedServer",
    "TestWindowsProtectionJournalChannelRejectsDifferentChild",
    "TestWindowsProtectionJournalChannelFailedPersistence",
    "TestWindowsProtectionJournalChannelLateReplacement",
    "TestWindowsProtectionJournalChannelCloseJoinsAppend",
    "TestWindowsProtectionJournalChannelRetirementOwnership",
)
JOURNAL_ADMISSION_REQUIRED = (
    'TestJournalAdmissionExactRoundTrip',
    'TestJournalAdmissionRequestBindsWholeIntent',
    'TestJournalAdmissionRejectsUnreadyIntent',
    'TestJournalAdmissionSettlementKeepsExactLiveSuccessor',
    'TestJournalAdmissionSettlementCopiesCapturedState',
    'TestJournalAdmissionReplyBindsRequestAndSettlement',
    'TestJournalAdmissionRejectsNoncanonicalFrames',
)
JOURNAL_ADMISSION_NATIVE_REQUIRED = (
    'TestWindowsProtectionJournalAdmissionTwoPhaseCheckpoint',
    'TestWindowsProtectionJournalAdmissionPreparedReadFailures',
    'TestWindowsProtectionJournalAdmissionSettlementWriteFailure',
    'TestWindowsProtectionJournalAdmissionOperationReplacement',
    'TestWindowsProtectionJournalAdmissionCandidateMismatch',
    'TestWindowsProtectionJournalAdmissionCloseJoinsPreparedRead',
    'TestWindowsProtectionJournalAdmissionRetainedAdmissionClose',
)
JOURNAL_CAPTURE_REQUIRED = (
    'TestWindowsProtectionJournalAdmissionCapturedCheckpoint',
    'TestWindowsProtectionJournalAdmissionCapturedOwnerFailure',
    'TestWindowsProtectionJournalAdmissionRequiresCapturedOwner',
    'TestWindowsProtectionJournalAdmissionCloseJoinsCapturedOwner',
)
JOURNAL_ATTEMPT_REQUIRED = (
    'TestWindowsProtectionJournalAttemptPendingDrain',
    'TestWindowsProtectionJournalAttemptRejectsNewerCheckpoint',
    'TestWindowsProtectionJournalAttemptNoWrite',
)
JOURNAL_RECOVERY_REQUIRED = (
    'TestWindowsProtectionJournalRecoveryExactOutcomes',
    'TestWindowsProtectionJournalRecoveryKeepsPendingOff',
    'TestWindowsProtectionJournalRecoveryRejectsChangedProvenance',
    'TestWindowsProtectionJournalRecoveryRequiresBoundIntactHead',
    'TestWindowsProtectionJournalRecoveryProcessProvenance',
    'TestWindowsProtectionJournalRecoveryOwnedOrdering',
    'TestWindowsProtectionJournalRecoveryRejectsMissingProof',
    'TestWindowsProtectionJournalRecoveryExactWriteRetry',
    'TestWindowsProtectionJournalRecoveryDurableErrorRetries',
    'TestWindowsProtectionJournalRecoveryCancellationJoinsWriter',
    'TestWindowsProtectionJournalRecoveryCapturesImmutableInputs',
    'TestWindowsProtectionJournalRecoveryLostSnapshotStaysUnresolved',
)
JOURNAL_RECOVERY_NATIVE_REQUIRED = (
    'TestWindowsProtectionJournalRecoveryNativeControllerRetirement',
    'TestWindowsProtectionJournalRecoveryNativeEngineRetirement',
    'TestWindowsProtectionJournalRecoveryNativePendingOff',
    'TestWindowsProtectionJournalRecoveryNativePIDReuseAndToken',
    'TestWindowsProtectionJournalRecoveryNativeExactAppendRetry',
    'TestWindowsProtectionJournalRecoveryNativeLegacyAndTornState',
    'TestWindowsProtectionJournalRecoveryNativeSnapshotAndExit',
    'TestWindowsProtectionJournalRecoveryNativeCloseJoinsObservation',
    'TestWindowsProtectionJournalRecoveryNativeStickyClose',
)
REQUIRED_SUBCASES = {
    REQUIRED[6]: ("record-write", "record-delete", "record-rename", "root-rename", "parent-rename"),
    REQUIRED[8]: ("session", "source", "config", "network", "generation"),
    REQUIRED[12]: ("foreign-owner", "broad-write", "inherited", "legacy-record", "unknown-journal",
                   "foreign-lock", "linked-parent"),
    JOURNAL_STORE_REQUIRED[3]: ("header-write", "lock-delete", "slot-rename", "root-rename", "parent-rename", "data-rename"),
    JOURNAL_STORE_REQUIRED[4]: ("files.json", "journal.lock", "slot-0.json", "slot-1.json"),
    JOURNAL_STORE_REQUIRED[5]: ("desktop-user", "private-directory", "unknown-file"),
    JOURNAL_STORE_REQUIRED[6]: ("initial", "later"),
    JOURNAL_STORE_REQUIRED[9]: ("unproved-absence", "user-owner", "broad-write", "inherited", "legacy-file"),
    JOURNAL_STORE_REQUIRED[11]: ("new-candidate", "old-release-to-absence", "old-off-to-absence"),
    JOURNAL_STORE_REQUIRED[13]: ("complete", "files.json", "journal.lock", "slot-0.json", "slot-1.json", "other-data", "unknown-root"),
    JOURNAL_STORE_REQUIRED[14]: ("native-protection", "cancelled", "namespace-appeared", "desktop", "data", "machine-ancestor", "missing-reader"),
    JOURNAL_CHANNEL_REQUIRED[6]: ("server", "client"),
    JOURNAL_ADMISSION_NATIVE_REQUIRED[1]: ("before-flush", "after-flush"),
    JOURNAL_ATTEMPT_REQUIRED[0]: ("intent", "settled"),
    JOURNAL_RECOVERY_NATIVE_REQUIRED[1]: ("settled-live", "pending-successor"),
    JOURNAL_RECOVERY_NATIVE_REQUIRED[2]: ("retained", "absence-unsaved"),
    JOURNAL_RECOVERY_NATIVE_REQUIRED[3]: ("reused-creation", "wrong-token"),
    JOURNAL_RECOVERY_NATIVE_REQUIRED[5]: ("legacy-unbound", "torn-peer", "retired-desktop"),
}


def sources():
    expected = {"record.go", "record_test.go", "owner_windows.go", "owner_windows_test.go",
                "path_windows.go", "security_windows.go", "journal_record.go", "journal_record_test.go", "journal_profile_binding_test.go",
                "journal_header.go", "journal_header_test.go", "journal_store_windows.go", "journal_store_windows_test.go",
                "journal_startup_windows.go", "journal_startup_windows_test.go",
                "journal_commit_record.go", "journal_commit_record_test.go",
                "journal_channel_windows.go", "journal_channel_windows_test.go",
                "journal_admission_record.go", "journal_admission_record_test.go",
                "journal_admission_windows.go", "journal_admission_windows_test.go",
                "journal_admission_capture_windows_test.go", "journal_attempt_windows_test.go",
                "journal_recovery_record.go", "journal_recovery_record_test.go",
                "journal_recovery.go", "journal_recovery_test.go",
                "journal_recovery_windows.go", "journal_recovery_windows_test.go"}
    owned = sorted(TARGET.glob("*.go"))
    if {path.name for path in owned} != expected:
        raise ValueError("Windows protection owner source/test closure changed")
    controller = sorted((ROOT / "internal/windowscontroller").glob("*.go"))
    if not {"process_windows.go", "identity_windows.go", "machine_directories_windows.go", "inherited_process_windows.go"}.issubset(
            path.name for path in controller):
        raise ValueError("Windows protection owner lost its shipping native identity dependency")
    # Journal target comparison uses the actual shared native WFP types. Capture
    # that source dependency as well; decoded records still confer no authority.
    physical = sorted((ROOT / "internal/mobiletor").glob("*.go"))
    bootstrap = sorted((ROOT / "internal/windowsbootstrap").glob("*.go"))
    if {path.name for path in bootstrap} != {"layout.go", "layout_test.go", "protocol.go", "protocol_test.go"}:
        raise ValueError("Native journal channel lost its exact controller bootstrap dependency")
    paths = owned + controller + bootstrap + physical + [ROOT / "go.mod", Path(__file__).resolve(),
                                  ROOT / "deploy/test_desktop_windows_identity.py",
                                  ROOT / "deploy/prepare-desktop-external.py"]
    result = {}
    for path in paths:
        if not path.is_file() or any(part.is_symlink() for part in (path, *path.parents) if part != ROOT.parent):
            raise ValueError("Windows protection owner source is not its regular captured file")
        result[path.relative_to(ROOT).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def mutants():
    read = lambda name: (TARGET / name).read_text(encoding="utf-8")
    once, function = NATIVE.replace_once, NATIVE.function_mutant
    owner, path, security = read("owner_windows.go"), read("path_windows.go"), read("security_windows.go")
    journal, header = read("journal_store_windows.go"), read("journal_header.go")
    startup = read("journal_startup_windows.go")
    commit = read("journal_commit_record.go")
    channel = read("journal_channel_windows.go")
    admission = read("journal_admission_record.go")
    native_admission = read("journal_admission_windows.go")
    recovery_record, recovery = read("journal_recovery_record.go"), read("journal_recovery.go")
    recovery_native, journal_record = read("journal_recovery_windows.go"), read("journal_record.go")
    if native_admission.count("server.currentOwner()") != 6:
        raise ValueError("Native prepared admission changed its captured ownership checks")
    peer_call = "client.pipe.VerifyPeer(client.parent, client.parentImage)"
    if channel.count(peer_call) != 3:
        raise ValueError("Native journal inherited-parent peer callsites changed")
    changed_bytes = once(owner, "read > OwnerRecordLimit || !bytes.Equal(buffer[:read], owner.body)",
                         "read > OwnerRecordLimit || false && !bytes.Equal(buffer[:read], owner.body)")
    changed_bytes = once(changed_bytes, "if err != nil || actual != owner.record {",
                         "if err != nil || false && actual != owner.record {")
    return (
        ("journal_startup_windows.go", "startup-ignores-native-absence", JOURNAL_STORE_REQUIRED[14],
         "startup accepted changed native protection, namespace or retained identity",
         once(startup, "\tif err := read(ctx, nil); err != nil {\n\t\treturn false, err\n\t}\n", "")),
        ("journal_startup_windows.go", "startup-ignores-appeared-namespace", JOURNAL_STORE_REQUIRED[14],
         "startup accepted changed native protection, namespace or retained identity",
         once(startup, "// into an absent store. Retain an unexpected opened root for checked Close.\n\tif err := store.verifyInitialNamespaceAbsent(); err != nil {\n\t\treturn false, err\n\t}\n",
              "// Test-only defect: omit the second native namespace observation.\n")),
        ("journal_startup_windows.go", "startup-ignores-retired-capture", JOURNAL_STORE_REQUIRED[14],
         "startup accepted changed native protection, namespace or retained identity",
         once(startup, "\tif err := store.verifyInitialAbsenceCapture(ctx); err != nil {\n\t\treturn false, err\n\t}\n\treturn true, nil",
              "\treturn true, nil")),
        ("journal_record.go", "mutable-adoption-provenance", JOURNAL_RECOVERY_REQUIRED[2],
         "ordinary checkpoint rewrote immutable adoption provenance",
         once(journal_record, "!sameJournalAdoption(previous.Adoption, next.Adoption)", "false && !sameJournalAdoption(previous.Adoption, next.Adoption)")),
        ("journal_recovery_record.go", "recovery-erases-pending-off", JOURNAL_RECOVERY_REQUIRED[0],
         "recovery erased the accepted Off before its actual profile-save acknowledgment",
         once(recovery_record, 'if previous.Phase != "intent" || previous.Intent.Action != "off" {', 'if true {')),
        ("journal_recovery.go", "recovery-changes-first-outcome", JOURNAL_RECOVERY_REQUIRED[7],
         "retry replaced the first observed native outcome after uncertain persistence",
         once(recovery, "if owner.selected >= 0 && owner.selected != matched {", "if false && owner.selected >= 0 && owner.selected != matched {")),
        ("journal_recovery_record.go", "recovery-forgets-candidate-engine", JOURNAL_RECOVERY_REQUIRED[4],
         "recovery omitted its previous controller or possible native source",
         function(recovery_record, "func journalRecoveryProcesses(", "if record.Intent != nil {", "if false && record.Intent != nil {")),
        ("journal_recovery_windows.go", "recovery-adopts-live-controller", JOURNAL_RECOVERY_NATIVE_REQUIRED[0],
         "a live old controller reached native observation or journal adoption",
         once(recovery_native, '\tif process.Alive() == nil {\n\t\treturn errors.New("Windows journal recovery still has a live recorded controller or engine")\n\t}',
              '\tif process.Alive() == nil {\n\t\twitness.retired = true\n\t\treturn nil\n\t}')),
        ("journal_recovery_windows.go", "recovery-accepts-wrong-primary-token", JOURNAL_RECOVERY_NATIVE_REQUIRED[6],
         "exited process with a different recorded primary token was accepted",
         once(recovery_native, "if err != nil || !identity.Primary || identity.SID != witness.recorded.SID ||\n\t\tidentity.AuthenticationID != witness.recorded.AuthenticationID || identity.SessionID != witness.recorded.SessionID {",
              "if false && (err != nil || !identity.Primary || identity.SID != witness.recorded.SID ||\n\t\tidentity.AuthenticationID != witness.recorded.AuthenticationID || identity.SessionID != witness.recorded.SessionID) {")),
        ("journal_recovery_windows.go", "recovery-confuses-reused-pid", JOURNAL_RECOVERY_NATIVE_REQUIRED[3],
         "recorded prior creation was confused with the live replacement process",
         once(recovery_native, "if started != witness.recorded.StartTimeUTCTicks {", "if false && started != witness.recorded.StartTimeUTCTicks {")),
        ("journal_commit_record.go", "lost-captured-profile-binding", "TestWindowsProtectionJournalRetainsCapturedProfileRevision",
         "successor lost its actual captured profile binding",
         once(commit, "ProfileID: capture.ProfileID, ProfileRevision: capture.ProfileRevision, Engine: &actualEngine", "ProfileID: capture.ProfileID, Engine: &actualEngine")),
        ("journal_store_windows.go", "unbound-native-journal-write", "TestWindowsProtectionJournalStoreRejectsUnboundTarget",
         "unbound target acquired native journal write authority",
         once(journal, "\tif err := requireJournalProfileBindings(next); err != nil {\n\t\treturn JournalSelection{}, err\n\t}\n", "")),
        ("journal_store_windows.go", "unbound-old-journal-retirement", "TestWindowsProtectionJournalStoreRejectsUnboundTarget",
         "unbound old intent acquired native empty-settlement authority",
         once(journal, "\tif err := requireJournalProfileBindings(store.current.Record); err != nil {\n\t\treturn JournalSelection{}, err\n\t}\n", "")),
        ("security_windows.go", "native-security-readback", REQUIRED[12],
         "an existing or untrusted protection owner was adopted",
         function(security, "func verifyProtectionSecurity(", "return security.verify(directory)", "return nil")),
        ("owner_windows.go", "captured-connection", REQUIRED[8],
         "another captured connection acquired the native preparation",
         once(owner, "if capture != owner.record.Capture {", "if false {")),
        ("path_windows.go", "retained-file-identity", REQUIRED[8],
         "another retained file identity acquired the native preparation",
         once(path,
              "return expected.VolumeSerialNumber == actual.VolumeSerialNumber && expected.FileIndexHigh == actual.FileIndexHigh &&\n\t\texpected.FileIndexLow == actual.FileIndexLow && expected.NumberOfLinks == actual.NumberOfLinks",
              "return true")),
        ("path_windows.go", "single-record-link", REQUIRED[13],
         "multiply linked recovery record acquired native file authority",
         once(path, " || !directory && actual.NumberOfLinks != 1", "")),
        ("owner_windows.go", "immutable-owner-record", REQUIRED[9],
         "changed immutable owner bytes were accepted", changed_bytes),
        ("owner_windows.go", "joined-discard-retry", REQUIRED[11],
         "retried native discard did not independently prove absence",
         once(owner, "if owner.discarded {", "if owner.discarded || owner.discarding {")),
        ("owner_windows.go", "durable-close-record", REQUIRED[7],
         "Close discarded or changed the durable owner record",
         function(owner, "func (owner *PreparedOwner) Close()", "return owner.closeLocked()",
                  "return errors.Join(owner.deleteCreatedRecord(), owner.closeLocked())")),
        ("path_windows.go", "retained-ancestor-sharing", REQUIRED[14],
         "captured protection ancestry allowed a namespace replacement",
         function(path, "func pinProtectionDirectory(", "syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE)",
                  "syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE)")),
        ("path_windows.go", "metadata-only-ancestor", REQUIRED[14],
         "captured protection ancestry allowed a namespace replacement",
         function(path, "func pinProtectionDirectory(",
                  "syscall.FILE_LIST_DIRECTORY|protectionReadAttributes|protectionReadControl",
                  "protectionReadAttributes|protectionReadControl")),
        ("journal_header.go", "canonical-native-header", JOURNAL_STORE_REQUIRED[1],
         "noncanonical journal header encoding was admitted",
         once(header, "if err != nil || !bytes.Equal(raw, canonical) {",
              "if err != nil || false && !bytes.Equal(raw, canonical) {")),
        ("journal_store_windows.go", "replaced-journal-file", JOURNAL_STORE_REQUIRED[4],
         "journal adopted identical bytes under a replacement native file identity",
         once(journal, "if store.header != expected || store.header.validate() != nil {",
              "if false && store.header != expected || store.header.validate() != nil {")),
        ("journal_store_windows.go", "durable-journal-lock", JOURNAL_STORE_REQUIRED[2],
         "journal close deleted or rewrote its durable native owner",
         function(journal, "func (store *ProtectionJournal) Close()", "return errors.Join(store.closeErr, failure)",
                  "if store.lock != nil && failure == nil { _ = os.Remove(store.lock.path) }; return errors.Join(store.closeErr, failure)")),
        ("journal_store_windows.go", "same-pending-journal-write", JOURNAL_STORE_REQUIRED[7],
         "journal failed-write retry adopted another pending operation",
         once(journal, "} else if !bytes.Equal(store.pending.body, body) {",
              "} else if false && !bytes.Equal(store.pending.body, body) {")),
        ("journal_store_windows.go", "unacknowledged-journal-write", JOURNAL_STORE_REQUIRED[7],
         "failed durable append was silently acknowledged by Snapshot",
         function(journal, "func (store *ProtectionJournal) Snapshot(", "if store.pending != nil {",
                  "if false && store.pending != nil {")),
        ("journal_store_windows.go", "torn-journal-append", JOURNAL_STORE_REQUIRED[6],
         "incomplete journal acquired ordinary append authority",
         once(once(journal,
                   "previousSHA256 != store.current.SHA256 || store.current.Incomplete {",
                   "previousSHA256 != store.current.SHA256 || false && store.current.Incomplete {"),
              "selection.SHA256 != previousSHA256 || selection.Incomplete {",
              "selection.SHA256 != previousSHA256 || false && selection.Incomplete {")),
        ("journal_commit_record.go", "commit-exact-predecessor", JOURNAL_COMMIT_REQUIRED[1],
         "invalid captured journal head or predecessor was accepted",
         once(commit, "return *a == *b", "return true")),
        ("journal_commit_record.go", "commit-complete-capture", JOURNAL_COMMIT_REQUIRED[2],
         "request admitted another complete captured journal or configuration",
         once(commit, "request.CaptureSHA256 != journalCommitDigest(canonical)",
              "false && request.CaptureSHA256 != journalCommitDigest(canonical)")),
        ("journal_commit_record.go", "commit-candidate-source", JOURNAL_COMMIT_REQUIRED[2],
         "request admitted a changed native candidate or challenge",
         once(once(commit, "if request.Candidate.Capture.SessionID != capture.Transfer.SessionID ||",
                   "if false && (request.Candidate.Capture.SessionID != capture.Transfer.SessionID ||"),
              "request.Candidate.Policy != capture.Transfer.Policy {",
              "request.Candidate.Policy != capture.Transfer.Policy) {")),
        ("journal_commit_record.go", "commit-intent-digest", JOURNAL_COMMIT_REQUIRED[4],
         "commit reply accepted an unrelated intent digest or sequence",
         once(commit, "reply.IntentSHA256 != journalCommitDigest(intentRaw)",
              "false && reply.IntentSHA256 != journalCommitDigest(intentRaw)")),
        ("journal_commit_record.go", "commit-captured-head-copy", JOURNAL_COMMIT_REQUIRED[3],
         "derived intent rewrote its captured caller-owned comparison values",
         once(commit, "next := cloneJournalRecord(capture.Head)", "next := capture.Head")),
        ("journal_commit_record.go", "commit-canonical-capture", JOURNAL_COMMIT_REQUIRED[6],
         "noncanonical capture reached the private commit contract",
         once(commit, "if err != nil || !bytes.Equal(raw, canonical) {\n\t\treturn JournalCommitCapture{},",
              "if err != nil || false && !bytes.Equal(raw, canonical) {\n\t\treturn JournalCommitCapture{},")),
        ("journal_admission_record.go", 'admission-whole-intent', 'TestJournalAdmissionRequestBindsWholeIntent',
         'admission request accepted another complete successor intent',
         once(admission, 'request.IntentSHA256 != journalCommitDigest(intentRaw)',
              'false && request.IntentSHA256 != journalCommitDigest(intentRaw)')),
        ("journal_admission_record.go", 'admission-old-predecessor', 'TestJournalAdmissionSettlementKeepsExactLiveSuccessor',
         'admission checkpoint retained the predecessor instead of its exact candidate',
         once(admission, 'next.Committed = next.Intent.Candidate',
              'next.Committed = cloneJournalState(intent.Committed)')),
        ("journal_admission_record.go", 'admission-clear-live-engine', 'TestJournalAdmissionSettlementKeepsExactLiveSuccessor',
         'admission checkpoint prematurely forgot its live native engine',
         once(admission, 'next.Committed = next.Intent.Candidate',
              'next.Committed = next.Intent.Candidate\n\tnext.Committed.Engine = nil')),
        ("journal_admission_record.go", 'admission-candidate-alias', 'TestJournalAdmissionSettlementCopiesCapturedState',
         'admission checkpoint aliases the captured candidate owner',
         once(admission, 'next := cloneJournalRecord(intent)',
              'next := intent')),
        ("journal_admission_record.go", 'admission-reply-nonce', 'TestJournalAdmissionReplyBindsRequestAndSettlement',
         'admission reply accepted a different challenge',
         once(admission, 'reply.RequestSHA256 != journalCommitDigest(requestRaw)',
              'false && reply.RequestSHA256 != journalCommitDigest(requestRaw)')),
        ("journal_admission_record.go", 'admission-reply-active-checkpoint', 'TestJournalAdmissionReplyBindsRequestAndSettlement',
         'admission reply accepted another actual engine checkpoint',
         once(admission, 'reply.SettledSHA256 != journalCommitDigest(settledRaw)',
              'false && reply.SettledSHA256 != journalCommitDigest(settledRaw)')),
        ("journal_admission_record.go", 'admission-request-canonical', 'TestJournalAdmissionRejectsNoncanonicalFrames',
         'noncanonical admission request reached prepared comparison',
         once(admission, 'if err != nil || !bytes.Equal(raw, canonical) {\n\t\treturn JournalAdmissionRequest{}, errors.New',
              'if err != nil || false && !bytes.Equal(raw, canonical) {\n\t\treturn JournalAdmissionRequest{}, errors.New')),
        ("journal_admission_record.go", 'admission-reply-canonical', 'TestJournalAdmissionRejectsNoncanonicalFrames',
         'noncanonical admission reply reached active checkpoint comparison',
         once(admission, 'if err != nil || !bytes.Equal(raw, canonical) {\n\t\treturn JournalAdmissionReply{}, errors.New',
              'if err != nil || false && !bytes.Equal(raw, canonical) {\n\t\treturn JournalAdmissionReply{}, errors.New')),
        ("journal_admission_windows.go", "prepared-read-before-flush", JOURNAL_ADMISSION_NATIVE_REQUIRED[1],
         "pre-flush failure fabricated a durable settled checkpoint",
         once(native_admission,
              "if err := read(bounded, target); err != nil {\n\t\treturn JournalRecord{}, err\n\t}",
              "// Broken: the prepared kernel state was not read before checkpoint persistence.")),
        ("journal_admission_windows.go", "prepared-read-after-flush", JOURNAL_ADMISSION_NATIVE_REQUIRED[1],
         "native admission omitted its failed independent read",
         once(native_admission,
              "if err := read(bounded, target); err != nil {\n\t\treturn durable, err\n\t}",
              "// Broken: the prepared kernel state was not read after checkpoint persistence.")),
        ("journal_admission_windows.go", "prepared-actual-checkpoint-append", JOURNAL_ADMISSION_NATIVE_REQUIRED[2],
         "failed actual settlement write acknowledged or erased its retained pending owner",
         once(native_admission, "selection, appendErr := server.journal.Append(bounded, settled.PreviousSHA256, settled)",
              "selection, appendErr := JournalSelection{Record: settled, SHA256: journalCommitDigest(settledBytes)}, error(nil)")),
        ("journal_admission_windows.go", "prepared-late-operation-owner", JOURNAL_ADMISSION_NATIVE_REQUIRED[3],
         "late operation replacement acquired admission or lost its durable checkpoint",
         native_admission.replace("server.currentOwner()", "error(nil)")),
        ("journal_admission_windows.go", "prepared-exact-candidate", JOURNAL_ADMISSION_NATIVE_REQUIRED[4],
         "native journal admission accepted a substituted prepared candidate",
         once(native_admission, " || client.request.Candidate != target", "")),
        ("journal_admission_windows.go", "prepared-consumed-acknowledgment", JOURNAL_ADMISSION_NATIVE_REQUIRED[0],
         "native admission did not acknowledge one independently bracketed checkpoint",
         once(native_admission,
              'return errors.Join(client.admissionErr, bounded.Err(), errors.New("native journal admission acknowledgment has already been consumed"))',
              'return errors.Join(client.admissionErr, bounded.Err())')),
        ("journal_channel_windows.go", "prepared-second-phase-join", JOURNAL_ADMISSION_NATIVE_REQUIRED[6],
         "journal admission close returned before its entered second phase joined",
         function(channel, "func (server *JournalCommitServer) Close(", "<-server.admissionJoined", "_ = server.admissionJoined")),
        ("journal_admission_windows.go", "prepared-retained-durable-error", JOURNAL_ADMISSION_NATIVE_REQUIRED[1],
         "post-flush failure discarded its durable live-engine checkpoint",
         once(native_admission,
              "if err := read(bounded, target); err != nil {\n\t\treturn durable, err\n\t}",
              "if err := read(bounded, target); err != nil {\n\t\treturn JournalRecord{}, err\n\t}")),
        ("journal_admission_windows.go", "prepared-captured-host-before-ack", JOURNAL_CAPTURE_REQUIRED[0],
         "native admission omitted its captured host before acknowledgment",
         once(native_admission,
              "if err := prepared(bounded, cloneJournalRecord(durable)); err != nil {\n\t\treturn durable, err\n\t}",
              "// Broken: the host attempt was not recorded before the startup acknowledgment.")),
        ("journal_admission_windows.go", "prepared-captured-host-error", JOURNAL_CAPTURE_REQUIRED[1],
         "captured host rejection was ignored or discarded its flushed checkpoint",
         once(native_admission,
              "if err := prepared(bounded, cloneJournalRecord(durable)); err != nil {\n\t\treturn durable, err\n\t}",
              "_ = prepared(bounded, cloneJournalRecord(durable))")),
        ("journal_admission_windows.go", "prepared-captured-host-copy", JOURNAL_CAPTURE_REQUIRED[0],
         "captured host callback changed the retained checkpoint through an alias",
         once(native_admission, "prepared(bounded, cloneJournalRecord(durable))", "prepared(bounded, durable)")),
        ("journal_admission_windows.go", "prepared-captured-host-required", JOURNAL_CAPTURE_REQUIRED[2],
         "missing captured host consumed a native admission read or phase",
         once(native_admission, " || prepared == nil", "")),
        ("journal_admission_windows.go", "journal-drain-joined-owner", JOURNAL_CAPTURE_REQUIRED[3],
         "revoked but unjoined captured callback supplied a durable journal drain",
         function(native_admission, "func (server *JournalCommitServer) DrainAttempt(",
                  'default:\n\t\treturn JournalRecord{}, errors.New("native journal attempt cannot drain an entered callback")',
                  'default:\n\t\treturn cloneJournalRecord(*server.attempted), nil')),
        ("journal_channel_windows.go", "journal-intent-attempt-capture", JOURNAL_ATTEMPT_REQUIRED[0],
         "channel forgot the exact native append before its failed flush",
         once(channel, "server.attempted = &attempted", "_ = attempted")),
        ("journal_admission_windows.go", "journal-settlement-attempt-capture", JOURNAL_ATTEMPT_REQUIRED[0],
         "channel forgot the exact native append before its failed flush",
         once(native_admission, "server.attempted = &attempted", "_ = attempted")),
        ("journal_admission_windows.go", "journal-drain-exact-generation", JOURNAL_ATTEMPT_REQUIRED[1],
         "old channel adopted another durable journal generation",
         once(native_admission,
              "if durable, ok := exact(selection); ok {\n\t\treturn durable, errors.Join(readErr, ctx.Err())\n\t}",
              "if durable := cloneJournalRecord(selection.Record); readErr == nil && durable.Validate() == nil {\n\t\treturn durable, ctx.Err()\n\t}")),
        ("journal_admission_windows.go", "journal-drain-actual-retry", JOURNAL_ATTEMPT_REQUIRED[0],
         "readonly retry discarded or adopted a different journal attempt",
         once(native_admission,
              "selection, appendErr := server.journal.Append(ctx, attempted.PreviousSHA256, attempted)",
              "selection, appendErr := JournalSelection{Record: attempted, SHA256: journalCommitDigest(raw)}, error(nil)")),
        ("journal_channel_windows.go", "channel-captured-native-child", JOURNAL_CHANNEL_REQUIRED[2],
         "another actual child acquired the journal commit owner",
         once(channel, "peer, err := child.VerifyPeer(server.pipe, expectedImage)",
              "peer, err := server.pipe.Peer()")),
        ("journal_channel_windows.go", "channel-inherited-parent-peer", JOURNAL_CHANNEL_REQUIRED[1],
         "forged native pipe acknowledged an unflushed journal intent",
         channel.replace(peer_call, "client.pipe.Peer()")),
        ("journal_channel_windows.go", "channel-actual-durable-append", JOURNAL_CHANNEL_REQUIRED[3],
         "failed native journal persistence produced a commit acknowledgment",
         once(channel, "selection, appendErr := server.journal.Append(ctx, intent.PreviousSHA256, intent)",
              "selection, appendErr := JournalSelection{Record: intent, SHA256: journalCommitDigest(intentBytes)}, error(nil)")),
        ("journal_channel_windows.go", "channel-late-operation-owner", JOURNAL_CHANNEL_REQUIRED[4],
         "late application replacement acquired a persisted native commit acknowledgment",
         function(channel, "func (server *JournalCommitServer) currentOwner()",
                  "if err := server.current(); err != nil {\n\t\treturn err\n\t}",
                  "// Broken: the original application operation is no longer inspected.")),
        ("journal_channel_windows.go", "channel-consumed-acknowledgment", JOURNAL_CHANNEL_REQUIRED[0],
         "native journal channel did not acknowledge one exact flushed intent",
         once(channel,
              'return errors.Join(client.resultErr, bounded.Err(), errors.New("native journal commit acknowledgment has already been consumed"))',
              'return errors.Join(client.resultErr, bounded.Err())')),
        ("journal_channel_windows.go", "channel-server-callback-join", JOURNAL_CHANNEL_REQUIRED[6],
         "journal server acknowledged retirement before its entered callback joined",
         function(channel, "func (server *JournalCommitServer) Close(", "<-server.joined", "_ = server.joined")),
        ("journal_channel_windows.go", "channel-client-callback-join", JOURNAL_CHANNEL_REQUIRED[6],
         "journal client acknowledged retirement before its callback joined",
         function(channel, "func (client *JournalCommitClient) Close(", "<-client.gate", "// Broken: the entered client callback is not joined.")),
    )


def execute(go="go"):
    if platform.system() != "Windows" or not ctypes.windll.shell32.IsUserAnAdmin():
        raise ValueError("Protection owner proof requires an actual elevated Windows host")
    before = sources()
    compiler, captured, architecture = NATIVE.selected_compiler(go, ROOT, dict(os.environ))
    race = ["-race"] if architecture == "amd64" else []
    captured["CGO_ENABLED"] = "1" if race else "0"
    build = [compiler, "test", "-c", "-mod=readonly", "-tags=routervpn_windows_protection_native",
             "-gcflags=all=-d=checkptr=2", *race]
    with tempfile.TemporaryDirectory(prefix="routervpn-windows-protection-owner-") as directory:
        workspace = Path(directory)
        binary = workspace / "owner.test.exe"
        status, output = NATIVE.run([*build, "-o", binary, PACKAGE], cwd=ROOT, env=captured, timeout=240)
        if status:
            raise ValueError("Native protection owner baseline failed to compile:\n" + output[-32768:])
        digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        status, output = NATIVE.run([binary, "-test.run=^Test(WindowsProtection|JournalCommit|JournalAdmission)", "-test.count=1",
                                     "-test.timeout=90s", "-test.v"], cwd=ROOT, env=captured, timeout=105)
        print(output, end="" if output.endswith("\n") else "\n", flush=True)
        if (status or "--- SKIP:" in output or "DATA RACE" in output or
                any("--- PASS: " + test + " (" not in output for test in (*REQUIRED, *JOURNAL_REQUIRED, *JOURNAL_STORE_REQUIRED, *JOURNAL_COMMIT_REQUIRED, *JOURNAL_CHANNEL_REQUIRED, *JOURNAL_ADMISSION_REQUIRED, *JOURNAL_ADMISSION_NATIVE_REQUIRED, *JOURNAL_CAPTURE_REQUIRED, *JOURNAL_ATTEMPT_REQUIRED, *JOURNAL_RECOVERY_REQUIRED, *JOURNAL_RECOVERY_NATIVE_REQUIRED))):
            raise ValueError("Protection owner baseline did not execute every native ownership case")
        for test, names in REQUIRED_SUBCASES.items():
            if any("--- PASS: " + test + "/" + name + " (" not in output for name in names):
                raise ValueError("Protection owner baseline omitted a real negative ownership case: " + test)
        if hashlib.sha256(binary.read_bytes()).hexdigest() != digest:
            raise ValueError("Native protection owner binary changed during execution")
        changes = mutants()
        for filename, name, test, witness, replacement in changes:
            changed = workspace / (name + ".go")
            changed.write_text(replacement, encoding="utf-8")
            overlay = workspace / (name + ".json")
            overlay.write_text(json.dumps({"Replace": {str(TARGET / filename): str(changed)}}), encoding="utf-8")
            candidate = workspace / (name + ".test.exe")
            status, output = NATIVE.run([*build, "-overlay=" + str(overlay), "-o", candidate, PACKAGE],
                                        cwd=ROOT, env=captured, timeout=120)
            if status:
                raise ValueError("Protection owner mutant failed to compile: " + name + "\n" + output[-16384:])
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            status, output = NATIVE.run([candidate, "-test.run=^" + test + "$", "-test.count=1",
                                         "-test.timeout=30s", "-test.v"], cwd=ROOT, env=captured, timeout=45)
            if (status == 0 or "--- FAIL: " + test + " (" not in output or witness not in output or
                    "--- SKIP:" in output or "panic:" in output or "DATA RACE" in output):
                raise ValueError("Protection owner mutant missed its exact broken behavior: " + name +
                                 "\n" + output[-16384:])
            if hashlib.sha256(candidate.read_bytes()).hexdigest() != digest:
                raise ValueError("Protection owner mutant changed during execution: " + name)
            print("Rejected production Windows protection owner mutant:", name, flush=True)
        if sources() != before:
            raise ValueError("Protection owner shipping sources changed during the actual native gate")
    print("Native protection preparation passed five strict-owner-record groups, nine intent-record groups, two native-file header groups, "
          f"ten preparation ownership groups, thirteen durable journal storage/startup groups, three durable profile-binding groups, seven commit-record groups, seven native commit-channel groups, seven admission-record groups, seven native prepared-admission groups, four captured-host admission groups, three attempted-write drain groups, twelve recovery record/lifecycle groups, nine native retirement/adoption groups and {len(mutants())} production negative controls. "
          "This suite models only BFE observations; actual scoped BFE proof, application recovery wiring and ordinary-path activation remain separate requirements.", flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    execute(parser.parse_args().go)
