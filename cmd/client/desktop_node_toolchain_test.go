package main

import "testing"

// These required regressions use test-only Go 1.25 synctest.
// An older CI toolchain or an omitted test file must fail the test build.
var (
	_ func(*testing.T) = TestDesktopNodeALLKeepsCompleteTLSFirstOrder
	_ func(*testing.T) = TestDesktopNodePublicALLMissingGraphsKeepOriginalOwner
	_ func(*testing.T) = TestDesktopNodePublicALLCancellationKeepsCapturedOperation
	_ func(*testing.T) = TestDesktopNodePublicConnectUsesCapturedOwnedHost
	_ func(*testing.T) = TestDesktopNodeOwnedPQPlatformBoundary
	_ func(*testing.T) = TestDesktopNodePublicPQSourceAndProofFailuresPreserveOwnership
	_ func(*testing.T) = TestDesktopNodePublicCapabilitiesRequireCapturedReadiness
	_ func(*testing.T) = TestDesktopNodePublicAutoRetainsCatalogAndExactPredecessor
	_ func(*testing.T) = TestDesktopNodePublicSmartRestoresCapturedSourceAndLiveMTU
	_ func(*testing.T) = TestDesktopNodePublicSpeedLabCancellationRestoresExactWinner
	_ func(*testing.T) = TestDesktopNodePublicConnectRejectsReplacedRequest
	_ func(*testing.T) = TestDesktopNodePublicConnectCancellationAndProofReplacement
	_ func(*testing.T) = TestDesktopNodePublicDisconnectAndOffRetainUnjoinedOwners
	_ func(*testing.T) = TestDesktopNodeOrdinaryPublicationFixture
	_ func(*testing.T) = TestDesktopNodePublicOrdinaryCancellationRetainsCapturedCleanup
	_ func(*testing.T) = TestDesktopOwnedNodeHealthUsesSealedSourceAfterSavedBundleChanges
	_ func(*testing.T) = TestDesktopOwnedNodeHealthRejectsWrongOrRetiredProof
	_ func(*testing.T) = TestDesktopOwnedNodeHealthRejectsUncapturedProfileBeforeNetwork
	_ func(*testing.T) = TestDesktopOwnedNodeMonitorAllowsActiveMTUAndProvedExpiry
	_ func(*testing.T) = TestDesktopOwnedNodeMonitorRejectsUnrelatedOrReplacedTUNReadback
	_ func(*testing.T) = TestDesktopOwnedNodeMonitorRetiresFailureAfterJoiningWatch
	_ func(*testing.T) = TestDesktopOwnedNodeMonitorCannotStopReplacement
	_ func(*testing.T) = TestDesktopOwnedNodeMonitorDefersToForegroundOperation
	_ func(*testing.T) = TestDesktopOwnedNodeMonitorCancellationJoinsWithoutStopping
	_ func(*testing.T) = TestDesktopOwnedNodeMonitorForegroundRetirementAndOldRetry
	_ func(*testing.T) = TestDesktopOwnedNodeMonitorMTUDrainJoinsDirectChildWithoutExecProcess
	_ func(*testing.T) = TestDesktopOwnedNodePreparationPreservesSourceAndExistingRuntime
	_ func(*testing.T) = TestDesktopOwnedNodePreparationCapturesResolvedEndpointOnce
	_ func(*testing.T) = TestDesktopOwnedNodePreparationKeepsCapturedAESAndWhitening
	_ func(*testing.T) = TestDesktopOwnedNodePreparationDoesNotBorrowAnotherNodesStartLayer
	_ func(*testing.T) = TestDesktopOwnedNodePreparationRejectsRetiredCapture
	_ func(*testing.T) = TestDesktopOwnedNodePreparationRejectsLateLookupReplacement
	_ func(*testing.T) = TestDesktopOwnedNodePreparationCancelsItsVerificationChild
	_ func(*testing.T) = TestDesktopOwnedNodePreparationRejectsSourceBeforeLookup
	_ func(*testing.T) = TestDesktopOwnedNodePreparationRejectsUnsupportedAdmission
	_ func(*testing.T) = TestDesktopOwnedNodeSealedSourceAndRestoredMTU
	_ func(*testing.T) = TestDesktopOwnedNodeConstructorRejectsMixedPrivateProfile
	_ func(*testing.T) = TestDesktopOwnedNodeHandoffRejectsSubstitutedAuthority
	_ func(*testing.T) = TestDesktopOwnedNodeAdmissionBindsCurrentProcessAndNonce
	_ func(*testing.T) = TestDesktopOwnedNodeAdmissionRejectsLateCancellationAndReplacement
	_ func(*testing.T) = TestDesktopOwnedNodeStartFailureRetainsPartialOwnerAndPredecessor
	_ func(*testing.T) = TestDesktopOwnedNodeWorkspaceReplacementPreservesNewOwner
	_ func(*testing.T) = TestDesktopOwnedNodeCurrentKeepsMeasuredStateSeparateFromSelection
	_ func(*testing.T) = TestDesktopOwnedNodeReadinessRequiresCurrentStartAndTUN
	_ func(*testing.T) = TestDesktopOwnedNodeRetirementRequiresJoinedChildAndIndependentTarget
	_ func(*testing.T) = TestDesktopOwnedNodeFailedTrialRestoresOriginalWithLatestJoinedPredecessor
	_ func(*testing.T) = TestDesktopOwnedNodeReleasedSlotDoesNotClaimLaterLegacyCleanup
	_ func(*testing.T) = TestDesktopOwnedNodeUnprovedOrAlwaysSlotCannotFallThrough
	_ func(*testing.T) = TestDesktopOwnedNodeOldReleasePreservesReplacementSlot
	_ func(*testing.T) = TestDesktopNodeProcessArguments
	_ func(*testing.T) = TestDesktopNodeProcessFailedJoinRetainsPinsAndExactWait
	_ func(*testing.T) = TestDesktopNodeProcessConcurrentCloseJoinsAndHonorsCancellation
	_ func(*testing.T) = TestDesktopNodeProcessCancelledWaitDoesNotManufactureExit
	_ func(*testing.T) = TestDesktopNodeProcessControllerReplacementAndPartialOwner
	_ func(*testing.T) = TestDesktopNodeProcessPinReleaseRetriesAfterJoinedChild
	_ func(*testing.T) = TestDesktopNodeRecoveryRetainsAlwaysBeforeSuccessor
	_ func(*testing.T) = TestDesktopNodeRecoveryPendingOffOriginalAndSavedResult
	_ func(*testing.T) = TestDesktopNodeRecoveryOffRetriesActualSavedResult
	_ func(*testing.T) = TestDesktopNodeRecoveryRejectsUnprovedReceiptAndChangedProfile
	_ func(*testing.T) = TestDesktopNodeRecoveryAdmissionRetriesAndHTTPPendingOff
	_ func(*testing.T) = TestDesktopNodeRecoveryEmptyStartupClosesStore
	_ func(*testing.T) = TestDesktopNodeRecoveryTerminalShutdownPreservesUnknownPolicy
	_ func(*testing.T) = TestDesktopNodeRecoveryCancellationKeepsReplacement
	_ func(*testing.T) = TestDesktopNodeRecoveryRequiresJoinedInitializationBeforeBegin
	_ func(*testing.T) = TestDesktopNodeRecoveryPartialOpenAndNativeCloseRemainOwned
	_ func(*testing.T) = TestDesktopNodeRecoveryUncertainResultCannotBeReplaced
	_ func(*testing.T) = TestDesktopNodeRecoveryHTTPDoesNotReuseUnknownOwnerToken
	_ func(*testing.T) = TestDesktopNodeRecoveryAdmissionCancellation
	_ func(*testing.T) = TestDesktopNodeRecoveryOldCompletionKeepsNewOperation
	_ func(*testing.T) = TestDesktopNodePublicLogicalBasePreferenceRetainsCapturedSource
	_ func(*testing.T) = TestDesktopNodePublicLogicalBasePreferencePreparationFailureRollsBack
	_ func(*testing.T) = TestDesktopNodePublicLogicalBasePreferenceFailedSuccessorKeepsMatchingSource
	_ func(*testing.T) = TestLogicalBaseRollbackRejectsChangedOrUnjoinedOwners
	_ func(*testing.T) = TestLogicalBaseRollbackPreservesDurablePredecessorAndCancellation
	_ func(*testing.T) = TestLogicalBaseRollbackWriteFailureRetainsSavedStagedValue
)
