# Windows selected-candidate controller, November 25, 2026

The native Windows amd64 runner compiled the full desktop controller test package with Go 1.26.3 and race detection. All 18 connected-phase roots passed, with 91 required parent and child verdicts. The private-response HTTP root ran all nine children together in 115.16 seconds under its 120-second limit. The controller harness models the child process and kernel. [Receipt](selected-candidate-controller.json) · [Private-response transcript](selected-candidate-controller.json.TestDesktopSelectedPrivateResponseHTTPPreservesCompleteSourceAndNamedProfile.jsonl)

| Identifier | Value |
| --- | --- |
| Tested commit | [`7d86b5ccd67500dfae4c323e8943330e38662c49`](https://github.com/Eabusham2/router-vpn/commit/7d86b5ccd67500dfae4c323e8943330e38662c49) |
| GitHub Actions run, attempt 1 | [45714736413](https://github.com/Eabusham2/router-vpn/actions/runs/45714736413) |
| Native Windows job | [139557783846](https://github.com/Eabusham2/router-vpn/actions/runs/45714736413/job/139557783846) |
| GitHub artifact | [15069504773](https://github.com/Eabusham2/router-vpn/actions/runs/45714736413/artifacts/15069504773) |
| Original ZIP SHA-256 | `f2aeab4af0d7e368c4bdd780843e3b9283b70bffdc7542968fd2a84a49aa9035` |
| Verifier source inputs SHA-256 | `d4e693e3d8fa3990eef61a9f47d14e9fdfbf1c7ea9735de238359f504a592dc3` |
| Compiled test image SHA-256 | `7e8e542a5a32505b7a370cbbacc88804d487bb6d39075372de39e9dd6e5589b3` |

The downloaded ZIP matched GitHub’s digest. This directory preserves its JSON receipt and 18 per-root JSONL transcripts byte for byte, including Windows line endings.

The verifier computed the same source-input digest on `9cda43e30abdea17252ae7fd36317a255d0f79c1`. Release publication still requires all release gates to pass on the exact commit being published. [Release evidence requirements](../../EXACT-SHA-RELEASE-EVIDENCE.md)

## Original artifact files

The 19 extracted files total 84,973 bytes. Each digest below covers the original Windows bytes. The receipt separately records the SHA-256 of each Go test output stream before Windows line-ending conversion. All 18 stream digests matched their transcripts.

```text
42bb649a02402e94eb2d34fe8b0134bd83825cddb60de85d4b9ae6744813c25b  selected-candidate-controller.json
190f2674776df34091bbb5a07da849d064a4603b1dba7a58e527e9251de0c12f  selected-candidate-controller.json.TestDesktopSelectedCandidateHTTPRetainsSparsePrefixAndSelectedWinner.jsonl
b31b09e0eb9d62e73b8d8e7c67366ff571a9779d30575b1ff1c67773e2f62cdf  selected-candidate-controller.json.TestDesktopSelectedCandidateCancellationJoinsWithoutStart.jsonl
bc9e07c45a37fbe861e07c6251a993221cdbe00021e9efcd590ca964c1347eb5  selected-candidate-controller.json.TestDesktopSelectedCandidateMetadataRejectsForeignOriginals.jsonl
84bf8d0c81126247b6eadf5cecf9ee3dffd06f3da850a710bc05d96d39874a03  selected-candidate-controller.json.TestDesktopSelectedCandidatePendingRetirementPreservesForeignMetadata.jsonl
ae92ee33e33d297c9829ce18c05686f35d8c9dc8a07b57bb4e0b16d6d2a73370  selected-candidate-controller.json.TestDesktopSelectedCandidateResultRetirement.jsonl
de0f4adf5d925d8654c0efb4d9372c9ef1629ef5d2cb7a875daf8eb18874fe05  selected-candidate-controller.json.TestDesktopSelectedIntermediateResponseCancelCannotBorrowAnotherEligibleStop.jsonl
1c10b641171a5470427d5aa1755d472dbc492b7e92a5f362e9b4e87125b72472  selected-candidate-controller.json.TestDesktopSelectedIntermediateResponseHTTPPreservesOriginalSuffixAndNamedLoad.jsonl
ab6993245f19ff784eb40bc82a00e347efcaeac04b7ca110b7cdda44d5a4619f  selected-candidate-controller.json.TestDesktopSelectedIntermediateResponseRejectsChangedOriginalSuffixBeforeSave.jsonl
68c81097df31101fcb41e8acaff207f892c93d42840e522772e8c359be94f6f3  selected-candidate-controller.json.TestDesktopSelectedMeasurementWorkspaceRetirement.jsonl
59cc22ff84a992e2d51d82d15af860718d78a9ca798e9f729d3686baefe13649  selected-candidate-controller.json.TestDesktopSelectedPrivateResponseCancelBeforeStartRetainsIssuedSource.jsonl
d3142e5e68b1352c2e38ce0d4d9ecb50421054dae8a4521244bec01ca4e23ca3  selected-candidate-controller.json.TestDesktopSelectedPrivateResponseConnectedServerWinnerHasNoPrivateOffer.jsonl
6d2ddf759c82c1df3c0ccdd4fa0010e1cf7cc02d7972ccf4964ce98516941a2e  selected-candidate-controller.json.TestDesktopSelectedPrivateResponseHTTPPreservesCompleteSourceAndNamedProfile.jsonl
ddbc04a46946ed8ebe87cccb44c3752be9070386542e3108524d8f28826fe15a  selected-candidate-controller.json.TestDesktopSelectedServerResponseConnected.jsonl
a06b361d97d7a16f72e765ff195e6c88aaa9ad18107275c16207ec233b726d6e  selected-candidate-controller.json.TestDesktopSelectedServerUnregisteredCannotBeSaved.jsonl
e46a62c2ef283ebb1601e7be79b45c4776e465e5ab056ca02758f6dd8c1e9f33  selected-candidate-controller.json.TestDesktopSelectedThroughputCancellationJoinsOriginal.jsonl
b08566f5243d170b4c3defed010ef3304b4b8758fb0086787f5479d6f8ace03c  selected-candidate-controller.json.TestDesktopSelectedThroughputPublicController.jsonl
f11db7b1ba1f013a10fc5ddbb313498fa063e29b4b5761264aba45a5107eb535  selected-candidate-controller.json.TestDesktopSelectedThroughputRejectsForeignRows.jsonl
ac7cf8a3c6fe77ca421f2eac7a332a30390f6f7ffc1bdb336c1a6d9544400964  selected-candidate-controller.json.TestDesktopSelectedThroughputTerminalOwnership.jsonl
```
