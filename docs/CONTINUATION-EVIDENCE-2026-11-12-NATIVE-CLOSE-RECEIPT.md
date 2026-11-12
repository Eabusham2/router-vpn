# Original native Box teardown receipt

Apple ordered Server/Compare adoption needs to distinguish the start of native teardown from its completed result. The pinned Box closes `done` before closing its managers and TUN. The pinned daemon also removes its instance from the service slot before closing it, and previously discarded the returned close error. Neither observation proves that the original reader has joined.

## Narrow source change

The generated native owner adds `Box.RouterVPNCaptureCloseReceipt()`. Its opaque receipt is bound to the exact original Box. `JoinContext(ctx, originalBox)` waits for the original complete `Close` call to return and reports its retained error. An unstarted close, another Box, an expired caller, a duplicate Close, or the early `done` signal cannot supply a successful receipt. A panic never publishes completion. The original manager-close body is preserved, and duplicate Close keeps the existing `os.ErrClosed` behavior.

The daemon's exact pinned `CloseService` body now returns the original instance-close error and publishes its existing fatal status on that error. A successful close retains the existing idle transition. The strict preparer accepts only the complete original or complete owned daemon method, rejecting partial changes. Its existing native source inventory includes the new receipt and test templates.

## Verification

The official native preparation completed on fresh clean local clones at sing-box `1ac1a339cb1223e9c70eae14c44411c75033c02d` and Xray `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`, using this source unit based on `0edf2d05b0c063bf079f8f2f189b3b81becfdee4`. No tidied dependency guard was bypassed.

The native owner suite executes the actual pinned Box close and actual managers. Its explicit reference monitor has a complete Close implementation, and a held internal service exposes the real early-done/late-join interval. Both successful and failed original close results are checked. The complete owner inventory is now 14 roots and 28 verdicts; existing discovery, actual graph substitution, selected DNS epoch, application gate, failed acquisition, restoration and original managed-outbound cases remain required. Two new causal controls remove the actual join or discard the original close error; neither compiler failure nor a race counts as their expected rejection.

Nine preparation tests include an executable regression using the entire exact pinned daemon method and substituted service/native-instance boundary types. The discarded-error mutant must reach its specific runtime assertion. Six native verdict/inventory tests preserve omission, wrong failure and incomplete-child refusals. Windows ARM64 omits only the unsupported Go race flag in that portable daemon fixture, using the effective Go target; its real positive and causal test remain required.

Executed results: all 14 roots / 28 native verdicts passed with `-race`; both new native causal controls reached their exact intended assertions without a race or build failure. The strict native source digest remained `577549b0be4270fc91bf7b45a1b010f18e655e459d76f95e948ac338de17cf5e` before and after execution. All nine preparation and six verdict/inventory tests passed, including the compiled daemon error control. The five preexisting native causal controls remain in the mandatory runner; they were not needlessly repeated for this separate close-receipt unit.

This is a native lifecycle prerequisite. It does not enable Apple ordered Server/Compare UI, implement its remaining mobile wrapper/MTU composition, prove a physical NetworkExtension session, or supply a signed Apple build. A receipt of a failed close remains a failure and cannot authorize restoration.
