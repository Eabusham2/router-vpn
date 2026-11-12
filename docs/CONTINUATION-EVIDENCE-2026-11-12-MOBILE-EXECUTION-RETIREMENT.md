# Retire the observed original mobile execution owner

The generated mobile execution wrapper must not recover authority merely because native service or Box pointers are restored after an observed replacement. This unit cancels the exact observed state lifetime on a failed, non-canceled native observation. It does not cancel a different successor state. A caller deadline or cancellation without a valid ownership observation remains retryable.

Progress now reports that canceled original lifetime as retired, complete and not ready. Original remote cleanup remains available through the existing retained Close path, which joins the shared controller before native engine retirement. The repair does not stop a replacement service or release an unjoined original owner.

The added component regression exercises original service, instance, Box and wrapper-state replacement, restores the original pointers, and requires permanent refusal. It also checks that the unrelated successor lifetime is not canceled. The existing actual service-lock deadline test still requires successful observation after its ordinary caller timeout. A new causal control removes only the lifetime invalidation and must reach the exact pointer-restoration assertion.

The duplicate unpublished wrapper prototype was set aside after upstream `ca407625` supplied the production construction/close bridge. This unit changes that existing implementation; it adds no second wrapper, runtime or UI admission path.

## Validation boundary

The generated libbox and daemon component tests use the existing pinned native types and explicit constructor/platform boundaries. They do not establish privileged TUN, encrypted-path, Apple SDK, signing or device acceptance. Native tests use source cutoff `3bd81df` plus this focused repair; the later shared mobile MTU/readback extension is not claimed by this receipt.

- Preparation and runner checks: 18 passing tests.
- Actual pinned native component baseline: all 20 roots and 52 records passed with `-race`. Libbox completed in 4.150 s and daemon in 1.259 s, after dependency compilation.
- The new causal overlay compiled and reached `observed foreign owner revived after pointer restoration`. No compiler failure or race diagnostic counted as rejection. The 11 earlier controls remain required by the shipping runner and were not rerun for this narrow repair.
- Component source digest and original ownership manifest remained unchanged before and after baseline and causal execution: `e76d0514fc613017158067b375152366464d7a22f1cdbf882b2ae751cc2fd907`.
- The disposable mobile core was prepared from pinned core `1ac1a339cb1223e9c70eae14c44411c75033c02d` using the shipping mobile preparation order. Official Xray generation in a staging checkout matched all 1,020 files of the immutable shared pinned Xray tree before the shipping module replacement selected that shared path; the staging path was never compiled.

No production deadline or test alarm was increased.
