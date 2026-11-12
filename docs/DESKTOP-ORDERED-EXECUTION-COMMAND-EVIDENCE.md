# Desktop ordered execution command prerequisites

This unit retains the typed physical execution adapters introduced by `b0a77da3ddcfe08a7d55c05d159e4869f4ce9505`; it does not add another physical factory. Its distinct changes bind a staged desktop execution preparation to the original session, target, physical source, complete configuration and execution-source digest, retain the existing physical MTU transaction around the exact native execution engine, and permit Darwin readiness records only for the closed execution physical policy.

Server and Compare can share the initial physical configuration. The separate execution-source digest is therefore required: a changed execution setting must not borrow the same physical/configuration hashes. The command capture rejects missing, Local, generic, changed-execution and ambiguous staged sources, as well as changed session, target, configuration, physical source and graph bytes.

The MTU companion requires the original Box, exact sealed physical policy and `binding.OwnsEngine(engine)` before delegating to the existing physical grant transaction and actual native execution manager. Its lifetime callback observes the retained physical generation so that an authorized old-reader detachment does not itself invalidate the transaction. This is an adapter prerequisite; this unit does not claim an installed execution MTU replacement has run.

## Exact native preparation and verification

The native source was prepared from checkout `d6de40859713754bf39724cecdacac66a0e46fc5` plus this unit using the complete official `prepare_native_sources` entry point, Go 1.26.3, pinned sing-box `1ac1a339cb1223e9c70eae14c44411c75033c02d`, and pinned Xray `50231eaff98ccc31b5cbd247a721c16e97fe5ec1`. All 1,020 common Xray files were unchanged. Strict preparation and post-test verification compared all 2,439 mapped source records.

Both actual generated packages were built with `go test -c -p=1 -mod=readonly -race`, the shipping desktop tags (`with_wireguard,with_gvisor,with_quic,with_utls,with_openvpn,with_naive_outbound,with_purego`) and `-ldflags=-checklinkname=0`. The first Box linker was killed under shared resource pressure; the unchanged serial retry passed with `GOMAXPROCS=1`, `GOGC=10`, and `GOMEMLIMIT=512MiB`. No test deadline was increased.

The executed checks were:

- `^TestRouterVPNDesktopNodeChainExecutionPhysical`: all 13 exact mandatory verdicts, using the upstream real Box/encrypted-prefix constructors and an explicitly unstarted TUN double.
- `^TestRouterVPNDesktopNodeChainExecutionCommand`: all 19 exact mandatory verdicts, including six platform/settings replays and eleven source/ownership substitutions.
- The existing `^TestRouterVPNDesktopNodeChainPhysical` and `^TestRouterVPNDesktopNodeChainCommand` roots from the same actual race binaries.
- `go test -race -p=1 ./internal/mobilemultihop -run '^TestDesktopNodeReadyDarwin' -count=1 -timeout=90s -v`, including closed execution readiness and changed receipt/type refusals.
- `ExecutionAdmissionGate` and the two existing native MTU inventory regressions: three Python tests passed. The gate rejects each missing verdict, duplicate output, skips and race output; it does not weaken the exact native inventory.

Native binary executions retained their 90-second limits. The actual preparation, build, test and before/after source receipts are in the task evidence directory `desktop-execution-evidence/adopted-run`.

## Remaining shipping boundary

The command capture is not yet a public Server/Compare admission path. Actual CLI dispatch, authenticated platform execution capture, the one-child execution/measurement/MTU adjunct, parent launch adoption and Last restoration remain follow-up work. Stop must cancel proof work while retaining the original Box until remote lease and execution cleanup positively join. Cross-child restoration must retain the original complete source and Last decision, join the old child first, and prove the restored path before Connected. These prerequisite tests do not establish privileged installed TUN, PF/WFP/nft, or physical-device acceptance.
