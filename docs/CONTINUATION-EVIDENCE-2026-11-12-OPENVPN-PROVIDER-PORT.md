# OpenVPN native provider port discovery, 2026-11-12

## Observed hosted failure

The Windows native external OpenVPN job [130886896340](https://github.com/Eabusham2/router-vpn/actions/runs/43128208479/job/130886896340), source `0bd9d0238f615158f8cb9b30c304abb8dc7c04cc`, passed the complete TCP WFP group and UDP on-connect, always, successor/restore, trust rejection and control-key rejection. UDP reject/dns and the following cases failed before provider startup with:

```
routervpn-openvpn-provider phase=provider-port-reservation class=syscall errno=10013 network=udp4 operation=bind
routervpn-openvpn-peer phase=provider-serve class=test-failure
owned OpenVPN provider startup exchange failed owned OpenVPN provider lost bounded reply
```

The current fixture still selected an ephemeral TCP port and attempted to bind UDP to that same number for every provider. A TCP allocation does not establish that the same UDP port is usable. Microsoft documents that [dynamic client port ranges can differ between TCP and UDP](https://learn.microsoft.com/en-us/windows/win32/api/winsock/nf-winsock-bind), and [exclusive socket ownership can produce WSAEACCES](https://learn.microsoft.com/en-us/windows/win32/winsock/windows-sockets-error-codes-2). The log establishes the cross-transport probe failure; it does not identify which external Windows reservation owned that number.

## Repair and controls

The test provider now discovers its ephemeral port using the original captured provider transport only. UDP binds UDP port zero; TCP binds TCP port zero. The original unavailable TCP fallback remains independently reserved and owned on Windows. Distinct port-number checks and the existing native provider bind-collision handling remain. Selected-protocol access errors propagate immediately; they are neither retried nor converted into an available port. No production socket policy, timeout, WFP rule, rejection case, or negative control changes.

The new native test has eight mandatory verdicts covering both actual TCP/UDP allocations, unselected-transport refusal sentinels, immediate selected access-error propagation and unknown-transport rejection. The Windows witness invocation now requires all eight. The runner executes the exact current Go allocator and native test bodies in a race-enabled subprocess. A forced TCP selection for UDP fails the unselected-transport sentinel; hiding access errors fails the error-propagation assertion. The current source passes.

All eight focused `OrdinaryOpenVPNScope` runner tests passed in 6.362 seconds, including actual race-enabled socket tests and both causal mutants. `git diff --check` passed. This local Linux evidence does not claim actual Windows WFP acceptance; the original hosted native gate remains required.
