# Android DNS Retest transaction witness

Android multihop run [43163222577](https://github.com/Eabusham2/router-vpn/actions/runs/43163222577),
job 130999202348, failed before the DNS Retest assertions because the disposable
Java projection did not declare its `dnsChecked` test hook. The fixture anchored
that declaration to the old non-volatile `selectionGeneration` field; the shipping
store now uses a volatile generation.

The hook is now attached to the exact owning class declaration, with a required
single-match check. The original store field, visibility, volatile qualifier,
writer lock, and publication code are preserved. The hook still pauses the real
compare/publication boundary so the test can attempt a concurrent selection.

The corrected source passed all 80 DNS Retest checks using the actual Java
callbacks, loopback HTTP request, and store transactions. All five existing
compiled controls were rejected at their intended assertions: atomic writer
ownership, generation freshness, latest operation, dialog dismissal, and socket
cancellation. Android widgets and native admission remain explicit fixture
boundaries; this is not a device-routing or selected-DNS tunnel receipt.
