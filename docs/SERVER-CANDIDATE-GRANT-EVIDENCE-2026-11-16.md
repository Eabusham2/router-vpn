# Server candidate grant contracts — November 16, 2026

This unit adds an authenticated, single-target TCP-connect grant contract and
original-lease manager/HTTP boundary for a selected remote WG/AWG packet member.
It retains the complete source, registry, worker, operation, inventory and
absolute request deadline. The existing proof/final routes and their credentials
are unchanged. A server-generated operation identity separates old credentials
from replacement operations; admission allows at most 50 connects, one in flight.

Expiry revokes authority immediately and retains the exact owner until callbacks
and native cleanup join. Canonical requests remain within the existing 1,024-entry
bound so exact late cancellation can be acknowledged. Capacity eviction removes
only expired requests without a live operation. A seen Create is rejected before
eviction; an unknown or evicted expired DELETE cannot manufacture an acknowledgment.
Close acknowledgments bind the original operation and canonical request digest.

The first actual relay run compiled with race/default vet but failed three expiry
assertions because eager pruning discarded the original cancellation record. Its
log SHA-256 is `4302f07ff465788db6ac249c3b9096da7a0983ecdac395a31e1b030aa68ffa7c`.
The corrected source retains all original assertions and adds changed-deadline,
altered-digest, unknown-expired and evicted-request refusals. No clocks changed.

## Executed evidence

The corrected source was frozen on `238eb57184503d7d35d2f36f0df9ad65788c23d3`.
All 1,545 recorded package/module/driver inputs remained unchanged during each
phase; the root go.sum is explicitly absent. The later `94dee36d` desktop/Apple/Linux
changes intersect none of those compiled inputs. This is scoped source evidence,
not an exact-head release run. Go 1.26.3, race/default vet, 2 CPUs, GOGC=50,
900 MiB soft memory target and package parallelism 1 were used. Each phase retained
its 180-second Go timeout and 240-second process limit. Nine Python verdict and
inventory checks also passed; they are not native executions.

| Phase | Records / result | Wall seconds | Executable log SHA-256 |
| --- | --- | --- | --- |
| relay | 22 passes | 9.534 | `ae004647fd72667e8622ba3b4b70c16b012c437ece61f1db15122618e3a3d4c2` |
| policy | 2 passes | 42.276 | `431f22652295371ba162f34619b61b75a7960c36305312895af962281ea3527e` |
| agent | 6 passes | 26.513 | `14267221dfa8507ba21bc1bd61af3482ae1e014dab19838f272b1d61aa34f493` |
| quota-control | 1 exact expected assertion refusal | 6.166 | `362cbc918f2567eaa92d23a7c604e6d6aa22afe574b76f23b9d8f58882c4b726` |
| join-control | 1 exact expected assertion refusal | 5.558 | `ae682687dc2489ec924aabd52204f8442d238a90286b8cdeea93b3d07dd83d45` |

The two controls compile the actual source with only the quota or held-status
join guard omitted and must fail at their exact designated assertions. Race,
panic, fatal and timeout diagnostics cannot satisfy those controls.

## Remaining boundary

These tests exercise shared admission/manager semantics and the authenticated
agent HTTP boundary. The native candidate worker is a separate required unit;
without it this API fails unavailable. No encrypted Server traffic, installed
host, SDK/device or full Server/Compare candidate chooser acceptance is claimed.
The client execution-owned grant acquisition and joined cancellation integration
also remain separate. Existing profile Server/Compare execution and restoration
are not candidate measurement. Mandatory workflow and native artifact gates retain
all five phases; host measurements must use the actual fifty TCP samples.
