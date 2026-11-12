# Linux fixture carrier readiness

The generated-command TUN run at `81ea491551d34488283f686b67602745b794f1c8`
passed on AMD64 and failed on ARM64. The ARM64 job
[130967856177](https://github.com/Eabusham2/router-vpn/actions/runs/43153464309/job/130967856177)
recorded two additions during one TUN route operation: the intended IPv6
default route on interface 4 and an IPv6 kernel LOCAL /128 route on interface
3, the fixture's original carrier. The production ownership predicate refused
that foreign addition. The other five TUN scenarios passed in the same run.

The fixture had set its selected ULA with `nodad` but started the test immediately
after bringing up both veth endpoints. The separately generated link-local
address still undergoes DAD; its LOCAL route was not part of the ready baseline.
The runner now observes both original carrier interfaces, their selected
IPv4/IPv6 addresses, completed DAD and complete IPv6 kernel LOCAL routes before
starting the owned executable. It retains the original interface identity across
observations. A failed or replaced address, foreign route, missing route or
five-second setup deadline fails the fixture. Waiting never disables DAD or IPv6.

This changes only the isolated test fixture. The production TUN route admission,
foreign-change refusal, original test-process deadlines and all six native
scenario verdicts remain unchanged. The TUN's own address lifecycle remains
inside the actual native acceptance test.

Local checks executed the shipping readback predicate and bounded polling loop,
including independently delayed endpoints, missing LOCAL routes, duplicate or
failed addresses, interface replacement and a carrier that never becomes ready.
Three causal mutations (ignore tentative state, ignore missing routes, ignore
replacement identity) were rejected. The existing verdict inventory and Python
compilation checks passed. These checks are invoked by the mandatory guardian
namespace regression, whose original native cases also execute the new readiness
barrier. Actual privileged namespace and ARM64 TUN replay remain hosted evidence;
the local executor cannot open the required netlink socket.
# Native JSON owner correction

At `0277f9fc9e425989dbe9850abf94f5369899a2ef`, both jobs in [Linux generated Node command TUN acceptance](https://github.com/Eabusham2/router-vpn/actions/runs/43156396698) failed before the native test with `fixture carrier has a foreign local route`. The readiness command used a `dev` filter while requiring the returned JSON to contain `dev`. The upstream [iproute2 `print_route` implementation](https://github.com/iproute2/iproute2/blob/main/ip/iproute.c) emits `RTA_OIF` only when `filter.oifmask != -1`; a device filter therefore suppresses that field even for JSON output.

The fixture now reads the complete local IPv6 table in each of its two private namespaces. It selects the exact original carrier using the returned device field. Loopback routes are allowed outside that carrier, while missing device fields, another device claiming the carrier's address, and non-kernel carrier routes remain rejected. DAD completion, exact address/LOCAL-route equality, original interface identity, and the five-second setup deadline remain required. No production guardian, TUN route guard, or runtime deadline changed.

Portable checks execute the actual readiness predicate and loop with the upstream field-suppression behavior at the command boundary. All readiness and inventory checks pass, including four causal controls: missing DAD validation, missing LOCAL-route equality, replaced interface ownership, and restoration of the erroneous device-filtered command. Python compilation and `git diff --check` pass. Actual namespace/TUN acceptance on both native architectures remains pending the hosted run of this correction; this executor cannot open the required netlink socket.
