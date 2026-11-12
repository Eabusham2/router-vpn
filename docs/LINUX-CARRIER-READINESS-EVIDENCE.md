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
