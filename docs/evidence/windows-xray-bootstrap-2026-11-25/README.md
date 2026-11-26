# Windows Xray bootstrap, November 25, 2026

Native Windows amd64 and arm64 passed the original nine Xray traffic cases within the unchanged 90-second limit on commit `526760a3e56f2e3370d1649622e1ca7b64e30b08`. Both jobs also passed the startup-records check, the three reference-detector controls and the wrong-credential root. The elapsed times below come from the Go test output in each job log. [GitHub Actions run 45723168446, attempt 1](https://github.com/Eabusham2/router-vpn/actions/runs/45723168446)

| Windows architecture | Native job log | Xray traffic | Wrong credential | Original artifact | Extracted receipt |
| --- | --- | ---: | ---: | --- | --- |
| amd64 | [139586277375](https://github.com/Eabusham2/router-vpn/actions/runs/45723168446/job/139586277375) | 26.36 s | 35.77 s | [15073703660](https://github.com/Eabusham2/router-vpn/actions/runs/45723168446/artifacts/15073703660) | [JSON](amd64/windows-startup-amd64-bootstrap-baselines.json) |
| arm64 | [139586277419](https://github.com/Eabusham2/router-vpn/actions/runs/45723168446/job/139586277419) | 25.30 s | 34.25 s | [15073273553](https://github.com/Eabusham2/router-vpn/actions/runs/45723168446/artifacts/15073273553) | [JSON](arm64/windows-startup-arm64-bootstrap-baselines.json) |

Each traffic run exercised `reality-vision`, `reality-pq-vision` and `reality-xhttp` with each of the three Start Layer settings `off`, `aes-256-gcm` and `aes-256-gcm+xor-whitening`. These jobs exercised encrypted reference-peer traffic with the bootstrap fixture's modeled permit and tunnel. Kernel WFP enforcement has its own native gate. Whole-release qualification requires the complete gate set on the release commit. [Exact-SHA release evidence](../../EXACT-SHA-RELEASE-EVIDENCE.md)

Each downloaded ZIP matched GitHub's reported byte count and SHA-256. Its single 4,006-byte JSON receipt is preserved with the original Windows line ending.

| Architecture | ZIP bytes | ZIP SHA-256 | Extracted JSON SHA-256 |
| --- | ---: | --- | --- |
| amd64 | 1,926 | `f7e9814372766ee8a6faa75b77881bb6106ea13b6ba2387a3c86caea1cc62111` | `6dbf7b77457d9520dd13ee246f888a81ff4f88106c38e10121381c2114a383b7` |
| arm64 | 1,929 | `f1cdb9bd69b63554b043f953d013aa4f3a216fbb0c6da6d757fadbe983da095e` | `7e5f3a56d544b3f1193a97d1b6892bc76975fb19d43439d696a8922bf3e6862a` |
