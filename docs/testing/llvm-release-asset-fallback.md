# Pinned LLVM release-asset download fallback

## Observed release blocker

The exact-main ARM64 auxiliary build at `63c6a935e9971ce28bd07688985178e7c17e4ef7`
failed in the pinned Windows Tor compiler prerequisite. Job
[129003139949](https://github.com/Eabusham2/router-vpn/actions/runs/42569431298/job/129003139949)
received HTTP 504 from the LLVM-MinGW release download before compiler execution.
Earlier exact-source runs reached the same download failure.

The installer now switches after a transient gateway response to the official
public GitHub binary asset API for the same pinned archive. The four asset IDs
were checked against the upstream `20261006` release metadata. This is a route
change within the existing three attempts and absolute 600-second download
budget. It adds no credentials, compiler version change, alternate archive,
checksum exception, or retry after a permanent HTTP error, transport failure,
partial download, cancellation, or integrity failure.

## Verification on 2026-11-09

- All 17 `VerifiedWindowsInstaller` tests passed, including the actual installer
  path with modeled primary gateway responses and a complete verified API body.
  The new cases cover API route/header identity, three-attempt exhaustion,
  permanent and transport errors, the original deadline, and refusal of long,
  short, changed, insecure, metadata, and partial API responses before extraction
  or compiler execution. Existing extraction, reuse, ownership, and compiler
  version checks remain enabled.
- An independent unauthenticated request downloaded the entire Linux AMD64 asset
  `618062377` from the official API. The redirect ended at
  `release-assets.githubusercontent.com`, with HTTP 200, 84,003,044 bytes, and
  SHA-256 `5f9c6ed95b2d4bdb2869a488c5fd5857fbdabcf288a0aa3eb1da43f6a08d8ab4`.
  Both values match the existing pin. The download took 10.23 seconds; this
  inspection did not execute the archive.

These results verify the route and installer invariants. A later hosted build
must establish successful compiler execution and release publication at its own
commit; the repaired downloader alone does not establish either result.

References: [upstream release](https://github.com/mstorsjo/llvm-mingw/releases/tag/20261006)
and [official release-asset API documentation](https://docs.github.com/en/rest/releases/assets#get-a-release-asset).
