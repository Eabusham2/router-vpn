# All-platform builds

The repository uses one workflow:

```text
.github/workflows/build-all.yml
```

Open **GitHub → Actions → Build all platforms → Run workflow**.

## Artifacts

### RouterVPN-desktop-unix

Contains checked archives and SHA-256 files for:

- Windows amd64
- Windows arm64
- Windows PortableApps-style amd64
- Windows PortableApps-style arm64
- macOS Intel
- macOS Apple Silicon
- Linux amd64
- Linux arm64
- Linux armv7
- FreeBSD amd64/arm64
- OpenBSD amd64/arm64
- NetBSD amd64/arm64
- DragonFly BSD amd64
- illumos amd64

The Go controller builds natively for these targets. Full VPN operation also requires the matching local tunnel engines and privileges. The Windows packages use WSL2 or matching native engines for the multi-engine shell launchers.

### RouterVPN-Android-APK

Contains:

```text
RouterVPN-android-debug.apk
RouterVPN-android-debug.apk.sha256
```

The APK is a private router-bundle importer/controller. The native Android `VpnService` engine adapter is not linked yet, so it is not labeled as a full-device VPN.

### RouterVPN-iOS-IPA

Always contains when the unsigned build succeeds:

```text
RouterVPN-unsigned-resignable.ipa
RouterVPN-unsigned-resignable.ipa.sha256
```

When all Apple secrets are set and valid, it also contains:

```text
RouterVPN-signed.ipa
RouterVPN-signed.ipa.sha256
RouterVPN.xcarchive
```

The unsigned IPA must be re-signed before installation. The signed or re-signed app still needs the native Packet Tunnel engine adapter before custom VPN connections can work.

### RouterVPN-all-platforms

Contains one tarball with all three platform artifact sets and a combined checksum file.

## Apple signing secrets

Create these repository Actions secrets:

```text
APPLE_TEAM_ID
IOS_CERTIFICATE_BASE64
IOS_CERTIFICATE_PASSWORD
IOS_APP_PROFILE_BASE64
IOS_TUNNEL_PROFILE_BASE64
```

Use these bundle identifiers:

```text
App:       com.eabusham.routervpn
Extension: com.eabusham.routervpn.PacketTunnel
```

Both App IDs and both provisioning profiles must permit the Packet Tunnel Network Extension entitlement.

### Convert the certificate to Base64

macOS:

```bash
base64 -i certificate.p12 | tr -d '\n'
```

Paste the result into `IOS_CERTIFICATE_BASE64` and put the `.p12` password in `IOS_CERTIFICATE_PASSWORD`.

### Convert provisioning profiles to Base64

```bash
base64 -i RouterVPN.mobileprovision | tr -d '\n'
base64 -i RouterVPNPacketTunnel.mobileprovision | tr -d '\n'
```

Put the first result in `IOS_APP_PROFILE_BASE64` and the second in `IOS_TUNNEL_PROFILE_BASE64`.

## Verification performed by the workflow

The workflow fails instead of uploading an artifact when any of these checks fail:

- Go tests
- JSON parsing
- shell syntax validation
- required desktop packages present
- package SHA-256 verification
- ZIP integrity
- tar.gz integrity
- APK ZIP integrity
- unsigned IPA ZIP integrity
- Packet Tunnel extension present inside the IPA
- signed IPA ZIP integrity when signing is enabled
- aggregate tarball integrity

## Workflow limitation

The workflow proves that source and packaging complete on GitHub’s runners. It cannot prove that every VPN engine works on the exact ASUS AI Board kernel, ISP, travel network, or mobile device. The router finalizer separately validates generated Xray and sing-box configs and removes rejected advanced profiles from the private bundle.
