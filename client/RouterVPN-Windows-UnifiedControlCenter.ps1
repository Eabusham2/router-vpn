
Set-StrictMode -Version Latest

# Shared policy consumed by the Windows map-first WPF surface. This module does
# not launch a second window; it supplies the canonical order/defaults and
# secure-path validation to the existing product shell.
$script:RouterVPNUnifiedControlCenter = [ordered]@{
    Experience = 'Unified Map Control Center'
    DefaultMode = 'smart-auto'
    DefaultNodeCount = 1
    DefaultIPv6 = $true
    DefaultMtuPolicy = 'auto'
    RequireEncryptedAuto = $false
    RequireObfuscationAuto = $false
    AuthenticatedTransport = $true
    BottomSheetOrder = @('connection','multihop','settings','mode','dns')
    ProfileActions = @('create','load','update','delete','import-router-bundle')
    BridgeTypes = @('SOCKS5','HTTP CONNECT','HTTPS CONNECT','Shadowsocks 2022','Tor bridge')
    SecureSuites = @(
        'WireGuard Noise_IK + ChaCha20-Poly1305',
        'AmneziaWG Noise_IK + ChaCha20-Poly1305',
        'OpenVPN TLS 1.3 + AEAD',
        'Shadowsocks 2022 BLAKE3 + AEAD',
        'Tor ntor-v3 outer bridge'
    )
}

function Test-RouterVPNSecureNodeChain {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$NodeTypes)
    $final = $NodeTypes[-1].ToLowerInvariant()
    $allowed = @('router-vpn','wireguard','amneziawg','openvpn','shadowsocks-2022')
    if ($allowed -notcontains $final) {
        throw "$final is a bridge only. Add an authenticated encrypted tunnel after it."
    }
    return $true
}

function Get-RouterVPNUnifiedHandshakeLabel {
    param([bool]$Established)
    if ($Established) { return 'Authenticated handshake ✓' }
    return 'Authenticated handshake pending'
}
