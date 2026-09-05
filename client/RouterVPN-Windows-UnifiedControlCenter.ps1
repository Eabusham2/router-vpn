Set-StrictMode -Version Latest

# Shared policy consumed by the Windows map-first WPF surface. This module does
# not launch a second window; it supplies the canonical order/defaults and
# secure-path validation to the existing product shell. Platform-specific truth
# must stay narrower than the cross-platform catalog. Runtime availability for
# capability-gated transports such as Tor/OpenVPN comes from the controller API,
# never from a hard-coded UI promise.
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
    BridgeTypes = @('SOCKS5','HTTP CONNECT','HTTPS CONNECT','Shadowsocks 2022','Tor bridge (runtime capability-gated)')
    UnavailableTypes = @{}
    SecureSuites = @(
        'WireGuard Noise_IK + ChaCha20-Poly1305',
        'AmneziaWG Noise_IK + ChaCha20-Poly1305',
        'OpenVPN TLS 1.3 + AEAD (only when the native OpenVPN capability check passes)',
        'Shadowsocks 2022 BLAKE3 + AEAD',
        'Hysteria2 QUIC + TLS 1.3',
        'Tor pluggable transport + proven ntor-v3 circuit (only when /api/tor-bridge/capabilities reports supported)'
    )
}

function Test-RouterVPNSecureNodeChain {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string[]]$NodeTypes)
    $final = $NodeTypes[-1].ToLowerInvariant()
    $unavailable = $script:RouterVPNUnifiedControlCenter.UnavailableTypes[$final]
    if ($unavailable) { throw $unavailable }
    # tor-bridge is a complete final transport only when the live controller
    # capability and connect path prove the pinned Tor/PT runtime. Windows ARM64
    # therefore remains unavailable through the backend capability reason even
    # though this shared static policy recognizes the transport family.
    $allowed = @('router-vpn','wireguard','amneziawg','openvpn','shadowsocks','shadowsocks-2022','hysteria2','tor-bridge')
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
