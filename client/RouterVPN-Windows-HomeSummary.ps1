# Dot-sourced by the stable Windows product wrapper before the WPF product is parsed.
# Home uses only /api/home-summary for combined state and its session-keyed
# /api/home-summary/prove-exit action for the actual public VPN exit.

function global:Format-RouterVPNHomeSummary {
    param($Summary)
    if ($null -eq $Summary) { return 'Home state unavailable.' }
    $exit = if ([string]$Summary.actual_exit_status -eq 'proved' -and $Summary.actual_exit_ip) {
        [string]$Summary.actual_exit_ip
    } elseif ([bool]$Summary.connected) {
        'Unproven — click Prove actual exit'
    } else { 'Not connected' }
    $dns = if ($Summary.dns_host) { "$($Summary.dns_mode) • $($Summary.dns_host)" } else { [string]$Summary.dns_mode }
    if ($Summary.dns_latency_ms -and [double]$Summary.dns_latency_ms -gt 0) { $dns += " • $([Math]::Round([double]$Summary.dns_latency_ms,2)) ms" }
    $nodeLatency = if ([int]$Summary.node_latency_samples -gt 0) { "$([Math]::Round([double]$Summary.node_latency_ms,2)) ms / $($Summary.node_latency_samples) samples" } else { 'Not measured' }
    $mtu = if ([int]$Summary.effective_mtu -gt 0) { "$($Summary.effective_mtu) • $($Summary.effective_mtu_source)" } else { 'Default / not measured' }
    $fallback = if ($Summary.fallback) { [string]$Summary.fallback } else { 'None' }
    $warnings = @($Summary.warnings | Where-Object { $_ })
    $warningText = if ($warnings.Count) { $warnings -join ' | ' } else { 'None' }
    @(
        "Node: $($Summary.node_name) • $($Summary.location)"
        "Public endpoint: $($Summary.public_endpoint)"
        "Actual public VPN exit: $exit"
        "Connection: $($Summary.connection_phase) • path proof $($Summary.path_proof)"
        "Logical/runtime/base: $($Summary.logical_mode) • $($Summary.actual_runtime) • $($Summary.actual_base)"
        "Fallback: $fallback"
        "DNS: $dns • proof $($Summary.dns_status)"
        "Node latency: $nodeLatency"
        "LAN access: $(if($Summary.lan_access){'On'}else{'Off'}) • Kill switch: $($Summary.kill_switch)"
        "Effective MTU: $mtu • IPv6: $($Summary.ipv6_mode) • Auto-connect: $($Summary.auto_connect)"
        "Warnings: $warningText"
    ) -join "`r`n"
}

function global:Get-RouterVPNHomeSummary {
    param([string]$BaseUrl)
    Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/home-summary') -Method Get -TimeoutSec 5
}

function global:Prove-RouterVPNHomeExit {
    param([string]$BaseUrl)
    Invoke-RestMethod -Uri ($BaseUrl.TrimEnd('/') + '/api/home-summary/prove-exit') -Method Post -ContentType 'application/json' -Body '{}' -TimeoutSec 12
}

# Shipping contract markers:
# node location public endpoint actual public VPN exit connection phase logical mode
# actual runtime actual base fallback DNS latency node latency LAN access kill switch
# effective MTU warnings Connect Emergency Disconnect /api/home-summary
