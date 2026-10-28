param([string]$SourceRoot=(Split-Path -Parent $PSScriptRoot))
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$source=[IO.File]::ReadAllText((Join-Path $SourceRoot 'client/test-windows-wfp.ps1'))
$fixture=[regex]::Match($source,"(?s)\`$fixtureSource=@'\r?\n(.*?)\r?\n'@")
if(-not $fixture.Success) { throw 'The real kernel fixture source was not found.' }
Add-Type -TypeDefinition $fixture.Groups[1].Value
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseInput($source,[ref]$tokens,[ref]$errors)
if($errors.Count) { throw 'The real WFP fixture has parse errors.' }
$function=$ast.Find({param($n) $n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq 'New-FixtureEndpointPair'},$true)
if($null -eq $function) { throw 'The real endpoint allocator was not found.' }
Invoke-Expression $function.Extent.Text
$checks=0
function Assert([bool]$Value,[string]$Message) { $script:checks++;if(-not $Value) { throw $Message } }
function Check-Drained([string]$Address,[int[]]$Ports) {
    foreach($port in $Ports) {
        $listener=New-Object Net.Sockets.TcpListener([Net.IPAddress]::Parse($Address),$port)
        try { $listener.Start();Assert $true 'The discarded TCP reservation must be reusable.' }
        finally { $listener.Stop() }
    }
}
foreach($address in @('127.0.0.1','::1')) {
    $state=[pscustomobject]@{Calls=0;Ports=(New-Object 'Collections.Generic.List[int]')}
    $open={param($IP,$Port)
        $state.Calls++;$state.Ports.Add($Port)
        if($state.Calls -le 8) { throw (New-Object Net.Sockets.SocketException([int][Net.Sockets.SocketError]::AccessDenied)) }
        New-Object RouterVPNWfpDatagramEcho($IP,$Port)
    }.GetNewClosure()
    $pair=$null
    try {
        $pair=New-FixtureEndpointPair $address $open
        Assert ($state.Calls -eq 9) 'Eight excluded UDP ports prevented a later valid reservation.'
        Assert ($pair.TCP.Port -eq $state.Ports[8]) 'TCP and UDP lost the same captured port.'
        $tcp=New-Object Net.Sockets.TcpClient([Net.IPAddress]::Parse($address).AddressFamily)
        try {
            $tcp.Connect($address,$pair.TCP.Port);$stream=$tcp.GetStream();$stream.ReadTimeout=2000
            $stream.WriteByte(73);Assert ($stream.ReadByte() -eq 73) 'The selected TCP endpoint does not echo actual data.'
        } finally { $tcp.Dispose() }
        $udp=New-Object Net.Sockets.UdpClient([Net.IPAddress]::Parse($address).AddressFamily)
        try {
            $udp.Client.ReceiveTimeout=2000;$udp.Connect($address,$pair.TCP.Port)
            [byte[]]$payload=@(11,19,23);$null=$udp.Send($payload,$payload.Length)
            $peer=New-Object Net.IPEndPoint([Net.IPAddress]::Parse($address),0)
            $reply=$udp.Receive([ref]$peer)
            Assert ([Convert]::ToBase64String($reply) -ceq [Convert]::ToBase64String($payload)) 'The selected UDP endpoint does not echo actual data.'
        } finally { $udp.Dispose() }
    } finally { if($null -ne $pair) { $pair.UDP.Dispose();$pair.TCP.Dispose() } }
    Check-Drained $address $state.Ports.ToArray()

    $state=[pscustomobject]@{Calls=0;Ports=(New-Object 'Collections.Generic.List[int]')}
    $deny={param($IP,$Port)
        $state.Calls++;$state.Ports.Add($Port)
        throw (New-Object Net.Sockets.SocketException([int][Net.Sockets.SocketError]::AccessDenied))
    }.GetNewClosure()
    $failed=$false
    try { $null=New-FixtureEndpointPair $address $deny } catch { $failed=$true }
    Assert ($failed -and $state.Calls -eq 32) 'Reservation failure was hidden or retried beyond its bound.'
    Check-Drained $address $state.Ports.ToArray()

    $state=[pscustomobject]@{Calls=0;Ports=(New-Object 'Collections.Generic.List[int]')}
    $unexpected={param($IP,$Port) $state.Calls++;$state.Ports.Add($Port);throw 'CONTROL unexpected listener failure'}.GetNewClosure()
    $failure=''
    try { $null=New-FixtureEndpointPair $address $unexpected } catch { $failure=$_.Exception.ToString() }
    Assert ($state.Calls -eq 1 -and $failure.Contains('CONTROL unexpected listener failure')) 'A nonallocation failure was retried or suppressed.'
    Check-Drained $address $state.Ports.ToArray()

    $failed=$false
    try { $null=New-FixtureEndpointPair $address -ChoosePort {0} } catch { $failed=$true }
    Assert $failed 'An invalid port reached the endpoint reservation.'
}
Write-Output "WFP real endpoint reservation: $checks checks passed (IPv4 and IPv6, TCP and UDP, bounded collisions and cleanup)."
