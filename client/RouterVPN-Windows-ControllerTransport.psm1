# One module instance owns the channel for this PowerShell runspace. Feature
# clients own only their requests/handlers. A failed or retired native handoff
# stays native: an old callback must never fall back to an ordinary HTTP socket.
Set-StrictMode -Version 2
$script:ControllerMode='legacy'
$script:ControllerChannel=$null
$script:ControllerPipe=''
$script:ControllerParentHandle=[long]0
$script:ControllerDataRoot=''

function Initialize-RouterVPNControllerTransport {
    param([string]$ControllerPipe,[long]$ControllerParentHandle)
    $Supplied=$PSBoundParameters.ContainsKey('ControllerPipe')-or$PSBoundParameters.ContainsKey('ControllerParentHandle')
    if($script:ControllerMode-cne'legacy'){
        if($script:ControllerMode-cne'owned'-or$null-eq$script:ControllerChannel){throw 'The captured native controller channel is closed or unavailable.'}
        if($Supplied-and($ControllerPipe-cne$script:ControllerPipe-or$ControllerParentHandle-ne$script:ControllerParentHandle)){throw 'The native controller handoff cannot replace this UI owner.'}
        return 'https://127.0.0.1:8788'
    }
    if(-not$Supplied){return 'http://127.0.0.1:8788'}
    $script:ControllerMode='failed'
    if(-not$PSBoundParameters.ContainsKey('ControllerPipe')-or-not$PSBoundParameters.ContainsKey('ControllerParentHandle')-or
       [string]::IsNullOrEmpty($ControllerPipe)-or$ControllerParentHandle-le0){throw 'The complete captured native controller handoff is required.'}
    # Resolve the known system cmdlet directly. Unqualified cold discovery can
    # analyze every installed module before the captured pipe is authenticated.
    Microsoft.PowerShell.Utility\Add-Type -AssemblyName System.Net.Http
    if(-not('RouterVPN.ControllerUI.ControllerChannel'-as[type])){
        $Source=[IO.Path]::Combine($PSScriptRoot,'RouterVPN-Windows-ControllerTransport.cs')
        $Code=[IO.File]::ReadAllText($Source,[Text.Encoding]::UTF8)
        $Compile=@{TypeDefinition=$Code;ErrorAction='Stop'}
        if($PSVersionTable.PSEdition-eq'Desktop'){
            $Parameters=New-Object System.CodeDom.Compiler.CompilerParameters
            $Parameters.CompilerOptions='/langversion:5'
            $Parameters.GenerateExecutable=$false;$Parameters.GenerateInMemory=$true
            foreach($Reference in @('System.dll','System.Core.dll','System.Net.Http.dll')){[void]$Parameters.ReferencedAssemblies.Add($Reference)}
            $Compile.CompilerParameters=$Parameters
        }else{$Compile.CompilerOptions='/langversion:5'}
        Add-Type @Compile
    }
    # ConnectAsync verifies the inherited read-only parent handle and the actual
    # pipe server before sending its public hello. Neither this module nor any
    # feature receives a controller bearer or a TLS-validation callback.
    $script:ControllerChannel=[RouterVPN.ControllerUI.ControllerChannel]::ConnectAsync($ControllerPipe,$ControllerParentHandle,10000,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
    $script:ControllerPipe=$ControllerPipe;$script:ControllerParentHandle=$ControllerParentHandle
    # The retained native parent supplies this public path in its reconstructed
    # environment. Capture it only after authenticating that parent and pipe;
    # later feature callbacks must not follow mutable process environment.
    $script:ControllerDataRoot=[string]$env:HOMEVPN_ROOT
    $script:ControllerMode='owned'
    return 'https://127.0.0.1:8788'
}

function Get-RouterVPNControllerDataRoot {
    if($script:ControllerMode-ceq'legacy'){return $null}
    if($script:ControllerMode-cne'owned'-or$null-eq$script:ControllerChannel){throw 'The captured native controller channel is closed or unavailable.'}
    if([string]::IsNullOrWhiteSpace($script:ControllerDataRoot)){throw 'The native UI has no captured data directory.'}
    return $script:ControllerDataRoot
}

function Assert-RouterVPNControllerBaseUrl {
    param([Parameter(Mandatory=$true)][string]$BaseUrl)
    $Value=$BaseUrl.TrimEnd('/')
    if($script:ControllerMode-cne'legacy'){
        if($script:ControllerMode-cne'owned'-or$null-eq$script:ControllerChannel){throw 'The captured native controller channel is closed or unavailable.'}
        if($Value-cne'https://127.0.0.1:8788'){throw 'The native UI requires its exact captured HTTPS controller identity.'}
        return
    }
    # Standalone feature fixtures can use their own loopback listener. App and
    # Tray retain the fixed legacy 8788 startup check until launcher adoption.
    $Address=[Uri]$Value
    if(-not$Address.IsAbsoluteUri-or$Address.Scheme-cne'http'-or$Address.Host-cne'127.0.0.1'-or
       $Address.UserInfo-or$Address.Query-or$Address.Fragment-or$Address.AbsolutePath-ne'/'){
        throw 'The legacy UI requires its captured local controller.'
    }
}

function New-RouterVPNControllerClient {
    param([ValidateRange(1,960000)][int]$TimeoutMilliseconds=900000,[ValidateRange(1,8388608)][int]$ResponseLimit=8388608)
    Add-Type -AssemblyName System.Net.Http
    if($script:ControllerMode-cne'legacy'){
        if($script:ControllerMode-cne'owned'-or$null-eq$script:ControllerChannel){throw 'The captured native controller channel is closed or unavailable.'}
        return $script:ControllerChannel.CreateClient($TimeoutMilliseconds,$ResponseLimit)
    }
    $Handler=[Net.Http.HttpClientHandler]::new();$Handler.UseProxy=$false;$Handler.AllowAutoRedirect=$false
    $Client=[Net.Http.HttpClient]::new($Handler)
    $Client.Timeout=[Threading.Timeout]::InfiniteTimeSpan;$Client.MaxResponseContentBufferSize=$ResponseLimit
    return $Client
}

function Set-RouterVPNControllerRequestTimeout {
    param([Parameter(Mandatory=$true)]$Request,[ValidateRange(1,960000)][int]$TimeoutMilliseconds)
    # Framework exposes a Dictionary; current .NET exposes an explicit
    # IDictionary facade over HttpRequestOptions that PowerShell cannot index.
    # Both representations are read by the exact C# per-request deadline gate.
    $Properties=$Request.Properties
    if($Properties-is[Collections.IDictionary]){$Properties['RouterVPNControllerTimeoutMilliseconds']=[int]$TimeoutMilliseconds}
    else{
        $Key=[Net.Http.HttpRequestOptionsKey[object]]::new('RouterVPNControllerTimeoutMilliseconds')
        $Request.Options.Set($Key,[object][int]$TimeoutMilliseconds)
    }
}

function Invoke-RouterVPNControllerRequest {
    param([Parameter(Mandatory=$true)][string]$Uri,[ValidateSet('GET','POST','PUT','DELETE')][string]$Method='GET',
          [string]$ContentType='application/json',$Body=$null,[ValidateRange(1,960)][int]$TimeoutSec=45,
          [ValidateRange(1,8388608)][int]$ResponseLimit=8388608)
    $Address=[Uri]$Uri
    if(-not$Address.IsAbsoluteUri){throw 'The controller request requires an absolute captured URI.'}
    Assert-RouterVPNControllerBaseUrl ($Address.GetLeftPart([UriPartial]::Authority))
    if($script:ControllerMode-ceq'legacy'){
        $Arguments=@{Uri=$Uri;Method=$Method;TimeoutSec=$TimeoutSec}
        if($Method-cne'GET'){$Arguments.ContentType=$ContentType;$Arguments.Body=$Body}
        return Invoke-RestMethod @Arguments
    }
    $Method=$Method.ToUpperInvariant()
    if($ContentType-cne'application/json'){throw 'The native controller request content type is not supported.'}
    $Client=$null;$Request=$null;$Response=$null
    try{
        $Client=New-RouterVPNControllerClient -TimeoutMilliseconds ($TimeoutSec*1000) -ResponseLimit $ResponseLimit
        $Verb=[Net.Http.HttpMethod]::new($Method.ToUpperInvariant())
        $Request=[Net.Http.HttpRequestMessage]::new($Verb,$Uri)
        if($null-ne$Body){
            if($Body-is[byte[]]){$Bytes=$Body}
            elseif($Body-is[string]){$Bytes=[Text.Encoding]::UTF8.GetBytes($Body)}
            else{throw 'The native controller body must be captured JSON text or exact import bytes.'}
            $Request.Content=[Net.Http.ByteArrayContent]::new($Bytes)
            $Request.Content.Headers.ContentType=[Net.Http.Headers.MediaTypeHeaderValue]::new('application/json')
        }
        $Response=$Client.SendAsync($Request,[Threading.CancellationToken]::None).GetAwaiter().GetResult()
        $Text=$Response.Content.ReadAsStringAsync().GetAwaiter().GetResult()
        if(-not$Response.IsSuccessStatusCode){
            $Failure=[Net.Http.HttpRequestException]::new(('Controller request failed (HTTP '+[int]$Response.StatusCode+').'))
            $Failure.Data['StatusCode']=[int]$Response.StatusCode
            throw $Failure
        }
        if([string]::IsNullOrWhiteSpace($Text)){return $null}
        return ConvertFrom-Json -InputObject $Text -ErrorAction Stop
    }finally{
        if($null-ne$Response){$Response.Dispose()}
        if($null-ne$Request){$Request.Dispose()}
        if($null-ne$Client){$Client.Dispose()}
    }
}

function Close-RouterVPNControllerTransport {
    if($script:ControllerMode-ceq'legacy'){return}
    $script:ControllerMode='closed'
    if($null-ne$script:ControllerChannel){
        # Keep the retained channel until its request/read/write tasks join.
        # A repeated close can still join after an exceptional caller unwind.
        [void]$script:ControllerChannel.CloseAsync().GetAwaiter().GetResult()
    }
}

Export-ModuleMember -Function Initialize-RouterVPNControllerTransport,Get-RouterVPNControllerDataRoot,Assert-RouterVPNControllerBaseUrl,New-RouterVPNControllerClient,Set-RouterVPNControllerRequestTimeout,Invoke-RouterVPNControllerRequest,Close-RouterVPNControllerTransport
