param(
    [string]$Root=(Split-Path $PSScriptRoot -Parent),
    [string]$Source='',
    [string]$Case='',
    [string]$CompileAssembly='',
    [string]$LoadAssembly=''
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if(-not$Source){$Source=Join-Path $Root 'client/RouterVPN-Windows-ControllerTransport.cs'}
if($CompileAssembly-and$LoadAssembly){throw 'Choose only one assembly check.'}
if($LoadAssembly){
    $Assembly=[Reflection.Assembly]::LoadFrom([IO.Path]::GetFullPath($LoadAssembly))
    $Channel=$Assembly.GetType('RouterVPN.ControllerUI.ControllerChannel',$true)
    if($Channel.GetConstructors().Count-ne0-or$null-eq$Channel.GetMethod('ConnectAsync')-or$null-eq$Channel.GetMethod('CreateClient')-or$null-eq$Channel.GetMethod('CloseAsync')){throw 'Compiled controller transport changed its authenticated public surface.'}
    if($null-ne$Assembly.GetType('RouterVPN.ControllerUI.Tests.TransportTests',$false)){throw 'Shipping controller DLL contains the fixture.'}
    Write-Host 'PASS controller GUI transport compiled DLL load'
    exit 0
}
$Fixture=Join-Path $Root 'deploy/fixtures/windows-controller-transport/transport_tests.cs'
$Code=[IO.File]::ReadAllText($Source,[Text.Encoding]::UTF8)
if(-not$CompileAssembly){$Code+=[Environment]::NewLine+[IO.File]::ReadAllText($Fixture,[Text.Encoding]::UTF8)}
Add-Type -AssemblyName System.Net.Http
$Compile=@{TypeDefinition=$Code;CompilerOptions='/langversion:5';ErrorAction='Stop'}
if($CompileAssembly){$Compile.OutputAssembly=[IO.Path]::GetFullPath($CompileAssembly);$Compile.OutputType='Library'}
if($PSVersionTable.PSEdition-eq'Desktop'){
    $Compile.ReferencedAssemblies=@('System.dll','System.Core.dll','System.Net.Http.dll')
}
Add-Type @Compile
if($CompileAssembly){Write-Host 'PASS controller GUI transport production DLL compilation';exit 0}
try{
    [RouterVPN.ControllerUI.Tests.TransportTests]::Run($Case)
}catch{
    # Preserve the executable control's exact text under both shell formatters;
    # their interactive error wrapping must not masquerade as another failure.
    [Console]::Error.WriteLine($_.Exception.ToString())
    exit 1
}
