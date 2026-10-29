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
$Compile=@{TypeDefinition=$Code;ErrorAction='Stop'}
if($PSVersionTable.PSEdition-eq'Desktop'){
    # Windows PowerShell 5.1 exposes CodeDOM CompilerParameters, not the
    # PowerShell 7 CompilerOptions switch. Keep the same C#5 boundary and pass
    # its references and output path through that object; Add-Type rejects
    # its separate reference/output switches with CompilerParameters. This
    # is the actual Framework compiler used for the DLL.
    # https://learn.microsoft.com/powershell/module/microsoft.powershell.utility/add-type?view=powershell-5.1
    $Parameters=New-Object System.CodeDom.Compiler.CompilerParameters
    $Parameters.CompilerOptions='/langversion:5'
    $Parameters.GenerateExecutable=$false
    $Parameters.GenerateInMemory=-not [bool]$CompileAssembly
    foreach($Reference in @('System.dll','System.Core.dll','System.Net.Http.dll')){
        [void]$Parameters.ReferencedAssemblies.Add($Reference)
    }
    if($CompileAssembly){$Parameters.OutputAssembly=[IO.Path]::GetFullPath($CompileAssembly)}
    $Compile.CompilerParameters=$Parameters
}else{
    $Compile.CompilerOptions='/langversion:5'
    if($CompileAssembly){$Compile.OutputAssembly=[IO.Path]::GetFullPath($CompileAssembly);$Compile.OutputType='Library'}
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
