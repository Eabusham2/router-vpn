param(
    [Parameter(Mandatory=$true)][string]$Assembly,
    [Parameter(Mandatory=$true)][string]$Fixture,
    [Parameter(Mandatory=$true)][string]$Output
)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
if($PSVersionTable.PSEdition-ne'Desktop'-or$PSVersionTable.PSVersion.Major-ne5-or$PSVersionTable.PSVersion.Minor-ne1){
    throw 'The actual GUI process fixture requires Windows PowerShell 5.1 and its Framework compiler.'
}
$Assembly=[IO.Path]::GetFullPath($Assembly)
$Fixture=[IO.Path]::GetFullPath($Fixture)
$Output=[IO.Path]::GetFullPath($Output)
if(-not[IO.File]::Exists($Assembly)-or-not[IO.File]::Exists($Fixture)-or[IO.File]::Exists($Output)){
    throw 'The native GUI compiler requires captured inputs and a new owned output.'
}
$Parameters=New-Object System.CodeDom.Compiler.CompilerParameters
$Parameters.CompilerOptions='/langversion:5 /platform:anycpu'
$Parameters.GenerateExecutable=$true
$Parameters.GenerateInMemory=$false
$Parameters.OutputAssembly=$Output
foreach($Reference in @('System.dll','System.Core.dll','System.Net.Http.dll',$Assembly)){
    [void]$Parameters.ReferencedAssemblies.Add($Reference)
}
$Provider=New-Object Microsoft.CSharp.CSharpCodeProvider
try{
    $Result=$Provider.CompileAssemblyFromFile($Parameters,@($Fixture))
    if($Result.Errors.HasErrors-or-not[IO.File]::Exists($Output)){
        throw ('Actual Framework GUI process compilation failed: '+(($Result.Errors|ForEach-Object {$_.ToString()})-join[Environment]::NewLine))
    }
}finally{$Provider.Dispose()}
Write-Host 'PASS actual Framework GUI process compilation'
