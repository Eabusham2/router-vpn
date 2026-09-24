param([Parameter(Mandatory=$true)][string]$ProductSource)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Ast=[ScriptBlock]::Create($ProductSource).Ast
foreach($Name in @('UnifiedMultihopValue','RefreshUnifiedMultihopComparison')) {
 $Functions=@($Ast.FindAll({param($N) $N-is[System.Management.Automation.Language.FunctionDefinitionAst] -and $N.Name-eq$Name},$true))
 if($Functions.Count-ne1){throw "Missing composed comparison function: $Name"}
 . ([ScriptBlock]::Create($Functions[0].Extent.Text))
}
$script:ComparisonTestLabel=[pscustomobject]@{Text=''}
function Control([string]$Name){if($Name-eq'UnifiedComparisonText'){return $script:ComparisonTestLabel};throw 'Unexpected test control'}
$valid=@{candidate=@{execution='server';transport='shadowsocks'};eligible=$true;last_node_ms=20;external_ms=40;score_ms=30}
RefreshUnifiedMultihopComparison @{execution='server';comparison=@{id='one';stage='selected';measurements=@($valid)}}
if($script:ComparisonTestLabel.Text-notmatch '20[.,]0 \+ 40[.,]0.*30[.,]0 ms'){throw 'Valid comparison not displayed'}
foreach($Failure in @('last-node timeout','external timeout','stale session')) {
 $bad=@{candidate=@{execution='local';transport='shadowsocks'};eligible=$false;failure=$Failure}
 RefreshUnifiedMultihopComparison @{comparison=@{id='two';stage='measured';measurements=@($bad)}}
 if($script:ComparisonTestLabel.Text-notlike "*rejected*$Failure*" -or $script:ComparisonTestLabel.Text-like '*= 0*'){throw 'Failed probe rendered as a score'}
}
foreach($BadScore in @([double]::NaN,[double]::PositiveInfinity,-1,0)) {
 $bad=$valid.Clone();$bad.score_ms=$BadScore
 RefreshUnifiedMultihopComparison @{comparison=@{id='three';stage='measured';measurements=@($bad)}}
 if($script:ComparisonTestLabel.Text-notlike '*rejected*'){throw 'Invalid score displayed as winner'}
}
foreach($Marker in @('UnifiedExecution','/api/multihop/status','StopUnifiedComparisonProgress','StartUnifiedComparisonProgress','UseProxy=$false','AllowAutoRedirect=$false','MaxResponseContentBufferSize=32768')) {
 if(-not$ProductSource.Contains($Marker)){throw "Missing shipping execution/progress guard: $Marker"}
}
if(-not$ProductSource.Contains('$Body.execution=')){throw 'Connect does not submit selected execution'}
Write-Host 'Windows Local/Server/Compare controls and actual response renderer: PASS'
