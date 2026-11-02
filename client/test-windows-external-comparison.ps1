param([string]$Root=(Split-Path $PSScriptRoot -Parent),[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
$Source=Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $Root 'client/RouterVPN-Windows-Telemetry.ps1')
$Match=[regex]::Match($Source,'(?ms)^    \$telemetry=@''\r?\n(.*?)\r?\n''@')
if(-not$Match.Success){throw 'Actual generated telemetry block missing.'}
$Ast=[ScriptBlock]::Create($Match.Groups[1].Value).Ast
$Functions=@($Ast.FindAll({param($N)$N-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$N.Name-match'^(ExternalComparison|SetExternalComparison|StartExternalComparison|ReceiveExternalComparison|TickExternalComparison)'},$true))
if($Functions.Count-ne10){throw 'Actual external comparison helper composition changed.'}
foreach($F in $Functions){. ([ScriptBlock]::Create($F.Extent.Text))}
$Show=@($Ast.FindAll({param($N)$N-is[System.Management.Automation.Language.FunctionDefinitionAst]-and$N.Name-eq'ShowExternalComparison'},$true));if($Show.Count-ne1){throw 'Native external comparison window missing.'}
$BeginNode=@($Show[0].FindAll({param($N)$N-is[System.Management.Automation.Language.AssignmentStatementAst]-and$N.Left.Extent.Text-eq'$Begin'},$true));if($BeginNode.Count-ne1){throw 'Actual Compare action changed.'}
$Begin=@($BeginNode[0].Right.FindAll({param($N)$N-is[System.Management.Automation.Language.ScriptBlockExpressionAst]},$false))[0].ScriptBlock.GetScriptBlock()
$CloseNode=@($Show[0].FindAll({param($N)$N-is[System.Management.Automation.Language.InvokeMemberExpressionAst]-and$N.Member.Extent.Text-eq'Add_Closing'},$true));if($CloseNode.Count-ne1){throw 'Native close callback missing.'};$Closing=@($CloseNode[0].Arguments[0].FindAll({param($N)$N-is[System.Management.Automation.Language.ScriptBlockExpressionAst]},$false))[0].ScriptBlock.GetScriptBlock()
$Markup=@($Show[0].FindAll({param($N)($N-is[System.Management.Automation.Language.ExpandableStringExpressionAst]-or$N-is[System.Management.Automation.Language.StringConstantExpressionAst])-and$N.Value.TrimStart().StartsWith('<Window')},$true));if($Markup.Count-ne1){throw 'Native XAML missing.'};[xml]$Xml=$Markup[0].Value
foreach($Name in @('Compare','Fastest','Cancel','Close','Status','Result')){if($Xml.SelectNodes('//*[@Name="'+$Name+'"]').Count-ne1){throw ('Actual native control missing: '+$Name)}}
# Only WPF controls and short HTTP response delivery are doubles. The generated
# action, cancellation, receipt parser, request sender and task drain execute.
Add-Type -AssemblyName System.Net.Http
$Code=@'
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
public sealed class ComparisonHTTPFixture : IDisposable {
 public readonly List<string> Paths=new List<string>(), Bodies=new List<string>(), Methods=new List<string>();
 TaskCompletionSource<HttpResponseMessage> pending;
 public Task<HttpResponseMessage> SendAsync(HttpRequestMessage request,CancellationToken token) {
  if(pending!=null)throw new Exception("Overlapping HTTP worker");
  Paths.Add(request.RequestUri.AbsolutePath+request.RequestUri.Query);Methods.Add(request.Method.Method);
  Bodies.Add(request.Content==null?"":request.Content.ReadAsStringAsync().GetAwaiter().GetResult());
  var owned=new TaskCompletionSource<HttpResponseMessage>();pending=owned;
  token.Register(()=>owned.TrySetCanceled());return owned.Task;
 }
 public void Reply(string json) {var owned=pending;pending=null;if(owned==null)throw new Exception("No captured HTTP request");var response=new HttpResponseMessage(HttpStatusCode.OK){Content=new StringContent(json)};if(!owned.TrySetResult(response))response.Dispose();}
 public void Dispose(){if(pending!=null)pending.TrySetCanceled();pending=null;}
}
'@
$Compile=@{TypeDefinition=$Code;ErrorAction='Stop'}
if($PSVersionTable.PSEdition-eq'Desktop'){
 $Parameters=New-Object System.CodeDom.Compiler.CompilerParameters
 $Parameters.CompilerOptions='/langversion:5';$Parameters.GenerateExecutable=$false;$Parameters.GenerateInMemory=$true
 foreach($Reference in @('System.dll','System.Core.dll','System.Net.Http.dll')){[void]$Parameters.ReferencedAssemblies.Add($Reference)}
 $Compile.CompilerParameters=$Parameters
}else{$Compile.CompilerOptions='/langversion:5'}
Add-Type @Compile
$BaseUrl='http://127.0.0.1:8788'
function Set-RouterVPNControllerRequestTimeout($Request,$Milliseconds){if($Milliseconds-ne10000){throw 'Unexpected UI request timeout.'}}
$script:Busy=$false;$script:Refreshes=0
function Assert-RouterVPNMutationIdle($Label){if($script:Busy){throw 'Explicit mutation busy fixture'}}
function RefreshProduct{$script:Refreshes++}
function RefreshUnifiedTelemetry{}
$script:Checks=0
function Check([bool]$Value,[string]$Note){$script:Checks++;if(-not$Value){throw $Note}}
function Fixture([string]$Name){return [IO.File]::ReadAllText((Join-Path $Output ($Name+'.json')))}
function NewState{
 $Dialog=[pscustomobject]@{Closed=$false};$Dialog|Add-Member ScriptMethod Close {$this.Closed=$true}
 return @{Dialog=$Dialog;Status=[pscustomobject]@{Text=''};Result=[pscustomobject]@{Text=''};Compare=[pscustomobject]@{IsEnabled=$true};Fastest=[pscustomobject]@{IsEnabled=$true};Cancel=[pscustomobject]@{IsEnabled=$false};Client=[ComparisonHTTPFixture]::new();Task=$null;Request=$null;Cts=$null;Phase='';Choice=$null;RequestID='';CohortID='';Started=$false;Finished=$true;CancelWanted=$false;CancelAccepted=$false;CloseWanted=$false;AllowClose=$false;Closed=$false;Next=[DateTime]::UtcNow}
}
function Reply($S,[string]$Name){$S.Client.Reply((Fixture $Name));TickExternalComparison $S}
function SaveBody($S,[int]$Index,[string]$Name){[IO.File]::WriteAllText((Join-Path $Output ($Name+'.json')),$S.Client.Bodies[$Index],[Text.UTF8Encoding]::new($false))}
$Offer=Fixture 'offer'|ConvertFrom-Json;$Compared=Fixture 'compared'|ConvertFrom-Json;$Incomplete=Fixture 'incomplete'|ConvertFrom-Json
Check (ExternalComparisonMatches $Compared $Offer.request_id $Offer.cohort_id) 'Matching server identity rejected.'
Check (-not(ExternalComparisonMatches (Fixture 'foreign'|ConvertFrom-Json) $Offer.request_id $Offer.cohort_id)) 'Foreign result accepted.'
Check ((ExternalComparisonScore $Compared.rows[0])-eq4.5) 'Actual strict50 metric was lost.'
Check ($null-eq(ExternalComparisonScore $Incomplete.rows[0])) '49 samples displayed as score.'
Check ((ExternalComparisonRows $Compared.rows $true).Contains('not a current winner')) 'Historical values presented as current selection.'
Check (-not(ExternalComparisonState (Fixture 'draining'|ConvertFrom-Json)).Contains('original connection state was restored')) 'Undrained cancellation claimed restoration.'
$Warning=ExternalComparisonState (Fixture 'connected-warning'|ConvertFrom-Json)
Check ($Warning.Contains('winner selection was saved')-and-not$Warning.Contains('winner is connected')) 'A committed warning claimed a currently connected path.'
$S=NewState;&$Begin $false
Check ($S.Client.Paths[0]-ceq'/api/speed-lab/external-comparison'-and$S.Client.Methods[0]-ceq'GET') 'Compare did not capture a fresh server offer.'
Reply $S 'offer';Check ($S.Client.Methods[1]-ceq'POST'-and$S.Started-and-not$S.Finished) 'Compare did not start exact capture.';SaveBody $S 1 'compare-body'
Reply $S 'active';$S.Next=[DateTime]::MinValue;TickExternalComparison $S
Check ($S.Client.Paths[2]-ceq('/api/speed-lab/external-comparison?request_id='+$Offer.request_id)) 'Polling lost original request.'
Reply $S 'compared';Check ($S.Finished-and$S.Compare.IsEnabled-and$S.Status.Text.Contains('original connection state was restored')-and-not$S.Status.Text.Contains('winner is connected')) 'Compare-only altered final adoption intent.';$S.Client.Dispose()
$S=NewState;&$Begin $true;Reply $S 'offer';SaveBody $S 1 'connect-body';Reply $S 'connected'
Check ($S.Finished-and$S.Status.Text.Contains('winner is connected')-and$script:Refreshes-eq2) 'Explicit fastest completion missing.';$S.Client.Dispose()
$S=NewState;&$Begin $true;Reply $S 'offer';Reply $S 'foreign'
Check ($S.CancelWanted-and-not$S.Finished-and-not$S.Result.Text.Contains('4.50')) 'Foreign response claimed winner.'
$S.Next=[DateTime]::MinValue;TickExternalComparison $S;SaveBody $S 2 'cancel-body';Check ($S.Client.Paths[2]-ceq'/api/speed-lab/external-comparison/cancel') 'Foreign response did not cancel original intent.'
$Event=[pscustomobject]@{Cancel=$false};&$Closing $S.Dialog $Event
Check ($Event.Cancel-and$S.CloseWanted-and-not$S.Dialog.Closed) 'Close escaped before cancellation drain.'
Reply $S 'draining';Check (-not$S.Finished-and-not$S.Dialog.Closed-and$S.Cancel.IsEnabled) 'Pending cleanup was treated as done.'
$S.Next=[DateTime]::MinValue;TickExternalComparison $S;Reply $S 'cancelled'
Check ($S.Finished-and$S.Dialog.Closed-and$S.AllowClose) 'Completed owned drain did not release close.';$S.Client.Dispose()
$S=NewState;$script:Busy=$true;&$Begin $true;Check ($S.Client.Paths.Count-eq0) 'Busy main decision captured a batch.';$script:Busy=$false;$S.Client.Dispose()
$S=NewState;StartExternalComparisonRequest $S 'offer' '/api/speed-lab/external-comparison';$Event=[pscustomobject]@{Cancel=$false};&$Closing $S.Dialog $Event;TickExternalComparison $S
Check ($S.Dialog.Closed-and-not$S.Started-and$S.Client.Paths.Count-eq1) 'Close during preview started a stale batch.';$S.Client.Dispose()
Write-Output ('Actual generated Windows external comparison actions: '+$script:Checks+' checks PASS; WPF controls/HTTP completion are explicit fixture boundaries.')
