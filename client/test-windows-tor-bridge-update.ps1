param([string]$Root=(Split-Path $PSScriptRoot -Parent),[Parameter(Mandatory=$true)][string]$Output)
$ErrorActionPreference='Stop';Set-StrictMode -Version 2
$Source=Get-Content -Raw -Encoding UTF8 (Join-Path $Root 'client/RouterVPN-Windows-TorBridge.ps1')
$Ast=[ScriptBlock]::Create($Source).Ast
foreach($Prefix in @('function TestUnifiedExternalMutationIdle','function GetUnifiedTorUpdateProfile')){
    $Blocks=@($Ast.FindAll({param($N)$N-is[Management.Automation.Language.StringConstantExpressionAst]-and$N.Value.StartsWith($Prefix)},$true))
    if($Blocks.Count-ne1){throw 'Native Tor form source closure changed'}
    . ([ScriptBlock]::Create($Blocks[0].Value))
    if($Prefix-ceq'function GetUnifiedTorUpdateProfile'){$Tor=[ScriptBlock]::Create($Blocks[0].Value)}
}
$Actions=@($Tor.Ast.FindAll({param($N)$N-is[Management.Automation.Language.InvokeMemberExpressionAst]-and$N.Member.Extent.Text-ceq'Add_Click'-and$N.Expression.Extent.Text-ceq'$D.FindName(''TorSave'')'},$true))
if($Actions.Count-ne1){throw 'Actual Tor Save callback is missing or ambiguous'}
$Save=$Actions[0].Arguments[0].ScriptBlock.GetScriptBlock()
$Checks=@($Tor.Ast.FindAll({param($N)$N-is[Management.Automation.Language.InvokeMemberExpressionAst]-and$N.Member.Extent.Text-ceq'Add_Checked'-and$N.Expression.Extent.Text-ceq'$Update'},$true))
if($Checks.Count-ne1){throw 'Actual Update checkbox handler is missing or ambiguous'}
$SelectUpdate=$Checks[0].Arguments[0].ScriptBlock.GetScriptBlock()
$Unchecks=@($Tor.Ast.FindAll({param($N)$N-is[Management.Automation.Language.InvokeMemberExpressionAst]-and$N.Member.Extent.Text-ceq'Add_Unchecked'-and$N.Expression.Extent.Text-ceq'$Update'},$true))
if($Unchecks.Count-ne1){throw 'Actual Add checkbox handler is missing or ambiguous'}
$SelectAdd=$Unchecks[0].Arguments[0].ScriptBlock.GetScriptBlock()
$CaptureStatements=@($Tor.Ast.FindAll({param($N)$N-is[Management.Automation.Language.AssignmentStatementAst]-and$N.Left.Extent.Text-cin@('$Displayed','$Opened','$CapturedProfile')},$true))
if($CaptureStatements.Count-ne3){throw 'Actual rendered-catalog capture changed'}
$Capture=[ScriptBlock]::Create(($CaptureStatements|ForEach-Object{$_.Extent.Text})-join"`n")
$Markup=@($Tor.Ast.FindAll({param($N)($N-is[Management.Automation.Language.ExpandableStringExpressionAst]-or$N-is[Management.Automation.Language.StringConstantExpressionAst])-and$N.Value.TrimStart().StartsWith('<Window')},$true))
if($Markup.Count-ne1){throw 'Native Tor editor markup missing'}
[xml]$XML=$Markup[0].Value
if($null-eq$XML.SelectSingleNode('//*[@Name="TorUpdate"]')){throw 'Native Tor update control missing'}
$Raw=Get-Content -Raw (Join-Path $Output 'tor-update-source-catalog.json')
$Opened=$Raw|ConvertFrom-Json;$script:Current=$Raw|ConvertFrom-Json
$Capabilities=Get-Content -Raw (Join-Path $Output 'tor-update-capabilities.json')|ConvertFrom-Json
$InputLines=Get-Content -Raw (Join-Path $Output 'tor-update-input-lines.json')|ConvertFrom-Json
$Name=[pscustomobject]@{Text='Native Tor update'};$Transport=[pscustomobject]@{Items=@('obfs4','meek_lite','snowflake','webtunnel','custom'|ForEach-Object{[pscustomobject]@{Tag=$_}});SelectedIndex=0}
$Transport|Add-Member ScriptProperty SelectedItem {return $this.Items[$this.SelectedIndex]}
$Kill=[pscustomobject]@{Items=@([pscustomobject]@{Tag='off'},[pscustomobject]@{Tag='on-connect'},[pscustomobject]@{Tag='always'});SelectedIndex=2}
$Kill|Add-Member ScriptProperty SelectedItem {if($this.SelectedIndex-ge0-and$this.SelectedIndex-lt$this.Items.Count){return $this.Items[$this.SelectedIndex]};return $null}
$Lines=[pscustomobject]@{Text=''}
$Update=[pscustomobject]@{IsChecked=$true};$Status=[pscustomobject]@{Text=''};$Support=@{Root=$Capabilities}
$Button=[pscustomobject]@{IsEnabled=$true};$D=[pscustomobject]@{Button=$Button}
$D|Add-Member ScriptMethod FindName {param($ID)if($ID-cne'TorSave'){throw 'Unexpected form control'};return $this.Button}
$NativeWPF=$env:OS-eq'Windows_NT'
if($NativeWPF){
    if([Threading.Thread]::CurrentThread.ApartmentState-ne'STA'){throw 'The native WPF fixture must run with -STA'}
    Add-Type -AssemblyName PresentationFramework,PresentationCore,WindowsBase
    $D=[Windows.Markup.XamlReader]::Load([Xml.XmlNodeReader]::new($XML))
    $Name=$D.FindName('TorName');$Transport=$D.FindName('TorTransport');$Kill=$D.FindName('TorKill');$Lines=$D.FindName('TorLines');$Update=$D.FindName('TorUpdate');$Status=$D.FindName('TorStatus');$Button=$D.FindName('TorSave')
    $Transport.SelectedIndex=0;$Kill.SelectedIndex=0
    $Update.Add_Checked($SelectUpdate);$Update.Add_Unchecked($SelectAdd);$Button.Add_Click($Save)
    $SelectUpdate={$Update.IsChecked=$false;$Update.IsChecked=$true}
    $Save={$Button.RaiseEvent([Windows.RoutedEventArgs]::new([Windows.Controls.Primitives.ButtonBase]::ClickEvent))}
    $Update.IsChecked=$true
}
$script:Saved=$null;$script:Busy=$false;$script:NodeReads=0;$script:Checks=0
function Check([bool]$Value,[string]$Why){$script:Checks++;if(-not$Value){throw $Why}}
function Api($Path,$Method='GET',$Body=$null,$Timeout=0){
    if($Path-ceq'/api/status'){return [pscustomobject]@{connected=$script:Busy;phase='off'}}
    if($Path-ceq'/api/nodes'){$script:NodeReads++;return $script:Current}
    if($Path-cne'/api/tor-bridge/import'-or$Method-cne'POST'){throw 'Unexpected editor request'}
    $script:Saved=$Body;return [pscustomobject]@{profile=[pscustomobject]@{name='Saved fixture'}}
}
function Log($Message){}
function RefreshProduct{}
function Control($ID){if($ID-cne'UnifiedNodeCombo'){throw 'Unexpected rendered control'};return $script:Rendered}
$LocalRaw=$Raw
$Selections=@('local','server')+@('wireguard','amneziawg','socks5','http-connect','https-connect','shadowsocks','hysteria2','openvpn'|ForEach-Object{'ordinary-'+$_})
foreach($Execution in $Selections){
    $Ordinary=$Execution.StartsWith('ordinary-');$TCPOnly=$Execution-cin@('ordinary-socks5','ordinary-http-connect','ordinary-https-connect')
    $FilePrefix=if($Execution-ceq'local'){''}else{$Execution+'-'}
    $Raw=Get-Content -Raw (Join-Path $Output ('tor-update-'+$FilePrefix+'source-catalog.json'))
    $Opened=$Raw|ConvertFrom-Json;$script:Current=$Raw|ConvertFrom-Json
foreach($ID in @('obfs4','meek_lite','snowflake','webtunnel')){
    foreach($Policy in @('off','on-connect','always')){
        $Transport.SelectedIndex=@('obfs4','meek_lite','snowflake','webtunnel').IndexOf($ID);$Kill.SelectedIndex=@('off','on-connect','always').IndexOf($Policy);$Lines.Text=$InputLines.$ID-join"`n"
        $script:Saved=$null;$Button.IsEnabled=$true;&$Save
        if($TCPOnly-and$ID-ceq'snowflake'-and$Policy-cne'off'){
            Check ($null-eq$Saved-and$Button.IsEnabled) 'Strict Snowflake escaped the captured TCP-only predecessor check'
            continue
        }
        Check ($null-ne$Saved) ('Actual Tor Save rejected valid update: '+$Status.Text)
        Check ($Saved.id-ceq'tor-edit'-and$Saved.expected_selected_node_id-ceq'tor-edit'-and$Saved.expected_profile_tokens.Count-eq2) 'Update lost captured Tor and entry identities'
        Check ($Saved.transport-ceq$ID-and$Saved.kill_switch_policy-ceq$Policy-and-not$Button.IsEnabled) 'Update changed selection or allowed stale repeated Save'
        foreach($Forbidden in @('profile_id','entry_id','entry_mode','direct','execution','api_token','dns_mode')){Check (-not$Saved.ContainsKey($Forbidden)) ('Bridge form copied unrelated setting '+$Forbidden)}
        [IO.File]::WriteAllText((Join-Path $Output ('tor-update-'+$FilePrefix+$ID+'-'+$Policy+'.json')),($Saved|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))
    }
}
$AlwaysRaw=Get-Content -Raw (Join-Path $Output ('tor-update-'+$FilePrefix+'always-source-catalog.json'))
$Opened=$AlwaysRaw|ConvertFrom-Json;$script:Current=$AlwaysRaw|ConvertFrom-Json;$Kill.SelectedIndex=0
&$SelectUpdate
Check ($Kill.SelectedIndex-eq2-and$Name.Text-ceq'Captured Tor exit') 'Update checkbox did not load the saved Always policy and name'
$PreservedTransport=if($Ordinary){'meek_lite'}else{'snowflake'}
$Transport.SelectedIndex=@('obfs4','meek_lite','snowflake','webtunnel').IndexOf($PreservedTransport);$Lines.Text=$InputLines.$PreservedTransport-join"`n";$script:Saved=$null;$Button.IsEnabled=$true;&$Save
Check ($null-ne$Saved-and$Saved.kill_switch_policy-ceq'always') ('Actual Save lost untouched saved protection: '+$Status.Text)
[IO.File]::WriteAllText((Join-Path $Output ('tor-update-'+$FilePrefix+'preserved-protection.json')),($Saved|ConvertTo-Json -Depth 16),[Text.UTF8Encoding]::new($false))
$Faults=@('selected','exit-token','entry-token','missing-entry','duplicate-exit','entry-is-external','compare-path','server-direct','server-external-entry','compare-off','server-direct-off','server-external-off','old-controller','missing-token','busy','display-mutated','invalid-saved-policy','missing-saved-policy')
if($Ordinary){$Faults+=@('ordinary-mode','ordinary-public-proof','ordinary-capability','ordinary-fixed-bypass');if($TCPOnly){$Faults+=@('ordinary-mixed-udp','ordinary-mixed-udp-bare','ordinary-mixed-udp-unicode')}}
foreach($Fault in $Faults){
    $Opened=$Raw|ConvertFrom-Json;$script:Current=$Raw|ConvertFrom-Json;$Support.Root=$Capabilities|ConvertTo-Json -Depth 16|ConvertFrom-Json;$script:Busy=$false
    $Kill.SelectedIndex=2
    switch($Fault){
        'selected'{$script:Current.selected_id='entry'}
        'exit-token'{$script:Current.profiles[0].profile_token='a'*64}
        'entry-token'{$script:Current.profiles[1].profile_token='b'*64}
        'missing-entry'{$script:Current.profiles=@($script:Current.profiles[0])}
        'duplicate-exit'{$script:Current.profiles+=@($script:Current.profiles[0])}
        'entry-is-external'{$Opened.profiles[1].node_kind='external';if($Ordinary){$Opened.profiles[1].external.protocol='unknown'};$script:Current=$Opened}
        'compare-path'{$Opened.profiles[0].multihop_execution='auto';$script:Current=$Opened}
        'server-direct'{$Opened.profiles[0].multihop_execution='server';$Opened.profiles[0].multihop_enabled=$false;$script:Current=$Opened}
        'server-external-entry'{$Opened.profiles[0].multihop_execution='server';$Opened.profiles[1].node_kind='external';$script:Current=$Opened}
        'compare-off'{$Opened.profiles[0].multihop_execution='auto';$script:Current=$Opened}
        'server-direct-off'{$Opened.profiles[0].multihop_execution='server';$Opened.profiles[0].multihop_enabled=$false;$script:Current=$Opened}
        'server-external-off'{$Opened.profiles[0].multihop_execution='server';$Opened.profiles[1].node_kind='external';$script:Current=$Opened}
        'old-controller'{$Support.Root=@{profile_update_source_preconditions=$false;transports=$Capabilities.transports}}
        'missing-token'{$Opened.profiles[0].profile_token='';$script:Current=$Opened}
        'busy'{$script:Busy=$true}
        'display-mutated'{$script:Rendered=[pscustomobject]@{Tag=($Raw|ConvertFrom-Json)};. $Capture;$script:Rendered.Tag.profiles[1].profile_token='c'*64;$script:Current=$script:Rendered.Tag}
        'invalid-saved-policy'{$Opened.profiles[0].kill_switch_policy='unexpected';&$SelectUpdate;Check ($Kill.SelectedIndex-eq-1) 'Invalid saved policy silently became Off'}
        'missing-saved-policy'{$Opened.profiles[0].PSObject.Properties.Remove('kill_switch_policy');&$SelectUpdate;Check ($Kill.SelectedIndex-eq-1) 'Missing saved policy silently became Off'}
        'ordinary-mode'{$Opened.profiles[0].multihop_entry_mode='unrelated-mode';$script:Current=$Opened}
        'ordinary-public-proof'{$Opened.profiles[1].external.expected_public_ip='';$script:Current=$Opened}
        'ordinary-capability'{foreach($Row in $Support.Root.transports){$Row.strict_external_entry_kill_switch=$false}}
        'ordinary-fixed-bypass'{$Opened.profiles[0].multihop_entry_mode='unrelated-mode';$script:Current=$Opened}
    }
    if($Fault.EndsWith('-off')){$Kill.SelectedIndex=0;$Transport.SelectedIndex=0;$Lines.Text=$InputLines.obfs4-join"`n"}
    elseif($Fault-ceq'ordinary-fixed-bypass'){$Transport.SelectedIndex=0;$Lines.Text=$InputLines.obfs4-join"`n"}
    elseif($Fault.StartsWith('ordinary-mixed-udp')){
        $Mixed=[string]$InputLines.snowflake[0]
        if($Fault.EndsWith('-bare')){$Mixed=$Mixed-replace'^Bridge ',''}
        if($Fault.EndsWith('-unicode')){$Mixed=$Mixed-replace'^Bridge snowflake ',('bRiDgE'+[char]0x00a0+'SnOwFlAkE'+[char]0x00a0)}
        $Transport.SelectedIndex=4;$Lines.Text=(@($InputLines.obfs4)+@($Mixed))-join"`n"
    }
    elseif($Ordinary){$Transport.SelectedIndex=1;$Lines.Text=$InputLines.meek_lite-join"`n"}
    else{$Transport.SelectedIndex=2;$Lines.Text=$InputLines.snowflake-join"`n"}
    $script:Saved=$null;$Button.IsEnabled=$true;&$Save;Check ($null-eq$Saved) ('Tor update adopted '+$Fault)
}
}
$Raw=$LocalRaw
$script:Busy=$false;$Opened=$Raw|ConvertFrom-Json;$script:Current=$Raw|ConvertFrom-Json;$Support.Root=$Capabilities
$Update.IsChecked=$false;$Kill.SelectedIndex=2;$Transport.SelectedIndex=2;$Lines.Text=$InputLines.snowflake-join"`n"
$script:Saved=$null;&$Save;Check ($null-eq$Saved) 'New Direct dynamic transport borrowed Router protection'
$Kill.SelectedIndex=0;$script:Saved=$null;$BeforeReads=$NodeReads;&$Save
Check ($null-ne$Saved-and-not$Saved.ContainsKey('id')-and-not$Saved.ContainsKey('expected_profile_tokens')-and$NodeReads-eq$BeforeReads) 'Add borrowed selected identity or recaptured nodes'
if($NativeWPF){$D.Close()}
Write-Host "Windows actual Tor editor callbacks: $script:Checks checks PASS; WPF=$NativeWPF"
