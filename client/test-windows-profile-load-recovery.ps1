# The shipping Settings callback fixture loads this suite with -TransactionOnly.
$state=Join-Path $FixtureStateRoot '.routervpn-state'
$presetFile=Join-Path $state 'windows-custom-presets-v1.json'
$modeFile=Join-Path $state 'windows-selected-mode-v1.txt'
$journal=Join-Path $state 'windows-profile-load-v1.json'
$expected='custom:Exact Saved Name'
$oldPreset=[Text.Encoding]::UTF8.GetBytes('[{"name":"Sibling","layers":["tls"]}]')
$oldMode=[byte[]](239,187,191)+[Text.Encoding]::UTF8.GetBytes('auto')
$script:Loaded=[pscustomobject]@{profile=[pscustomobject]@{name='Saved profile';mode=$expected};mode=$expected;custom_layers=@('wg','pq');selected_node_id='private-node';profile_tokens=@{'private-node'=('7'*64)};multihop_enabled=$false;private_key='never-write-this'}
$priorTag=$RouterCombo.Tag
function TxReject([scriptblock]$Action,[string]$Message){
    $refused=$false
    try{& $Action}catch{$refused=$true}
    Check $refused $Message
}
function ResetTxFixture {
    Check (-not [IO.File]::Exists($journal)) 'Prior native load still owns the fixture'
    [IO.File]::WriteAllBytes($presetFile,$oldPreset);[IO.File]::WriteAllBytes($modeFile,$oldMode)
    $RouterCombo.Tag=$priorTag;$RouterCombo.SelectedValue='private-node';$toggle.IsChecked=$true
    $script:PhaseHook=$null;$script:Absent=$false;$script:Tx=$null;$global:RouterVPNTestWriteFault=$null
}
function CheckBeforeImage {
    Check ([Convert]::ToBase64String([IO.File]::ReadAllBytes($presetFile)) -ceq [Convert]::ToBase64String($oldPreset)) 'Rollback did not restore the exact original preset bytes'
    Check ([Convert]::ToBase64String([IO.File]::ReadAllBytes($modeFile)) -ceq [Convert]::ToBase64String($oldMode)) 'Rollback lost the original selected mode bytes or BOM'
}
function CheckAfterImage {
    Check ([IO.File]::ReadAllText($modeFile) -ceq $expected) 'Commit lost the exact selected CUSTOM name'
    $presets=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($presetFile))
    Check ($presets.Count -eq 2 -and $presets[0].name -ceq 'Sibling' -and $presets[1].name -ceq 'Exact Saved Name' -and ($presets[1].layers -join ',') -ceq 'wg,pq') 'Commit changed a sibling, literal CUSTOM name, or ordered layers'
}
$module=Get-Module RouterVPN-Windows-UIState
& $module {
    $script:ActualPreferenceWrite=(Get-Item Function:Write-RouterVPNUIStateBytes).ScriptBlock
    function script:Write-RouterVPNUIStateBytes([string]$Path,[byte[]]$Bytes,[bool]$CreateOnly,[int]$Limit=$script:UIStateLimit){
        if($null-ne$global:RouterVPNTestWriteFault){&$global:RouterVPNTestWriteFault $Path $Bytes}
        &$script:ActualPreferenceWrite $Path $Bytes $CreateOnly $Limit
    }
}
try{
    ResetTxFixture
    Invoke-RouterVPNPreferenceBatch $FixtureStateRoot {
        TxReject {Open-RouterVPNProfileState $FixtureStateRoot} 'Profile load acquired the lease in the middle of an ordinary CUSTOM edit'
        Write-RouterVPNUIState $FixtureStateRoot 'windows-custom-presets-v1.json' '[]'
        Write-RouterVPNUIState $FixtureStateRoot 'windows-selected-mode-v1.txt' 'auto'
    }
    ResetTxFixture
    $script:PhaseHook={param($phase,$when,$payload)
        if($phase -ceq 'prepare'){
            $local=ConvertFrom-Json -InputObject ([IO.File]::ReadAllText($journal))
            Check ($local.phase -ceq 'preparing' -and $local.operation_id -ceq $payload.operation_id) 'The initial controller request preceded its local operation'
            CheckBeforeImage
            TxReject {Write-RouterVPNUIState $FixtureStateRoot 'windows-selected-mode-v1.txt' 'other'} 'A simultaneous preference writer acquired the held transaction lock'
        }
        if($phase -ceq 'commit' -and $when -ceq 'before'){CheckAfterImage}
        if($phase -ceq 'finish' -and $when -ceq 'before'){
            $raw=[IO.File]::ReadAllText($journal)
            Check ($raw -notmatch 'never-write-this|private_key' -and ($raw|ConvertFrom-Json).phase -ceq 'complete') 'Finish preceded a complete nonsecret local journal'
        }
    }
    &$LoadCallback
    Check ($profileStatus.Text.StartsWith('Loaded ') -and $script:Tx.finished -and -not [IO.File]::Exists($journal)) ('Exact coordinated Load failed: '+$profileStatus.Text)
    CheckAfterImage

    ResetTxFixture
    $notify=$OnConnectionProfileLoaded;$OnConnectionProfileLoaded={throw 'post-commit refresh unavailable'}
    &$LoadCallback
    Check ($profileStatus.Text.StartsWith('Loaded ') -and $profileStatus.Text.Contains('Refresh failed:') -and $script:Tx.state -ceq 'committed') 'Post-commit notification failure incorrectly reported a failed profile load'
    $OnConnectionProfileLoaded=$notify
    ResetTxFixture
    $script:ReplyTransform={param($r)$r.profile.id='different-saved-profile';return $r}
    &$LoadCallback
    Check ($profileStatus.Text.StartsWith('Load failed:') -and $script:Tx.state -ceq 'aborted' -and $script:Tx.finished) 'A prepared reply for another saved profile was accepted'
    CheckBeforeImage
    $script:ReplyTransform=$null

    ResetTxFixture
    $global:RouterVPNTestWriteFault={param($path,$bytes)if($path -ceq $modeFile){throw [IO.IOException]::new('injected selected-mode write failure')}}
    &$LoadCallback
    Check ($profileStatus.Text.StartsWith('Load failed:') -and $script:Tx.state -ceq 'aborted' -and $script:Tx.finished -and -not [IO.File]::Exists($journal)) ('Second preference failure did not roll back: '+$profileStatus.Text)
    CheckBeforeImage
    Check ([object]::ReferenceEquals($RouterCombo.Tag,$priorTag)) 'Local write failure replaced the previous visible router catalog'

    ResetTxFixture
    [IO.File]::Delete($modeFile);[IO.File]::Delete($presetFile)
    $global:RouterVPNTestWriteFault={param($path,$bytes)if($path -ceq $modeFile){throw [IO.IOException]::new('injected failure creating selected mode')}}
    &$LoadCallback
    Check ($script:Tx.state -ceq 'aborted' -and $script:Tx.finished -and -not [IO.File]::Exists($modeFile) -and -not [IO.File]::Exists($presetFile)) 'Partial create did not restore both originally absent preferences'

    ResetTxFixture
    $global:RouterVPNTestWriteFault={param($path,$bytes)
        if($path -ceq $modeFile -or ($path -ceq $presetFile -and [Convert]::ToBase64String($bytes) -ceq [Convert]::ToBase64String($oldPreset))){throw [IO.IOException]::new('injected rollback write failure')}
    }
    &$LoadCallback
    Check ($profileStatus.Text.StartsWith('Load recovery pending:') -and $script:Tx.state -ceq 'prepared' -and -not $script:Tx.finished -and [IO.File]::Exists($journal)) 'Unfinished rollback released the controller'
    $global:RouterVPNTestWriteFault=$null
    $script:EnteredBuilder=$false
    TxReject {Invoke-RouterVPNPreferenceBatch $FixtureStateRoot {$script:EnteredBuilder=$true}} 'A CUSTOM builder entered during recovery'
    Check (-not $script:EnteredBuilder) 'An interrupted load allowed an ordinary builder write'
    TxReject {Write-RouterVPNUIState $FixtureStateRoot 'windows-custom-presets-v1.json' 'foreign'} 'A preset writer crossed a crash-recovery journal'
    foreach($path in @('/api/auto','/api/connect-logical','/api/external-profile/connect','/api/multihop/connect','/api/strategy/smart-auto','/api/strategy/auto','/api/strategy/custom')){
        TxReject {Assert-RouterVPNProfileAdmission $FixtureStateRoot $path 'POST'} ('Unresolved load allowed a fresh connection: '+$path)
    }
    foreach($path in @('/api/disconnect','/api/disconnect/retry','/api/emergency-stop')){Assert-RouterVPNProfileAdmission $FixtureStateRoot $path 'POST'}
    $staged=[IO.File]::ReadAllBytes($presetFile)
    [IO.File]::WriteAllText($presetFile,'different-owner')
    TxReject {Repair-RouterVPNProfileLoad $BaseUrl} 'Rollback overwrote a later preference owner'
    Check ([IO.File]::ReadAllText($presetFile) -ceq 'different-owner' -and $script:Tx.state -ceq 'prepared') 'A CAS conflict changed another writer or released admission'
    [IO.File]::WriteAllBytes($presetFile,$staged);$script:Absent=$true
    TxReject {Repair-RouterVPNProfileLoad $BaseUrl} 'Missing backend ownership discarded a partially staged journal'
    $script:Absent=$false
    $generation=$script:Tx.generation;$script:Tx.generation='0'*32
    TxReject {Repair-RouterVPNProfileLoad $BaseUrl} 'Wrong remote generation authorized rollback'
    $script:Tx.generation=$generation
    Repair-RouterVPNProfileLoad $BaseUrl
    Check ($script:Tx.state -ceq 'aborted' -and $script:Tx.finished -and -not [IO.File]::Exists($journal)) 'Restart failed to recover the original prepared owner'
    CheckBeforeImage

    foreach($lost in @('commit-before','commit-after','finish-after')){
        ResetTxFixture
        $script:PhaseHook={param($phase,$when,$payload)if(($phase+'-'+$when) -ceq $lost -or ($phase -ceq 'status' -and [IO.File]::Exists($journal))){throw 'injected lost reply'}}
        &$LoadCallback
        Check ($profileStatus.Text.StartsWith('Load recovery pending:') -and [IO.File]::Exists($journal)) 'Unknown controller outcome failed to retain its journal'
        $script:PhaseHook=$null
        if($lost -ceq 'finish-after'){$script:Absent=$true;[IO.File]::WriteAllText($modeFile,'new-owner')}
        Repair-RouterVPNProfileLoad $BaseUrl
        if($lost -ceq 'commit-before'){CheckBeforeImage;Check ($script:Tx.state -ceq 'aborted') 'Unreached COMMIT switched the profile'}
        elseif($lost -ceq 'commit-after'){CheckAfterImage;Check ($script:Tx.state -ceq 'committed') 'Lost committed reply restored the old profile'}
        else{Check ([IO.File]::ReadAllText($modeFile) -ceq 'new-owner') 'Finished old operation overwrote a subsequent owner'}
        Check (-not [IO.File]::Exists($journal)) 'Recovered terminal operation kept the local writer fence'
    }
    ResetTxFixture
    $script:PhaseHook={param($phase,$when,$payload)if($phase -ceq 'prepare' -or ($phase -ceq 'status' -and [IO.File]::Exists($journal))){throw 'controller unavailable before prepare'}}
    &$LoadCallback
    $pending=Get-Content $journal -Raw|ConvertFrom-Json
    Check ($pending.phase -ceq 'preparing') 'An unreachable prepare staged local changes'
    $script:PhaseHook=$null;$script:Absent=$true
    Repair-RouterVPNProfileLoad $BaseUrl
    CheckBeforeImage
    Check ($script:Tx.operation_id -ceq $pending.operation_id -and $script:Tx.state -ceq 'aborted' -and $script:Tx.finished -and -not [IO.File]::Exists($journal)) 'Absent ambiguous prepare was not reacquired and retired for its exact owner'
    Check ($script:Tombstone -and $pending.request.expected_revision -cne [string]$script:Revision) 'The ambiguous initial request retained a usable revision'
    ResetTxFixture
    $script:PhaseHook={param($phase,$when,$payload)if($phase -ceq 'prepare' -or ($phase -ceq 'status' -and [IO.File]::Exists($journal))){throw 'original prepare lost'}}
    &$LoadCallback
    Check ([IO.File]::Exists($journal)) 'Original prepare failure lost its revision'
    $script:PhaseHook=$null;$script:Absent=$true;$script:Revision++
    [IO.File]::WriteAllText($modeFile,'later-owner')
    Repair-RouterVPNProfileLoad $BaseUrl
    Check (-not [IO.File]::Exists($journal) -and [IO.File]::ReadAllText($modeFile) -ceq 'later-owner') 'Superseded untouched preparation overwrote a newer local owner'
    if([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT){
        # Instantiate the shipping selector types with their real binding and
        # SelectionChanged events. The CI matrix runs both Windows shells.
        Add-Type -AssemblyName PresentationFramework
        ResetTxFixture
        foreach($name in @('GetUnifiedModeID','GetUnifiedPresets','RefreshUnifiedModeChoices')){
            . ([ScriptBlock]::Create((ShippingFunction $ProductSource $name).Replace('$PSScriptRoot','$FixtureStateRoot')))
        }
        $ModesGrid=[pscustomobject]@{ItemsSource=@()}
        $RouterCombo=New-Object System.Windows.Controls.ComboBox
        $RouterCombo.SelectedValuePath='id';$RouterCombo.ItemsSource=@($priorTag.profiles);$RouterCombo.Tag=$priorTag;$RouterCombo.SelectedValue='private-node'
        $Owner.Controls['UnifiedNodeCombo']=$RouterCombo
        $ModeCombo=New-Object System.Windows.Controls.ComboBox
        $ModeCombo.SelectedValuePath='id';$Owner.Controls['UnifiedModeCombo']=$ModeCombo
        RefreshUnifiedModeChoices @()
        $script:UngatedProjection=0
        function Assert-RouterVPNMutationIdle {$script:UngatedProjection++;throw 'Programmatic load entered an ordinary mutation handler'}
        foreach($binding in @([pscustomobject]@{name='$RouterCombo';widget=$RouterCombo},[pscustomobject]@{name="(Control 'UnifiedModeCombo')";widget=$ModeCombo})){
            $handlers=@((ShippingIndex $ProductSource).AST.FindAll({param($n)$n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] -and $n.Member.Extent.Text -ceq 'Add_SelectionChanged' -and $n.Expression.Extent.Text -ceq $binding.name},$true))
            Check ($handlers.Count -eq 1) 'Actual WPF profile selection event is missing'
            $source=$handlers[0].Arguments[0].ScriptBlock.Extent.Text
            $binding.widget.Add_SelectionChanged([ScriptBlock]::Create($source.Substring(1,$source.Length-2).Replace('$PSScriptRoot','$FixtureStateRoot')))
        }
        $script:Loaded.selected_node_id='entry_private';$script:Loaded.profile_tokens=@{entry_private=('6'*64)}
        &$LoadCallback
        Check ($profileStatus.Text.StartsWith('Loaded ') -and $RouterCombo.SelectedItem.id -ceq 'entry_private' -and $ModeCombo.SelectedItem.id -ceq $expected) ('Real WPF controls did not select the prepared node and literal mode: '+$profileStatus.Text)
        Check ($script:UngatedProjection -eq 0) 'Staged WPF selections initiated an ordinary controller mutation'
        CheckAfterImage
    }
    Write-Output ('Windows coordinated profile load, real preference files, failed writes and recovery: '+$script:Count+' assertions passed')
}finally{
    & $module {Set-Item -Path Function:script:Write-RouterVPNUIStateBytes -Value $script:ActualPreferenceWrite}
    Remove-Variable RouterVPNTestWriteFault -Scope Global -ErrorAction SilentlyContinue
}
