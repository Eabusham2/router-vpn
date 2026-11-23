param([Parameter(Mandatory=$true)][string]$ProductSource,[switch]$Native,[string]$RenderPng)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest

$ast=[ScriptBlock]::Create($ProductSource).Ast
foreach($name in @('GlobeUnitXY','GlobeXY','GetUnifiedLandGeometry','GetUnifiedGlobeOutline','AddUnifiedGlobeShape','GetUnifiedGlobeLeg','GetUnifiedGlobePacket',
    'GetUnifiedGlobeActiveRoute','GetUnifiedGlobeHopColor','AddGlobeLine','DrawMap','ClearUnifiedGlobeRoute','TickUnifiedMapAnimation','CancelUnifiedTelemetryRefreshAsync')){
    $found=@($ast.FindAll({param($n)$n -is [Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -ceq $name},$true))
    if($found.Count -ne 1){throw "Missing or duplicate composed map function: $name"}
    . ([ScriptBlock]::Create($found[0].Extent.Text))
}
function Check-Map([bool]$ok,[string]$message){if(-not $ok){throw $message}}
function Check-SamePoint($a,$b){
    Check-Map ([Math]::Abs($a[0]-$b[0]) -lt .000001 -and [Math]::Abs($a[1]-$b[1]) -lt .000001) 'Projected map endpoint changed'
}
$w=640;$h=300
foreach($dir in @(-1,1)){
    $from=@(5,(170*$dir));$to=@(35,(-175*$dir));$leg=GetUnifiedGlobeLeg $from $to $w $h
    Check-Map ($leg.ContainsKey('cross') -and [Math]::Abs($leg.cross-2.0/3) -lt .000001) 'Date-line route did not split at the short crossing'
    Check-SamePoint $leg.before (GlobeXY 25 (180*$dir) $w $h)
    Check-SamePoint $leg.after (GlobeXY 25 (-180*$dir) $w $h)
    foreach($fraction in @(0,.1,.4,.64,.67,.8,1)){
        $point=GetUnifiedGlobePacket $leg $fraction
        Check-Map ([Math]::Abs($point[0]-$w/2) -gt $w/3) 'Animated packet crossed the center of a date-line route'
    }
    Check-SamePoint (GetUnifiedGlobePacket $leg 0) (GlobeXY 5 $from[1] $w $h)
    Check-SamePoint (GetUnifiedGlobePacket $leg 1) (GlobeXY 35 $to[1] $w $h)
    foreach($lon in @(170,180)){
        $edge=GetUnifiedGlobeLeg @(15,(180*$dir)) @(30,(-$lon*$dir)) $w $h
        foreach($f in @(0,.1,.9,1)){
            $point=GetUnifiedGlobePacket $edge $f
            Check-Map ([Math]::Abs($point[0]-$w/2) -gt $w/3) 'Exact date-line endpoint moved through the map'
        }
    }
}
$ordinary=GetUnifiedGlobeLeg @(12,17) @(28,50) $w $h
Check-Map (-not $ordinary.ContainsKey('cross')) 'Ordinary route split at the date line'
function ClearUnifiedLiveHTTPS{}
function UnifiedTelemetryBusy{return $false}
function ExpireUnifiedLiveHTTPS{}
function UpdateUnifiedLocation{}
$script:UnifiedRoutePacket=[pscustomobject]@{Visibility='Visible'}
$script:UnifiedRoute=@{segments=@{0=$ordinary};count=1};$script:UnifiedMapPhase=0.0
[void](CancelUnifiedTelemetryRefreshAsync)
Check-Map ($null -eq $script:UnifiedRoute -and $script:UnifiedRoutePacket.Visibility -eq 'Collapsed') 'Cancelled route still owns its packet'
TickUnifiedMapAnimation
Check-Map ($script:UnifiedRoutePacket.Visibility -eq 'Collapsed' -and $null -eq $script:UnifiedRoute) 'Cancelled route still animated before the next refresh'
if(-not $Native){Write-Host 'Passed Windows globe leg, date-line packet and cancellation checks';return}

Add-Type -AssemblyName PresentationFramework
$MapCanvas=[Windows.Controls.Canvas]::new()
$MapCanvas.Width=$w;$MapCanvas.Height=$h
$MapCanvas.Measure([Windows.Size]::new($w,$h));$MapCanvas.Arrange([Windows.Rect]::new(0,0,$w,$h))
function UnifiedLiveHTTPSForID($id){return 0}
function Control($name){return [pscustomobject]@{IsChecked=$false}}
$script:UnifiedLandGeometry=$null;$script:UnifiedGlobeOutlines=@{}
$ids=@(1..10 | ForEach-Object {"node$_"})
$profiles=@(for($i=0;$i -lt $ids.Count;$i++){
    if($i -eq 4){continue}
    [pscustomobject]@{id=$ids[$i];name=$ids[$i];latitude=5+3*$i;longitude=$(if($i%2){-175}else{170});node_kind=$(if($i -eq 2){'external'}else{'router-vpn'});latency_trimmed_mean_ms=0;latency_median_ms=0}
})
$status=@{connected=$true;phase='connected'}
$mh=@{connected=$true;active_node_ids=$ids;active_route_id=('a'*64);actual_entry_id=$ids[0];actual_exit_id=$ids[-1]}
DrawMap $profiles $ids[0] $status $mh
foreach($position in 1,2){
    $dot=@($MapCanvas.Children | Where-Object {$_ -is [Windows.Shapes.Ellipse] -and $_.Tag -ceq $ids[$position]})[0]
    $rim=if($position -eq 2){'#F25BAC'}else{'#EAF3FF'}
    $fill=GetUnifiedGlobeHopColor $position $ids.Count
    Check-Map ($dot.Stroke.Color -eq [Windows.Media.ColorConverter]::ConvertFromString($rim) -and $dot.Fill.Color -eq [Windows.Media.ColorConverter]::ConvertFromString($fill)) 'Native imported/paired marker lost its node kind or hop position'
}
$land=@($MapCanvas.Children | Where-Object {$_.Uid -ceq 'globe-land'})
Check-Map ($land.Count -eq 1 -and $script:UnifiedLandGeometry.IsFrozen) 'Native WPF did not load one frozen land geometry'
$ocean=@($MapCanvas.Children | Where-Object {$_.Uid -ceq 'globe-ocean'})[0]
foreach($lat in -88,-80,-60,0,60,80,88){
    foreach($lon in -179,179){
        $xy=GlobeXY $lat $lon $w $h
        Check-Map ($ocean.Data.FillContains([Windows.Point]::new($xy[0],$xy[1]))) 'Projected world coordinate fell outside the WPF ocean boundary'
    }
}
$pen=[Windows.Media.Pen]::new([Windows.Media.Brushes]::White,1)
foreach($lon in -120,-60,0,60,120){
    $meridian=@($MapCanvas.Children | Where-Object {$_.Uid -ceq "globe-meridian-$lon"})[0]
    foreach($lat in -85,-35,0,35,85){
        $xy=GlobeXY $lat $lon $w $h
        Check-Map ($meridian.Data.StrokeContains($pen,[Windows.Point]::new($xy[0],$xy[1]))) 'WPF meridian missed its projected longitude'
    }
}
foreach($lat in -60,-30,0,30,60){
    $line=@($MapCanvas.Children | Where-Object {$_.Uid -ceq "globe-parallel-$lat"})[0]
    Check-SamePoint @($line.X1,$line.Y1) (GlobeXY $lat -180 $w $h)
    Check-SamePoint @($line.X2,$line.Y2) (GlobeXY $lat 180 $w $h)
}
foreach($fixture in @(@(38,-98,$true),@(0,-140,$false),@(-25,133,$true),@(-25,-110,$false))){
    $xy=GlobeXY $fixture[0] $fixture[1] $w $h
    Check-Map ($land[0].Data.FillContains([Windows.Point]::new($xy[0],$xy[1])) -eq $fixture[2]) 'Native WPF projected land/ocean mismatch'
}
$legs=@($MapCanvas.Children | Where-Object {$_ -is [Windows.Shapes.Line] -and [Windows.Controls.Panel]::GetZIndex($_) -eq 1})
Check-Map ($legs.Count -eq 14 -and $script:UnifiedRoute.count -eq 9 -and -not $script:UnifiedRoute.segments.ContainsKey(3) -and -not $script:UnifiedRoute.segments.ContainsKey(4)) 'Native displayed route collapsed missing nodes, lost a leg or omitted a date-line split'
foreach($line in $legs){Check-Map ([Math]::Abs($line.X1-$line.X2) -lt $w/3) 'Native WPF route line crossed through the map'}
$script:UnifiedMapPhase=3.1;TickUnifiedMapAnimation
Check-Map ($script:UnifiedRoutePacket.Visibility -eq 'Collapsed') 'Native packet skipped a missing route coordinate'
$script:UnifiedMapPhase=2.1;TickUnifiedMapAnimation
Check-Map ($script:UnifiedRoutePacket.Visibility -eq 'Visible' -and [Math]::Abs([Windows.Controls.Canvas]::GetLeft($script:UnifiedRoutePacket)+4-$w/2) -gt $w/3) 'Native packet left its original short leg'
if($RenderPng){
    $MapCanvas.Measure([Windows.Size]::new($w,$h));$MapCanvas.Arrange([Windows.Rect]::new(0,0,$w,$h));$MapCanvas.UpdateLayout()
    $preview=[Windows.Media.Imaging.RenderTargetBitmap]::new($w,$h,96,96,[Windows.Media.PixelFormats]::Pbgra32)
    $preview.Render($MapCanvas)
    $encoder=[Windows.Media.Imaging.PngBitmapEncoder]::new()
    $encoder.Frames.Add([Windows.Media.Imaging.BitmapFrame]::Create($preview))
    $file=[IO.File]::Create($RenderPng)
    try{$encoder.Save($file)}finally{$file.Dispose()}
}
$first=$script:UnifiedLandGeometry
DrawMap @() '' @{connected=$false;phase='off'} $mh
Check-Map ($null -eq $script:UnifiedRoute -and $null -eq $script:UnifiedRoutePacket) 'Disconnected snapshot adopted a previous multihop route'
Check-Map ([object]::ReferenceEquals($first,$script:UnifiedLandGeometry)) 'Redrawing the map rebuilt the bundled land'
Check-Map (@($MapCanvas.Children | Where-Object {$_ -is [Windows.Controls.TextBlock] -and $_.Text -eq 'Map: Natural Earth'}).Count -eq 1) 'Map attribution missing from empty map'
$MapCanvas.Measure([Windows.Size]::new($w,$h));$MapCanvas.Arrange([Windows.Rect]::new(0,0,$w,$h));$MapCanvas.UpdateLayout()
$bitmap=[Windows.Media.Imaging.RenderTargetBitmap]::new($w,$h,96,96,[Windows.Media.PixelFormats]::Pbgra32)
$bitmap.Render($MapCanvas)
foreach($fixture in @(@(38,-98,0x60,0x5B,0x33),@(-25,-110,0x43,0x27,0x10))){
    $xy=GlobeXY $fixture[0] $fixture[1] $w $h
    $pixels=[byte[]]::new(7*7*4);$matchedPixels=0
    $bitmap.CopyPixels([Windows.Int32Rect]::new([int]$xy[0]-3,[int]$xy[1]-3,7,7),$pixels,28,0)
    for($i=0;$i -lt $pixels.Length;$i+=4){
        if($pixels[$i] -eq $fixture[2] -and $pixels[$i+1] -eq $fixture[3] -and $pixels[$i+2] -eq $fixture[4] -and $pixels[$i+3] -eq 255){$matchedPixels++}
    }
    Check-Map ($matchedPixels -ge 12) 'WPF bitmap omitted visible land or ocean at its projected location'
}
Write-Host 'Passed Windows WPF land, ocean, original ordered route, date-line rendering, caching and cancellation checks'
