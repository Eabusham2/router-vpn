#!/usr/bin/env python3
"""Small progressive-enhancement patch for Setup Center download/method UX."""

UX_PATCH = r'''
<style>
/* Unified Map Control Center non-blocking overlay contract. */
.overlay[hidden],.wizard-overlay[hidden],[data-routervpn-overlay][hidden]{display:none!important;pointer-events:none!important}
.overlay:not([hidden]),.wizard-overlay:not([hidden]),[data-routervpn-overlay]:not([hidden]){pointer-events:auto}
@media(max-width:820px){.wizard,.overlay>*,.wizard-overlay>*{max-height:calc(100dvh - 24px);overflow:auto}.rvpn-primary-controls{position:relative;z-index:3}}
</style>

<style>
/* Shipping Setup Center accessibility/responsive overrides. This patch is inserted after the generated base CSS. */
.tabs button,.btn,button{appearance:none}
.tabs button:focus-visible,.btn:focus-visible,button:focus-visible,select:focus-visible,input:focus-visible{outline:3px solid #69d2ff;outline-offset:2px}
.tabs button:disabled,.btn:disabled,button:disabled{opacity:.55;cursor:not-allowed}
@media(max-width:820px){.tabs button{flex:1 1 130px}.download .btn{width:100%;text-align:center}.wizard{padding:15px;max-height:calc(100vh - 24px)}}
#rvpn-device-download{position:fixed;left:128px;bottom:22px;z-index:998;border:1px solid #334155;border-radius:14px;padding:10px 14px;background:#0f766e;color:white;font:700 14px system-ui;cursor:pointer;box-shadow:0 14px 40px #0006}
#rvpn-device-download[disabled]{opacity:.55;cursor:not-allowed}
#rvpn-device-download-note{position:fixed;left:22px;bottom:72px;z-index:997;max-width:460px;background:#111827;color:#e2e8f0;border:1px solid #334155;border-radius:12px;padding:9px 12px;font:12px/1.4 system-ui;display:none}
#rvpn-download-job{position:fixed;left:22px;bottom:22px;z-index:1002;width:min(520px,calc(100vw - 44px));max-height:calc(100vh - 44px);overflow:auto;background:#101827;color:#f8fafc;border:1px solid #334155;border-radius:16px;padding:14px;box-shadow:0 20px 70px #0009;font:13px/1.4 system-ui;display:none}
#rvpn-download-job .rvpn-job-head{display:flex;gap:10px;align-items:flex-start;justify-content:space-between}#rvpn-download-job .rvpn-job-title{font-weight:800;overflow-wrap:anywhere}#rvpn-download-job .rvpn-job-track{height:9px;border-radius:999px;background:#25334a;overflow:hidden;margin:10px 0}#rvpn-download-job .rvpn-job-fill{height:100%;width:0;background:#22c55e;transition:width .2s ease}#rvpn-download-job .rvpn-job-meta{color:#a9b6cc;font-size:12px;overflow-wrap:anywhere}#rvpn-download-job .rvpn-job-history{margin-top:7px;color:#94a3b8;font-size:11px;overflow-wrap:anywhere}#rvpn-download-job .rvpn-job-actions{display:flex;gap:8px;flex-wrap:wrap;margin-top:10px}#rvpn-download-job button{border:1px solid #475569;border-radius:9px;padding:7px 10px;background:#172033;color:#f8fafc;cursor:pointer}#rvpn-download-job button.rvpn-cancel{border-color:#7f1d1d;background:#3f151b}#rvpn-download-job button:disabled{opacity:.5;cursor:not-allowed}
@media(max-width:560px){#rvpn-device-download{left:12px;right:12px;bottom:calc(12px + env(safe-area-inset-bottom));width:auto;max-width:none;text-align:center}#rvpn-device-download-note{left:12px;right:12px;bottom:calc(64px + env(safe-area-inset-bottom));max-width:none}#rvpn-download-job{left:12px;right:12px;bottom:calc(12px + env(safe-area-inset-bottom));width:auto;max-height:calc(100vh - 24px - env(safe-area-inset-bottom))}}
</style>
<button id="rvpn-device-download" type="button">Download for this device</button>
<div id="rvpn-device-download-note" role="status"></div>
<div id="rvpn-download-job" role="status" aria-live="polite">
  <div class="rvpn-job-head"><div><div class="rvpn-job-title" id="rvpn-job-title">Preparing download</div><div class="rvpn-job-meta" id="rvpn-job-phase">Queued</div></div><button id="rvpn-job-close" type="button" aria-label="Hide download progress">×</button></div>
  <div class="rvpn-job-track"><div class="rvpn-job-fill" id="rvpn-job-fill"></div></div>
  <div class="rvpn-job-meta" id="rvpn-job-meta"></div>
  <div class="rvpn-job-history" id="rvpn-job-history"></div>
  <div class="rvpn-job-actions"><button id="rvpn-job-cancel" class="rvpn-cancel" type="button">Cancel</button><button id="rvpn-job-retry" type="button" style="display:none">Retry</button></div>
</div>
<iframe id="rvpn-job-download-frame" title="Router VPN package download" hidden></iframe>
<script>
(async()=>{
 const btn=document.getElementById('rvpn-device-download'),note=document.getElementById('rvpn-device-download-note');
 const panel=document.getElementById('rvpn-download-job'),title=document.getElementById('rvpn-job-title'),phase=document.getElementById('rvpn-job-phase'),fill=document.getElementById('rvpn-job-fill'),meta=document.getElementById('rvpn-job-meta'),history=document.getElementById('rvpn-job-history'),cancel=document.getElementById('rvpn-job-cancel'),retry=document.getElementById('rvpn-job-retry'),close=document.getElementById('rvpn-job-close'),frame=document.getElementById('rvpn-job-download-frame');
 const ua=(navigator.userAgent||'').toLowerCase(),plat=(navigator.platform||'').toLowerCase();
 let arch=/arm64|aarch64|\barm\b/.test(ua+' '+plat)?'arm64':(/x86_64|amd64|x64|win64/.test(ua+' '+plat)?'amd64':'unknown');
 if(navigator.userAgentData&&navigator.userAgentData.getHighEntropyValues){try{const h=await navigator.userAgentData.getHighEntropyValues(['architecture','bitness']);const a=String(h.architecture||'').toLowerCase();if(/arm/.test(a))arch='arm64';else if(/x86/.test(a)&&String(h.bitness||'')==='64')arch='amd64'}catch(_){}}
 const isArm=arch==='arm64';
 const persistedJobKey='routervpn.setup.download-job.v2';
 let family='unknown',active=null,pollTimer=0,lastRequest=null,downloadStarted=false;
 if(/android/.test(ua))family='android';
 else if(/iphone|ipad|ipod/.test(ua)||(/mac/.test(plat)&&navigator.maxTouchPoints>1))family='ios';
 else if(/win/.test(plat+ua))family='windows';
 else if(/mac/.test(plat+ua))family='macos';
 else if(/linux|x11/.test(plat+ua))family='linux';
 const aliases={windows:['windows','win'],macos:['macos','darwin','mac'],linux:['linux'],android:['android','.apk'],ios:['ios','ipad','iphone','.ipa']};
 function candidates(){return [...document.querySelectorAll('a[href]')].filter(a=>{const s=(a.textContent+' '+a.getAttribute('href')).toLowerCase();return (aliases[family]||[]).some(x=>s.includes(x))&&/download|\.zip|\.tar\.gz|\.apk|\.ipa|package|installer/.test(s)})}
 function score(a){const s=(a.textContent+' '+a.getAttribute('href')).toLowerCase();let n=0;if(/native|router vpn app|installer/.test(s))n+=8;if(isArm&&/arm64|aarch64/.test(s))n+=6;if(!isArm&&/amd64|x86_64|x64/.test(s))n+=6;if(/portable/.test(s))n-=2;if(/all.platform|bundle/.test(s))n-=5;return n}
 function best(){if(['windows','macos','linux'].includes(family)&&arch==='unknown')return null;return candidates().sort((a,b)=>score(b)-score(a))[0]||null}
 function packageName(a){try{const u=new URL(a.href,location.href);if(u.origin!==location.origin)return'';const name=decodeURIComponent(u.pathname.split('/').pop()||'');return /\.(zip|apk|ipa|tar\.gz|tar\.xz|deb|rpm|pkg|dmg|exe|msi)$/i.test(name)?name:''}catch(_){return''}}
 function fmtBytes(n){n=Number(n||0);if(!n)return'0 B';const units=['B','KiB','MiB','GiB'];let i=0;while(n>=1024&&i<units.length-1){n/=1024;i++}return `${n.toFixed(i?1:0)} ${units[i]}`}
 function labelPhase(p){return String(p||'queued').split('-').map(x=>x?x[0].toUpperCase()+x.slice(1):x).join(' ')}
 function terminal(j){return ['failed','cancelled','delivered','delivery-interrupted','expired'].includes(j.status)}
 function safeSameOriginPath(value,prefix){try{const u=new URL(String(value||''),location.href);return u.origin===location.origin&&u.pathname.startsWith(prefix)?u.pathname+u.search:''}catch(_){return''}}
 function persistActive(){try{if(!active||terminal(active)){sessionStorage.removeItem(persistedJobKey);return}const status=safeSameOriginPath(active.status_url,'/api/download-jobs/');if(!status){sessionStorage.removeItem(persistedJobKey);return}sessionStorage.setItem(persistedJobKey,JSON.stringify({status_url:status,name:active.name||'',direct_href:safeSameOriginPath(lastRequest&&lastRequest.directHref,'/'),saved_at:Date.now()}))}catch(_){}}
 function clearPersisted(){try{sessionStorage.removeItem(persistedJobKey)}catch(_){}}
 function render(j){
   active=j;panel.style.display='block';title.textContent=j.name||'Router VPN package';phase.textContent=`${labelPhase(j.phase)} • ${Math.max(0,Math.min(100,Number(j.progress||0)))}%`;fill.style.width=`${Math.max(0,Math.min(100,Number(j.progress||0)))}%`;
   const bytes=Number(j.bytes_total||0)?`${fmtBytes(j.bytes_sent||0)} / ${fmtBytes(j.bytes_total||0)}`:(Number(j.size||0)?fmtBytes(j.size):'size pending');
   meta.textContent=[j.source?`Source: ${j.source}`:'',bytes,j.error?`Error: ${j.error}`:''].filter(Boolean).join(' • ');
   history.textContent=`Lifecycle: ${(j.phase_history||[]).map(labelPhase).join(' → ')||labelPhase(j.phase)}`;
   cancel.disabled=terminal(j)||j.status==='delivered';cancel.style.display=terminal(j)?'none':'';retry.style.display=(j.status==='failed'||j.status==='cancelled'||j.status==='delivery-interrupted'||j.status==='expired')?'':'none';
   if(terminal(j))clearPersisted();else persistActive();
 }
 async function json(path,opt={}){const safe=safeSameOriginPath(path,'/api/');if(!safe)throw new Error('Refused a non-local Setup Center job URL');const r=await fetch(safe,{credentials:'same-origin',cache:'no-store',redirect:'error',...opt});let d={};try{d=await r.json()}catch{}if(!r.ok||d.ok===false)throw new Error(d.error||`HTTP ${r.status}`);return d}
 function stopPoll(){if(pollTimer){clearTimeout(pollTimer);pollTimer=0}}
 function schedulePoll(delay){stopPoll();pollTimer=setTimeout(poll,document.hidden?Math.max(delay,1600):delay)}
 async function poll(){
   if(!active||!active.status_url)return;
   try{
     const d=await json(active.status_url),j=d.job;render(j);
     if(j.status==='ready'&&!downloadStarted&&j.download_url){const download=safeSameOriginPath(j.download_url,'/api/download-jobs/');if(!download){phase.textContent='The job returned an unsafe download URL and was not opened.'}else{downloadStarted=true;frame.src=download;phase.textContent='Browser download requested. Setup Center will not claim delivery until the server confirms it.'}}
     if(!terminal(j))schedulePoll(500)
   }catch(e){phase.textContent=navigator.onLine?`Progress check failed: ${e.message}`:'Offline. The authenticated download job will resume when this device reconnects.';persistActive();schedulePoll(1200)}
 }
 async function startJob(name,directHref){
   stopPoll();downloadStarted=false;lastRequest={name,directHref};panel.style.display='block';title.textContent=name;phase.textContent='Creating authenticated download job…';fill.style.width='0%';meta.textContent='';history.textContent='';cancel.style.display='';cancel.disabled=true;retry.style.display='none';
   try{
     const d=await json('/api/download-jobs',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});render(d.job);persistActive();poll();
   }catch(e){
     // Static helpers/private profile links are intentionally not async jobs. If
     // a future package link is not in the broker allow-list, preserve its exact
     // same-origin download instead of manufacturing a different package.
     phase.textContent=`Async package job unavailable: ${e.message}`;meta.textContent='Using the exact original Setup Center link.';retry.style.display='';
     if(directHref)setTimeout(()=>{location.href=directHref},250);
   }
 }
 const found=best();
 if(found){btn.dataset.href=found.href;btn.title=`Detected ${family}${arch==='arm64'?' ARM64':arch==='amd64'?' x64':''}; uses the best matching generic/native Setup Center package link with real job progress.`}
 else if(['windows','macos','linux'].includes(family)&&arch==='unknown'){btn.title=`Detected ${family}, but CPU architecture is not safely exposed by this browser. Choose the x64/Intel or ARM64/Apple Silicon package explicitly.`}
 else{btn.title='No matching platform package link is currently published by this node.'}
 btn.addEventListener('click',()=>{const a=best();if(a){const name=packageName(a);if(name){startJob(name,a.href);return}a.click();return}note.textContent=(['windows','macos','linux'].includes(family)&&arch==='unknown')?`Detected ${family}, but this browser does not safely reveal whether the CPU is x64/Intel or ARM64/Apple Silicon. Choose the matching platform package below; Router VPN will not guess the wrong architecture.`:`No ${family==='unknown'?'detected-platform':family} package is currently published. Keep this Setup Center open and use the platform package/download section or retry after the node finishes publishing artifacts.`;note.style.display='block';setTimeout(()=>note.style.display='none',7000)});
 document.addEventListener('click',e=>{const a=e.target&&e.target.closest?e.target.closest('a[href]'):null;if(!a)return;const name=packageName(a);if(!name)return;e.preventDefault();startJob(name,a.href)},true);
 cancel.addEventListener('click',async()=>{if(!active||!active.status_url)return;cancel.disabled=true;phase.textContent='Cancellation requested…';try{const d=await json(active.status_url,{method:'DELETE'});render(d.job);if(!terminal(d.job))poll()}catch(e){phase.textContent=`Cancel failed: ${e.message}`;cancel.disabled=false}});
 retry.addEventListener('click',()=>{if(lastRequest)startJob(lastRequest.name,lastRequest.directHref)});
 close.addEventListener('click',()=>{panel.style.display='none'});
 frame.addEventListener('load',()=>{if(active&&!terminal(active)){phase.textContent='The browser accepted the download request; waiting for server delivery confirmation…';persistActive()}});
 document.addEventListener('visibilitychange',()=>{if(active&&!terminal(active)&&!document.hidden)schedulePoll(0)});
 window.addEventListener('online',()=>{if(active&&!terminal(active)){phase.textContent='Back online; resuming authenticated download progress…';schedulePoll(0)}});
 window.addEventListener('offline',()=>{if(active&&!terminal(active)){stopPoll();phase.textContent='Offline. The authenticated download job is preserved for this tab.';persistActive()}});
 try{const saved=JSON.parse(sessionStorage.getItem(persistedJobKey)||'null');const status=safeSameOriginPath(saved&&saved.status_url,'/api/download-jobs/');if(status&&Date.now()-Number(saved.saved_at||0)<6*60*60*1000){active={status_url:status,name:String(saved.name||'Router VPN package')};const direct=safeSameOriginPath(saved&&saved.direct_href,'/');lastRequest={name:active.name,directHref:direct||''};panel.style.display='block';title.textContent=active.name;phase.textContent='Resuming authenticated download job…';poll()}else clearPersisted()}catch(_){clearPersisted()}

 // A method with a missing prerequisite is still a method, not a reason to hide
 // the entire lane. Keep SOCKS5, OverTLS and Shadowsocks cards/details expanded
 // when their current content says no servers were found, and make the reason
 // visibly actionable while leaving actual Connect/Download controls disabled by
 // their own existing capability checks.
 const methodNames=['socks5','overtls','over tls','shadowsocks'];
 for(const container of document.querySelectorAll('details,section,article,.card,.method,.setup-method')){
   const text=(container.textContent||'').toLowerCase();
   if(!methodNames.some(n=>text.includes(n))||!text.includes('no servers found'))continue;
   if(container.tagName==='DETAILS')container.open=true;
   container.dataset.routerVpnNoServers='open';
   if(!container.querySelector('.rvpn-no-server-help')){
     const msg=document.createElement('div');msg.className='rvpn-no-server-help';msg.style.cssText='margin:8px 0;padding:9px 10px;border-left:3px solid #f59e0b;background:#3a2a12;border-radius:7px;color:#fde68a;font:12px/1.4 system-ui';
     msg.textContent='No server/config is currently published for this method. The method stays open: check node health/finalization and its generated method prerequisites, then refresh. Router VPN will not substitute a different protocol and call it ready.';
     container.appendChild(msg);
   }
 }
})();
</script>
'''