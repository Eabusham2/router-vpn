#!/usr/bin/env python3
"""Small progressive-enhancement patch for Setup Center download/method UX."""

UX_PATCH = r'''
<style>
#rvpn-device-download{position:fixed;left:128px;bottom:22px;z-index:998;border:1px solid #334155;border-radius:14px;padding:10px 14px;background:#0f766e;color:white;font:700 14px system-ui;cursor:pointer;box-shadow:0 14px 40px #0006}
#rvpn-device-download[disabled]{opacity:.55;cursor:not-allowed}
#rvpn-device-download-note{position:fixed;left:22px;bottom:72px;z-index:997;max-width:460px;background:#111827;color:#e2e8f0;border:1px solid #334155;border-radius:12px;padding:9px 12px;font:12px/1.4 system-ui;display:none}
</style>
<button id="rvpn-device-download" type="button">Download for this device</button>
<div id="rvpn-device-download-note" role="status"></div>
<script>
(()=>{
 const btn=document.getElementById('rvpn-device-download'),note=document.getElementById('rvpn-device-download-note');
 const ua=(navigator.userAgent||'').toLowerCase(),plat=(navigator.platform||'').toLowerCase();
 const isArm=/arm|aarch64/.test(ua+' '+plat)||(navigator.userAgentData&&navigator.userAgentData.architecture==='arm');
 let family='unknown';
 if(/android/.test(ua))family='android';
 else if(/iphone|ipad|ipod/.test(ua)||(/mac/.test(plat)&&navigator.maxTouchPoints>1))family='ios';
 else if(/win/.test(plat+ua))family='windows';
 else if(/mac/.test(plat+ua))family='macos';
 else if(/linux|x11/.test(plat+ua))family='linux';
 const aliases={windows:['windows','win'],macos:['macos','darwin','mac'],linux:['linux'],android:['android','.apk'],ios:['ios','ipad','iphone','.ipa']};
 function candidates(){return [...document.querySelectorAll('a[href]')].filter(a=>{const s=(a.textContent+' '+a.getAttribute('href')).toLowerCase();return (aliases[family]||[]).some(x=>s.includes(x))&&/download|\.zip|\.tar\.gz|\.apk|\.ipa|package|installer/.test(s)})}
 function score(a){const s=(a.textContent+' '+a.getAttribute('href')).toLowerCase();let n=0;if(/native|router vpn app|installer/.test(s))n+=8;if(isArm&&/arm64|aarch64/.test(s))n+=6;if(!isArm&&/amd64|x86_64|x64/.test(s))n+=6;if(/portable/.test(s))n-=2;if(/all.platform|bundle/.test(s))n-=5;return n}
 function best(){return candidates().sort((a,b)=>score(b)-score(a))[0]||null}
 const found=best();
 if(found){btn.dataset.href=found.href;btn.title=`Detected ${family}${isArm?' ARM64':''}; uses the best matching generic/native Setup Center package link.`}
 else{btn.title='No matching platform package link is currently published by this node.'}
 btn.addEventListener('click',()=>{const a=best();if(a){a.click();return}note.textContent=`No ${family==='unknown'?'detected-platform':family} package is currently published. Keep this Setup Center open and use the platform package/download section or retry after the node finishes publishing artifacts.`;note.style.display='block';setTimeout(()=>note.style.display='none',7000)});

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
