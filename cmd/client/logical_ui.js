(() => {
  let rawModeData = [];

  const rawLayers = () => rawModeData;
  const modeByLogicalID = id => (modeData || []).find(x => x.id === id) || null;
  const baseLabel = base => base === 'awg' ? 'AmneziaWG' : base === 'wg' ? 'WireGuard' : 'Auto';
  const runtimeLabel = id => {
    for (const logical of modeData || []) {
      for (const [base, variant] of Object.entries(logical.variants || {})) {
        if (variant.runtime_id === id) return `${logical.name}${base === 'native' ? '' : ` · ${baseLabel(base)}`}`;
      }
    }
    return id || 'CONNECTED';
  };

  function ensureBasePicker() {
    if (document.getElementById('modeBase')) return;
    const picker = document.createElement('select');
    picker.id = 'modeBase';
    picker.className = 'medium';
    picker.innerHTML = '<option value="auto">Base: Auto (preferred + fallback)</option><option value="wg">Base: WireGuard</option><option value="awg">Base: AmneziaWG</option>';
    picker.addEventListener('change', renderModeBaseState);
    mode.insertAdjacentElement('afterend', picker);
    const note = document.createElement('div');
    note.id = 'modeBaseState';
    note.className = 'small';
    mode.closest('.row').insertAdjacentElement('afterend', note);
    mode.addEventListener('change', renderModeBaseState);
  }

  function readyText(logical) {
    if (!logical) return '';
    if (!logical.base_selector) return logical.available ? 'Ready' : (logical.reason || 'Unavailable');
    const entries = ['wg', 'awg'].map(base => {
      const v = logical.variants?.[base];
      if (!v) return null;
      return `${baseLabel(base)}: ${v.available ? 'ready' : (v.reason || 'unavailable')}`;
    }).filter(Boolean);
    return entries.join(' • ');
  }

  function renderModeBaseState() {
    ensureBasePicker();
    const logical = modeByLogicalID(mode.value);
    const picker = document.getElementById('modeBase');
    const state = document.getElementById('modeBaseState');
    if (!logical) {
      picker.hidden = true;
      state.textContent = '';
      return;
    }
    picker.hidden = !logical.base_selector;
    if (logical.base_selector) {
      const saved = currentProfile()?.base_tunnel || 'wg';
      if (!picker.dataset.touched) picker.value = 'auto';
      const preferred = picker.value === 'auto' ? (logical.preferred_base || saved || 'wg') : picker.value;
      const selected = logical.variants?.[preferred];
      let text = `Auto preference: ${baseLabel(preferred)}.`;
      if (picker.value !== 'auto') text = `Selected base: ${baseLabel(picker.value)}.`;
      if (logical.fallback) text += ' If that compatible base is unavailable, Router VPN tries the other base.';
      if (selected && !selected.available && logical.available) text += ` ${baseLabel(preferred)} is unavailable right now; fallback is ready.`;
      state.innerHTML = `${escapeHtml(text)}<br><span class="${logical.available ? 'ok' : 'bad'}">${escapeHtml(readyText(logical))}</span>`;
    } else {
      state.innerHTML = `<span class="${logical.available ? 'ok' : 'bad'}">${escapeHtml(readyText(logical))}</span>`;
    }
  }

  function aggregateLayers(logical) {
    const all = [];
    for (const variant of Object.values(logical.variants || {})) {
      for (const layer of variant.mode?.layers || []) if (!all.includes(layer)) all.push(layer);
    }
    return all;
  }

  window.renderLayers = function renderLayersLogical() {
    const ignore = new Set(['tcp','https','protocol-split','quic-udp-fallback','udp-over-tcp','health-fallback','pq-max-tls','pq-max-quic']);
    const unique = [...new Set(rawLayers().flatMap(x => x.layers || []).filter(x => !ignore.has(x)))].sort((a,b)=>(layerLabels[a]||a).localeCompare(layerLabels[b]||b));
    customlayers.innerHTML = unique.map(x => `<label class="layer"><input type="checkbox" value="${x}"> ${layerLabels[x]||x}</label>`).join('');
    fillCustomSelections(currentProfile());
  };

  window.reloadModes = async function reloadLogicalModes() {
    try {
      [modeData, rawModeData] = await Promise.all([j('/api/logical-modes'), j('/api/modes')]);
      ensureBasePicker();
      const previous = mode.value;
      mode.innerHTML = '';
      for (const x of modeData) {
        const o = document.createElement('option');
        o.value = x.id;
        o.disabled = !x.available;
        o.textContent = x.name + (x.available ? '' : ' — unavailable');
        mode.appendChild(o);
      }
      if ([...mode.options].some(x => x.value === previous && !x.disabled)) mode.value = previous;
      else if ([...mode.options].some(x => x.value === 'base-raw' && !x.disabled)) mode.value = 'base-raw';

      modes.innerHTML = modeData.map(x => {
        const layers = aggregateLayers(x).map(y => escapeHtml(layerLabels[y] || y)).join(' → ');
        const base = x.base_selector
          ? `<div class="small">${escapeHtml(readyText(x))}</div>`
          : '';
        const status = x.available
          ? `<span class="ok">✓ ready</span>${x.reason ? `<div class="small warn">${escapeHtml(x.reason)}</div>` : ''}`
          : `<span class="bad">— ${escapeHtml(x.reason || 'unavailable')}</span>`;
        return `<tr><td><b>${escapeHtml(x.name)}</b><div class="small">${escapeHtml(x.description || '')}</div></td><td>${layers}${base}</td><td>${x.ping_min_ms}–${x.ping_max_ms} ms</td><td>+${x.traffic_min_pct}–${x.traffic_max_pct}%</td><td>-${x.speed_loss_min_pct}–${x.speed_loss_max_pct}%</td><td>${status}</td></tr>`;
      }).join('');
      renderLayers();
      renderModeBaseState();
    } catch (e) {
      toast('Logical mode check failed: ' + e.message, true);
    }
  };

  window.quickConnect = async function quickConnectLogical(id) {
    const aliases = {wg:'base-raw','awg2-fast':'base-raw','wg-pq':'base-pq','awg2-pq':'base-pq','max-quic-wg':'max-quic','max-quic-awg':'max-quic','max-tls-wg':'max-tls','max-tls-awg':'max-tls'};
    mode.value = aliases[id] || id;
    renderModeBaseState();
    await connectMode();
  };

  window.connectMode = async function connectLogicalMode() {
    const logical = modeByLogicalID(mode.value);
    if (!logical) return toast('Choose a mode first', true);
    const picker = document.getElementById('modeBase');
    const base = logical.base_selector ? (picker?.value || 'auto') : 'auto';
    try {
      const result = await post('/api/connect-logical', {mode: logical.id, base});
      const fallback = result.fallback_used ? ' (fallback)' : '';
      toast(`${logical.name} connected · ${baseLabel(result.base)}${fallback}`);
      setTimeout(refreshPublicIP, 1200);
    } catch (_) {}
  };

  const oldRefresh = window.refresh;
  window.refresh = async function refreshLogicalState() {
    await oldRefresh();
    try {
      const s = lastStatus;
      if (!s?.connected) return;
      const logical = s.logical_mode || '';
      const runtime = s.runtime_mode || s.mode || '';
      const label = logical ? (modeByLogicalID(logical)?.name || logical) : runtimeLabel(runtime);
      const base = s.base && s.base !== 'native' ? ` · ${baseLabel(s.base)}` : '';
      connChip.textContent = label + base;
      const p = currentProfile();
      routeInfo.innerHTML = `Connected to <b>${escapeHtml(p?.name || 'router')}</b> using <b>${escapeHtml(label + base)}</b>.<br><span class="small">Runtime: ${escapeHtml(runtime)} • Endpoint: ${escapeHtml(p?.endpoint || '')} • DNS: ${escapeHtml(dnsDisplay(p))}</span>`;
    } catch (_) {}
  };

  const basePickerTouch = () => {
    const picker = document.getElementById('modeBase');
    if (picker) picker.dataset.touched = '1';
  };
  document.addEventListener('change', e => { if (e.target?.id === 'modeBase') basePickerTouch(); });

  // ----- Product state layer: typed session visibility -----
  function ensureSessionPanel() {
    if (document.getElementById('typedSessionPanel')) return;
    const page = document.querySelector('[data-page="connect"]');
    const hero = page?.querySelector('.card.hero');
    if (!hero) return;
    const card = document.createElement('div');
    card.id = 'typedSessionPanel';
    card.className = 'card';
    card.innerHTML = '<div class="row"><div class="grow"><h3 style="margin:0">Connection validation</h3><div class="small">Requested mode → actual runtime, selected-node path proof, rollback and typed errors.</div></div><span id="typedSessionPhase" class="chip">off</span></div><div id="typedSessionBody" class="small">No connection session yet.</div><details style="margin-top:10px"><summary>Recent connection events</summary><div id="typedSessionEvents" class="small"></div></details>';
    hero.insertAdjacentElement('afterend', card);
  }

  function phaseClass(phase, connected) {
    if (connected && phase === 'connected') return 'chip ok';
    if (phase === 'failed') return 'chip bad';
    if (phase === 'checking' || phase === 'starting' || String(phase).startsWith('auto:')) return 'chip info';
    return 'chip';
  }

  async function refreshTypedSession() {
    ensureSessionPanel();
    try {
      const s = await j('/api/session');
      const chip = document.getElementById('typedSessionPhase');
      const body = document.getElementById('typedSessionBody');
      const events = document.getElementById('typedSessionEvents');
      if (!chip || !body || !events) return;
      chip.textContent = s.phase || 'off';
      chip.className = phaseClass(s.phase, s.connected);
      const requested = [s.requested_mode, s.requested_base].filter(Boolean).join(' · ') || '—';
      const actual = [s.actual_mode, s.actual_base].filter(Boolean).join(' · ') || '—';
      const proofClass = s.path_proof === 'passed' ? 'ok' : s.path_proof === 'failed' ? 'bad' : 'warn';
      const dnsProof = s.dns_proof || {};
      const err = s.error ? `<div class="notice warn" style="margin-top:9px"><b>${escapeHtml(s.error.code || 'connection_failed')}</b> — ${escapeHtml(s.error.message || '')}<br><span class="small">Retryable: ${s.error.retryable ? 'yes' : 'no'}</span></div>` : '';
      body.innerHTML = `<div class="grid3"><div class="metric"><span class="small">Requested</span><b>${escapeHtml(requested)}</b></div><div class="metric"><span class="small">Actual runtime</span><b>${escapeHtml(actual)}</b><span class="small">${escapeHtml(s.engine || '')}</span></div><div class="metric"><span class="small">Selected-node path proof</span><b class="${proofClass}">${escapeHtml(s.path_proof || 'not-run')}</b></div><div class="metric"><span class="small">Rollback</span><b>${escapeHtml(s.rollback_state || 'not-needed')}</b></div><div class="metric"><span class="small">Public exit</span><b>${escapeHtml(s.exit_ip || 'not verified')}</b></div><div class="metric"><span class="small">DNS proof</span><b class="${dnsProof.status === 'proven' ? 'ok' : 'warn'}">${escapeHtml(dnsProof.status || 'not-proven')}</b><span class="small">${escapeHtml(dnsProof.reason || dnsProof.host || '')}</span></div></div>${err}`;
      const recent = [...(s.events || [])].slice(-8).reverse();
      events.innerHTML = recent.length ? recent.map(e => `<div style="padding:6px 0;border-bottom:1px solid var(--line)"><b>${escapeHtml(e.phase || e.type)}</b> · ${escapeHtml(e.message || e.type || '')}<br><span class="small">${escapeHtml(e.at || '')}${e.runtime_mode ? ' · '+escapeHtml(e.runtime_mode) : ''}</span></div>`).join('') : '<div class="small">No events yet.</div>';
    } catch (_) {}
  }

  // ----- Versioned onboarding mirror/reopen state -----
  const ONBOARDING_STATE_V1 = 'routervpn.onboarding.state.v1';
  const onboardingNames = ['welcome','link-node','native-permission','forwarding','forwarding','link-node','native-permission','dns','mode-and-base','public-exit-test','forwarding','select-node','privacy-security','finish'];
  function readOnboardingState() {
    try {
      const x = JSON.parse(localStorage.getItem(ONBOARDING_STATE_V1) || '{}');
      return x && x.schema_version === 1 ? x : {};
    } catch (_) { return {}; }
  }
  function mirrorOnboarding({reopened=false, completed=false}={}) {
    try {
      const now = new Date().toISOString();
      const old = readOnboardingState();
      const idx = Math.max(0, Math.min(Number(window.onboardingStep ?? onboardingStep ?? 0), onboardingNames.length - 1));
      const done = [...new Set(onboardingNames.slice(0, idx))];
      const state = {
        schema_version: 1,
        completed: completed || localStorage.getItem(ONBOARDING_DONE) === '1',
        current_step: (completed || localStorage.getItem(ONBOARDING_DONE) === '1') ? 'finish' : onboardingNames[idx],
        completed_steps: completed ? [...new Set(onboardingNames)] : done,
        started_at: old.started_at || now,
        updated_at: now,
        completed_at: completed ? now : (old.completed_at || ''),
        last_reopened_at: reopened ? now : (old.last_reopened_at || '')
      };
      localStorage.setItem(ONBOARDING_STATE_V1, JSON.stringify(state));
    } catch (_) {}
  }
  try {
    const originalStartOnboarding = window.startOnboarding;
    const originalRenderOnboarding = window.renderOnboarding;
    const originalAction = window.onboardingAction;
    const originalBack = window.onboardingBack;
    if (typeof originalStartOnboarding === 'function') window.startOnboarding = function(force=false){mirrorOnboarding({reopened:!!force});return originalStartOnboarding(force)};
    if (typeof originalRenderOnboarding === 'function') window.renderOnboarding = function(){const out=originalRenderOnboarding();mirrorOnboarding();return out};
    if (typeof originalAction === 'function') window.onboardingAction = function(){const wasLast=onboardingStep===onboardingSteps.length-1;const out=originalAction();mirrorOnboarding({completed:wasLast});return out};
    if (typeof originalBack === 'function') window.onboardingBack = function(){const out=originalBack();mirrorOnboarding();return out};
  } catch (_) {}

  // ----- Cross-platform policy intent/readiness panel -----
  function ensurePolicyPanel() {
    if (document.getElementById('nodePolicyPanel')) return;
    const page = document.querySelector('[data-page="nodes"]');
    if (!page) return;
    const card = document.createElement('div');
    card.id = 'nodePolicyPanel';
    card.className = 'card';
    card.innerHTML = `<h3>Cross-platform policy intent</h3><div class="notice warn">These values are versioned and preserved across clients. A stored value is <b>not</b> proof that this platform currently enforces it; live enforcement stays unavailable until its runtime adapter passes end-to-end tests.</div><div class="grid3" style="margin-top:12px"><label>Kill switch policy<br><select id="policyKill"><option value="off">Off</option><option value="on-connect">On connect (desired)</option><option value="always">Always (desired)</option></select></label><label>IPv6 policy<br><select id="policyIPv6"><option value="auto">Auto</option><option value="on">On</option><option value="off">Off</option></select></label><label>Startup mode<br><select id="policyStartup"><option value="manual">Manual</option><option value="auto">AUTO</option><option value="smart-auto">SMART AUTO</option><option value="last">Last mode</option></select></label><label>MTU policy<br><select id="policyMTU"><option value="default">Default</option><option value="auto">Auto desired</option><option value="manual">Manual desired</option></select></label><label>Manual MTU<br><input id="policyManualMTU" type="number" min="576" max="9000" placeholder="e.g. 1380"></label><label>Diagnostics retention days<br><input id="policyRetention" type="number" min="1" max="365" value="7"></label></div><div class="row"><label class="layer"><input id="policyLAN" type="checkbox"> Allow home LAN while connected</label><label class="layer"><input id="policyDiag" type="checkbox"> Local diagnostics</label><label class="layer"><input id="policyShareDiag" type="checkbox"> Share diagnostics only when explicitly requested</label><label class="layer"><input id="policyTelemetry" type="checkbox"> Telemetry opt-in</label></div><div class="row"><button class="primary" onclick="saveCrossPlatformPolicy()">Save policy intent</button><span id="policyReadiness" class="small warn">Kill-switch, MTU auto-apply and startup automation are not claimed as runtime-enforced here yet.</span></div>`;
    const addEdit = [...page.querySelectorAll('.card')].find(x => x.querySelector('#pname'));
    if (addEdit) addEdit.insertAdjacentElement('afterend', card); else page.appendChild(card);
  }

  function populatePolicyPanel() {
    ensurePolicyPanel();
    const p = currentProfile() || {};
    const byId = id => document.getElementById(id);
    if (!byId('policyKill')) return;
    byId('policyKill').value = p.kill_switch_policy || (p.kill_switch ? 'on-connect' : 'off');
    byId('policyIPv6').value = p.ipv6_mode || 'auto';
    byId('policyStartup').value = p.startup_mode || 'manual';
    byId('policyMTU').value = p.mtu_policy || 'default';
    byId('policyManualMTU').value = p.manual_mtu || '';
    byId('policyRetention').value = p.diagnostics_retention_days || 7;
    byId('policyLAN').checked = p.home_lan_access !== false;
    byId('policyDiag').checked = !!p.diagnostics_enabled;
    byId('policyShareDiag').checked = !!p.share_diagnostics;
    byId('policyTelemetry').checked = !!p.telemetry_enabled;
  }

  window.saveCrossPlatformPolicy = async function saveCrossPlatformPolicy() {
    if (!currentProfile()) return toast('Select or import a node first', true);
    const v = id => document.getElementById(id);
    const mtuPolicy = v('policyMTU').value;
    const manual = +v('policyManualMTU').value || 0;
    if (mtuPolicy === 'manual' && (manual < 576 || manual > 9000)) return toast('Manual MTU must be between 576 and 9000', true);
    const ok = await saveProfile({
      kill_switch_policy:v('policyKill').value,
      ipv6_mode:v('policyIPv6').value,
      startup_mode:v('policyStartup').value,
      mtu_policy:mtuPolicy,
      manual_mtu:manual,
      home_lan_access:v('policyLAN').checked,
      diagnostics_enabled:v('policyDiag').checked,
      diagnostics_retention_days:+v('policyRetention').value || 7,
      share_diagnostics:v('policyShareDiag').checked,
      telemetry_enabled:v('policyTelemetry').checked
    });
    if (ok) { populatePolicyPanel(); toast('Policy intent saved; runtime readiness remains separately validated.'); }
  };

  const originalLoadProfiles = window.loadProfiles;
  if (typeof originalLoadProfiles === 'function') window.loadProfiles = async function loadProfilesWithPolicy(){const out=await originalLoadProfiles();populatePolicyPanel();return out};

  // Keep the legacy HTML onboarding copy aligned with the logical-mode/download
  // architecture before the async first-run wizard can open.
  try {
    if (Array.isArray(onboardingSteps) && onboardingSteps[5]) {
      onboardingSteps[5].body = `<p>The Router VPN application is generic and can hold multiple nodes. Link this node separately using the authenticated home Setup Center.</p><p><b>Private file path:</b> request <code>router-vpn-bundle.json</code> or the private client bundle on demand, then import it under Nodes. <b>Pairing:</b> create a short-lived one-time LAN code in Setup Center and redeem it from a supported client; the permanent Setup Center access token never goes into the node bundle.</p><p class="small">Apple-family clients must grant Local Network permission before LAN pairing. WireGuard-only users can instead scan/import the real WireGuard profile in a compatible app.</p>`;
    }
    if (Array.isArray(onboardingSteps) && onboardingSteps[8]) {
      onboardingSteps[8].body = onboardingSteps[8].body
        .replace(
          'The Modes page always shows all 20 modes, layers, overhead estimates and exact availability reasons.',
          'The Modes page shows the 16 logical modes, layers, overhead estimates, exact availability reasons and the WireGuard/AmneziaWG base selector where compatible.'
        )
        .replace(
          'WireGuard is the default base; AmneziaWG stays available in advanced node settings.',
          'WireGuard is the default preference; AmneziaWG remains a selectable/fallback base where supported.'
        );
    }
    if (Array.isArray(onboardingSteps) && onboardingSteps[12]) {
      onboardingSteps[12].body = `<p>Emergency stop terminates local Router VPN transports. Connection validation now reports requested and actual mode/base, selected-node path proof, rollback and typed errors.</p><p>Strict firewall kill-switch behavior is preserved as policy intent but is <b>not</b> shown as enforced until the current platform firewall adapter passes end-to-end tests. Setup Center private material is authenticated and pairing codes are LAN-only, short-lived and one-time.</p>`;
    }
  } catch (_) {}

  // Surface authentication change before opening the home Setup Center. The
  // access token deliberately remains router-local rather than being stored in
  // this client profile.
  try {
    const originalOpenSetupCenter = window.openSetupCenter;
    if (typeof originalOpenSetupCenter === 'function') window.openSetupCenter = function(section='start'){
      toast('Setup Center is authenticated. If prompted, retrieve the router-local token from /opt/router-vpn/config/setup-center.token and use it once; it is not stored in this client.');
      return originalOpenSetupCenter(section);
    };
  } catch (_) {}

  ensureSessionPanel();
  ensurePolicyPanel();
  populatePolicyPanel();
  mirrorOnboarding();
  refreshTypedSession();
  setInterval(refreshTypedSession, 750);

  // The legacy UI init may have already loaded raw rows while this deferred
  // extension was parsed. Replace them immediately with the logical catalog.
  queueMicrotask(() => reloadModes());
})();
