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

  // The legacy UI init may have already loaded raw rows while this deferred
  // extension was parsed. Replace them immediately with the logical catalog.
  queueMicrotask(() => reloadModes());
})();
