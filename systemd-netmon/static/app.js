/* systemd-netmon frontend: polls /api/snapshot, renders tables, guarded actions. No external deps. */
(function () {
  'use strict';
  const TOKEN = document.querySelector('meta[name="csrf-token"]').content;
  const $ = (id) => document.getElementById(id);
  const S = {
    paused: false, interval: 1000, timer: null, query: '', view: 'active',
    baseline: {}, config: null, snap: null, inflight: false, modal: null, menuFor: null,
  };

  // ---------------- utils ----------------
  const esc = (v) => String(v == null ? '' : v).replace(/[&<>"']/g, (c) => (
    { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const shq = (a) => /^[A-Za-z0-9_@%+=:,./-]+$/.test(a) ? a : "'" + String(a).replace(/'/g, "'\\''") + "'";
  function formatBytes(bytes) {
    if (bytes == null) return 'n/a';
    if (bytes <= 0) return '0 B';
    const k = 1024, sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
    const i = Math.min(Math.floor(Math.log(bytes) / Math.log(k)), sizes.length - 1);
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
  }
  const kbps = (bps) => (bps == null ? null : bps / 1024);
  function generateSparkline(history) {
    const blocks = [' ', '▂', '▃', '▄', '▅', '▆', '▇', '█'];
    if (!history || !history.length) return '<span class="text-slate-600">—</span>';
    const h = history.slice(-20);
    const max = Math.max(...h, 1);
    return h.map((v) => blocks[Math.min(Math.floor((v / max) * (blocks.length - 1)), blocks.length - 1)]).join('');
  }
  function globMatch(pat, s) {
    const re = new RegExp('^' + pat.replace(/[.+^${}()|\\]/g, '\\$&').replace(/\*/g, '.*').replace(/\?/g, '.') + '$');
    return re.test(s);
  }
  const isProtected = (unit) => !!(S.config && S.config.denylist.some((d) => globMatch(d.pattern, unit)));

  async function api(method, path, body) {
    const opt = { method, credentials: 'same-origin', headers: {} };
    if (body !== undefined) {
      opt.headers['Content-Type'] = 'application/json';
      opt.headers['X-Netmon-Token'] = TOKEN;
      opt.body = JSON.stringify(body);
    }
    const r = await fetch(path, opt);
    let data = {};
    try { data = await r.json(); } catch (e) { /* ignore */ }
    return { status: r.status, data };
  }

  // ---------------- polling ----------------
  function schedule() {
    clearTimeout(S.timer);
    S.timer = setTimeout(poll, S.interval);
  }
  async function poll() {
    if (S.paused) return;
    if (S.inflight) return schedule();
    S.inflight = true;
    try {
      const { status, data } = await api('GET', '/api/snapshot');
      if (status === 401) { setStatus('err', 'SESSION EXPIRED: reopen launch URL'); return; }
      if (status !== 200) throw new Error('HTTP ' + status);
      if (S.paused) return;  // paused while the request was in flight: keep the frozen view
      S.snap = data;
      setStatus('live');
      renderAll();
    } catch (e) {
      setStatus('err', 'BACKEND UNREACHABLE');
    } finally {
      S.inflight = false;
      if (!S.paused) schedule();
    }
  }
  function pollNow() { clearTimeout(S.timer); poll(); }

  function setStatus(kind, text) {
    const dot = $('status-dot'), st = $('status-text');
    if (kind === 'live') {
      dot.className = 'inline-block w-2 h-2 rounded-full bg-emerald-500 animate-subtle';
      st.className = 'text-emerald-400 font-medium'; st.textContent = 'LIVE POLLING';
    } else if (kind === 'paused') {
      dot.className = 'inline-block w-2 h-2 rounded-full bg-amber-500';
      st.className = 'text-amber-400 font-medium'; st.textContent = 'PAUSED';
    } else {
      dot.className = 'inline-block w-2 h-2 rounded-full bg-red-500';
      st.className = 'text-red-400 font-medium'; st.textContent = text;
    }
  }

  function togglePause() {
    S.paused = !S.paused;
    $('pause-text').textContent = S.paused ? 'RESUME' : 'PAUSE';   // fixed: resume used to show "PAUSED"
    $('pause-icon-wrap').innerHTML = '<i data-lucide="' + (S.paused ? 'play' : 'pause') + '" class="w-3.5 h-3.5"></i>';
    NetmonIcons.render($('pause-icon-wrap'));
    if (S.paused) { clearTimeout(S.timer); setStatus('paused'); } else { setStatus('live'); pollNow(); }
  }
  function changeInterval(val) { S.interval = parseInt(val, 10) || 1000; if (!S.paused) schedule(); }
  function resetStats() {
    if (!S.snap) return;
    S.baseline = {};
    S.snap.services.forEach((s) => { if (s.in_bytes != null) S.baseline[s.unit] = (s.in_bytes || 0) + (s.out_bytes || 0); });
    S.snap.services.forEach((s) => { s.history = []; });
    toast('info', 'Stats reset', 'Totals now count from this moment (display only; kernel counters untouched).');
    renderAll();
  }
  function toggleDrawer() { $('dbus-drawer').classList.toggle('translate-x-full'); }

  // ---------------- rendering ----------------
  function filteredServices() {
    const q = S.query;
    let list = (S.snap ? S.snap.services : []).filter((s) =>
      s.unit.toLowerCase().includes(q) || (s.description || '').toLowerCase().includes(q));
    if (S.view === 'active') list = list.filter((s) => ['active', 'activating', 'deactivating', 'reloading'].includes(s.active_state));
    else if (S.view === 'accounting') list = list.filter((s) => s.accounting_active);
    const rate = (s) => (s.in_bps || 0) + (s.out_bps || 0);
    list.sort((a, b) => rate(b) - rate(a) || (b.accounting_active - a.accounting_active) || a.unit.localeCompare(b.unit));
    return list;
  }
  function stateBadge(s) {
    const a = s.active_state;
    const cls = a === 'active' ? 'text-emerald-400 border-emerald-800/60 bg-emerald-950/30'
      : a === 'failed' ? 'text-red-400 border-red-800/60 bg-red-950/30'
      : (a === 'activating' || a === 'deactivating' || a === 'reloading') ? 'text-amber-300 border-amber-800/60 bg-amber-950/30'
      : 'text-slate-400 border-slate-700 bg-slate-800/40';
    const uf = s.unit_file_state;
    const ufCls = uf === 'masked' || uf === 'masked-runtime' ? 'text-red-400' : uf === 'enabled' ? 'text-cyan-400/80' : 'text-slate-500';
    return '<span class="px-1 rounded border ' + cls + '">' + esc(a) + '/' + esc(s.sub_state) + '</span> <span class="' + ufCls + ' text-[10px]">' + esc(uf) + '</span>';
  }
  function renderServices() {
    const list = filteredServices();
    let html = '';
    list.forEach((s, i) => {
      const acct = s.accounting_active;
      const r = kbps((s.in_bps || 0) + (s.out_bps || 0));
      const rateCls = !acct ? 'text-slate-600' : r > 100 ? 'text-emerald-400 font-bold glow-green' : r > 10 ? 'text-cyan-400 font-semibold' : 'text-slate-400';
      const thr = acct ? (s.in_bps == null ? '[… KBPS]' : '[' + r.toFixed(2) + ' KBPS]') : 'n/a';
      const io = acct
        ? '<span class="text-emerald-400">↓' + (s.in_bps == null ? '…' : kbps(s.in_bps).toFixed(1)) + '</span> / <span class="text-cyan-400">↑' + (s.out_bps == null ? '…' : kbps(s.out_bps).toFixed(1)) + '</span>'
        : '<span class="text-slate-600" title="IPAccounting is off for this unit">IPAccounting off</span>';
      const total = acct ? formatBytes((s.in_bytes || 0) + (s.out_bytes || 0) - (S.baseline[s.unit] || 0)) : 'n/a';
      const dot = acct && r > 0 ? 'bg-emerald-400' : s.active_state === 'active' ? 'bg-slate-500' : s.active_state === 'failed' ? 'bg-red-500' : 'bg-slate-700';
      const lock = isProtected(s.unit) ? '<span title="protected unit" class="text-amber-500">⚿</span>' : '';
      html += '<div class="svc-grid px-3 py-1.5 items-center hover:bg-slate-800/40 transition-colors ' + (i % 2 === 0 ? 'bg-slate-900/20' : '') + '">'
        + '<div class="flex items-center space-x-2 truncate" title="' + esc(s.description) + '"><span class="w-1.5 h-1.5 rounded-full shrink-0 ' + dot + '"></span><span class="text-slate-200 truncate font-semibold">' + esc(s.unit) + '</span>' + lock + '</div>'
        + '<div class="truncate text-[11px]">' + stateBadge(s) + '</div>'
        + '<div class="text-right"><span class="' + rateCls + '">' + thr + '</span></div>'
        + '<div class="text-right text-[11px] text-slate-400 truncate">' + io + '</div>'
        + '<div class="px-3 hide-sm"><span class="text-cyan-400/80 font-bold text-xs tracking-tighter whitespace-pre">' + (acct ? generateSparkline(s.history) : '') + '</span></div>'
        + '<div class="text-right text-slate-400 text-[11px]">' + total + '</div>'
        + '<div class="text-right"><button class="act-btn px-1.5 rounded hover:bg-slate-700 text-slate-300" data-kind="unit" data-unit="' + esc(s.unit) + '" title="Actions">⋮</button></div>'
        + '</div>';
    });
    if (!list.length) {
      const err = S.snap && S.snap.systemd_error;
      html = '<div class="p-4 text-center text-slate-500">' + (err ? 'systemd unavailable: ' + esc(err) : 'No matching systemd units found.') + '</div>';
    }
    $('services-list').innerHTML = html;
  }
  function renderRawSockets() {
    const q = S.query;
    const list = (S.snap ? S.snap.sockets : []).filter((x) => !q || (x.process || '').toLowerCase().includes(q)
      || x.proto.toLowerCase().includes(q) || (x.unit || '').toLowerCase().includes(q));
    let html = '';
    list.forEach((x, i) => {
      const drops = x.kind === 'packet' ? formatBytes(x.rmem) + ' rmem'
        : (x.drops == null ? 'n/a' : x.drops.toLocaleString() + ' drops' + (x.drop_rate ? ' (+' + x.drop_rate.toFixed(1) + '/s)' : ''));
      const iface = x.iface ? ' <span class="text-slate-500">@' + esc(x.iface) + '</span>' : '';
      html += '<div class="sock-grid px-3 py-1.5 items-center hover:bg-slate-800/40 transition-colors ' + (i % 2 === 0 ? 'bg-slate-900/20' : '') + '">'
        + '<div class="text-slate-500 text-[11px] truncate">#' + esc(x.inode) + '</div>'
        + '<div class="font-semibold text-amber-300 flex items-center gap-1.5 truncate"><i data-lucide="zap" class="w-3 h-3 text-amber-400 shrink-0"></i><span class="truncate">' + (x.process ? esc(x.process) : '<span class="text-slate-500" title="owner not visible (run as root)">unknown</span>') + '</span></div>'
        + '<div class="text-center text-slate-400">' + (x.pid ? esc(x.pid) + (x.pids.length > 1 ? '<span class="text-slate-500">+' + (x.pids.length - 1) + '</span>' : '') : '?') + '</div>'
        + '<div class="text-[11px] truncate"><span class="bg-slate-800 text-slate-300 px-1.5 py-0.5 rounded border border-slate-700">' + esc(x.proto) + '</span>' + iface + '</div>'
        + '<div class="text-right text-slate-500" title="not exposed by the kernel for raw/packet sockets">n/a</div>'
        + '<div class="text-right text-slate-400 text-[11px] hide-sm">' + drops + '</div>'
        + '<div class="text-slate-500 text-[11px] truncate hide-sm">' + esc(x.unit || '') + '</div>'
        + '<div class="text-right"><button class="act-btn px-1.5 rounded hover:bg-slate-700 text-slate-300" data-kind="pid" data-inode="' + esc(x.inode) + '" title="Actions">⋮</button></div>'
        + '</div>';
    });
    if (!list.length) html = '<div class="p-4 text-center text-slate-500">No raw or packet sockets open.</div>';
    $('raw-sockets-list').innerHTML = html;
    NetmonIcons.render($('raw-sockets-list'));
  }
  function renderHeaderSummary() {
    const t = (S.snap && S.snap.totals) || {};
    $('total-ingress').textContent = (kbps(t.in_bps || 0)).toFixed(2) + ' KB/s';
    $('total-egress').textContent = (kbps(t.out_bps || 0)).toFixed(2) + ' KB/s';
    $('active-units-count').textContent = (t.active_units || 0) + ' / ' + (t.units || 0) + ' (' + (t.accounting_units || 0) + ')';
    $('raw-sockets-count').textContent = (t.sockets || 0) + ' sockets active';
    const b = [];
    if (S.snap && S.snap.systemd_error) b.push('systemd: ' + S.snap.systemd_error);
    if (S.snap && !S.snap.sockets_pid_mapping_complete) b.push('Some socket owners are hidden: run the backend as root to map every inode to its PID.');
    if (S.config && !S.config.is_root && !S.config.read_only && !S.config.dry_run) b.push('Backend is not root: unit actions need the polkit rule (README), PID kills only work on your own processes.');
    $('banner').textContent = b.join('  •  ');
    $('banner').classList.toggle('hidden', !b.length);
  }
  function renderAll() { renderServices(); renderRawSockets(); renderHeaderSummary(); }

  // ---------------- action menu ----------------
  const UNIT_ITEMS = [
    { a: 'start', label: 'Start', icon: 'play', show: (s) => s.active_state !== 'active' },
    { a: 'stop', label: 'Stop', icon: 'circle-stop', warn: true },
    { a: 'restart', label: 'Restart', icon: 'rotate-cw', warn: true },
    { a: 'kill', sig: 'SIGTERM', label: 'Kill (SIGTERM)', icon: 'zap', danger: true },
    { a: 'kill', sig: 'SIGKILL', label: 'Kill (SIGKILL)', icon: 'skull', danger: true },
    { sep: true },
    { a: 'enable', label: 'Enable at boot', icon: 'power', show: (s) => s.unit_file_state === 'disabled' },
    { a: 'disable', label: 'Disable at boot', icon: 'power', warn: true, show: (s) => !['disabled', 'masked', 'masked-runtime', 'static'].includes(s.unit_file_state) },
    { a: 'mask', label: 'Mask (block all starts)', icon: 'ban', danger: true, show: (s) => !s.unit_file_state.startsWith('masked') },
    { a: 'unmask', label: 'Unmask', icon: 'rotate-ccw', show: (s) => s.unit_file_state.startsWith('masked') },
    { sep: true },
    { a: 'ipaccounting', label: 'Enable IPAccounting (runtime)', icon: 'activity', show: (s) => !s.accounting_active },
  ];
  function openMenu(btn) {
    const menu = $('action-menu');
    const kind = btn.dataset.kind;
    let html = '';
    if (S.config && S.config.read_only) {
      html = '<div class="px-3 py-2 text-slate-500 flex items-center gap-2"><i data-lucide="lock" class="w-3.5 h-3.5"></i> read-only mode</div>';
    } else if (kind === 'unit') {
      const s = (S.snap.services || []).find((u) => u.unit === btn.dataset.unit);
      if (!s) return;
      html += '<div class="px-3 py-1 text-[10px] text-slate-500 truncate">' + esc(s.unit) + '</div>';
      UNIT_ITEMS.forEach((it) => {
        if (it.sep) { html += '<div class="my-1 border-t border-slate-800"></div>'; return; }
        if (it.show && !it.show(s)) return;
        const cls = it.danger ? 'text-red-400 hover:bg-red-950/60' : it.warn ? 'text-amber-300 hover:bg-amber-950/40' : 'text-slate-200 hover:bg-slate-800';
        html += '<button class="menu-item w-full text-left px-3 py-1.5 flex items-center gap-2 ' + cls + '" data-kind="unit" data-unit="' + esc(s.unit) + '" data-action="' + it.a + '" data-sig="' + (it.sig || '') + '"><i data-lucide="' + it.icon + '" class="w-3.5 h-3.5"></i>' + it.label + '</button>';
      });
    } else {
      const x = (S.snap.sockets || []).find((k) => String(k.inode) === btn.dataset.inode);
      if (!x) return;
      html += '<div class="px-3 py-1 text-[10px] text-slate-500 truncate">' + esc(x.process || 'unknown') + ' pid ' + esc(x.pid || '?') + '</div>';
      if (!x.pid) html += '<div class="px-3 py-2 text-slate-500">owner PID unknown (run as root)</div>';
      else {
        ['SIGTERM', 'SIGKILL'].forEach((sig) => {
          html += '<button class="menu-item w-full text-left px-3 py-1.5 flex items-center gap-2 text-red-400 hover:bg-red-950/60" data-kind="pid" data-pid="' + esc(x.pid) + '" data-inode="' + esc(x.inode) + '" data-sig="' + sig + '"><i data-lucide="' + (sig === 'SIGKILL' ? 'skull' : 'zap') + '" class="w-3.5 h-3.5"></i>Kill PID ' + esc(x.pid) + ' (' + sig + ')</button>';
        });
        if (x.unit && x.unit.endsWith('.service')) {
          html += '<div class="my-1 border-t border-slate-800"></div><button class="menu-item w-full text-left px-3 py-1.5 flex items-center gap-2 text-amber-300 hover:bg-amber-950/40" data-kind="unit" data-unit="' + esc(x.unit) + '" data-action="stop" data-sig=""><i data-lucide="circle-stop" class="w-3.5 h-3.5"></i>Stop owning unit ' + esc(x.unit) + '</button>';
        }
      }
    }
    menu.innerHTML = html;
    NetmonIcons.render(menu);
    menu.classList.remove('hidden');
    const r = btn.getBoundingClientRect();
    const mh = menu.offsetHeight, mw = menu.offsetWidth;
    menu.style.top = Math.max(4, (r.bottom + mh > window.innerHeight ? r.top - mh : r.bottom)) + 'px';
    menu.style.left = Math.max(4, r.right - mw) + 'px';
  }
  const closeMenu = () => $('action-menu').classList.add('hidden');

  // ---------------- confirmation modal ----------------
  async function openConfirm(req) {
    closeMenu();
    const prev = req.kind === 'unit'
      ? await api('POST', '/api/unit/preview', { unit: req.unit, action: req.action, signal: req.sig || null, now: !!req.now })
      : await api('POST', '/api/pid/preview', { pid: req.pid, inode: req.inode, signal: req.sig });
    if (prev.status !== 200) { toast('err', 'Cannot prepare action', prev.data.error || ('HTTP ' + prev.status)); return; }
    const p = prev.data;
    S.modal = Object.assign({}, req, { preview: p });
    const danger = p.danger || req.action === 'mask';
    const warn = ['stop', 'restart', 'disable'].includes(req.action);
    const label = req.kind === 'unit' ? (req.action === 'kill' ? 'kill ' + req.sig : req.action) : 'kill PID ' + req.pid + ' (' + req.sig + ')';
    $('modal-title').innerHTML = '<i data-lucide="' + (danger ? 'triangle-alert' : 'terminal') + '" class="w-4 h-4"></i><span>' + esc(label.toUpperCase()) + '</span>';
    $('modal-title').className = 'px-4 py-3 border-b border-slate-800 flex items-center gap-2 font-bold text-sm ' + (danger ? 'text-red-400' : warn ? 'text-amber-300' : 'text-cyan-400');
    $('modal-target').innerHTML = req.kind === 'unit' ? 'Unit: <b class="text-slate-100">' + esc(req.unit) + '</b>'
      : 'Process: <b class="text-slate-100">' + esc(p.process) + '</b> (PID ' + esc(req.pid) + ', socket #' + esc(req.inode) + (p.unit ? ', unit ' + esc(p.unit) : '') + ')';
    $('modal-cmd').textContent = '$ ' + p.cmd.map(shq).join(' ') + (req.kind === 'pid' ? '    # sent via os.kill()' : '');
    $('modal-now-wrap').classList.toggle('hidden', !(req.kind === 'unit' && (req.action === 'disable' || req.action === 'mask')));
    $('modal-now').checked = !!req.now;
    const notes = {
      kill: 'Signals every process in the unit. Units with Restart= may respawn immediately.',
      mask: 'Links the unit to /dev/null: nothing (not even dependencies) can start it until unmasked.',
      disable: 'Prevents start at boot; it may still be started by sockets/dependencies.',
      stop: 'Runtime only; it will start again at next boot if enabled.',
      ipaccounting: 'Runtime only (lost at reboot). Counters start from zero now.',
    };
    const w = $('modal-warn');
    const wtxt = req.kind === 'pid' ? 'Sends ' + req.sig + ' directly to the process. If it belongs to a service with Restart=, systemd may restart it.' : (notes[req.action] || '');
    w.textContent = wtxt; w.classList.toggle('hidden', !wtxt);
    w.className = (wtxt ? '' : 'hidden ') + (danger ? 'bg-red-950/50 border border-red-800/60 text-red-300' : 'bg-slate-950 border border-slate-800 text-slate-400') + ' rounded p-2';
    const fw = req.kind === 'unit' ? req.unit : String(req.pid);
    $('modal-force').classList.toggle('hidden', !p.requires_force);
    $('modal-force-word').textContent = fw;
    $('modal-force-input').value = '';
    $('modal-note').innerHTML = (p.requires_force ? '<span class="text-red-300">Protected: ' + esc(p.deny_reason) + '.</span> ' : '')
      + (p.dry_run ? '<span class="text-amber-300 font-bold">DRY-RUN: the command will be logged, not executed.</span> ' : '')
      + 'Logged to the audit log.';
    const ok = $('modal-ok');
    ok.textContent = p.dry_run ? 'Log (dry-run)' : (p.requires_force ? 'Force run' : 'Run');
    ok.className = 'px-3 py-1 rounded border font-bold ' + (danger || p.requires_force ? 'bg-red-900/70 border-red-600 text-red-100 hover:bg-red-800' : warn ? 'bg-amber-900/60 border-amber-600 text-amber-100 hover:bg-amber-800' : 'bg-cyan-900/60 border-cyan-600 text-cyan-100 hover:bg-cyan-800');
    NetmonIcons.render($('modal-title'));
    $('modal').classList.remove('hidden');
    (p.requires_force ? $('modal-force-input') : ok).focus();
  }
  const closeModal = () => { $('modal').classList.add('hidden'); S.modal = null; };

  async function runModal() {
    const m = S.modal;
    if (!m) return;
    let force = false;
    if (m.preview.requires_force) {
      const want = m.kind === 'unit' ? m.unit : String(m.pid);
      if ($('modal-force-input').value.trim() !== want) { $('modal-force-input').classList.add('animate-pulse'); return; }
      force = true;
    }
    $('modal-ok').disabled = true;
    try {
      const res = m.kind === 'unit'
        ? await api('POST', '/api/unit/action', { unit: m.unit, action: m.action, signal: m.sig || null, now: !!m.now, force })
        : await api('POST', '/api/pid/kill', { pid: m.pid, inode: m.inode, signal: m.sig, force });
      const d = res.data;
      const cmd = d.cmd ? '$ ' + d.cmd.map(shq).join(' ') : '';
      if (res.status === 200 && d.ok) toast(d.dry_run ? 'info' : 'ok', d.dry_run ? 'Dry-run logged' : 'Done', cmd + (d.stdout ? '\n' + d.stdout : '') + (d.stderr ? '\n' + d.stderr : ''));
      else toast('err', 'Failed' + (d.rc != null ? ' (rc=' + d.rc + ')' : ''), (d.error || d.message || ('HTTP ' + res.status)) + (cmd ? '\n' + cmd : ''));
    } catch (e) {
      toast('err', 'Request failed', String(e));
    } finally {
      $('modal-ok').disabled = false;
      closeModal();
      pollNow();
    }
  }

  function toast(kind, title, body) {
    const el = document.createElement('div');
    const cls = kind === 'ok' ? 'border-emerald-700 text-emerald-300' : kind === 'err' ? 'border-red-700 text-red-300' : 'border-amber-700 text-amber-300';
    el.className = 'bg-slate-950/95 border rounded shadow-xl p-2 text-xs ' + cls;
    el.innerHTML = '<div class="font-bold">' + esc(title) + '</div>' + (body ? '<pre class="whitespace-pre-wrap break-all text-slate-300 mt-1 max-h-40 overflow-y-auto select-text">' + esc(body) + '</pre>' : '');
    $('toasts').appendChild(el);
    setTimeout(() => el.remove(), kind === 'err' ? 12000 : 6000);
    el.addEventListener('click', () => el.remove());
  }

  // ---------------- wiring ----------------
  async function init() {
    NetmonIcons.render(document);
    const { status, data } = await api('GET', '/api/config');
    if (status === 200) {
      S.config = data;
      const mb = $('mode-badge');
      if (data.read_only) { mb.textContent = 'READ-ONLY'; mb.className = 'px-1.5 py-0.5 rounded border text-[10px] font-bold border-slate-600 text-slate-300'; }
      else if (data.dry_run) { mb.textContent = 'DRY-RUN'; mb.className = 'px-1.5 py-0.5 rounded border text-[10px] font-bold border-amber-600 text-amber-300'; }
      else { mb.textContent = data.is_root ? 'ACTIONS ARMED (root)' : 'ACTIONS (non-root)'; mb.className = 'px-1.5 py-0.5 rounded border text-[10px] font-bold border-red-700 text-red-300'; }
      $('denylist').innerHTML = data.denylist.map((d) => '<div><code class="text-amber-300">' + esc(d.pattern) + '</code> — ' + esc(d.reason) + '</div>').join('');
    }
    $('btn-pause').addEventListener('click', togglePause);
    $('rate-select').addEventListener('change', (e) => changeInterval(e.target.value));
    $('view-select').addEventListener('change', (e) => { S.view = e.target.value; renderServices(); });
    $('btn-drawer').addEventListener('click', toggleDrawer);
    $('btn-drawer-close').addEventListener('click', toggleDrawer);
    $('search-input').addEventListener('input', (e) => { S.query = e.target.value.toLowerCase(); renderServices(); renderRawSockets(); });
    $('modal-cancel').addEventListener('click', closeModal);
    $('modal-ok').addEventListener('click', runModal);
    $('modal').addEventListener('click', (e) => { if (e.target.id === 'modal') closeModal(); });
    $('modal-now').addEventListener('change', (e) => { if (S.modal) { const r = Object.assign({}, S.modal, { now: e.target.checked }); delete r.preview; openConfirm(r); } });
    $('modal-force-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') runModal(); });
    document.addEventListener('click', (e) => {
      if (e.target.closest('.act-btn')) return;  // handled on pointerdown (rows re-render while polling)
      const it = e.target.closest('.menu-item');
      if (it) {
        const d = it.dataset;
        if (d.kind === 'unit') openConfirm({ kind: 'unit', unit: d.unit, action: d.action, sig: d.sig || null });
        else openConfirm({ kind: 'pid', pid: parseInt(d.pid, 10), inode: parseInt(d.inode, 10), sig: d.sig });
        return;
      }
      if (!e.target.closest('#action-menu')) closeMenu();
    });
    // pointerdown instead of click: a poll re-render between mousedown and mouseup would swallow a click
    document.addEventListener('pointerdown', (e) => {
      const act = e.target.closest && e.target.closest('.act-btn');
      if (act && e.button === 0) { e.preventDefault(); openMenu(act); }
    });
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') { closeMenu(); closeModal(); $('dbus-drawer').classList.add('translate-x-full'); return; }
      const tag = (e.target.tagName || '').toLowerCase();
      if (S.modal || tag === 'input' || tag === 'select' || tag === 'textarea') return;
      if (e.key === ' ') { e.preventDefault(); togglePause(); }
      else if (e.key === '/') { e.preventDefault(); $('search-input').focus(); }
      else if (e.key.toLowerCase() === 'r') resetStats();
    });
    poll();
  }
  document.addEventListener('DOMContentLoaded', init);
})();
