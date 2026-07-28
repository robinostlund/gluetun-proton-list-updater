// Dashboard front end. No frameworks and no external requests: the page is
// served from the container and must work on an isolated network.
//
// State arrives over server-sent events; every render is a full redraw from the
// latest snapshot, which keeps the UI impossible to get out of sync.
'use strict';

const el = (id) => document.getElementById(id);
const text = (id, value) => { const node = el(id); if (node) node.textContent = value; };

let snapshot = null;
let filterTerm = '';

/* ---------- formatting helpers ---------- */

function timeAgo(iso) {
  if (!iso || iso.startsWith('0001-01-01')) return 'never';
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return '–';
  const seconds = Math.round((Date.now() - then) / 1000);
  if (seconds < 0) return 'in ' + humanize(-seconds);
  if (seconds < 5) return 'just now';
  return humanize(seconds) + ' ago';
}

function humanize(seconds) {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h`;
  return `${Math.round(seconds / 86400)}d`;
}

function nanos(ns) {
  if (!ns) return '–';
  return `${(ns / 1e6).toFixed(1)} ms`;
}

const boolMark = (value) => value ? '<span class="ok">yes</span>' : '<span class="no">no</span>';

function loadCell(load) {
  const severity = load >= 80 ? 'bad' : load >= 60 ? 'warn' : '';
  return `${load}%<span class="bar ${severity}"><span style="width:${Math.min(load, 100)}%"></span></span>`;
}

function escapeHTML(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

/* ---------- rendering ---------- */

function render() {
  if (!snapshot) return;

  text('version', snapshot.version ? `v${snapshot.version}` : 'dev');

  const activity = el('activity');
  activity.hidden = !snapshot.activity;
  text('activity-text', snapshot.activity || '');

  renderAlerts();
  renderCurrent();
  renderBest();
  renderGluetun();
  renderProton();
  renderServersFile();
  renderLatency();
  renderCandidates();
  renderHistory();
  renderSettings();
  renderStats();

  el('auto-switch').checked = Boolean(snapshot.selection.auto_switch);
}

function renderAlerts() {
  const alerts = [];
  const selection = snapshot.selection;

  if (snapshot.proton.needs_totp) {
    alerts.push(`<div class="alert alert-warn">
      <div>
        <strong>Two-factor code required</strong>
        Proton is waiting for a TOTP code to finish signing in.
        <form id="totp-form">
          <input type="text" id="totp-code" inputmode="numeric" autocomplete="one-time-code"
                 pattern="[0-9]*" maxlength="8" placeholder="123456" required>
          <button type="submit" class="primary small">Submit code</button>
        </form>
      </div>
    </div>`);
  }
  if (selection.needs_gluetun_restart) {
    alerts.push(`<div class="alert alert-bad"><div>
      <strong>Gluetun is running an older server list</strong>
      It rejected every server offered, which means the servers.json written here has not been
      loaded yet. Restart the Gluetun container to pick it up.
    </div></div>`);
  }
  if (snapshot.gluetun.provider_mismatch) {
    alerts.push(`<div class="alert alert-bad"><div>
      <strong>Gluetun is not configured for ProtonVPN</strong>
      It reports provider "${escapeHTML(snapshot.gluetun.provider)}", so nothing done here can affect it.
    </div></div>`);
  }
  if (!snapshot.gluetun.reachable) {
    alerts.push(`<div class="alert alert-warn"><div>
      <strong>Gluetun control server unreachable</strong>
      servers.json is still being maintained; switching is paused until Gluetun answers again.
      ${escapeHTML(snapshot.gluetun.last_error || '')}
    </div></div>`);
  }
  if (snapshot.proton.from_cache) {
    alerts.push(`<div class="alert alert-warn"><div>
      <strong>Using the cached server list</strong>
      Proton could not be reached, so loads and scores may be stale.
      ${escapeHTML(snapshot.proton.last_fetch_error || '')}
    </div></div>`);
  }
  if (selection.last_error) {
    alerts.push(`<div class="alert alert-bad"><div>
      <strong>Last switch attempt failed</strong>${escapeHTML(selection.last_error)}
    </div></div>`);
  }

  el('alerts').innerHTML = alerts.join('');
  const form = el('totp-form');
  if (form) form.addEventListener('submit', submitTOTP);
}

function renderCurrent() {
  const current = snapshot.selection.current;
  const gluetun = snapshot.gluetun;

  text('current-name', current ? current.server_name : 'unknown');
  text('current-where', current
    ? `${current.country}${current.city ? ' · ' + current.city : ''} · ${current.hostname}`
    : 'No server identified yet');
  el('current-load').innerHTML = current ? loadCell(current.load) : '–';
  text('current-rtt', current && current.rtt_known ? `${current.rtt_ms} ms` : 'unmeasured');
  text('current-score', current && !current.excluded ? current.score.toFixed(3) : '–');
  text('current-rank', current && current.rank
    ? `#${current.rank} of ${snapshot.candidates_total}`
    : current && current.excluded ? 'not in allowed set' : '–');
  text('current-ip', gluetun.public_ip || '–');
  text('current-port', gluetun.forwarded_port ? String(gluetun.forwarded_port) : 'none');

  const sources = {
    'pinned': 'Identified by the hostname this tool pinned in Gluetun.',
    'public-ip': "Identified by matching Gluetun's public IP to a Proton exit address.",
    'unknown': 'Could not identify the server: the tunnel may be down, or the server is not in Proton’s current list.',
  };
  let note = sources[snapshot.selection.current_source] || '';
  if (current && current.excluded) {
    note = 'This server is outside your filters (country, load or features), which is why a switch is due. ' + note;
  }
  text('current-source', note);
}

function renderBest() {
  const best = snapshot.selection.best;
  const selection = snapshot.selection;

  text('best-name', best ? best.server_name : '–');
  text('best-where', best ? `${best.country}${best.city ? ' · ' + best.city : ''} · ${best.hostname}` : '');
  el('best-load').innerHTML = best ? loadCell(best.load) : '–';
  text('best-rtt', best && best.rtt_known ? `${best.rtt_ms} ms` : 'unmeasured');
  text('best-score', best ? best.score.toFixed(3) : '–');
  text('improvement', selection.improvement ? selection.improvement.toFixed(3) : '0.000');

  const parts = [];
  parts.push(`Needs ${selection.min_improvement.toFixed(3)} improvement to switch automatically.`);
  if (selection.cooldown_remaining) parts.push(`Cooldown: ${selection.cooldown_remaining} left.`);
  if (!selection.auto_switch) parts.push('Automatic switching is off.');
  if (selection.mode === 'none') parts.push('Reconnect mode is "none": the tunnel is never touched.');
  text('switch-note', parts.join(' '));
}

function renderGluetun() {
  const gluetun = snapshot.gluetun;
  text('gluetun-status', gluetun.status || 'unknown');
  el('gluetun-reachable').innerHTML = boolMark(gluetun.reachable);
  text('gluetun-version', gluetun.version || '–');
  text('gluetun-vpn', gluetun.vpn_type || '–');
  text('gluetun-provider', gluetun.provider || '–');
  text('gluetun-check', timeAgo(gluetun.last_check));
  text('gluetun-error', gluetun.reachable ? (gluetun.last_error || '') : '');

  const stream = el('stream-state');
  stream.className = 'pill ' + (gluetun.status === 'running' ? 'pill-good' : 'pill-bad');
}

function renderProton() {
  const proton = snapshot.proton;
  text('proton-count', `${proton.logicals_count} logical servers`);
  el('proton-login').innerHTML = boolMark(proton.logged_in);
  text('proton-fetch', timeAgo(proton.last_fetch));
  text('proton-loads', timeAgo(proton.last_load_refresh));
  text('proton-next', snapshot.next_runs.server_list || '–');
  text('candidate-count', String(snapshot.candidates_total));
  text('proton-error', proton.last_fetch_error || proton.last_load_error || '');
}

function renderServersFile() {
  const servers = snapshot.servers_file;
  text('servers-count', `${servers.server_count} entries`);
  text('servers-path', servers.path);
  text('servers-mode', servers.write_mode);
  text('servers-schema', String(servers.schema_version));
  text('servers-write', timeAgo(servers.last_write));
  text('servers-preserved', (servers.preserved_keys || []).join(', ') || 'none');
  text('servers-error', servers.last_error || '');
}

function renderLatency() {
  const latency = snapshot.latency;
  text('latency-median', latency.median_ns ? nanos(latency.median_ns) : 'not probed');
  text('latency-measured', String(latency.measured || 0));
  text('latency-failed', String(latency.failed || 0));
  text('latency-best', nanos(latency.best_ns));
  text('latency-worst', nanos(latency.worst_ns));
  text('latency-next', snapshot.next_runs.latency || '–');
}

function renderCandidates() {
  const term = filterTerm.toLowerCase();
  const rows = snapshot.candidates.filter((candidate) => !term
    || candidate.server_name.toLowerCase().includes(term)
    || candidate.country.toLowerCase().includes(term)
    || (candidate.city || '').toLowerCase().includes(term)
    || candidate.hostname.toLowerCase().includes(term));

  text('candidates-shown', `showing ${rows.length} of ${snapshot.candidates_total}`);

  el('candidates').tBodies[0].innerHTML = rows.map((candidate) => {
    const tags = [];
    if (candidate.is_current) tags.push('<span class="tag">current</span>');
    if (candidate.p2p) tags.push('<span class="tag">p2p</span>');
    if (candidate.stream) tags.push('<span class="tag">stream</span>');
    if (candidate.secure_core) tags.push('<span class="tag">secure core</span>');
    if (candidate.tor) tags.push('<span class="tag">tor</span>');
    if (candidate.free) tags.push('<span class="tag">free</span>');
    if (candidate.wireguard) tags.push('<span class="tag">wg</span>');

    const scoreTitle = `load ${candidate.score_load} + latency ${candidate.score_latency} + proton ${candidate.score_proton}`;

    return `<tr class="${candidate.is_current ? 'is-current' : ''}">
      <td class="num">${candidate.rank}</td>
      <td><div>${escapeHTML(candidate.server_name)}</div><div class="hostname">${escapeHTML(candidate.hostname)}</div></td>
      <td>${escapeHTML(candidate.country)}${candidate.city ? ' · ' + escapeHTML(candidate.city) : ''}</td>
      <td class="num">${loadCell(candidate.load)}</td>
      <td class="num">${candidate.rtt_known ? candidate.rtt_ms + ' ms' : '–'}</td>
      <td class="num" title="${escapeHTML(scoreTitle)}">${candidate.score.toFixed(3)}</td>
      <td><div class="tags">${tags.join('')}</div></td>
      <td class="right">
        <button class="small" data-switch="${escapeHTML(candidate.hostname)}"
          ${candidate.is_current ? 'disabled' : ''}>Use</button>
      </td>
    </tr>`;
  }).join('');
}

function renderHistory() {
  const rows = (snapshot.history || []).map((record) => `<tr>
      <td title="${escapeHTML(record.at)}">${timeAgo(record.at)}</td>
      <td class="hostname">${escapeHTML(record.from || '—')} → ${escapeHTML(record.to)}</td>
      <td>${escapeHTML(record.reason)}</td>
      <td class="num">${record.score_before >= 0 ? record.score_before.toFixed(3) : '–'} → ${record.score_after.toFixed(3)}</td>
      <td>${record.succeeded
        ? `<span class="ok">ok</span>${record.public_ip ? ' · ' + escapeHTML(record.public_ip) : ''}`
        : `<span class="no">failed</span> ${escapeHTML(record.error || '')}`}</td>
    </tr>`);
  el('history').tBodies[0].innerHTML = rows.join('')
    || '<tr><td colspan="5" class="muted">No switches recorded yet.</td></tr>';
}

function renderSettings() {
  const settings = snapshot.settings;
  const entries = [
    ['Countries', (settings.countries || []).join(', ') || 'all'],
    ['Excluded', (settings.exclude_countries || []).join(', ') || 'none'],
    ['Cities', (settings.cities || []).join(', ') || 'all'],
    ['Max load', `${settings.max_load}%`],
    ['Protocol', settings.vpn_type],
    ['Secure core', settings.secure_core],
    ['Tor', settings.tor],
    ['P2P', settings.p2p],
    ['Streaming', settings.stream],
    ['Free tier', settings.free_tier],
    ['Load weight', settings.load_weight],
    ['Latency weight', settings.latency_weight],
    ['Proton weight', settings.proton_weight],
    ['Latency ceiling', settings.latency_ceiling],
    ['List refresh', settings.refresh_interval],
    ['Load refresh', settings.load_refresh_interval],
    ['Latency sweep', settings.latency_enabled ? `${settings.latency_interval} (top ${settings.latency_top_n})` : 'disabled'],
    ['Evaluation', settings.evaluation_interval],
    ['Switch cooldown', settings.switch_cooldown],
    ['Min switch interval', settings.switch_min_interval],
    ['Load trigger', settings.load_trigger ? `${settings.load_trigger}%` : 'disabled'],
    ['Reconnect mode', snapshot.selection.mode],
    ['Uptime', timeAgo(snapshot.started_at).replace(' ago', '')],
  ];
  el('settings').innerHTML = entries
    .map(([key, value]) => `<div><dt>${escapeHTML(key)}</dt><dd>${escapeHTML(value)}</dd></div>`)
    .join('');
}

function renderStats() {
  const stats = snapshot.stats || {};
  const entries = [
    ['Logical servers', `${stats.logicals_kept || 0} of ${stats.logicals_total || 0}`],
    ['Physical servers', `${stats.physical_kept || 0} of ${stats.physical_total || 0}`],
    ['Skipped: disabled', stats.disabled_skipped || 0],
    ['Skipped: duplicate IP', stats.duplicate_skipped || 0],
    ['Secure core available', stats.secure_core_total || 0],
    ['Tor available', stats.tor_total || 0],
    ['P2P available', stats.p2p_total || 0],
    ['Streaming available', stats.stream_total || 0],
    ['Free tier available', stats.free_total || 0],
    ['IPv6 capable', stats.ipv6_total || 0],
  ];
  if ((stats.unknown_countries || []).length) {
    entries.push(['Unknown country codes', stats.unknown_countries.join(', ')]);
  }
  el('stats').innerHTML = entries
    .map(([key, value]) => `<div><dt>${escapeHTML(key)}</dt><dd>${escapeHTML(value)}</dd></div>`)
    .join('');
}

function renderLogs(records) {
  el('logs').innerHTML = records.map((record) => {
    const time = new Date(record.time).toLocaleTimeString();
    const level = (record.level || 'info').toLowerCase();
    const attrs = Object.entries(record.attrs || {})
      .filter(([key]) => key !== 'time' && key !== 'level')
      .map(([key, value]) => `${key}=${value}`)
      .join(' ');
    return `<li>
      <span class="time">${escapeHTML(time)}</span>
      <span class="level level-${escapeHTML(level)}">${escapeHTML(level)}</span>
      <span class="msg">${escapeHTML(record.message)}${attrs ? ' <span class="muted">' + escapeHTML(attrs) + '</span>' : ''}</span>
    </li>`;
  }).join('') || '<li class="muted">No log records yet.</li>';
}

/* ---------- actions ---------- */

function toast(message, kind) {
  const node = el('toast');
  node.textContent = message;
  node.className = 'toast ' + (kind || '');
  node.hidden = false;
  clearTimeout(toast.timer);
  toast.timer = setTimeout(() => { node.hidden = true; }, kind === 'bad' ? 9000 : 4000);
}

async function post(url, body) {
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body || {}),
  });
  let payload = {};
  try { payload = await response.json(); } catch { /* empty body is fine */ }
  if (!response.ok || payload.ok === false) {
    throw new Error(payload.error || `request failed with HTTP ${response.status}`);
  }
  return payload;
}

async function runAction(button, url, body, successMessage) {
  button.disabled = true;
  try {
    await post(url, body);
    toast(successMessage, 'good');
  } catch (error) {
    toast(error.message, 'bad');
  } finally {
    button.disabled = false;
    refreshLogs();
  }
}

async function submitTOTP(event) {
  event.preventDefault();
  const input = el('totp-code');
  const button = event.target.querySelector('button');
  await runAction(button, '/api/totp', { code: input.value.trim() }, 'Code submitted.');
  input.value = '';
}

async function refreshLogs() {
  try {
    const response = await fetch('/api/logs?limit=120');
    if (response.ok) renderLogs(await response.json());
  } catch { /* the stream will retry */ }
}

/* ---------- wiring ---------- */

document.addEventListener('click', (event) => {
  const action = event.target.closest('button[data-action]');
  if (action) {
    runAction(action, action.dataset.action, {}, 'Requested.');
    return;
  }
  const use = event.target.closest('button[data-switch]');
  if (use) {
    const hostname = use.dataset.switch;
    toast(`Switching to ${hostname}… this waits for the tunnel to come back up.`);
    runAction(use, '/api/switch', { hostname }, `Now on ${hostname}.`);
  }
});

el('auto-switch').addEventListener('change', (event) => {
  const checkbox = event.target;
  post('/api/auto-switch', { enabled: checkbox.checked })
    .then(() => toast(`Automatic switching ${checkbox.checked ? 'enabled' : 'disabled'}.`, 'good'))
    .catch((error) => { toast(error.message, 'bad'); checkbox.checked = !checkbox.checked; });
});

el('filter').addEventListener('input', (event) => {
  filterTerm = event.target.value;
  renderCandidates();
});

function connect() {
  const stream = new EventSource('/api/events');
  stream.onmessage = (event) => {
    snapshot = JSON.parse(event.data);
    render();
  };
  stream.onerror = () => {
    el('stream-state').className = 'pill pill-bad';
    el('stream-state').textContent = 'reconnecting…';
    // EventSource retries on its own; nothing to do but wait.
  };
  stream.onopen = () => {
    el('stream-state').textContent = 'live';
  };
}

// Relative timestamps ("3m ago") need a periodic redraw to stay honest.
setInterval(() => { if (snapshot) render(); }, 15000);
setInterval(refreshLogs, 15000);

connect();
refreshLogs();
