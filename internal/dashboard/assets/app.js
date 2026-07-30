// Dashboard front end. No frameworks and no external requests: the page is
// served from the container and must work on an isolated network.
//
// State arrives over server-sent events; every render is a full redraw from the
// latest snapshot, which keeps the UI impossible to get out of sync.
'use strict';

const el = (id) => document.getElementById(id);

// Values are truncated with an ellipsis rather than wrapped, so the full text is
// always attached as a tooltip - nothing becomes unreadable, and nothing is lost.
const text = (id, value) => {
  const node = el(id);
  if (!node) return;
  const string = value === undefined || value === null ? '' : String(value);
  node.textContent = string;
  if (string && string !== '–' && string !== '—') {
    node.title = string;
  } else {
    node.removeAttribute('title');
  }
};

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

// Feature badges for a server. Shared by the table and the summary cards so the
// same server never appears to have different properties in two places.
function featureTags(candidate, options = {}) {
  const tags = [];
  if (options.current) tags.push('<span class="tag">current</span>');
  if (candidate.p2p) tags.push('<span class="tag tag-p2p">p2p</span>');
  if (candidate.stream) tags.push('<span class="tag">stream</span>');
  if (candidate.secure_core) tags.push('<span class="tag">secure core</span>');
  if (candidate.tor) tags.push('<span class="tag">tor</span>');
  tags.push(candidate.free
    ? '<span class="tag tag-free">free</span>'
    : '<span class="tag tag-paid">paid</span>');
  if (candidate.wireguard) tags.push('<span class="tag">wg</span>');
  if (candidate.excluded) tags.push('<span class="tag tag-excluded">outside filters</span>');
  // A tag as well as the row colour, so the row does not depend on colour alone to
  // read as unusable.
  if (candidate.blocked) {
    const by = (candidate.blocked_by || []).join(', ');
    tags.push(`<span class="tag tag-blocked" title="Gluetun enforces ${escapeHTML(by)}">cannot use</span>`);
  }
  return tags.join('');
}

// shortHost drops the domain every Proton hostname shares.
//
// In the history panel the cell has to fit two hostnames in half the page width, and
// ".protonvpn.net" is 14 identical characters per name that distinguish nothing. Only
// that exact suffix is removed, so anything unexpected is left alone, and the full
// name stays in the cell's title.
function shortHost(hostname) {
  return String(hostname || '').replace(/\.protonvpn\.net$/, '');
}

// portForwardingState answers only "is Gluetun asking Proton for a port?".
// "unknown" is kept distinct from "off": before Gluetun's settings have been read
// once, claiming it is off would be a guess.
function portForwardingState(gluetun) {
  const requested = gluetun.port_forwarding_enabled;
  if (requested === undefined || requested === null) return 'unknown';
  return requested ? 'on' : 'off';
}

// rate renders bytes per second the way the engine's log does, so the two agree.
function rate(bytesPerSecond) {
  const value = Number(bytesPerSecond || 0);
  if (value < 1000) return `${value} B/s`;
  const units = ['kB/s', 'MB/s', 'GB/s', 'TB/s'];
  let scaled = value;
  for (const unit of units) {
    scaled /= 1000;
    if (scaled < 1000) return `${scaled.toFixed(1)} ${unit}`;
  }
  return `${(scaled / 1000).toFixed(1)} PB/s`;
}

function bytes(total) {
  const value = Number(total || 0);
  if (value < 1000) return `${value} B`;
  const units = ['kB', 'MB', 'GB', 'TB'];
  let scaled = value;
  for (const unit of units) {
    scaled /= 1000;
    if (scaled < 1000) return `${scaled.toFixed(1)} ${unit}`;
  }
  return `${(scaled / 1000).toFixed(1)} PB`;
}

// A rate shown against the threshold that would defer a switch, with a bar so the
// margin is visible at a glance rather than needing two numbers compared by eye.
function rateAgainst(speed, threshold) {
  const shown = escapeHTML(rate(speed));
  if (!threshold) return shown;
  const fraction = Math.min(Number(speed || 0) / Number(threshold), 1);
  const severity = fraction >= 1 ? 'bad' : fraction >= 0.6 ? 'warn' : '';
  return `${shown}<span class="bar ${severity}"><span style="width:${fraction * 100}%"></span></span>`;
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
  renderExit();
  renderGluetunDetail();
  renderProton();
  renderServersFile();
  renderTransfer();
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
    // When Gluetun has disclosed how many servers it knows, say so: a few hundred
    // against thousands written is the unmistakable signature of it running on its
    // own built-in list, and it turns vague advice into a diagnosis.
    const known = snapshot.gluetun.known_hostnames;
    const counts = known
      ? ` It reports knowing <strong>${known}</strong> servers, while
          <strong>${snapshot.candidates_total}</strong> are being offered here.`
      : '';
    alerts.push(`<div class="alert alert-bad"><div>
      <strong>Gluetun is running an older server list</strong>
      It rejected the server offered, which means the server data written here has not been
      loaded yet.${counts}
      Gluetun reads that data only when it starts, so <strong>restart the Gluetun container</strong>
      to pick it up. Alternatively, set <code>UPDATER_PROTONVPN_EMAIL</code> and
      <code>UPDATER_PROTONVPN_PASSWORD</code> on the Gluetun container so its own updater can
      refresh the list without a restart.
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
  if (snapshot.servers_file.ignored) {
    alerts.push(`<div class="alert alert-bad"><div>
      <strong>Gluetun is not reading the server list written here</strong>
      ${escapeHTML(snapshot.servers_file.ignored_reason || '')}
    </div></div>`);
  }
  if (snapshot.gluetun.reachable && !snapshot.gluetun.settings_readable) {
    alerts.push(`<div class="alert alert-bad"><div>
      <strong>Gluetun will not let this tool read or change its settings</strong>
      GET /v1/vpn/settings was refused, so PUT will be too and no server can be pinned.
      Gluetun's default control-server role excludes those routes — set
      <code>HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE</code> on the Gluetun container and give this
      container the matching <code>GLUETUN_API_KEY</code>.
    </div></div>`);
  }
  if (snapshot.proton.account_delinquent) {
    alerts.push(`<div class="alert alert-warn"><div>
      <strong>Proton reports this account as delinquent</strong>
      Connections can be refused while an account is behind on payment, which looks
      identical to a server problem from here.
    </div></div>`);
  }
  if (snapshot.proton.from_cache) {
    const stale = snapshot.proton.cache_stale;
    alerts.push(`<div class="alert alert-${stale ? 'bad' : 'warn'}"><div>
      <strong>Using the cached server list${stale ? ' — and it is old' : ''}</strong>
      Proton could not be reached, so this list came from disk (fetched
      ${escapeHTML(timeAgo(snapshot.proton.last_fetch))}).
      ${stale
        ? 'Utilisation figures that old may no longer reflect reality, so the ranking is a best guess.'
        : 'Utilisation is still reasonably recent; the list is corrected as soon as Proton answers.'}
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
    ? `${current.country}${current.city ? ' · ' + current.city : ''}`
    : 'No server identified yet');
  text('current-host', current ? current.hostname : '');
  el('current-tags').innerHTML = current ? featureTags(current) : '';
  el('current-load').innerHTML = current ? loadCell(current.load) : '–';
  text('current-rtt', current && current.rtt_known ? `${current.rtt_ms} ms` : 'unmeasured');
  text('current-score', current && !current.excluded ? current.score.toFixed(3) : '–');
  text('current-rank', current && current.rank
    ? `#${current.rank} of ${snapshot.candidates_total}`
    : current && current.excluded ? 'not in allowed set' : '–');
  text('current-ip', (gluetun.exit && gluetun.exit.ip) || '–');
  // Whether Gluetun even asks for a port distinguishes "not yet" from "never".
  const ports = gluetun.forwarded_ports || [];
  const requested = gluetun.port_forwarding_enabled;
  text('current-port', ports.length
    ? ports.join(', ') + (snapshot.gluetun.exit_current ? '' : ' (last seen)')
    : requested === false ? 'not requested' : 'none');

  const sources = {
    'pinned': "Identified from Gluetun's own server selection, which is exact.",
    'remembered': 'Identified from the hostname this tool last pinned; Gluetun could not be asked.',
    'public-ip': "Identified by matching Gluetun's public IP to a Proton exit address — " +
      'a weak signal, since Proton publishes the server address rather than the observed one.',
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
  text('best-where', best ? `${best.country}${best.city ? ' · ' + best.city : ''}` : '');
  text('best-host', best ? best.hostname : '');
  el('best-tags').innerHTML = best ? featureTags(best) : '';
  el('best-load').innerHTML = best ? loadCell(best.load) : '–';
  text('best-rtt', best && best.rtt_known ? `${best.rtt_ms} ms` : 'unmeasured');
  text('best-score', best ? best.score.toFixed(3) : '–');
  text('improvement', selection.improvement ? selection.improvement.toFixed(3) : '0.000');

  const parts = [];
  if ((snapshot.gluetun.requirements_adopted || []).includes('port_forward_only')) {
    // Name the setting. "Gluetun requires one" is bewildering to an operator who
    // only ever set VPN_PORT_FORWARDING and never PORT_FORWARD_ONLY.
    const because = snapshot.gluetun.port_forward_requirement_from === 'VPN_PORT_FORWARDING'
      ? 'because Gluetun asks Proton for a forwarded port (VPN_PORT_FORWARDING), and Proton ' +
        'forwards ports on P2P servers only'
      : 'because Gluetun refuses anything else (PORT_FORWARD_ONLY)';
    parts.push(`Only port-forwarding (P2P) servers are considered, ${because} — ` +
      'so a busier server can legitimately win here.');
  }
  parts.push(`Needs ${selection.min_improvement.toFixed(3)} improvement to switch automatically.`);
  if (selection.cooldown_remaining) parts.push(`Cooldown: ${selection.cooldown_remaining} left.`);
  if (!selection.auto_switch) parts.push('Automatic switching is off.');
  if (selection.mode === 'none') parts.push('Reconnect mode is "none": the tunnel is never touched.');
  text('switch-note', parts.join(' '));

  // The engine's own words for why it stayed put. "Nothing is happening" is the state
  // that most needs explaining, and it used to be visible only at debug level.
  text('switch-reasoning', selection.explanation
    ? `Staying put: ${selection.explanation}.`
    : '');
}

// parseDuration reads Go's duration format ("5m0s", "1h30m", "90s") into seconds.
// The snapshot carries intervals as Go strings, and comparing against one is what
// makes "overdue" mean a missed refresh rather than an arbitrary age.
function parseDuration(value) {
  if (!value) return 0;
  let seconds = 0;
  for (const [, amount, unit] of String(value).matchAll(/([\d.]+)(ms|h|m|s|us|ns)/g)) {
    const scale = { h: 3600, m: 60, s: 1, ms: 1e-3, us: 1e-6, ns: 1e-9 }[unit] ?? 0;
    seconds += parseFloat(amount) * scale;
  }
  return seconds;
}

function renderGluetun() {
  const gluetun = snapshot.gluetun;
  text('gluetun-status', gluetun.status || 'unknown');
  el('gluetun-reachable').innerHTML = boolMark(gluetun.reachable);
  text('gluetun-version', gluetun.version || '–');
  text('gluetun-vpn', gluetun.vpn_type || '–');
  text('gluetun-provider', gluetun.provider || '–');
  text('gluetun-dns', gluetun.dns_status || '–');

  text('gluetun-check', timeAgo(gluetun.last_check));
  text('gluetun-error', gluetun.reachable ? (gluetun.last_error || '') : '');

  const stream = el('stream-state');
  stream.className = 'pill ' + (gluetun.status === 'running' ? 'pill-good' : 'pill-bad');
}

// Gluetun's public IP report: this is the exit address the internet actually
// sees, which is the definitive answer to "where am I coming out?".
function renderExit() {
  const exit = snapshot.gluetun.exit || {};
  const running = snapshot.gluetun.status === 'running';

  text('exit-ip', exit.ip || (running ? 'not reported yet' : '—'));
  const current = snapshot.gluetun.exit_current;
  // Proton's region is frequently the same word as the city ("Stockholm,
  // Stockholm, Sweden"), so duplicates are collapsed.
  const place = [...new Set([exit.city, exit.region, exit.country].filter(Boolean))].join(', ');
  text('exit-where', place || (running ? '' : 'Tunnel is not running'));
  text('exit-org', exit.organization || '–');
  text('exit-tz', exit.timezone || '–');
  text('exit-hostname', exit.hostname || '–');
  text('exit-location', exit.location || '–');

  let note = '';
  if (exit.ip && !current) {
    note = `Last seen ${timeAgo(snapshot.gluetun.exit_observed_at)}, while the tunnel was up — ` +
      'not a current reading. It is kept rather than blanked so a poll landing mid-reconnect ' +
      'does not hide a working connection.';
  } else if (!running) {
    note = 'Only queried while the tunnel is running: with it down, Gluetun would report your real address.';
  } else if (!exit.ip) {
    note = 'Gluetun has not resolved the public IP yet.';
  } else {
    const current = snapshot.selection.current;
    if (current && current.exit_ip && current.exit_ip === exit.ip) {
      note = `Matches ${current.server_name}'s Proton exit address, which is how the current server is identified.`;
    }
  }
  text('exit-note', note);
}

// Everything else Gluetun's API reports, including the filters it is enforcing -
// which is usually the reason a specific server was refused.
function renderGluetunDetail() {
  const gluetun = snapshot.gluetun;
  const entries = [
    ['Control server', gluetun.reachable ? 'reachable' : 'unreachable'],
    ['Tunnel status', gluetun.status || 'unknown'],
    ['Version', gluetun.version || '–'],
    ['Commit', gluetun.commit || '–'],
    ['Built', gluetun.created || '–'],
    ['VPN type', gluetun.vpn_type || '–'],
    ['Provider', gluetun.provider || '–'],
    ['DNS status', gluetun.dns_status || '–'],
    ["Gluetun's own updater", gluetun.updater_status || '–'],
    ['Settings readable', gluetun.settings_readable ? 'yes' : 'no — PUT /v1/vpn/settings will also be refused'],
    ['Public IP', (gluetun.exit && gluetun.exit.ip) || '–'],
    // Whether Gluetun asks for a forwarded port at all. The port itself is on the
    // Current server card, and the P2P consequence is on the Best candidate card,
    // so this only needs to answer the plain question.
    ['Port forwarding', portForwardingState(gluetun)],
    ['Forwarded ports', (gluetun.forwarded_ports || []).join(', ') || 'none'],
    ['Servers layout', snapshot.servers_file.layout || '–'],
    ['Servers written to', (snapshot.servers_file.paths || []).join(', ') || '–'],
    ['Preferred flag', snapshot.servers_file.preferred ? 'yes' : 'no'],
    ['Schema version', String(snapshot.servers_file.schema_version || '–')],
  ];

  const adopted = gluetun.requirements_adopted || [];
  if (adopted.length) {
    entries.push(['Requirements adopted', adopted.join(', ')]);
  }
  // How much of the list written here Gluetun can actually reach. It only knows this
  // once Gluetun has refused a hostname, since that is the only time Gluetun
  // enumerates its own list.
  if (gluetun.known_hostnames) {
    entries.push(['Servers Gluetun knows',
      `${gluetun.known_hostnames} (of ${snapshot.candidates_total} offered here)`]);
  }

  // Gluetun's *live* server selection - not the operator's configured filters.
  //
  // Deliberately not labelled "Filter": pinning a server replaces Gluetun's
  // countries and cities with the chosen server's own, so after the first switch
  // these describe the server currently selected rather than SERVER_COUNTRIES as it
  // was set. Calling them filters made that look like lost configuration.
  const selection = gluetun.selection || {};
  for (const [key, values] of Object.entries(selection)) {
    entries.push([`Selected ${key}`, values.join(', ')]);
  }

  el('gluetun-detail').innerHTML = entries
    .map(([key, value]) => `<div><dt>${escapeHTML(key)}</dt><dd>${escapeHTML(value)}</dd></div>`)
    .join('');

  // Explain the "Selected …" rows, because they are the single most surprising thing
  // on this page: an operator who set SERVER_COUNTRIES to three countries sees one.
  const pinnedByUs = (selection.hostnames || []).length > 0;
  text('gluetun-detail-note', pinnedByUs
    ? 'The "Selected …" rows are the selection Gluetun is applying right now, not the '
      + 'filters you configured. Pinning a server replaces Gluetun\'s countries and '
      + 'cities with that server\'s own — otherwise Gluetun would AND them together and '
      + 'a server outside SERVER_COUNTRIES would match nothing, crashing its VPN loop. '
      + 'Your original SERVER_COUNTRIES is restored when the Gluetun container restarts.'
    : '');
}

function renderProton() {
  const proton = snapshot.proton;
  text('proton-count', `${proton.logicals_count} logical servers`);
  el('proton-login').innerHTML = boolMark(proton.logged_in);
  // The account's tier decides which servers are usable at all: Proton lists
  // servers above it, and they refuse the connection.
  const tier = proton.account_tier;
  text('proton-plan', proton.account_plan
    ? `${proton.account_plan}${tier === undefined || tier === null ? '' : ` (tier ${tier})`}`
    : '–');
  text('proton-fetch', timeAgo(proton.last_fetch) + (proton.from_cache ? ' (from cache)' : ''));
  text('proton-loads', timeAgo(proton.last_load_refresh));
  text('proton-next', snapshot.next_runs.server_list || '–');
  text('candidate-count', String(snapshot.candidates_total));
  text('proton-error', proton.last_fetch_error || proton.last_load_error || '');
}

function renderServersFile() {
  const servers = snapshot.servers_file;
  text('servers-count', `${servers.server_count} entries`);
  text('servers-layout', servers.ignored ? `${servers.layout || '–'} (ignored)` : (servers.layout || '–'));
  text('servers-path', (servers.paths || [servers.path]).join(', '));
  el('servers-preferred-flag').innerHTML = boolMark(servers.preferred);
  text('servers-mode', servers.write_mode);
  text('servers-schema', String(servers.schema_version));
  text('servers-write', timeAgo(servers.last_write));
  text('servers-preserved', (servers.preserved_keys || []).join(', ') || 'none');
  text('servers-error', servers.last_error || (servers.ignored ? 'Gluetun keeps no server data on disk, so this is not read.' : ''));
}

// Transfer rates from qBittorrent, and whether they are holding switching back.
//
// The card hides itself entirely when the feature is not configured: an empty panel
// reading "0 B/s" would suggest the tunnel is idle, which is a different claim from
// "nobody is measuring".
function renderTransfer() {
  const transfer = snapshot.transfer || {};
  const card = el('transfer-card');
  card.hidden = !transfer.configured;
  if (!transfer.configured) return;

  text('transfer-rates', transfer.has_reading
    ? `${rate(transfer.download_speed)} ↓  ${rate(transfer.upload_speed)} ↑`
    : 'no reading');
  el('transfer-down').innerHTML = rateAgainst(transfer.download_speed, transfer.busy_download_threshold);
  el('transfer-up').innerHTML = rateAgainst(transfer.upload_speed, transfer.busy_upload_threshold);
  text('transfer-down-limit', transfer.busy_download_threshold
    ? rate(transfer.busy_download_threshold) : 'not a trigger');
  text('transfer-up-limit', transfer.busy_upload_threshold
    ? rate(transfer.busy_upload_threshold) : 'not a trigger');
  text('transfer-total', `${bytes(transfer.download_total)} ↓ / ${bytes(transfer.upload_total)} ↑`);
  text('transfer-checked', transfer.last_check ? timeAgo(transfer.last_check) : 'never');

  // qBittorrent's own connectivity, worth showing next to a port-forwarding setup:
  // "firewalled" there usually means the forwarded port is not reaching it.
  const connection = transfer.connection_status;
  text('transfer-state', connection ? `qBittorrent is ${connection}` : '');

  const tags = [];
  // "Not busy" and "never measured" are different claims, and only the first is
  // about traffic. Saying "idle" with no reading would assert something nobody
  // has looked at.
  if (transfer.busy) {
    tags.push('<span class="tag tag-blocked">switching on hold</span>');
  } else if (!transfer.has_reading) {
    tags.push('<span class="tag tag-excluded">no reading yet</span>');
  } else {
    tags.push('<span class="tag">idle enough to switch</span>');
  }
  if (transfer.version) tags.push(`<span class="tag">${escapeHTML(transfer.version)}</span>`);
  if (!transfer.reachable) tags.push('<span class="tag tag-excluded">stale reading</span>');
  el('transfer-tags').innerHTML = tags.join('');

  const notes = [];
  if (transfer.busy) {
    notes.push(`A transfer is in progress, so automatic switching is deferred${
      transfer.deferred_for ? ` (${transfer.deferred_for} so far)` : ''}.`);
    notes.push(transfer.max_defer
      ? `It will switch anyway after ${transfer.max_defer}.`
      : 'It will wait for as long as the transfer lasts.');
  } else if (!transfer.has_reading) {
    notes.push('qBittorrent has not answered yet, so nothing is known about current traffic. '
      + 'Switching is not being held back — a misconfiguration here must not freeze the tunnel '
      + 'on one server indefinitely.');
  } else {
    notes.push('Nothing is above the thresholds, so switching is not being held back.');
  }
  notes.push('"Reconnect to best" always proceeds — an explicit instruction is never deferred.');
  text('transfer-note', notes.join(' '));

  // An unreachable qBittorrent is shown as an error, but the rates above are kept:
  // the last known values keep deferring switches rather than falling open.
  text('transfer-error', transfer.reachable ? '' : (transfer.last_error || ''));
}

function renderLatency() {
  const latency = snapshot.latency;
  text('latency-median', latency.median_ns ? nanos(latency.median_ns) : 'not probed');
  text('latency-measured', String(latency.measured || 0));
  text('latency-failed', String(latency.failed || 0));
  text('latency-best', nanos(latency.best_ns));
  text('latency-worst', nanos(latency.worst_ns));
  text('latency-next', snapshot.next_runs.latency || '–');

  // Coverage tells the operator whether the probe budget is large enough.
  const total = snapshot.candidates_total || 0;
  const covered = latency.measured || 0;
  text('latency-coverage', total ? `${covered} of ${total} candidates` : '–');
}

function renderCandidates() {
  const term = filterTerm.toLowerCase();
  const rows = snapshot.candidates.filter((candidate) => !term
    || candidate.server_name.toLowerCase().includes(term)
    || candidate.country.toLowerCase().includes(term)
    || (candidate.city || '').toLowerCase().includes(term)
    || candidate.hostname.toLowerCase().includes(term));

  // Ranking is only as good as the load figures behind it, and nothing on the page
  // said how old those were. Overdue is measured against LOAD_REFRESH_INTERVAL, so it
  // means "a refresh was missed", not merely "some time has passed".
  const refreshed = snapshot.proton.last_load_refresh;
  const overdueAfter = parseDuration(snapshot.settings.load_refresh_interval);
  const ageSeconds = refreshed && !refreshed.startsWith('0001-01-01')
    ? (Date.now() - new Date(refreshed).getTime()) / 1000
    : null;
  const freshness = el('candidates-freshness');
  if (ageSeconds === null) {
    freshness.textContent = '· loads not fetched yet';
    freshness.classList.add('stale');
  } else {
    const stale = overdueAfter > 0 && ageSeconds > overdueAfter * 2;
    freshness.textContent = `· loads ${timeAgo(refreshed)}`;
    freshness.classList.toggle('stale', stale);
    freshness.title = stale
      ? `Expected every ${snapshot.settings.load_refresh_interval}; this is overdue, so the `
        + 'ranking may be based on out-of-date utilisation.'
      : `Refreshed every ${snapshot.settings.load_refresh_interval}.`;
  }

  const selectable = rows.filter((candidate) => !candidate.blocked).length;
  const blockedShown = rows.length - selectable;
  text('candidates-shown', `showing ${selectable} of ${snapshot.candidates_total}`
    + (blockedShown ? ` · ${blockedShown} unusable` : ''));

  el('candidates').tBodies[0].innerHTML = rows.map((candidate) => {
    const scoreTitle = candidate.rtt_known
      ? `load ${candidate.score_load} + latency ${candidate.score_latency} + proton ${candidate.score_proton}`
      : `load ${candidate.score_load} + assumed latency ${candidate.score_latency} (not probed yet) ` +
        `+ proton ${candidate.score_proton}`;

    // A blocked server is listed so it is not simply missing, but it must read as
    // unusable at a glance: Gluetun would refuse the selection outright.
    const blockedBy = (candidate.blocked_by || []).join(', ');
    const blockedWhy = `Gluetun cannot use this server: it enforces ${blockedBy || 'a filter'}`;

    return `<tr class="${candidate.is_current ? 'is-current' : ''} ${candidate.blocked ? 'is-blocked' : ''}"
      ${candidate.blocked ? `title="${escapeHTML(blockedWhy)}"` : ''}>
      <td class="num">${candidate.blocked ? '<span class="muted">–</span>' : candidate.rank}</td>
      <td><div>${escapeHTML(candidate.server_name)}</div><div class="hostname">${escapeHTML(candidate.hostname)}</div></td>
      <td>${escapeHTML(candidate.country)}</td>
      <td>${candidate.city ? escapeHTML(candidate.city) : '<span class="muted">–</span>'}</td>
      <td class="num">${loadCell(candidate.load)}</td>
      <td class="num">${candidate.rtt_known
        ? candidate.rtt_ms + ' ms'
        : '<span class="muted" title="Outside the latency probe budget (LATENCY_TOP_N)">not probed</span>'}</td>
      <td class="num" title="${escapeHTML(scoreTitle)}">${candidate.rtt_known
        ? candidate.score.toFixed(3)
        : '~' + candidate.score.toFixed(3)}</td>
      <td><div class="tags">${featureTags(candidate, { current: candidate.is_current })}</div></td>
      <td class="right">
        <button class="small" data-switch="${escapeHTML(candidate.hostname)}"
          ${candidate.is_current || candidate.blocked ? 'disabled' : ''}
          ${candidate.blocked ? `title="${escapeHTML(blockedWhy)}"` : ''}>Use</button>
      </td>
    </tr>`;
  }).join('');
}

function renderHistory() {
  // The reason sits under the hostnames rather than in a column of its own. Two
  // full hostnames and a sentence like "current server unknown or not a candidate"
  // do not fit side by side in a half-width panel, and the result was a horizontal
  // scrollbar on the one table that should be skimmable.
  const rows = (snapshot.history || []).map((record) => `<tr>
      <td title="${escapeHTML(record.at)}">${timeAgo(record.at)}</td>
      <td title="${escapeHTML(`${record.from || '—'} → ${record.to}`)}">
        <div class="hostname">${escapeHTML(shortHost(record.from) || '—')} → ${escapeHTML(shortHost(record.to))}</div>
        <div class="muted">${escapeHTML(record.reason)}</div>
      </td>
      <td class="num">${record.score_before >= 0 ? record.score_before.toFixed(3) : '–'} → ${record.score_after.toFixed(3)}</td>
      <td>${record.succeeded
        ? `<span class="ok">ok</span>${record.public_ip ? ' · ' + escapeHTML(record.public_ip) : ''}`
        : `<span class="no">failed</span> ${escapeHTML(record.error || '')}`}</td>
    </tr>`);
  el('history').tBodies[0].innerHTML = rows.join('')
    || '<tr><td colspan="4" class="muted">No switches recorded yet.</td></tr>';
  el('clear-history').disabled = (snapshot.history || []).length === 0;
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
    ['Skipped: above account tier', stats.above_tier_skipped || 0],
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

// Clearing throws data away, so both ask first. The switch history is the only
// record of what this tool has done, and it is not recoverable.
el('clear-history').addEventListener('click', (event) => {
  if (!confirm('Discard the recorded switch history? This cannot be undone.')) return;
  runAction(event.currentTarget, '/api/history/clear', {}, 'Switch history cleared.');
});

el('clear-logs').addEventListener('click', async (event) => {
  if (!confirm('Empty the activity log shown here? The container\'s own log stream is untouched.')) return;
  await runAction(event.currentTarget, '/api/logs/clear', {}, 'Activity log cleared.');
  // runAction refreshes the log, but it does so before the toast's own entry has
  // been written; fetch once more so the panel is not left showing nothing at all.
  refreshLogs();
});

el('auto-switch').addEventListener('change', (event) => {
  const checkbox = event.target;
  post('/api/auto-switch', { enabled: checkbox.checked })
    .then(() => toast(`Automatic switching ${checkbox.checked ? 'enabled' : 'disabled'}.`, 'good'))
    .catch((error) => { toast(error.message, 'bad'); checkbox.checked = !checkbox.checked; });
});

// "Why is this server not in the list?" - answered against the raw Proton
// response, so it can explain servers that are not candidates.
el('explain-form').addEventListener('submit', async (event) => {
  event.preventDefault();
  const query = el('explain-query').value.trim();
  const out = el('explain-result');
  if (!query) { out.innerHTML = ''; return; }

  out.innerHTML = '<p class="explain-note">Looking…</p>';
  try {
    const response = await fetch(`/api/explain?q=${encodeURIComponent(query)}`);
    const payload = await response.json();
    if (!response.ok || payload.ok === false) throw new Error(payload.error || 'lookup failed');
    out.innerHTML = renderExplanations(query, payload.matches || []);
  } catch (error) {
    out.innerHTML = `<p class="explain-note error">${escapeHTML(error.message)}</p>`;
  }
});

function renderExplanations(query, matches) {
  if (!matches.length) {
    return `<p class="explain-note">No server matching <code>${escapeHTML(query)}</code> in Proton's
      response. It may be new since the last fetch — try "Refresh server list".</p>`;
  }

  return matches.map((match) => {
    const tags = [
      match.p2p ? 'p2p' : null, match.stream ? 'stream' : null,
      match.secure_core ? 'secure core' : null, match.tor ? 'tor' : null,
      match.free ? 'free' : null, match.enabled ? null : 'disabled by Proton',
    ].filter(Boolean).map((t) => `<span class="tag">${escapeHTML(t)}</span>`).join('');

    const physical = (match.physical || []).map((p) => `<li>
      <span class="hostname">${escapeHTML(p.hostname)}</span> · ${escapeHTML(p.entry_ip)}
      ${p.included
        ? '<span class="ok">used</span>'
        : `<span class="no">not used</span> — ${escapeHTML(p.reason || '')}
           ${p.deduplicated_by ? 'kept instead: ' + escapeHTML(p.deduplicated_by) : ''}`}
    </li>`).join('');

    return `<div class="explain">
      <p><strong>${escapeHTML(match.server_name)}</strong> ·
        ${escapeHTML(match.country)}${match.city ? ' · ' + escapeHTML(match.city) : ''} ·
        load ${match.load}% ${match.included
          ? '<span class="ok">is a candidate</span>'
          : '<span class="no">is not a candidate</span>'}</p>
      <div class="tags">${tags}</div>
      ${match.reasons && match.reasons.length
        ? '<ul class="explain-reasons">' + match.reasons.map((r) => `<li>${escapeHTML(r)}</li>`).join('') + '</ul>'
        : ''}
      ${match.notes && match.notes.length
        ? '<ul class="explain-notes">' + match.notes.map((n) => `<li>${escapeHTML(n)}</li>`).join('') + '</ul>'
        : ''}
      <ul class="explain-physical">${physical}</ul>
    </div>`;
  }).join('');
}

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
