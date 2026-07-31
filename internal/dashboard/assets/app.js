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
  if (options.current) tags.push('<span class="tag tag-current">current</span>');
  if (candidate.p2p) tags.push('<span class="tag tag-p2p">p2p</span>');
  if (candidate.stream) tags.push('<span class="tag">stream</span>');
  if (candidate.secure_core) tags.push('<span class="tag">secure core</span>');
  if (candidate.tor) tags.push('<span class="tag">tor</span>');
  tags.push(candidate.free
    ? '<span class="tag tag-free">free</span>'
    : '<span class="tag tag-paid">paid</span>');
  if (candidate.ipv6) tags.push('<span class="tag">ipv6</span>');
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

// rate renders a rate in bits per second, scaling to the unit that fits.
//
// No conversion here: the value arrives in bits, because every source converts at the
// boundary where it is read and the thresholds are configured in megabits. Bits because that
// is how a link speed is quoted everywhere else - an ISP sells 100/10 Mbit, iperf and
// speedtest report bits - so "am I saturating the connection?" needs no arithmetic.
function rate(bitsPerSecond) {
  const bits = Number(bitsPerSecond || 0);
  if (bits < 1000) return `${Math.round(bits)} bit/s`;
  const units = ['kbit/s', 'Mbit/s', 'Gbit/s', 'Tbit/s'];
  let scaled = bits;
  for (const unit of units) {
    scaled /= 1000;
    if (scaled < 1000) return `${trimZero(scaled)} ${unit}`;
  }
  return `${trimZero(scaled / 1000)} Pbit/s`;
}

// trimZero drops a trailing ".0": "90 Mbit/s" reads better than "90.0 Mbit/s", and the extra
// digit is noise at that magnitude.
function trimZero(value) {
  return value.toFixed(1).replace(/\.0$/, '');
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

// fastestRateCell renders the highest rate ever measured on a server.
//
// Separate from the volume, because they answer different questions and share a unit
// family: "412 GB" and "11 MB/s" describe the same server and mean nothing alike. A rate
// reflects the swarm as much as the server, so it is labelled as the best it has managed
// rather than as a capability.
function fastestRateCell(measured) {
  if (!measured || !measured.transfer_known) {
    return '<span class="muted">not measured</span>';
  }
  if (!measured.max_download && !measured.max_upload) {
    return '<span class="muted">nothing measured yet</span>';
  }

  const down = rate(measured.max_download || 0);
  const up = rate(measured.max_upload || 0);
  const title = `The fastest readings taken during this stay on the server: ${down} down, `
    + `${up} up. Deliberately not all-time - a rate is a claim about conditions, and what a `
    + 'server managed two months ago says nothing about what it will do now. Reconnecting '
    + 'replaces it with the first real reading of the new stay, not before. A rate also '
    + 'reflects the swarm and your peers as much as the server.';

  return `<div title="${escapeHTML(title)}">${escapeHTML(down)} down</div>`
    + `<div class="muted" title="${escapeHTML(title)}">${escapeHTML(up)} up</div>`;
}

// transferredCell renders how much data has ever moved through one server.
//
// Not comparable with the qBittorrent card's session totals, which cover every server and
// reset when qBittorrent restarts. This figure is attributed to this server alone, kept for
// the life of the server, and is a floor: an interval spanning a switch is credited to
// neither server rather than guessed at.
function transferredCell(measured) {
  if (!measured || !measured.transfer_known) {
    return '<span class="muted">not measured</span>';
  }
  if (!measured.downloaded && !measured.uploaded) {
    return '<span class="muted">not used</span>';
  }

  const down = bytes(measured.downloaded || 0);
  const up = bytes(measured.uploaded || 0);
  const visits = measured.visits > 1 ? ` across ${measured.visits} stays` : '';
  const title = `${down} down, ${up} up through this server in total${visits}. `
    + 'Counted from qBittorrent\'s own session counters by difference, so it covers what '
    + 'this tool observed - not traffic from before it was watching. Kept until Proton '
    + 'retires the server.';

  // Both lines carry their direction. Leaving it off the first one was fine while it held
  // the larger number and could be read as the obvious one, but a server that only ever
  // seeded shows "0 B" on that line - which reads as a total, not as a direction.
  return `<div title="${escapeHTML(title)}">${escapeHTML(down)} down</div>`
    + `<div class="muted" title="${escapeHTML(title)}">${escapeHTML(up)} up</div>`;
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

// outcome renders the result of the most recent attempt at something.
//
// Every integration now answers the same two questions in the same place - can we
// reach it, and did the last exchange work - so they are rendered the same way rather
// than each card inventing its own wording.
function outcome(node, attempted, failed, error) {
  const el_ = el(node);
  if (!el_) return;
  if (!attempted) {
    el_.innerHTML = '<span class="muted">not yet</span>';
    el_.removeAttribute('title');
    return;
  }
  el_.innerHTML = failed ? '<span class="no">failed</span>' : '<span class="ok">successful</span>';
  if (failed && error) el_.title = error; else el_.removeAttribute('title');
}

function boolRow(node, value) {
  const el_ = el(node);
  if (!el_) return;
  el_.innerHTML = value ? '<span class="ok">true</span>' : '<span class="no">false</span>';
}

// parseCoordinates reads Gluetun's "lat,lon" location string.
//
// Returns null unless both values parse and fall inside the valid ranges, so a partial
// or malformed value produces no link rather than one pointing nowhere.
function parseCoordinates(location) {
  const parts = String(location || '').split(',');
  if (parts.length !== 2) return null;
  const lat = Number(parts[0]);
  const lon = Number(parts[1]);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return null;
  if (Math.abs(lat) > 90 || Math.abs(lon) > 180) return null;
  return [lat, lon];
}

// stateSpan colours a lifecycle word: running is good, crashed is bad, anything else is
// neither. Shared so every such row reads the same - the DNS row used to be plain text
// beside a coloured VPN row, which made the two look like different kinds of fact.
function stateSpan(state) {
  const value = state || 'unknown';
  const level = value === 'running' ? 'ok'
    : value === 'crashed' || value === 'failed' ? 'no'
      : 'muted';
  return `<span class="${level}">${escapeHTML(value)}</span>`;
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
  renderStatusStrip();
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

// One line for "is everything working?".
//
// Every chip is derived from the same snapshot the cards use, so the two can never
// disagree; the strip is a summary, not a second source of truth. Each carries the
// detail as a tooltip, so a bad chip explains itself without hunting for the card.
function renderStatusStrip() {
  const gluetun = snapshot.gluetun;
  const proton = snapshot.proton;
  const servers = snapshot.servers_file;
  const transfer = snapshot.transfer || {};
  const selection = snapshot.selection;
  const chips = [];

  const chip = (label, value, level, detail) => chips.push(
    `<span class="chip chip-${level}"${detail ? ` title="${escapeHTML(detail)}"` : ''}>`
    + `<span class="chip-label">${escapeHTML(label)}</span><b>${escapeHTML(value)}</b></span>`);

  // The tunnel first: nothing else matters if it is down.
  if (!gluetun.reachable) {
    chip('Gluetun', 'unreachable', 'bad', gluetun.last_error
      || 'The control server did not answer. Switching is paused; the server list is still maintained.');
  } else {
    const running = gluetun.status === 'running';
    chip('Tunnel', gluetun.status || 'unknown',
      running ? 'good' : gluetun.status === 'crashed' ? 'bad' : 'warn',
      running ? '' : 'The tunnel is not running, so it cannot be moved.');
  }

  chip('ProtonVPN', proton.last_fetch_error ? 'error' : proton.logged_in ? 'signed in' : 'signed out',
    proton.last_fetch_error ? 'bad' : proton.logged_in ? 'good' : 'warn',
    proton.last_fetch_error || (proton.from_cache ? 'Using the cached server list.' : ''));

  // Whether the data written here is being read at all - silent when wrong.
  chip('Server data', servers.ignored ? 'ignored' : servers.last_write ? 'written' : 'not written',
    servers.ignored ? 'bad' : servers.last_write ? 'good' : 'warn',
    servers.ignored_reason || '');

  if (transfer.configured) {
    chip('qBittorrent', transfer.reachable ? 'connected' : 'unreachable',
      transfer.reachable ? 'good' : 'bad', transfer.last_error || '');
    const verdict = transfer.port_forwarding || 'unknown';
    chip('Port forwarding', verdict,
      verdict === 'working' ? 'good' : verdict === 'unknown' || verdict === 'not requested' ? 'warn' : 'bad',
      transfer.port_forwarding_detail || '');

    // The live rates, immediately before the switching verdict they explain: cause, then
    // effect.
    //
    // "Transfer" rather than "Bandwidth": bandwidth is capacity, and calling 11 MB/s the
    // bandwidth of a link that could do ten times that is simply wrong. It is also the word
    // this tool uses everywhere else - transfer awareness, "a transfer is in progress".
    //
    // One chip for both directions, with each direction named in words. A slash - "11.2 / 1.1"
    // - is shorter and relies on the reader knowing that down comes first; in a bar this
    // small there is room to just say it.
    //
    // Deliberately uncoloured. These are instantaneous and the verdict beside them is decided
    // on the windowed average, so colouring them against the threshold would have them
    // disagree with it every time traffic dips between pieces - which is exactly what
    // averaging exists to absorb. The chip beside them carries the verdict; the tooltip
    // carries the average that produced it.
    const down = transfer.download_speed || 0;
    const up = transfer.upload_speed || 0;
    const detail = [`Instantaneous: ${rate(down)} down, ${rate(up)} up.`];
    if (transfer.busy_window) {
      detail.push(`Switching is decided on the ${transfer.busy_window} average, which is `
        + `${rate(transfer.average_download)} down and ${rate(transfer.average_upload)} up.`);
    }
    const triggers = [
      transfer.busy_download_threshold ? `${rate(transfer.busy_download_threshold)} down` : '',
      transfer.busy_upload_threshold ? `${rate(transfer.busy_upload_threshold)} up` : '',
    ].filter(Boolean);
    detail.push(triggers.length
      ? `Switching is deferred at ${triggers.join(' or ')}.`
      : 'Neither direction is a trigger for deferring a switch.');
    if (transfer.source) {
      detail.push(`Measured by ${transfer.source}.`);
    }
    if (!transfer.reachable && transfer.has_reading) {
      detail.push('qBittorrent is not answering, so this is the last reading taken - which is '
        + 'what keeps deferring switches until it answers again.');
    }
    // "idle" rather than "0 B/s down · 0 B/s up", which is a lot of characters to say nothing
    // and is the usual state.
    chip('Transfer', down || up ? `${rate(down)} down · ${rate(up)} up` : 'idle',
      transfer.reachable ? 'info' : 'warn', detail.join(' '));
  }

  // What the engine will actually do, which is the question behind all of the above.
  if (transfer.busy) {
    chip('Switching', 'on hold', 'warn',
      `A transfer is in progress${transfer.deferred_for ? ` (${transfer.deferred_for})` : ''}, `
      + 'so automatic switching is deferred.');
  } else if (!selection.auto_switch) {
    chip('Switching', 'manual only', 'warn', 'Automatic switching is turned off.');
  } else {
    chip('Switching', 'automatic', 'good', selection.explanation || '');
  }

  el('status-strip').innerHTML = chips.join('');
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
          <button type="submit" class="control small">Submit code</button>
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
  // "not probed" everywhere, not "unmeasured": it is the same fact as in the candidate table
  // and the detail panel - the prober only covers LATENCY_TOP_N servers - and naming one fact
  // three ways makes a reader wonder which of the three they are looking at.
  text('current-rtt', current && current.rtt_known ? `${current.rtt_ms} ms` : 'not probed');
  text('current-score', current && !current.excluded ? current.score.toFixed(3) : '–');
  text('current-rank', current && current.rank
    ? `#${current.rank} of ${snapshot.candidates_total}`
    : current && current.excluded ? 'not in allowed set' : '–');

  // How long the tunnel has been where it is - the quickest answer to "is it flapping?".
  // Blank unless this tool put it there: if Gluetun moved on its own, or the tunnel was
  // already up at startup, the arrival time is genuinely unknown.
  const since = snapshot.selection.on_current_since;
  if (since && !since.startsWith('0001-01-01')) {
    const seconds = Math.max(0, Math.round((Date.now() - new Date(since).getTime()) / 1000));
    text('current-since', humanize(seconds));
    el('current-since').title = `Switched here at ${since}.`;
  } else {
    text('current-since', 'unknown');
    el('current-since').title =
      'Only known when this tool made the switch. Gluetun may have moved on its own, or '
      + 'the tunnel was already up when this container started.';
  }

  // Two different facts about the same server, which were briefly one row and read as
  // whichever the reader assumed. Volume is how much has gone through it; rate is how fast
  // it ever went. Click the row in the candidate list for the rest.
  el('current-transferred').innerHTML = transferredCell(current && current.stats);
  el('current-throughput').innerHTML = fastestRateCell(current && current.stats);
  // Whether Gluetun even asks for a port distinguishes "not yet" from "never".
  const ports = gluetun.forwarded_ports || [];
  const requested = gluetun.port_forwarding_enabled;
  text('current-port', ports.length
    ? ports.join(', ') + (snapshot.gluetun.exit_current ? '' : ' (last seen)')
    : requested === false ? 'not requested' : 'none');

}

function renderBest() {
  const best = snapshot.selection.best;
  const selection = snapshot.selection;

  text('best-name', best ? best.server_name : '–');
  text('best-where', best ? `${best.country}${best.city ? ' · ' + best.city : ''}` : '');
  text('best-host', best ? best.hostname : '');
  el('best-tags').innerHTML = best ? featureTags(best) : '';
  el('best-load').innerHTML = best ? loadCell(best.load) : '–';
  text('best-rtt', best && best.rtt_known ? `${best.rtt_ms} ms` : 'not probed');
  text('best-score', best ? best.score.toFixed(3) : '–');
  // The same row as on the current server, so the two read across: a candidate that
  // scores better on load and latency may still be one that was measurably slower.
  // Volume only. A rate on a server the tunnel is not using would read as a rate it is
  // achieving now, which is exactly what it is not.
  el('best-transferred').innerHTML = transferredCell(best && best.stats);
  // The improvement is the number that decides whether the best candidate is used at
  // all, so it says so rather than leaving the reader to compare it against the
  // threshold two rows below.
  //
  // Judged only when there is a current server to improve on: with none identified, a
  // switch is due regardless and "too low" would be actively wrong.
  const improvement = selection.improvement ? selection.improvement.toFixed(3) : '0.000';
  const minimum = selection.min_improvement.toFixed(3);
  const judged = Boolean(best && selection.current);
  const enough = selection.improvement >= selection.min_improvement;

  if (!judged) {
    text('improvement', best ? improvement : '–');
  } else if (enough) {
    el('improvement').innerHTML = `<span class="ok">${improvement}</span>`
      + ` <span class="muted">meets ${minimum}</span>`;
    el('improvement').title = 'Big enough to switch on its own merits.';
  } else {
    el('improvement').innerHTML = `<span class="no">${improvement}</span>`
      + ` <span class="no">too low</span> <span class="muted">needs ${minimum}</span>`;
    el('improvement').title =
      `The best candidate scores only ${improvement} better than the current server, and `
      + `SWITCHING_MIN_IMPROVEMENT requires ${minimum}. Reconnecting drops every connection through `
      + 'the tunnel, so a gain this small is not worth it. Lower SWITCHING_MIN_IMPROVEMENT to act on '
      + 'smaller gains, or use "Reconnect to best" to switch anyway.';
  }

  // Rank is a rank. It used to carry the improvement as well, which meant the same
  // number appeared under two different labels in the same card.
  text('best-rank', best ? `#1 of ${snapshot.candidates_total}` : '–');

  text('best-min-improvement', selection.min_improvement.toFixed(3));
  boolRow('best-auto', selection.auto_switch);
  text('best-cooldown', selection.cooldown_remaining
    ? `${selection.cooldown_remaining} left` : 'none');

  // Why the candidate set is narrower than the country filter would suggest. The long
  // explanation lives on hover; the row itself just names the constraint.
  const p2pOnly = (snapshot.gluetun.requirements_adopted || []).includes('port_forward_only');
  const from = snapshot.gluetun.port_forward_requirement_from;
  text('best-restriction', p2pOnly ? `P2P only (${from || 'port forwarding'})` : 'nothing');
  el('best-restriction').title = p2pOnly
    ? 'Proton forwards ports on P2P servers only, so a busier P2P server can legitimately '
      + 'outrank a quieter one. Comes from ' + (from || 'a Gluetun port-forwarding setting') + '.'
    : '';

  // One line, in the engine's own words, for why nothing is happening.
  const decision = selection.explanation
    ? selection.explanation
    : (selection.mode === 'none' ? 'reconnect mode is "none"' : 'switch is due');
  text('best-decision', decision);
}

// parseDuration reads Go's duration format ("5m0s", "1h30m", "90s") into seconds.
// The snapshot carries intervals as Go strings, and comparing against one is what makes
// "overdue" mean a missed refresh rather than an arbitrary age.
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
  // Distinct from Connected: the control server can answer perfectly well while the
  // tunnel itself is stopped or crashed.
  el('gluetun-status').innerHTML = stateSpan(gluetun.status);
  boolRow('gluetun-reachable', gluetun.reachable);
  outcome('gluetun-outcome', !gluetun.last_check.startsWith('0001-01-01'),
    !gluetun.reachable || Boolean(gluetun.last_error), gluetun.last_error);
  text('gluetun-version', gluetun.version || '–');
  text('gluetun-vpn', gluetun.vpn_type || '–');
  text('gluetun-provider', gluetun.provider || '–');
  // Coloured like the VPN row, for the same reason: "running" is a good state and
  // anything else is worth noticing, and the two rows sit next to each other.
  el('gluetun-dns').innerHTML = stateSpan(gluetun.dns_status);

  // The only IPv6 fact Gluetun exposes. Its public-IP endpoint returns a single
  // address, so there is no separate public IPv6 exit to report; whether the tunnel
  // carries IPv6 at all is the answerable question, and it comes from the tunnel
  // interface's own addresses.
  const ipv4 = gluetun.tunnel_ipv4 || [];
  const ipv6 = gluetun.tunnel_ipv6 || [];
  text('gluetun-ipv4', ipv4.length ? ipv4.join(', ') : 'none');
  text('gluetun-ipv6', ipv6.length ? ipv6.join(', ') : 'none');
  el('gluetun-ipv4').title = el('gluetun-ipv6').title =
    "The tunnel interface's own addresses, from Gluetun's WireGuard settings. This is the "
    + 'only IPv6 fact Gluetun exposes: its public-IP endpoint returns a single address, so '
    + 'there is no separate public IPv6 exit address to show.';

  text('gluetun-check', timeAgo(gluetun.last_check));
  text('gluetun-error', gluetun.reachable ? (gluetun.last_error || '') : '');

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
  text('exit-where', place || (running ? '–' : 'tunnel is not running'));
  text('exit-org', exit.organization || '–');
  text('exit-tz', exit.timezone || '–');
  text('exit-hostname', exit.hostname || '–');
  // Gluetun reports "lat,lon". Rendered as a link rather than an embedded map: the
  // page is deliberately self-contained - a strict CSP and no CDN, so it works on an
  // air-gapped network - which rules out map tiles. The link is navigation, not a
  // subresource, so nothing is fetched unless it is clicked.
  const coords = parseCoordinates(exit.location);
  if (coords) {
    const [lat, lon] = coords;
    el('exit-coords').innerHTML =
      `<a href="https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=8/${lat}/${lon}"`
      + ` target="_blank" rel="noreferrer noopener">${lat}, ${lon} ↗</a>`;
    el('exit-coords').title =
      "Opens OpenStreetMap in a new tab. Nothing is loaded until you click: the dashboard "
      + 'itself makes no external requests.';
  } else {
    text('exit-coords', exit.location || '–');
  }

}

// Everything else Gluetun's API reports, including the filters it is enforcing -
// which is usually the reason a specific server was refused.
function renderGluetunDetail() {
  const gluetun = snapshot.gluetun;
  const entries = [
    // Only what the Gluetun card does not already show. Repeating a dozen values here
    // under different names - "Control server" for Connected, "VPN type" for Protocol,
    // "Servers written to" for Paths - meant the same fact read differently depending
    // on where you happened to look.
    ["Gluetun's own updater", gluetun.updater_status || '–'],
    ['Commit', gluetun.commit || '–'],
    ['Built', gluetun.created || '–'],
    ['Port forwarding requested', portForwardingState(gluetun)],
    ['Settings readable', gluetun.settings_readable
      ? 'yes'
      : 'no — PUT /v1/vpn/settings will also be refused'],
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
    entries.push([`Selected ${key}`, values.join(', '),
      'Gluetun\'s live selection, not the filters you configured: pinning a server replaces '
      + 'its countries and cities with that server\'s own. Your SERVER_COUNTRIES is restored '
      + 'when the Gluetun container restarts.']);
  }

  // Rendered into a .kv grid now that this is a band of the Gluetun card rather than a
   // panel of its own, so the rows match every other row on the page.
  el('gluetun-detail').innerHTML = entries
    .map(([key, value, why]) => `<div${why ? ` title="${escapeHTML(why)}"` : ''}>`
      + `<dt>${escapeHTML(key)}</dt><dd>${escapeHTML(value)}</dd></div>`)
    .join('');

}

function renderProton() {
  const proton = snapshot.proton;
  text('proton-count', proton.logicals_count ? String(proton.logicals_count) : '–');
  // What the filters removed, which is the question the raw counts prompt. Derived from
  // the same pair the Filtering band breaks down, so the two can never disagree.
  const stats = snapshot.stats || {};
  const physical = stats.physical_total || 0;
  const kept = stats.physical_kept || 0;
  text('proton-filtered', physical ? `${physical - kept} of ${physical} physical` : '–');
  el('proton-filtered').title =
    'Physical servers Proton listed, minus those that survived every filter. The Filtering '
    + 'band below breaks down which rule removed what.';
  boolRow('proton-login', proton.logged_in);
  outcome('proton-outcome', !proton.last_fetch.startsWith('0001-01-01'),
    Boolean(proton.last_fetch_error), proton.last_fetch_error);
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
  text('servers-count', String(servers.server_count));
  text('servers-layout', servers.ignored ? `${servers.layout || '–'} (ignored)` : (servers.layout || '–'));
  text('servers-path', (servers.paths || [servers.path]).join(', '));
  el('servers-preferred-flag').innerHTML = boolMark(servers.preferred);
  text('servers-mode', servers.write_mode);
  text('servers-schema', String(servers.schema_version));
  text('servers-write', timeAgo(servers.last_write));
  outcome('servers-outcome', !servers.last_write.startsWith('0001-01-01'),
    Boolean(servers.last_error), servers.last_error);
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


  // The instantaneous rates, and separately the averages the thresholds are actually
  // compared against. Showing only the first made the card look like it contradicted
  // its own verdict every time traffic dipped between pieces; the bars belong on the
  // values that decide.
  text('transfer-down-now', rate(transfer.download_speed));
  text('transfer-up-now', rate(transfer.upload_speed));
  el('transfer-down').innerHTML = rateAgainst(transfer.average_download, transfer.busy_download_threshold);
  el('transfer-up').innerHTML = rateAgainst(transfer.average_upload, transfer.busy_upload_threshold);
  text('transfer-window', transfer.busy_window
    ? `${transfer.busy_window} (${transfer.samples} reading${transfer.samples === 1 ? '' : 's'})`
    : 'not averaged');
  el('transfer-window').title = transfer.busy_window
    ? 'Traffic is bursty: a torrent that is plainly active drops to nothing between '
      + 'pieces. Averaging over this window stops a single dip letting a switch through '
      + 'mid-transfer. Set with SWITCHING_BUSY_WINDOW.'
    : 'SWITCHING_BUSY_WINDOW is 0, so the latest reading alone decides.';
  // The configured thresholds, in the unit they are configured in: SWITCHING_BUSY_DOWNLOAD
  // is megabits per second, and this is what that resolved to.
  const threshold = (value) => value ? rate(value) : 'not a trigger';
  text('transfer-down-limit', threshold(transfer.busy_download_threshold));
  text('transfer-up-limit', threshold(transfer.busy_upload_threshold));
  // qBittorrent's own caps, which give the rates context: 900 kB/s means something
  // different against a 1 MB/s cap than against none. They are qBittorrent's settings,
  // not ours, and have no bearing on the busy thresholds above.
  const cap = (limit) => limit ? rate(limit) : 'unlimited';
  text('transfer-down-cap', cap(transfer.download_limit));
  text('transfer-up-cap', cap(transfer.upload_limit));
  el('transfer-down-cap').title = el('transfer-up-cap').title =
    "qBittorrent's own rate limit, set in qBittorrent. Independent of the thresholds "
    + "above, which are this tool's and decide when switching is deferred.";

  // qBittorrent's own session counters: every server since qBittorrent last started.
  //
  // Deliberately labelled apart from the per-server totals in the Server selection card
  // and the candidate list, because the two are not the same quantity and inviting the
  // comparison would be misleading. This one resets when qBittorrent restarts and knows
  // nothing about which server carried what; those are attributed per server, kept for the
  // life of the server, and exclude any interval that could not be attributed.
  text('transfer-down-total', bytes(transfer.download_total));
  text('transfer-up-total', bytes(transfer.upload_total));
  el('transfer-down-total').title = el('transfer-up-total').title =
    "qBittorrent's own counter, across every server, since qBittorrent last started. It "
    + 'will not match the per-server totals elsewhere: those are attributed to individual '
    + 'servers and survive a qBittorrent restart, and they exclude intervals that span a '
    + 'server switch.';
  text('transfer-checked', transfer.has_reading ? timeAgo(transfer.last_check) : 'never');
  outcome('transfer-outcome', transfer.has_reading || Boolean(transfer.last_error),
    !transfer.reachable, transfer.last_error);

  // "Connected" means this tool can reach qBittorrent's API - nothing else.
  //
  // It used to show connection_status here, labelled "qBittorrent is connected",
  // which reads as exactly that but actually reports qBittorrent's *peer*
  // connectivity. Two different questions, and conflating them made a firewalled
  // instance look unreachable and vice versa. connection_status now feeds the
  // port-forwarding verdict, where it belongs.
  el('transfer-connected').innerHTML = transfer.reachable
    ? '<span class="ok">true</span>'
    : '<span class="no">false</span>';

  // Just the verdict. The listen port has a row of its own two lines down, and
  // repeating it here was the same value twice.
  const verdict = transfer.port_forwarding || 'unknown';
  const verdictClass = { working: 'ok', unreachable: 'no', mismatch: 'no' }[verdict] || 'muted';
  el('transfer-portfwd').innerHTML = `<span class="${verdictClass}">${escapeHTML(verdict)}</span>`;
  el('transfer-portfwd').title = transfer.port_forwarding_detail || '';


  text('transfer-version', transfer.version || '–');
  // The port settings are read separately from the rates and can fail on their own, so
  // an unknown port carries the reason rather than leaving it to be guessed at.
  text('transfer-listen', transfer.listen_port ? String(transfer.listen_port) : 'unknown');
  el('transfer-listen').title = transfer.listen_port
    ? 'The port qBittorrent accepts incoming peer connections on. It must match the '
      + 'port Gluetun forwarded, or nothing reaches it.'
    : (transfer.listen_port_error
      || "qBittorrent's port settings have not been read yet.");

  // One line for whether switching is being held back, and why.
  let switching;
  if (transfer.busy) {
    switching = `on hold${transfer.deferred_for ? ` for ${transfer.deferred_for}` : ''}`
      + (transfer.max_defer ? `, until ${transfer.max_defer}` : '');
  } else if (!transfer.has_reading) {
    switching = 'not held back (nothing measured yet)';
  } else {
    switching = 'not held back';
  }
  text('transfer-switching', switching);
  el('transfer-switching').title =
    'Only automatic switching is deferred. "Reconnect to best" and the per-row Use '
    + 'buttons always proceed — an explicit instruction is never overridden.';

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
  text('latency-last', latency.last_run && !latency.last_run.startsWith('0001-01-01')
    ? timeAgo(latency.last_run) : 'never');
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
      data-hostname="${escapeHTML(candidate.hostname)}"
      title="${escapeHTML(candidate.blocked ? blockedWhy : 'Click for details')}">
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
      <td class="num">${transferredCell(candidate.stats)}</td>
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

// The variable groups, in the order they are shown. The prefix is what a variable is
// named after, so grouping by it needs no mapping table to fall out of date.
const SETTING_GROUPS = [
  ['PROTON_', 'ProtonVPN'],
  ['GLUETUN_SERVERS_', 'Server data written for Gluetun'],
  ['GLUETUN_', 'Gluetun'],
  ['FILTER_', 'Filtering'],
  ['SCORING_', 'Scoring'],
  ['LATENCY_', 'Latency'],
  ['SWITCHING_', 'Switching'],
  ['QBITTORRENT_', 'qBittorrent'],
  ['DASHBOARD_', 'Dashboard'],
  ['LOG_', 'Logging'],
];

// renderSettings lists every configuration variable as it actually resolved.
//
// Every one, including those left at their defaults: "how is this configured" is not
// answerable from the ones somebody remembered to set. This used to be a hand-written list
// of about half of them, which drifted every time a variable was added or renamed - so the
// list now comes from the engine, recorded while the configuration was parsed.
//
// Secret values never arrive here at all. The engine sends "set" or "not set" for those,
// which is the diagnostic part and none of the sensitive part.
function renderSettings() {
  const variables = (snapshot.settings || {}).variables || [];
  if (!variables.length) {
    el('settings').innerHTML = '<div><dt>unavailable</dt><dd class="muted">'
      + 'this build did not report its configuration</dd></div>';
    return;
  }

  const grouped = new Map(SETTING_GROUPS.map(([, label]) => [label, []]));
  const other = [];
  for (const variable of variables) {
    const group = SETTING_GROUPS.find(([prefix]) => variable.name.startsWith(prefix));
    (group ? grouped.get(group[1]) : other).push(variable);
  }
  if (other.length) grouped.set('Other', other);

  const row = (variable) => {
    // Booleans get the colours they have everywhere else on the page: green for true, red
    // for false. Everything else is body text.
    //
    // Defaults used to be greyed out here, which was a mistake - it dimmed most of the panel
    // (most variables are defaults) and it collided with the meaning grey already carries
    // elsewhere, which is "absent" rather than "in effect". A default is very much in
    // effect. Whether it was chosen is marked on the row instead, and said in the tooltip.
    const value = escapeHTML(variable.value);
    const shown = variable.value === 'true' ? '<span class="ok">true</span>'
      : variable.value === 'false' ? '<span class="no">false</span>'
        : value;
    // "set"/"not set" is deliberately left uncoloured: an unset optional credential -
    // GLUETUN_PASSWORD, say - is not a fault, and red would claim it was.
    const title = variable.secret
      ? 'A credential. Its value is never sent to this page.'
      : variable.configured ? 'Set in the environment.' : 'Not set; this is the default.';
    const marker = variable.configured ? ' class="configured"' : '';
    return `<div${marker}><dt title="${escapeHTML(title)}">${escapeHTML(variable.name)}</dt>`
      + `<dd title="${escapeHTML(title)}">${shown}</dd></div>`;
  };

  let html = '';
  for (const [label, entries] of grouped) {
    if (!entries.length) continue;
    html += `<div class="settings-group"><h3 class="card-section">${escapeHTML(label)}</h3>`
      + `<dl class="kv">${entries.map(row).join('')}</dl></div>`;
  }
  el('settings').innerHTML = html;
}

function renderStats() {
  const stats = snapshot.stats || {};
  // Only the breakdown. The totals are rows of their own above - "Logical servers",
  // "Candidates", "Filtered out" - and repeating them here as "kept of total" said the
  // same thing a second way.
  const entries = [
    ['Skipped: disabled by Proton', stats.disabled_skipped || 0],
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

/* ---------- collapsing ---------- */

// The candidate table is the tallest thing on the page and not always wanted. The
// choice is remembered, because re-hiding it on every reload would be worse than not
// offering the toggle at all.
const collapseKey = (target) => `collapsed:${target}`;

function applyCollapse(button) {
  const target = button.dataset.collapse;
  const body = el(target);
  if (!body) return;
  let hidden = false;
  try {
    hidden = localStorage.getItem(collapseKey(target)) === '1';
  } catch { /* storage can be unavailable; defaulting to shown is the safe way round */ }
  body.hidden = hidden;
  button.textContent = hidden ? 'Show' : 'Hide';
  button.setAttribute('aria-expanded', String(!hidden));
}

function toggleCollapse(button) {
  const target = button.dataset.collapse;
  const body = el(target);
  if (!body) return;
  const hidden = !body.hidden;
  try {
    localStorage.setItem(collapseKey(target), hidden ? '1' : '0');
  } catch { /* not being able to remember it is not a reason to refuse the toggle */ }
  applyCollapse(button);
}

/* ---------- wiring ---------- */

document.addEventListener('click', (event) => {
  // Starting or stopping one of Gluetun's loops. The destructive direction asks first:
  // stopping the VPN drops every connection through it and stays stopped.
  const lifecycle = event.target.closest('button[data-lifecycle]');
  if (lifecycle) {
    const confirmation = lifecycle.dataset.confirm;
    if (confirmation && !confirm(confirmation)) return;
    const status = lifecycle.dataset.status;
    runAction(lifecycle, lifecycle.dataset.lifecycle, { status },
      `${lifecycle.textContent.trim()} requested.`);
    return;
  }
  const collapse = event.target.closest('button[data-collapse]');
  if (collapse) {
    toggleCollapse(collapse);
    return;
  }
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
    return;
  }

  // A candidate row opens its detail panel. Checked last, and only for clicks that were
  // not on a control: the Use button lives inside the row, and a click that both
  // switched the tunnel and opened a panel would be indefensible.
  const row = event.target.closest('tr[data-hostname]');
  if (row && !event.target.closest('button, a, input')) {
    openCandidateModal(row.dataset.hostname);
  }
});

// The detail panel for one candidate.
//
// Read-only. Everything here is either already in the snapshot or fetched from
// /api/history for this one server - the series are deliberately not in the snapshot,
// because attaching 48 readings to each of several hundred rows would put tens of
// thousands of points on the wire on every update to show the one panel someone opened.
async function openCandidateModal(hostname) {
  const candidate = (snapshot.candidates || []).find((entry) => entry.hostname === hostname);
  if (!candidate) return;
  const modal = el('candidate-modal');

  text('modal-name', candidate.server_name);
  text('modal-host', candidate.hostname);
  el('modal-tags').innerHTML = featureTags(candidate, { current: candidate.is_current });

  // A blocked server is listed but unusable, and the panel is where there is finally
  // room to say which Gluetun setting is responsible.
  const blocked = el('modal-blocked');
  blocked.hidden = !candidate.blocked;
  blocked.textContent = candidate.blocked
    ? `Gluetun cannot use this server: it enforces ${(candidate.blocked_by || []).join(', ') || 'a filter'}.`
    : '';

  text('modal-server-name', candidate.server_name);
  text('modal-logical-id', candidate.logical_id || 'unknown');
  text('modal-tier', tierName(candidate.tier));
  text('modal-entry-ip', candidate.entry_ip || 'unknown');
  // Absent means "not recorded", which is a different fact from "no IPv6": the address
  // is only kept when GLUETUN_SERVERS_INCLUDE_IPV6 is on.
  text('modal-entry-ipv6', candidate.entry_ipv6
    || (candidate.ipv6 ? 'not recorded (GLUETUN_SERVERS_INCLUDE_IPV6 is off)' : 'none'));
  text('modal-exit-ip', candidate.exit_ip || 'unknown');
  text('modal-wireguard', candidate.wireguard ? 'present' : 'missing');
  el('modal-wireguard').title = candidate.wireguard
    ? 'Proton published a WireGuard public key for this server.'
    : 'Without a key this server cannot be used for WireGuard at all.';

  text('modal-country', candidate.country || 'unknown');
  text('modal-city', candidate.city || 'not given');
  // Proton fills Region in for some servers and not others, which is why it is here and
  // not a column that would be empty most of the time.
  text('modal-region', candidate.region || 'not given');

  text('modal-rank', candidate.blocked ? 'not selectable'
    : candidate.rank ? `#${candidate.rank} of ${snapshot.candidates_total}` : 'unranked');
  text('modal-score', candidate.score.toFixed(3)
    + (candidate.rtt_known ? '' : ' (latency assumed, not probed)'));
  text('modal-score-load', candidate.score_load.toFixed(4));
  text('modal-score-latency', candidate.score_latency.toFixed(4));
  text('modal-score-proton', candidate.score_proton.toFixed(4));
  // Proton's own number, before this tool weights it. The penalty above is what it
  // becomes; this is the input, and the two are worth being able to compare.
  text('modal-proton-score', String(candidate.proton_score ?? 0));
  el('modal-load').innerHTML = loadCell(candidate.load);
  text('modal-rtt', candidate.rtt_known ? `${candidate.rtt_ms} ms` : 'not probed');

  // Everything here is already in the snapshot: the statistics are a dozen fixed numbers
  // per server rather than a series, small enough to travel with it. There is no fetch,
  // so no loading state and no chance of a slow answer painting the previous server's
  // figures into this panel.
  renderCandidateStats(candidate.stats);

  if (!modal.open) modal.showModal();
}

// renderCandidateStats fills the two observed-over-time bands.
//
// Absent figures read as absent. A server that has never been probed for latency, or a
// deployment with no qBittorrent, must not show a zero - "never measured" and "measured as
// zero" are different claims, and only one of them is ours to make.
function renderCandidateStats(stats) {
  const measured = stats || {};

  const percent = (value) => value ? `${value}%` : 'unknown';
  text('modal-stat-load', percent(measured.load));
  text('modal-stat-load-lowest', percent(measured.load_lowest));
  text('modal-stat-load-highest', percent(measured.load_highest));
  el('modal-stat-load-lowest').title = 'The quietest this server has been seen. Lowest is '
    + 'best for load.';
  el('modal-stat-load-highest').title = 'The busiest it has been seen. A server that is '
    + 'quiet now but has peaked at 95% is a different proposition from one that never has.';

  // Latency is only probed for LATENCY_TOP_N servers, so never having a figure is normal
  // rather than a fault, and the row says which.
  const milliseconds = (value) => value ? `${value} ms` : 'not probed';
  text('modal-stat-rtt', milliseconds(measured.rtt_ms));
  text('modal-stat-rtt-lowest', milliseconds(measured.rtt_lowest_ms));
  text('modal-stat-rtt-highest', milliseconds(measured.rtt_highest_ms));
  el('modal-stat-rtt-lowest').title = 'The best round trip ever measured. Lowest is best.';
  el('modal-stat-rtt-highest').title = 'The worst ever measured, which is what a stable '
    + 'connection is judged against.';

  text('modal-stat-samples', measured.samples
    ? `${measured.samples} load reading${measured.samples === 1 ? '' : 's'}`
    : 'none yet');
  el('modal-stat-samples').title = 'How much evidence is behind the extremes above. One '
    + 'reading per loads refresh, for every candidate.';
  text('modal-stat-visits', measured.visits
    ? `${measured.visits} time${measured.visits === 1 ? '' : 's'}`
    : 'never used');
  // timeAgo already reports a zero time as "never", which is what an unmeasured server is.
  text('modal-stat-first', timeAgo(measured.first_seen));

  // Three different reasons a transfer figure can be missing, and they must not be
  // conflated - the first is about this deployment, the other two about this server:
  //
  //   1. nothing is measuring at all, because qBittorrent is not configured;
  //   2. qBittorrent is configured but this server has never been measured;
  //   3. it has been measured and the answer is zero.
  //
  // Whether the integration exists is a property of the deployment, so it comes from the
  // snapshot rather than being inferred from a per-server field. Inferring it was a bug:
  // a candidate with no record yet reported "needs qBittorrent" on a deployment where
  // qBittorrent was working perfectly well.
  const transferRows = ['modal-stat-downloaded', 'modal-stat-uploaded',
    'modal-stat-max-down', 'modal-stat-max-up', 'modal-stat-reads',
    'modal-stat-last-transfer'];

  if (!(snapshot.transfer || {}).configured) {
    for (const id of transferRows) {
      text(id, 'needs qBittorrent');
      el(id).title = 'Set QBITTORRENT_URL and QBITTORRENT_API_KEY to measure transfers. '
        + 'Gluetun exposes no throughput information of its own.';
    }
    return;
  }
  // transfer_known is still consulted, for the narrower case it exists for: figures a
  // previous run left behind must not be presented as current.
  if (!measured.transfer_known) {
    for (const id of transferRows) {
      text(id, 'not measured');
      el(id).title = 'This server has not carried traffic while this tool was watching, '
        + 'so there is nothing measured for it yet.';
    }
    return;
  }

  const volume = (value) => value ? bytes(value) : 'nothing yet';
  text('modal-stat-downloaded', volume(measured.downloaded));
  text('modal-stat-uploaded', volume(measured.uploaded));
  el('modal-stat-downloaded').title = el('modal-stat-uploaded').title =
    'Every byte counted through this server, across every stay. Never reset by a '
    + 'reconnect; removed only when Proton retires the server. Counted from qBittorrent\'s '
    + 'session counters by difference, so it covers what this tool observed.';

  const speed = (value) => value ? rate(value) : 'not measured';
  text('modal-stat-max-down', speed(measured.max_download));
  text('modal-stat-max-up', speed(measured.max_upload));
  el('modal-stat-max-down').title = el('modal-stat-max-up').title =
    (measured.current
      ? 'The fastest readings so far during this stay on the server. '
      : 'The fastest readings during the most recent stay on this server. ')
    + 'Not all-time: a rate is a claim about conditions, and one from months ago says '
    + 'nothing about the server now. Reconnecting replaces it with the first real reading '
    + 'of the new stay. It reflects the swarm and your peers as much as the server, so it '
    + 'is the best it has managed rather than a guarantee.';

  // Which stay the rates above belong to, since "fastest" means nothing without it.
  text('modal-stat-stay', measured.current ? 'this stay, in progress'
    : measured.visits ? `the most recent of ${measured.visits} stay`
      + `${measured.visits === 1 ? '' : 's'}` : 'no stay yet');
  text('modal-stat-reads', measured.transfer_readings
    ? `${measured.transfer_readings}` : 'none');
  text('modal-stat-last-transfer', timeAgo(measured.last_transfer_at));
}


// tierName maps Proton's plan level to its name. Reported as unknown rather than guessed
// when Proton did not say, and the raw number is kept alongside so an unfamiliar tier is
// still legible.
function tierName(tier) {
  if (tier === undefined || tier === null) return 'unknown';
  const names = { 0: 'Free', 1: 'Basic', 2: 'Plus', 3: 'Visionary' };
  return names[tier] ? `${names[tier]} (${tier})` : `tier ${tier}`;
}

el('modal-close').addEventListener('click', () => el('candidate-modal').close());

// Clicking the backdrop closes it. The dialog element itself is the click target only
// when the click landed outside its content box.
el('candidate-modal').addEventListener('click', (event) => {
  if (event.target === el('candidate-modal')) el('candidate-modal').close();
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

// Restore any remembered collapsed panels before the first render.
for (const button of document.querySelectorAll('button[data-collapse]')) {
  applyCollapse(button);
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
  // Text and colour set together, both describing the stream.
  //
  // The colour used to be set in renderGluetun from the *VPN* status, which meant a
  // perfectly healthy update stream turned red whenever the tunnel was stopped - a pill
  // labelled "Live update stream" saying "live" in red - and a dead stream went green on the
  // next render while still reading "reconnecting…".
  stream.onerror = () => {
    el('stream-state').className = 'pill pill-bad';
    el('stream-state').textContent = 'reconnecting…';
    // EventSource retries on its own; nothing to do but wait.
  };
  stream.onopen = () => {
    el('stream-state').className = 'pill pill-good';
    el('stream-state').textContent = 'live';
  };
}

// Relative timestamps ("3m ago") need a periodic redraw to stay honest.
setInterval(() => { if (snapshot) render(); }, 15000);
setInterval(refreshLogs, 15000);

connect();
refreshLogs();
