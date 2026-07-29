# gluetun-proton-list-updater

A Go sidecar that keeps a [Gluetun](https://github.com/qdm12/gluetun) container connected to the
**least utilised ProtonVPN server** in the countries you allow — with optional latency-aware
scoring, a web dashboard, and no manual reconnects.

It does four things:

1. Fetches ProtonVPN's full logical server list (authenticated, via SRP).
2. Writes Gluetun's `/gluetun/servers.json` in Gluetun's own schema.
3. Measures round-trip latency to Proton's entry nodes and ranks servers by
   utilisation + latency.
4. Moves the tunnel onto the winner through Gluetun's control server — **without restarting
   the Gluetun container**.

---

## Why this exists

Gluetun picks a *random* server from the ones matching your filters. Proton publishes a live
`Load` percentage per server, and a 5%-loaded server behaves very differently from a
90%-loaded one. This sidecar reads that number, combines it with measured latency, and pins
the best server.

---

## How it works

```
┌────────────────────────┐        Proton API (SRP auth)
│  proton-updater        │ ──── GET /vpn/v1/logicals ─────────▶ full server list + Load
│  (this tool)           │ ──── GET /vpn/v1/loads ────────────▶ cheap utilisation refresh
│                        │ ──── TCP connect to entry IPs ─────▶ latency
│                        │
│  ranking: load+latency │        writes            ┌──────────────────────┐
│                        │ ─────────────────────────▶│ /gluetun/servers.json│
│                        │                          └──────────────────────┘
│                        │        Gluetun control server
│                        │ ──── PUT /v1/vpn/settings ─────────▶ pin hostname + reconnect
│                        │ ──── GET /v1/publicip/ip ──────────▶ verify the switch worked
└────────────────────────┘
```

### The two mechanisms that matter

**Writing `servers.json`.** Gluetun reads this file at startup and merges it with its built-in
list. Two details decide whether your data is actually used, and both are easy to get wrong:

| Requirement | What this tool does |
|---|---|
| The `protonvpn.version` must equal the version compiled into the running Gluetun, or Gluetun logs *"discarded because they have version X"* and silently ignores your file. | Reads the version back out of the `servers.json` Gluetun itself wrote, instead of hardcoding a number that rots. Override with `SERVERS_SCHEMA_VERSION`. |
| The `protonvpn.timestamp` must be newer than Gluetun's built-in one, because Gluetun merges by recency. | Always stamps the current time. |

**Switching servers.** `PUT /v1/vpn/settings` with a one-hostname server selection makes Gluetun
stop the tunnel, apply the selection and start again — a targeted reconnect with no container
restart. The switch is then *verified*: the tool polls Gluetun's public IP until it matches the
chosen server's Proton exit address. "We sent the request" is not the same as "it worked".

The pin carries the chosen server's **country and city as well as its hostname**. That is not
cosmetic: Gluetun ANDs every selection filter, so a hostname alone would still be intersected with
whatever `SERVER_COUNTRIES` the container started with — and a mismatch leaves no server matching,
which crashes Gluetun's VPN loop.

> **Note on new servers.** Gluetun validates a pinned hostname against the list it loaded **at
> startup**, and no endpoint re-reads `servers.json`. A server that only appears in a freshly
> written file is refused until Gluetun's in-memory list is refreshed — see
> [Can Gluetun see a server it did not know at startup?](#can-gluetun-see-a-server-it-did-not-know-at-startup)

---

## Quick start

```bash
git clone https://github.com/robinostlund/gluetun-proton-list-updater
cd gluetun-proton-list-updater

cp .env.example .env
$EDITOR .env          # Proton credentials, WireGuard key, countries

docker compose up -d
```

Dashboard: <http://localhost:8080>

### Requirements and versions

| Component | Minimum | Recommended | Why |
|---|---|---|---|
| **Gluetun** | `v3.31.0` | `v3.41.1` or `latest` (both tested) | `v3.31.0` introduced `/v1/vpn/*`, including `PUT /v1/vpn/settings` — the endpoint that makes a targeted reconnect possible. `v3.39.0` added the `secure_core` and `tor` fields to Gluetun's server model; on older versions those flags are ignored, so Gluetun cannot filter on them. Both **storage layouts** are supported and detected automatically — see below. |
| **Gluetun setting** | `STORAGE_SERVERS_ENABLED=yes` | (the default) | With server storage off, Gluetun keeps no server data on disk and reads none, so the curated list written here is ignored. |
| **Proton account** | paid | paid | Proton's server list has required authentication since 2025 — an unauthenticated `/vpn/v1/logicals` answers `401`. There is no credential-free mode. |
| **Docker Engine** | `20.10` | `24+` | `docker compose` v2 syntax; multi-arch images are `linux/amd64` and `linux/arm64`. |
| **Go** (only to build from source) | `1.23` | `1.24` | The module targets 1.23; the container image builds with 1.24. |

Verified against Gluetun `v3.41.1` and `latest` by integration tests that run against a real
Gluetun container — see [Development](#development). The ProtonVPN schema version has been `4`
throughout, and is detected at runtime regardless.

### Gluetun changed where server data lives — both layouts are handled

This is worth knowing, because getting it wrong is invisible:

| Gluetun | Layout | What it reads |
|---|---|---|
| up to `v3.41.1` | **legacy** | one fat file, `/gluetun/servers.json` |
| current `master` / `:latest` | **directory** | `/gluetun/servers/` with `manifest.json` plus one file per provider, e.g. `/gluetun/servers/protonvpn.json` |

A Gluetun using the directory layout reads the legacy file **only when
`/gluetun/servers/manifest.json` is absent**. So writing just `servers.json` to a current Gluetun
has no effect at all — the tool would look healthy while being entirely ignored.

The layout is therefore **detected on every write**, by looking for the artefacts Gluetun creates
on startup, and the data goes wherever that Gluetun actually reads. On a fresh volume where Gluetun
has not started yet, both are written. Confirmed against `:latest`, which then logs:

```
[storage] Using protonvpn servers from file (marked as preferred)
```

That `preferred` flag (`SERVERS_PREFERRED`, on by default) is what makes it deterministic: Gluetun
uses our list regardless of timestamps. Older versions ignore the unknown field harmlessly and fall
back to the timestamp comparison.

### Two settings on the Gluetun container that are not optional

**1. The control server must allow `/v1/vpn/settings`.** This is the most common setup mistake, and
it fails with a bare `401 Unauthorized`. Gluetun's built-in `public` role covers
`GET`/`PUT /v1/vpn/status`, `/v1/publicip/ip`, `/v1/portforward` and `/v1/updater/status` — but
**not** `/v1/vpn/settings`, which is what pins a specific server. Widen the role:

```yaml
HTTP_CONTROL_SERVER_AUTH_DEFAULT_ROLE: >-
  {"name":"updater","auth":"apikey","apikey":"your-secret"}
```

Then set `GLUETUN_API_KEY` to the same value on this container. (`"auth":"none"` also works and
needs no key, but leaves the control server open to anything on that Docker network.) Without it,
the tool falls back to `RECONNECT_MODE=status`-style behaviour only if you configure it — otherwise
every switch is refused and the dashboard says so.

**2. Do not set `SERVER_NAMES` or `SERVER_NUMBERS` on Gluetun.** Gluetun combines every
server-selection filter with **AND**, and a *list* filter cannot be cleared through its API (an empty
list means "leave unchanged"). A filter this tool cannot overwrite can leave **no** server matching,
and Gluetun then logs `no server found`, crashes its VPN loop, and the tunnel stays down. Do that
filtering here instead.

`SERVER_COUNTRIES`, `SERVER_CITIES` and the `*_ONLY` flags are all fine:

- `countries` and `cities` are overwritten with the chosen server's own values on every pin.
- the boolean `*_ONLY` filters (`PORT_FORWARD_ONLY`, `SECURE_CORE_ONLY`, `TOR_ONLY`, `STREAM_ONLY`, …)
  are **read** from Gluetun and adopted as selection requirements — so a server that satisfies them
  is chosen in the first place — and then **cleared** on the pin, because pinning one hostname is
  already more specific than any of them and Gluetun's built-in view of a server's features can
  disagree with Proton's current data. One disagreement was enough to crash a real tunnel:

  ```
  no server found: … hostname node-se-07.protonvpn.net; port forwarding only
  ```

  There is an integration test for exactly that, verified to fail without the fix.

Also required: the `/gluetun` volume shared between both containers.

### Do not set `STORAGE_FILEPATH` on Gluetun

It is the old name for a setting that no longer means what it looks like, and it has two traps:

```go
// gluetun's own settings reader
filePath := r.Get("STORAGE_FILEPATH", …)
if filePath != nil {
    if *filePath == "" {
        s.ServersEnabled = ptrTo(false)      // an empty value DISABLES storage
    } else {
        s.LegacyServersFilepath = *filePath  // only sets the LEGACY path
    }
} else {
    s.ServersEnabled, … = r.BoolPtr("STORAGE_SERVERS_ENABLED")
    s.ServersPath = r.String("STORAGE_SERVERS_DIRECTORY_PATH")
}
```

1. **It does not switch Gluetun to the legacy layout.** `STORAGE_FILEPATH=/gluetun/servers.json` only
   tells Gluetun where the legacy file to *migrate from* lives. Current Gluetun still uses
   `/gluetun/servers/`, and reads the legacy file only when that directory's `manifest.json` is
   absent — which it never is after Gluetun has started. Verified: with it set, Gluetun still logs
   `Servers directory path: /gluetun/servers/`.
2. **Setting it makes `STORAGE_SERVERS_ENABLED` be ignored entirely** — they are the two branches of
   one `if`. And an *empty* value silently disables server storage, which is easy to do by accident
   with `STORAGE_FILEPATH:` and nothing after it in a compose file. Verified: with
   `STORAGE_FILEPATH=` **and** `STORAGE_SERVERS_ENABLED=yes`, Gluetun logs
   `Storage settings: disabled`.

Leave both unset (the defaults are what this tool expects), or use the current names:
`STORAGE_SERVERS_ENABLED` and `STORAGE_SERVERS_DIRECTORY_PATH`. If you do move the directory, set
`SERVERS_DIR` here to match. Trap 2 is caught by the check described next.

### `STORAGE_SERVERS_ENABLED=yes` is required

It is Gluetun's default, so most setups already have it — but it is worth stating, because turning it
off breaks this tool silently. With server storage disabled Gluetun keeps no server data on disk and
reads none, so the curated list written here is ignored while everything else still looks fine.

The requirement is enforced by observation rather than by trust. When Gluetun answers its control
server but has written no server data of its own, the tool logs a warning, shows a dashboard banner,
and reports itself **unhealthy**:

```
WARN gluetun is not reading the server data written here
     hint="…has written no server data of its own… This tool requires STORAGE_SERVERS_ENABLED=yes
           on the Gluetun container (its default), and requires the same /gluetun volume to be
           mounted into both containers - one of those two is not the case."
```

That check cannot false-positive while Gluetun is down: it only triggers when Gluetun is answering,
and Gluetun writes its server data before its control server starts listening. It also catches a
much more common mistake — **the `/gluetun` volume not actually being shared** between the two
containers, which is indistinguishable from the outside.

If you genuinely want to run without server storage, that is supported: server *switching* does not
need it (loads come from Proton's API, and the reconnect goes through the control server — verified
against a Gluetun running with storage off). Gluetun then selects from the list embedded in its own
build, so anything Proton added since that build is unusable. Set `SERVERS_WRITE_MODE=none` to stop
writing data nothing reads, and the warning and health failure go away.

### Two-factor authentication

- **Unattended:** set `PROTON_TOTP_SECRET` to the account's base32 TOTP secret. Codes are
  generated automatically.
- **Interactive:** leave it unset. When Proton asks for a code, the dashboard shows a form and
  the login waits (10 minutes) for you to submit one.

FIDO2/hardware-key-only accounts cannot be used; the tool says so explicitly rather than
looping.

### The container runs as root, deliberately

Gluetun needs `NET_ADMIN`, so it runs as root and creates `/gluetun` as `root:root 0755`. A
non-root process simply cannot create files in that directory — which means it cannot write the one
file that makes this tool useful. The same applies to a bind mount owned by the host user.

Running unprivileged is supported, it just needs ownership arranged first:

```yaml
user: "1000:1000"            # in docker-compose.yml
```
```bash
chown -R 1000:1000 /your/gluetun /your/data    # on the host, for bind mounts
```

Either way a **startup pre-flight check** tests every directory by actually writing to it, and
refuses to start with a message naming the paths, the uid it is running as and the `chown` that
fixes it. Silently limping along without writing anything is the one outcome ruled out.

### Important: do not share Gluetun's network namespace

Run the sidecar on a normal Docker network. **Do not** use `network_mode: service:gluetun`. The
tool has to reach the Proton API and measure latency to Proton's entry nodes from *outside* the
tunnel — inside it, every measurement would be taken through the VPN connection you are trying
to evaluate, and the tool would lose contact whenever the tunnel drops.

---

## The dashboard

- **Current server** — name, country, load, latency, score, rank, public IP, forwarded port,
  and how the server was identified.
- **Public IP (from Gluetun)** — the exit address Gluetun reports, with country, region, city,
  organisation, timezone and reverse DNS, and a note when it matches the selected server's Proton
  exit address (which is how the current server is identified).
- **Forwarded port** — the port Proton forwarded, plus whether Gluetun is even *requesting* one, so
  "no port" is never ambiguous.
- **Gluetun's own view** — everything its control server reports: tunnel status, version, commit,
  build date, protocol, provider, DNS state, its own updater state, and **the server filters
  Gluetun is currently enforcing** (usually the reason a specific server was refused).
- **Best candidate** — with the score gap and the reason a switch has or has not happened.
- **Actions** — reconnect to best, refresh the server list, refresh loads, probe latency,
  re-evaluate, rewrite `servers.json`, toggle automatic switching.
- **Candidate table** — every allowed server ranked, with a load bar, latency, score breakdown
  (hover the score) and a per-row **Use** button to switch to a specific server.
- **Switch history**, **live log**, **effective settings** and **filtering statistics** (how many
  servers each rule removed, so an unexpectedly short list is self-explanatory).

Live updates arrive over server-sent events. The page is a single self-contained asset — no CDN,
no build step, works on an air-gapped network, and follows your light/dark preference.

Optional HTTP basic auth via `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD`. `/healthz` stays
unauthenticated so Docker's health check works.

### HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/state` | Full state snapshot (JSON) |
| `GET` | `/api/events` | Server-sent event stream of snapshots |
| `GET` | `/api/logs?limit=n` | Recent log records |
| `POST` | `/api/refresh` | Refresh the Proton server list |
| `POST` | `/api/loads` | Refresh utilisation only |
| `POST` | `/api/probe` | Run a latency sweep |
| `POST` | `/api/evaluate` | Re-run the switch decision |
| `POST` | `/api/reconnect` | Switch to the best server (ignores cooldown) |
| `POST` | `/api/switch` | `{"hostname":"se-02.protonvpn.net"}` |
| `POST` | `/api/auto-switch` | `{"enabled":true}` |
| `POST` | `/api/totp` | `{"code":"123456"}` |
| `GET` | `/healthz` | Health check |

---

## Scoring

Lower is better. The score is a weighted sum of penalties, each normalised to `[0,1]`:

```
score = LOAD_WEIGHT    × (load / 100)
      + LATENCY_WEIGHT × (min(rtt, LATENCY_CEILING) / LATENCY_CEILING)
      + PROTON_WEIGHT  × (Proton's own score, normalised across candidates)
```

With the defaults (`load 1.0`, `latency 0.7`, ceiling `150ms`):

| Server | Load | RTT | Score | |
|---|---|---|---|---|
| `se-02` | 5% | 12 ms | **0.106** | wins |
| `se-01` | 80% | 8 ms | 0.837 | busy |
| `us-14` | 2% | 140 ms | 0.673 | idle but far away |

A **fixed** latency ceiling is used rather than normalising across the candidate set, because a
relative scale makes every score move whenever the set changes — which causes reconnect
flapping. With a fixed ceiling, a server's score only changes when the server does.

Latency probing is a plain TCP connect to the entry IP on port 443 (served by every Proton entry
node for OpenVPN/TCP). No `NET_RAW`, no ICMP. Each server is sampled a few times and the
**minimum** is kept — the least noisy statistic — then smoothed with an EWMA across sweeps so a
single unlucky probe cannot trigger a reconnect. Unprobed servers get a neutral penalty (0.5) so
they are neither favoured nor excluded. Set `SCORE_LATENCY_WEIGHT=0` for pure lowest-load
selection.

## How often does it reconnect?

Every switch tears down the tunnel and with it every connection through it, so the pacing is
deliberately conservative and bounded from two directions.

**With the defaults, at most one automatic reconnect every 15 minutes, and a hard ceiling of one
every 5 minutes.** In practice a steady state is **0–2 switches per day**: the improvement
threshold means nothing happens unless a server is meaningfully better.

| Guard | Default | What it does |
|---|---|---|
| `SWITCH_MIN_INTERVAL` | `5m` | **Hard floor. Nothing bypasses it**, not even an overloaded server. This is the guarantee on how often the tunnel can drop. |
| `SWITCH_COOLDOWN` | `15m` | Normal spacing between automatic switches. Only the load trigger may skip it. |
| `SWITCH_MIN_IMPROVEMENT` | `0.10` | The score gap the challenger must win by. With the default weights, 0.10 is roughly "10 % less loaded" or "15 ms closer". The main defence against flapping. |
| `SWITCH_EVALUATION_INTERVAL` | `5m` | How often the decision is *considered*. Considering is free; only the guards above allow acting. |
| `SWITCH_LOAD_TRIGGER` | `85` | Skips the cooldown and the improvement threshold when the current server exceeds this load — but only if the best candidate is actually below it, so a night where everything is busy cannot turn into a reconnect loop. |

Every switch is also **verified**, and verification failure does not retry: the attempt is
recorded and the next evaluation is 5 minutes away. A mutation that times out is treated as
"outcome unknown" and verified rather than re-sent, so a slow Gluetun cannot cause a double
reconnect.

To make it calmer still: raise `SWITCH_COOLDOWN` and `SWITCH_MIN_INTERVAL`, raise
`SWITCH_MIN_IMPROVEMENT` (e.g. `0.25`), or set `SWITCH_LOAD_TRIGGER=0` to disable load-based
switching. For a fully manual setup use `AUTO_SWITCH=false` and reconnect from the dashboard;
`RECONNECT_MODE=none` never touches the tunnel at all and only maintains `servers.json`.

### When it switches

All of these must hold:

- automatic switching is on, and reconnect mode is not `none`;
- Gluetun is reachable, and the tunnel is **running** or **crashed** — a crashed tunnel is worth
  moving because that is often what fixes it, while a deliberately **stopped** one is never
  restarted, and a **starting**/**stopping** one is left until it settles (a state change would
  block on it);
- Gluetun is actually configured for ProtonVPN;
- the minimum interval and the cooldown have elapsed;
- the best server beats the current one by at least `SWITCH_MIN_IMPROVEMENT`.

A server the filters exclude (wrong country, over `MAX_LOAD`) counts as "must move", and the
dashboard shows the current server with a *not in allowed set* marker rather than hiding it.

## Can Gluetun see a server it did not know at startup?

Not by itself, and this is worth understanding because it is the one thing the tool cannot fully
solve on its own.

Gluetun reads `servers.json` **only at startup**, keeps that list in memory, and validates a pinned
hostname against it. There is no control-server route that re-reads the file. So a server Proton
added an hour ago is refused with `400` no matter how current `servers.json` is.

The tool handles that in three escalating steps:

1. **Try the next candidates** (`SWITCH_CANDIDATES`, default 3). Usually one of them is a server
   Gluetun already knows, and nothing is disrupted.
2. **Ask Gluetun to refresh its own list** (`GLUETUN_REFRESH_SERVERS_ON_REJECT`, default `true`).
   This calls `PUT /v1/updater/status`, which makes Gluetun fetch from Proton and replace its
   in-memory list — new hostnames then become selectable **without restarting the container**. It
   requires `UPDATER_PROTONVPN_EMAIL` and `UPDATER_PROTONVPN_PASSWORD` on the Gluetun container
   (the same Proton credentials); without them Gluetun logs `credentials missing` and skips the
   update, and the tool falls through to step 3.
3. **Say so plainly.** The dashboard raises a *"Gluetun is running an older server list — restart
   it"* banner, naming the fix rather than failing silently.

Because of step 2, setting those two variables on the Gluetun container is recommended even though
it duplicates the credentials — it is what removes the only remaining need for a manual restart.

---

## Configuration

Every setting is an environment variable. Any variable also accepts `<NAME>_FILE=/path`
(read the value from a file) or `<NAME>_SECRET=name` (read `/run/secrets/name`) for Docker
secrets. Configuration is validated at startup and **all** problems are reported at once.

### Proton

| Variable | Default | Description |
|---|---|---|
| `PROTON_USERNAME` | *required* | Proton account email |
| `PROTON_PASSWORD` | *required* | Proton account password |
| `PROTON_TOTP_SECRET` | – | Base32 TOTP secret for unattended 2FA |
| `PROTON_REFRESH_INTERVAL` | `12h` | Full server-list refresh (min `15m`) |
| `PROTON_LOAD_REFRESH_INTERVAL` | `15m` | Utilisation-only refresh (min `1m`) |
| `PROTON_API_URL` | `https://vpn-api.proton.me` | API base URL |
| `PROTON_APP_VERSION` | `linux-vpn-cli@4.15.2` | `x-pm-appversion` header; Proton rejects versions it deems too old |
| `PROTON_REQUEST_TIMEOUT` | `30s` | Per-request timeout |
| `PROTON_CACHE_MAX_AGE` | `72h` | How old the cached list may be before it is reported as stale. It is still used past this — a stale list beats none. `0` disables the warning |

### Gluetun

| Variable | Default | Description |
|---|---|---|
| `GLUETUN_URL` | `http://gluetun:8000` | Control server base URL |
| `GLUETUN_API_KEY` | – | API-key auth |
| `GLUETUN_USERNAME` / `GLUETUN_PASSWORD` | – | Basic auth |
| `GLUETUN_REQUEST_TIMEOUT` | `10s` | Timeout for read-only requests |
| `GLUETUN_MUTATION_TIMEOUT` | `2m` | Timeout for state-changing requests. Gluetun does not answer these until its VPN loop has restarted, which takes seconds normally and much longer while a tunnel is unhealthy — hence the wide gap from the read timeout |
| `GLUETUN_HEALTH_INTERVAL` | `30s` | Status/public-IP poll interval |
| `GLUETUN_REFRESH_SERVERS_ON_REJECT` | `true` | When Gluetun refuses every hostname, ask it to refresh its own server list (needs `UPDATER_PROTONVPN_EMAIL`/`_PASSWORD` on the Gluetun container) |
| `GLUETUN_UPDATER_TIMEOUT` | `3m` | How long to wait for that refresh |

### Server list output

| Variable | Default | Description |
|---|---|---|
| `SERVERS_FILE` | `/gluetun/servers.json` | Gluetun's **legacy** fat file (up to v3.41.1) |
| `SERVERS_DIR` | `/gluetun/servers` | Gluetun's **directory** layout (current versions). Which one is used is detected automatically |
| `SERVERS_PREFERRED` | `true` | Set Gluetun's `preferred` flag, making it use our list regardless of timestamps |
| `SERVERS_WRITE_MODE` | `update` | `update` keeps other providers' sections, `replace` writes only ProtonVPN, `none` disables writing |
| `SERVERS_SCHEMA_VERSION` | *auto* | Override the detected schema version |
| `SERVERS_INCLUDE_IPV6` | `false` | Include Proton's IPv6 entry addresses |
| `SERVERS_ONLY_ALLOWED_COUNTRIES` | `false` | Restrict the file to `COUNTRIES` (requires it to be set) |

### Filtering

| Variable | Default | Description |
|---|---|---|
| `COUNTRIES` | *all* | Allow-list; accepts codes or names (`SE`, `Sweden`, `netherlands`) |
| `EXCLUDE_COUNTRIES` | – | Applied after `COUNTRIES` |
| `CITIES` | *all* | City allow-list |
| `MAX_LOAD` | `90` | Drop servers above this utilisation |
| `VPN_TYPE` | `auto` | `auto` follows Gluetun's protocol; or `wireguard` / `openvpn` |
| `SECURE_CORE` | `exclude` | `include` / `exclude` / `only` |
| `TOR` | `exclude` | `include` / `exclude` / `only` |
| `P2P` | `include` | `include` / `exclude` / `only` (Proton only forwards ports on P2P servers) |
| `STREAM` | `include` | `include` / `exclude` / `only` |
| `FREE_TIER` | `exclude` | `include` / `exclude` / `only` |

### Scoring and latency

| Variable | Default | Description |
|---|---|---|
| `SCORE_LOAD_WEIGHT` | `1.0` | Weight of `load/100` |
| `SCORE_LATENCY_WEIGHT` | `0.7` | Weight of normalised latency (`0` disables) |
| `SCORE_PROTON_WEIGHT` | `0.0` | Weight of Proton's own score |
| `SCORE_LATENCY_CEILING` | `150ms` | RTT that scores a full latency penalty |
| `SCORE_UNKNOWN_LATENCY_PENALTY` | `0.5` | Assumed value for unprobed servers |
| `LATENCY_ENABLED` | `true` | Enable probing |
| `LATENCY_PORT` | `443` | TCP port dialled |
| `LATENCY_SAMPLES` | `3` | Samples per server (minimum is kept) |
| `LATENCY_TIMEOUT` | `2s` | Per-dial timeout |
| `LATENCY_CONCURRENCY` | `24` | Parallel dials |
| `LATENCY_INTERVAL` | `30m` | Sweep interval |
| `LATENCY_TOP_N` | `150` | Probe only the N most promising candidates (`0` = all). Selection is by **load, never by score** — including latency would mean an unprobed server's assumed-latency penalty kept it out of the budget, so it could never become probed |
| `LATENCY_SMOOTHING` | `0.5` | EWMA weight of a new measurement |

### Switching

| Variable | Default | Description |
|---|---|---|
| `AUTO_SWITCH` | `true` | Automatic switching (dashboard toggle persists) |
| `RECONNECT_MODE` | `settings` | `settings` pins an exact hostname; `status` just stop/starts and lets Gluetun choose; `none` never touches the tunnel |
| `SWITCH_MIN_IMPROVEMENT` | `0.10` | Score gap required to switch |
| `SWITCH_COOLDOWN` | `15m` | Normal spacing between automatic switches |
| `SWITCH_MIN_INTERVAL` | `5m` | Hard floor between automatic switches; nothing bypasses it |
| `SWITCH_LOAD_TRIGGER` | `85` | Skip the cooldown and the improvement threshold above this load, provided the best candidate is below it (`0` disables) |
| `SWITCH_EVALUATION_INTERVAL` | `5m` | How often the decision is re-run |
| `SWITCH_VERIFY_TIMEOUT` | `90s` | How long to wait for the tunnel to come back |
| `SWITCH_CANDIDATES` | `3` | How many servers to try before giving up |

### Dashboard and general

| Variable | Default | Description |
|---|---|---|
| `DASHBOARD_ENABLED` | `true` | Serve the web UI |
| `DASHBOARD_ADDRESS` | `:8080` | Listen address |
| `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD` | – | Basic auth (set both) |
| `STATE_DIR` | `/data` | Proton session (`session.json`), cached server list (`logicals.json`), cached utilisation (`loads.json`) and switch history (`state.json`). Should be a volume: without it every restart re-authenticates, and Proton rate-limits logins |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `LOG_FORMAT` | `text` | `text` or `json` |
| `TZ` | – | Timezone for log timestamps |

---

## Fault tolerance

The failure modes this was built around, and what happens:

| Failure | Behaviour |
|---|---|
| **Proton unreachable** | Falls back to the server list cached in `STATE_DIR`, flags it on the dashboard, keeps managing the tunnel. `servers.json` is left untouched rather than emptied. |
| **Proton unreachable across a restart** | The cached list is reloaded from disk at startup, and the separately cached utilisation figures are applied over it — so a restart resumes with loads minutes old rather than hours old. Past `PROTON_CACHE_MAX_AGE` the list is still used (stale beats nothing) but reported as stale. |
| **Proton rate limits (429)** | Retried up to 3 times, honouring `Retry-After`. |
| **Proton session expires** | Refresh token used automatically; a dead refresh token triggers a fresh login. The session is persisted, so restarts do not re-authenticate — Proton rate-limits logins hard. |
| **Wrong credentials** | Reported once, distinctly, without a retry storm. |
| **Gluetun down or restarting** | Marked degraded; `servers.json` upkeep continues; no switch is attempted. |
| **Gluetun rejects a hostname** | Next candidate is tried; if all are refused, a *"restart Gluetun"* banner explains why. |
| **Gluetun is not using ProtonVPN** | Detected and warned about; switching is suspended. |
| **Tunnel deliberately stopped** | Left alone — the tool never starts a tunnel you stopped. |
| **Tunnel crashed** | Treated as actionable: moving to another server is usually what fixes it. |
| **Gluetun mid-transition** (`starting`/`stopping`) | No state change is sent, because Gluetun would block on it until the transition finished. |
| **A state change times out** | Treated as "outcome unknown" and verified, never re-sent — a slow Gluetun must not cause a second reconnect. |
| **Cross-country pin** | The chosen server's own country and city are sent with the hostname, so Gluetun's AND-combined filters can never intersect to nothing (which would crash its VPN loop). |
| **Switch does not come up** | Verification fails, the attempt is recorded with its error, and no reconnect storm follows. |
| **Empty or unusable Proton response** | Rejected before it can overwrite a good list. |
| **Crash mid-write** | All files are written to a temp file, `fsync`ed, then atomically renamed. A reader never sees a partial `servers.json`. |
| **Latency probe blip** | A failed probe keeps the previous measurement; EWMA smoothing damps outliers. |
| **Corrupt state files** | Logged and rebuilt from scratch instead of preventing startup. |
| **Unwritable `/data` or `/gluetun`** | Refused at startup with the paths, the uid and the `chown` that fixes it — rather than running and never writing anything. |
| **Gluetun storage layout changes** | Detected on every write, so a Gluetun upgrade cannot silently orphan the data. |
| **`servers.json` write failure** | Reported as **unhealthy** by `/healthz`, because the tool's primary job is broken even if everything else looks fine. |
| **Server data written but not read** | Also **unhealthy**: a requirement is unmet (`STORAGE_SERVERS_ENABLED`, or an unshared volume) and the tool would otherwise appear to work. |

Other hardening: bounded history and log buffers, context timeouts on every request, credentials
never logged (session UIDs are redacted), the session file is `0600`, and the container runs as a
non-root user.

---

## Development

```bash
make help         # list targets
make test         # go test ./... -race
make check        # vet + test
make build        # ./bin/gluetun-proton-updater
make image        # container image
make integration  # tests against a real Gluetun container
```

`make integration` starts a throwaway Gluetun container, runs the control-server tests against it
and removes it again. The WireGuard key is random, so the tunnel never comes up — irrelevant, since
what is being tested is Gluetun's API contract: that a hostname pin is accepted and applied, that
an unknown hostname is a distinguishable `400`, that a cross-country pin does not crash the VPN
loop, that stop/start works, and that the updater endpoint exists. A fake can only confirm that the
code matches the author's understanding of the API; this confirms the understanding. Point it at
another version with `make integration GLUETUN_VERSION=v3.39.0`.

The layout separates the pure logic from the I/O, so the interesting parts are testable without a
network:

```
cmd/gluetun-proton-updater/   entry point and wiring
internal/config/              environment parsing and validation
internal/proton/              Proton API client (SRP, TOTP, logicals, loads)
internal/gluetunapi/          Gluetun control-server client
internal/catalog/             Proton logicals → candidates + Gluetun servers (pure)
internal/scoring/             ranking (pure)
internal/latency/             TCP round-trip probing
internal/serversfile/         servers.json reading, merging, atomic writing
internal/engine/              orchestration, scheduling, state, switch decisions
internal/dashboard/           HTTP API and embedded web UI
internal/atomicfile/          crash-safe file writes
internal/countries/           ISO code → Gluetun country name
internal/logbuf/              in-memory log ring for the dashboard
```

All state mutation happens in a single goroutine (the engine's select loop); timers and dashboard
commands both funnel into it, so there is no lock ordering to reason about and two switches can
never race.

---

## Notes on the Proton API

Things that cost time to work out, recorded here so they do not have to be rediscovered:

- **`SecureCoreFilter=all` is mandatory for a complete list.** Without it Proton silently omits
  every Secure Core logical server. This — not pagination — is the usual reason a hand-rolled
  fetcher ends up with a short list. There is no pagination on this endpoint.
- The endpoint used is `/vpn/v1/logicals?SecureCoreFilter=all&WithState=true&WithIpV6=1`, matching
  Proton's own clients.
- `/vpn/v1/loads` returns the same logical IDs with only `Load`/`Score`/`Status` — a few kilobytes
  instead of several megabytes, which is why utilisation can be refreshed every 15 minutes and the
  full list only twice a day.
- `If-Modified-Since` is honoured; an unchanged list costs one `304`.
- A logical server (`SE#12`) can be backed by several physical machines. Gluetun connects by
  hostname, so each *physical* machine is a candidate. Machines shared between logicals are
  deduplicated by entry IP, keeping the **least loaded** of the duplicates — except for Secure
  Core, where one entry node legitimately serves several exit countries.
- Feature bits: `1` Secure Core, `2` Tor, `4` P2P, `8` Streaming, `16` IPv6. Gluetun's
  `port_forward` flag maps to P2P, because Proton only forwards ports on P2P servers.
- `Tier: 0` is the free tier. A missing `Tier` is treated as paid, matching Gluetun.
- Proton's `EntryIP` is what you connect to; `ExitIP` is what the internet sees — which is what
  makes it possible to identify the current server from Gluetun's reported public IP.

---

## Releases

Images are published to GitHub Container Registry, built for `linux/amd64` and `linux/arm64`:

```
ghcr.io/robinostlund/gluetun-proton-list-updater:latest
ghcr.io/robinostlund/gluetun-proton-list-updater:1.2.3   # exact version
ghcr.io/robinostlund/gluetun-proton-list-updater:1.2     # latest patch of 1.2
ghcr.io/robinostlund/gluetun-proton-list-updater:1        # latest minor of 1
```

Pushing a tag builds and releases automatically:

```bash
git tag -a v1.2.3 -m "v1.2.3"
git push origin v1.2.3
```

That runs the tests, then publishes the image with the tags above and creates a GitHub Release with
generated notes. A tag whose version has a suffix (`v1.2.3-rc.1`) is published as a pre-release and
deliberately does **not** move `latest`. The tests run before the push, so a tag can never publish
an image that does not build or pass them. A failed publish can be re-run from the Actions tab via
the *Release* workflow's `workflow_dispatch` input.

Pin a version in production (`:1.2.3` or `:1.2`) rather than tracking `latest`.

---

## Troubleshooting

**Requests to Gluetun time out (but DNS resolves).** Gluetun's firewall only accepts traffic from
the subnets it detected at startup. A Docker network attached to the Gluetun container *after* it
started (`docker network connect`) is not among them, and packets are dropped, so the control server
appears to hang rather than refuse. Put both containers on the same network in the compose file, or
add the subnet to Gluetun's `FIREWALL_OUTBOUND_SUBNETS`.

**`401 Unauthorized` on every switch.** Gluetun's default control-server role does not include
`/v1/vpn/settings`. See [the two required Gluetun settings](#two-settings-on-the-gluetun-container-that-are-not-optional).

**"Gluetun is not reading the server data written here"** (and `/healthz` reporting unhealthy).
Either `STORAGE_SERVERS_ENABLED` is off on Gluetun, or the `/gluetun` volume is not shared between
the containers. See [above](#storage_servers_enabledyes-is-required).

**"Gluetun rejected every candidate hostname".** Gluetun is working from a server list older than
the one written here. See
[Can Gluetun see a server it did not know at startup?](#can-gluetun-see-a-server-it-did-not-know-at-startup)

**Servers show `not probed`.** They are outside `LATENCY_TOP_N`. Raise it, or set it to `0` to probe
every candidate. Selection is unaffected by *which* servers are probed — probe targets are chosen by
load, never by score.

**Permission denied writing `/data` or `/gluetun`.** The pre-flight check names the paths and the
`chown` that fixes it; see [the note on running as root](#the-container-runs-as-root-deliberately).

---

## Credits

- [qdm12/gluetun](https://github.com/qdm12/gluetun) — the VPN client this orbits. The
  `servers.json` schema and the country-name mapping mirror Gluetun's own (MIT).
- [warrentc3/proton-gluetun-updater](https://github.com/warrentc3/proton-gluetun-updater) — the
  Python tool that inspired this, and the source of the `SecureCoreFilter=all` insight.

## Licence

MIT — see [LICENSE](LICENSE).
