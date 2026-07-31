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
│                        │ ──── GET /v1/vpn/settings+status ──▶ verify the switch worked
└────────────────────────┘
```

### The two mechanisms that matter

**Writing `servers.json`.** Gluetun reads this file at startup and merges it with its built-in
list. Two details decide whether your data is actually used, and both are easy to get wrong:

| Requirement | What this tool does |
|---|---|
| The `protonvpn.version` must equal the version compiled into the running Gluetun, or Gluetun logs *"discarded because they have version X"* and silently ignores your file. | Reads the version back out of the `servers.json` Gluetun itself wrote, instead of hardcoding a number that rots. Override with `GLUETUN_SERVERS_SCHEMA_VERSION`. |
| The `protonvpn.timestamp` must be newer than Gluetun's built-in one, because Gluetun merges by recency. | Always stamps the current time. |

**Switching servers.** `PUT /v1/vpn/settings` with a one-hostname server selection makes Gluetun
stop the tunnel, apply the selection and start again — a targeted reconnect with no container
restart. The switch is then *verified* against **Gluetun's own reported selection and tunnel
status**: the hostname it says it is using must be the one we asked for, and the tunnel must reach
`running`. "We sent the request" is not the same as "it worked".

Verification deliberately does *not* rely on the public IP matching Proton's published exit
address — with Proton those frequently differ, so that check produced false alarms on switches
that had in fact succeeded. The exit IP is still shown on the dashboard, as information.

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
| **Gluetun** | `v3.41.3` | `v3.41.3` or `latest` (both tested) | `v3.41.3` is the oldest release supported. **Avoid `v3.41.2` specifically:** it has a port-forwarding deadlock that hangs the VPN loop on `stopping`, so every switch request from here times out and the tunnel never returns — `v3.41.3` is a one-commit hotfix for it. Earlier versions than that are not tested and not supported: they lack `secure_core`/`tor` in their server model (added in `v3.39.0`), so Gluetun cannot filter on those at all. Both **storage layouts** are supported and detected automatically — see below. |
| **Gluetun setting** | `STORAGE_SERVERS_ENABLED=yes` | (the default) | With server storage off, Gluetun keeps no server data on disk and reads none, so the curated list written here is ignored. |
| **Proton account** | paid | paid | Proton's server list has required authentication since 2025 — an unauthenticated `/vpn/v1/logicals` answers `401`. There is no credential-free mode. |
| **Docker Engine** | `20.10` | `24+` | `docker compose` v2 syntax; multi-arch images are `linux/amd64` and `linux/arm64`. |
| **Go** (only to build from source) | `1.23` | `1.24` | The module targets 1.23; the container image builds with 1.24. |

Verified against Gluetun `v3.41.3` and `latest` by integration tests that run against a
real Gluetun container — see [Development](#development). The ProtonVPN schema version has been `4`
throughout, and is detected at runtime regardless.

### Gluetun changed where server data lives — both layouts are handled

This is worth knowing, because getting it wrong is invisible:

| Gluetun | Layout | What it reads |
|---|---|---|
| up to `v3.41.3` | **legacy** | one fat file, `/gluetun/servers.json` |
| current `master` / `:latest` | **directory** | `/gluetun/servers/` with `manifest.json` plus one file per provider, e.g. `/gluetun/servers/protonvpn.json` |

A Gluetun using the directory layout reads the legacy file **only when
`/gluetun/servers/manifest.json` is absent**. So writing just `servers.json` to a current Gluetun
has no effect at all — the tool would look healthy while being entirely ignored.

The layout is therefore **detected on every write**, by looking for the artefacts Gluetun creates
on startup, and the data goes wherever that Gluetun actually reads.

> **The artefacts outlive the Gluetun that made them.** This bit the author. Running `:latest`
> once leaves `servers/manifest.json` on the volume for good; point `v3.41.3` (legacy layout) at
> that same volume and the manifest is still there, describing a layout nothing reads any more.
> Trusting it sent every write to a file the running Gluetun ignored, and the only symptom was
> that it refused every hostname offered — having quietly kept its small built-in list.
>
> So detection treats **one** artefact as conclusive and **both together** as ambiguous:
>
> | On the volume | Conclusion |
> |---|---|
> | `manifest.json` only | directory layout (a legacy Gluetun would have written `servers.json` at startup, so its absence rules that out) |
> | `servers.json` only | legacy |
> | both | unknowable from the filesystem — **write both** |
> | neither | nothing has started yet — **write both** |
>
> Writing both is always safe, which is what makes it the right answer when in doubt: a
> directory-layout Gluetun reads the legacy file only when the manifest is missing, and a legacy
> Gluetun never looks in the directory.

Confirmed against `:latest`, which then logs:

```
[storage] Using protonvpn servers from file (marked as preferred)
```

That `preferred` flag (`GLUETUN_SERVERS_PREFERRED`, on by default) is what makes it deterministic: Gluetun
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
`GLUETUN_SERVERS_DIR` here to match. Trap 2 is caught by the check described next.

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
build, so anything Proton added since that build is unusable. Set `GLUETUN_SERVERS_WRITE_MODE=none` to stop
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

A status strip, four cards, and the detail below — each card answering one subject, all in the same
label-and-value shape.

**Status strip.** One line at the top answering *"is everything working?"* without reading anything
else:

```
TUNNEL running   PROTONVPN signed in   SERVER DATA written   QBITTORRENT connected
PORT FORWARDING working   SWITCHING automatic
```

Every chip states its value in words as well as colour, and carries the detail on hover — a bad chip
explains itself without hunting for the card. They are derived from the same snapshot the cards use,
so the strip can never disagree with the card below it.

**Server selection** — three columns: the current server, the candidate that would replace it, and
the decision between them. Current and best carry identical row labels so the two read across.

The current column also answers the two questions a single load figure prompts:

- **On this server** — how long the tunnel has been where it is, which is the quickest answer to
  "is it flapping?". It reads `unknown` unless this tool made the switch: if Gluetun moved on its
  own, or the tunnel was already up when this container started, the arrival time is genuinely not
  known and a number would be a guess.
- **Transferred via this server** and **Fastest measured rate** — two different facts, which were
  briefly one row and read as whichever the reader assumed. The *Best candidate* column shows only
  the volume: a rate on a server the tunnel is not using would read as a rate it is achieving now.
- **Measured throughput** — how much data has ever moved through this server. What has been
  *observed* about it over time, as opposed to what Proton predicts, is in the [candidate detail
  panel](#clicking-a-candidate): the best and worst load and latency ever seen, the fastest transfer
  rates, and the running totals.

The
**Improvement** row states its own verdict — `0.021 too low, needs 0.100` in red, or `0.180 meets
0.100` in green — because that single number decides whether the best candidate is used at all.
Below it: the **Decision** in the engine's own words (`cooldown active for another 12m`), the
thresholds behind it, what the selection is **restricted to** (P2P only, and which Gluetun setting
caused it), and how the current server was **identified**.

That last one matters more than it looks, because **restarting Gluetun discards the selection**. The
hostname is applied through Gluetun's control server at runtime, not written into its configuration,
so a restarted Gluetun comes back having chosen a server from the filters it was *started* with. It is
identified in three ways, in descending order of confidence:

| Source | What it means |
|---|---|
| `pinned` | Gluetun's own settings name exactly this hostname. Exact — Gluetun validated it |
| `public-ip` | Gluetun's exit address matches this server's published `ExitIP`. Reliable when it hits, meaningless when it misses: Proton's published address is often not the one the internet sees |
| `remembered` | What this tool last asked for, used **only** when Gluetun could not be asked |

The third is deliberately narrow. A readable Gluetun reporting *no* hostname selection **disproves**
the remembered value rather than merely failing to confirm it — so the current server reads as unknown
and the next evaluation re-selects and re-pins. This shipped wrong once: the remembered value was
returned whenever nothing else matched, so after a Gluetun restart the dashboard named the wrong
server, transfer figures were credited to it, and selection saw nothing to fix because its own choice
looked current. A warning names the server it has forgotten and why.

**Gluetun** — the tunnel, its exit address, the server data written for it, and what Gluetun's own
control server reports, in one place. It also carries **controls for Gluetun's own loops** — start
and stop the VPN, start and stop its DNS-over-TLS resolver, run its updater, refresh what it reports,
and rewrite the servers file — placed next to the state they change. Stopping either loop leaves it
stopped: the engine treats a stopped tunnel as a deliberate decision and never starts it behind you.
Stopping the VPN asks first, since every connection through it drops.

### The settings panel shows every variable

**Updater settings** lists every configuration variable as it actually resolved, including the ones
left at their defaults, grouped by the prefix they are named after. A default in effect is shown but
muted: it is in effect, and it is not a decision anybody made, and those are different things.

The list is **recorded while the configuration is parsed**, not described afterwards. It used to be a
hand-written list of about twenty labels, which answered "how is this configured" with the subset
somebody had remembered to add — and drifted every time a variable was renamed. A test now fails if
any variable this tool reads is missing from it.

**Credential values never reach the page.** The six secret variables report only `set` or `not set` —
which is the diagnostic part, and none of the sensitive part. That is a denylist rather than a guess
based on the name, because missing one is a credential leak rather than a cosmetic bug, and a separate
test asserts that no secret's value appears anywhere in what the dashboard receives.

### Controls live in the card for what they act on

There is no shared controls panel. Every button sits in the card for the integration it talks to, and
each card that has any puts them in a **Controls** band:

| Card | Controls |
|---|---|
| **Server selection** | Reconnect to best, Re-evaluate, and the automatic-switching toggle |
| **Gluetun** | Refresh, Rewrite servers.json, start/stop VPN, start/stop DNS, Run updater |
| **ProtonVPN** | Refresh server list, Refresh loads, Probe latency |
| **qBittorrent** | Refresh |

Every control has the same appearance. They used to differ — one accent-filled button among plain
ones — which read as a ranking of importance that does not exist: reconnecting is not more
significant than stopping the VPN.

**ProtonVPN keeps two refreshes rather than one**, because the two calls cost very different amounts:
the server list is several megabytes and Proton changes it about twice a day, while the loads are a
few kilobytes and change every few minutes. A single "Refresh" would make the expensive call every
time someone wanted the cheap one. *Probe latency* is local measurement, not a Proton API call. Tunnel
status, version, protocol, provider, DNS; the public IP with its location, organisation and reverse
DNS; then the layout, paths, schema version and write outcome of the data written for Gluetun.

**ProtonVPN** — the server list and the latency measured against Proton's entry nodes, since that
latency is one of the two inputs to the score. Plan and tier, candidate count, fetch times, then
median/best/worst RTT and probe coverage.

**qBittorrent** — appears only when configured. Current rates with a bar against each threshold,
qBittorrent's **own** rate caps for context (`unlimited` when it has none — these are its settings,
not this tool's, and have no bearing on the busy thresholds), session totals, and two rows that
answer the questions that matter: whether **port forwarding** is actually reaching qBittorrent (see
below) and whether **switching** is being held back.

Every integration answers the same two questions in the same words — **Connected** (can this tool
reach it) and **Last … result** (`successful` / `failed`, with the error on hover). Descriptive
paragraphs were removed in favour of labelled rows; the reasoning behind a value lives in its
tooltip, and only genuine failures get a line of their own.

Below the cards: **Actions** (reconnect to best, refresh the list, refresh loads, probe latency,
re-evaluate, rewrite the server data, toggle automatic switching), the **Candidate table**, and
panels for **Switch history**, **Recent activity**, **Effective settings** and **Filtering**.

- **Load freshness** — the Candidates heading carries `loads 2m ago`, turning amber once a refresh
  has been missed. Ranking is only as good as the utilisation behind it.
- **Candidate table** — every allowed server ranked, with separate **Country** and **City** columns,
  a load bar, latency, score breakdown (hover the score) and a per-row **Use** button. Servers
  Gluetun's own filters rule out appear at the end in **amber**, with no rank, a `cannot use` tag and
  a disabled button — visible for diagnosis, impossible to select.
- **Switch history** — what moved where and why, with a **Clear** button. The shared
  `.protonvpn.net` suffix is trimmed for width; hover a row for the full names.
- **Live log** — recent activity, also with a **Clear** button, which empties only the buffer this
  page reads.
- **Effective settings**, **Gluetun's own view** and **Filtering** fold away behind a summary line.
  They are reference material read once during setup, not scanned daily. Native `<details>`, so no
  JavaScript is involved and they work with the keyboard.
- The **candidate table** can be hidden with a toggle in its heading — it is the tallest thing on the
  page — and the choice is remembered across reloads.

Live updates arrive over server-sent events. The page is a single self-contained asset — no CDN, no
build step, works on an air-gapped network, and follows your light/dark preference.

Optional HTTP basic auth via `DASHBOARD_USERNAME` / `DASHBOARD_PASSWORD`. `/healthz` stays
unauthenticated so Docker's health check works.

## Not switching during a transfer

A switch tears the tunnel down and takes every connection through it with it. Doing that in the
middle of a download to reach a marginally quieter server is a self-inflicted interruption, so the
tool can watch qBittorrent and wait instead.

It is **off unless configured**. Gluetun exposes no throughput information at all — its control
server has no such route, and it never reads the byte counters that exist inside its own network
namespace — so the rates have to come from something that knows about the traffic.

```yaml
QBITTORRENT_URL: "http://qbittorrent:8080"
QBITTORRENT_API_KEY: "qbt_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"
SWITCHING_BUSY_DOWNLOAD: "16"       # Mbit/s: defer while downloading faster than this
SWITCHING_BUSY_UPLOAD: "4"          # Mbit/s: and while uploading faster than this
SWITCHING_BUSY_WINDOW: 5m           # averaged over this period, not sampled once
```

Generate the key in qBittorrent itself: **Preferences → Web UI → API keys**. It is sent as
`Authorization: Bearer …`, which is qBittorrent's own scheme for programmatic access. A key rather
than a username and password on purpose: it cannot expire mid-session, it is exempt from
qBittorrent's CSRF protection so no `Referer` handling is needed, and it cannot trip the
brute-force lockout that repeated logins would. Verified against a real qBittorrent **5.2.2**.

### Where the rates come from

Rates are read through an ordered list of sources, first answer wins, and the dashboard names
whichever one answered — because it changes what the numbers cover.

| Source | Covers | Status |
|---|---|---|
| **qBittorrent** | That client's own traffic | The only one today |
| **Gluetun** | Everything crossing the tunnel | Not possible yet — see below |

Gluetun would be the better source: it sits in the network namespace the traffic actually crosses, so
its numbers would include everything through the tunnel rather than one client's share. It cannot be
implemented yet — Gluetun's control server has no throughput route and it never reads the byte
counters in its own namespace — so the seam exists and the list has one entry. Adding it later is a
new file and a line in that list; nothing that consumes a reading has to change, because the
conversion to the shared unit happens inside each source.

### One unit: megabits per second

Thresholds are **plain numbers in megabits per second**. `16` means 16 Mbit/s. No suffixes, no
`MB`/`MiB`/`Mbit` vocabulary to remember, and no factor-of-eight trap between two spellings that look
interchangeable.

That is the same unit the dashboard displays and the same unit a link speed is quoted in — an ISP
sells 100/10 Mbit, `iperf` and speedtest report bits — so a threshold, a live reading and a log line
can be compared without arithmetic anywhere.

**Volumes stay in bytes.** `412 GB downloaded` is a volume, and nobody measures data in bits.

Rates are converted **once, where a source is read**: qBittorrent's Web API answers in bytes per
second, its adapter converts, and everything past that point — the samples, the averages, the
thresholds, the stored maxima, the JSON, the page — is bits. Nothing in the middle multiplies by
anything.

> **Upgrading:** the old spellings are refused rather than reinterpreted. `SWITCHING_BUSY_DOWNLOAD:
> "2MB"` fails at startup with `write a plain number of megabits per second instead, so 2MB becomes
> 16` — because silently reading `2MB` as 2 Mbit/s would cut the threshold to an eighth without
> saying so.

### The rates are averaged, not sampled once

Traffic is bursty. A torrent that is plainly active drops to nothing between pieces, and a poll
landing in one of those dips would report the tunnel idle and let a switch through mid-transfer —
the exact interruption this exists to prevent. So the comparison uses the **mean over
`SWITCHING_BUSY_WINDOW`** (default `5m`), and the dashboard shows the instantaneous rates *and* the
averages, with the bars on the averages because those are what decide.

A mean rather than a peak, deliberately: one spike should not hold the tunnel for a whole window,
and an average over a few minutes is what distinguishes "in use" from "was used once recently". Set
`SWITCHING_BUSY_WINDOW=0` for the old single-reading behaviour.

Samples age out relative to the **last successful reading**, not to the clock. Measured from now, a
qBittorrent that stopped answering would drain the window until the average fell below the threshold
and a switch was allowed — silently undoing the fail-safe below.

**The two directions are independent.** Seeding at 40 Mbit/s and downloading at 40 Mbit/s are different
situations, and you may want to protect one and not the other. Setting either to `0` stops it being
a trigger; setting both to `0` is rejected at startup, since the feature would read as enabled while
never deferring anything.

### Clicking a candidate

Clicking a row in the candidate list opens a **read-only detail panel** for that server. It exists
because several facts had nowhere to live: the score breakdown was a tooltip, the measured
throughput was squeezed into one table cell, and a blocked server's reasons were a hover.

It is read-only deliberately. The row's own **Use** button remains the only way to move the tunnel,
so opening a panel can never be the click that reconnects you — the row handler ignores any click
that landed on a control, and the switch handler returns before the row handler is reached.

Beyond what the table already shows, the panel surfaces the Proton fields that were parsed but never
displayed: the **logical ID** (what a Proton support conversation needs), the **plan tier**,
Proton's **own score** before this tool weights it, the **region**, and the **IPv6 entry address**.
That last one distinguishes *not recorded* from *no IPv6* — the address is only kept when
`GLUETUN_SERVERS_INCLUDE_IPV6` is on, so its absence says nothing about the server's capability.

#### What has been observed about each server

The panel shows what has actually been measured about a server over time — but as **figures rather
than graphs**, deliberately. A stored series buys graphs at the cost of a state file that grows with
every server and every hour; a dozen fixed numbers answer what those graphs were being read for and
cost the same whether a server has been used for a day or a year. It is also what makes this
affordable for **every candidate** rather than a chosen few.

| Figure | Meaning |
|---|---|
| **Load** now / best / worst | Proton's utilisation, and the extremes ever seen. A server that is quiet now but has peaked at 95 % is a different proposition from one that never has |
| **Latency** now / best / worst | Round trip, same idea. Absent for servers outside `LATENCY_TOP_N`, which reads *not probed* rather than as a zero |
| **Downloaded / Uploaded** | Every byte ever moved through this server, all time |
| **Fastest download / upload** | The best readings during **one stay** — the current one, or the most recent for a server not in use |
| **Observations**, **Stays**, **First seen** | How much evidence is behind the extremes, and since when |

Best means *lowest* for both load and latency. The stored field names say `lowest` and `highest`
rather than best and worst, because reading those requires already knowing which direction is good.

**Rates cover one stay; volumes cover all time.** They are different kinds of claim. "412 GB have
gone through this server" only grows truer with age. "This server does 110 Mbit/s" was true on one
evening under one set of conditions, and repeating it about a server that is busier now is worse than
saying nothing — so a rate describes the current stay, or the most recent one for a server not in use.

The replacement is **lazy**, which is the part worth knowing: arriving on a server does not clear the
figure, the first reading with traffic in it replaces it. Otherwise reconnecting would blank the row
and leave it blank until a download happened to start, which is exactly when the number is wanted. A
restart is not an arrival either — the stay is persisted, so the tunnel not having moved means the
stay continues.

Load and latency extremes stay all-time, because they are sampled for every candidate whether or not
it is in use, so they are not tied to stays at all.

Load and latency are recorded for every candidate on each loads refresh, so they accumulate whether
or not a server is ever used. The four transfer figures need the qBittorrent integration; without it
they read **needs qBittorrent** rather than `0 B`, because a zero would be a claim about the server
rather than an admission about us.

#### Data transferred, kept for the life of the server

The **Transferred** column in the candidate list is how much data has ever moved through each server.
That, rather than a peak rate, is the figure that means something cumulatively: a peak is one lucky
moment, while "412 GB have gone through this server" says how much you have actually used it.

These totals are **never reset** — not by a reconnect, not by returning after a month away. The only
thing that removes one is Proton retiring the server, which takes the whole record with it: totals,
rates, load and latency extremes, all at once, under the three guards described above. Each removal
is logged **with the figures being discarded** rather than as a bare count.

They come from qBittorrent's session counters by **difference between polls**, which is the only way
to attribute a global counter to a particular server. Four things make a difference meaningless, and
each yields nothing rather than a wrong number:

| Situation | Why the difference is meaningless |
|---|---|
| The first poll | Nothing to subtract from — a session that had already moved 50 GB is not ours to claim |
| The counter went **backwards** | qBittorrent restarted; its session totals began again from zero |
| The baseline belongs to another server | Those bytes were carried by that server, which has already been credited |
| The previous poll was not attributable | The gap is unaccounted for, so any skipped reading drops the baseline |

An idle interval is *not* one of those: nothing moved, which is a real zero rather than a gap, so the
baseline moves forward through quiet periods instead of restarting.

Two honest limits. This counts what the tool **observed** — bytes that moved before it started
watching, or during the interval a qBittorrent restart straddles, are not counted, so treat the
totals as a floor. And it is qBittorrent's traffic, not the tunnel's: anything else using the VPN is
invisible here.

##### Why these do not match the qBittorrent card

The qBittorrent card's *Downloaded, all servers* is qBittorrent's own session counter. It is a
different quantity from the per-server totals, and the two can differ in **either** direction:

| | Per-server totals | qBittorrent's session counter |
|---|---|---|
| Scope | One server | Every server the session touched |
| Resets | Never (only Proton retiring the server removes it) | Whenever qBittorrent restarts |
| Covers | Only intervals this tool could attribute | Everything, including intervals spanning a switch |

So within one qBittorrent session the per-server totals will be **lower** — they exclude the
intervals that straddle a switch. Across a qBittorrent restart they will be **higher**, because they
kept counting where qBittorrent started again from zero. The rows are labelled apart for exactly this
reason, and a test keeps them that way; comparing them is not meaningful.

#### What this costs on disk

One record per server, and it does not grow with time. Measured, not estimated:

| Scenario | `state.json` |
|---|---|
| 300 candidates, 20 of them used | **58 KB** |
| The 600-server cap saturated, every field at its widest | **249 KB** |

A test fails if a change pushes the worst case past 320 KB. The cap is a backstop against a
deployment left to wander across every server Proton offers, not a retention policy — least recently
seen goes first, and it is logged, because a transferred total disappearing is exactly the kind of
silent loss these figures must not suffer.

The **write volume** matters more than the size. The statistics are updated on every qBittorrent
poll, every 15 seconds by default, and the state file is rewritten in full — so a poll mutates memory
only, and the write happens **once a minute, and again on shutdown**. That is a sixteenth of the
writes, which on hardware that may well be an SD card is the difference between about 30 MB a day and
a gigabyte, while bounding what an unclean kill can lose to a minute of counting.

The shutdown flush is not optional: without it, a restart inside the timer window discarded
everything counted since the last write, which read as the figures not surviving a restart at all.


### What it does and does not hold back

| | Behaviour |
|---|---|
| Automatic switching | deferred while either average is at or above its threshold |
| **Reconnect to best** and per-row **Use** | always proceed — an explicit instruction is never overridden |
| `SWITCHING_LOAD_TRIGGER` (overloaded server) | also deferred: a slow transfer beats a broken one |
| Current server unknown | also deferred: that is no reason to break a transfer that is demonstrably flowing |
| Tunnel **crashed** | **not** deferred — nothing is flowing through a tunnel that is down, so there is only a recovery to delay |

`SWITCHING_BUSY_MAX_DEFER` bounds the wait. It defaults to unset, meaning an active transfer always
wins, which is the point of the feature. Set it (`2h`) if you would rather cap how stale the server
choice can become on a permanently busy tunnel.

### If qBittorrent stops answering

The last known rates are kept and **keep deferring switches**, marked as a stale reading on the
dashboard. This is deliberate: treating "I could not find out" as "nothing is happening" would
interrupt exactly the transfer the feature exists to protect.

"Never answered" is split by how long that has been true, because the two cases want opposite
answers:

| State | Behaviour |
|---|---|
| No answer **yet**, within 5 minutes of startup | switching **waits**. Both containers restart together and qBittorrent is often not up when the first poll lands |
| No answer for longer than that | falls **open**, with a warning naming the settings to check |

The first case is not hypothetical: without it, a restart during an active download switched servers
every time — the exact interruption this feature exists to prevent, at the moment it is most likely
to happen. The second keeps a wrong URL or key from freezing selection for ever.

The wait applies only when there is something to protect, and what decides that is whether the
**tunnel** is up — not whether this tool can name the server it is on. Those are easy to conflate and
it matters: on startup the current server is routinely unidentifiable for a moment, because a
restarted Gluetun has discarded the pin and nothing has been re-pinned yet, while the tunnel is up and
downloading at full speed.

**Startup order is part of this.** qBittorrent is polled before Gluetun is checked, because checking
Gluetun evaluates on its own as soon as it becomes usable — so an evaluation could otherwise happen
before anything knew whether a transfer was running. A test asserts the order, since it is six
adjacent lines that would reorder silently.

### Is the forwarded port actually reaching qBittorrent?

Neither side can answer this alone, which is why it silently goes wrong. Gluetun knows which port
Proton forwarded; qBittorrent knows which port it listens on and whether anything is arriving. The
**Port forwarding** row compares them:

| Verdict | Meaning |
|---|---|
| `working` | the ports agree and incoming connections are arriving |
| `mismatch` | Gluetun forwarded one port, qBittorrent listens on another — **nothing reaches it** |
| `unreachable` | the ports agree but qBittorrent reports itself firewalled: nothing is arriving |
| `not requested` | Gluetun is not asking Proton for a port, so no incoming connections are expected |
| `unknown` | qBittorrent has not answered yet, or has no peers to infer from |

`mismatch` is the one worth having. Neither container calls it an error: Gluetun forwards a port
successfully, qBittorrent runs happily, and every incoming connection goes nowhere — commonly
because qBittorrent is still on its default `6881`. It is also flagged when qBittorrent's
**random port** setting is on, since that guarantees the match breaks on its next restart.

There is deliberately no active reachability probe. Testing a port from outside means calling a
third-party service on your behalf, and from inside a container this tool cannot test external
reachability itself. `connection_status` is qBittorrent's own answer to the same question, from the
only vantage point that knows.

### `401` means the URL, `403` means the key

The two status codes are the opposite way round from what you would guess, so this is worth knowing
before you go hunting. Measured against a real qBittorrent `5.2.2`:

| Request | Status |
|---|---|
| correct key, `Host` port **matches** qBittorrent's Web UI port | `200` |
| correct key, `Host` port **does not match** | **`401`** |
| wrong or missing key, port matches | **`403`** |

So **a `401` is never about the API key.** qBittorrent validates the `Host` header *before* it looks
at any credentials — `validateHostHeader` runs first and throws `Unauthorized`, while a key that
fails to create a session falls through to a scope check that throws `Forbidden` — and it requires
the **port in the URL to equal qBittorrent's own Web UI port**.

That makes the fix mechanical: if you see `401`, `QBITTORRENT_URL` is pointing at a *remapped* port.
Use qBittorrent's internal port, the one it is actually listening on. Container-to-container on the
same Docker network — `http://qbittorrent:8080` — is the normal case and works; publishing it to
the host as `8091:8080` and then asking for `:8091` does not.

The two are reported separately, so the log names the right thing to fix rather than sending you
after the key when the key is fine.

### Gluetun's "Selected …" rows are not your filters

This is the most surprising thing on the page, so it is worth stating plainly. Set
`SERVER_COUNTRIES: "Sweden,Germany,Netherlands"` on Gluetun and, once this tool has pinned a
server, *Gluetun's own view* will show a single country and a single city:

```
Selected hostnames : node-se-11.protonvpn.net
Selected countries : Sweden
Selected cities    : Stockholm
```

Nothing has been lost. Those rows are the selection **Gluetun is applying right now**, and pinning
a server deliberately replaces its countries and cities with that server's own. It has to: Gluetun
ANDs every selection filter, so a hostname left to intersect with the original three countries
would match nothing the moment the chosen server sat outside them — and an empty match crashes
Gluetun's VPN loop rather than being ignored.

Verified against a real `v3.41.3`:

| Moment | `countries` | `cities` | `hostnames` |
|---|---|---|---|
| before any pin | `sweden, germany, netherlands` | – | – |
| after this tool pins a server | `Sweden` | `Stockholm` | `node-se-11.protonvpn.net` |
| after restarting the Gluetun container | `sweden, germany, netherlands` | – | – |

So your configuration is intact — Gluetun re-reads `SERVER_COUNTRIES` on every container start.
The one consequence worth knowing: while this tool is running, Gluetun's *own* fallback choice is
narrowed to the pinned server's country. If this container stops, Gluetun keeps the last selection
until it restarts. The dashboard explains this in a note under the panel, and the rows are labelled
**Selected** rather than *Filter* for exactly this reason.

### `Servers Gluetun knows`

When Gluetun refuses a hostname it enumerates every hostname it *would* accept — the only moment it
discloses the list it is actually running. That count appears here, next to how many this tool is
offering. A few hundred against a few thousand means Gluetun is on its built-in list and needs
restarting; the two numbers being close means its list is current. It reads `0` until Gluetun has
refused something, which is not the same as knowing nothing.

### HTTP API

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/api/state` | Full state snapshot (JSON) |
| `GET` | `/api/events` | Server-sent event stream of snapshots |
| `GET` | `/api/logs?limit=n` | Recent log records |
| `GET` | `/api/explain?q=SE%23444` | Why a given Proton server is, or is not, a candidate |
| `POST` | `/api/refresh` | Refresh the Proton server list |
| `POST` | `/api/loads` | Refresh utilisation only |
| `POST` | `/api/probe` | Run a latency sweep |
| `POST` | `/api/evaluate` | Re-run the switch decision |
| `POST` | `/api/reconnect` | Switch to the best server (ignores cooldown) |
| `POST` | `/api/switch` | `{"hostname":"se-02.protonvpn.net"}` |
| `POST` | `/api/auto-switch` | `{"enabled":true}` |
| `POST` | `/api/history/clear` | Discard the persisted switch history |
| `POST` | `/api/logs/clear` | Empty the in-memory activity log |
| `POST` | `/api/gluetun/updater` | Run Gluetun's own server-list updater |
| `POST` | `/api/gluetun/vpn` | `{"status":"running"}` or `{"status":"stopped"}` |
| `POST` | `/api/gluetun/dns` | `{"status":"running"}` or `{"status":"stopped"}` |
| `POST` | `/api/totp` | `{"code":"123456"}` |
| `GET` | `/healthz` | Health check |

## Servers your account cannot use

Proton's server list is the same whoever asks: it includes servers **above your
plan's tier**, which look entirely ordinary and simply refuse the connection. A
free account offered a Plus server would burn a reconnect and leave the tunnel
down for nothing.

So the tool asks Proton what the account is entitled to (`GET /vpn/v2` → `MaxTier`)
and excludes anything above it. The tier is remembered in `STATE_DIR`, so a restart
while Proton is unreachable still filters correctly, and a server whose tier Proton
does not report is kept rather than discarded — refusing on missing information
would be worse than trying.

The dashboard shows this in three places:

- the **Proton list** card shows the plan and tier, e.g. `VPN Plus (tier 2)`
- every server in the candidate table carries a **`free`** or **`paid`** badge, so
  which servers need a subscription is visible rather than implied
- the **Filtering** panel counts what was skipped as *above account tier*

`FILTER_FREE_TIER` remains a separate preference: it decides whether you *want* free-tier
servers (default `exclude`, since they are heavily loaded), while the tier check
decides what is *possible*. A delinquent account is also flagged, because Proton
refuses connections in that state and it looks identical to a server fault.

## "Why is server X not in the list?"

Ask the tool. It evaluates the question against the **raw Proton response** cached in `STATE_DIR`, so
it can explain servers that are not candidates:

```bash
curl -s 'http://localhost:8080/api/explain?q=SE%23444' | jq
```

or type the name into the box in the dashboard's *Filtering* panel. It names every rule that
rejected the server — `FILTER_MAX_LOAD`, a country or city filter, a feature filter, a filter Gluetun itself
enforces, a Proton `Status 0`, a missing WireGuard key — and lists each physical machine behind it.

The most common answer is not an exclusion at all. **Proton groups one physical machine under several
logical names**: `SE#148` and `SE#444` can be the same box, with the same hostname and entry IP but
different reported loads. Gluetun connects by *hostname*, so that machine is usable either way — it
simply appears in the candidate list under whichever name won deduplication (the quieter one). The
diagnostic says so explicitly:

```
usable: SE#444 is the same machine as SE#148 (node-se-12.protonvpn.net),
so it appears in the list under that name
```

So a name visible on Proton's portal but absent from the dashboard is usually present as a sibling,
not missing. Deduplication is by entry IP, matching Gluetun's own updater, and keeps the
least-loaded of the servers sharing a machine.

## Scoring

Lower is better. The score is a weighted sum of penalties, each normalised to `[0,1]`:

```
score = SCORING_LOAD_WEIGHT    × (load / 100)
      + SCORING_LATENCY_WEIGHT × (min(rtt, SCORING_LATENCY_CEILING) / SCORING_LATENCY_CEILING)
      + SCORING_PROTON_WEIGHT  × (Proton's own score, normalised across candidates)
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
they are neither favoured nor excluded. Set `SCORING_LATENCY_WEIGHT=0` for pure lowest-load
selection.

## How often does it reconnect?

Every switch tears down the tunnel and with it every connection through it, so the pacing is
deliberately conservative and bounded from two directions.

**With the defaults, at most one automatic reconnect every 15 minutes, and a hard ceiling of one
every 5 minutes.** In practice a steady state is **0–2 switches per day**: the improvement
threshold means nothing happens unless a server is meaningfully better.

| Guard | Default | What it does |
|---|---|---|
| `SWITCHING_MIN_INTERVAL` | `5m` | **Hard floor. Nothing bypasses it**, not even an overloaded server. This is the guarantee on how often the tunnel can drop. |
| `SWITCHING_COOLDOWN` | `15m` | Normal spacing between automatic switches. Only the load trigger may skip it. |
| `SWITCHING_MIN_IMPROVEMENT` | `0.10` | The score gap the challenger must win by. With the default weights, 0.10 is roughly "10 % less loaded" or "15 ms closer". The main defence against flapping. |
| `SWITCHING_EVALUATION_INTERVAL` | `5m` | How often the decision is *considered*. Considering is free; only the guards above allow acting. An evaluation also runs immediately whenever Gluetun becomes usable, so a slow-starting Gluetun does not leave the tunnel unmanaged until the next tick. |
| `SWITCHING_LOAD_TRIGGER` | `85` | Skips the cooldown and the improvement threshold when the current server exceeds this load — but only if the best candidate is actually below it, so a night where everything is busy cannot turn into a reconnect loop. |

Every switch is also **verified**, and verification failure does not retry: the attempt is
recorded and the next evaluation is 5 minutes away. A mutation that times out is treated as
"outcome unknown" and verified rather than re-sent, so a slow Gluetun cannot cause a double
reconnect.

To make it calmer still: raise `SWITCHING_COOLDOWN` and `SWITCHING_MIN_INTERVAL`, raise
`SWITCHING_MIN_IMPROVEMENT` (e.g. `0.25`), or set `SWITCHING_LOAD_TRIGGER=0` to disable load-based
switching. For a fully manual setup use `AUTO_SWITCH=false` and reconnect from the dashboard;
`RECONNECT_MODE=none` never touches the tunnel at all and only maintains `servers.json`.

### It reacts to Gluetun starting, without waiting for the next tick

Gluetun normally takes longer to come up than this container, so the first health
checks find it unreachable and there is nothing to evaluate. As soon as it becomes
usable — reachable, and either running or crashed — an evaluation runs immediately
rather than waiting out `SWITCHING_EVALUATION_INTERVAL`:

```
INFO gluetun became usable, evaluating now rather than waiting for the next round
```

The same applies after a Gluetun restart, or after the tunnel is started again
having been stopped. Pressing *Re-evaluate* on the dashboard should not be
necessary for this.

### When it switches

All of these must hold:

- automatic switching is on, and reconnect mode is not `none`;
- Gluetun is reachable, and the tunnel is **running** or **crashed** — a crashed tunnel is worth
  moving because that is often what fixes it, while a deliberately **stopped** one is never
  restarted, and a **starting**/**stopping** one is left until it settles (a state change would
  block on it);
- Gluetun is actually configured for ProtonVPN;
- the minimum interval and the cooldown have elapsed;
- the best server beats the current one by at least `SWITCHING_MIN_IMPROVEMENT`.

A server the filters exclude (wrong country, over `FILTER_MAX_LOAD`) counts as "must move", and the
dashboard shows the current server with a *not in allowed set* marker rather than hiding it.

## Can Gluetun see a server it did not know at startup?

> **Triggering Gluetun's updater does not make it read this tool's list, and it overwrites
> that list.** Worth stating plainly, because the opposite is the natural assumption.
>
> `PUT /v1/updater/status` makes Gluetun fetch from **Proton's API** — not from
> `servers.json`. There is no route that makes Gluetun re-read the file. And Gluetun then
> *persists* what it fetched: `SetServers` calls `flushToFile`, which opens the servers
> file with `O_TRUNC`, so the curated list is replaced by Gluetun's own.
>
> So the updater is triggered only in the one case where it helps — when Gluetun has
> refused a hostname, to make it aware of servers added since it started — and the servers
> file is **rewritten immediately afterwards** to restore the curated data. It is never
> triggered after an ordinary write, which would replace the list just written.

Not by itself, and this is worth understanding because it is the one thing the tool cannot fully
solve on its own.

Gluetun reads `servers.json` **only at startup**, keeps that list in memory, and validates a pinned
hostname against it. There is no control-server route that re-reads the file. So a server Proton
added an hour ago is refused with `400` no matter how current `servers.json` is.

The tool handles that in three escalating steps:

1. **Try the next candidates** (`SWITCHING_CANDIDATES`, default 3). Usually one of them is a server
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

### qBittorrent (optional — off unless `QBITTORRENT_URL` is set)

| Variable | Default | Meaning |
|---|---|---|
| `QBITTORRENT_URL` | – | Web UI address, e.g. `http://qbittorrent:8080`. Empty disables the feature. |
| `QBITTORRENT_API_KEY` | – | API key from Preferences → Web UI → API keys. Required when the URL is set. |
| `QBITTORRENT_INTERVAL` | `15s` | How often the rates are read. |
| `QBITTORRENT_TIMEOUT` | `5s` | Per-request timeout. Must be shorter than the interval. |
| `SWITCHING_BUSY_DOWNLOAD` | `8` | **Mbit/s.** Defer automatic switching at or above this download rate. `0` disables this trigger. |
| `SWITCHING_BUSY_UPLOAD` | `8` | **Mbit/s.** Defer automatic switching at or above this upload rate. `0` disables this trigger. |
| `SWITCHING_BUSY_WINDOW` | `5m` | Average the rates over this period before comparing them. `0` uses the latest reading alone. |
| `SWITCHING_BUSY_MAX_DEFER` | unset | Cap on how long a transfer may defer switching. Unset means indefinitely. |

### Server list output

| Variable | Default | Description |
|---|---|---|
| `GLUETUN_SERVERS_FILE` | `/gluetun/servers.json` | Gluetun's **legacy** fat file (used by v3.41.3 and earlier) |
| `GLUETUN_SERVERS_DIR` | `/gluetun/servers` | Gluetun's **directory** layout (current versions). Which one is used is detected automatically |
| `GLUETUN_SERVERS_PREFERRED` | `true` | Set Gluetun's `preferred` flag, making it use our list regardless of timestamps |
| `GLUETUN_SERVERS_WRITE_MODE` | `update` | `update` keeps other providers' sections, `replace` writes only ProtonVPN, `none` disables writing |
| `GLUETUN_SERVERS_SCHEMA_VERSION` | *auto* | Override the detected schema version |
| `GLUETUN_SERVERS_INCLUDE_IPV6` | `false` | Include Proton's IPv6 entry addresses |
| `GLUETUN_SERVERS_ONLY_ALLOWED_COUNTRIES` | `false` | Restrict the file to `FILTER_COUNTRIES` (requires it to be set) |

### Filtering

| Variable | Default | Description |
|---|---|---|
| `FILTER_COUNTRIES` | *all* | Allow-list; accepts codes or names (`SE`, `Sweden`, `netherlands`) |
| `FILTER_EXCLUDE_COUNTRIES` | – | Applied after `FILTER_COUNTRIES` |
| `FILTER_CITIES` | *all* | City allow-list |
| `FILTER_MAX_LOAD` | `90` | Drop servers above this utilisation |
| `FILTER_VPN_TYPE` | `auto` | `auto` follows Gluetun's protocol; or `wireguard` / `openvpn` |
| `FILTER_SECURE_CORE` | `exclude` | `include` / `exclude` / `only` |
| `FILTER_TOR` | `exclude` | `include` / `exclude` / `only` |
| `FILTER_P2P` | `include` | `include` / `exclude` / `only` (Proton only forwards ports on P2P servers) |
| `FILTER_STREAM` | `include` | `include` / `exclude` / `only` |
| `FILTER_FREE_TIER` | `exclude` | `include` / `exclude` / `only` |
| `FILTER_IPV6` | `include` | `include` / `exclude` / `only` — Proton's IPv6 capability flag. `only` restricts the tunnel to IPv6-capable servers. Distinct from `GLUETUN_SERVERS_INCLUDE_IPV6`, which only decides whether a v6 *entry address* is written for Gluetun. |

#### P2P servers are only required when Gluetun asks for a forwarded port

Whether selection is restricted to P2P servers comes entirely from Gluetun's own
port-forwarding settings. **Two** settings matter, and they are easy to confuse:

| Gluetun setting | What it does |
|---|---|
| `VPN_PORT_FORWARDING` | asks Proton for a forwarded port once connected. Gluetun will still connect to a server that cannot give one. |
| `PORT_FORWARD_ONLY` | makes Gluetun *refuse* a server that cannot forward a port. |

**ProtonVPN forwards ports on P2P servers and nowhere else.** So port forwarding
being on at all is a reason to require P2P — otherwise the quietest server wins,
connects perfectly, and never receives a port. Verified against a real Gluetun in
all three configurations, with a deliberately quieter non-P2P server so the choice
is unambiguous:

| `VPN_PORT_FORWARDING` | `PORT_FORWARD_ONLY` | Requirement adopted | Reason shown | Chooses |
|---|---|---|---|---|
| `on` | `on` | `port_forward_only` | `PORT_FORWARD_ONLY` | the P2P server at 40 % load, over a non-P2P one at 5 % |
| `on` | `off` | `port_forward_only` | `VPN_PORT_FORWARDING` | the P2P server at 40 % load — a non-P2P one could never get the port |
| `off` | `off` | none | — | the quieter non-P2P server at 5 % |

Nothing is narrowed when port forwarding is off. `FILTER_P2P` remains a separate,
independent preference (`include` by default) if you want to require or avoid P2P
servers regardless of what Gluetun asks for.

Two caveats worth knowing:

- **An adopted requirement is kept until this container restarts.** Pinning a server
  clears the filter inside Gluetun by design, so a later reading of "off" cannot be
  distinguished from our own doing — the tool assumes the operator still means it. If
  you turn port forwarding off on Gluetun, restart the updater too.
- **The inferred requirement gives way rather than stranding the tunnel.** If
  `VPN_PORT_FORWARDING` is on and no P2P server survives your other filters,
  requiring P2P would leave nothing to connect to at all — while Gluetun itself would
  have connected happily. So it is dropped, with a warning in the log, and you get a
  tunnel without a forwarded port. An explicit `PORT_FORWARD_ONLY` is never dropped:
  that is Gluetun's own filter, and it would refuse those servers regardless.

#### Servers Gluetun cannot use are still listed

A server ruled out by one of those Gluetun-enforced filters does not silently
disappear from the candidate table — that turns "where did my quiet Stockholm server
go?" into a mystery whose answer lives on a different container. Instead it is shown
with an **amber row**, no rank, a **`cannot use`** tag naming the responsible setting,
and a **disabled Use button**. Asking for one over the API is refused with the same
explanation:

```
server "node-se-plain.protonvpn.net" cannot be used: gluetun enforces port_forward_only
```

Only Gluetun-enforced exclusions are listed this way, capped at 25 rows. Servers you
excluded yourself — `FILTER_COUNTRIES`, `FILTER_MAX_LOAD`, a feature filter — are counted in the
**Filtering** panel instead, because you already know about those and listing them
would bury the useful rows under hundreds of self-inflicted ones.

## Scoring and latency

| Variable | Default | Description |
|---|---|---|
| `SCORING_LOAD_WEIGHT` | `1.0` | Weight of `load/100` |
| `SCORING_LATENCY_WEIGHT` | `0.7` | Weight of normalised latency (`0` disables) |
| `SCORING_PROTON_WEIGHT` | `0.0` | Weight of Proton's own score |
| `SCORING_LATENCY_CEILING` | `150ms` | RTT that scores a full latency penalty |
| `SCORING_UNKNOWN_LATENCY_PENALTY` | `0.5` | Assumed value for unprobed servers |
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
| `SWITCHING_AUTO` | `true` | Automatic switching (dashboard toggle persists) |
| `SWITCHING_MODE` | `settings` | `settings` pins an exact hostname; `status` just stop/starts and lets Gluetun choose; `none` never touches the tunnel |
| `SWITCHING_MIN_IMPROVEMENT` | `0.10` | Score gap required to switch |
| `SWITCHING_COOLDOWN` | `15m` | Normal spacing between automatic switches |
| `SWITCHING_MIN_INTERVAL` | `5m` | Hard floor between automatic switches; nothing bypasses it |
| `SWITCHING_LOAD_TRIGGER` | `85` | Skip the cooldown and the improvement threshold above this load, provided the best candidate is below it (`0` disables) |
| `SWITCHING_EVALUATION_INTERVAL` | `5m` | How often the decision is re-run |
| `SWITCHING_VERIFY_TIMEOUT` | `90s` | How long to wait for the tunnel to come back |
| `SWITCHING_CANDIDATES` | `3` | How many servers to try before giving up |

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

### What `info` shows

The default level is meant to answer "is it working" without being read continuously. In steady
state that is roughly four lines an hour:

| Event | Cadence |
|---|---|
| Loads refreshed | every `PROTON_LOAD_REFRESH_INTERVAL` (15 min) |
| Latency swept | every `LATENCY_INTERVAL` (30 min) |
| Server list fetched, servers file written | every `PROTON_REFRESH_INTERVAL` (12 h) |
| Not switching, and why | when the **reason changes** |
| Switching, transfers starting and stopping, anything that failed | when it happens |

Two of those used to be `debug`, which meant that at the default level **nothing at all appeared
between startup and the first latency sweep half an hour later** — a healthy tool looked exactly like
a wedged one. The reason for not switching is logged on change rather than every time, because the
five-minute evaluation would otherwise contribute 288 identical lines a day, which is its own kind of
invisible.

The 30-second health check and the one-minute state flush stay at `debug`: at 2 880 and 1 440 lines a
day they would bury everything else. Raise `LOG_LEVEL=debug` to see them, and note that the
dashboard's *Recent activity* panel shows exactly what the level admits — it is fed by the same
handler.

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
another version with `make integration GLUETUN_VERSION=latest`.

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

**"Gluetun rejected every candidate hostname"**, or an error saying a hostname *"is not one of the
N choices gluetun knows"*. Gluetun is working from its own server list rather than the one written
here. Two causes, in order of likelihood:

1. **Gluetun has not restarted since the list was written.** It reads server data only at startup.
   See [Can Gluetun see a server it did not know at startup?](#can-gluetun-see-a-server-it-did-not-know-at-startup)
2. **The data was written in the layout Gluetun is not reading.** If the reported choice count is
   only a few hundred while the dashboard shows thousands of servers written, this is it. Check the
   `Servers written to` row in *Gluetun's own view* against the layout the running Gluetun uses —
   `v3.41.3` reads `/gluetun/servers.json`, `:latest` reads `/gluetun/servers/protonvpn.json`. Both
   are written whenever the layout is ambiguous, so this should not happen; if it does, please open
   an issue with that row and the Gluetun version.

**A switch fails but names a server that would work.** When Gluetun refuses a hostname it
enumerates every hostname it *would* accept — the only time it discloses the list it is actually
running. That list is captured and used: remaining candidates outside it are skipped instead of
being tried and refused one by one, and the error names the best-ranked server Gluetun can use right
now. The list is discarded as soon as a switch succeeds, since that proves it is out of date.

**Gluetun's own updater is triggered but nothing changes**, and Gluetun logs *"credentials missing:
email is empty - skipping update"*. Refreshing Gluetun's in-memory list needs
`UPDATER_PROTONVPN_EMAIL` and `UPDATER_PROTONVPN_PASSWORD` on the **Gluetun** container. Without
them, restart Gluetun to pick up the list written here.

**Gluetun is stuck at `[vpn] stopping`, and a switch times out after two minutes.** First check the
Gluetun version: **`v3.41.2` has a port-forwarding deadlock that causes exactly this**, and it was
[fixed in `v3.41.3`](https://github.com/passteque/gluetun/releases/tag/v3.41.3) by a one-commit
hotfix. Upgrading is the fix; nothing here can work around a hung VPN loop.

Beyond that specific bug it can still happen, and it is a Gluetun-side stall rather than something
this tool can clear. Gluetun applies a selection *synchronously* —
it stops the VPN loop, applies the change, starts it again, and only then answers — so a stalled
stop blocks the HTTP response for as long as it lasts. Two things make the collision likely rather
than rare: Gluetun's health monitor restarts the loop on its own whenever the tunnel fails a check,
so a struggling tunnel is in transition much of the time; and port forwarding on a server that
cannot forward a port leaves that loop retrying, which is one more thing a stop has to tear down.

Two mitigations are in place. The tool now **waits up to 45 s for the VPN loop to settle** before
sending a selection change, and reports a clear stall rather than blocking for the full mutation
timeout. And requiring P2P whenever port forwarding is on (above) stops the configuration that
provokes it. If it still stalls, restart the Gluetun container.

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
