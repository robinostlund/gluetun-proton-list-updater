package proton

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"sync"
	"time"
)

// codeAppVersionUnsupported is Proton's "This version of the app is no longer
// supported" code, answered with HTTP 422 to any request whose x-pm-appversion
// is older than Proton's current minimum for that client family.
const codeAppVersionUnsupported = 5003

// AppVersionHeader returns the x-pm-appversion the official Linux GUI client
// sends for a given release.
func AppVersionHeader(version string) string { return "linux-vpn-gui@" + version }

// UserAgentFor returns the User-Agent the official Linux GUI client sends.
func UserAgentFor(version string) string { return "ProtonVPN/" + version + " (Linux)" }

// AppVersionResolver returns the newest Proton VPN Linux GUI release, as a
// bare semantic version such as "4.19.0".
type AppVersionResolver func(ctx context.Context) (version string, err error)

// appVersionUpgradeCooldown bounds how often a 5003 can trigger a lookup, so
// a version Proton keeps rejecting cannot hammer the resolver.
const appVersionUpgradeCooldown = 10 * time.Minute

// identity holds the mutable client identity headers.
type identity struct {
	mu          sync.RWMutex
	appVersion  string
	userAgent   string
	lastAttempt time.Time
	upgradeMu   sync.Mutex // serialises upgrades so concurrent 5003s look up once
}

func (i *identity) get() (appVersion, userAgent string) {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.appVersion, i.userAgent
}

// upgradeAppVersion is called after Proton answered 5003 to a request sent
// with x-pm-appversion set to rejected. It reports whether the identity now
// differs from rejected, meaning a retry is worthwhile.
func (c *Client) upgradeAppVersion(ctx context.Context, rejected string) bool {
	if c.resolveVersion == nil {
		return false
	}
	c.identity.upgradeMu.Lock()
	defer c.identity.upgradeMu.Unlock()

	// Another goroutine may already have upgraded while we waited.
	if current, _ := c.identity.get(); current != rejected {
		return true
	}
	c.identity.mu.RLock()
	last := c.identity.lastAttempt
	c.identity.mu.RUnlock()
	if !last.IsZero() && time.Since(last) < appVersionUpgradeCooldown {
		return false
	}
	c.identity.mu.Lock()
	c.identity.lastAttempt = time.Now()
	c.identity.mu.Unlock()

	version, err := c.resolveVersion(ctx)
	if err != nil {
		c.logger.Warn("proton rejected the app version and the latest one could not be looked up; "+
			"set PROTON_APP_VERSION to a current linux-vpn-gui@ version",
			"rejected", rejected, "error", err)
		return false
	}
	appVersion := AppVersionHeader(version)
	if appVersion == rejected {
		c.logger.Warn("proton rejected the newest known app version", "app_version", appVersion)
		return false
	}

	c.identity.mu.Lock()
	c.identity.appVersion = appVersion
	c.identity.userAgent = UserAgentFor(version)
	c.identity.mu.Unlock()
	c.logger.Warn("proton rejected the app version as too old, switched to the latest release",
		"rejected", rejected, "app_version", appVersion,
		"hint", "update PROTON_APP_VERSION (or unset it) to avoid this lookup")
	return true
}

// gtkTagPattern matches stable release tags of ProtonVPN/proton-vpn-gtk-app.
var gtkTagPattern = regexp.MustCompile(`^v(\d+)\.(\d+)\.(\d+)$`)

// GitHubAppVersionResolver looks up the newest stable tag of the official
// Proton VPN Linux GTK app on GitHub. It is only consulted after Proton
// answers 5003, so the unauthenticated GitHub rate limit is not a concern.
func GitHubAppVersionResolver(httpClient *http.Client) AppVersionResolver {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 15 * time.Second}
	}
	return func(ctx context.Context) (string, error) {
		const url = "https://api.github.com/repos/ProtonVPN/proton-vpn-gtk-app/tags?per_page=100"
		request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
		if err != nil {
			return "", err
		}
		request.Header.Set("Accept", "application/vnd.github+json")
		response, err := httpClient.Do(request)
		if err != nil {
			return "", fmt.Errorf("fetching proton-vpn-gtk-app tags: %w", err)
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusOK {
			snippet, _ := io.ReadAll(io.LimitReader(response.Body, 512))
			return "", fmt.Errorf("fetching proton-vpn-gtk-app tags: HTTP %d: %s", response.StatusCode, snippet)
		}
		var tags []struct {
			Name string `json:"name"`
		}
		if err := json.NewDecoder(io.LimitReader(response.Body, 4<<20)).Decode(&tags); err != nil {
			return "", fmt.Errorf("decoding proton-vpn-gtk-app tags: %w", err)
		}
		names := make([]string, len(tags))
		for i, tag := range tags {
			names[i] = tag.Name
		}
		version, ok := newestStableTag(names)
		if !ok {
			return "", fmt.Errorf("no stable release tag among %d proton-vpn-gtk-app tags", len(tags))
		}
		return version, nil
	}
}

// newestStableTag returns the highest vX.Y.Z tag without its "v". Tags are
// compared numerically: GitHub's listing order is not semantic-version order.
func newestStableTag(tags []string) (version string, ok bool) {
	var best [3]int
	for _, tag := range tags {
		match := gtkTagPattern.FindStringSubmatch(tag)
		if match == nil {
			continue
		}
		var parts [3]int
		for i := range parts {
			parts[i], _ = strconv.Atoi(match[i+1])
		}
		if !ok || parts[0] > best[0] ||
			(parts[0] == best[0] && (parts[1] > best[1] || (parts[1] == best[1] && parts[2] > best[2]))) {
			best, version, ok = parts, tag[1:], true
		}
	}
	return version, ok
}
