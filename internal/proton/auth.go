package proton

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	srp "github.com/ProtonMail/go-srp"
)

// srpModulusBits is the SRP group size Proton uses.
const srpModulusBits = 2048

// twoFactorTOTP is the bit Proton sets in 2FA.Enabled when an authenticator
// app is enrolled. FIDO2 hardware keys use another bit and cannot be satisfied
// with a typed code.
const twoFactorTOTP = 1 << 0

// Session is the set of tokens that make up an authenticated Proton session.
type Session struct {
	UID          string    `json:"uid"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	Scopes       []string  `json:"scopes"`
	CreatedAt    time.Time `json:"created_at"`
}

func (s Session) valid() bool {
	return s.UID != "" && s.AccessToken != "" && s.RefreshToken != ""
}

// HasVPNScope reports whether the session may read VPN data. A session without
// it is usually one that stopped at the two-factor step.
func (s Session) HasVPNScope() bool { return slices.Contains(s.Scopes, "vpn") }

// SessionStore persists a session across restarts.
type SessionStore interface {
	Load() (session Session, err error)
	Save(session Session) (err error)
	Clear() (err error)
}

// sessionHolder guards the current session.
type sessionHolder struct {
	mu      sync.RWMutex
	session Session
}

func (h *sessionHolder) get() Session {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.session
}

func (h *sessionHolder) set(session Session) {
	h.mu.Lock()
	h.session = session
	h.mu.Unlock()
}

func (h *sessionHolder) clear() { h.set(Session{}) }

// ensureSession guarantees a usable session, logging in if there is none.
// A single flight lock prevents two concurrent refreshes from both logging in,
// which Proton would rate-limit.
var loginMutex sync.Mutex

func (c *Client) ensureSession(ctx context.Context) (err error) {
	if session := c.session.get(); session.valid() && session.HasVPNScope() {
		return nil
	}

	loginMutex.Lock()
	defer loginMutex.Unlock()

	// Re-check: another goroutine may have logged in while we waited.
	if session := c.session.get(); session.valid() && session.HasVPNScope() {
		return nil
	}
	return c.login(ctx)
}

// login performs the full SRP handshake, followed by the two-factor step when
// the account requires it.
func (c *Client) login(ctx context.Context) (err error) {
	c.logger.Info("authenticating with Proton")

	info, err := c.authInfo(ctx)
	if err != nil {
		return fmt.Errorf("requesting SRP parameters: %w", err)
	}

	// go-srp verifies the PGP clear-signature on the modulus against Proton's
	// pinned key, so a tampered modulus is rejected here rather than trusted.
	auth, err := srp.NewAuth(info.Version, c.username, []byte(c.password),
		info.Salt, info.Modulus, info.ServerEphemeral)
	if err != nil {
		return fmt.Errorf("initialising SRP: %w", err)
	}

	proofs, err := auth.GenerateProofs(srpModulusBits)
	if err != nil {
		return fmt.Errorf("generating SRP proofs: %w", err)
	}

	session, serverProof, twoFactor, err := c.submitProofs(ctx, info.SRPSession, proofs)
	if err != nil {
		return err
	}

	// Verifying the server proof is what makes SRP mutual: it proves the peer
	// knows our verifier, so a spoofed API cannot harvest the password.
	if !bytes.Equal(serverProof, proofs.ExpectedServerProof) {
		return errors.New("proton: server proof mismatch, refusing to trust the API response")
	}

	if twoFactor.needed() {
		session, err = c.completeTwoFactor(ctx, session, twoFactor)
		if err != nil {
			return err
		}
	}

	if !session.HasVPNScope() {
		return fmt.Errorf("proton: session lacks the vpn scope (scopes: %s)",
			strings.Join(session.Scopes, ", "))
	}

	session.CreatedAt = time.Now()
	c.session.set(session)
	c.persist(session)
	c.logger.Info("authenticated with Proton", "uid", redactUID(session.UID))
	return nil
}

type authInfoResponse struct {
	Code            int    `json:"Code"`
	Modulus         string `json:"Modulus"`
	ServerEphemeral string `json:"ServerEphemeral"`
	Version         int    `json:"Version"`
	Salt            string `json:"Salt"`
	SRPSession      string `json:"SRPSession"`
	Username        string `json:"Username"`
}

func (c *Client) authInfo(ctx context.Context) (info authInfoResponse, err error) {
	request := map[string]string{"Username": c.username}
	_, _, err = c.do(ctx, http.MethodPost, pathAuthInfo, request, nil, Session{}, &info)
	if err != nil {
		return info, err
	}
	switch {
	case info.Modulus == "":
		return info, errors.New("proton: SRP modulus missing from response")
	case info.ServerEphemeral == "":
		return info, errors.New("proton: SRP server ephemeral missing from response")
	case info.Salt == "":
		return info, errors.New("proton: SRP salt missing from response")
	case info.SRPSession == "":
		return info, errors.New("proton: SRP session missing from response")
	}
	return info, nil
}

// twoFactorInfo mirrors the 2FA object Proton returns from /auth.
type twoFactorInfo struct {
	Enabled uint `json:"Enabled"`
	TOTP    uint `json:"TOTP"`
}

func (t twoFactorInfo) needed() bool { return t.Enabled != 0 }

func (t twoFactorInfo) totpEnrolled() bool { return t.Enabled&twoFactorTOTP != 0 }

func (c *Client) submitProofs(ctx context.Context, srpSession string, proofs *srp.Proofs) (
	session Session, serverProof []byte, twoFactor twoFactorInfo, err error,
) {
	request := map[string]string{
		"Username":        c.username,
		"ClientEphemeral": base64.StdEncoding.EncodeToString(proofs.ClientEphemeral),
		"ClientProof":     base64.StdEncoding.EncodeToString(proofs.ClientProof),
		"SRPSession":      srpSession,
	}

	var response struct {
		Code         int           `json:"Code"`
		UID          string        `json:"UID"`
		AccessToken  string        `json:"AccessToken"`
		RefreshToken string        `json:"RefreshToken"`
		Scopes       []string      `json:"Scopes"`
		ServerProof  string        `json:"ServerProof"`
		TwoFactor    uint          `json:"TwoFactor"`
		TwoFA        twoFactorInfo `json:"2FA"`
	}

	_, _, err = c.do(ctx, http.MethodPost, pathAuth, request, nil, Session{}, &response)
	if err != nil {
		var apiErr *APIError
		// 8002 is Proton's "incorrect login credentials" code. Surfacing it as
		// a distinct error lets the caller stop retrying a wrong password.
		if errors.As(err, &apiErr) && apiErr.Code == 8002 {
			return session, nil, twoFactor, fmt.Errorf("%w: %s", ErrInvalidCredentials, apiErr.Message)
		}
		return session, nil, twoFactor, err
	}

	if response.ServerProof == "" {
		return session, nil, twoFactor, errors.New("proton: server proof missing from auth response")
	}
	serverProof, err = base64.StdEncoding.DecodeString(response.ServerProof)
	if err != nil {
		return session, nil, twoFactor, fmt.Errorf("decoding server proof: %w", err)
	}

	session = Session{
		UID:          response.UID,
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		Scopes:       response.Scopes,
	}
	if !session.valid() {
		return session, nil, twoFactor, errors.New("proton: auth response is missing session tokens")
	}

	twoFactor = response.TwoFA
	if response.TwoFactor != 0 && twoFactor.Enabled == 0 {
		// Older API shapes only set the scalar field.
		twoFactor.Enabled = twoFactorTOTP
	}
	return session, serverProof, twoFactor, nil
}

// completeTwoFactor submits a TOTP code for a session that is authenticated but
// not yet scoped for VPN access.
func (c *Client) completeTwoFactor(ctx context.Context, session Session, twoFactor twoFactorInfo) (
	completed Session, err error,
) {
	if !twoFactor.totpEnrolled() {
		return session, errors.New("proton: account requires a two-factor method other than TOTP " +
			"(such as a FIDO2 security key), which this tool cannot satisfy")
	}
	if c.codes == nil {
		return session, ErrTOTPRequired
	}

	code, err := c.codes.Code(ctx)
	if err != nil {
		return session, err
	}

	var response struct {
		Code   int      `json:"Code"`
		Scopes []string `json:"Scopes"`
		Scope  string   `json:"Scope"`
	}
	_, _, err = c.do(ctx, http.MethodPost, pathAuth2FA,
		map[string]string{"TwoFactorCode": code}, nil, session, &response)
	if err != nil {
		return session, fmt.Errorf("submitting two-factor code: %w", err)
	}

	session.Scopes = response.Scopes
	if len(session.Scopes) == 0 && response.Scope != "" {
		session.Scopes = strings.Fields(response.Scope)
	}
	return session, nil
}

// refresh exchanges the refresh token for a new access token.
func (c *Client) refresh(ctx context.Context) (err error) {
	current := c.session.get()
	if current.RefreshToken == "" {
		return errors.New("proton: no refresh token held")
	}

	request := map[string]any{
		"ResponseType": "token",
		"GrantType":    "refresh_token",
		"RefreshToken": current.RefreshToken,
		"RedirectURI":  "http://protonmail.ch",
	}

	var response struct {
		Code         int      `json:"Code"`
		UID          string   `json:"UID"`
		AccessToken  string   `json:"AccessToken"`
		RefreshToken string   `json:"RefreshToken"`
		Scopes       []string `json:"Scopes"`
	}
	if _, _, err := c.do(ctx, http.MethodPost, pathAuthRefresh, request, nil, current, &response); err != nil {
		return err
	}
	if response.AccessToken == "" || response.RefreshToken == "" {
		return errors.New("proton: refresh response is missing tokens")
	}

	refreshed := Session{
		UID:          current.UID,
		AccessToken:  response.AccessToken,
		RefreshToken: response.RefreshToken,
		Scopes:       response.Scopes,
		CreatedAt:    time.Now(),
	}
	if response.UID != "" {
		refreshed.UID = response.UID
	}
	// A refresh keeps existing scopes when the response omits them.
	if len(refreshed.Scopes) == 0 {
		refreshed.Scopes = current.Scopes
	}

	c.session.set(refreshed)
	c.persist(refreshed)
	c.logger.Debug("refreshed proton session")
	return nil
}

// Logout invalidates the session server-side and locally. Failures are only
// logged: a stale session on Proton's side is harmless, and shutdown must not
// be held up.
func (c *Client) Logout(ctx context.Context) {
	session := c.session.get()
	if !session.valid() {
		return
	}
	if _, _, err := c.do(ctx, http.MethodDelete, pathAuth, nil, nil, session, nil); err != nil {
		c.logger.Debug("proton logout failed", "error", err)
	}
	c.session.clear()
	if c.store != nil {
		if err := c.store.Clear(); err != nil {
			c.logger.Debug("clearing stored proton session failed", "error", err)
		}
	}
}

func (c *Client) persist(session Session) {
	if c.store == nil {
		return
	}
	if err := c.store.Save(session); err != nil {
		c.logger.Warn("could not persist proton session", "error", err)
	}
}
