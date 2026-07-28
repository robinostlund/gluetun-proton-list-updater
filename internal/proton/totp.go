package proton

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/pquerna/otp/totp"
)

// SecretCodeProvider generates TOTP codes from the account's shared secret, so
// two-factor login needs no human involvement.
type SecretCodeProvider struct {
	secret string
}

// NewSecretCodeProvider validates the base32 secret up front - a typo in an
// environment variable should fail at startup, not hours later when the session
// expires.
func NewSecretCodeProvider(secret string) (provider *SecretCodeProvider, err error) {
	secret = strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(secret), " ", ""))
	if secret == "" {
		return nil, errors.New("proton: empty TOTP secret")
	}
	if _, err := totp.GenerateCode(secret, time.Now()); err != nil {
		return nil, fmt.Errorf("proton: invalid TOTP secret: %w", err)
	}
	return &SecretCodeProvider{secret: secret}, nil
}

// Code implements CodeProvider.
func (p *SecretCodeProvider) Code(_ context.Context) (code string, err error) {
	code, err = totp.GenerateCode(p.secret, time.Now())
	if err != nil {
		return "", fmt.Errorf("proton: generating TOTP code: %w", err)
	}
	return code, nil
}

// ManualCodeProvider waits for a code to be submitted out of band, which is how
// the dashboard supports accounts whose TOTP secret is not available to the
// container.
type ManualCodeProvider struct {
	// Timeout bounds how long a login waits for a human.
	Timeout time.Duration

	mu      sync.Mutex
	waiting bool
	codes   chan string
}

// NewManualCodeProvider returns a provider that blocks until Submit is called.
func NewManualCodeProvider(timeout time.Duration) *ManualCodeProvider {
	if timeout <= 0 {
		timeout = 10 * time.Minute
	}
	return &ManualCodeProvider{
		Timeout: timeout,
		// Buffered so a code submitted a moment before the login reaches this
		// point is not lost.
		codes: make(chan string, 1),
	}
}

// Code implements CodeProvider.
func (p *ManualCodeProvider) Code(ctx context.Context) (code string, err error) {
	p.setWaiting(true)
	defer p.setWaiting(false)

	timer := time.NewTimer(p.Timeout)
	defer timer.Stop()

	select {
	case code = <-p.codes:
		return code, nil
	case <-timer.C:
		return "", fmt.Errorf("%w: no code submitted within %s", ErrTOTPRequired, p.Timeout)
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Submit hands a code to a waiting login. It reports false when nothing is
// waiting, so the dashboard can tell the user their code was not needed.
func (p *ManualCodeProvider) Submit(code string) (accepted bool) {
	code = strings.TrimSpace(code)
	if code == "" {
		return false
	}
	select {
	case p.codes <- code:
		return true
	default:
		return false
	}
}

// Waiting reports whether a login is currently blocked on a code.
func (p *ManualCodeProvider) Waiting() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.waiting
}

func (p *ManualCodeProvider) setWaiting(waiting bool) {
	p.mu.Lock()
	p.waiting = waiting
	p.mu.Unlock()
}
