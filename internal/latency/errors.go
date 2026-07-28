package latency

import "errors"

// ErrUnreachable is recorded when every sample for a server failed without a
// more specific error, which happens when the context is cancelled mid-sweep.
var ErrUnreachable = errors.New("no successful probe")

func orUnreachable(err error) error {
	if err == nil {
		return ErrUnreachable
	}
	return err
}
