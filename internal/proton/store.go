package proton

import (
	"fmt"
	"os"
	"sync"

	"github.com/robinostlund/gluetun-proton-list-updater/internal/atomicfile"
)

// FileSessionStore keeps the Proton session on disk so restarts reuse it.
// Proton rate-limits authentication aggressively, so a container that
// re-authenticates on every restart eventually locks itself out; reusing the
// refresh token avoids that entirely.
type FileSessionStore struct {
	path string
	mu   sync.Mutex
}

// NewFileSessionStore returns a store backed by the file at path.
func NewFileSessionStore(path string) *FileSessionStore {
	return &FileSessionStore{path: path}
}

// Load implements SessionStore. A missing file yields a zero Session and no
// error.
func (s *FileSessionStore) Load() (session Session, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	found, err := atomicfile.ReadJSON(s.path, &session)
	if err != nil {
		return Session{}, err
	}
	if !found {
		return Session{}, nil
	}
	return session, nil
}

// Save implements SessionStore. The file holds bearer tokens, so it is written
// readable only by the owner.
func (s *FileSessionStore) Save(session Session) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return atomicfile.WriteJSON(s.path, session, 0o600)
}

// Clear implements SessionStore.
func (s *FileSessionStore) Clear() (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("removing %s: %w", s.path, err)
	}
	return nil
}
