// Package atomicfile writes files so a reader never observes a partial write.
//
// This matters more than usual here: Gluetun reads servers.json at startup, and
// a half-written file would either be discarded or, worse, leave Gluetun with
// no servers at all. Writing to a temporary file in the same directory and
// renaming it over the target makes the replacement atomic on POSIX systems.
package atomicfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// Write atomically replaces the file at path with data.
//
// The temporary file is created in the target's directory, because rename is
// only atomic within a filesystem and /tmp is frequently a different mount in
// containers.
func Write(path string, data []byte, perm os.FileMode) (err error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return fmt.Errorf("creating directory %s: %w", directory, err)
	}

	temporary, err := os.CreateTemp(directory, "."+filepath.Base(path)+".tmp*")
	if err != nil {
		return fmt.Errorf("creating temporary file in %s: %w", directory, err)
	}
	temporaryName := temporary.Name()

	// From here on every failure must remove the temporary file, otherwise a
	// long-running container slowly litters the volume.
	defer func() {
		if err != nil {
			_ = os.Remove(temporaryName)
		}
	}()

	if _, err = temporary.Write(data); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("writing %s: %w", temporaryName, err)
	}
	// fsync before rename: without it a crash can leave a renamed but empty
	// file, which is exactly the state we are trying to make impossible.
	if err = temporary.Sync(); err != nil {
		_ = temporary.Close()
		return fmt.Errorf("syncing %s: %w", temporaryName, err)
	}
	if err = temporary.Close(); err != nil {
		return fmt.Errorf("closing %s: %w", temporaryName, err)
	}
	if err = os.Chmod(temporaryName, perm); err != nil {
		return fmt.Errorf("setting permissions on %s: %w", temporaryName, err)
	}
	if err = os.Rename(temporaryName, path); err != nil {
		return fmt.Errorf("renaming %s to %s: %w", temporaryName, path, err)
	}
	return nil
}

// WriteJSON marshals value as indented JSON and writes it atomically.
func WriteJSON(path string, value any, perm os.FileMode) (err error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding JSON for %s: %w", path, err)
	}
	data = append(data, '\n')
	return Write(path, data, perm)
}

// ReadJSON decodes the JSON file at path into value. A missing file reports
// found=false with no error, since "not there yet" is the normal first-run
// state for every file this package manages.
func ReadJSON(path string, value any) (found bool, err error) {
	data, err := os.ReadFile(path) //nolint:gosec // operator-provided path by design
	switch {
	case os.IsNotExist(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("reading %s: %w", path, err)
	case len(data) == 0:
		return false, nil
	}
	if err := json.Unmarshal(data, value); err != nil {
		return true, fmt.Errorf("decoding %s: %w", path, err)
	}
	return true, nil
}
