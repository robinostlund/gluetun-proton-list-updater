// Package preflight validates the environment before the engine starts.
//
// It exists because of a failure that is otherwise very easy to miss: if the
// state directory or the directory holding servers.json is not writable, the
// tool still authenticates, still fetches Proton's server list and still looks
// healthy - while silently never writing the one file Gluetun reads. Failing
// loudly at startup, with the actual uid and the actual fix, is far kinder than
// a warning buried in the log.
package preflight

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Check describes one directory that must be writable.
type Check struct {
	// Path is the directory to test.
	Path string
	// Purpose is a human description used in the error message.
	Purpose string
	// Hint is appended to the error when the check fails.
	Hint string
}

// Verify tests every check and returns a single error describing all failures.
//
// Directories are created when missing, which is the normal first-run case for
// a fresh volume.
func Verify(checks ...Check) (err error) {
	var problems []string

	for _, check := range checks {
		if check.Path == "" {
			continue
		}
		if problem := verifyOne(check); problem != "" {
			problems = append(problems, problem)
		}
	}

	if len(problems) == 0 {
		return nil
	}
	return fmt.Errorf("%w:\n  - %s\n\n%s", ErrNotWritable,
		strings.Join(problems, "\n  - "), ownershipAdvice())
}

// ErrNotWritable is returned when any directory cannot be written to.
var ErrNotWritable = errors.New("required directories are not writable")

func verifyOne(check Check) (problem string) {
	if err := os.MkdirAll(check.Path, 0o755); err != nil {
		return fmt.Sprintf("%s (%s): cannot create directory: %s", check.Path, check.Purpose, err)
	}

	info, err := os.Stat(check.Path)
	if err != nil {
		return fmt.Sprintf("%s (%s): %s", check.Path, check.Purpose, err)
	}
	if !info.IsDir() {
		return fmt.Sprintf("%s (%s): not a directory", check.Path, check.Purpose)
	}

	// Actually create a file rather than inspecting the mode bits: only a write
	// accounts for ownership, group membership, read-only mounts and ACLs all at
	// once.
	probe, err := os.CreateTemp(check.Path, ".preflight*")
	if err != nil {
		message := fmt.Sprintf("%s (%s): %s", check.Path, check.Purpose, err)
		if check.Hint != "" {
			message += "\n      " + check.Hint
		}
		return message
	}
	name := probe.Name()
	_ = probe.Close()
	_ = os.Remove(name)
	return ""
}

// ownershipAdvice spells out the fix, including the identity this process is
// actually running as - which is the piece an operator otherwise has to guess.
func ownershipAdvice() string {
	uid, gid := os.Getuid(), os.Getgid()
	return fmt.Sprintf(
		"This process runs as uid %d, gid %d.\n"+
			"Either let it run as root (the default, and what Gluetun itself does, since Gluetun\n"+
			"creates /gluetun owned by root), or give uid %d ownership of the paths above:\n"+
			"  chown -R %d:%d <path>\n"+
			"For a bind mount, run that on the host directory.",
		uid, gid, uid, uid, gid)
}

// ServersDir returns the directory that must be writable in order to replace the
// servers file. Writes are atomic, so it is the directory - not the file - that
// needs to be writable.
func ServersDir(serversFile string) string {
	if serversFile == "" {
		return ""
	}
	return filepath.Dir(serversFile)
}
