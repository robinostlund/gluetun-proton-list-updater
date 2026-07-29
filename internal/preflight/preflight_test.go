package preflight

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyPassesForAWritableDirectory(t *testing.T) {
	t.Parallel()

	err := Verify(Check{Path: t.TempDir(), Purpose: "state"})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// A fresh volume starts empty, so creating the directory is the normal case.
func TestVerifyCreatesMissingDirectories(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "nested", "state")
	if err := Verify(Check{Path: path, Purpose: "state"}); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if info, err := os.Stat(path); err != nil || !info.IsDir() {
		t.Errorf("directory was not created: %v", err)
	}
}

// The whole point of the package: an unwritable directory must stop startup.
func TestVerifyFailsForAnUnwritableDirectory(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on windows")
	}
	if os.Getuid() == 0 {
		t.Skip("root can write to any directory, so this cannot be tested as root")
	}

	path := filepath.Join(t.TempDir(), "readonly")
	if err := os.Mkdir(path, 0o555); err != nil {
		t.Fatal(err)
	}

	err := Verify(Check{
		Path:    path,
		Purpose: "servers.json directory",
		Hint:    "Gluetun creates this directory owned by root.",
	})
	if err == nil {
		t.Fatal("expected an error for a read-only directory")
	}
	if !errors.Is(err, ErrNotWritable) {
		t.Errorf("err = %v, want ErrNotWritable", err)
	}

	// The message has to be actionable: the path, the purpose, the hint, the
	// identity it runs as, and the chown that fixes it.
	message := err.Error()
	for _, want := range []string{path, "servers.json directory", "Gluetun creates this directory", "uid", "chown"} {
		if !strings.Contains(message, want) {
			t.Errorf("error message is missing %q:\n%s", want, message)
		}
	}
}

// All failures at once, so one restart is enough to learn about both.
func TestVerifyReportsEveryFailure(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" || os.Getuid() == 0 {
		t.Skip("needs POSIX modes and a non-root user")
	}

	base := t.TempDir()
	first := filepath.Join(base, "one")
	second := filepath.Join(base, "two")
	for _, path := range []string{first, second} {
		if err := os.Mkdir(path, 0o555); err != nil {
			t.Fatal(err)
		}
	}

	err := Verify(
		Check{Path: first, Purpose: "state"},
		Check{Path: second, Purpose: "servers"},
	)
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), first) || !strings.Contains(err.Error(), second) {
		t.Errorf("both paths should be reported:\n%s", err)
	}
}

func TestVerifyIgnoresEmptyPaths(t *testing.T) {
	t.Parallel()

	if err := Verify(Check{Path: "", Purpose: "disabled"}); err != nil {
		t.Errorf("an empty path should be skipped, got %v", err)
	}
}

func TestVerifyRejectsAFileWhereADirectoryIsExpected(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "afile")
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := Verify(Check{Path: path, Purpose: "state"}); err == nil {
		t.Fatal("expected an error when the path is a file")
	}
}

// Writes are atomic, so it is the containing directory that must be writable.
func TestServersDir(t *testing.T) {
	t.Parallel()

	if got := ServersDir("/gluetun/servers.json"); got != "/gluetun" {
		t.Errorf("ServersDir = %q, want /gluetun", got)
	}
	if got := ServersDir(""); got != "" {
		t.Errorf("ServersDir(\"\") = %q, want empty", got)
	}
}
