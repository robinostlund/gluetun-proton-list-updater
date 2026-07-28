package atomicfile

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestWriteReplacesAtomically(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "file.json")

	if err := Write(path, []byte("first"), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := Write(path, []byte("second"), 0o644); err != nil {
		t.Fatalf("Write: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "second" {
		t.Errorf("contents = %q, want second", data)
	}
}

func TestWriteCreatesMissingDirectories(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "nested", "deeper", "file.json")

	if err := Write(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file was not created: %v", err)
	}
}

func TestWriteAppliesPermissions(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("file modes are not meaningful on windows")
	}

	path := filepath.Join(t.TempDir(), "secret.json")
	if err := Write(path, []byte("token"), 0o600); err != nil {
		t.Fatalf("Write: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode = %o, want 600", got)
	}
}

// A failed write must not leave temporary files behind, or a long-running
// container slowly fills its volume.
func TestWriteLeavesNoTemporaryFiles(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	path := filepath.Join(directory, "file.json")

	if err := Write(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "file.json" {
		names := make([]string, len(entries))
		for i, entry := range entries {
			names[i] = entry.Name()
		}
		t.Errorf("directory contains %v, want only file.json", names)
	}
}

func TestWriteAndReadJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "value.json")

	type payload struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}

	if err := WriteJSON(path, payload{Name: "proton", Count: 3}, 0o600); err != nil {
		t.Fatalf("WriteJSON: %v", err)
	}

	var decoded payload
	found, err := ReadJSON(path, &decoded)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if !found || decoded.Name != "proton" || decoded.Count != 3 {
		t.Errorf("decoded = %+v (found %v)", decoded, found)
	}
}

// A missing file is the normal first-run state, not an error.
func TestReadJSONMissingFile(t *testing.T) {
	t.Parallel()

	var value map[string]any
	found, err := ReadJSON(filepath.Join(t.TempDir(), "absent.json"), &value)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if found {
		t.Error("found should be false")
	}
}

func TestReadJSONEmptyFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "empty.json")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}

	var value map[string]any
	found, err := ReadJSON(path, &value)
	if err != nil {
		t.Fatalf("ReadJSON: %v", err)
	}
	if found {
		t.Error("an empty file should be treated as absent")
	}
}

func TestReadJSONCorruptFile(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "broken.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	var value map[string]any
	found, err := ReadJSON(path, &value)
	if err == nil {
		t.Fatal("expected a decoding error")
	}
	if !found {
		t.Error("found should be true: the file exists, it is just unusable")
	}
}
