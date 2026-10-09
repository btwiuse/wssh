package shell

import (
	"os"
	"runtime"
	"strings"
	"testing"
)

// The fold in hasEnv is the part no session test can reach from a single
// platform: it exists so a Windows client sending "Path=" does not end up
// with a second "PATH=" appended beside it.
func TestHasEnv(t *testing.T) {
	env := []string{"HOME=/home/tester", "Path=C:\\Windows", "LANG=C"}

	tests := []struct {
		key  string
		want bool
	}{
		{"HOME", true},
		{"home", true},
		{"PATH", true},
		{"path", true},
		{"LANG", true},
		{"USER", false},
		{"PAT", false}, // a prefix is not a match
		{"PATH_EXTRA", false},
	}

	for _, tt := range tests {
		if got := hasEnv(env, tt.key); got != tt.want {
			t.Errorf("hasEnv(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

// A PATH that names directories which do not exist would be worse than none:
// the session would look like it had a PATH and still fail to find anything.
func TestSystemPathNamesRealDirectories(t *testing.T) {
	got := systemPath()
	if got == "" {
		t.Fatal("systemPath is empty")
	}

	sep := ":"
	if runtime.GOOS == "windows" {
		sep = ";"
		if !strings.Contains(got, sep) {
			t.Errorf("windows PATH %q should be semicolon separated", got)
		}
	} else if got != defaultPath {
		t.Errorf("systemPath() = %q, want sshd's %q", got, defaultPath)
	}

	for _, dir := range strings.Split(got, sep) {
		if info, err := os.Stat(dir); err != nil || !info.IsDir() {
			t.Errorf("systemPath() names %q, which is not a directory", dir)
		}
	}
}
