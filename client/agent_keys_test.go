package client_test

import (
	"crypto/ed25519"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
)

// writeOpenSSHPrivateKey writes an ed25519 private key in OpenSSH's
// openssh-key-v1 PEM format. The format is the same one wssh
// keygen produces and the one a user with `ssh-keygen -t
// ed25519` would have on disk; it is also the only format the
// standard library's ssh.ParsePrivateKey accepts.
//
// The shape of the format is finicky (PROTOCOL.key in
// openssh-portable): a magic prefix, three top-level
// length-prefixed strings (cipher, kdf, kdf-options) each
// followed by a NUL terminator, a key count, a public-key
// blob, a private-key blob whose inner format depends on the
// algorithm. Rather than reimplement all of that by hand --
// which the previous version of this file tried to do and
// which kept getting the per-key format wrong for ed25519 --
// this version delegates to ssh.MarshalPrivateKey, the same
// path the standard library uses to write the bytes in
// MarshalPrivateKey. We just wrap the resulting PEM block and
// write it out.
func writeOpenSSHPrivateKey(t *testing.T, path string, key ed25519.PrivateKey) {
	t.Helper()
	block, err := ssh.MarshalPrivateKey(key, "wssh-test")
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, block); err != nil {
		t.Fatalf("pem encode: %v", err)
	}
}
