package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/keygen"
	"github.com/spf13/cobra"
)

// defaultKeyType is ed25519 because it is small, fast and has no parameters to
// get wrong. RSA and ECDSA are here for the peers that insist.
const defaultKeyType = "ed25519"

func newKeygenCmd() *cobra.Command {
	var (
		keyType    string
		bits       int
		comment    string
		outDir     string
		name       string
		passphrase string
		authorized string
		force      bool
	)

	cmd := &cobra.Command{
		Use:   "keygen [name]",
		Short: "Generate a key pair to authenticate with",
		Long: `Generate a key pair to authenticate with.

Writes the private key to disk and prints the public key, which is what goes
into a server's authorized_keys. Nothing is written to the server for you:
the public key has to be copied across, and that step is the point.

The private key is written with owner-only permissions, and will refuse to
overwrite an existing file unless asked.`,
		Example: `  # An ed25519 key in the current directory
  wssh keygen

  # RSA, for a peer that will not take anything else
  wssh keygen --type rsa --bits 4096

  # Into ~/.ssh, named like ssh would name it
  wssh keygen --out-dir ~/.ssh id_ed25519

  # Also append the public key to an authorized_keys file
  wssh keygen --authorized-keys ~/.ssh/authorized_keys`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) == 1 {
				name = args[0]
			}
			if name == "" {
				name = "id_" + keyType
			}

			kind, err := parseKeyType(keyType)
			if err != nil {
				return err
			}

			path := name
			if outDir != "" {
				path = filepath.Join(outDir, name)
			}

			// Checked before generating, not after: keygen writes the files as
			// part of creating the pair, so afterwards it is always too late.
			// Overwriting a private key on a whim is how logins get lost.
			if _, err := os.Stat(path); err == nil && !force {
				return fmt.Errorf("a key is already there at %s; "+
					"pass --force to replace it", path)
			}

			pair, err := keygen.New(path,
				keygen.WithKeyType(kind),
				keygen.WithWrite(),
				keygen.WithPassphrase(passphrase),
				bitOption(kind, bits),
			)
			if err != nil {
				return fmt.Errorf("generate key: %w", err)
			}

			fmt.Printf("%s\n", pair.AuthorizedKey())

			if authorized != "" {
				if err := appendAuthorizedKey(authorized, pair.AuthorizedKey()); err != nil {
					return err
				}
				fmt.Fprintf(os.Stderr, "appended to %s\n", authorized)
			}
			fmt.Fprintf(os.Stderr, "\nwrote %s and %s.pub\n", path, path)
			if passphrase == "" {
				fmt.Fprintf(os.Stderr, "keep %s private: anyone holding it can log in as you\n", path)
			}
			return nil
		},
	}

	cmd.Flags().StringVar(&keyType, "type", defaultKeyType,
		"key type: ed25519, rsa or ecdsa")
	cmd.Flags().IntVar(&bits, "bits", 0, "RSA key size in bits (ignored for the other types)")
	cmd.Flags().StringVar(&comment, "comment", "", "comment to record in the public key")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "directory to write the keys into")
	cmd.Flags().StringVar(&passphrase, "passphrase", "",
		"encrypt the private key with this passphrase; asked for when empty")
	cmd.Flags().StringVar(&authorized, "authorized-keys", "",
		"append the public key to this authorized_keys file")
	cmd.Flags().BoolVar(&force, "force", false, "overwrite an existing key")

	return cmd
}

func parseKeyType(name string) (keygen.KeyType, error) {
	switch strings.ToLower(name) {
	case "ed25519", "":
		return keygen.Ed25519, nil
	case "rsa":
		return keygen.RSA, nil
	case "ecdsa":
		return keygen.ECDSA, nil
	default:
		return "", fmt.Errorf("unknown key type %q: use ed25519, rsa or ecdsa", name)
	}
}

// bitOption only means something for RSA; passing a size to the other types
// would be a confusing way of saying nothing.
func bitOption(kind keygen.KeyType, bits int) keygen.Option {
	if kind != keygen.RSA || bits <= 0 {
		return func(*keygen.KeyPair) {}
	}
	return keygen.WithBitSize(bits)
}

// appendAuthorizedKey adds a line to an authorized_keys file, creating it if
// needed. Keys are appended rather than written so that adding one does not
// quietly revoke the others.
func appendAuthorizedKey(path, authorizedKey string) error {
	if dir := filepath.Dir(path); dir != "" {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return err //nolint:wrapcheck
		}
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("open %s: %w", path, err)
	}
	defer f.Close() //nolint:errcheck

	// The mode above only applies when the file is created. ssh refuses to
	// read an authorized_keys that anyone else can write to, so tightening an
	// existing file is part of appending to it.
	if err := f.Chmod(0o600); err != nil {
		return fmt.Errorf("chmod %s: %w", path, err)
	}

	if _, err := fmt.Fprintf(f, "%s\n", strings.TrimSpace(authorizedKey)); err != nil {
		return err //nolint:wrapcheck
	}
	return nil
}
