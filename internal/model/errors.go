package model

import (
	"errors"
	"fmt"
)

var (
	ErrKeyNotFound         = errors.New("OpenPGP key not found")
	ErrNoRecipients        = errors.New("no recipients selected")
	ErrNoPrivateKey        = errors.New("no compatible private key available")
	ErrNoVerificationKeys  = errors.New("no public keys available for verification")
	ErrPassphraseRequired  = errors.New("passphrase required")
	ErrPasswordRequired    = errors.New("symmetric password required")
	ErrInvalidPassphrase   = errors.New("invalid passphrase")
	ErrUnsupportedKeySize  = errors.New("unsupported RSA key size")
	ErrInvalidBackupFormat = errors.New("invalid backup format")
)

// PassphraseRequiredError lets the UI prompt for one specific secret key.
type PassphraseRequiredError struct {
	Fingerprint string
	Identity    string
}

func (e *PassphraseRequiredError) Error() string {
	if e.Identity != "" {
		return fmt.Sprintf("%s para %s", ErrPassphraseRequired, e.Identity)
	}
	return ErrPassphraseRequired.Error()
}

func (e *PassphraseRequiredError) Unwrap() error { return ErrPassphraseRequired }
