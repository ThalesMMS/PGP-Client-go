package model

import (
	"errors"
	"fmt"
)

var (
	ErrKeyNotFound         = errors.New("chave OpenPGP não encontrada")
	ErrNoRecipients        = errors.New("nenhum destinatário selecionado")
	ErrNoPrivateKey        = errors.New("nenhuma chave privada compatível disponível")
	ErrNoVerificationKeys  = errors.New("nenhuma chave pública disponível para verificação")
	ErrPassphraseRequired  = errors.New("frase secreta necessária")
	ErrPasswordRequired    = errors.New("senha simétrica necessária")
	ErrInvalidPassphrase   = errors.New("frase secreta inválida")
	ErrUnsupportedKeySize  = errors.New("tamanho de chave RSA não suportado")
	ErrInvalidBackupFormat = errors.New("formato de backup inválido")
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
