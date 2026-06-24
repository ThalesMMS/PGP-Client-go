package pgp

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"time"

	gcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
)

func (s *Service) Encrypt(req model.EncryptRequest) ([]byte, error) {
	builder := gcrypto.PGP().Encryption()

	if len(req.RecipientFingerprints) > 0 {
		recipients, err := s.publicKeyRing(req.RecipientFingerprints, true)
		if err != nil {
			return nil, err
		}
		builder = builder.Recipients(recipients)
	} else if len(req.Password) > 0 {
		// GopenPGP clears passwords held by a handle. Pass a private copy so a
		// service call never mutates the caller's request buffer.
		builder = builder.Password(append([]byte(nil), req.Password...))
	} else {
		return nil, model.ErrNoRecipients
	}

	if req.SignerFingerprint != "" {
		signer, err := s.unlockPrivate(req.SignerFingerprint, req.SignerPassphrase, false)
		if err != nil {
			return nil, err
		}
		builder = builder.SigningKey(signer)
	}
	if req.Compress {
		builder = builder.Compress()
	}
	if req.UTF8 {
		builder = builder.Utf8()
	}
	handle, err := builder.New()
	if err != nil {
		return nil, fmt.Errorf("configurar criptografia: %w", err)
	}
	defer handle.ClearPrivateParams()
	message, err := handle.Encrypt(req.Plaintext)
	if err != nil {
		return nil, fmt.Errorf("criptografar: %w", err)
	}
	if req.Armor {
		armored, err := message.ArmorBytes()
		if err != nil {
			return nil, fmt.Errorf("codificar ASCII armor: %w", err)
		}
		return armored, nil
	}
	return message.Bytes(), nil
}

func (s *Service) Decrypt(req model.DecryptRequest) (model.DecryptResult, error) {
	message := gcrypto.NewPGPMessage(req.Ciphertext)
	trimmed := strings.TrimSpace(string(req.Ciphertext))
	if strings.HasPrefix(trimmed, "-----BEGIN PGP MESSAGE-----") {
		var err error
		message, err = gcrypto.NewPGPMessageFromArmored(trimmed)
		if err != nil {
			return model.DecryptResult{}, fmt.Errorf("interpretar mensagem blindada: %w", err)
		}
	}
	recipientIDs, _ := message.HexEncryptionKeyIDs()
	envelope, inspectErr := inspectEncryptionPackets(bytes.NewReader(message.Bytes()))
	if inspectErr == nil {
		recipientIDs = envelope.recipientIDs
	} else {
		envelope.recipientIDs = recipientIDs
	}
	result := model.DecryptResult{
		RecipientKeyIDs:   append([]string(nil), recipientIDs...),
		UsedSymmetricMode: inspectErr == nil && envelope.symmetricRecipient && !envelope.hasPublicRecipient(),
	}
	if result.UsedSymmetricMode && len(req.Password) == 0 {
		return result, model.ErrPasswordRequired
	}

	builder := gcrypto.PGP().Decryption().MaxDecompressedMessageSize(1 << 30)
	var privateRing *gcrypto.KeyRing
	var required *model.PassphraseRequiredError
	needPrivateKeys := inspectErr != nil || envelope.hasPublicRecipient() || !envelope.symmetricRecipient
	if len(req.Password) > 0 && envelope.symmetricRecipient {
		needPrivateKeys = false
	}
	if needPrivateKeys {
		lookupIDs := recipientIDs
		if (inspectErr != nil && len(lookupIDs) == 0) || envelope.anonymousRecipient {
			lookupIDs = nil
		}
		var err error
		privateRing, required, err = s.decryptionKeyRing(lookupIDs, req.Passphrases)
		if err != nil {
			return result, err
		}
	}
	if privateRing != nil && privateRing.CountEntities() > 0 {
		builder = builder.DecryptionKeys(privateRing)
	}
	if len(req.Password) > 0 {
		builder = builder.Password(append([]byte(nil), req.Password...))
	}
	if (privateRing == nil || privateRing.CountEntities() == 0) && len(req.Password) == 0 {
		if required != nil {
			return result, required
		}
		return result, model.ErrNoPrivateKey
	}
	verificationRing, _ := s.allPublicKeyRing()
	if verificationRing != nil && verificationRing.CountEntities() > 0 {
		builder = builder.VerificationKeys(verificationRing)
	}
	if req.UTF8 {
		builder = builder.Utf8()
	}
	handle, err := builder.New()
	if err != nil {
		return result, fmt.Errorf("configurar descriptografia: %w", err)
	}
	defer handle.ClearPrivateParams()
	verified, err := handle.Decrypt(req.Ciphertext, gcrypto.Auto)
	if err != nil {
		// A matching locked key may still be pending even when another key was tried.
		if required != nil {
			return result, required
		}
		return result, fmt.Errorf("descriptografar: %w", err)
	}
	result.Plaintext = verified.Bytes()
	if metadata := verified.Metadata(); metadata != nil {
		result.Filename = metadata.Filename()
	}
	fillDecryptSignature(&result, &verified.VerifyResult)
	return result, nil
}

func (s *Service) Sign(req model.SignRequest) ([]byte, error) {
	if strings.TrimSpace(req.SignerFingerprint) == "" {
		return nil, model.ErrNoPrivateKey
	}
	signer, err := s.unlockPrivate(req.SignerFingerprint, req.Passphrase, false)
	if err != nil {
		return nil, err
	}
	builder := gcrypto.PGP().Sign().SigningKey(signer)
	if req.UTF8 || req.Mode == model.SignatureCleartext {
		builder = builder.Utf8()
	}
	if req.Mode == model.SignatureDetached {
		builder = builder.Detached()
	}
	handle, err := builder.New()
	if err != nil {
		return nil, fmt.Errorf("configurar assinatura: %w", err)
	}
	defer handle.ClearPrivateParams()
	if req.Mode == model.SignatureCleartext {
		result, err := handle.SignCleartext(req.Data)
		if err != nil {
			return nil, fmt.Errorf("assinar texto claro: %w", err)
		}
		return result, nil
	}
	encoding := int8(gcrypto.Bytes)
	if req.Armor {
		encoding = gcrypto.Armor
	}
	result, err := handle.Sign(req.Data, encoding)
	if err != nil {
		return nil, fmt.Errorf("assinar: %w", err)
	}
	return result, nil
}

func (s *Service) Verify(req model.VerifyRequest) (model.VerifyResult, error) {
	keyRing, err := s.allPublicKeyRing()
	if err != nil {
		return model.VerifyResult{}, err
	}
	if keyRing == nil || keyRing.CountEntities() == 0 {
		return model.VerifyResult{}, model.ErrNoVerificationKeys
	}
	builder := gcrypto.PGP().Verify().VerificationKeys(keyRing).MaxDecompressedMessageSize(1 << 30)
	if req.UTF8 || req.Mode == model.SignatureCleartext {
		builder = builder.Utf8()
	}
	handle, err := builder.New()
	if err != nil {
		return model.VerifyResult{}, fmt.Errorf("configurar verificação: %w", err)
	}

	var verification *gcrypto.VerifyResult
	var data []byte
	switch req.Mode {
	case model.SignatureDetached:
		verification, err = handle.VerifyDetached(req.Data, req.Signature, gcrypto.Auto)
	case model.SignatureCleartext:
		var cleartext *gcrypto.VerifyCleartextResult
		cleartext, err = handle.VerifyCleartext(req.Signature)
		if cleartext != nil {
			verification = &cleartext.VerifyResult
			data = cleartext.Cleartext()
		}
	default:
		var inline *gcrypto.VerifiedDataResult
		inline, err = handle.VerifyInline(req.Signature, gcrypto.Auto)
		if inline != nil {
			verification = &inline.VerifyResult
			data = inline.Bytes()
		}
	}
	if err != nil {
		return model.VerifyResult{}, fmt.Errorf("verificar assinatura: %w", err)
	}
	result := model.VerifyResult{Data: data}
	fillVerifyResult(&result, verification)
	return result, nil
}

func (s *Service) publicKeyRing(fingerprints []string, requireEncryption bool) (*gcrypto.KeyRing, error) {
	ring, _ := gcrypto.NewKeyRing(nil)
	seen := make(map[string]bool)
	for _, fingerprint := range fingerprints {
		fingerprint = normalizeFingerprint(fingerprint)
		if fingerprint == "" || seen[fingerprint] {
			continue
		}
		seen[fingerprint] = true
		key, err := s.store.LoadKey(fingerprint)
		if err != nil {
			return nil, err
		}
		public, err := key.ToPublic()
		if err != nil {
			return nil, fmt.Errorf("extrair chave pública: %w", err)
		}
		if requireEncryption && !public.CanEncrypt(time.Now().Unix()) {
			return nil, fmt.Errorf("%s: chave não apta para criptografia", fingerprint)
		}
		if err := ring.AddKey(public); err != nil {
			return nil, err
		}
	}
	if ring.CountEntities() == 0 {
		return nil, model.ErrNoRecipients
	}
	return ring, nil
}

func (s *Service) allPublicKeyRing() (*gcrypto.KeyRing, error) {
	keys, err := s.store.LoadAllKeys()
	if err != nil {
		return nil, err
	}
	ring, _ := gcrypto.NewKeyRing(nil)
	for _, key := range keys {
		public, err := key.ToPublic()
		if err != nil {
			continue
		}
		if err := ring.AddKey(public); err != nil {
			return nil, err
		}
	}
	return ring, nil
}

func (s *Service) decryptionKeyRing(recipientIDs []string, passphrases map[string][]byte) (*gcrypto.KeyRing, *model.PassphraseRequiredError, error) {
	keys, err := s.store.LoadAllKeys()
	if err != nil {
		return nil, nil, err
	}
	wanted := make(map[string]bool)
	for _, id := range recipientIDs {
		wanted[strings.ToUpper(id)] = true
	}
	ring, _ := gcrypto.NewKeyRing(nil)
	var required *model.PassphraseRequiredError
	for _, key := range keys {
		if !key.IsPrivate() {
			continue
		}
		if len(wanted) > 0 && !matchesAnyKeyID(key, wanted) {
			continue
		}
		fingerprint := normalizeFingerprint(key.GetFingerprint())
		passphrase := passphrases[fingerprint]
		unlocked, unlockErr := s.unlockPrivate(fingerprint, passphrase, false)
		if unlockErr != nil {
			var prompt *model.PassphraseRequiredError
			if errors.As(unlockErr, &prompt) {
				if required == nil {
					required = prompt
				}
				continue
			}
			return nil, nil, unlockErr
		}
		if err := ring.AddKey(unlocked); err != nil {
			return nil, nil, err
		}
	}
	return ring, required, nil
}

func matchesAnyKeyID(key *gcrypto.Key, wanted map[string]bool) bool {
	entity := key.GetEntity()
	if entity == nil || entity.PrimaryKey == nil {
		return false
	}
	if wanted[strings.ToUpper(fmt.Sprintf("%016X", entity.PrimaryKey.KeyId))] {
		return true
	}
	for _, subkey := range entity.Subkeys {
		if subkey.PublicKey != nil && wanted[strings.ToUpper(fmt.Sprintf("%016X", subkey.PublicKey.KeyId))] {
			return true
		}
	}
	return false
}

func fillDecryptSignature(result *model.DecryptResult, verification *gcrypto.VerifyResult) {
	if verification == nil || len(verification.Signatures) == 0 {
		return
	}
	result.SignaturePresent = true
	result.SignerKeyID = strings.ToUpper(verification.SignedByKeyIdHex())
	if unix := verification.SignatureCreationTime(); unix > 0 {
		t := time.Unix(unix, 0)
		result.SignatureTime = &t
	}
	if err := verification.SignatureError(); err != nil {
		result.SignatureError = err.Error()
		return
	}
	result.SignatureValid = true
}

func fillVerifyResult(result *model.VerifyResult, verification *gcrypto.VerifyResult) {
	if verification == nil {
		result.SignatureErr = "resultado de verificação ausente"
		return
	}
	result.SignerKeyID = strings.ToUpper(verification.SignedByKeyIdHex())
	if unix := verification.SignatureCreationTime(); unix > 0 {
		t := time.Unix(unix, 0)
		result.SignatureTime = &t
	}
	if signer := verification.SignedByKey(); signer != nil {
		entity := signer.GetEntity()
		for _, identity := range entity.Identities {
			if identity != nil && identity.UserId != nil {
				result.SignerName = identity.UserId.Name
				result.SignerEmail = identity.UserId.Email
				break
			}
		}
	}
	if err := verification.SignatureError(); err != nil {
		result.SignatureErr = err.Error()
		return
	}
	result.Valid = true
}
