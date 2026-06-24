package pgp

import (
	"errors"
	"fmt"
	"net/mail"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	gcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
	keyring "github.com/zalando/go-keyring"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
	"github.com/ThalesMMS/PGP-Client-go/internal/storage"
)

// Service coordinates OpenPGP operations and persistence. The implementation
// deliberately keeps GUI concerns out of cryptographic code.
type Service struct {
	store    *storage.Store
	secrets  storage.SecretStore
	cache    *storage.SecretCache
	mu       sync.RWMutex
	settings model.Settings
}

func NewService(store *storage.Store, secrets storage.SecretStore) (*Service, error) {
	if store == nil {
		return nil, errors.New("armazenamento nulo")
	}
	if secrets == nil {
		secrets = storage.SystemSecretStore{}
	}
	settings, err := store.LoadSettings()
	if err != nil {
		return nil, err
	}
	return &Service{
		store:    store,
		secrets:  secrets,
		cache:    storage.NewSecretCache(),
		settings: settings,
	}, nil
}

func NewDefaultService() (*Service, error) {
	store, err := storage.New("")
	if err != nil {
		return nil, err
	}
	return NewService(store, storage.SystemSecretStore{})
}

func (s *Service) StoreRoot() string { return s.store.Root() }

func (s *Service) Settings() model.Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSettings(s.settings)
}

func (s *Service) SaveSettings(settings model.Settings) error {
	if settings.DefaultKeyBits != 2048 && settings.DefaultKeyBits != 3072 && settings.DefaultKeyBits != 4096 {
		return model.ErrUnsupportedKeySize
	}
	if settings.DefaultExpiryDays < 0 {
		return errors.New("validade padrão não pode ser negativa")
	}
	if settings.BackupReminderDays < 0 {
		return errors.New("intervalo de backup não pode ser negativo")
	}
	if settings.PassphraseCacheMinutes < 1 {
		settings.PassphraseCacheMinutes = 1
	}
	if _, err := NewKeyserverClient(settings.DefaultKeyserver); err != nil {
		return err
	}
	settings = cloneSettings(settings)
	if err := s.store.SaveSettings(settings); err != nil {
		return err
	}
	s.mu.Lock()
	s.settings = settings
	s.mu.Unlock()
	return nil
}

func cloneSettings(settings model.Settings) model.Settings {
	if settings.LastBackupAt != nil {
		lastBackup := *settings.LastBackupAt
		settings.LastBackupAt = &lastBackup
	}
	return settings
}

func (s *Service) LockNow() { s.cache.Clear() }

func (s *Service) MarkBackupCreated() error {
	settings := s.Settings()
	now := time.Now().UTC()
	settings.LastBackupAt = &now
	return s.SaveSettings(settings)
}

func (s *Service) GenerateKey(req model.KeyGenerationRequest) (model.KeyInfo, error) {
	req.Name = strings.TrimSpace(req.Name)
	req.Email = strings.TrimSpace(req.Email)
	req.Comment = strings.TrimSpace(req.Comment)
	if req.Name == "" && req.Email == "" {
		return model.KeyInfo{}, errors.New("informe nome ou e-mail")
	}
	if req.Email != "" {
		address, err := mail.ParseAddress(req.Email)
		if err != nil || !strings.EqualFold(address.Address, req.Email) {
			return model.KeyInfo{}, errors.New("e-mail inválido")
		}
	}
	if req.Bits == 0 {
		req.Bits = s.Settings().DefaultKeyBits
	}
	if req.Bits != 2048 && req.Bits != 3072 && req.Bits != 4096 {
		return model.KeyInfo{}, model.ErrUnsupportedKeySize
	}
	if req.ExpiryDays < 0 {
		return model.KeyInfo{}, errors.New("validade não pode ser negativa")
	}
	var lifetime uint32
	if req.ExpiryDays > 0 {
		seconds := int64(req.ExpiryDays) * 24 * 60 * 60
		if seconds > int64(^uint32(0)) {
			return model.KeyInfo{}, errors.New("validade excede o limite do formato OpenPGP")
		}
		lifetime = uint32(seconds)
	}

	config := &packet.Config{
		Algorithm:       packet.PubKeyAlgoRSA,
		RSABits:         req.Bits,
		KeyLifetimeSecs: lifetime,
	}
	entity, err := openpgp.NewEntity(req.Name, req.Comment, req.Email, config)
	if err != nil {
		return model.KeyInfo{}, fmt.Errorf("gerar chave RSA: %w", err)
	}
	key, err := gcrypto.NewKeyFromEntity(entity)
	if err != nil {
		return model.KeyInfo{}, err
	}
	if len(req.Passphrase) > 0 {
		key, err = gcrypto.PGP().LockKey(key, req.Passphrase)
		if err != nil {
			return model.KeyInfo{}, fmt.Errorf("proteger chave privada: %w", err)
		}
	}
	if err := s.store.SaveKey(key); err != nil {
		return model.KeyInfo{}, err
	}
	fingerprint := normalizeFingerprint(key.GetFingerprint())
	if len(req.Passphrase) > 0 {
		s.cache.Put(fingerprint, req.Passphrase, s.cacheTTL())
		if req.RememberSecret {
			if err := s.secrets.Set(fingerprint, req.Passphrase); err != nil {
				s.cache.Delete(fingerprint)
				_ = s.secrets.Delete(fingerprint)
				if cleanupErr := s.store.DeleteKey(fingerprint); cleanupErr != nil {
					return model.KeyInfo{}, errors.Join(
						fmt.Errorf("salvar frase secreta no cofre do sistema: %w", err),
						fmt.Errorf("reverter chave criada: %w", cleanupErr),
					)
				}
				return model.KeyInfo{}, fmt.Errorf("salvar frase secreta no cofre do sistema: %w", err)
			}
		}
	}
	return s.KeyInfo(fingerprint)
}

func (s *Service) Import(data []byte) ([]model.KeyInfo, error) {
	keys, err := storage.ParseKeyBundle(data)
	if err != nil {
		return nil, err
	}
	infos := make([]model.KeyInfo, 0, len(keys))
	for _, key := range keys {
		if err := s.store.SaveKey(key); err != nil {
			return nil, err
		}
		info, err := s.KeyInfo(key.GetFingerprint())
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (s *Service) ListKeys() ([]model.KeyInfo, error) {
	keys, err := s.store.LoadAllKeys()
	if err != nil {
		return nil, err
	}
	metadata, err := s.store.Metadata()
	if err != nil {
		return nil, err
	}
	infos := make([]model.KeyInfo, 0, len(keys))
	for _, key := range keys {
		info, err := extractKeyInfo(key, metadata[normalizeFingerprint(key.GetFingerprint())])
		if err != nil {
			return nil, err
		}
		infos = append(infos, info)
	}
	sort.SliceStable(infos, func(i, j int) bool {
		left := strings.ToLower(infos[i].DisplayName() + infos[i].Email)
		right := strings.ToLower(infos[j].DisplayName() + infos[j].Email)
		if left == right {
			return infos[i].Fingerprint < infos[j].Fingerprint
		}
		return left < right
	})
	return infos, nil
}

func (s *Service) KeyInfo(fingerprint string) (model.KeyInfo, error) {
	key, err := s.store.LoadKey(fingerprint)
	if err != nil {
		return model.KeyInfo{}, err
	}
	metadata, err := s.store.Metadata()
	if err != nil {
		return model.KeyInfo{}, err
	}
	return extractKeyInfo(key, metadata[normalizeFingerprint(key.GetFingerprint())])
}

func (s *Service) DeleteKey(fingerprint string) error {
	fingerprint = normalizeFingerprint(fingerprint)
	if err := s.store.DeleteKey(fingerprint); err != nil {
		return err
	}
	s.cache.Delete(fingerprint)
	_ = s.secrets.Delete(fingerprint)
	return nil
}

func (s *Service) ExportPublic(fingerprint string) ([]byte, error) {
	key, err := s.store.LoadKey(fingerprint)
	if err != nil {
		return nil, err
	}
	armored, err := key.GetArmoredPublicKey()
	if err != nil {
		return nil, fmt.Errorf("exportar chave pública: %w", err)
	}
	return []byte(armored), nil
}

func (s *Service) ExportPrivate(fingerprint string) ([]byte, error) {
	key, err := s.store.LoadKey(fingerprint)
	if err != nil {
		return nil, err
	}
	if !key.IsPrivate() {
		return nil, model.ErrNoPrivateKey
	}
	armored, err := key.Armor()
	if err != nil {
		return nil, fmt.Errorf("exportar chave privada: %w", err)
	}
	return []byte(armored), nil
}

func (s *Service) SetTrust(fingerprint string, trust model.TrustLevel) error {
	switch trust {
	case model.TrustUnknown, model.TrustNever, model.TrustMarginal, model.TrustFull, model.TrustUltimate:
	default:
		return errors.New("nível de confiança inválido")
	}
	return s.store.UpdateMetadata(fingerprint, func(metadata *model.KeyMetadata) {
		metadata.Trust = trust
	})
}

func (s *Service) MarkVerified(fingerprint, method string, verified bool) error {
	return s.store.UpdateMetadata(fingerprint, func(metadata *model.KeyMetadata) {
		metadata.Verified = verified
		metadata.VerificationMethod = strings.TrimSpace(method)
		if verified {
			now := time.Now().UTC()
			metadata.VerifiedAt = &now
		} else {
			metadata.VerifiedAt = nil
		}
	})
}

func (s *Service) RememberPassphrase(fingerprint string, passphrase []byte) error {
	key, err := s.unlockPrivate(fingerprint, passphrase, false)
	if err != nil {
		return err
	}
	_ = key
	return s.secrets.Set(normalizeFingerprint(fingerprint), passphrase)
}

func (s *Service) ForgetPassphrase(fingerprint string) error {
	s.cache.Delete(fingerprint)
	return s.secrets.Delete(normalizeFingerprint(fingerprint))
}

func (s *Service) RevokeKey(fingerprint string, passphrase []byte, reason packet.ReasonForRevocation, reasonText string) error {
	stored, err := s.store.LoadKey(fingerprint)
	if err != nil {
		return err
	}
	wasLocked, _ := stored.IsLocked()
	key, err := s.unlockPrivate(fingerprint, passphrase, false)
	if err != nil {
		return err
	}
	if err := key.GetEntity().Revoke(reason, strings.TrimSpace(reasonText), &packet.Config{}); err != nil {
		return fmt.Errorf("revogar chave: %w", err)
	}
	if wasLocked {
		used, err := s.obtainPassphrase(fingerprint, passphrase)
		if err != nil {
			return err
		}
		key, err = gcrypto.PGP().LockKey(key, used)
		if err != nil {
			return fmt.Errorf("reproteger chave revogada: %w", err)
		}
	}
	return s.store.SaveKey(key)
}

func (s *Service) unlockPrivate(fingerprint string, supplied []byte, remember bool) (*gcrypto.Key, error) {
	fingerprint = normalizeFingerprint(fingerprint)
	key, err := s.store.LoadKey(fingerprint)
	if err != nil {
		return nil, err
	}
	if !key.IsPrivate() {
		return nil, model.ErrNoPrivateKey
	}
	locked, err := key.IsLocked()
	if err != nil {
		return nil, fmt.Errorf("verificar proteção da chave: %w", err)
	}
	if !locked {
		return key, nil
	}
	passphrase, err := s.obtainPassphrase(fingerprint, supplied)
	if err != nil {
		if errors.Is(err, model.ErrPassphraseRequired) {
			return nil, s.passphraseRequired(fingerprint)
		}
		return nil, err
	}
	unlocked, err := key.Unlock(passphrase)
	if err != nil {
		if len(supplied) > 0 {
			return nil, model.ErrInvalidPassphrase
		}
		// A stale cache or vault entry must not prevent a manual retry.
		s.cache.Delete(fingerprint)
		return nil, s.passphraseRequired(fingerprint)
	}
	s.cache.Put(fingerprint, passphrase, s.cacheTTL())
	if remember {
		if err := s.secrets.Set(fingerprint, passphrase); err != nil {
			return nil, err
		}
	}
	return unlocked, nil
}

func (s *Service) passphraseRequired(fingerprint string) *model.PassphraseRequiredError {
	info, _ := s.KeyInfo(fingerprint)
	return &model.PassphraseRequiredError{Fingerprint: fingerprint, Identity: info.PrimaryIdentity()}
}

func (s *Service) obtainPassphrase(fingerprint string, supplied []byte) ([]byte, error) {
	if len(supplied) > 0 {
		return append([]byte(nil), supplied...), nil
	}
	if passphrase, ok := s.cache.Get(fingerprint); ok {
		return passphrase, nil
	}
	passphrase, err := s.secrets.Get(normalizeFingerprint(fingerprint))
	if err == nil && len(passphrase) > 0 {
		return passphrase, nil
	}
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		// Platform vault unavailability must not block a manual passphrase prompt.
		return nil, model.ErrPassphraseRequired
	}
	return nil, model.ErrPassphraseRequired
}

func (s *Service) cacheTTL() time.Duration {
	minutes := s.Settings().PassphraseCacheMinutes
	if minutes < 1 {
		minutes = 1
	}
	return time.Duration(minutes) * time.Minute
}

func normalizeFingerprint(value string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(value), " ", ""))
}

func extractKeyInfo(key *gcrypto.Key, metadata model.KeyMetadata) (model.KeyInfo, error) {
	entity := key.GetEntity()
	if entity == nil || entity.PrimaryKey == nil {
		return model.KeyInfo{}, errors.New("certificado OpenPGP sem chave primária")
	}
	fingerprint := normalizeFingerprint(key.GetFingerprint())
	if metadata.Fingerprint == "" {
		metadata = model.KeyMetadata{Fingerprint: fingerprint, Trust: model.TrustUnknown, ImportedAt: time.Now().UTC()}
	}

	identities := make([]string, 0, len(entity.Identities))
	type identity struct{ name, email, comment, rendered string }
	parsed := make([]identity, 0, len(entity.Identities))
	for _, item := range entity.Identities {
		if item == nil || item.UserId == nil {
			continue
		}
		rendered := item.UserId.Id
		if rendered == "" {
			rendered = strings.TrimSpace(item.UserId.Name + " <" + item.UserId.Email + ">")
		}
		parsed = append(parsed, identity{item.UserId.Name, item.UserId.Email, item.UserId.Comment, rendered})
	}
	sort.Slice(parsed, func(i, j int) bool { return parsed[i].rendered < parsed[j].rendered })
	for _, item := range parsed {
		identities = append(identities, item.rendered)
	}
	var name, email, comment string
	if len(parsed) > 0 {
		name, email, comment = parsed[0].name, parsed[0].email, parsed[0].comment
	}

	bits, _ := entity.PrimaryKey.BitLength()
	created := entity.PrimaryKey.CreationTime
	var expiresAt *time.Time
	if selfSignature, err := entity.PrimarySelfSignature(time.Time{}, &packet.Config{}); err == nil &&
		selfSignature != nil && selfSignature.KeyLifetimeSecs != nil && *selfSignature.KeyLifetimeSecs > 0 {
		expires := created.Add(time.Duration(*selfSignature.KeyLifetimeSecs) * time.Second)
		expiresAt = &expires
	}
	locked := false
	if key.IsPrivate() {
		locked, _ = key.IsLocked()
	}
	now := time.Now()
	return model.KeyInfo{
		Fingerprint: fingerprint,
		KeyID:       strings.ToUpper(key.GetHexKeyID()),
		ShortKeyID:  shortKeyID(key.GetHexKeyID()),
		Name:        name,
		Email:       email,
		Comment:     comment,
		UserIDs:     identities,
		Algorithm:   algorithmName(entity.PrimaryKey.PubKeyAlgo),
		Bits:        int(bits),
		CreatedAt:   created,
		ExpiresAt:   expiresAt,
		IsPrivate:   key.IsPrivate(),
		IsLocked:    locked,
		CanEncrypt:  key.CanEncrypt(now.Unix()),
		CanVerify:   key.CanVerify(now.Unix()),
		Expired:     key.IsExpired(now.Unix()),
		Revoked:     key.IsRevoked(now.Unix()),
		Metadata:    metadata,
	}, nil
}

func shortKeyID(value string) string {
	value = strings.ToUpper(value)
	if len(value) > 8 {
		return value[len(value)-8:]
	}
	return value
}

func algorithmName(algorithm packet.PublicKeyAlgorithm) string {
	switch algorithm {
	case packet.PubKeyAlgoRSA, packet.PubKeyAlgoRSAEncryptOnly, packet.PubKeyAlgoRSASignOnly:
		return "RSA"
	case packet.PubKeyAlgoDSA:
		return "DSA"
	case packet.PubKeyAlgoElGamal:
		return "ElGamal"
	case packet.PubKeyAlgoECDSA:
		return "ECDSA"
	case packet.PubKeyAlgoECDH:
		return "ECDH"
	case packet.PubKeyAlgoEdDSA:
		return "EdDSA"
	default:
		return fmt.Sprintf("OpenPGP (%d)", algorithm)
	}
}
