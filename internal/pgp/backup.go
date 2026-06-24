package pgp

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"golang.org/x/crypto/argon2"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
)

const backupMagic = "PGPCLIENTBACKUP1\n"

const maxBackupArchiveSize = 256 << 20

const (
	backupKDFTime    uint32 = 3
	backupKDFMemory  uint32 = 64 * 1024 // KiB
	backupKDFThreads uint8  = 4
	backupKeyLength  uint32 = 32
)

type backupPayload struct {
	Version   int                          `json:"version"`
	CreatedAt time.Time                    `json:"createdAt"`
	Keys      []string                     `json:"keys"`
	Metadata  map[string]model.KeyMetadata `json:"metadata"`
	Settings  model.Settings               `json:"settings"`
}

type backupEnvelope struct {
	Version    int    `json:"version"`
	KDF        string `json:"kdf"`
	KDFTime    uint32 `json:"kdfTime"`
	KDFMemory  uint32 `json:"kdfMemoryKiB"`
	KDFThreads uint8  `json:"kdfThreads"`
	Salt       string `json:"salt"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

// CreateBackup serializes all public/private key material, local trust metadata
// and settings into an Argon2id + AES-256-GCM encrypted archive.
func (s *Service) CreateBackup(password []byte) ([]byte, error) {
	if len(password) < 8 {
		return nil, errors.New("backup password must be at least 8 characters")
	}
	keys, err := s.store.LoadAllKeys()
	if err != nil {
		return nil, err
	}
	armoredKeys := make([]string, 0, len(keys))
	for _, key := range keys {
		var armored string
		if key.IsPrivate() {
			armored, err = key.Armor()
		} else {
			armored, err = key.GetArmoredPublicKey()
		}
		if err != nil {
			return nil, fmt.Errorf("serialize key for backup: %w", err)
		}
		armoredKeys = append(armoredKeys, armored)
	}
	metadata, err := s.store.Metadata()
	if err != nil {
		return nil, err
	}
	payloadBytes, err := json.Marshal(backupPayload{
		Version:   1,
		CreatedAt: time.Now().UTC(),
		Keys:      armoredKeys,
		Metadata:  metadata,
		Settings:  s.Settings(),
	})
	if err != nil {
		return nil, fmt.Errorf("serialize backup: %w", err)
	}
	defer wipe(payloadBytes)

	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}
	key := argon2.IDKey(password, salt, backupKDFTime, backupKDFMemory, backupKDFThreads, backupKeyLength)
	defer wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	ciphertext := gcm.Seal(nil, nonce, payloadBytes, []byte(backupMagic))
	envelope := backupEnvelope{
		Version:    1,
		KDF:        "argon2id",
		KDFTime:    backupKDFTime,
		KDFMemory:  backupKDFMemory,
		KDFThreads: backupKDFThreads,
		Salt:       base64.StdEncoding.EncodeToString(salt),
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertext),
	}
	encoded, err := json.MarshalIndent(envelope, "", "  ")
	if err != nil {
		return nil, err
	}
	return append([]byte(backupMagic), append(encoded, '\n')...), nil
}

// RestoreBackup decrypts and imports an archive. Existing private keys are not
// downgraded by public-only records. Local metadata is merged by fingerprint.
func (s *Service) RestoreBackup(archive, password []byte, restoreSettings bool) ([]model.KeyInfo, error) {
	if len(archive) < len(backupMagic) || len(archive) > maxBackupArchiveSize || string(archive[:len(backupMagic)]) != backupMagic {
		return nil, model.ErrInvalidBackupFormat
	}
	var envelope backupEnvelope
	if err := json.Unmarshal(archive[len(backupMagic):], &envelope); err != nil {
		return nil, model.ErrInvalidBackupFormat
	}
	if envelope.Version != 1 || envelope.KDF != "argon2id" || envelope.KDFTime == 0 || envelope.KDFTime > 10 || envelope.KDFMemory < 8*1024 || envelope.KDFMemory > 256*1024 || envelope.KDFThreads == 0 || envelope.KDFThreads > 16 {
		return nil, model.ErrInvalidBackupFormat
	}
	salt, err := base64.StdEncoding.DecodeString(envelope.Salt)
	if err != nil || len(salt) < 16 || len(salt) > 64 {
		return nil, model.ErrInvalidBackupFormat
	}
	nonce, err := base64.StdEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return nil, model.ErrInvalidBackupFormat
	}
	ciphertext, err := base64.StdEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return nil, model.ErrInvalidBackupFormat
	}
	key := argon2.IDKey(password, salt, envelope.KDFTime, envelope.KDFMemory, envelope.KDFThreads, backupKeyLength)
	defer wipe(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(nonce) != gcm.NonceSize() {
		return nil, model.ErrInvalidBackupFormat
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, []byte(backupMagic))
	if err != nil {
		return nil, errors.New("incorrect password or tampered backup")
	}
	defer wipe(plaintext)
	var payload backupPayload
	if err := json.Unmarshal(plaintext, &payload); err != nil || payload.Version != 1 {
		return nil, model.ErrInvalidBackupFormat
	}

	var restored []model.KeyInfo
	for _, armored := range payload.Keys {
		infos, err := s.Import([]byte(armored))
		if err != nil {
			return nil, fmt.Errorf("restore key: %w", err)
		}
		restored = append(restored, infos...)
	}
	for fingerprint, metadata := range payload.Metadata {
		metadata := metadata
		if err := s.store.UpdateMetadata(fingerprint, func(target *model.KeyMetadata) {
			*target = metadata
		}); err != nil {
			return nil, fmt.Errorf("restore metadata for %s: %w", fingerprint, err)
		}
	}
	if restoreSettings {
		if err := s.SaveSettings(payload.Settings); err != nil {
			return nil, err
		}
	}
	return restored, nil
}

func wipe(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
