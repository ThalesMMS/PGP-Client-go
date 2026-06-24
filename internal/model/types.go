package model

import "time"

// TrustLevel represents the local trust assigned by the user. It is intentionally
// stored outside the OpenPGP certificate because local trust is application state.
type TrustLevel string

const (
	TrustUnknown  TrustLevel = "unknown"
	TrustNever    TrustLevel = "never"
	TrustMarginal TrustLevel = "marginal"
	TrustFull     TrustLevel = "full"
	TrustUltimate TrustLevel = "ultimate"
)

// KeyMetadata is application-owned state associated with an OpenPGP key.
type KeyMetadata struct {
	Fingerprint        string     `json:"fingerprint"`
	Trust              TrustLevel `json:"trust"`
	Verified           bool       `json:"verified"`
	VerificationMethod string     `json:"verificationMethod,omitempty"`
	VerifiedAt         *time.Time `json:"verifiedAt,omitempty"`
	ImportedAt         time.Time  `json:"importedAt"`
	LastKeyserverSync  *time.Time `json:"lastKeyserverSync,omitempty"`
}

// KeyInfo is the immutable projection used by the UI and CLI.
type KeyInfo struct {
	Fingerprint string
	KeyID       string
	ShortKeyID  string
	Name        string
	Email       string
	Comment     string
	UserIDs     []string
	Algorithm   string
	Bits        int
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	IsPrivate   bool
	IsLocked    bool
	CanEncrypt  bool
	CanVerify   bool
	Expired     bool
	Revoked     bool
	Metadata    KeyMetadata
}

func (k KeyInfo) DisplayName() string {
	if k.Name != "" {
		return k.Name
	}
	if k.Email != "" {
		return k.Email
	}
	return k.ShortKeyID
}

func (k KeyInfo) PrimaryIdentity() string {
	if k.Name != "" && k.Email != "" {
		return k.Name + " <" + k.Email + ">"
	}
	return k.DisplayName()
}

// Settings contains non-secret application preferences.
type Settings struct {
	Language                 string     `json:"language"`
	DefaultArmor             bool       `json:"defaultArmor"`
	DefaultKeyBits           int        `json:"defaultKeyBits"`
	DefaultExpiryDays        int        `json:"defaultExpiryDays"`
	RememberPassphrases      bool       `json:"rememberPassphrases"`
	PassphraseCacheMinutes   int        `json:"passphraseCacheMinutes"`
	ConfirmBeforeDelete      bool       `json:"confirmBeforeDelete"`
	ShowFullKeyID            bool       `json:"showFullKeyID"`
	DefaultKeyserver         string     `json:"defaultKeyserver"`
	BackupReminderDays       int        `json:"backupReminderDays"`
	LastBackupAt             *time.Time `json:"lastBackupAt,omitempty"`
	WarnOnUntrustedRecipient bool       `json:"warnOnUntrustedRecipient"`
}

func DefaultSettings() Settings {
	return Settings{
		Language:                 "pt-BR",
		DefaultArmor:             true,
		DefaultKeyBits:           3072,
		DefaultExpiryDays:        730,
		RememberPassphrases:      false,
		PassphraseCacheMinutes:   15,
		ConfirmBeforeDelete:      true,
		ShowFullKeyID:            true,
		DefaultKeyserver:         "https://keys.openpgp.org",
		BackupReminderDays:       30,
		WarnOnUntrustedRecipient: true,
	}
}

// KeyGenerationRequest defines a new RSA OpenPGP key.
type KeyGenerationRequest struct {
	Name           string
	Email          string
	Comment        string
	Bits           int
	ExpiryDays     int
	Passphrase     []byte
	RememberSecret bool
}

// EncryptRequest defines public-key or password-based encryption.
type EncryptRequest struct {
	Plaintext             []byte
	RecipientFingerprints []string
	Password              []byte
	SignerFingerprint     string
	SignerPassphrase      []byte
	Armor                 bool
	Compress              bool
	UTF8                  bool
}

// DecryptRequest defines decryption and optional embedded-signature verification.
type DecryptRequest struct {
	Ciphertext  []byte
	Passphrases map[string][]byte
	Password    []byte
	UTF8        bool
}

// DecryptResult contains plaintext and signature information.
type DecryptResult struct {
	Plaintext         []byte
	Filename          string
	SignaturePresent  bool
	SignatureValid    bool
	SignatureError    string
	SignerKeyID       string
	SignatureTime     *time.Time
	RecipientKeyIDs   []string
	UsedSymmetricMode bool
}

type SignatureMode string

const (
	SignatureDetached  SignatureMode = "detached"
	SignatureInline    SignatureMode = "inline"
	SignatureCleartext SignatureMode = "cleartext"
)

type SignRequest struct {
	Data              []byte
	SignerFingerprint string
	Passphrase        []byte
	Mode              SignatureMode
	Armor             bool
	UTF8              bool
}

type VerifyRequest struct {
	Data      []byte
	Signature []byte
	Mode      SignatureMode
	UTF8      bool
}

type VerifyResult struct {
	Data          []byte
	Valid         bool
	SignatureErr  string
	SignerKeyID   string
	SignerName    string
	SignerEmail   string
	SignatureTime *time.Time
}

// KeyserverResult is a machine-readable HKP search result.
type KeyserverResult struct {
	KeyID       string
	Fingerprint string
	Algorithm   string
	Bits        int
	CreatedAt   time.Time
	ExpiresAt   *time.Time
	Revoked     bool
	Disabled    bool
	Expired     bool
	UserIDs     []string
}
