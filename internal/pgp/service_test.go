package pgp

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
	"github.com/ThalesMMS/PGP-Client-go/internal/storage"
)

func newTestService(t *testing.T) *Service {
	t.Helper()
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, storage.NewMemorySecretStore())
	if err != nil {
		t.Fatal(err)
	}
	settings := service.Settings()
	settings.PassphraseCacheMinutes = 5
	if err := service.SaveSettings(settings); err != nil {
		t.Fatal(err)
	}
	return service
}

func generateTestKey(t *testing.T, service *Service, name, email, passphrase string) model.KeyInfo {
	t.Helper()
	info, err := service.GenerateKey(model.KeyGenerationRequest{
		Name:       name,
		Email:      email,
		Bits:       2048,
		ExpiryDays: 30,
		Passphrase: []byte(passphrase),
	})
	if err != nil {
		t.Fatal(err)
	}
	return info
}

func TestEncryptDecryptSignedMultiRecipient(t *testing.T) {
	service := newTestService(t)
	alice := generateTestKey(t, service, "Alice", "alice@example.test", "alice-long-passphrase")
	bob := generateTestKey(t, service, "Bob", "bob@example.test", "bob-long-passphrase")
	carol := generateTestKey(t, service, "Carol", "carol@example.test", "carol-long-passphrase")
	service.LockNow()

	plaintext := []byte("confidential message with accents: cafe")
	ciphertext, err := service.Encrypt(model.EncryptRequest{
		Plaintext:             plaintext,
		RecipientFingerprints: []string{bob.Fingerprint, carol.Fingerprint},
		SignerFingerprint:     alice.Fingerprint,
		SignerPassphrase:      []byte("alice-long-passphrase"),
		Armor:                 true,
		Compress:              true,
		UTF8:                  true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(ciphertext, []byte("BEGIN PGP MESSAGE")) {
		t.Fatalf("expected ASCII armor, got %q", ciphertext[:min(40, len(ciphertext))])
	}

	service.LockNow()
	result, err := service.Decrypt(model.DecryptRequest{
		Ciphertext: ciphertext,
		Passphrases: map[string][]byte{
			bob.Fingerprint: []byte("bob-long-passphrase"),
		},
		UTF8: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(result.Plaintext, plaintext) {
		t.Fatalf("plaintext mismatch: %q", result.Plaintext)
	}
	if !result.SignaturePresent || !result.SignatureValid {
		t.Fatalf("expected valid embedded signature: %+v", result)
	}
	if result.SignerKeyID != alice.KeyID {
		t.Fatalf("signer key ID = %s, want %s", result.SignerKeyID, alice.KeyID)
	}
	if len(result.RecipientKeyIDs) != 2 {
		t.Fatalf("recipient IDs = %v", result.RecipientKeyIDs)
	}
}

func TestSignVerifyAllModes(t *testing.T) {
	service := newTestService(t)
	alice := generateTestKey(t, service, "Alice", "alice@example.test", "alice-long-passphrase")
	service.LockNow()
	data := []byte("signed content\nsecond line\n")

	tests := []struct {
		name  string
		mode  model.SignatureMode
		armor bool
	}{
		{"detached-armored", model.SignatureDetached, true},
		{"inline-armored", model.SignatureInline, true},
		{"cleartext", model.SignatureCleartext, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signature, err := service.Sign(model.SignRequest{
				Data:              data,
				SignerFingerprint: alice.Fingerprint,
				Passphrase:        []byte("alice-long-passphrase"),
				Mode:              tt.mode,
				Armor:             tt.armor,
				UTF8:              true,
			})
			if err != nil {
				t.Fatal(err)
			}
			request := model.VerifyRequest{Signature: signature, Mode: tt.mode, UTF8: true}
			if tt.mode == model.SignatureDetached {
				request.Data = data
			}
			verified, err := service.Verify(request)
			if err != nil {
				t.Fatal(err)
			}
			if !verified.Valid {
				t.Fatalf("verification failed: %+v", verified)
			}
			if verified.SignerKeyID != alice.KeyID {
				t.Fatalf("signer key ID = %s, want %s", verified.SignerKeyID, alice.KeyID)
			}
			if tt.mode != model.SignatureDetached && !bytes.Equal(verified.Data, data) {
				t.Fatalf("recovered data mismatch: %q", verified.Data)
			}
		})
	}
}

func TestPassphrasePromptAndInvalidPassphrase(t *testing.T) {
	service := newTestService(t)
	alice := generateTestKey(t, service, "Alice", "alice@example.test", "alice-long-passphrase")
	service.LockNow()

	_, err := service.Sign(model.SignRequest{
		Data:              []byte("test"),
		SignerFingerprint: alice.Fingerprint,
		Mode:              model.SignatureDetached,
		Armor:             true,
	})
	var required *model.PassphraseRequiredError
	if !errors.As(err, &required) {
		t.Fatalf("expected PassphraseRequiredError, got %v", err)
	}
	if required.Fingerprint != alice.Fingerprint {
		t.Fatalf("fingerprint = %s", required.Fingerprint)
	}

	_, err = service.Sign(model.SignRequest{
		Data:              []byte("test"),
		SignerFingerprint: alice.Fingerprint,
		Passphrase:        []byte("wrong"),
		Mode:              model.SignatureDetached,
		Armor:             true,
	})
	if !errors.Is(err, model.ErrInvalidPassphrase) {
		t.Fatalf("expected invalid passphrase, got %v", err)
	}
}

func TestEncryptedBackupRoundTripAndAuthentication(t *testing.T) {
	service := newTestService(t)
	alice := generateTestKey(t, service, "Alice", "alice@example.test", "alice-long-passphrase")
	if err := service.SetTrust(alice.Fingerprint, model.TrustUltimate); err != nil {
		t.Fatal(err)
	}
	archive, err := service.CreateBackup([]byte("backup-password-long"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(archive, []byte(backupMagic)) {
		t.Fatal("backup magic missing")
	}

	restored := newTestService(t)
	infos, err := restored.RestoreBackup(archive, []byte("backup-password-long"), true)
	if err != nil {
		t.Fatal(err)
	}
	if len(infos) != 1 {
		t.Fatalf("restored %d keys", len(infos))
	}
	info, err := restored.KeyInfo(alice.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsPrivate || info.Metadata.Trust != model.TrustUltimate {
		t.Fatalf("restored key mismatch: %+v", info)
	}

	if _, err := restored.RestoreBackup(archive, []byte("wrong-password"), false); err == nil {
		t.Fatal("expected wrong password failure")
	}
	tampered := append([]byte(nil), archive...)
	tampered[len(tampered)-8] ^= 0x01
	if _, err := restored.RestoreBackup(tampered, []byte("backup-password-long"), false); err == nil {
		t.Fatal("expected tamper failure")
	}
}

func TestStreamingFileRoundTrip(t *testing.T) {
	service := newTestService(t)
	bob := generateTestKey(t, service, "Bob", "bob@example.test", "bob-long-passphrase")
	service.LockNow()

	input := filepath.Join(t.TempDir(), "large.bin")
	encrypted := input + ".gpg"
	decrypted := input + ".out"
	payload := bytes.Repeat([]byte("0123456789abcdef"), 128*1024) // 2 MiB
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.EncryptFile(context.Background(), input, encrypted, model.EncryptRequest{
		RecipientFingerprints: []string{bob.Fingerprint},
		Compress:              true,
	}); err != nil {
		t.Fatal(err)
	}
	service.LockNow()
	if _, err := service.DecryptFile(context.Background(), encrypted, decrypted, model.DecryptRequest{
		Passphrases: map[string][]byte{bob.Fingerprint: []byte("bob-long-passphrase")},
	}); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, payload) {
		t.Fatalf("decrypted file mismatch: got %d bytes, want %d", len(actual), len(payload))
	}
}

func TestKeyserverMachineReadableParser(t *testing.T) {
	input := strings.Join([]string{
		"info:1:1",
		"pub:0123456789ABCDEF:1:3072:1700000000:1800000000:",
		"fpr:0123456789ABCDEF0123456789ABCDEF01234567",
		"uid:Alice%20Example%20%3Calice%40example.test%3E:1700000000:1800000000:",
	}, "\n")
	results, err := parseMachineReadableIndex([]byte(input))
	if err != nil {
		t.Fatal(err)
	}
	if len(results) != 1 {
		t.Fatalf("results = %d", len(results))
	}
	got := results[0]
	if got.Algorithm != "RSA" || got.Bits != 3072 || got.Fingerprint != "0123456789ABCDEF0123456789ABCDEF01234567" {
		t.Fatalf("unexpected result: %+v", got)
	}
	if len(got.UserIDs) != 1 || got.UserIDs[0] != "Alice Example <alice@example.test>" {
		t.Fatalf("UIDs = %v", got.UserIDs)
	}
}

func TestVerifyInlineFileCommitsOnlyAfterValidSignature(t *testing.T) {
	service := newTestService(t)
	alice := generateTestKey(t, service, "Alice", "alice@example.test", "alice-long-passphrase")
	data := []byte("content that can only be published after verification")

	signed, err := service.Sign(model.SignRequest{
		Data:              data,
		SignerFingerprint: alice.Fingerprint,
		Passphrase:        []byte("alice-long-passphrase"),
		Mode:              model.SignatureInline,
		Armor:             false,
		UTF8:              true,
	})
	if err != nil {
		t.Fatal(err)
	}

	directory := t.TempDir()
	signedPath := filepath.Join(directory, "message.pgp")
	outputPath := filepath.Join(directory, "verified.txt")
	if err := os.WriteFile(signedPath, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}

	result, err := service.VerifyFile(context.Background(), "", signedPath, outputPath, model.VerifyRequest{
		Mode: model.SignatureInline,
		UTF8: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.Valid {
		t.Fatalf("valid signed file rejected: %+v", result)
	}
	verified, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(verified, data) {
		t.Fatalf("verified output mismatch: %q", verified)
	}

	payloadAt := bytes.Index(signed, data)
	if payloadAt < 0 {
		t.Fatal("literal payload not found in inline message")
	}
	tampered := append([]byte(nil), signed...)
	tampered[payloadAt] ^= 0x01
	if err := os.WriteFile(signedPath, tampered, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(outputPath, []byte("sentinel"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, _ = service.VerifyFile(context.Background(), "", signedPath, outputPath, model.VerifyRequest{
		Mode: model.SignatureInline,
		UTF8: true,
	})
	preserved, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(preserved) != "sentinel" {
		t.Fatalf("unverified plaintext replaced output: %q", preserved)
	}
}

func TestDecryptFilePromptsOnlyForMatchingRecipient(t *testing.T) {
	service := newTestService(t)
	_ = generateTestKey(t, service, "Alice", "alice@example.test", "alice-long-passphrase")
	bob := generateTestKey(t, service, "Bob", "bob@example.test", "bob-long-passphrase")

	directory := t.TempDir()
	input := filepath.Join(directory, "message.txt")
	encrypted := filepath.Join(directory, "message.gpg")
	decrypted := filepath.Join(directory, "message.out")
	payload := []byte("recipient-aware streaming decryption")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.EncryptFile(context.Background(), input, encrypted, model.EncryptRequest{
		RecipientFingerprints: []string{bob.Fingerprint},
	}); err != nil {
		t.Fatal(err)
	}

	service.LockNow()
	_, err := service.DecryptFile(context.Background(), encrypted, decrypted, model.DecryptRequest{
		Passphrases: map[string][]byte{},
	})
	var required *model.PassphraseRequiredError
	if !errors.As(err, &required) {
		t.Fatalf("expected passphrase prompt, got %v", err)
	}
	if required.Fingerprint != bob.Fingerprint {
		t.Fatalf("prompted for %s, want Bob %s", required.Fingerprint, bob.Fingerprint)
	}
	if _, statErr := os.Stat(decrypted); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("output should not be committed before decryption, stat error = %v", statErr)
	}
}

func TestSymmetricFileDecryptDoesNotPromptForUnrelatedPrivateKeys(t *testing.T) {
	service := newTestService(t)
	_ = generateTestKey(t, service, "Alice", "alice@example.test", "alice-long-passphrase")
	service.LockNow()

	directory := t.TempDir()
	input := filepath.Join(directory, "message.txt")
	encrypted := filepath.Join(directory, "message.gpg")
	decrypted := filepath.Join(directory, "message.out")
	payload := []byte("password-only encrypted payload")
	password := []byte("symmetric-password-long")
	if err := os.WriteFile(input, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := service.EncryptFile(context.Background(), input, encrypted, model.EncryptRequest{
		Password: password,
		Compress: true,
	}); err != nil {
		t.Fatal(err)
	}

	if _, err := service.DecryptFile(context.Background(), encrypted, decrypted, model.DecryptRequest{}); !errors.Is(err, model.ErrPasswordRequired) {
		t.Fatalf("expected symmetric password requirement, got %v", err)
	}
	result, err := service.DecryptFile(context.Background(), encrypted, decrypted, model.DecryptRequest{Password: password})
	if err != nil {
		t.Fatal(err)
	}
	if !result.UsedSymmetricMode {
		t.Fatalf("expected symmetric mode result: %+v", result)
	}
	actual, err := os.ReadFile(decrypted)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(actual, payload) {
		t.Fatalf("decrypted payload = %q, want %q", actual, payload)
	}
}

func TestStaleVaultPassphraseFallsBackToManualPrompt(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	secrets := storage.NewMemorySecretStore()
	service, err := NewService(store, secrets)
	if err != nil {
		t.Fatal(err)
	}
	alice := generateTestKey(t, service, "Alice", "alice@example.test", "alice-long-passphrase")
	service.LockNow()
	if err := secrets.Set(alice.Fingerprint, []byte("stale-wrong-passphrase")); err != nil {
		t.Fatal(err)
	}

	_, err = service.Sign(model.SignRequest{
		Data:              []byte("test"),
		SignerFingerprint: alice.Fingerprint,
		Mode:              model.SignatureDetached,
		Armor:             true,
	})
	var required *model.PassphraseRequiredError
	if !errors.As(err, &required) {
		t.Fatalf("expected manual passphrase prompt, got %v", err)
	}
	if required.Fingerprint != alice.Fingerprint {
		t.Fatalf("prompted for %s, want %s", required.Fingerprint, alice.Fingerprint)
	}
}

type rejectingSecretStore struct{}

func (rejectingSecretStore) Get(string) ([]byte, error) { return nil, errors.New("vault unavailable") }
func (rejectingSecretStore) Set(string, []byte) error   { return errors.New("vault unavailable") }
func (rejectingSecretStore) Delete(string) error        { return nil }

func TestGenerateKeyRollsBackWhenRememberingSecretFails(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := NewService(store, rejectingSecretStore{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = service.GenerateKey(model.KeyGenerationRequest{
		Name:           "Alice",
		Email:          "alice@example.test",
		Bits:           2048,
		ExpiryDays:     30,
		Passphrase:     []byte("alice-long-passphrase"),
		RememberSecret: true,
	})
	if err == nil {
		t.Fatal("expected vault error")
	}
	keys, listErr := service.ListKeys()
	if listErr != nil {
		t.Fatal(listErr)
	}
	if len(keys) != 0 {
		t.Fatalf("generated key survived failed vault transaction: %+v", keys)
	}
}
