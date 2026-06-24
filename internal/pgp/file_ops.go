package pgp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/ProtonMail/go-crypto/openpgp/armor"
	"github.com/ProtonMail/go-crypto/openpgp/packet"
	gcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/ThalesMMS/PGP-Client-go/internal/fileutil"
	"github.com/ThalesMMS/PGP-Client-go/internal/model"
)

// EncryptFile performs streaming encryption and atomically replaces outputPath
// only after the OpenPGP writer has closed successfully.
func (s *Service) EncryptFile(ctx context.Context, inputPath, outputPath string, req model.EncryptRequest) error {
	builder := gcrypto.PGP().Encryption()
	if len(req.RecipientFingerprints) > 0 {
		recipients, err := s.publicKeyRing(req.RecipientFingerprints, true)
		if err != nil {
			return err
		}
		builder = builder.Recipients(recipients)
	} else if len(req.Password) > 0 {
		builder = builder.Password(append([]byte(nil), req.Password...))
	} else {
		return model.ErrNoRecipients
	}
	if req.SignerFingerprint != "" {
		signer, err := s.unlockPrivate(req.SignerFingerprint, req.SignerPassphrase, false)
		if err != nil {
			return err
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
		return err
	}
	defer handle.ClearPrivateParams()

	input, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()
	return atomicOutput(outputPath, 0o600, func(output *os.File) error {
		encoding := int8(gcrypto.Bytes)
		if req.Armor {
			encoding = gcrypto.Armor
		}
		writer, err := handle.EncryptingWriter(output, encoding)
		if err != nil {
			return err
		}
		if _, err := copyWithContext(ctx, writer, input); err != nil {
			_ = writer.Close()
			return err
		}
		return writer.Close()
	})
}

// DecryptFile streams plaintext to a temporary file. Signature details are
// returned after the input has been consumed completely.
func (s *Service) DecryptFile(ctx context.Context, inputPath, outputPath string, req model.DecryptRequest) (model.DecryptResult, error) {
	var result model.DecryptResult
	envelope, inspectErr := inspectEncryptionFile(inputPath)
	if inspectErr == nil {
		result.RecipientKeyIDs = append([]string(nil), envelope.recipientIDs...)
		result.UsedSymmetricMode = envelope.symmetricRecipient && !envelope.hasPublicRecipient()
		if result.UsedSymmetricMode && len(req.Password) == 0 {
			return result, model.ErrPasswordRequired
		}
	}

	var privateRing *gcrypto.KeyRing
	var required *model.PassphraseRequiredError
	needPrivateKeys := inspectErr != nil || envelope.hasPublicRecipient() || !envelope.symmetricRecipient
	if len(req.Password) > 0 && envelope.symmetricRecipient {
		// A password recipient is sufficient. Avoid prompting for unrelated
		// locked private keys in mixed or symmetric-only messages.
		needPrivateKeys = false
	}
	if needPrivateKeys {
		lookupIDs := envelope.recipientIDs
		if inspectErr != nil || envelope.anonymousRecipient {
			lookupIDs = nil
		}
		var err error
		privateRing, required, err = s.decryptionKeyRing(lookupIDs, req.Passphrases)
		if err != nil {
			return result, err
		}
	}
	builder := gcrypto.PGP().Decryption().MaxDecompressedMessageSize(16 << 30)
	if privateRing != nil && privateRing.CountEntities() > 0 {
		builder = builder.DecryptionKeys(privateRing)
	}
	if len(req.Password) > 0 {
		builder = builder.Password(append([]byte(nil), req.Password...))
		result.UsedSymmetricMode = true
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
		return result, err
	}
	defer handle.ClearPrivateParams()
	input, err := os.Open(inputPath)
	if err != nil {
		return result, err
	}
	defer input.Close()

	err = atomicOutput(outputPath, 0o600, func(output *os.File) error {
		reader, err := handle.DecryptingReader(input, gcrypto.Auto)
		if err != nil {
			return err
		}
		if metadata := reader.GetMetadata(); metadata != nil {
			result.Filename = metadata.Filename()
		}
		if _, err := copyWithContext(ctx, output, reader); err != nil {
			return err
		}
		verification, err := reader.VerifySignature()
		if err != nil {
			return err
		}
		fillDecryptSignature(&result, verification)
		return nil
	})
	if err != nil {
		if required != nil {
			return result, required
		}
		return result, fmt.Errorf("descriptografar arquivo: %w", err)
	}
	return result, nil
}

type encryptionEnvelope struct {
	recipientIDs       []string
	anonymousRecipient bool
	symmetricRecipient bool
}

func (envelope encryptionEnvelope) hasPublicRecipient() bool {
	return envelope.anonymousRecipient || len(envelope.recipientIDs) > 0
}

// inspectEncryptionFile parses only the OpenPGP session-key packet prefix. It
// never consumes the encrypted payload and therefore preserves streaming file
// operations while allowing the UI to request the correct private-key secret.
func inspectEncryptionFile(path string) (encryptionEnvelope, error) {
	file, err := os.Open(path)
	if err != nil {
		return encryptionEnvelope{}, err
	}
	defer file.Close()

	header := make([]byte, 128)
	n, readErr := file.Read(header)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return encryptionEnvelope{}, readErr
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return encryptionEnvelope{}, err
	}

	var source io.Reader = file
	if bytes.Contains(header[:n], []byte("-----BEGIN PGP MESSAGE-----")) {
		block, err := armor.Decode(file)
		if err != nil {
			return encryptionEnvelope{}, err
		}
		if block == nil || block.Type != "PGP MESSAGE" {
			return encryptionEnvelope{}, errors.New("bloco ASCII armor não é uma mensagem PGP")
		}
		source = block.Body
	}
	return inspectEncryptionPackets(source)
}

func inspectEncryptionPackets(source io.Reader) (encryptionEnvelope, error) {
	packets := packet.NewReader(source)
	seen := make(map[string]struct{})
	var envelope encryptionEnvelope
	for {
		item, err := packets.Next()
		if errors.Is(err, io.EOF) {
			return envelope, nil
		}
		if err != nil {
			return encryptionEnvelope{}, err
		}
		switch typed := item.(type) {
		case *packet.EncryptedKey:
			if typed.KeyId == 0 {
				envelope.anonymousRecipient = true
				continue
			}
			keyID := fmt.Sprintf("%016X", typed.KeyId)
			if _, ok := seen[keyID]; !ok {
				seen[keyID] = struct{}{}
				envelope.recipientIDs = append(envelope.recipientIDs, keyID)
			}
		case *packet.SymmetricKeyEncrypted:
			envelope.symmetricRecipient = true
		case *packet.SymmetricallyEncrypted, *packet.AEADEncrypted:
			return envelope, nil
		}
	}
}

func (s *Service) SignFile(ctx context.Context, inputPath, outputPath string, req model.SignRequest) error {
	if req.Mode == model.SignatureCleartext {
		data, err := os.ReadFile(inputPath)
		if err != nil {
			return err
		}
		req.Data = data
		signed, err := s.Sign(req)
		if err != nil {
			return err
		}
		return atomicBytes(outputPath, signed, 0o644)
	}
	signer, err := s.unlockPrivate(req.SignerFingerprint, req.Passphrase, false)
	if err != nil {
		return err
	}
	builder := gcrypto.PGP().Sign().SigningKey(signer)
	if req.Mode == model.SignatureDetached {
		builder = builder.Detached()
	}
	if req.UTF8 {
		builder = builder.Utf8()
	}
	handle, err := builder.New()
	if err != nil {
		return err
	}
	defer handle.ClearPrivateParams()
	input, err := os.Open(inputPath)
	if err != nil {
		return err
	}
	defer input.Close()
	return atomicOutput(outputPath, 0o644, func(output *os.File) error {
		encoding := int8(gcrypto.Bytes)
		if req.Armor {
			encoding = gcrypto.Armor
		}
		writer, err := handle.SigningWriter(output, encoding)
		if err != nil {
			return err
		}
		if _, err := copyWithContext(ctx, writer, input); err != nil {
			_ = writer.Close()
			return err
		}
		return writer.Close()
	})
}

func (s *Service) VerifyFile(ctx context.Context, dataPath, signaturePath, outputPath string, req model.VerifyRequest) (model.VerifyResult, error) {
	if req.Mode == model.SignatureCleartext {
		signature, err := os.ReadFile(signaturePath)
		if err != nil {
			return model.VerifyResult{}, err
		}
		req.Signature = signature
		result, err := s.Verify(req)
		if err == nil && result.Valid && outputPath != "" {
			err = atomicBytes(outputPath, result.Data, 0o644)
		}
		return result, err
	}

	ring, err := s.allPublicKeyRing()
	if err != nil {
		return model.VerifyResult{}, err
	}
	if ring == nil || ring.CountEntities() == 0 {
		return model.VerifyResult{}, model.ErrNoVerificationKeys
	}
	builder := gcrypto.PGP().Verify().VerificationKeys(ring).MaxDecompressedMessageSize(16 << 30)
	if req.UTF8 {
		builder = builder.Utf8()
	}
	handle, err := builder.New()
	if err != nil {
		return model.VerifyResult{}, err
	}

	signature, err := os.Open(signaturePath)
	if err != nil {
		return model.VerifyResult{}, err
	}
	defer signature.Close()

	// Use an interface-typed nil for inline signatures. Passing a typed nil
	// *os.File would create a non-nil interface and incorrectly select the
	// detached-signature path inside GopenPGP.
	var detachedData gcrypto.Reader
	var dataFile *os.File
	if req.Mode == model.SignatureDetached {
		dataFile, err = os.Open(dataPath)
		if err != nil {
			return model.VerifyResult{}, err
		}
		defer dataFile.Close()
		detachedData = dataFile
	}

	reader, err := handle.VerifyingReader(detachedData, signature, gcrypto.Auto)
	if err != nil {
		return model.VerifyResult{}, err
	}

	var pending *fileutil.PendingFile
	if req.Mode != model.SignatureDetached && outputPath != "" {
		pending, err = fileutil.NewPending(outputPath, 0o644, 0o755)
		if err != nil {
			return model.VerifyResult{}, err
		}
		defer pending.Abort()
		if _, err := copyWithContext(ctx, pending.File, reader); err != nil {
			return model.VerifyResult{}, err
		}
	} else if _, err := copyWithContext(ctx, io.Discard, reader); err != nil {
		return model.VerifyResult{}, err
	}

	verification, err := reader.VerifySignature()
	if err != nil {
		return model.VerifyResult{}, err
	}
	result := model.VerifyResult{}
	fillVerifyResult(&result, verification)

	// Never expose inline plaintext as "verified" until the cryptographic
	// validation has completed successfully.
	if pending != nil && result.Valid {
		if err := pending.Commit(); err != nil {
			return model.VerifyResult{}, err
		}
	}
	return result, nil
}

func atomicBytes(path string, data []byte, mode os.FileMode) error {
	return fileutil.AtomicWrite(path, data, mode, 0o755)
}

func atomicOutput(path string, mode os.FileMode, write func(*os.File) error) error {
	return fileutil.AtomicOutput(path, mode, 0o755, write)
}

func copyWithContext(ctx context.Context, dst io.Writer, src io.Reader) (int64, error) {
	buffer := make([]byte, 128*1024)
	var total int64
	for {
		select {
		case <-ctx.Done():
			return total, ctx.Err()
		default:
		}
		n, readErr := src.Read(buffer)
		if n > 0 {
			written, writeErr := dst.Write(buffer[:n])
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
			if written != n {
				return total, io.ErrShortWrite
			}
		}
		if errors.Is(readErr, io.EOF) {
			return total, nil
		}
		if readErr != nil {
			return total, readErr
		}
	}
}
