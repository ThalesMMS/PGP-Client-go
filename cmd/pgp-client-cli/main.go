package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/ThalesMMS/PGP-Client-go/internal/fileutil"
	"github.com/ThalesMMS/PGP-Client-go/internal/model"
	pgpcore "github.com/ThalesMMS/PGP-Client-go/internal/pgp"
)

type stringList []string

func (s *stringList) String() string { return strings.Join(*s, ",") }
func (s *stringList) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("empty value")
	}
	*s = append(*s, value)
	return nil
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	service, err := pgpcore.NewDefaultService()
	if err != nil {
		fatal(err)
	}
	command := os.Args[1]
	args := os.Args[2:]
	switch command {
	case "list":
		err = listKeys(service, args)
	case "generate":
		err = generateKey(service, args)
	case "import":
		err = importKeys(service, args)
	case "export-public":
		err = exportKey(service, args, false)
	case "export-private":
		err = exportKey(service, args, true)
	case "encrypt":
		err = encryptFile(service, args)
	case "decrypt":
		err = decryptFile(service, args)
	case "sign":
		err = signFile(service, args)
	case "verify":
		err = verifyFile(service, args)
	case "backup":
		err = backup(service, args)
	case "restore":
		err = restore(service, args)
	case "keyserver-search":
		err = keyserverSearch(service, args)
	case "keyserver-import":
		err = keyserverImport(service, args)
	case "keyserver-upload":
		err = keyserverUpload(service, args)
	case "lock":
		service.LockNow()
		fmt.Println("Session locked.")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", command)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `PGP Client CLI

Usage:
  pgp-client-cli list [--json]
  pgp-client-cli generate --name NAME --email EMAIL [--bits 3072] [--expires 730]
  pgp-client-cli import FILE [FILE...]
  pgp-client-cli export-public  --key FINGERPRINT --out FILE
  pgp-client-cli export-private --key FINGERPRINT --out FILE
  pgp-client-cli encrypt --recipient FINGERPRINT [--recipient ...] [--sign FINGERPRINT] INPUT OUTPUT
  pgp-client-cli decrypt INPUT OUTPUT
  pgp-client-cli sign --key FINGERPRINT [--mode detached|inline|cleartext] INPUT OUTPUT
  pgp-client-cli verify --mode detached|inline|cleartext --signature SIGNATURE [--data DATA] [--out OUTPUT]
  pgp-client-cli backup OUTPUT.pgpbackup
  pgp-client-cli restore [--settings] BACKUP.pgpbackup
  pgp-client-cli keyserver-search QUERY
  pgp-client-cli keyserver-import FINGERPRINT_OR_KEYID
  pgp-client-cli keyserver-upload FINGERPRINT
  pgp-client-cli lock

Secrets can be supplied through PGP_CLIENT_PASSPHRASE and PGP_CLIENT_PASSWORD.
Without them, the CLI prompts for hidden terminal input.
`)
}

func listKeys(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "JSON output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	keys, err := service.ListKeys()
	if err != nil {
		return err
	}
	if *asJSON {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		return encoder.Encode(keys)
	}
	fmt.Printf("%-18s %-8s %-9s %-25s %s\n", "KEY ID", "TYPE", "ALGORITHM", "IDENTITY", "FINGERPRINT")
	for _, key := range keys {
		kind := "public"
		if key.IsPrivate {
			kind = "secret"
		}
		fmt.Printf("%-18s %-8s %-9s %-25s %s\n", key.KeyID, kind, fmt.Sprintf("%s-%d", key.Algorithm, key.Bits), truncate(key.PrimaryIdentity(), 25), key.Fingerprint)
	}
	return nil
}

func generateKey(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	name := fs.String("name", "", "name")
	email := fs.String("email", "", "email")
	comment := fs.String("comment", "", "comment")
	bits := fs.Int("bits", 3072, "RSA 2048, 3072 or 4096")
	expires := fs.Int("expires", 730, "expiration in days; 0 = never")
	unprotected := fs.Bool("unprotected", false, "do not protect the private key")
	remember := fs.Bool("remember", false, "store the passphrase in the system vault")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var passphrase []byte
	var err error
	if !*unprotected {
		passphrase, err = secretFromEnvOrPrompt("PGP_CLIENT_PASSPHRASE", "New key passphrase: ")
		if err != nil {
			return err
		}
		if os.Getenv("PGP_CLIENT_PASSPHRASE") == "" {
			confirmation, err := readSecret("Confirm passphrase: ")
			if err != nil {
				return err
			}
			if string(passphrase) != string(confirmation) {
				return errors.New("passphrases do not match")
			}
		}
	}
	info, err := service.GenerateKey(model.KeyGenerationRequest{
		Name:           *name,
		Email:          *email,
		Comment:        *comment,
		Bits:           *bits,
		ExpiryDays:     *expires,
		Passphrase:     passphrase,
		RememberSecret: *remember,
	})
	if err != nil {
		return err
	}
	fmt.Printf("Key created: %s %s\n", info.KeyID, info.Fingerprint)
	return nil
}

func importKeys(service *pgpcore.Service, args []string) error {
	if len(args) == 0 {
		return errors.New("provide at least one file")
	}
	for _, path := range args {
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		infos, err := service.Import(data)
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		for _, info := range infos {
			fmt.Printf("Imported: %s %s\n", info.KeyID, info.PrimaryIdentity())
		}
	}
	return nil
}

func exportKey(service *pgpcore.Service, args []string, private bool) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fingerprint := fs.String("key", "", "fingerprint")
	out := fs.String("out", "", "output file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fingerprint == "" || *out == "" {
		return errors.New("--key and --out are required")
	}
	var data []byte
	var err error
	if private {
		data, err = service.ExportPrivate(*fingerprint)
	} else {
		data, err = service.ExportPublic(*fingerprint)
	}
	if err != nil {
		return err
	}
	mode := os.FileMode(0o644)
	if private {
		mode = 0o600
	}
	return writeAtomic(*out, data, mode)
}

func encryptFile(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("encrypt", flag.ContinueOnError)
	var recipients stringList
	fs.Var(&recipients, "recipient", "recipient fingerprint; repeatable")
	signer := fs.String("sign", "", "signing key fingerprint")
	armor := fs.Bool("armor", false, "ASCII armor")
	compress := fs.Bool("compress", true, "OpenPGP compression")
	passwordMode := fs.Bool("password", false, "symmetric password encryption")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: encrypt [options] INPUT OUTPUT")
	}
	req := model.EncryptRequest{
		RecipientFingerprints: recipients,
		SignerFingerprint:     *signer,
		Armor:                 *armor,
		Compress:              *compress,
	}
	if *passwordMode {
		password, err := secretFromEnvOrPrompt("PGP_CLIENT_PASSWORD", "Encryption password: ")
		if err != nil {
			return err
		}
		req.Password = password
		req.RecipientFingerprints = nil
	}
	for {
		err := service.EncryptFile(context.Background(), fs.Arg(0), fs.Arg(1), req)
		var required *model.PassphraseRequiredError
		if errors.As(err, &required) {
			secret, promptErr := secretFromEnvOrPrompt("PGP_CLIENT_PASSPHRASE", "Passphrase for "+required.Identity+": ")
			if promptErr != nil {
				return promptErr
			}
			req.SignerPassphrase = secret
			continue
		}
		return err
	}
}

func decryptFile(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("decrypt", flag.ContinueOnError)
	passwordMode := fs.Bool("password", false, "try symmetric password")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("usage: decrypt [--password] INPUT OUTPUT")
	}
	req := model.DecryptRequest{Passphrases: make(map[string][]byte)}
	if *passwordMode {
		password, err := secretFromEnvOrPrompt("PGP_CLIENT_PASSWORD", "Decryption password: ")
		if err != nil {
			return err
		}
		req.Password = password
	}
	for {
		result, err := service.DecryptFile(context.Background(), fs.Arg(0), fs.Arg(1), req)
		var required *model.PassphraseRequiredError
		if errors.As(err, &required) {
			secret, promptErr := secretFromEnvOrPrompt("PGP_CLIENT_PASSPHRASE", "Passphrase for "+required.Identity+": ")
			if promptErr != nil {
				return promptErr
			}
			req.Passphrases[required.Fingerprint] = secret
			continue
		}
		if err == nil && result.SignaturePresent {
			fmt.Printf("Signature: valid=%t keyID=%s error=%s\n", result.SignatureValid, result.SignerKeyID, result.SignatureError)
		}
		return err
	}
}

func signFile(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fingerprint := fs.String("key", "", "secret key fingerprint")
	modeText := fs.String("mode", "detached", "detached, inline or cleartext")
	armor := fs.Bool("armor", true, "ASCII armor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *fingerprint == "" {
		return errors.New("usage: sign --key FINGERPRINT [options] INPUT OUTPUT")
	}
	mode, err := parseMode(*modeText)
	if err != nil {
		return err
	}
	req := model.SignRequest{SignerFingerprint: *fingerprint, Mode: mode, Armor: *armor}
	for {
		err := service.SignFile(context.Background(), fs.Arg(0), fs.Arg(1), req)
		var required *model.PassphraseRequiredError
		if errors.As(err, &required) {
			secret, promptErr := secretFromEnvOrPrompt("PGP_CLIENT_PASSPHRASE", "Passphrase for "+required.Identity+": ")
			if promptErr != nil {
				return promptErr
			}
			req.Passphrase = secret
			continue
		}
		return err
	}
}

func verifyFile(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("verify", flag.ContinueOnError)
	modeText := fs.String("mode", "detached", "detached, inline or cleartext")
	dataPath := fs.String("data", "", "original data for detached signature")
	signaturePath := fs.String("signature", "", "signature or signed message")
	out := fs.String("out", "", "verified inline content output")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mode, err := parseMode(*modeText)
	if err != nil {
		return err
	}
	if *signaturePath == "" {
		return errors.New("--signature is required")
	}
	if mode == model.SignatureDetached && *dataPath == "" {
		return errors.New("--data is required for detached signatures")
	}
	result, err := service.VerifyFile(context.Background(), *dataPath, *signaturePath, *out, model.VerifyRequest{Mode: mode})
	if err != nil {
		return err
	}
	if !result.Valid {
		return fmt.Errorf("invalid signature: %s", result.SignatureErr)
	}
	fmt.Printf("Valid signature: keyID=%s signer=%s <%s>\n", result.SignerKeyID, result.SignerName, result.SignerEmail)
	return nil
}

func backup(service *pgpcore.Service, args []string) error {
	if len(args) != 1 {
		return errors.New("usage: backup OUTPUT.pgpbackup")
	}
	password, err := secretFromEnvOrPrompt("PGP_CLIENT_PASSWORD", "Backup password: ")
	if err != nil {
		return err
	}
	archive, err := service.CreateBackup(password)
	if err != nil {
		return err
	}
	if err := writeAtomic(args[0], archive, 0o600); err != nil {
		return err
	}
	return service.MarkBackupCreated()
}

func restore(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("restore", flag.ContinueOnError)
	settings := fs.Bool("settings", false, "restore preferences")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("usage: restore [--settings] BACKUP.pgpbackup")
	}
	archive, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := secretFromEnvOrPrompt("PGP_CLIENT_PASSWORD", "Backup password: ")
	if err != nil {
		return err
	}
	infos, err := service.RestoreBackup(archive, password, *settings)
	if err != nil {
		return err
	}
	fmt.Printf("%d key(s) restored.\n", len(infos))
	return nil
}

func keyserverSearch(service *pgpcore.Service, args []string) error {
	if len(args) == 0 {
		return errors.New("provide a query")
	}
	results, err := service.SearchKeyserver(context.Background(), strings.Join(args, " "))
	if err != nil {
		return err
	}
	for _, result := range results {
		fmt.Printf("%s %s-%d %s\n", result.KeyID, result.Algorithm, result.Bits, strings.Join(result.UserIDs, "; "))
	}
	return nil
}

func keyserverImport(service *pgpcore.Service, args []string) error {
	if len(args) != 1 {
		return errors.New("provide a fingerprint or Key ID")
	}
	infos, err := service.ImportFromKeyserver(context.Background(), args[0])
	if err != nil {
		return err
	}
	for _, info := range infos {
		fmt.Printf("Imported: %s %s\n", info.KeyID, info.PrimaryIdentity())
	}
	return nil
}

func keyserverUpload(service *pgpcore.Service, args []string) error {
	if len(args) != 1 {
		return errors.New("provide the fingerprint")
	}
	return service.UploadToKeyserver(context.Background(), args[0])
}

func parseMode(value string) (model.SignatureMode, error) {
	switch strings.ToLower(value) {
	case "detached":
		return model.SignatureDetached, nil
	case "inline":
		return model.SignatureInline, nil
	case "cleartext":
		return model.SignatureCleartext, nil
	default:
		return "", errors.New("mode must be detached, inline or cleartext")
	}
}

func secretFromEnvOrPrompt(env, prompt string) ([]byte, error) {
	if value := os.Getenv(env); value != "" {
		return []byte(value), nil
	}
	return readSecret(prompt)
}

func readSecret(prompt string) ([]byte, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return nil, errors.New("input is not a terminal; use the secret environment variable")
	}
	fmt.Fprint(os.Stderr, prompt)
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("empty secret")
	}
	return secret, nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	return fileutil.AtomicWrite(path, data, mode, 0o755)
}

func truncate(value string, max int) string {
	runes := []rune(value)
	if len(runes) <= max {
		return value
	}
	if max < 2 {
		return string(runes[:max])
	}
	if max < 4 {
		return string(runes[:max-1]) + "."
	}
	return string(runes[:max-3]) + "..."
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
