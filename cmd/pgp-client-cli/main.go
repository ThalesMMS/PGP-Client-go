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
		return errors.New("valor vazio")
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
		fmt.Println("Sessão bloqueada.")
	case "help", "-h", "--help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "comando desconhecido: %s\n\n", command)
		usage()
		os.Exit(2)
	}
	if err != nil {
		fatal(err)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `PGP Client CLI

Uso:
  pgp-client-cli list [--json]
  pgp-client-cli generate --name NOME --email EMAIL [--bits 3072] [--expires 730]
  pgp-client-cli import ARQUIVO [ARQUIVO...]
  pgp-client-cli export-public  --key FINGERPRINT --out ARQUIVO
  pgp-client-cli export-private --key FINGERPRINT --out ARQUIVO
  pgp-client-cli encrypt --recipient FINGERPRINT [--recipient ...] [--sign FINGERPRINT] ENTRADA SAIDA
  pgp-client-cli decrypt ENTRADA SAIDA
  pgp-client-cli sign --key FINGERPRINT [--mode detached|inline|cleartext] ENTRADA SAIDA
  pgp-client-cli verify --mode detached|inline|cleartext --signature ASSINATURA [--data DADOS] [--out SAIDA]
  pgp-client-cli backup SAIDA.pgpbackup
  pgp-client-cli restore [--settings] BACKUP.pgpbackup
  pgp-client-cli keyserver-search CONSULTA
  pgp-client-cli keyserver-import FINGERPRINT_OU_KEYID
  pgp-client-cli keyserver-upload FINGERPRINT
  pgp-client-cli lock

Segredos podem ser fornecidos pelas variáveis PGP_CLIENT_PASSPHRASE e
PGP_CLIENT_PASSWORD. Sem elas, o CLI solicita a entrada sem eco em terminal.
`)
}

func listKeys(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "saída JSON")
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
	fmt.Printf("%-18s %-8s %-9s %-25s %s\n", "KEY ID", "TIPO", "ALGORITMO", "IDENTIDADE", "FINGERPRINT")
	for _, key := range keys {
		kind := "pública"
		if key.IsPrivate {
			kind = "secreta"
		}
		fmt.Printf("%-18s %-8s %-9s %-25s %s\n", key.KeyID, kind, fmt.Sprintf("%s-%d", key.Algorithm, key.Bits), truncate(key.PrimaryIdentity(), 25), key.Fingerprint)
	}
	return nil
}

func generateKey(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("generate", flag.ContinueOnError)
	name := fs.String("name", "", "nome")
	email := fs.String("email", "", "e-mail")
	comment := fs.String("comment", "", "comentário")
	bits := fs.Int("bits", 3072, "RSA 2048, 3072 ou 4096")
	expires := fs.Int("expires", 730, "validade em dias; 0 = nunca")
	unprotected := fs.Bool("unprotected", false, "não proteger a chave privada")
	remember := fs.Bool("remember", false, "guardar frase secreta no cofre do sistema")
	if err := fs.Parse(args); err != nil {
		return err
	}
	var passphrase []byte
	var err error
	if !*unprotected {
		passphrase, err = secretFromEnvOrPrompt("PGP_CLIENT_PASSPHRASE", "Frase secreta da nova chave: ")
		if err != nil {
			return err
		}
		if os.Getenv("PGP_CLIENT_PASSPHRASE") == "" {
			confirmation, err := readSecret("Confirme a frase secreta: ")
			if err != nil {
				return err
			}
			if string(passphrase) != string(confirmation) {
				return errors.New("as frases secretas não coincidem")
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
	fmt.Printf("Chave criada: %s %s\n", info.KeyID, info.Fingerprint)
	return nil
}

func importKeys(service *pgpcore.Service, args []string) error {
	if len(args) == 0 {
		return errors.New("informe ao menos um arquivo")
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
			fmt.Printf("Importada: %s %s\n", info.KeyID, info.PrimaryIdentity())
		}
	}
	return nil
}

func exportKey(service *pgpcore.Service, args []string, private bool) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fingerprint := fs.String("key", "", "fingerprint")
	out := fs.String("out", "", "arquivo de saída")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *fingerprint == "" || *out == "" {
		return errors.New("--key e --out são obrigatórios")
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
	fs.Var(&recipients, "recipient", "fingerprint do destinatário; repetível")
	signer := fs.String("sign", "", "fingerprint da chave de assinatura")
	armor := fs.Bool("armor", false, "ASCII armor")
	compress := fs.Bool("compress", true, "compressão OpenPGP")
	passwordMode := fs.Bool("password", false, "criptografia simétrica por senha")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("uso: encrypt [opções] ENTRADA SAIDA")
	}
	req := model.EncryptRequest{
		RecipientFingerprints: recipients,
		SignerFingerprint:     *signer,
		Armor:                 *armor,
		Compress:              *compress,
	}
	if *passwordMode {
		password, err := secretFromEnvOrPrompt("PGP_CLIENT_PASSWORD", "Senha de criptografia: ")
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
			secret, promptErr := secretFromEnvOrPrompt("PGP_CLIENT_PASSPHRASE", "Frase secreta de "+required.Identity+": ")
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
	passwordMode := fs.Bool("password", false, "tentar senha simétrica")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 {
		return errors.New("uso: decrypt [--password] ENTRADA SAIDA")
	}
	req := model.DecryptRequest{Passphrases: make(map[string][]byte)}
	if *passwordMode {
		password, err := secretFromEnvOrPrompt("PGP_CLIENT_PASSWORD", "Senha de descriptografia: ")
		if err != nil {
			return err
		}
		req.Password = password
	}
	for {
		result, err := service.DecryptFile(context.Background(), fs.Arg(0), fs.Arg(1), req)
		var required *model.PassphraseRequiredError
		if errors.As(err, &required) {
			secret, promptErr := secretFromEnvOrPrompt("PGP_CLIENT_PASSPHRASE", "Frase secreta de "+required.Identity+": ")
			if promptErr != nil {
				return promptErr
			}
			req.Passphrases[required.Fingerprint] = secret
			continue
		}
		if err == nil && result.SignaturePresent {
			fmt.Printf("Assinatura: válida=%t keyID=%s erro=%s\n", result.SignatureValid, result.SignerKeyID, result.SignatureError)
		}
		return err
	}
}

func signFile(service *pgpcore.Service, args []string) error {
	fs := flag.NewFlagSet("sign", flag.ContinueOnError)
	fingerprint := fs.String("key", "", "fingerprint da chave secreta")
	modeText := fs.String("mode", "detached", "detached, inline ou cleartext")
	armor := fs.Bool("armor", true, "ASCII armor")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 2 || *fingerprint == "" {
		return errors.New("uso: sign --key FINGERPRINT [opções] ENTRADA SAIDA")
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
			secret, promptErr := secretFromEnvOrPrompt("PGP_CLIENT_PASSPHRASE", "Frase secreta de "+required.Identity+": ")
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
	modeText := fs.String("mode", "detached", "detached, inline ou cleartext")
	dataPath := fs.String("data", "", "dados originais para assinatura destacada")
	signaturePath := fs.String("signature", "", "assinatura ou mensagem assinada")
	out := fs.String("out", "", "saída do conteúdo inline verificado")
	if err := fs.Parse(args); err != nil {
		return err
	}
	mode, err := parseMode(*modeText)
	if err != nil {
		return err
	}
	if *signaturePath == "" {
		return errors.New("--signature é obrigatório")
	}
	if mode == model.SignatureDetached && *dataPath == "" {
		return errors.New("--data é obrigatório para assinatura destacada")
	}
	result, err := service.VerifyFile(context.Background(), *dataPath, *signaturePath, *out, model.VerifyRequest{Mode: mode})
	if err != nil {
		return err
	}
	if !result.Valid {
		return fmt.Errorf("assinatura inválida: %s", result.SignatureErr)
	}
	fmt.Printf("Assinatura válida: keyID=%s signer=%s <%s>\n", result.SignerKeyID, result.SignerName, result.SignerEmail)
	return nil
}

func backup(service *pgpcore.Service, args []string) error {
	if len(args) != 1 {
		return errors.New("uso: backup SAIDA.pgpbackup")
	}
	password, err := secretFromEnvOrPrompt("PGP_CLIENT_PASSWORD", "Senha do backup: ")
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
	settings := fs.Bool("settings", false, "restaurar preferências")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		return errors.New("uso: restore [--settings] BACKUP.pgpbackup")
	}
	archive, err := os.ReadFile(fs.Arg(0))
	if err != nil {
		return err
	}
	password, err := secretFromEnvOrPrompt("PGP_CLIENT_PASSWORD", "Senha do backup: ")
	if err != nil {
		return err
	}
	infos, err := service.RestoreBackup(archive, password, *settings)
	if err != nil {
		return err
	}
	fmt.Printf("%d chave(s) restaurada(s).\n", len(infos))
	return nil
}

func keyserverSearch(service *pgpcore.Service, args []string) error {
	if len(args) == 0 {
		return errors.New("informe uma consulta")
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
		return errors.New("informe fingerprint ou Key ID")
	}
	infos, err := service.ImportFromKeyserver(context.Background(), args[0])
	if err != nil {
		return err
	}
	for _, info := range infos {
		fmt.Printf("Importada: %s %s\n", info.KeyID, info.PrimaryIdentity())
	}
	return nil
}

func keyserverUpload(service *pgpcore.Service, args []string) error {
	if len(args) != 1 {
		return errors.New("informe o fingerprint")
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
		return "", errors.New("modo deve ser detached, inline ou cleartext")
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
		return nil, errors.New("entrada não é um terminal; use a variável de ambiente de segredo")
	}
	fmt.Fprint(os.Stderr, prompt)
	secret, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	if len(secret) == 0 {
		return nil, errors.New("segredo vazio")
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
	return string(runes[:max-1]) + "…"
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "erro:", err)
	os.Exit(1)
}
