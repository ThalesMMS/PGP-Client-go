package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	gcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"

	"github.com/ThalesMMS/PGP-Client-go/internal/fileutil"
	"github.com/ThalesMMS/PGP-Client-go/internal/model"
)

const (
	appDirName        = "pgp-client-go"
	metadataFileName  = "metadata.json"
	settingsFileName  = "settings.json"
	privateFileSuffix = ".secret.asc"
	publicFileSuffix  = ".public.asc"
)

// Store persists certificates, local metadata and preferences. Private key
// files are written with mode 0600. Every update is an atomic rename.
type Store struct {
	root    string
	keysDir string
	mu      sync.RWMutex
}

func DefaultRoot() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("obter diretório de configuração: %w", err)
	}
	return filepath.Join(configDir, appDirName), nil
}

func New(root string) (*Store, error) {
	if strings.TrimSpace(root) == "" {
		var err error
		root, err = DefaultRoot()
		if err != nil {
			return nil, err
		}
	}
	s := &Store{root: root, keysDir: filepath.Join(root, "keys")}
	if err := os.MkdirAll(s.keysDir, 0o700); err != nil {
		return nil, fmt.Errorf("criar armazenamento de chaves: %w", err)
	}
	return s, nil
}

func (s *Store) Root() string { return s.root }

func normalizeFingerprint(fingerprint string) string {
	return strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(fingerprint), " ", ""))
}

func safeFingerprint(fingerprint string) string {
	return strings.ToLower(normalizeFingerprint(fingerprint))
}

func (s *Store) keyPath(fingerprint string, private bool) string {
	suffix := publicFileSuffix
	if private {
		suffix = privateFileSuffix
	}
	return filepath.Join(s.keysDir, safeFingerprint(fingerprint)+suffix)
}

// SaveKey stores one OpenPGP entity. A private key supersedes its public-only
// copy; importing a public copy never overwrites an existing private key.
func (s *Store) SaveKey(key *gcrypto.Key) error {
	if key == nil {
		return errors.New("chave nula")
	}
	fingerprint := normalizeFingerprint(key.GetFingerprint())
	if fingerprint == "" {
		return errors.New("chave sem fingerprint")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	private := key.IsPrivate()
	if !private {
		if _, err := os.Stat(s.keyPath(fingerprint, true)); err == nil {
			return nil
		}
	}

	var armored string
	var err error
	if private {
		armored, err = key.Armor()
	} else {
		armored, err = key.GetArmoredPublicKey()
	}
	if err != nil {
		return fmt.Errorf("serializar chave: %w", err)
	}
	mode := os.FileMode(0o644)
	if private {
		mode = 0o600
	}
	if err := atomicWriteFile(s.keyPath(fingerprint, private), []byte(armored), mode); err != nil {
		return fmt.Errorf("salvar chave: %w", err)
	}
	if private {
		_ = os.Remove(s.keyPath(fingerprint, false))
	}

	metadata, err := s.loadMetadataLocked()
	if err != nil {
		return err
	}
	if _, ok := metadata[fingerprint]; !ok {
		metadata[fingerprint] = model.KeyMetadata{
			Fingerprint: fingerprint,
			Trust:       model.TrustUnknown,
			ImportedAt:  time.Now().UTC(),
		}
		if err := s.saveMetadataLocked(metadata); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) DeleteKey(fingerprint string) error {
	fingerprint = normalizeFingerprint(fingerprint)
	s.mu.Lock()
	defer s.mu.Unlock()

	found := false
	for _, private := range []bool{false, true} {
		path := s.keyPath(fingerprint, private)
		if err := os.Remove(path); err == nil {
			found = true
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("excluir chave: %w", err)
		}
	}
	if !found {
		return model.ErrKeyNotFound
	}
	metadata, err := s.loadMetadataLocked()
	if err != nil {
		return err
	}
	delete(metadata, fingerprint)
	return s.saveMetadataLocked(metadata)
}

func (s *Store) LoadKey(fingerprint string) (*gcrypto.Key, error) {
	fingerprint = normalizeFingerprint(fingerprint)
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, private := range []bool{true, false} {
		data, err := os.ReadFile(s.keyPath(fingerprint, private))
		if err == nil {
			key, parseErr := gcrypto.NewKey(data)
			if parseErr != nil {
				return nil, fmt.Errorf("ler chave %s: %w", fingerprint, parseErr)
			}
			return key, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("ler chave %s: %w", fingerprint, err)
		}
	}
	return nil, model.ErrKeyNotFound
}

func (s *Store) LoadAllKeys() ([]*gcrypto.Key, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	entries, err := os.ReadDir(s.keysDir)
	if err != nil {
		return nil, fmt.Errorf("listar chaves: %w", err)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	keys := make([]*gcrypto.Key, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || (!strings.HasSuffix(entry.Name(), privateFileSuffix) && !strings.HasSuffix(entry.Name(), publicFileSuffix)) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.keysDir, entry.Name()))
		if err != nil {
			return nil, fmt.Errorf("ler %s: %w", entry.Name(), err)
		}
		key, err := gcrypto.NewKey(data)
		if err != nil {
			return nil, fmt.Errorf("interpretar %s: %w", entry.Name(), err)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

// ParseKeyBundle accepts binary or ASCII-armored OpenPGP keyrings, including
// bundles with multiple entities and locked private keys.
func ParseKeyBundle(data []byte) ([]*gcrypto.Key, error) {
	var entities openpgp.EntityList
	var err error
	trimmed := strings.TrimSpace(string(data))
	if strings.HasPrefix(trimmed, "-----BEGIN PGP") {
		entities, err = openpgp.ReadArmoredKeyRing(strings.NewReader(trimmed))
	} else {
		entities, err = openpgp.ReadKeyRing(strings.NewReader(string(data)))
	}
	if err != nil {
		return nil, fmt.Errorf("interpretar chave OpenPGP: %w", err)
	}
	keys := make([]*gcrypto.Key, 0, len(entities))
	for _, entity := range entities {
		key, err := gcrypto.NewKeyFromEntity(entity)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	if len(keys) == 0 {
		return nil, errors.New("nenhuma chave OpenPGP encontrada")
	}
	return keys, nil
}

func (s *Store) Metadata() (map[string]model.KeyMetadata, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.loadMetadataLocked()
}

func (s *Store) UpdateMetadata(fingerprint string, update func(*model.KeyMetadata)) error {
	fingerprint = normalizeFingerprint(fingerprint)
	s.mu.Lock()
	defer s.mu.Unlock()
	metadata, err := s.loadMetadataLocked()
	if err != nil {
		return err
	}
	item, ok := metadata[fingerprint]
	if !ok {
		item = model.KeyMetadata{Fingerprint: fingerprint, Trust: model.TrustUnknown, ImportedAt: time.Now().UTC()}
	}
	update(&item)
	item.Fingerprint = fingerprint
	metadata[fingerprint] = item
	return s.saveMetadataLocked(metadata)
}

func (s *Store) loadMetadataLocked() (map[string]model.KeyMetadata, error) {
	path := filepath.Join(s.root, metadataFileName)
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return make(map[string]model.KeyMetadata), nil
	}
	if err != nil {
		return nil, fmt.Errorf("ler metadados: %w", err)
	}
	metadata := make(map[string]model.KeyMetadata)
	if len(data) == 0 {
		return metadata, nil
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return nil, fmt.Errorf("interpretar metadados: %w", err)
	}
	return metadata, nil
}

func (s *Store) saveMetadataLocked(metadata map[string]model.KeyMetadata) error {
	data, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("serializar metadados: %w", err)
	}
	if err := atomicWriteFile(filepath.Join(s.root, metadataFileName), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("salvar metadados: %w", err)
	}
	return nil
}

func (s *Store) LoadSettings() (model.Settings, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	settings := model.DefaultSettings()
	data, err := os.ReadFile(filepath.Join(s.root, settingsFileName))
	if errors.Is(err, os.ErrNotExist) {
		return settings, nil
	}
	if err != nil {
		return settings, fmt.Errorf("ler preferências: %w", err)
	}
	if err := json.Unmarshal(data, &settings); err != nil {
		return settings, fmt.Errorf("interpretar preferências: %w", err)
	}
	return settings, nil
}

func (s *Store) SaveSettings(settings model.Settings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		return fmt.Errorf("serializar preferências: %w", err)
	}
	if err := atomicWriteFile(filepath.Join(s.root, settingsFileName), append(data, '\n'), 0o600); err != nil {
		return fmt.Errorf("salvar preferências: %w", err)
	}
	return nil
}

func atomicWriteFile(path string, data []byte, mode os.FileMode) error {
	return fileutil.AtomicWrite(path, data, mode, 0o700)
}
