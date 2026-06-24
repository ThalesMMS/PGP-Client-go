package storage

import (
	"errors"
	"strings"
	"sync"
	"time"

	keyring "github.com/zalando/go-keyring"
)

const keychainService = "com.thalesmms.pgpclientgo"

// SecretStore abstracts the platform credential vault for deterministic tests.
type SecretStore interface {
	Get(account string) ([]byte, error)
	Set(account string, secret []byte) error
	Delete(account string) error
}

type SystemSecretStore struct{}

func (SystemSecretStore) Get(account string) ([]byte, error) {
	secret, err := keyring.Get(keychainService, strings.ToUpper(account))
	if err != nil {
		return nil, err
	}
	return []byte(secret), nil
}

func (SystemSecretStore) Set(account string, secret []byte) error {
	return keyring.Set(keychainService, strings.ToUpper(account), string(secret))
}

func (SystemSecretStore) Delete(account string) error {
	err := keyring.Delete(keychainService, strings.ToUpper(account))
	if errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// MemorySecretStore is useful for tests and explicitly opt-in ephemeral use.
type MemorySecretStore struct {
	mu      sync.RWMutex
	secrets map[string][]byte
}

func NewMemorySecretStore() *MemorySecretStore {
	return &MemorySecretStore{secrets: make(map[string][]byte)}
}

func (m *MemorySecretStore) Get(account string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	secret, ok := m.secrets[strings.ToUpper(account)]
	if !ok {
		return nil, keyring.ErrNotFound
	}
	return append([]byte(nil), secret...), nil
}

func (m *MemorySecretStore) Set(account string, secret []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.secrets[strings.ToUpper(account)] = append([]byte(nil), secret...)
	return nil
}

func (m *MemorySecretStore) Delete(account string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.secrets, strings.ToUpper(account))
	return nil
}

type cacheEntry struct {
	secret    []byte
	expiresAt time.Time
}

// SecretCache keeps passphrases only in memory and clears overwritten buffers.
type SecretCache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
}

func NewSecretCache() *SecretCache {
	return &SecretCache{entries: make(map[string]cacheEntry)}
}

func (c *SecretCache) Put(account string, secret []byte, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	account = strings.ToUpper(account)
	if old, ok := c.entries[account]; ok {
		zero(old.secret)
	}
	if ttl <= 0 {
		ttl = time.Minute
	}
	c.entries[account] = cacheEntry{secret: append([]byte(nil), secret...), expiresAt: time.Now().Add(ttl)}
}

func (c *SecretCache) Get(account string) ([]byte, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	account = strings.ToUpper(account)
	entry, ok := c.entries[account]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expiresAt) {
		zero(entry.secret)
		delete(c.entries, account)
		return nil, false
	}
	return append([]byte(nil), entry.secret...), true
}

func (c *SecretCache) Delete(account string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	account = strings.ToUpper(account)
	if entry, ok := c.entries[account]; ok {
		zero(entry.secret)
		delete(c.entries, account)
	}
}

func (c *SecretCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	for account, entry := range c.entries {
		zero(entry.secret)
		delete(c.entries, account)
	}
}

func zero(value []byte) {
	for i := range value {
		value[i] = 0
	}
}
