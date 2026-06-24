package storage

import (
	"testing"

	"github.com/ProtonMail/go-crypto/openpgp/packet"
	openpgp "github.com/ProtonMail/go-crypto/openpgp/v2"
	gcrypto "github.com/ProtonMail/gopenpgp/v3/crypto"
)

func TestPublicImportDoesNotOverwritePrivateKey(t *testing.T) {
	store, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	entity, err := openpgp.NewEntity("Alice", "", "alice@example.test", &packet.Config{Algorithm: packet.PubKeyAlgoRSA, RSABits: 2048})
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := gcrypto.NewKeyFromEntity(entity)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err = gcrypto.PGP().LockKey(privateKey, []byte("long-passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKey(privateKey); err != nil {
		t.Fatal(err)
	}
	publicKey, err := privateKey.ToPublic()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SaveKey(publicKey); err != nil {
		t.Fatal(err)
	}
	loaded, err := store.LoadKey(privateKey.GetFingerprint())
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.IsPrivate() {
		t.Fatal("public import overwrote private key")
	}
	locked, err := loaded.IsLocked()
	if err != nil || !locked {
		t.Fatalf("private key protection lost: locked=%t err=%v", locked, err)
	}
}
