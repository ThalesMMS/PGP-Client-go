//go:build ci

package ui

import (
	"os"
	"path/filepath"
	"testing"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	fynetest "fyne.io/fyne/v2/test"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
	pgpcore "github.com/ThalesMMS/PGP-Client-go/internal/pgp"
	"github.com/ThalesMMS/PGP-Client-go/internal/storage"
)

func TestDesktopPagesRender(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := pgpcore.NewService(store, storage.NewMemorySecretStore())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.GenerateKey(model.KeyGenerationRequest{
		Name:       "Alice",
		Email:      "alice@example.test",
		Bits:       2048,
		ExpiryDays: 30,
		Passphrase: []byte("alice-long-passphrase"),
	}); err != nil {
		t.Fatal(err)
	}

	desktop, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	defer desktop.app.Quit()

	for _, page := range []pageID{pageKeyring, pageEncrypt, pageDecrypt, pageSign, pageVerify} {
		desktop.showPage(page)
		if markup := fynetest.RenderObjectToMarkup(desktop.content); markup == "" {
			t.Fatalf("page %q rendered empty markup", page)
		}
	}
}

func TestOpenPathRoutesToFileWorkflow(t *testing.T) {
	store, err := storage.New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	service, err := pgpcore.NewService(store, storage.NewMemorySecretStore())
	if err != nil {
		t.Fatal(err)
	}
	desktop, err := New(service)
	if err != nil {
		t.Fatal(err)
	}
	defer desktop.app.Quit()

	tests := []struct {
		name string
		ext  string
		page pageID
	}{
		{name: "ordinary file", ext: ".txt", page: pageEncrypt},
		{name: "encrypted file", ext: ".gpg", page: pageDecrypt},
		{name: "detached signature", ext: ".sig", page: pageVerify},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "sample"+tt.ext)
			if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
				t.Fatal(err)
			}
			desktop.openPath(path)
			if desktop.page != tt.page {
				t.Fatalf("page = %q, want %q", desktop.page, tt.page)
			}
			tabs := findAppTabs(desktop.content)
			if tabs == nil {
				t.Fatal("workflow tabs not found")
			}
			if got := tabs.CurrentTabIndex(); got != 1 {
				t.Fatalf("selected tab = %d, want file tab 1", got)
			}
		})
	}
}

func findAppTabs(object fyne.CanvasObject) *container.AppTabs {
	if tabs, ok := object.(*container.AppTabs); ok {
		return tabs
	}
	if group, ok := object.(*fyne.Container); ok {
		for _, child := range group.Objects {
			if tabs := findAppTabs(child); tabs != nil {
				return tabs
			}
		}
	}
	return nil
}
