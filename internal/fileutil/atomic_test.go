package fileutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicOutputPreservesDestinationOnFailure(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "result.txt")
	if err := os.WriteFile(destination, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}

	expected := errors.New("write failed")
	err := AtomicOutput(destination, 0o600, 0o700, func(output *os.File) error {
		if _, err := output.WriteString("partial"); err != nil {
			return err
		}
		return expected
	})
	if !errors.Is(err, expected) {
		t.Fatalf("error = %v, want %v", err, expected)
	}
	actual, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "original" {
		t.Fatalf("destination changed after failure: %q", actual)
	}
}

func TestAtomicWriteReplacesDestination(t *testing.T) {
	destination := filepath.Join(t.TempDir(), "result.txt")
	if err := os.WriteFile(destination, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AtomicWrite(destination, []byte("new"), 0o600, 0o700); err != nil {
		t.Fatal(err)
	}
	actual, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if string(actual) != "new" {
		t.Fatalf("destination = %q, want new", actual)
	}
}
