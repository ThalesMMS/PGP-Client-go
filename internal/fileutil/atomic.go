// Package fileutil contains small, security-oriented filesystem helpers shared
// by the persistence, OpenPGP and command-line layers.
package fileutil

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// PendingFile is a temporary file in the destination directory. Call Commit
// only after every validation step has succeeded; otherwise call Abort.
type PendingFile struct {
	File        *os.File
	temporary   string
	destination string
	committed   bool
}

// NewPending creates a same-directory temporary file so the final rename stays
// on the same filesystem. The destination directory is created when needed.
func NewPending(destination string, fileMode, directoryMode fs.FileMode) (*PendingFile, error) {
	if strings.TrimSpace(destination) == "" {
		return nil, errors.New("empty output path")
	}
	directory := filepath.Dir(destination)
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(directory, ".pgp-client-*")
	if err != nil {
		return nil, err
	}
	if err := temporary.Chmod(fileMode); err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporary.Name())
		return nil, err
	}
	return &PendingFile{
		File:        temporary,
		temporary:   temporary.Name(),
		destination: destination,
	}, nil
}

// Commit flushes and closes the temporary file before replacing the target.
func (pending *PendingFile) Commit() error {
	if pending == nil || pending.File == nil {
		return errors.New("invalid temporary file")
	}
	if pending.committed {
		return errors.New("temporary file already committed")
	}
	if err := pending.File.Sync(); err != nil {
		_ = pending.File.Close()
		return err
	}
	if err := pending.File.Close(); err != nil {
		return err
	}
	if err := replace(pending.temporary, pending.destination); err != nil {
		return err
	}
	pending.committed = true
	return nil
}

// Abort closes and removes the temporary file. It is safe to call repeatedly.
func (pending *PendingFile) Abort() {
	if pending == nil || pending.committed {
		return
	}
	if pending.File != nil {
		_ = pending.File.Close()
	}
	if pending.temporary != "" {
		_ = os.Remove(pending.temporary)
	}
}

// AtomicWrite writes data to a temporary file and commits it only after a
// successful flush.
func AtomicWrite(destination string, data []byte, fileMode, directoryMode fs.FileMode) error {
	return AtomicOutput(destination, fileMode, directoryMode, func(output *os.File) error {
		_, err := output.Write(data)
		return err
	})
}

// AtomicOutput runs write against a same-directory temporary file and commits
// the result only when write returns nil.
func AtomicOutput(destination string, fileMode, directoryMode fs.FileMode, write func(*os.File) error) error {
	pending, err := NewPending(destination, fileMode, directoryMode)
	if err != nil {
		return err
	}
	defer pending.Abort()
	if err := write(pending.File); err != nil {
		return err
	}
	return pending.Commit()
}

// Windows does not allow renaming over an existing destination. Unix-like
// systems retain true atomic replacement through rename(2); on Windows, the
// destination is removed only after the first rename attempt fails.
func replace(source, destination string) error {
	if err := os.Rename(source, destination); err == nil {
		return nil
	} else if runtime.GOOS != "windows" {
		return err
	}
	if err := os.Remove(destination); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return os.Rename(source, destination)
}
