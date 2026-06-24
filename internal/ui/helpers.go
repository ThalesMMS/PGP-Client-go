package ui

import (
	"bytes"
	"errors"
	"fmt"
	"image/color"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
)

func heading(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.TextStyle = fyne.TextStyle{Bold: true}
	label.Importance = widget.HighImportance
	return label
}

func muted(text string) *widget.Label {
	label := widget.NewLabel(text)
	label.Importance = widget.LowImportance
	return label
}

func section(title string, objects ...fyne.CanvasObject) fyne.CanvasObject {
	items := []fyne.CanvasObject{heading(title), canvas.NewLine(theme.Color(theme.ColorNameSeparator))}
	items = append(items, objects...)
	return container.NewVBox(items...)
}

func card(objects ...fyne.CanvasObject) fyne.CanvasObject {
	background := canvas.NewRectangle(color.NRGBA{R: 25, G: 25, B: 27, A: 255})
	background.CornerRadius = 10
	return container.NewStack(background, container.NewPadded(container.NewVBox(objects...)))
}

func labeledValue(label, value string) fyne.CanvasObject {
	left := muted(label)
	right := widget.NewLabel(value)
	right.Wrapping = fyne.TextWrapWord
	return container.NewBorder(nil, nil, left, nil, right)
}

func formatFingerprint(fingerprint string) string {
	fingerprint = strings.ReplaceAll(strings.ToUpper(fingerprint), " ", "")
	parts := make([]string, 0, (len(fingerprint)+3)/4)
	for len(fingerprint) > 0 {
		n := 4
		if len(fingerprint) < n {
			n = len(fingerprint)
		}
		parts = append(parts, fingerprint[:n])
		fingerprint = fingerprint[n:]
	}
	return strings.Join(parts, " ")
}

func formatDate(value time.Time) string {
	if value.IsZero() {
		return "—"
	}
	return value.Local().Format("02 Jan 2006")
}

func keyKind(info model.KeyInfo) string {
	if info.IsPrivate {
		if info.IsLocked {
			return "Chave secreta protegida"
		}
		return "Chave secreta"
	}
	return "Chave pública"
}

func trustLabel(level model.TrustLevel) string {
	switch level {
	case model.TrustNever:
		return "Nunca confiar"
	case model.TrustMarginal:
		return "Confiança marginal"
	case model.TrustFull:
		return "Confiança plena"
	case model.TrustUltimate:
		return "Confiança definitiva"
	default:
		return "Desconhecida"
	}
}

func trustFromLabel(value string) model.TrustLevel {
	switch value {
	case "Nunca confiar":
		return model.TrustNever
	case "Confiança marginal":
		return model.TrustMarginal
	case "Confiança plena":
		return model.TrustFull
	case "Confiança definitiva":
		return model.TrustUltimate
	default:
		return model.TrustUnknown
	}
}

func extensionForEncrypted(armor bool) string {
	if armor {
		return ".asc"
	}
	return ".gpg"
}

func suggestedDecryptedPath(path string) string {
	lower := strings.ToLower(path)
	for _, ext := range []string{".gpg", ".pgp", ".asc"} {
		if strings.HasSuffix(lower, ext) {
			return path[:len(path)-len(ext)]
		}
	}
	return path + ".decrypted"
}

func writeURI(writer fyne.URIWriteCloser, data []byte, mode os.FileMode) error {
	if writer == nil {
		return errors.New("destino inválido")
	}
	uri := writer.URI()
	_, writeErr := io.Copy(writer, bytes.NewReader(data))
	closeErr := writer.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if uri != nil && uri.Scheme() == "file" && strings.TrimSpace(uri.Path()) != "" {
		if err := os.Chmod(uri.Path(), mode); err != nil {
			return err
		}
	}
	return nil
}

func filePickerRow(window fyne.Window, entry *widget.Entry, save bool, suggested string) fyne.CanvasObject {
	button := widget.NewButtonWithIcon("Escolher…", theme.FolderOpenIcon(), func() {
		if save {
			// A FileSave dialog creates/truncates the selected file before the
			// cryptographic operation starts. Select the directory instead and let
			// the transactional writer create the final file only on success.
			dialog.NewFolderOpen(func(folder fyne.ListableURI, err error) {
				if err != nil {
					dialog.ShowError(err, window)
					return
				}
				if folder == nil {
					return
				}
				name := suggested
				if current := strings.TrimSpace(entry.Text); current != "" {
					base := filepath.Base(current)
					if base != "." && base != string(filepath.Separator) {
						name = base
					}
				}
				if name == "" {
					name = "output.bin"
				}
				entry.SetText(filepath.Join(folder.Path(), name))
			}, window).Show()
			return
		}
		dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if reader == nil {
				return
			}
			entry.SetText(reader.URI().Path())
			_ = reader.Close()
		}, window).Show()
	})
	return container.NewBorder(nil, nil, nil, button, entry)
}

func spacer(width, height float32) fyne.CanvasObject {
	object := canvas.NewRectangle(color.Transparent)
	object.SetMinSize(fyne.NewSize(width, height))
	return object
}

func statusBadge(text string, ok bool) fyne.CanvasObject {
	icon := theme.WarningIcon()
	importance := widget.MediumImportance
	if ok {
		icon = theme.ConfirmIcon()
		importance = widget.SuccessImportance
	}
	label := widget.NewLabelWithStyle(text, fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	label.Importance = importance
	return container.NewHBox(widget.NewIcon(icon), label)
}

func errorText(err error) string {
	if err == nil {
		return ""
	}
	return fmt.Sprintf("%v", err)
}

func center(object fyne.CanvasObject) fyne.CanvasObject {
	return container.New(layout.NewCenterLayout(), object)
}
