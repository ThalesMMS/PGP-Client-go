package ui

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/ProtonMail/go-crypto/openpgp/packet"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
)

func (d *Desktop) buildKeyringPage() fyne.CanvasObject {
	if err := d.reloadKeys(); err != nil {
		return center(widget.NewLabel("Failed to load keys: " + err.Error()))
	}

	search := widget.NewEntry()
	search.SetPlaceHolder("Search keys...")
	filter := widget.NewSelect([]string{"All", "Secret", "Public", "Invalid"}, nil)
	filter.SetSelected("All")
	sortBy := widget.NewSelect([]string{"Name", "Created", "Key ID"}, nil)
	sortBy.SetSelected("Name")

	filtered := append([]model.KeyInfo(nil), d.keys...)
	selectedFingerprint := ""
	details := container.NewMax(center(muted("Select a key")))

	var list *widget.List
	apply := func() {
		query := strings.ToLower(strings.TrimSpace(search.Text))
		filtered = filtered[:0]
		for _, key := range d.keys {
			matchesQuery := query == "" || strings.Contains(strings.ToLower(strings.Join([]string{
				key.Name, key.Email, key.KeyID, key.Fingerprint, strings.Join(key.UserIDs, " "),
			}, " ")), query)
			if !matchesQuery {
				continue
			}
			switch filter.Selected {
			case "Secret":
				if !key.IsPrivate {
					continue
				}
			case "Public":
				if key.IsPrivate {
					continue
				}
			case "Invalid":
				if !key.Expired && !key.Revoked {
					continue
				}
			}
			filtered = append(filtered, key)
		}
		sort.SliceStable(filtered, func(i, j int) bool {
			switch sortBy.Selected {
			case "Created":
				return filtered[i].CreatedAt.After(filtered[j].CreatedAt)
			case "Key ID":
				return filtered[i].KeyID < filtered[j].KeyID
			default:
				return strings.ToLower(filtered[i].DisplayName()) < strings.ToLower(filtered[j].DisplayName())
			}
		})
		if list != nil {
			list.Refresh()
		}
	}

	list = widget.NewList(
		func() int { return len(filtered) },
		func() fyne.CanvasObject {
			icon := widget.NewIcon(theme.LoginIcon())
			name := widget.NewLabelWithStyle("Name", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
			identity := muted("email")
			keyID := muted("A1B2C3D4")
			text := container.NewVBox(name, identity, keyID)
			textWithSize := container.NewStack(spacer(250, 70), text)
			row := container.NewBorder(nil, canvas.NewLine(theme.Color(theme.ColorNameSeparator)), icon, nil, textWithSize)
			return row
		},
		func(id widget.ListItemID, object fyne.CanvasObject) {
			if id < 0 || id >= len(filtered) {
				return
			}
			key := filtered[id]
			row := object.(*fyne.Container)
			icon := row.Objects[2].(*widget.Icon)
			if key.IsPrivate {
				icon.SetResource(theme.LoginIcon())
			} else {
				icon.SetResource(theme.AccountIcon())
			}
			textStack := row.Objects[0].(*fyne.Container)
			text := textStack.Objects[1].(*fyne.Container)
			text.Objects[0].(*widget.Label).SetText(key.DisplayName())
			identity := key.Email
			if identity == "" {
				identity = keyKind(key)
			}
			text.Objects[1].(*widget.Label).SetText(identity)
			status := d.visibleKeyID(key)
			if key.Revoked {
				status += " - REVOKED"
			} else if key.Expired {
				status += " - EXPIRED"
			}
			text.Objects[2].(*widget.Label).SetText(status)
		},
	)
	list.OnSelected = func(id widget.ListItemID) {
		if id < 0 || id >= len(filtered) {
			return
		}
		selectedFingerprint = filtered[id].Fingerprint
		details.Objects = []fyne.CanvasObject{d.buildKeyDetails(filtered[id])}
		details.Refresh()
	}

	search.OnChanged = func(string) { apply() }
	filter.OnChanged = func(string) { apply() }
	sortBy.OnChanged = func(string) { apply() }

	toolbar := container.NewHBox(
		widget.NewButtonWithIcon("New", theme.ContentAddIcon(), d.showGenerateKey),
		widget.NewButtonWithIcon("Import", theme.DownloadIcon(), d.importKeyDialog),
		widget.NewButtonWithIcon("Server", theme.SearchIcon(), d.showKeyserverSearch),
		layout.NewSpacer(),
		widget.NewButtonWithIcon("Refresh", theme.ViewRefreshIcon(), func() {
			if err := d.reloadKeys(); err != nil {
				dialog.ShowError(err, d.window)
				return
			}
			d.showPage(pageKeyring)
		}),
	)
	controls := container.NewGridWithColumns(2, filter, sortBy)
	middle := container.NewBorder(
		container.NewVBox(container.NewPadded(heading("Keyring")), toolbar, controls, search, canvas.NewLine(theme.Color(theme.ColorNameSeparator))),
		nil, nil, nil,
		list,
	)
	middlePanel := container.NewStack(spacer(360, 600), middle)

	if len(filtered) > 0 {
		selectedFingerprint = filtered[0].Fingerprint
		list.Select(0)
	} else {
		empty := card(
			center(widget.NewIcon(theme.StorageIcon())),
			center(heading("No keys")),
			center(muted("Generate an RSA key or import an OpenPGP certificate.")),
			center(container.NewHBox(
				widget.NewButtonWithIcon("Generate key", theme.ContentAddIcon(), d.showGenerateKey),
				widget.NewButtonWithIcon("Import", theme.DownloadIcon(), d.importKeyDialog),
			)),
		)
		details.Objects = []fyne.CanvasObject{center(empty)}
	}

	split := container.NewHSplit(middlePanel, details)
	split.Offset = 0.34
	_ = selectedFingerprint
	apply()
	return split
}

func (d *Desktop) buildKeyDetails(info model.KeyInfo) fyne.CanvasObject {
	keyIcon := widget.NewIcon(theme.LoginIcon())
	if !info.IsPrivate {
		keyIcon.SetResource(theme.AccountIcon())
	}
	keyIcon.Resize(fyne.NewSize(64, 64))
	name := widget.NewLabelWithStyle(info.DisplayName(), fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	name.Importance = widget.HighImportance
	identity := muted(info.Email)
	kind := widget.NewLabel(keyKind(info))
	kind.Importance = widget.WarningImportance
	title := container.NewHBox(keyIcon, container.NewVBox(name, identity, kind))

	exportPublic := widget.NewButtonWithIcon("Public", theme.UploadIcon(), func() { d.exportKeyDialog(info, false) })
	exportPrivate := widget.NewButtonWithIcon("Private", theme.WarningIcon(), func() { d.exportKeyDialog(info, true) })
	if !info.IsPrivate {
		exportPrivate.Disable()
	}
	deleteButton := widget.NewButtonWithIcon("Delete", theme.DeleteIcon(), func() { d.deleteKeyDialog(info) })
	deleteButton.Importance = widget.DangerImportance
	toolbar := container.NewHBox(exportPublic, exportPrivate, layout.NewSpacer(), deleteButton)

	expires := "Never"
	if info.ExpiresAt != nil {
		expires = formatDate(*info.ExpiresAt)
	}
	facts := container.NewGridWithColumns(2,
		card(labeledValue("Key ID", info.KeyID), labeledValue("Created", formatDate(info.CreatedAt))),
		card(labeledValue("Algorithm", fmt.Sprintf("%s %d", info.Algorithm, info.Bits)), labeledValue("Expires", expires)),
	)

	fingerprintEntry := widget.NewEntry()
	fingerprintEntry.SetText(formatFingerprint(info.Fingerprint))
	fingerprintEntry.Disable()
	copyFingerprint := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		d.window.Clipboard().SetContent(info.Fingerprint)
		d.setStatus("Fingerprint copied")
	})
	compare := widget.NewButtonWithIcon("Compare", theme.SearchReplaceIcon(), func() { d.showFingerprintComparison(info) })
	fingerprint := section("Fingerprint", container.NewBorder(nil, nil, nil, container.NewHBox(copyFingerprint, compare), fingerprintEntry))

	uids := container.NewVBox()
	for _, uid := range info.UserIDs {
		uids.Add(card(widget.NewLabel(uid)))
	}
	if len(info.UserIDs) == 0 {
		uids.Add(muted("No identities available"))
	}

	trustSelect := widget.NewSelect([]string{
		"Unknown", "Never trust", "Marginal trust", "Full trust", "Ultimate trust",
	}, func(value string) {
		if err := d.service.SetTrust(info.Fingerprint, trustFromLabel(value)); err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		d.setStatus("Trust level updated")
	})
	trustSelect.SetSelected(trustLabel(info.Metadata.Trust))
	verified := widget.NewCheck("Fingerprint verified out-of-band", func(checked bool) {
		method := "manual comparison"
		if err := d.service.MarkVerified(info.Fingerprint, method, checked); err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		d.setStatus("Verification state updated")
	})
	verified.SetChecked(info.Metadata.Verified)
	trust := section("Local trust", trustSelect, verified)

	statusItems := []fyne.CanvasObject{}
	if info.Revoked {
		statusItems = append(statusItems, statusBadge("This key has been revoked", false))
	}
	if info.Expired {
		statusItems = append(statusItems, statusBadge("This key has expired", false))
	}
	if !info.Revoked && !info.Expired {
		statusItems = append(statusItems, statusBadge("Usable certificate", true))
	}
	statusItems = append(statusItems,
		labeledValue("Encryption", boolText(info.CanEncrypt)),
		labeledValue("Verification", boolText(info.CanVerify)),
	)
	status := section("Status", statusItems...)

	serverButton := widget.NewButtonWithIcon("Publish to server", theme.UploadIcon(), func() {
		d.runAsync("Publishing public key...", func() error {
			return d.service.UploadToKeyserver(context.Background(), info.Fingerprint)
		}, func() { d.setStatus("Public key sent to server") })
	})
	revokeButton := widget.NewButtonWithIcon("Revoke key...", theme.WarningIcon(), func() { d.showRevokeKey(info) })
	revokeButton.Importance = widget.DangerImportance
	if !info.IsPrivate || info.Revoked {
		revokeButton.Disable()
	}
	actions := section("Advanced actions", container.NewHBox(serverButton, revokeButton))

	content := container.NewVBox(
		container.NewPadded(title),
		toolbar,
		canvas.NewLine(theme.Color(theme.ColorNameSeparator)),
		facts,
		fingerprint,
		section("Identities", uids),
		trust,
		status,
		actions,
		spacer(1, 24),
	)
	return container.NewVScroll(container.NewPadded(content))
}

func boolText(value bool) string {
	if value {
		return "Available"
	}
	return "Unavailable"
}

func (d *Desktop) showGenerateKey() {
	settings := d.service.Settings()
	name := widget.NewEntry()
	name.SetPlaceHolder("Full name")
	email := widget.NewEntry()
	email.SetPlaceHolder("name@example.com")
	comment := widget.NewEntry()
	comment.SetPlaceHolder("Optional")
	bits := widget.NewSelect([]string{"2048", "3072", "4096"}, nil)
	bits.SetSelected(strconv.Itoa(settings.DefaultKeyBits))
	expiry := widget.NewEntry()
	expiry.SetText(strconv.Itoa(settings.DefaultExpiryDays))
	passphrase := widget.NewPasswordEntry()
	passphrase.SetPlaceHolder("Recommended")
	confirm := widget.NewPasswordEntry()
	confirm.SetPlaceHolder("Repeat the passphrase")
	remember := widget.NewCheck("Store in system vault", nil)
	remember.SetChecked(settings.RememberPassphrases)
	strength := muted("Use a long, unique passphrase.")
	passphrase.OnChanged = func(value string) {
		switch {
		case len(value) == 0:
			strength.SetText("No passphrase: the key will be stored without local protection.")
		case len(value) < 12:
			strength.SetText("Short passphrase; use at least 12 characters.")
		case len(value) < 20:
			strength.SetText("Reasonable strength; a longer passphrase is preferred.")
		default:
			strength.SetText("Long passphrase.")
		}
	}
	form := widget.NewForm(
		widget.NewFormItem("Name", name),
		widget.NewFormItem("Email", email),
		widget.NewFormItem("Comment", comment),
		widget.NewFormItem("RSA", bits),
		widget.NewFormItem("Expiration (days, 0 = never)", expiry),
		widget.NewFormItem("Passphrase", passphrase),
		widget.NewFormItem("Confirm", confirm),
	)
	content := container.NewVBox(form, strength, remember)
	prompt := dialog.NewCustomConfirm("Generate new key", "Generate", "Cancel", content, func(ok bool) {
		if !ok {
			return
		}
		if passphrase.Text != confirm.Text {
			dialog.ShowError(errors.New("passphrases do not match"), d.window)
			return
		}
		keyBits, _ := strconv.Atoi(bits.Selected)
		expiryDays, err := strconv.Atoi(strings.TrimSpace(expiry.Text))
		if err != nil || expiryDays < 0 {
			dialog.ShowError(errors.New("invalid expiration"), d.window)
			return
		}
		req := model.KeyGenerationRequest{
			Name:           name.Text,
			Email:          email.Text,
			Comment:        comment.Text,
			Bits:           keyBits,
			ExpiryDays:     expiryDays,
			Passphrase:     []byte(passphrase.Text),
			RememberSecret: remember.Checked,
		}
		passphrase.SetText("")
		confirm.SetText("")
		d.runAsync("Generating RSA key...", func() error {
			_, err := d.service.GenerateKey(req)
			return err
		}, func() {
			_ = d.reloadKeys()
			d.showPage(pageKeyring)
			d.setStatus("New key created")
		})
	}, d.window)
	prompt.Resize(fyne.NewSize(620, 600))
	prompt.Show()
}

func (d *Desktop) importKeyDialog() {
	dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		if reader == nil {
			return
		}
		defer reader.Close()
		data, err := io.ReadAll(io.LimitReader(reader, 64<<20))
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		d.runAsync("Importing key...", func() error {
			_, err := d.service.Import(data)
			return err
		}, func() {
			_ = d.reloadKeys()
			d.showPage(pageKeyring)
			d.setStatus("Key imported")
		})
	}, d.window).Show()
}

func (d *Desktop) exportKeyDialog(info model.KeyInfo, private bool) {
	if private && !info.IsPrivate {
		dialog.ShowError(model.ErrNoPrivateKey, d.window)
		return
	}
	if private {
		dialog.ShowConfirm("Export secret key", "The file will contain private cryptographic material. Store it in a secure location.", func(ok bool) {
			if ok {
				d.saveExport(info, true)
			}
		}, d.window)
		return
	}
	d.saveExport(info, false)
}

func (d *Desktop) saveExport(info model.KeyInfo, private bool) {
	dialogue := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		if writer == nil {
			return
		}
		var data []byte
		if private {
			data, err = d.service.ExportPrivate(info.Fingerprint)
		} else {
			data, err = d.service.ExportPublic(info.Fingerprint)
		}
		if err == nil {
			mode := os.FileMode(0o644)
			if private {
				mode = 0o600
			}
			err = writeURI(writer, data, mode)
		} else {
			_ = writer.Close()
		}
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		d.setStatus("Key exported")
	}, d.window)
	suffix := "-public.asc"
	if private {
		suffix = "-secret.asc"
	}
	dialogue.SetFileName(info.ShortKeyID + suffix)
	dialogue.Show()
}

func (d *Desktop) deleteKeyDialog(info model.KeyInfo) {
	perform := func() {
		if err := d.service.DeleteKey(info.Fingerprint); err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		_ = d.reloadKeys()
		d.showPage(pageKeyring)
		d.setStatus("Key deleted")
	}
	if d.service.Settings().ConfirmBeforeDelete {
		dialog.ShowConfirm("Delete key", "Delete "+info.PrimaryIdentity()+" from the local keyring? This action cannot be undone.", func(ok bool) {
			if ok {
				perform()
			}
		}, d.window)
		return
	}
	perform()
}

func (d *Desktop) showFingerprintComparison(info model.KeyInfo) {
	entry := widget.NewEntry()
	entry.SetPlaceHolder("Paste the fingerprint received through a trusted channel")
	result := muted("Comparison ignores spaces and case.")
	compare := func() {
		expected := strings.ReplaceAll(strings.ToUpper(info.Fingerprint), " ", "")
		actual := strings.ReplaceAll(strings.ToUpper(entry.Text), " ", "")
		if actual == "" {
			result.SetText("Enter a fingerprint.")
			return
		}
		if actual == expected {
			result.SetText("Exact match.")
			_ = d.service.MarkVerified(info.Fingerprint, "manual comparison", true)
		} else {
			result.SetText("Does not match. Do not trust this key.")
		}
	}
	entry.OnChanged = func(string) { compare() }
	content := container.NewVBox(
		widget.NewLabel("Local fingerprint:"),
		card(widget.NewLabel(formatFingerprint(info.Fingerprint))),
		widget.NewLabel("External fingerprint:"), entry, result,
	)
	prompt := dialog.NewCustom("Compare fingerprint", "Close", content, d.window)
	prompt.Resize(fyne.NewSize(620, 360))
	prompt.Show()
}

func (d *Desktop) showRevokeKey(info model.KeyInfo) {
	reason := widget.NewSelect([]string{"No reason", "Superseded", "Compromised", "Retired"}, nil)
	reason.SetSelected("No reason")
	details := widget.NewMultiLineEntry()
	details.SetPlaceHolder("Optional reason")
	passphrase := widget.NewPasswordEntry()
	content := container.NewVBox(
		widget.NewLabel("The revocation will be embedded in the local key and exported with the certificate."),
		widget.NewForm(
			widget.NewFormItem("Reason", reason),
			widget.NewFormItem("Description", details),
			widget.NewFormItem("Passphrase", passphrase),
		),
	)
	prompt := dialog.NewCustomConfirm("Revoke key", "Revoke", "Cancel", content, func(ok bool) {
		if !ok {
			return
		}
		code := packet.NoReason
		switch reason.Selected {
		case "Superseded":
			code = packet.KeySuperseded
		case "Compromised":
			code = packet.KeyCompromised
		case "Retired":
			code = packet.KeyRetired
		}
		secret := []byte(passphrase.Text)
		description := details.Text
		passphrase.SetText("")
		d.runAsync("Revoking key...", func() error {
			return d.service.RevokeKey(info.Fingerprint, secret, code, description)
		}, func() {
			_ = d.reloadKeys()
			d.showPage(pageKeyring)
			d.setStatus("Key revoked")
		})
	}, d.window)
	prompt.Resize(fyne.NewSize(560, 360))
	prompt.Show()
}

func (d *Desktop) showBackup() {
	password := widget.NewPasswordEntry()
	confirm := widget.NewPasswordEntry()
	content := widget.NewForm(
		widget.NewFormItem("Backup password", password),
		widget.NewFormItem("Confirm", confirm),
	)
	prompt := dialog.NewCustomConfirm("Encrypted backup", "Continue", "Cancel", content, func(ok bool) {
		if !ok {
			return
		}
		if password.Text != confirm.Text {
			dialog.ShowError(errors.New("passwords do not match"), d.window)
			return
		}
		secret := []byte(password.Text)
		password.SetText("")
		confirm.SetText("")
		var archive []byte
		d.runAsync("Creating backup...", func() error {
			var err error
			archive, err = d.service.CreateBackup(secret)
			return err
		}, func() {
			save := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
				if err != nil {
					dialog.ShowError(err, d.window)
					return
				}
				if writer == nil {
					return
				}
				if err := writeURI(writer, archive, 0o600); err != nil {
					dialog.ShowError(err, d.window)
					return
				}
				if err := d.service.MarkBackupCreated(); err != nil {
					dialog.ShowError(fmt.Errorf("backup saved, but the reminder could not be updated: %w", err), d.window)
					return
				}
				d.setStatus("Backup created")
			}, d.window)
			save.SetFileName("pgp-client-" + time.Now().Format("20060102") + ".pgpbackup")
			save.Show()
		})
	}, d.window)
	prompt.Resize(fyne.NewSize(520, 300))
	prompt.Show()
}

func (d *Desktop) showRestore() {
	dialog.NewFileOpen(func(reader fyne.URIReadCloser, err error) {
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		if reader == nil {
			return
		}
		archive, err := io.ReadAll(io.LimitReader(reader, 512<<20))
		_ = reader.Close()
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		password := widget.NewPasswordEntry()
		restoreSettings := widget.NewCheck("Also restore preferences", nil)
		content := container.NewVBox(password, restoreSettings)
		prompt := dialog.NewCustomConfirm("Restore backup", "Restore", "Cancel", content, func(ok bool) {
			if !ok {
				return
			}
			secret := []byte(password.Text)
			includeSettings := restoreSettings.Checked
			password.SetText("")
			d.runAsync("Restoring backup...", func() error {
				_, err := d.service.RestoreBackup(archive, secret, includeSettings)
				return err
			}, func() {
				_ = d.reloadKeys()
				d.showPage(pageKeyring)
				d.setStatus("Backup restored")
			})
		}, d.window)
		prompt.Show()
	}, d.window).Show()
}

func (d *Desktop) showKeyserverSearch() {
	query := widget.NewEntry()
	query.SetPlaceHolder("Email, fingerprint or Key ID")
	results := []model.KeyserverResult{}
	list := widget.NewList(
		func() int { return len(results) },
		func() fyne.CanvasObject {
			return container.NewVBox(
				widget.NewLabelWithStyle("Identity", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
				muted("Key ID"),
				canvas.NewLine(theme.Color(theme.ColorNameSeparator)),
			)
		},
		func(id widget.ListItemID, object fyne.CanvasObject) {
			if id < 0 || id >= len(results) {
				return
			}
			result := results[id]
			box := object.(*fyne.Container)
			identity := "No published identity"
			if len(result.UserIDs) > 0 {
				identity = result.UserIDs[0]
			}
			box.Objects[0].(*widget.Label).SetText(identity)
			box.Objects[1].(*widget.Label).SetText(fmt.Sprintf("%s · %s %d", result.KeyID, result.Algorithm, result.Bits))
		},
	)
	selected := -1
	list.OnSelected = func(id widget.ListItemID) { selected = id }
	searchButton := widget.NewButtonWithIcon("Search", theme.SearchIcon(), func() {
		searchTerm := query.Text
		d.runAsync("Querying server...", func() error {
			var err error
			results, err = d.service.SearchKeyserver(context.Background(), searchTerm)
			return err
		}, func() {
			list.Refresh()
			d.setStatus(fmt.Sprintf("%d result(s)", len(results)))
		})
	})
	query.OnSubmitted = func(string) { searchButton.OnTapped() }
	importButton := widget.NewButtonWithIcon("Import selected", theme.DownloadIcon(), func() {
		if selected < 0 || selected >= len(results) {
			dialog.ShowError(errors.New("select a result"), d.window)
			return
		}
		identifier := results[selected].Fingerprint
		if identifier == "" {
			identifier = results[selected].KeyID
		}
		d.runAsync("Downloading key...", func() error {
			_, err := d.service.ImportFromKeyserver(context.Background(), identifier)
			return err
		}, func() {
			_ = d.reloadKeys()
			d.setStatus("Key imported from server")
		})
	})
	content := container.NewBorder(
		container.NewBorder(nil, nil, nil, searchButton, query),
		importButton, nil, nil,
		list,
	)
	sizedContent := container.NewStack(spacer(720, 520), content)
	dialog.NewCustom("Keyserver", "Close", sizedContent, d.window).Show()
}
