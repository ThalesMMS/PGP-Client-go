package ui

import (
	"context"
	"fmt"
	"os"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
)

func (d *Desktop) buildEncryptPage() fyne.CanvasObject {
	hasPendingFile := d.pendingFile != ""
	message := container.NewTabItemWithIcon("Message", theme.MailComposeIcon(), d.buildEncryptText())
	file := container.NewTabItemWithIcon("File", theme.FileIcon(), d.buildEncryptFile())
	tabs := container.NewAppTabs(message, file)
	tabs.SetTabLocation(container.TabLocationTop)
	if hasPendingFile {
		tabs.Select(file)
	}
	return container.NewBorder(container.NewPadded(heading("Encrypt")), nil, nil, nil, tabs)
}

func (d *Desktop) buildDecryptPage() fyne.CanvasObject {
	hasPendingFile := d.pendingFile != ""
	message := container.NewTabItemWithIcon("Message", theme.MailReplyIcon(), d.buildDecryptText())
	file := container.NewTabItemWithIcon("File", theme.FileIcon(), d.buildDecryptFile())
	tabs := container.NewAppTabs(message, file)
	tabs.SetTabLocation(container.TabLocationTop)
	if hasPendingFile {
		tabs.Select(file)
	}
	return container.NewBorder(container.NewPadded(heading("Decrypt")), nil, nil, nil, tabs)
}

func (d *Desktop) buildSignPage() fyne.CanvasObject {
	hasPendingFile := d.pendingFile != ""
	message := container.NewTabItemWithIcon("Message", theme.DocumentCreateIcon(), d.buildSignText())
	file := container.NewTabItemWithIcon("File", theme.FileIcon(), d.buildSignFile())
	tabs := container.NewAppTabs(message, file)
	tabs.SetTabLocation(container.TabLocationTop)
	if hasPendingFile {
		tabs.Select(file)
	}
	return container.NewBorder(container.NewPadded(heading("Sign")), nil, nil, nil, tabs)
}

func (d *Desktop) buildVerifyPage() fyne.CanvasObject {
	hasPendingFile := d.pendingFile != ""
	message := container.NewTabItemWithIcon("Message", theme.ConfirmIcon(), d.buildVerifyText())
	file := container.NewTabItemWithIcon("File", theme.FileIcon(), d.buildVerifyFile())
	tabs := container.NewAppTabs(message, file)
	tabs.SetTabLocation(container.TabLocationTop)
	if hasPendingFile {
		tabs.Select(file)
	}
	return container.NewBorder(container.NewPadded(heading("Verify")), nil, nil, nil, tabs)
}

func (d *Desktop) recipientSelector() (*widget.CheckGroup, map[string]string) {
	labels := make([]string, 0)
	lookup := make(map[string]string)
	for _, key := range d.keys {
		if !key.CanEncrypt || key.Revoked || key.Expired {
			continue
		}
		label := fmt.Sprintf("%s · %s", key.PrimaryIdentity(), d.visibleKeyID(key))
		labels = append(labels, label)
		lookup[label] = key.Fingerprint
	}
	group := widget.NewCheckGroup(labels, nil)
	return group, lookup
}

func selectedFingerprints(group *widget.CheckGroup, lookup map[string]string) []string {
	result := make([]string, 0, len(group.Selected))
	for _, label := range group.Selected {
		if fingerprint := lookup[label]; fingerprint != "" {
			result = append(result, fingerprint)
		}
	}
	return result
}

func (d *Desktop) signerSelector() (*widget.Select, map[string]string) {
	options := []string{"No signature"}
	lookup := map[string]string{"No signature": ""}
	for _, key := range d.keys {
		if !key.IsPrivate || key.Revoked || key.Expired || !key.CanVerify {
			continue
		}
		label := fmt.Sprintf("%s · %s", key.PrimaryIdentity(), d.visibleKeyID(key))
		options = append(options, label)
		lookup[label] = key.Fingerprint
	}
	selectWidget := widget.NewSelect(options, nil)
	selectWidget.SetSelected(options[0])
	return selectWidget, lookup
}

func (d *Desktop) privateKeySelector() (*widget.Select, map[string]string) {
	options := make([]string, 0)
	lookup := make(map[string]string)
	for _, key := range d.keys {
		if !key.IsPrivate || key.Revoked || key.Expired || !key.CanVerify {
			continue
		}
		label := fmt.Sprintf("%s · %s", key.PrimaryIdentity(), d.visibleKeyID(key))
		options = append(options, label)
		lookup[label] = key.Fingerprint
	}
	if len(options) == 0 {
		options = []string{"No secret keys available"}
		lookup[options[0]] = ""
	}
	selectWidget := widget.NewSelect(options, nil)
	selectWidget.SetSelected(options[0])
	return selectWidget, lookup
}

func (d *Desktop) visibleKeyID(key model.KeyInfo) string {
	if d.service.Settings().ShowFullKeyID {
		return key.KeyID
	}
	return key.ShortKeyID
}

func (d *Desktop) confirmRecipientTrust(fingerprints []string, proceed func()) {
	if proceed == nil {
		return
	}
	if !d.service.Settings().WarnOnUntrustedRecipient || len(fingerprints) == 0 {
		proceed()
		return
	}
	selected := make(map[string]struct{}, len(fingerprints))
	for _, fingerprint := range fingerprints {
		selected[fingerprint] = struct{}{}
	}
	var warnings []string
	for _, key := range d.keys {
		if _, ok := selected[key.Fingerprint]; !ok {
			continue
		}
		trusted := key.Metadata.Trust == model.TrustFull || key.Metadata.Trust == model.TrustUltimate
		if trusted && key.Metadata.Verified {
			continue
		}
		reasons := make([]string, 0, 2)
		if !key.Metadata.Verified {
			reasons = append(reasons, "fingerprint not verified")
		}
		if !trusted {
			reasons = append(reasons, "local trust: "+trustLabel(key.Metadata.Trust))
		}
		warnings = append(warnings, fmt.Sprintf("- %s - %s", key.PrimaryIdentity(), strings.Join(reasons, "; ")))
	}
	if len(warnings) == 0 {
		proceed()
		return
	}
	message := "Review recipients before encrypting:\n\n" + strings.Join(warnings, "\n") + "\n\nContinue anyway?"
	dialog.ShowConfirm("Recipients without confirmed trust", message, func(ok bool) {
		if ok {
			proceed()
		}
	}, d.window)
}

func recipientPanel(group *widget.CheckGroup) fyne.CanvasObject {
	if len(group.Options) == 0 {
		return card(statusBadge("No keys suitable for encryption", false), muted("Import the recipient public key or use password encryption."))
	}
	scroll := container.NewVScroll(group)
	scroll.SetMinSize(fyne.NewSize(380, 150))
	return card(widget.NewLabel("Recipients"), scroll)
}

func textEditor(placeHolder string) *widget.Entry {
	entry := widget.NewMultiLineEntry()
	entry.SetPlaceHolder(placeHolder)
	entry.Wrapping = fyne.TextWrapWord
	entry.SetMinRowsVisible(9)
	return entry
}

func outputActions(window fyne.Window, output *widget.Entry, defaultName string, mode os.FileMode) fyne.CanvasObject {
	copyButton := widget.NewButtonWithIcon("Copy", theme.ContentCopyIcon(), func() {
		window.Clipboard().SetContent(output.Text)
	})
	saveButton := widget.NewButtonWithIcon("Save...", theme.DocumentSaveIcon(), func() {
		d := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
			if err != nil {
				dialog.ShowError(err, window)
				return
			}
			if writer == nil {
				return
			}
			if err := writeURI(writer, []byte(output.Text), mode); err != nil {
				dialog.ShowError(err, window)
			}
		}, window)
		d.SetFileName(defaultName)
		d.Show()
	})
	return container.NewHBox(copyButton, saveButton)
}

func (d *Desktop) buildEncryptText() fyne.CanvasObject {
	recipients, recipientLookup := d.recipientSelector()
	signer, signerLookup := d.signerSelector()
	symmetric := widget.NewCheck("Encrypt with password instead of keys", nil)
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Message password")
	password.Disable()
	symmetric.OnChanged = func(checked bool) {
		if checked {
			password.Enable()
			recipients.Disable()
		} else {
			password.Disable()
			recipients.Enable()
		}
	}
	armor := widget.NewCheck("ASCII armor (required for text)", nil)
	armor.SetChecked(true)
	armor.Disable()
	compress := widget.NewCheck("Compress before encrypting", nil)
	compress.SetChecked(true)
	input := textEditor("Plaintext message")
	output := textEditor("The encrypted message will appear here")
	output.Disable()

	var encrypted []byte
	encryptButton := widget.NewButtonWithIcon("Encrypt", theme.LoginIcon(), func() {
		req := model.EncryptRequest{
			Plaintext:             []byte(input.Text),
			RecipientFingerprints: selectedFingerprints(recipients, recipientLookup),
			SignerFingerprint:     signerLookup[signer.Selected],
			Armor:                 armor.Checked,
			Compress:              compress.Checked,
			UTF8:                  true,
		}
		if symmetric.Checked {
			req.RecipientFingerprints = nil
			req.Password = []byte(password.Text)
		}
		start := func() {
			d.runPassphraseAware("Encrypting...", func(fingerprint string, passphrase []byte) error {
				if fingerprint == req.SignerFingerprint {
					req.SignerPassphrase = passphrase
				}
				var err error
				encrypted, err = d.service.Encrypt(req)
				return err
			}, func() {
				output.Enable()
				output.SetText(string(encrypted))
				output.Disable()
				d.setStatus("Message encrypted")
			})
		}
		if symmetric.Checked {
			start()
		} else {
			d.confirmRecipientTrust(req.RecipientFingerprints, start)
		}
	})
	encryptButton.Importance = widget.HighImportance

	left := container.NewVBox(
		recipientPanel(recipients),
		card(symmetric, password),
		card(widget.NewForm(widget.NewFormItem("Sign with", signer)), armor, compress),
	)
	right := container.NewVBox(
		section("Input", input),
		container.NewHBox(encryptButton),
		section("Output", outputActions(d.window, output, "message.asc", 0o644), output),
	)
	split := container.NewHSplit(container.NewVScroll(container.NewPadded(left)), container.NewVScroll(container.NewPadded(right)))
	split.Offset = 0.35
	return split
}

func (d *Desktop) buildEncryptFile() fyne.CanvasObject {
	recipients, recipientLookup := d.recipientSelector()
	signer, signerLookup := d.signerSelector()
	inputPath := widget.NewEntry()
	outputPath := widget.NewEntry()
	if d.pendingFile != "" {
		inputPath.SetText(d.pendingFile)
		d.pendingFile = ""
	}
	armor := widget.NewCheck("ASCII armor", nil)
	armor.SetChecked(d.service.Settings().DefaultArmor)
	compress := widget.NewCheck("Compress", nil)
	compress.SetChecked(true)
	symmetric := widget.NewCheck("Use password instead of recipients", nil)
	password := widget.NewPasswordEntry()
	password.Disable()
	symmetric.OnChanged = func(checked bool) {
		if checked {
			password.Enable()
			recipients.Disable()
		} else {
			password.Disable()
			recipients.Enable()
		}
	}
	updateOutput := func() {
		if strings.TrimSpace(inputPath.Text) == "" {
			return
		}
		outputPath.SetText(inputPath.Text + extensionForEncrypted(armor.Checked))
	}
	inputPath.OnChanged = func(string) {
		if strings.TrimSpace(outputPath.Text) == "" {
			updateOutput()
		}
	}
	armor.OnChanged = func(bool) { updateOutput() }
	if inputPath.Text != "" {
		updateOutput()
	}
	inputRow := filePickerRow(d.window, inputPath, false, "")
	outputRow := filePickerRow(d.window, outputPath, true, "encrypted.gpg")
	button := widget.NewButtonWithIcon("Encrypt file", theme.LoginIcon(), func() {
		inputFile := inputPath.Text
		outputFile := outputPath.Text
		req := model.EncryptRequest{
			RecipientFingerprints: selectedFingerprints(recipients, recipientLookup),
			SignerFingerprint:     signerLookup[signer.Selected],
			Armor:                 armor.Checked,
			Compress:              compress.Checked,
		}
		if symmetric.Checked {
			req.RecipientFingerprints = nil
			req.Password = []byte(password.Text)
		}
		start := func() {
			d.runPassphraseAware("Encrypting file...", func(fingerprint string, passphrase []byte) error {
				if fingerprint == req.SignerFingerprint {
					req.SignerPassphrase = passphrase
				}
				return d.service.EncryptFile(context.Background(), inputFile, outputFile, req)
			}, func() { d.setStatus("File encrypted: " + outputFile) })
		}
		if symmetric.Checked {
			start()
		} else {
			d.confirmRecipientTrust(req.RecipientFingerprints, start)
		}
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(
			widget.NewFormItem("File", inputRow),
			widget.NewFormItem("Destination", outputRow),
		)),
		recipientPanel(recipients),
		card(symmetric, password),
		card(widget.NewForm(widget.NewFormItem("Sign with", signer)), armor, compress),
		button,
	)
	return container.NewVScroll(container.NewPadded(content))
}

func (d *Desktop) buildDecryptText() fyne.CanvasObject {
	input := textEditor("Paste an ASCII-armored PGP message")
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Symmetric password, if applicable")
	output := textEditor("The decrypted text will appear here")
	output.Disable()
	verification := container.NewMax(muted("No verification performed"))
	var decrypted model.DecryptResult
	button := widget.NewButtonWithIcon("Decrypt", theme.LogoutIcon(), func() {
		ciphertext := []byte(input.Text)
		symmetricPassword := []byte(password.Text)
		passphrases := make(map[string][]byte)
		d.runPassphraseAware("Decrypting...", func(fingerprint string, passphrase []byte) error {
			if fingerprint != "" {
				passphrases[fingerprint] = passphrase
			}
			var err error
			decrypted, err = d.service.Decrypt(model.DecryptRequest{
				Ciphertext:  ciphertext,
				Passphrases: passphrases,
				Password:    symmetricPassword,
				UTF8:        true,
			})
			return err
		}, func() {
			output.Enable()
			output.SetText(string(decrypted.Plaintext))
			output.Disable()
			verification.Objects = []fyne.CanvasObject{decryptSignatureStatus(decrypted)}
			verification.Refresh()
			d.setStatus("Message decrypted")
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		section("PGP message", input),
		card(widget.NewForm(widget.NewFormItem("Symmetric password (optional)", password))),
		button,
		section("Result", verification, outputActions(d.window, output, "decrypted.txt", 0o600), output),
	)
	return container.NewVScroll(container.NewPadded(content))
}

func decryptSignatureStatus(result model.DecryptResult) fyne.CanvasObject {
	if !result.SignaturePresent {
		return statusBadge("Message has no embedded signature", false)
	}
	if result.SignatureValid {
		text := "Valid signature"
		if result.SignerKeyID != "" {
			text += " · " + result.SignerKeyID
		}
		return statusBadge(text, true)
	}
	return statusBadge("Signature not validated: "+result.SignatureError, false)
}

func (d *Desktop) buildDecryptFile() fyne.CanvasObject {
	inputPath := widget.NewEntry()
	outputPath := widget.NewEntry()
	if d.pendingFile != "" {
		inputPath.SetText(d.pendingFile)
		outputPath.SetText(suggestedDecryptedPath(d.pendingFile))
		d.pendingFile = ""
	}
	inputPath.OnChanged = func(value string) {
		if strings.TrimSpace(outputPath.Text) == "" {
			outputPath.SetText(suggestedDecryptedPath(value))
		}
	}
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Only for password-encrypted messages")
	status := container.NewMax(muted("The signature will be verified when present."))
	var decrypted model.DecryptResult
	button := widget.NewButtonWithIcon("Decrypt file", theme.LogoutIcon(), func() {
		inputFile := inputPath.Text
		outputFile := outputPath.Text
		symmetricPassword := []byte(password.Text)
		passphrases := make(map[string][]byte)
		d.runPassphraseAware("Decrypting file...", func(fingerprint string, passphrase []byte) error {
			if fingerprint != "" {
				passphrases[fingerprint] = passphrase
			}
			var err error
			decrypted, err = d.service.DecryptFile(context.Background(), inputFile, outputFile, model.DecryptRequest{
				Passphrases: passphrases,
				Password:    symmetricPassword,
			})
			return err
		}, func() {
			status.Objects = []fyne.CanvasObject{decryptSignatureStatus(decrypted)}
			status.Refresh()
			d.setStatus("File decrypted: " + outputFile)
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(
			widget.NewFormItem("PGP file", filePickerRow(d.window, inputPath, false, "")),
			widget.NewFormItem("Destination", filePickerRow(d.window, outputPath, true, "decrypted.bin")),
			widget.NewFormItem("Symmetric password", password),
		)),
		status,
		button,
	)
	return container.NewVScroll(container.NewPadded(content))
}

func signatureModeSelect() (*widget.Select, map[string]model.SignatureMode) {
	lookup := map[string]model.SignatureMode{
		"Detached signature": model.SignatureDetached,
		"Signed message":     model.SignatureInline,
		"Cleartext signed":   model.SignatureCleartext,
	}
	selectWidget := widget.NewSelect([]string{"Detached signature", "Signed message", "Cleartext signed"}, nil)
	selectWidget.SetSelected("Detached signature")
	return selectWidget, lookup
}

func (d *Desktop) buildSignText() fyne.CanvasObject {
	signer, signerLookup := d.privateKeySelector()
	mode, modeLookup := signatureModeSelect()
	armor := widget.NewCheck("ASCII armor (required for text)", nil)
	armor.SetChecked(true)
	armor.Disable()
	input := textEditor("Text or message to sign")
	output := textEditor("The signature will appear here")
	output.Disable()
	var signature []byte
	button := widget.NewButtonWithIcon("Sign", theme.DocumentCreateIcon(), func() {
		fingerprint := signerLookup[signer.Selected]
		if fingerprint == "" {
			dialog.ShowError(model.ErrNoPrivateKey, d.window)
			return
		}
		req := model.SignRequest{
			Data:              []byte(input.Text),
			SignerFingerprint: fingerprint,
			Mode:              modeLookup[mode.Selected],
			Armor:             armor.Checked,
			UTF8:              true,
		}
		d.runPassphraseAware("Signing...", func(requiredFingerprint string, passphrase []byte) error {
			if requiredFingerprint == fingerprint {
				req.Passphrase = passphrase
			}
			var err error
			signature, err = d.service.Sign(req)
			return err
		}, func() {
			output.Enable()
			output.SetText(string(signature))
			output.Disable()
			d.setStatus("Signature created")
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(
			widget.NewFormItem("Secret key", signer),
			widget.NewFormItem("Format", mode),
		), armor),
		section("Content", input),
		button,
		section("Signature", outputActions(d.window, output, "signature.asc", 0o644), output),
	)
	return container.NewVScroll(container.NewPadded(content))
}

func (d *Desktop) buildSignFile() fyne.CanvasObject {
	signer, signerLookup := d.privateKeySelector()
	mode, modeLookup := signatureModeSelect()
	armor := widget.NewCheck("ASCII armor", nil)
	armor.SetChecked(true)
	inputPath := widget.NewEntry()
	outputPath := widget.NewEntry()
	if d.pendingFile != "" {
		inputPath.SetText(d.pendingFile)
		d.pendingFile = ""
	}
	updateOutput := func() {
		if inputPath.Text == "" {
			return
		}
		suffix := ".sig"
		if armor.Checked {
			suffix = ".asc"
		}
		if modeLookup[mode.Selected] == model.SignatureInline {
			suffix = ".signed.pgp"
		} else if modeLookup[mode.Selected] == model.SignatureCleartext {
			suffix = ".signed.asc"
		}
		outputPath.SetText(inputPath.Text + suffix)
	}
	inputPath.OnChanged = func(string) {
		if outputPath.Text == "" {
			updateOutput()
		}
	}
	mode.OnChanged = func(string) { updateOutput() }
	armor.OnChanged = func(bool) { updateOutput() }
	if inputPath.Text != "" {
		updateOutput()
	}
	button := widget.NewButtonWithIcon("Sign file", theme.DocumentCreateIcon(), func() {
		fingerprint := signerLookup[signer.Selected]
		if fingerprint == "" {
			dialog.ShowError(model.ErrNoPrivateKey, d.window)
			return
		}
		inputFile := inputPath.Text
		outputFile := outputPath.Text
		req := model.SignRequest{
			SignerFingerprint: fingerprint,
			Mode:              modeLookup[mode.Selected],
			Armor:             armor.Checked,
		}
		d.runPassphraseAware("Signing file...", func(requiredFingerprint string, passphrase []byte) error {
			if requiredFingerprint == fingerprint {
				req.Passphrase = passphrase
			}
			return d.service.SignFile(context.Background(), inputFile, outputFile, req)
		}, func() { d.setStatus("File signed: " + outputFile) })
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(
			widget.NewFormItem("File", filePickerRow(d.window, inputPath, false, "")),
			widget.NewFormItem("Destination", filePickerRow(d.window, outputPath, true, "signature.asc")),
			widget.NewFormItem("Secret key", signer),
			widget.NewFormItem("Format", mode),
		), armor),
		button,
	)
	return container.NewVScroll(container.NewPadded(content))
}

func (d *Desktop) buildVerifyText() fyne.CanvasObject {
	mode, modeLookup := signatureModeSelect()
	data := textEditor("Original data (required for detached signatures)")
	signature := textEditor("Paste the detached signature or signed message")
	output := textEditor("Content recovered from an inline/cleartext signature")
	output.Disable()
	status := container.NewMax(muted("No verification performed"))
	mode.OnChanged = func(value string) {
		if modeLookup[value] == model.SignatureDetached {
			data.Enable()
		} else {
			data.Disable()
		}
	}
	var verified model.VerifyResult
	button := widget.NewButtonWithIcon("Verify", theme.ConfirmIcon(), func() {
		req := model.VerifyRequest{
			Data:      []byte(data.Text),
			Signature: []byte(signature.Text),
			Mode:      modeLookup[mode.Selected],
			UTF8:      true,
		}
		d.runAsync("Verifying signature...", func() error {
			var err error
			verified, err = d.service.Verify(req)
			return err
		}, func() {
			status.Objects = []fyne.CanvasObject{verifyStatus(verified)}
			status.Refresh()
			output.Enable()
			output.SetText(string(verified.Data))
			output.Disable()
			if verified.Valid {
				d.setStatus("Valid signature")
			} else {
				d.setStatus("Invalid or unverifiable signature")
			}
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(widget.NewFormItem("Format", mode))),
		section("Data", data),
		section("Signature or signed message", signature),
		button,
		section("Result", status, outputActions(d.window, output, "verified.txt", 0o644), output),
	)
	return container.NewVScroll(container.NewPadded(content))
}

func verifyStatus(result model.VerifyResult) fyne.CanvasObject {
	if result.Valid {
		identity := strings.TrimSpace(result.SignerName + " <" + result.SignerEmail + ">")
		if identity == "<>" || identity == "" {
			identity = result.SignerKeyID
		}
		return statusBadge("Valid signature - "+identity, true)
	}
	message := result.SignatureErr
	if message == "" {
		message = "invalid signature or missing public key"
	}
	return statusBadge(message, false)
}

func (d *Desktop) buildVerifyFile() fyne.CanvasObject {
	mode, modeLookup := signatureModeSelect()
	dataPath := widget.NewEntry()
	signaturePath := widget.NewEntry()
	outputPath := widget.NewEntry()
	if d.pendingFile != "" {
		lower := strings.ToLower(d.pendingFile)
		if strings.HasSuffix(lower, ".sig") || strings.HasSuffix(lower, ".asc") || strings.HasSuffix(lower, ".pgp") {
			signaturePath.SetText(d.pendingFile)
		} else {
			dataPath.SetText(d.pendingFile)
		}
		d.pendingFile = ""
	}
	status := container.NewMax(muted("No verification performed"))
	mode.OnChanged = func(value string) {
		if modeLookup[value] == model.SignatureDetached {
			dataPath.Enable()
		} else {
			dataPath.Disable()
		}
	}
	var verified model.VerifyResult
	button := widget.NewButtonWithIcon("Verify file", theme.ConfirmIcon(), func() {
		dataFile := dataPath.Text
		signatureFile := signaturePath.Text
		outputFile := outputPath.Text
		req := model.VerifyRequest{Mode: modeLookup[mode.Selected]}
		d.runAsync("Verifying file...", func() error {
			var err error
			verified, err = d.service.VerifyFile(context.Background(), dataFile, signatureFile, outputFile, req)
			return err
		}, func() {
			status.Objects = []fyne.CanvasObject{verifyStatus(verified)}
			status.Refresh()
			if verified.Valid {
				d.setStatus("Valid signature")
			} else {
				d.setStatus("Signature not validated")
			}
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(
			widget.NewFormItem("Format", mode),
			widget.NewFormItem("Original data", filePickerRow(d.window, dataPath, false, "")),
			widget.NewFormItem("Signature/message", filePickerRow(d.window, signaturePath, false, "")),
			widget.NewFormItem("Verified output (inline)", filePickerRow(d.window, outputPath, true, "verified.bin")),
		)),
		status,
		button,
	)
	return container.NewVScroll(container.NewPadded(content))
}
