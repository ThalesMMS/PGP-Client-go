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
	message := container.NewTabItemWithIcon("Mensagem", theme.MailComposeIcon(), d.buildEncryptText())
	file := container.NewTabItemWithIcon("Arquivo", theme.FileIcon(), d.buildEncryptFile())
	tabs := container.NewAppTabs(message, file)
	tabs.SetTabLocation(container.TabLocationTop)
	if hasPendingFile {
		tabs.Select(file)
	}
	return container.NewBorder(container.NewPadded(heading("Criptografar")), nil, nil, nil, tabs)
}

func (d *Desktop) buildDecryptPage() fyne.CanvasObject {
	hasPendingFile := d.pendingFile != ""
	message := container.NewTabItemWithIcon("Mensagem", theme.MailReplyIcon(), d.buildDecryptText())
	file := container.NewTabItemWithIcon("Arquivo", theme.FileIcon(), d.buildDecryptFile())
	tabs := container.NewAppTabs(message, file)
	tabs.SetTabLocation(container.TabLocationTop)
	if hasPendingFile {
		tabs.Select(file)
	}
	return container.NewBorder(container.NewPadded(heading("Descriptografar")), nil, nil, nil, tabs)
}

func (d *Desktop) buildSignPage() fyne.CanvasObject {
	hasPendingFile := d.pendingFile != ""
	message := container.NewTabItemWithIcon("Mensagem", theme.DocumentCreateIcon(), d.buildSignText())
	file := container.NewTabItemWithIcon("Arquivo", theme.FileIcon(), d.buildSignFile())
	tabs := container.NewAppTabs(message, file)
	tabs.SetTabLocation(container.TabLocationTop)
	if hasPendingFile {
		tabs.Select(file)
	}
	return container.NewBorder(container.NewPadded(heading("Assinar")), nil, nil, nil, tabs)
}

func (d *Desktop) buildVerifyPage() fyne.CanvasObject {
	hasPendingFile := d.pendingFile != ""
	message := container.NewTabItemWithIcon("Mensagem", theme.ConfirmIcon(), d.buildVerifyText())
	file := container.NewTabItemWithIcon("Arquivo", theme.FileIcon(), d.buildVerifyFile())
	tabs := container.NewAppTabs(message, file)
	tabs.SetTabLocation(container.TabLocationTop)
	if hasPendingFile {
		tabs.Select(file)
	}
	return container.NewBorder(container.NewPadded(heading("Verificar")), nil, nil, nil, tabs)
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
	options := []string{"Sem assinatura"}
	lookup := map[string]string{"Sem assinatura": ""}
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
		options = []string{"Nenhuma chave secreta disponível"}
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
			reasons = append(reasons, "fingerprint não verificado")
		}
		if !trusted {
			reasons = append(reasons, "confiança local: "+trustLabel(key.Metadata.Trust))
		}
		warnings = append(warnings, fmt.Sprintf("• %s — %s", key.PrimaryIdentity(), strings.Join(reasons, "; ")))
	}
	if len(warnings) == 0 {
		proceed()
		return
	}
	message := "Revise os destinatários antes de criptografar:\n\n" + strings.Join(warnings, "\n") + "\n\nContinuar mesmo assim?"
	dialog.ShowConfirm("Destinatários sem confiança confirmada", message, func(ok bool) {
		if ok {
			proceed()
		}
	}, d.window)
}

func recipientPanel(group *widget.CheckGroup) fyne.CanvasObject {
	if len(group.Options) == 0 {
		return card(statusBadge("Nenhuma chave apta para criptografia", false), muted("Importe a chave pública do destinatário ou use criptografia por senha."))
	}
	scroll := container.NewVScroll(group)
	scroll.SetMinSize(fyne.NewSize(380, 150))
	return card(widget.NewLabel("Destinatários"), scroll)
}

func textEditor(placeHolder string) *widget.Entry {
	entry := widget.NewMultiLineEntry()
	entry.SetPlaceHolder(placeHolder)
	entry.Wrapping = fyne.TextWrapWord
	entry.SetMinRowsVisible(9)
	return entry
}

func outputActions(window fyne.Window, output *widget.Entry, defaultName string, mode os.FileMode) fyne.CanvasObject {
	copyButton := widget.NewButtonWithIcon("Copiar", theme.ContentCopyIcon(), func() {
		window.Clipboard().SetContent(output.Text)
	})
	saveButton := widget.NewButtonWithIcon("Salvar…", theme.DocumentSaveIcon(), func() {
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
	symmetric := widget.NewCheck("Criptografar com senha em vez de chaves", nil)
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Senha da mensagem")
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
	armor := widget.NewCheck("ASCII armor (obrigatório para texto)", nil)
	armor.SetChecked(true)
	armor.Disable()
	compress := widget.NewCheck("Comprimir antes de criptografar", nil)
	compress.SetChecked(true)
	input := textEditor("Mensagem em texto claro")
	output := textEditor("A mensagem criptografada aparecerá aqui")
	output.Disable()

	var encrypted []byte
	encryptButton := widget.NewButtonWithIcon("Criptografar", theme.LoginIcon(), func() {
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
			d.runPassphraseAware("Criptografando…", func(fingerprint string, passphrase []byte) error {
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
				d.setStatus("Mensagem criptografada")
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
		card(widget.NewForm(widget.NewFormItem("Assinar com", signer)), armor, compress),
	)
	right := container.NewVBox(
		section("Entrada", input),
		container.NewHBox(encryptButton),
		section("Saída", outputActions(d.window, output, "message.asc", 0o644), output),
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
	compress := widget.NewCheck("Comprimir", nil)
	compress.SetChecked(true)
	symmetric := widget.NewCheck("Usar senha em vez de destinatários", nil)
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
	button := widget.NewButtonWithIcon("Criptografar arquivo", theme.LoginIcon(), func() {
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
			d.runPassphraseAware("Criptografando arquivo…", func(fingerprint string, passphrase []byte) error {
				if fingerprint == req.SignerFingerprint {
					req.SignerPassphrase = passphrase
				}
				return d.service.EncryptFile(context.Background(), inputFile, outputFile, req)
			}, func() { d.setStatus("Arquivo criptografado: " + outputFile) })
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
			widget.NewFormItem("Arquivo", inputRow),
			widget.NewFormItem("Destino", outputRow),
		)),
		recipientPanel(recipients),
		card(symmetric, password),
		card(widget.NewForm(widget.NewFormItem("Assinar com", signer)), armor, compress),
		button,
	)
	return container.NewVScroll(container.NewPadded(content))
}

func (d *Desktop) buildDecryptText() fyne.CanvasObject {
	input := textEditor("Cole uma mensagem PGP ASCII-armored")
	password := widget.NewPasswordEntry()
	password.SetPlaceHolder("Senha simétrica, se aplicável")
	output := textEditor("O texto descriptografado aparecerá aqui")
	output.Disable()
	verification := container.NewMax(muted("Nenhuma verificação executada"))
	var decrypted model.DecryptResult
	button := widget.NewButtonWithIcon("Descriptografar", theme.LogoutIcon(), func() {
		ciphertext := []byte(input.Text)
		symmetricPassword := []byte(password.Text)
		passphrases := make(map[string][]byte)
		d.runPassphraseAware("Descriptografando…", func(fingerprint string, passphrase []byte) error {
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
			d.setStatus("Mensagem descriptografada")
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		section("Mensagem PGP", input),
		card(widget.NewForm(widget.NewFormItem("Senha simétrica (opcional)", password))),
		button,
		section("Resultado", verification, outputActions(d.window, output, "decrypted.txt", 0o600), output),
	)
	return container.NewVScroll(container.NewPadded(content))
}

func decryptSignatureStatus(result model.DecryptResult) fyne.CanvasObject {
	if !result.SignaturePresent {
		return statusBadge("Mensagem sem assinatura embutida", false)
	}
	if result.SignatureValid {
		text := "Assinatura válida"
		if result.SignerKeyID != "" {
			text += " · " + result.SignerKeyID
		}
		return statusBadge(text, true)
	}
	return statusBadge("Assinatura não validada: "+result.SignatureError, false)
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
	password.SetPlaceHolder("Somente para mensagens criptografadas por senha")
	status := container.NewMax(muted("A assinatura, quando presente, será verificada."))
	var decrypted model.DecryptResult
	button := widget.NewButtonWithIcon("Descriptografar arquivo", theme.LogoutIcon(), func() {
		inputFile := inputPath.Text
		outputFile := outputPath.Text
		symmetricPassword := []byte(password.Text)
		passphrases := make(map[string][]byte)
		d.runPassphraseAware("Descriptografando arquivo…", func(fingerprint string, passphrase []byte) error {
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
			d.setStatus("Arquivo descriptografado: " + outputFile)
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(
			widget.NewFormItem("Arquivo PGP", filePickerRow(d.window, inputPath, false, "")),
			widget.NewFormItem("Destino", filePickerRow(d.window, outputPath, true, "decrypted.bin")),
			widget.NewFormItem("Senha simétrica", password),
		)),
		status,
		button,
	)
	return container.NewVScroll(container.NewPadded(content))
}

func signatureModeSelect() (*widget.Select, map[string]model.SignatureMode) {
	lookup := map[string]model.SignatureMode{
		"Assinatura destacada": model.SignatureDetached,
		"Mensagem assinada":    model.SignatureInline,
		"Texto claro assinado": model.SignatureCleartext,
	}
	selectWidget := widget.NewSelect([]string{"Assinatura destacada", "Mensagem assinada", "Texto claro assinado"}, nil)
	selectWidget.SetSelected("Assinatura destacada")
	return selectWidget, lookup
}

func (d *Desktop) buildSignText() fyne.CanvasObject {
	signer, signerLookup := d.privateKeySelector()
	mode, modeLookup := signatureModeSelect()
	armor := widget.NewCheck("ASCII armor (obrigatório para texto)", nil)
	armor.SetChecked(true)
	armor.Disable()
	input := textEditor("Texto ou mensagem a assinar")
	output := textEditor("A assinatura aparecerá aqui")
	output.Disable()
	var signature []byte
	button := widget.NewButtonWithIcon("Assinar", theme.DocumentCreateIcon(), func() {
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
		d.runPassphraseAware("Assinando…", func(requiredFingerprint string, passphrase []byte) error {
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
			d.setStatus("Assinatura criada")
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(
			widget.NewFormItem("Chave secreta", signer),
			widget.NewFormItem("Formato", mode),
		), armor),
		section("Conteúdo", input),
		button,
		section("Assinatura", outputActions(d.window, output, "signature.asc", 0o644), output),
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
	button := widget.NewButtonWithIcon("Assinar arquivo", theme.DocumentCreateIcon(), func() {
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
		d.runPassphraseAware("Assinando arquivo…", func(requiredFingerprint string, passphrase []byte) error {
			if requiredFingerprint == fingerprint {
				req.Passphrase = passphrase
			}
			return d.service.SignFile(context.Background(), inputFile, outputFile, req)
		}, func() { d.setStatus("Arquivo assinado: " + outputFile) })
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(
			widget.NewFormItem("Arquivo", filePickerRow(d.window, inputPath, false, "")),
			widget.NewFormItem("Destino", filePickerRow(d.window, outputPath, true, "signature.asc")),
			widget.NewFormItem("Chave secreta", signer),
			widget.NewFormItem("Formato", mode),
		), armor),
		button,
	)
	return container.NewVScroll(container.NewPadded(content))
}

func (d *Desktop) buildVerifyText() fyne.CanvasObject {
	mode, modeLookup := signatureModeSelect()
	data := textEditor("Dados originais (necessários para assinatura destacada)")
	signature := textEditor("Cole a assinatura destacada ou a mensagem assinada")
	output := textEditor("Conteúdo recuperado de uma assinatura inline/cleartext")
	output.Disable()
	status := container.NewMax(muted("Nenhuma verificação executada"))
	mode.OnChanged = func(value string) {
		if modeLookup[value] == model.SignatureDetached {
			data.Enable()
		} else {
			data.Disable()
		}
	}
	var verified model.VerifyResult
	button := widget.NewButtonWithIcon("Verificar", theme.ConfirmIcon(), func() {
		req := model.VerifyRequest{
			Data:      []byte(data.Text),
			Signature: []byte(signature.Text),
			Mode:      modeLookup[mode.Selected],
			UTF8:      true,
		}
		d.runAsync("Verificando assinatura…", func() error {
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
				d.setStatus("Assinatura válida")
			} else {
				d.setStatus("Assinatura inválida ou não verificável")
			}
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(widget.NewFormItem("Formato", mode))),
		section("Dados", data),
		section("Assinatura ou mensagem assinada", signature),
		button,
		section("Resultado", status, outputActions(d.window, output, "verified.txt", 0o644), output),
	)
	return container.NewVScroll(container.NewPadded(content))
}

func verifyStatus(result model.VerifyResult) fyne.CanvasObject {
	if result.Valid {
		identity := strings.TrimSpace(result.SignerName + " <" + result.SignerEmail + ">")
		if identity == "<>" || identity == "" {
			identity = result.SignerKeyID
		}
		return statusBadge("Assinatura válida · "+identity, true)
	}
	message := result.SignatureErr
	if message == "" {
		message = "assinatura inválida ou chave pública ausente"
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
	status := container.NewMax(muted("Nenhuma verificação executada"))
	mode.OnChanged = func(value string) {
		if modeLookup[value] == model.SignatureDetached {
			dataPath.Enable()
		} else {
			dataPath.Disable()
		}
	}
	var verified model.VerifyResult
	button := widget.NewButtonWithIcon("Verificar arquivo", theme.ConfirmIcon(), func() {
		dataFile := dataPath.Text
		signatureFile := signaturePath.Text
		outputFile := outputPath.Text
		req := model.VerifyRequest{Mode: modeLookup[mode.Selected]}
		d.runAsync("Verificando arquivo…", func() error {
			var err error
			verified, err = d.service.VerifyFile(context.Background(), dataFile, signatureFile, outputFile, req)
			return err
		}, func() {
			status.Objects = []fyne.CanvasObject{verifyStatus(verified)}
			status.Refresh()
			if verified.Valid {
				d.setStatus("Assinatura válida")
			} else {
				d.setStatus("Assinatura não validada")
			}
		})
	})
	button.Importance = widget.HighImportance
	content := container.NewVBox(
		card(widget.NewForm(
			widget.NewFormItem("Formato", mode),
			widget.NewFormItem("Dados originais", filePickerRow(d.window, dataPath, false, "")),
			widget.NewFormItem("Assinatura/mensagem", filePickerRow(d.window, signaturePath, false, "")),
			widget.NewFormItem("Saída verificada (inline)", filePickerRow(d.window, outputPath, true, "verified.bin")),
		)),
		status,
		button,
	)
	return container.NewVScroll(container.NewPadded(content))
}
