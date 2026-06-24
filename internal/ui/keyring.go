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
		return center(widget.NewLabel("Falha ao carregar chaves: " + err.Error()))
	}

	search := widget.NewEntry()
	search.SetPlaceHolder("Pesquisar chaves…")
	filter := widget.NewSelect([]string{"Todas", "Secretas", "Públicas", "Inválidas"}, nil)
	filter.SetSelected("Todas")
	sortBy := widget.NewSelect([]string{"Nome", "Criação", "Key ID"}, nil)
	sortBy.SetSelected("Nome")

	filtered := append([]model.KeyInfo(nil), d.keys...)
	selectedFingerprint := ""
	details := container.NewMax(center(muted("Selecione uma chave")))

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
			case "Secretas":
				if !key.IsPrivate {
					continue
				}
			case "Públicas":
				if key.IsPrivate {
					continue
				}
			case "Inválidas":
				if !key.Expired && !key.Revoked {
					continue
				}
			}
			filtered = append(filtered, key)
		}
		sort.SliceStable(filtered, func(i, j int) bool {
			switch sortBy.Selected {
			case "Criação":
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
			name := widget.NewLabelWithStyle("Nome", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
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
				status += " · REVOGADA"
			} else if key.Expired {
				status += " · EXPIRADA"
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
		widget.NewButtonWithIcon("Nova", theme.ContentAddIcon(), d.showGenerateKey),
		widget.NewButtonWithIcon("Importar", theme.DownloadIcon(), d.importKeyDialog),
		widget.NewButtonWithIcon("Servidor", theme.SearchIcon(), d.showKeyserverSearch),
		layout.NewSpacer(),
		widget.NewButtonWithIcon("Atualizar", theme.ViewRefreshIcon(), func() {
			if err := d.reloadKeys(); err != nil {
				dialog.ShowError(err, d.window)
				return
			}
			d.showPage(pageKeyring)
		}),
	)
	controls := container.NewGridWithColumns(2, filter, sortBy)
	middle := container.NewBorder(
		container.NewVBox(container.NewPadded(heading("Chaveiro")), toolbar, controls, search, canvas.NewLine(theme.Color(theme.ColorNameSeparator))),
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
			center(heading("Nenhuma chave")),
			center(muted("Gere uma chave RSA ou importe um certificado OpenPGP.")),
			center(container.NewHBox(
				widget.NewButtonWithIcon("Gerar chave", theme.ContentAddIcon(), d.showGenerateKey),
				widget.NewButtonWithIcon("Importar", theme.DownloadIcon(), d.importKeyDialog),
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

	exportPublic := widget.NewButtonWithIcon("Pública", theme.UploadIcon(), func() { d.exportKeyDialog(info, false) })
	exportPrivate := widget.NewButtonWithIcon("Privada", theme.WarningIcon(), func() { d.exportKeyDialog(info, true) })
	if !info.IsPrivate {
		exportPrivate.Disable()
	}
	deleteButton := widget.NewButtonWithIcon("Excluir", theme.DeleteIcon(), func() { d.deleteKeyDialog(info) })
	deleteButton.Importance = widget.DangerImportance
	toolbar := container.NewHBox(exportPublic, exportPrivate, layout.NewSpacer(), deleteButton)

	expires := "Nunca"
	if info.ExpiresAt != nil {
		expires = formatDate(*info.ExpiresAt)
	}
	facts := container.NewGridWithColumns(2,
		card(labeledValue("Key ID", info.KeyID), labeledValue("Criada", formatDate(info.CreatedAt))),
		card(labeledValue("Algoritmo", fmt.Sprintf("%s %d", info.Algorithm, info.Bits)), labeledValue("Expira", expires)),
	)

	fingerprintEntry := widget.NewEntry()
	fingerprintEntry.SetText(formatFingerprint(info.Fingerprint))
	fingerprintEntry.Disable()
	copyFingerprint := widget.NewButtonWithIcon("Copiar", theme.ContentCopyIcon(), func() {
		d.window.Clipboard().SetContent(info.Fingerprint)
		d.setStatus("Fingerprint copiado")
	})
	compare := widget.NewButtonWithIcon("Comparar", theme.SearchReplaceIcon(), func() { d.showFingerprintComparison(info) })
	fingerprint := section("Fingerprint", container.NewBorder(nil, nil, nil, container.NewHBox(copyFingerprint, compare), fingerprintEntry))

	uids := container.NewVBox()
	for _, uid := range info.UserIDs {
		uids.Add(card(widget.NewLabel(uid)))
	}
	if len(info.UserIDs) == 0 {
		uids.Add(muted("Nenhuma identidade disponível"))
	}

	trustSelect := widget.NewSelect([]string{
		"Desconhecida", "Nunca confiar", "Confiança marginal", "Confiança plena", "Confiança definitiva",
	}, func(value string) {
		if err := d.service.SetTrust(info.Fingerprint, trustFromLabel(value)); err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		d.setStatus("Nível de confiança atualizado")
	})
	trustSelect.SetSelected(trustLabel(info.Metadata.Trust))
	verified := widget.NewCheck("Fingerprint verificado fora de banda", func(checked bool) {
		method := "comparação manual"
		if err := d.service.MarkVerified(info.Fingerprint, method, checked); err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		d.setStatus("Estado de verificação atualizado")
	})
	verified.SetChecked(info.Metadata.Verified)
	trust := section("Confiança local", trustSelect, verified)

	statusItems := []fyne.CanvasObject{}
	if info.Revoked {
		statusItems = append(statusItems, statusBadge("Esta chave foi revogada", false))
	}
	if info.Expired {
		statusItems = append(statusItems, statusBadge("Esta chave expirou", false))
	}
	if !info.Revoked && !info.Expired {
		statusItems = append(statusItems, statusBadge("Certificado utilizável", true))
	}
	statusItems = append(statusItems,
		labeledValue("Criptografia", boolText(info.CanEncrypt)),
		labeledValue("Verificação", boolText(info.CanVerify)),
	)
	status := section("Estado", statusItems...)

	serverButton := widget.NewButtonWithIcon("Publicar no servidor", theme.UploadIcon(), func() {
		d.runAsync("Publicando chave pública…", func() error {
			return d.service.UploadToKeyserver(context.Background(), info.Fingerprint)
		}, func() { d.setStatus("Chave pública enviada ao servidor") })
	})
	revokeButton := widget.NewButtonWithIcon("Revogar chave…", theme.WarningIcon(), func() { d.showRevokeKey(info) })
	revokeButton.Importance = widget.DangerImportance
	if !info.IsPrivate || info.Revoked {
		revokeButton.Disable()
	}
	actions := section("Ações avançadas", container.NewHBox(serverButton, revokeButton))

	content := container.NewVBox(
		container.NewPadded(title),
		toolbar,
		canvas.NewLine(theme.Color(theme.ColorNameSeparator)),
		facts,
		fingerprint,
		section("Identidades", uids),
		trust,
		status,
		actions,
		spacer(1, 24),
	)
	return container.NewVScroll(container.NewPadded(content))
}

func boolText(value bool) string {
	if value {
		return "Disponível"
	}
	return "Indisponível"
}

func (d *Desktop) showGenerateKey() {
	settings := d.service.Settings()
	name := widget.NewEntry()
	name.SetPlaceHolder("Nome completo")
	email := widget.NewEntry()
	email.SetPlaceHolder("nome@exemplo.com")
	comment := widget.NewEntry()
	comment.SetPlaceHolder("Opcional")
	bits := widget.NewSelect([]string{"2048", "3072", "4096"}, nil)
	bits.SetSelected(strconv.Itoa(settings.DefaultKeyBits))
	expiry := widget.NewEntry()
	expiry.SetText(strconv.Itoa(settings.DefaultExpiryDays))
	passphrase := widget.NewPasswordEntry()
	passphrase.SetPlaceHolder("Recomendado")
	confirm := widget.NewPasswordEntry()
	confirm.SetPlaceHolder("Repita a frase secreta")
	remember := widget.NewCheck("Guardar no cofre do sistema", nil)
	remember.SetChecked(settings.RememberPassphrases)
	strength := muted("Use uma frase longa e exclusiva.")
	passphrase.OnChanged = func(value string) {
		switch {
		case len(value) == 0:
			strength.SetText("Sem frase secreta: a chave será gravada sem proteção local.")
		case len(value) < 12:
			strength.SetText("Frase curta; prefira pelo menos 12 caracteres.")
		case len(value) < 20:
			strength.SetText("Força razoável; uma frase maior é preferível.")
		default:
			strength.SetText("Frase longa.")
		}
	}
	form := widget.NewForm(
		widget.NewFormItem("Nome", name),
		widget.NewFormItem("E-mail", email),
		widget.NewFormItem("Comentário", comment),
		widget.NewFormItem("RSA", bits),
		widget.NewFormItem("Validade (dias, 0 = nunca)", expiry),
		widget.NewFormItem("Frase secreta", passphrase),
		widget.NewFormItem("Confirmar", confirm),
	)
	content := container.NewVBox(form, strength, remember)
	prompt := dialog.NewCustomConfirm("Gerar nova chave", "Gerar", "Cancelar", content, func(ok bool) {
		if !ok {
			return
		}
		if passphrase.Text != confirm.Text {
			dialog.ShowError(errors.New("as frases secretas não coincidem"), d.window)
			return
		}
		keyBits, _ := strconv.Atoi(bits.Selected)
		expiryDays, err := strconv.Atoi(strings.TrimSpace(expiry.Text))
		if err != nil || expiryDays < 0 {
			dialog.ShowError(errors.New("validade inválida"), d.window)
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
		d.runAsync("Gerando chave RSA…", func() error {
			_, err := d.service.GenerateKey(req)
			return err
		}, func() {
			_ = d.reloadKeys()
			d.showPage(pageKeyring)
			d.setStatus("Nova chave criada")
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
		d.runAsync("Importando chave…", func() error {
			_, err := d.service.Import(data)
			return err
		}, func() {
			_ = d.reloadKeys()
			d.showPage(pageKeyring)
			d.setStatus("Chave importada")
		})
	}, d.window).Show()
}

func (d *Desktop) exportKeyDialog(info model.KeyInfo, private bool) {
	if private && !info.IsPrivate {
		dialog.ShowError(model.ErrNoPrivateKey, d.window)
		return
	}
	if private {
		dialog.ShowConfirm("Exportar chave secreta", "O arquivo conterá material criptográfico privado. Armazene-o em local seguro.", func(ok bool) {
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
		d.setStatus("Chave exportada")
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
		d.setStatus("Chave excluída")
	}
	if d.service.Settings().ConfirmBeforeDelete {
		dialog.ShowConfirm("Excluir chave", "Excluir "+info.PrimaryIdentity()+" do chaveiro local? Esta ação não pode ser desfeita.", func(ok bool) {
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
	entry.SetPlaceHolder("Cole o fingerprint recebido por um canal confiável")
	result := muted("A comparação ignora espaços e caixa.")
	compare := func() {
		expected := strings.ReplaceAll(strings.ToUpper(info.Fingerprint), " ", "")
		actual := strings.ReplaceAll(strings.ToUpper(entry.Text), " ", "")
		if actual == "" {
			result.SetText("Informe um fingerprint.")
			return
		}
		if actual == expected {
			result.SetText("Correspondência exata.")
			_ = d.service.MarkVerified(info.Fingerprint, "comparação manual", true)
		} else {
			result.SetText("Não corresponde. Não confie nesta chave.")
		}
	}
	entry.OnChanged = func(string) { compare() }
	content := container.NewVBox(
		widget.NewLabel("Fingerprint local:"),
		card(widget.NewLabel(formatFingerprint(info.Fingerprint))),
		widget.NewLabel("Fingerprint externo:"), entry, result,
	)
	prompt := dialog.NewCustom("Comparar fingerprint", "Fechar", content, d.window)
	prompt.Resize(fyne.NewSize(620, 360))
	prompt.Show()
}

func (d *Desktop) showRevokeKey(info model.KeyInfo) {
	reason := widget.NewSelect([]string{"Sem motivo", "Substituída", "Comprometida", "Aposentada"}, nil)
	reason.SetSelected("Sem motivo")
	details := widget.NewMultiLineEntry()
	details.SetPlaceHolder("Motivo opcional")
	passphrase := widget.NewPasswordEntry()
	content := container.NewVBox(
		widget.NewLabel("A revogação será incorporada à chave local e exportada com o certificado."),
		widget.NewForm(
			widget.NewFormItem("Motivo", reason),
			widget.NewFormItem("Descrição", details),
			widget.NewFormItem("Frase secreta", passphrase),
		),
	)
	prompt := dialog.NewCustomConfirm("Revogar chave", "Revogar", "Cancelar", content, func(ok bool) {
		if !ok {
			return
		}
		code := packet.NoReason
		switch reason.Selected {
		case "Substituída":
			code = packet.KeySuperseded
		case "Comprometida":
			code = packet.KeyCompromised
		case "Aposentada":
			code = packet.KeyRetired
		}
		secret := []byte(passphrase.Text)
		description := details.Text
		passphrase.SetText("")
		d.runAsync("Revogando chave…", func() error {
			return d.service.RevokeKey(info.Fingerprint, secret, code, description)
		}, func() {
			_ = d.reloadKeys()
			d.showPage(pageKeyring)
			d.setStatus("Chave revogada")
		})
	}, d.window)
	prompt.Resize(fyne.NewSize(560, 360))
	prompt.Show()
}

func (d *Desktop) showBackup() {
	password := widget.NewPasswordEntry()
	confirm := widget.NewPasswordEntry()
	content := widget.NewForm(
		widget.NewFormItem("Senha do backup", password),
		widget.NewFormItem("Confirmar", confirm),
	)
	prompt := dialog.NewCustomConfirm("Backup criptografado", "Continuar", "Cancelar", content, func(ok bool) {
		if !ok {
			return
		}
		if password.Text != confirm.Text {
			dialog.ShowError(errors.New("as senhas não coincidem"), d.window)
			return
		}
		secret := []byte(password.Text)
		password.SetText("")
		confirm.SetText("")
		var archive []byte
		d.runAsync("Criando backup…", func() error {
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
					dialog.ShowError(fmt.Errorf("backup salvo, mas não foi possível atualizar o lembrete: %w", err), d.window)
					return
				}
				d.setStatus("Backup criado")
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
		restoreSettings := widget.NewCheck("Restaurar também as preferências", nil)
		content := container.NewVBox(password, restoreSettings)
		prompt := dialog.NewCustomConfirm("Restaurar backup", "Restaurar", "Cancelar", content, func(ok bool) {
			if !ok {
				return
			}
			secret := []byte(password.Text)
			includeSettings := restoreSettings.Checked
			password.SetText("")
			d.runAsync("Restaurando backup…", func() error {
				_, err := d.service.RestoreBackup(archive, secret, includeSettings)
				return err
			}, func() {
				_ = d.reloadKeys()
				d.showPage(pageKeyring)
				d.setStatus("Backup restaurado")
			})
		}, d.window)
		prompt.Show()
	}, d.window).Show()
}

func (d *Desktop) showKeyserverSearch() {
	query := widget.NewEntry()
	query.SetPlaceHolder("E-mail, fingerprint ou Key ID")
	results := []model.KeyserverResult{}
	list := widget.NewList(
		func() int { return len(results) },
		func() fyne.CanvasObject {
			return container.NewVBox(
				widget.NewLabelWithStyle("Identidade", fyne.TextAlignLeading, fyne.TextStyle{Bold: true}),
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
			identity := "Sem identidade publicada"
			if len(result.UserIDs) > 0 {
				identity = result.UserIDs[0]
			}
			box.Objects[0].(*widget.Label).SetText(identity)
			box.Objects[1].(*widget.Label).SetText(fmt.Sprintf("%s · %s %d", result.KeyID, result.Algorithm, result.Bits))
		},
	)
	selected := -1
	list.OnSelected = func(id widget.ListItemID) { selected = id }
	searchButton := widget.NewButtonWithIcon("Pesquisar", theme.SearchIcon(), func() {
		searchTerm := query.Text
		d.runAsync("Consultando servidor…", func() error {
			var err error
			results, err = d.service.SearchKeyserver(context.Background(), searchTerm)
			return err
		}, func() {
			list.Refresh()
			d.setStatus(fmt.Sprintf("%d resultado(s)", len(results)))
		})
	})
	query.OnSubmitted = func(string) { searchButton.OnTapped() }
	importButton := widget.NewButtonWithIcon("Importar selecionada", theme.DownloadIcon(), func() {
		if selected < 0 || selected >= len(results) {
			dialog.ShowError(errors.New("selecione um resultado"), d.window)
			return
		}
		identifier := results[selected].Fingerprint
		if identifier == "" {
			identifier = results[selected].KeyID
		}
		d.runAsync("Baixando chave…", func() error {
			_, err := d.service.ImportFromKeyserver(context.Background(), identifier)
			return err
		}, func() {
			_ = d.reloadKeys()
			d.setStatus("Chave importada do servidor")
		})
	})
	content := container.NewBorder(
		container.NewBorder(nil, nil, nil, searchButton, query),
		importButton, nil, nil,
		list,
	)
	sizedContent := container.NewStack(spacer(720, 520), content)
	dialog.NewCustom("Servidor de chaves", "Fechar", sizedContent, d.window).Show()
}
