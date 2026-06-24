package ui

import (
	"errors"
	"strconv"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
)

func (d *Desktop) showSettings() {
	current := d.service.Settings()
	armor := widget.NewCheck("Usar ASCII armor por padrão", nil)
	armor.SetChecked(current.DefaultArmor)
	bits := widget.NewSelect([]string{"2048", "3072", "4096"}, nil)
	bits.SetSelected(strconv.Itoa(current.DefaultKeyBits))
	expiry := widget.NewEntry()
	expiry.SetText(strconv.Itoa(current.DefaultExpiryDays))
	remember := widget.NewCheck("Sugerir guardar frases secretas no cofre do sistema", nil)
	remember.SetChecked(current.RememberPassphrases)
	cache := widget.NewEntry()
	cache.SetText(strconv.Itoa(current.PassphraseCacheMinutes))
	confirmDelete := widget.NewCheck("Confirmar antes de excluir chaves", nil)
	confirmDelete.SetChecked(current.ConfirmBeforeDelete)
	showFullID := widget.NewCheck("Exibir Key ID completo", nil)
	showFullID.SetChecked(current.ShowFullKeyID)
	warnTrust := widget.NewCheck("Alertar para destinatários sem confiança local", nil)
	warnTrust.SetChecked(current.WarnOnUntrustedRecipient)
	keyserver := widget.NewSelectEntry([]string{
		"https://keys.openpgp.org",
		"https://keyserver.ubuntu.com",
	})
	keyserver.SetText(current.DefaultKeyserver)
	backupDays := widget.NewEntry()
	backupDays.SetText(strconv.Itoa(current.BackupReminderDays))

	general := container.NewVBox(
		section("Criptografia",
			widget.NewForm(
				widget.NewFormItem("RSA padrão", bits),
				widget.NewFormItem("Validade padrão (dias)", expiry),
			),
			armor,
		),
		section("Segurança",
			remember,
			widget.NewForm(widget.NewFormItem("Cache de frase secreta (min)", cache)),
			confirmDelete,
			warnTrust,
		),
		section("Interface", showFullID),
	)
	network := container.NewVBox(
		section("Servidor de chaves",
			widget.NewForm(widget.NewFormItem("HKPS", keyserver)),
			muted("Somente HTTPS é aceito, exceto localhost para testes."),
		),
		section("Backup",
			widget.NewForm(widget.NewFormItem("Lembrete (dias; 0 desativa)", backupDays)),
		),
	)
	tabs := container.NewAppTabs(
		container.NewTabItem("Geral", container.NewVScroll(general)),
		container.NewTabItem("Rede e backup", container.NewVScroll(network)),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	prompt := dialog.NewCustomConfirm("Preferências", "Salvar", "Cancelar", tabs, func(ok bool) {
		if !ok {
			return
		}
		keyBits, err := strconv.Atoi(bits.Selected)
		if err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		expiryDays, err := strconv.Atoi(strings.TrimSpace(expiry.Text))
		if err != nil || expiryDays < 0 {
			dialog.ShowError(errors.New("validade padrão inválida"), d.window)
			return
		}
		cacheMinutes, err := strconv.Atoi(strings.TrimSpace(cache.Text))
		if err != nil || cacheMinutes < 1 {
			dialog.ShowError(errors.New("cache deve ser de pelo menos 1 minuto"), d.window)
			return
		}
		reminderDays, err := strconv.Atoi(strings.TrimSpace(backupDays.Text))
		if err != nil || reminderDays < 0 {
			dialog.ShowError(errors.New("intervalo de backup inválido"), d.window)
			return
		}
		settings := model.Settings{
			Language:                 current.Language,
			DefaultArmor:             armor.Checked,
			DefaultKeyBits:           keyBits,
			DefaultExpiryDays:        expiryDays,
			RememberPassphrases:      remember.Checked,
			PassphraseCacheMinutes:   cacheMinutes,
			ConfirmBeforeDelete:      confirmDelete.Checked,
			ShowFullKeyID:            showFullID.Checked,
			DefaultKeyserver:         strings.TrimSpace(keyserver.Text),
			BackupReminderDays:       reminderDays,
			LastBackupAt:             current.LastBackupAt,
			WarnOnUntrustedRecipient: warnTrust.Checked,
		}
		if err := d.service.SaveSettings(settings); err != nil {
			dialog.ShowError(err, d.window)
			return
		}
		d.setStatus("Preferências salvas")
	}, d.window)
	prompt.Resize(fyne.NewSize(680, 600))
	prompt.Show()
}
