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
	armor := widget.NewCheck("Use ASCII armor by default", nil)
	armor.SetChecked(current.DefaultArmor)
	bits := widget.NewSelect([]string{"2048", "3072", "4096"}, nil)
	bits.SetSelected(strconv.Itoa(current.DefaultKeyBits))
	expiry := widget.NewEntry()
	expiry.SetText(strconv.Itoa(current.DefaultExpiryDays))
	remember := widget.NewCheck("Suggest storing passphrases in the system vault", nil)
	remember.SetChecked(current.RememberPassphrases)
	cache := widget.NewEntry()
	cache.SetText(strconv.Itoa(current.PassphraseCacheMinutes))
	confirmDelete := widget.NewCheck("Confirm before deleting keys", nil)
	confirmDelete.SetChecked(current.ConfirmBeforeDelete)
	showFullID := widget.NewCheck("Show full Key ID", nil)
	showFullID.SetChecked(current.ShowFullKeyID)
	warnTrust := widget.NewCheck("Warn about recipients without local trust", nil)
	warnTrust.SetChecked(current.WarnOnUntrustedRecipient)
	keyserver := widget.NewSelectEntry([]string{
		"https://keys.openpgp.org",
		"https://keyserver.ubuntu.com",
	})
	keyserver.SetText(current.DefaultKeyserver)
	backupDays := widget.NewEntry()
	backupDays.SetText(strconv.Itoa(current.BackupReminderDays))

	general := container.NewVBox(
		section("Encryption",
			widget.NewForm(
				widget.NewFormItem("Default RSA", bits),
				widget.NewFormItem("Default expiration (days)", expiry),
			),
			armor,
		),
		section("Security",
			remember,
			widget.NewForm(widget.NewFormItem("Passphrase cache (min)", cache)),
			confirmDelete,
			warnTrust,
		),
		section("Interface", showFullID),
	)
	network := container.NewVBox(
		section("Keyserver",
			widget.NewForm(widget.NewFormItem("HKPS", keyserver)),
			muted("Only HTTPS is accepted, except localhost for tests."),
		),
		section("Backup",
			widget.NewForm(widget.NewFormItem("Reminder (days; 0 disables)", backupDays)),
		),
	)
	tabs := container.NewAppTabs(
		container.NewTabItem("General", container.NewVScroll(general)),
		container.NewTabItem("Network and backup", container.NewVScroll(network)),
	)
	tabs.SetTabLocation(container.TabLocationTop)

	prompt := dialog.NewCustomConfirm("Preferences", "Save", "Cancel", tabs, func(ok bool) {
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
			dialog.ShowError(errors.New("invalid default expiration"), d.window)
			return
		}
		cacheMinutes, err := strconv.Atoi(strings.TrimSpace(cache.Text))
		if err != nil || cacheMinutes < 1 {
			dialog.ShowError(errors.New("cache must be at least 1 minute"), d.window)
			return
		}
		reminderDays, err := strconv.Atoi(strings.TrimSpace(backupDays.Text))
		if err != nil || reminderDays < 0 {
			dialog.ShowError(errors.New("invalid backup interval"), d.window)
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
		d.setStatus("Preferences saved")
	}, d.window)
	prompt.Resize(fyne.NewSize(680, 600))
	prompt.Show()
}
