package ui

import (
	"embed"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"

	"github.com/ThalesMMS/PGP-Client-go/internal/model"
	pgpcore "github.com/ThalesMMS/PGP-Client-go/internal/pgp"
)

//go:embed icon.png
var embeddedAssets embed.FS

type pageID string

const (
	pageKeyring pageID = "keyring"
	pageEncrypt pageID = "encrypt"
	pageDecrypt pageID = "decrypt"
	pageSign    pageID = "sign"
	pageVerify  pageID = "verify"
)

// Desktop is the main Fyne controller. It owns view state only; key and crypto
// operations remain in the service package.
type Desktop struct {
	app     fyne.App
	window  fyne.Window
	service *pgpcore.Service

	content *fyne.Container
	status  *widget.Label
	page    pageID

	keys        []model.KeyInfo
	pendingFile string

	navButtons map[pageID]*widget.Button
}

func New(service *pgpcore.Service) (*Desktop, error) {
	if service == nil {
		return nil, errors.New("serviço OpenPGP nulo")
	}
	application := fyneapp.NewWithID("com.thalesmms.pgpclientgo")
	application.Settings().SetTheme(MacPGPTheme{})
	if iconBytes, err := embeddedAssets.ReadFile("icon.png"); err == nil {
		application.SetIcon(fyne.NewStaticResource("pgp-client.png", iconBytes))
	}
	window := application.NewWindow("PGP Client")
	window.Resize(fyne.NewSize(1280, 800))
	window.SetMaster()

	desktop := &Desktop{
		app:        application,
		window:     window,
		service:    service,
		content:    container.NewMax(),
		status:     widget.NewLabel("Pronto"),
		navButtons: make(map[pageID]*widget.Button),
	}
	if err := desktop.reloadKeys(); err != nil {
		return nil, err
	}
	desktop.buildWindow()
	desktop.showBackupReminder()
	return desktop, nil
}

func (d *Desktop) showBackupReminder() {
	settings := d.service.Settings()
	if settings.BackupReminderDays <= 0 {
		return
	}
	if settings.LastBackupAt == nil {
		d.setStatus("Backup recomendado: nenhum backup registrado")
		return
	}
	dueAt := settings.LastBackupAt.Add(time.Duration(settings.BackupReminderDays) * 24 * time.Hour)
	if !time.Now().Before(dueAt) {
		d.setStatus("Backup recomendado: último backup em " + settings.LastBackupAt.Local().Format("02/01/2006"))
	}
}

func Run(service *pgpcore.Service, initialPaths ...string) error {
	desktop, err := New(service)
	if err != nil {
		return err
	}
	for _, path := range initialPaths {
		if strings.TrimSpace(path) != "" {
			desktop.openPath(path)
			break
		}
	}
	desktop.window.ShowAndRun()
	return nil
}

func (d *Desktop) buildWindow() {
	sidebar := d.buildSidebar()
	separator := canvas.NewLine(theme.Color(theme.ColorNameSeparator))
	separator.StrokeWidth = 1
	left := container.NewBorder(nil, nil, nil, separator, sidebar)
	left.Resize(fyne.NewSize(220, 800))

	statusBar := container.NewBorder(canvas.NewLine(theme.Color(theme.ColorNameSeparator)), nil, nil, nil,
		container.NewPadded(d.status))
	root := container.NewBorder(nil, statusBar, left, nil, d.content)
	d.window.SetContent(root)
	d.window.SetMainMenu(d.mainMenu())
	d.window.SetOnDropped(d.handleDrop)
	d.showPage(pageKeyring)
}

func (d *Desktop) buildSidebar() fyne.CanvasObject {
	logoBytes, _ := embeddedAssets.ReadFile("icon.png")
	logo := canvas.NewImageFromResource(fyne.NewStaticResource("logo.png", logoBytes))
	logo.SetMinSize(fyne.NewSize(42, 42))
	logo.FillMode = canvas.ImageFillContain
	title := widget.NewLabelWithStyle("PGP Client", fyne.TextAlignLeading, fyne.TextStyle{Bold: true})
	header := container.NewHBox(logo, title)

	makeNav := func(id pageID, label string, icon fyne.Resource) *widget.Button {
		button := widget.NewButtonWithIcon(label, icon, func() { d.showPage(id) })
		button.Alignment = widget.ButtonAlignLeading
		d.navButtons[id] = button
		return button
	}
	keysLabel := muted("CHAVES")
	operationsLabel := muted("OPERAÇÕES")
	settingsButton := widget.NewButtonWithIcon("Preferências", theme.SettingsIcon(), d.showSettings)
	settingsButton.Alignment = widget.ButtonAlignLeading
	lockButton := widget.NewButtonWithIcon("Bloquear agora", theme.LogoutIcon(), func() {
		d.service.LockNow()
		d.setStatus("Sessão sensível bloqueada")
	})
	lockButton.Alignment = widget.ButtonAlignLeading

	background := canvas.NewRectangle(theme.Color(theme.ColorNameHeaderBackground))
	body := container.NewBorder(
		container.NewVBox(header, spacer(1, 12)),
		container.NewVBox(settingsButton, lockButton),
		nil, nil,
		container.NewVBox(
			keysLabel,
			makeNav(pageKeyring, "Chaveiro", theme.StorageIcon()),
			spacer(1, 12),
			operationsLabel,
			makeNav(pageEncrypt, "Criptografar", theme.LoginIcon()),
			makeNav(pageDecrypt, "Descriptografar", theme.LogoutIcon()),
			makeNav(pageSign, "Assinar", theme.DocumentCreateIcon()),
			makeNav(pageVerify, "Verificar", theme.ConfirmIcon()),
		),
	)
	padded := container.NewPadded(body)
	return container.NewStack(background, spacer(220, 600), padded)
}

func (d *Desktop) mainMenu() *fyne.MainMenu {
	return fyne.NewMainMenu(
		fyne.NewMenu("Arquivo",
			fyne.NewMenuItem("Gerar nova chave…", d.showGenerateKey),
			fyne.NewMenuItem("Importar chave…", d.importKeyDialog),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Criar backup criptografado…", d.showBackup),
			fyne.NewMenuItem("Restaurar backup…", d.showRestore),
			fyne.NewMenuItemSeparator(),
			fyne.NewMenuItem("Sair", d.app.Quit),
		),
		fyne.NewMenu("Chaves",
			fyne.NewMenuItem("Pesquisar no servidor…", d.showKeyserverSearch),
			fyne.NewMenuItem("Bloquear sessão", func() {
				d.service.LockNow()
				d.setStatus("Sessão sensível bloqueada")
			}),
		),
		fyne.NewMenu("Ajuda",
			fyne.NewMenuItem("Sobre o PGP Client", d.showAbout),
		),
	)
}

func (d *Desktop) showPage(id pageID) {
	d.page = id
	for navID, button := range d.navButtons {
		if navID == id {
			button.Importance = widget.HighImportance
		} else {
			button.Importance = widget.MediumImportance
		}
		button.Refresh()
	}
	var page fyne.CanvasObject
	switch id {
	case pageEncrypt:
		page = d.buildEncryptPage()
	case pageDecrypt:
		page = d.buildDecryptPage()
	case pageSign:
		page = d.buildSignPage()
	case pageVerify:
		page = d.buildVerifyPage()
	default:
		page = d.buildKeyringPage()
	}
	d.content.Objects = []fyne.CanvasObject{page}
	d.content.Refresh()
}

func (d *Desktop) reloadKeys() error {
	keys, err := d.service.ListKeys()
	if err != nil {
		return err
	}
	d.keys = keys
	return nil
}

func (d *Desktop) setStatus(text string) {
	d.status.SetText(text)
}

func (d *Desktop) runAsync(label string, work func() error, done func()) {
	progress := widget.NewProgressBarInfinite()
	progress.Start()
	modal := dialog.NewCustomWithoutButtons(label, container.NewPadded(progress), d.window)
	modal.Show()
	go func() {
		err := work()
		fyne.Do(func() {
			progress.Stop()
			modal.Hide()
			if err != nil {
				dialog.ShowError(err, d.window)
				d.setStatus("Falha: " + errorText(err))
				return
			}
			if done != nil {
				done()
			}
		})
	}()
}

func (d *Desktop) runPassphraseAware(label string, attempt func(fingerprint string, passphrase []byte) error, done func()) {
	var run func(string, []byte)
	run = func(fingerprint string, passphrase []byte) {
		progress := widget.NewProgressBarInfinite()
		progress.Start()
		modal := dialog.NewCustomWithoutButtons(label, container.NewPadded(progress), d.window)
		modal.Show()
		go func() {
			err := attempt(fingerprint, passphrase)
			fyne.Do(func() {
				progress.Stop()
				modal.Hide()
				var required *model.PassphraseRequiredError
				if errors.As(err, &required) {
					d.promptPassphrase(required, func(secret []byte, remember bool) {
						if remember {
							if rememberErr := d.service.RememberPassphrase(required.Fingerprint, secret); rememberErr != nil {
								dialog.ShowError(rememberErr, d.window)
								return
							}
						}
						run(required.Fingerprint, secret)
					})
					return
				}
				if err != nil {
					dialog.ShowError(err, d.window)
					d.setStatus("Falha: " + errorText(err))
					return
				}
				if done != nil {
					done()
				}
			})
		}()
	}
	run("", nil)
}

func (d *Desktop) promptPassphrase(required *model.PassphraseRequiredError, retry func([]byte, bool)) {
	entry := widget.NewPasswordEntry()
	entry.SetPlaceHolder("Frase secreta")
	remember := widget.NewCheck("Guardar no cofre do sistema", nil)
	content := container.NewVBox(
		widget.NewLabel("Desbloquear "+required.Identity),
		entry,
		remember,
	)
	prompt := dialog.NewCustomConfirm("Frase secreta necessária", "Desbloquear", "Cancelar", content, func(ok bool) {
		if !ok {
			return
		}
		passphrase := []byte(entry.Text)
		entry.SetText("")
		retry(passphrase, remember.Checked)
	}, d.window)
	prompt.Resize(fyne.NewSize(460, 230))
	prompt.Show()
}

func (d *Desktop) handleDrop(_ fyne.Position, uris []fyne.URI) {
	for _, uri := range uris {
		if uri.Scheme() == "file" {
			d.openPath(uri.Path())
			return
		}
	}
}

// openPath routes files received by drag-and-drop or operating-system file
// associations to the corresponding workflow.
func (d *Desktop) openPath(path string) {
	path = strings.TrimSpace(path)
	if path == "" {
		return
	}
	if info, err := os.Stat(path); err != nil || info.IsDir() {
		if err == nil {
			err = errors.New("o caminho recebido é uma pasta")
		}
		d.setStatus("Arquivo inválido: " + errorText(err))
		return
	}

	lower := strings.ToLower(path)
	prefix, _ := readPrefix(path, 16*1024)
	prefixText := string(prefix)
	isArmoredKey := strings.Contains(prefixText, "BEGIN PGP PUBLIC KEY BLOCK") || strings.Contains(prefixText, "BEGIN PGP PRIVATE KEY BLOCK")
	if strings.HasSuffix(lower, ".key") || strings.HasSuffix(lower, ".pub") || isArmoredKey {
		d.runAsync("Importando chave…", func() error {
			data, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			_, err = d.service.Import(data)
			return err
		}, func() {
			_ = d.reloadKeys()
			d.showPage(pageKeyring)
			d.setStatus("Chave importada de " + filepath.Base(path))
		})
		return
	}
	if strings.HasSuffix(lower, ".sig") ||
		strings.Contains(prefixText, "BEGIN PGP SIGNATURE") ||
		strings.Contains(prefixText, "BEGIN PGP SIGNED MESSAGE") {
		d.pendingFile = path
		d.showPage(pageVerify)
		d.setStatus("Assinatura recebida: " + filepath.Base(path))
		return
	}
	if strings.HasSuffix(lower, ".gpg") || strings.HasSuffix(lower, ".pgp") || strings.HasSuffix(lower, ".asc") || strings.Contains(prefixText, "BEGIN PGP MESSAGE") {
		d.pendingFile = path
		d.showPage(pageDecrypt)
		d.setStatus("Arquivo recebido: " + filepath.Base(path))
		return
	}
	d.pendingFile = path
	d.showPage(pageEncrypt)
	d.setStatus("Arquivo recebido: " + filepath.Base(path))
}

func readPrefix(path string, limit int64) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, limit))
}

func (d *Desktop) showAbout() {
	text := widget.NewRichTextFromMarkdown(`# PGP Client

Cliente OpenPGP multiplataforma em Go/Fyne.

- Chaves RSA 2048/3072/4096
- Criptografia, descriptografia, assinatura e verificação
- Cofre de credenciais do sistema e cache de sessão
- Backup Argon2id + AES-256-GCM
- Servidores HKP/HKPS

Implementação independente inspirada na organização visual do MacPGP.`)
	text.Wrapping = fyne.TextWrapWord
	dialog.NewCustom("Sobre", "Fechar", container.NewPadded(text), d.window).Show()
}
