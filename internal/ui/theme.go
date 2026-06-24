package ui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// MacPGPTheme keeps Fyne's accessibility-aware metrics and fonts while using
// the dark graphite/orange visual language of the reference application.
type MacPGPTheme struct{}

func (MacPGPTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNamePrimary:
		return color.NRGBA{R: 255, G: 145, B: 44, A: 255}
	case theme.ColorNameBackground:
		return color.NRGBA{R: 31, G: 31, B: 33, A: 255}
	case theme.ColorNameButton:
		return color.NRGBA{R: 60, G: 60, B: 63, A: 255}
	case theme.ColorNameInputBackground:
		return color.NRGBA{R: 24, G: 24, B: 26, A: 255}
	case theme.ColorNameHeaderBackground:
		return color.NRGBA{R: 36, G: 36, B: 38, A: 255}
	case theme.ColorNameMenuBackground:
		return color.NRGBA{R: 40, G: 40, B: 43, A: 255}
	case theme.ColorNameSelection:
		return color.NRGBA{R: 26, G: 104, B: 219, A: 255}
	case theme.ColorNameHover:
		return color.NRGBA{R: 255, G: 255, B: 255, A: 18}
	case theme.ColorNameSeparator:
		return color.NRGBA{R: 78, G: 78, B: 82, A: 255}
	case theme.ColorNameShadow:
		return color.NRGBA{R: 0, G: 0, B: 0, A: 120}
	}
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (MacPGPTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (MacPGPTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (MacPGPTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameText:
		return 15
	case theme.SizeNameHeadingText:
		return 24
	case theme.SizeNameSubHeadingText:
		return 18
	}
	return theme.DefaultTheme().Size(name)
}
