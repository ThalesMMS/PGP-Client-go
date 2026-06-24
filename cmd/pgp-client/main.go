package main

import (
	"fmt"
	"os"
	"strings"

	pgpcore "github.com/ThalesMMS/PGP-Client-go/internal/pgp"
	"github.com/ThalesMMS/PGP-Client-go/internal/ui"
)

func main() {
	service, err := pgpcore.NewDefaultService()
	if err != nil {
		fmt.Fprintln(os.Stderr, "PGP Client:", err)
		os.Exit(1)
	}
	paths := make([]string, 0, len(os.Args)-1)
	for _, argument := range os.Args[1:] {
		// macOS may inject process-serial-number launch flags. They are not files.
		if strings.HasPrefix(argument, "-") {
			continue
		}
		paths = append(paths, argument)
	}
	if err := ui.Run(service, paths...); err != nil {
		fmt.Fprintln(os.Stderr, "PGP Client:", err)
		os.Exit(1)
	}
}
