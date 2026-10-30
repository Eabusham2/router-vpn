//go:build windows && routervpn_windows_main_diagnostic

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"

	"router-vpn/internal/windowsbootstrap"
	"router-vpn/internal/windowscontroller"
)

// This entry exists only in a deliberately tagged test executable. The native
// runner builds it only after the separately built shipping main fails, and
// copies it into a new blank disposable package. It executes the actual main;
// no production argument or environment variable enables diagnostic capture.
func init() {
	if len(os.Args) < 2 || os.Args[1] != windowsbootstrap.ControllerArgument {
		return
	}
	if _, err := windowsbootstrap.ParseArguments(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "test-only fullmain diagnostic rejected its rendezvous:", err)
		os.Exit(1)
	}
	image, err := windowscontroller.PinCurrentImage()
	if err != nil {
		fmt.Fprintln(os.Stderr, "test-only fullmain diagnostic could not retain itself:", err)
		os.Exit(1)
	}
	// The retained executable pins the complete resolved package ancestry. A
	// fixed new file cannot overwrite another log or follow a planted leaf.
	path := filepath.Join(filepath.Dir(image.Path()), ".routervpn-main-diagnostic.log")
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		_ = image.Close()
		fmt.Fprintln(os.Stderr, "test-only fullmain diagnostic could not create its exclusive log:", err)
		os.Exit(1)
	}
	os.Stderr = file
	log.SetOutput(file)
	fmt.Fprintln(file, "test-only diagnostic entering the actual controller main")
	main()
	fmt.Fprintln(file, "test-only diagnostic actual controller main returned")
	if err := file.Close(); err != nil {
		_ = image.Close()
		os.Exit(1)
	}
	if err := image.Close(); err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}
