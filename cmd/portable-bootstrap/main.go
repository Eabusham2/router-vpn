//go:build windows

package main

import (
	"os"

	"router-vpn/internal/windowsapp"
)

func main() {
	os.Exit(windowsapp.Main(true))
}
