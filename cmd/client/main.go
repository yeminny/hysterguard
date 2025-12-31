package main

import (
	"os"

	"github.com/hysterguard/hysterguard/cmd/client/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
