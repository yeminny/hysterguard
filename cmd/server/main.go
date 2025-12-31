package main

import (
	"os"

	"github.com/hysterguard/hysterguard/cmd/server/cmd"
)

func main() {
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
