package main

import (
	"os"

	"github.com/leaky-hub/appsec/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
