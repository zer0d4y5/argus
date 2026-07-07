package main

import (
	"os"

	"github.com/leaky-hub/argus/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
