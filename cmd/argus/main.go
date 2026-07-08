package main

import (
	"os"

	"github.com/zer0d4y5/argus/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
