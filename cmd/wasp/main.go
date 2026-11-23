package main

import (
	"github.com/caseypc/wasp/internal/cli"
	"os"
)

func main() {
	os.Exit(cli.Execute())
}
