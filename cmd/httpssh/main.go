package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/TylerZeroMaster/httpssh/internal/dialer"
	"github.com/TylerZeroMaster/httpssh/internal/keygen"
	"github.com/TylerZeroMaster/httpssh/internal/server"
	"github.com/TylerZeroMaster/httptunnel"
	"github.com/alecthomas/kong"
)

const version = "0.1.1"

func main() {
	var versionString = "Version: " + version + "\n" + httptunnel.License
	var usage struct {
		Serve   server.ServeCmd   `cmd:"" help:"Start http ssh tunneling server" default:"1"`
		Dial    dialer.DialCmd    `cmd:"" help:"Dial http ssh tunneling server"`
		Keygen  keygen.KeygenCmd  `cmd:"" help:"Generate totp configs"`
		Keydump keygen.KeydumpCmd `cmd:"" help:"Dump totp configs"`
		Version bool              `help:"Show version and license" short:"V"`
	}
	err := errors.New("unreachable")
	ctx := kong.Parse(&usage)
	if usage.Version {
		fmt.Print(versionString)
		os.Exit(0)
	}
	err = ctx.Run()
	ctx.FatalIfErrorf(err)
}
