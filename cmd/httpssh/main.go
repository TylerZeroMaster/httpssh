package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/TylerZeroMaster/httpssh/internal/dialer"
	"github.com/TylerZeroMaster/httpssh/internal/keygen"
	"github.com/TylerZeroMaster/httpssh/internal/server"
	"github.com/TylerZeroMaster/httptunnel"
	"github.com/alecthomas/kong"
)

const version = "0.1.0"

func main() {
	var versionString = "Version: " + version + "\n" + httptunnel.License
	var usage struct {
		Serve   server.Usage     `cmd:"" help:"Start http ssh tunneling server" default:"1"`
		Dial    dialer.DialUsage `cmd:"" help:"Dial http ssh tunneling server"`
		Keygen  keygen.GenUsage  `cmd:"" help:"Generate totp configs"`
		Keydump keygen.DumpUsage `cmd:"" help:"Dump totp configs"`
		Version bool             `help:"Show version and license" short:"V"`
	}
	err := errors.New("unreachable")
	ctx := kong.Parse(&usage)
	if usage.Version {
		fmt.Print(versionString)
		os.Exit(0)
	}
	commandParts := strings.Split(ctx.Command(), " ")
	switch commandParts[0] {
	case "serve":
		err = server.Serve(usage.Serve)
	case "dial":
		err = dialer.Dial(usage.Dial)
	case "keygen":
		err = keygen.Keygen(usage.Keygen)
	case "keydump":
		err = keygen.Keydump(usage.Keydump)
	}
	if err != nil {
		panic(err)
	}
}
