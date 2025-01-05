package main

import (
	"fmt"
	"os"

	"github.com/TylerZeroMaster/httpssh/internal/dialer"
	"github.com/TylerZeroMaster/httpssh/internal/keygen"
	"github.com/TylerZeroMaster/httpssh/internal/server"
	"github.com/TylerZeroMaster/httptunnel"
	"github.com/docopt/docopt-go"
)

const version = "0.1.0"

var versionString = "Version: " + version + "\n" + httptunnel.License

const usage = `SSH over HTTP; serve, dial, and generate keys

Usage:
    httpssh <command> [<args>...]

Commands:
    serve      Serve ssh over http
    dial       Dial httpssh (intended for use with ssh ProxyCommand; see README)
    keygen     Generate and inspect totp key configurations

For more information about a command, see command's help text.
`

func getHandler(command string) func([]string, string) error {
	switch command {
	case "serve":
		return server.Main
	case "dial":
		return dialer.Main
	case "keygen":
		return keygen.Main
	default:
		return nil
	}
}

func main() {
	var command string
	args := []string{}
	parser := &docopt.Parser{
		HelpHandler: func(err error, usage string) {
			fmt.Fprintln(os.Stderr, usage)
			if err != nil {
				errValue := err.Error()
				if errValue != "" {
					fmt.Println("Error:", errValue)
				}
				os.Exit(1)
			}
			os.Exit(0)
		},
		OptionsFirst:  true,
		SkipHelpFlags: false,
	}
	opts, err := parser.ParseArgs(usage, os.Args[1:], versionString)
	if err != nil {
		panic(err)
	}

	if maybeArgs := opts["<args>"]; maybeArgs != nil {
		args = maybeArgs.([]string)
	}
	if maybeCommand := opts["<command>"]; maybeCommand != nil {
		command = maybeCommand.(string)
	}

	args = append([]string{command}, args...)
	if handler := getHandler(command); handler != nil {
		err := handler(args, versionString)
		if err != nil {
			panic(err)
		}
	} else {
		parser.HelpHandler(fmt.Errorf("command not found: %s", command), usage)
	}
}
