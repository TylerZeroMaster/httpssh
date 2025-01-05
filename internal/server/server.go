package server

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/TylerZeroMaster/httpssh/internal/totu"
	"github.com/docopt/docopt-go"
	"github.com/rs/zerolog"
)

const usage = `Tunnel ssh over http

Usage:
    httpssh serve [--port=<port>] [--totp-config=<path>]...

Options:
    --port=<port>           The port for the http server to listen on [default: 8080]
    --totp-config=<path>    Path to TOTP config
`

var log = zerolog.New(os.Stderr).
	With().
	Timestamp().
	Logger().
	Level(zerolog.DebugLevel)

type cliOptions struct {
	Serve      bool
	Port       string
	TotpConfig []string
}

func Main(argv []string, versionString string) error {
	var options cliOptions
	opts, err := docopt.ParseArgs(usage, argv, versionString)
	if err != nil {
		return err
	}
	opts.Bind(&options)
	port := options.Port
	port = ":" + strings.Trim(port, ": ")
	if port == ":" {
		return errors.New("empty port")
	}
	totpPaths := options.TotpConfig
	if len(totpPaths) > 0 {
		log.Info().Strs("path", totpPaths).Msg("using totp config")
		validator, err := totu.NewValidator(totpPaths)
		if err != nil {
			return err
		}
		http.Handle("GET /{code}", NewTOTUHandler(validator, "code")(SSHTunnelHandler{}))
	} else {
		http.Handle("GET /ssh", SSHTunnelHandler{})
	}
	log.Info().Str("port", port).Msg("listening")
	return http.ListenAndServe(port, nil)
}
