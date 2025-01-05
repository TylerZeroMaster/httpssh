package server

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/TylerZeroMaster/httpssh/internal/totu"
	"github.com/rs/zerolog"
)

var log = zerolog.New(os.Stderr).
	With().
	Timestamp().
	Logger().
	Level(zerolog.DebugLevel)

type Usage struct {
	Port       string   `default:"8080" help:"The port for the http server to listen on"`
	TotpConfig []string `help:"Path to TOTP config"`
}

func Serve(options Usage) error {
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
