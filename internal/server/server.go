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
	Logger()

type ServeCmd struct {
	LogLevel   string   `help:"Set level of logging" enum:"debug,info,error,fatal" default:"info"`
	Port       string   `help:"The port for the http server to listen on" default:"8080"`
	TotpConfig []string `help:"Path to TOTP config"`
	Skew       int      `help:"Allow codes to be off by [-skew, skew] seconds" default:"0"`
}

func setLogLevel(logger zerolog.Logger, levelName string) zerolog.Logger {
	var level zerolog.Level
	switch levelName {
	case "debug":
		level = zerolog.DebugLevel
	case "info":
		level = zerolog.InfoLevel
	case "error":
		level = zerolog.ErrorLevel
	case "fatal":
		level = zerolog.FatalLevel
	default:
		panic("unknown log level: " + levelName)
	}
	return logger.Level(level)
}

func (args *ServeCmd) Run() error {
	log = setLogLevel(log, args.LogLevel)
	port := args.Port
	port = ":" + strings.Trim(port, ": ")
	if port == ":" {
		return errors.New("empty port")
	}
	totpPaths := args.TotpConfig
	if len(totpPaths) > 0 {
		log.Info().Strs("path", totpPaths).Msg("using totp config")
		validator, err := totu.NewValidator(totpPaths, args.Skew)
		if err != nil {
			return err
		}
		totuMiddleware := NewTOTUHandler(validator, "code")
		http.Handle("GET /{code}", totuMiddleware(SSHTunnelHandler{}))
	} else {
		http.Handle("GET /ssh", SSHTunnelHandler{})
	}
	log.Info().Str("port", port).Msg("listening")
	return http.ListenAndServe(port, nil)
}
