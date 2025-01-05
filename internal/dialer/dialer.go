package dialer

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TylerZeroMaster/httpssh/internal/totp"
	"github.com/TylerZeroMaster/httpssh/internal/totu"
	"github.com/TylerZeroMaster/httptunnel"
	"github.com/docopt/docopt-go"
)

const usage = `Dial ssh over http

Usage:
    httpssh dial <http-url> <ssh-host> <ssh-port> [--totp-config=<path>]

Options:
    --totp-config=<path>    Path to TOTP config
`

var dialer = httptunnel.DefaultDialer

func statusIs(status int, ok ...int) error {
	for _, code := range ok {
		if status == code {
			return nil
		}
	}
	return fmt.Errorf("request failed with status: %d", status)
}

func dialSsh(urlString, sshHost, sshPort string) error {
	options := &httptunnel.ConnectionOptions{
		PrepareRequest: func(r *http.Request) error {
			r.Header.Set("x-ssh-host", sshHost)
			r.Header.Set("x-ssh-port", sshPort)
			return nil
		},
	}
	// Unbox the tcp conn from the net.Conn interface so we can call
	// WriteTo/ReadFrom directly. These try to use splice, or similar,
	// to copy between pipes without copying into user address space
	// see `man 2 splice` and `net/tcpsock_posix.go` for more info
	// You can also use `strace` to verify that splice is being used
	netConn, _, resp, err := dialer.Dial(urlString, options)
	tcpConn := httptunnel.AssertTCPConn(netConn)

	if err != nil {
		return err
	}
	defer netConn.Close()
	if err := statusIs(resp.StatusCode, 101); err != nil {
		return err
	}
	go func() {
		_, err := tcpConn.WriteTo(os.Stdout)
		if err != nil {
			panic(err)
		}
	}()
	// TODO: Add deadlines?
	_, err = tcpConn.ReadFrom(os.Stdin)
	if err != nil {
		return err
	}
	return nil
}

func isInt(s string) error {
	for _, b := range []byte(s) {
		if (b ^ 0x30) > 9 {
			return errors.New("not an integer: " + s)
		}
	}
	return nil
}

func subTotpCode(input, totpPath string) (string, error) {
	config, err := totp.LoadConfig(totpPath)
	if err != nil {
		return "", err
	}
	code := totu.GenerateCode(time.Now(), config)
	return strings.ReplaceAll(input, "{{code}}", code), nil
}

type cliOptions struct {
	Dial       bool
	HTTPUrl    string `docopt:"<http-url>"`
	SSHHost    string `docopt:"<ssh-host>"`
	SSHPort    string `docopt:"<ssh-port>"`
	TotpConfig string
}

func Main(argv []string, versionString string) error {
	var options cliOptions
	opts, err := docopt.ParseArgs(usage, argv, versionString)
	if err != nil {
		return err
	}
	opts.Bind(&options)
	urlString := options.HTTPUrl
	totpPath := options.TotpConfig
	if err := isInt(options.SSHPort); err != nil {
		return err
	}
	if len(totpPath) > 0 {
		urlString, err = subTotpCode(urlString, totpPath)
		if err != nil {
			return err
		}
	}
	dialSsh(urlString, options.SSHHost, options.SSHPort)

	return nil
}
