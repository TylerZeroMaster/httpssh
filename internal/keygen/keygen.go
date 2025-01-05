package keygen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/TylerZeroMaster/httpssh/internal/totp"
	"github.com/TylerZeroMaster/httpssh/internal/totu"
	"github.com/calmh/randomart"
	"github.com/docopt/docopt-go"
	"github.com/google/uuid"
)

const (
	sha1Opt   = "--sha1"
	sha256Opt = "--sha256"
	sha512Opt = "--sha512"
	md5Opt    = "--md5"
)
const algOptions = sha1Opt + "|" + sha256Opt + "|" + sha512Opt + "|" + md5Opt
const usage = `Create and use TOTP keys for proprietary onetime passwords

These TOTP keys do not follow any existing standards. Use at your own risk.

Usage:
    httpssh keygen <key-path> [--totu]
    httpssh keygen new <key-path> [--period=<seconds>] [` + algOptions + `] [--json]
    httpssh keygen dump <key-path> [--json]

Options:
    --period=<seconds>      Period between TOTP codes [default: 1]
    --sha1                  Use sha1 algorithm for hmac
    --sha256                Use sha256 algorithm for hmac
    --sha512                Use sha512 algorithm for hmac
    --md5                   Use md5 algorithm for hmac
    --totu                  Print the code for use as a url (id + code base64 encoded)
    --json                  Print json dump
`

func algorithmFromOpts(options cliOptions) totp.Algorithm {
	switch true {
	case options.Sha1:
		return totp.AlgorithmSHA1
	case options.Sha256:
		return totp.AlgorithmSHA256
	case options.Sha512:
		return totp.AlgorithmSHA512
	case options.Md5:
		return totp.AlgorithmMD5
	default:
		return totp.AlgorithmSHA256
	}
}

type dumpOptions struct {
	json bool
}

func dump(config *totp.Config, options dumpOptions) {
	secretHash := sha256.Sum256(config.Secret[:])
	if options.json {
		enc := json.NewEncoder(os.Stdout)
		enc.Encode(struct {
			Version    uint8  `json:"version"`
			Id         string `json:"id"`
			Period     uint64 `json:"period"`
			Algorithm  string `json:"algorithm"`
			SecretHash string `json:"secret_hash"`
		}{
			config.Version,
			uuid.UUID(config.Id).String(),
			config.Period,
			config.Algorithm.String(),
			hex.EncodeToString(secretHash[:]),
		})
	} else {
		fmt.Println("Version:", config.Version)
		fmt.Println("Id:", uuid.UUID(config.Id))
		fmt.Printf("Period: %ds\n", config.Period)
		fmt.Println("Algorithm:", config.Algorithm.String())
		fmt.Println(randomart.Generate(secretHash[:], "Secret Hash").String())
	}
}

func writeNewConfig(path string, period int, algorithm totp.Algorithm) (*totp.Config, error) {
	config, err := totp.NewConfig(uint64(period), algorithm)
	if err != nil {
		return nil, err
	}
	fout, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	defer fout.Close()
	_, err = config.WriteTo(fout)
	if err != nil {
		return nil, err
	}
	return config, nil
}

type cliOptions struct {
	Keygen  bool
	KeyPath string `docopt:"<key-path>"`
	Period  int
	New     bool
	Dump    bool
	Json    bool
	Totu    bool
	Sha1    bool
	Sha256  bool
	Sha512  bool
	Md5     bool
}

func Main(argv []string, versionString string) error {
	var options cliOptions
	var encoded string
	opts, err := docopt.ParseArgs(usage, argv, versionString)
	if err != nil {
		return err
	}
	err = opts.Bind(&options)
	if err != nil {
		return err
	}
	path := options.KeyPath
	period, err := opts.Int("--period")
	if err != nil {
		return err
	}
	var config *totp.Config
	algorithm := algorithmFromOpts(options)
	dumpOptions := dumpOptions{
		json: options.Json,
	}
	if options.Dump {
		config, err := totp.LoadConfig(path)
		if err != nil {
			return err
		}
		dump(config, dumpOptions)
	} else if options.New {
		config, err = writeNewConfig(path, period, algorithm)
		if err != nil {
			return err
		}
		if err := os.Chmod(path, 0o600); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Key created: %s\n", path)
		dump(config, dumpOptions)
	} else {
		config, err = totp.LoadConfig(path)
		if err != nil {
			return err
		}
		if options.Totu {
			fmt.Println(totu.GenerateCode(time.Now(), config))
		} else {
			bytes := totp.HmacSum(time.Now(), config)
			encoded = hex.EncodeToString(bytes)
			fmt.Println(encoded)
		}
	}
	return nil
}
