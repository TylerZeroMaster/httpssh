package keygen

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	"github.com/TylerZeroMaster/httpssh/internal/totp"
	"github.com/calmh/randomart"
	"github.com/google/uuid"
)

type KeygenCmd struct {
	KeyPath   []string `arg:"" help:"Path to save key to"`
	Algorithm string   `help:"Use this algorithm for hmac" enum:"md5,sha1,sha256,sha512" default:"sha256"`
	Period    int      `help:"Period, in seconds, between TOTP codes" default:"1"`
	Json      bool     `help:"Print json dump"`
}

func (args *KeygenCmd) Run() error {
	var algorithm totp.Algorithm
	switch args.Algorithm {
	case "sha1":
		algorithm = totp.AlgorithmSHA1
	case "sha512":
		algorithm = totp.AlgorithmSHA512
	case "md5":
		algorithm = totp.AlgorithmMD5
	default:
		algorithm = totp.AlgorithmSHA256
	}
	for _, p := range args.KeyPath {
		config, err := writeNewConfig(p, args.Period, algorithm)
		if err != nil {
			return err
		}
		dump(p, config, dumpOptions{args.Json})
	}
	return nil
}

type KeydumpCmd struct {
	KeyPath []string `help:"Path to load key from" arg:""`
	Json    bool     `help:"Print json dump"`
}

func (args *KeydumpCmd) Run() error {
	for _, p := range args.KeyPath {
		config, err := totp.LoadConfig(p)
		if err != nil {
			return err
		}
		dump(p, config, dumpOptions{args.Json})
	}
	return nil
}

type dumpOptions struct {
	json bool
}

func dump(path string, config *totp.Config, options dumpOptions) {
	secretHash := sha256.Sum256(config.Secret[:])
	if options.json {
		enc := json.NewEncoder(os.Stdout)
		enc.Encode(struct {
			Path       string `json:"path"`
			Version    uint8  `json:"version"`
			Id         string `json:"id"`
			Period     uint64 `json:"period"`
			Algorithm  string `json:"algorithm"`
			SecretHash string `json:"secret_hash"`
		}{
			path,
			config.Version,
			uuid.UUID(config.Id).String(),
			config.Period,
			config.Algorithm.String(),
			hex.EncodeToString(secretHash[:]),
		})
	} else {
		fmt.Println("Path:", path)
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
	err = fout.Chmod(0o600)
	if err != nil {
		return nil, err
	}
	_, err = config.WriteTo(fout)
	if err != nil {
		return nil, err
	}
	return config, nil
}
