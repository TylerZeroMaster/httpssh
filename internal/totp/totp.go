package totp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"io"
	"math"
	"os"
	"time"

	"github.com/google/uuid"
)

type Algorithm uint8

const (
	AlgorithmSHA1 Algorithm = iota
	AlgorithmSHA256
	AlgorithmSHA512
	AlgorithmMD5
)
const ConfigSize = 1064
const IDSize = 16

var (
	ErrUnsupportedVersion = errors.New("unsupported config version")
)

func (alg Algorithm) Decode() func() hash.Hash {
	switch alg {
	case AlgorithmSHA1:
		return sha1.New
	case AlgorithmSHA256:
		return sha256.New
	case AlgorithmSHA512:
		return sha512.New
	case AlgorithmMD5:
		return md5.New
	default:
		return nil
	}
}

func (alg Algorithm) String() string {
	switch alg {
	case AlgorithmSHA1:
		return "sha1"
	case AlgorithmSHA256:
		return "sha256"
	case AlgorithmSHA512:
		return "sha512"
	case AlgorithmMD5:
		return "md5"
	default:
		return ""
	}
}

type Config struct {
	Version   uint8
	Id        [IDSize]byte
	Secret    [1024]byte
	Period    uint64
	Algorithm Algorithm
}

func (config *Config) Marshal() ([]byte, error) {
	buf := make([]byte, ConfigSize)
	_, err := binary.Encode(buf, binary.LittleEndian, config)
	if err != nil {
		return nil, err
	}
	return buf, nil
}

func (config *Config) WriteTo(w io.Writer) (int64, error) {
	return ConfigSize, binary.Write(w, binary.LittleEndian, config)
}

func (config *Config) Unmarshal(b []byte) (err error) {
	if version := b[0]; version != 1 {
		err = ErrUnsupportedVersion
	} else {
		_, err = binary.Decode(b, binary.LittleEndian, config)
	}
	return
}

func (config *Config) ReadFrom(r io.Reader) (int64, error) {
	b, err := io.ReadAll(r)
	if err != nil {
		return 0, err
	}
	err = config.Unmarshal(b)
	if err == nil {
		return ConfigSize, nil
	}
	return 0, err
}

func (config *Config) HmacSum(t time.Time) []byte {
	secretBytes := &config.Secret
	period := config.Period
	algorithm := config.Algorithm
	counter := uint64(math.Floor(float64(t.Unix()) / float64(period)))
	mac := hmac.New(algorithm.Decode(), secretBytes[:])
	binary.Write(mac, binary.BigEndian, counter)
	return mac.Sum(nil)
}

func (config *Config) GenEqual(t time.Time, rhs []byte) bool {
	lhs := config.HmacSum(t)
	return hmac.Equal(lhs, rhs)
}

func (config *Config) GenEqualSkewed(t time.Time, skew int, rhs []byte) bool {
	matched := false
	for i := -skew; i <= skew; i++ {
		skewed := t.Add(time.Duration(i) * time.Second)
		lhs := config.HmacSum(skewed)
		// Intentionally slow
		matched = hmac.Equal(lhs, rhs) || matched
	}
	return matched
}

func NewConfig(period uint64, algorithm Algorithm) (config *Config, err error) {
	secret := [1024]byte{}
	_, err = rand.Reader.Read(secret[:])
	if err != nil {
		return
	}
	config = &Config{
		Version:   1,
		Id:        uuid.New(),
		Period:    period,
		Algorithm: algorithm,
		Secret:    secret,
	}
	return
}

func HmacSum(t time.Time, config *Config) []byte {
	secretBytes := &config.Secret
	period := config.Period
	algorithm := config.Algorithm
	counter := uint64(math.Floor(float64(t.Unix()) / float64(period)))
	mac := hmac.New(algorithm.Decode(), secretBytes[:])
	binary.Write(mac, binary.BigEndian, counter)
	return mac.Sum(nil)
}

func LoadConfig(path string) (*Config, error) {
	config := new(Config)
	fin, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fin.Close()
	_, err = config.ReadFrom(fin)
	if err != nil {
		return nil, err
	}
	return config, nil
}
