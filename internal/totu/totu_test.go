package totu

import (
	"encoding/base64"
	"errors"
	"os"
	"path"
	"testing"
	"time"

	"github.com/TylerZeroMaster/httpssh/internal/totp"
)

func TestCircularList(t *testing.T) {
	list := CircularList[int]{make([]int, 4), 0}
	if list.Has(1) {
		t.Error("list should not have 1")
	}
	if !list.Has(0) {
		t.Error("list should have 0")
	}
	list = list.Put(1)
	if idx := list.Index(1); idx != 0 {
		t.Errorf("expected index 0, got: %v", idx)
	}
	if !list.Has(1) {
		t.Error("should have 1")
	}
	list = list.Put(2)
	list = list.Put(3)
	list = list.Put(4)
	list = list.Put(5)
	if idx := list.Index(4); idx != 3 {
		t.Error("list is not circular")
	}
	if idx := list.Index(5); idx != 0 {
		t.Error("list is not circular")
	}
	if list.Has(1) {
		t.Error("should have been overwritten")
	}
}

func TestGenerateCode(t *testing.T) {
	config := &totp.Config{
		Version:   1,
		Id:        [IDSize]byte{1},
		Secret:    [1024]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		Period:    1,
		Algorithm: totp.AlgorithmMD5,
	}
	var code string
	code = GenerateCode(time.Unix(0, 0), config)
	if expected := "AQAAAAAAAAAAAAAAAAAAAOnQMo13Ry7IEkj-KKG_Bjo="; code != expected {
		t.Errorf("codes do not match: (%s) vs (%s)", expected, code)
	}
	code = GenerateCode(time.Unix(2, 0), config)
	if expected := "AQAAAAAAAAAAAAAAAAAAAMZXeP-mrcBxv7LYnoRyRu8="; code != expected {
		t.Errorf("codes do not match: (%s) vs (%s)", expected, code)
	}
}

type testCodeGen struct {
	N      time.Time
	config *totp.Config
}

func (gen *testCodeGen) Next() (string, time.Time) {
	gen.N = gen.N.Add(1 * time.Second)
	code := GenerateCode(gen.N, gen.config)
	return code, gen.N
}

func TestValidator(t *testing.T) {
	tmp := t.TempDir()
	configPathsById := make(map[[IDSize]byte]string)
	configPaths := []string{
		path.Join(tmp, "a.bin"),
		path.Join(tmp, "b.bin"),
		path.Join(tmp, "c.bin"),
	}
	configs := []*totp.Config{}
	for idx, configPath := range configPaths {
		fout, err := os.Create(configPath)
		config := &totp.Config{
			Version:   1,
			Id:        [IDSize]byte{byte(idx)},
			Secret:    [1024]byte{byte(idx), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			Period:    1,
			Algorithm: totp.AlgorithmMD5,
		}
		if err != nil {
			t.Fatalf("create config: %v", err)
		}

		_, err = config.WriteTo(fout)
		if err != nil {
			t.Fatalf("write config: %v", err)
		}
		configPathsById[config.Id] = configPath
		fout.Close()
		configs = append(configs, config)
	}
	validator, err := NewValidator(configPaths, 1)
	if err != nil {
		t.Fatalf("new validator: %v", err)
	}
	configA := configs[0]
	configC := configs[2]
	genA := testCodeGen{time.Unix(0, 0), configA}
	genC := testCodeGen{time.Unix(0, 0), configC}
	var code string
	var expected error
	var now time.Time

	// valid
	expected = nil
	code, now = genA.Next()
	if err := validator.Validate(now, code); err != nil {
		t.Errorf("expected err (%v), got: %v", expected, err)
	}
	code, now = genC.Next()
	if err := validator.Validate(now, code); err != nil {
		t.Errorf("expected err (%v), got: %v", expected, err)
	}
	// code too short
	code = ""
	expected = ErrCodeTooShort
	if err := validator.Validate(time.Unix(0, 0), code); err != expected {
		t.Errorf("expected err (%v), got: %v", expected, err)
	}
	code = base64.URLEncoding.EncodeToString([]byte("1234"))
	if err := validator.Validate(time.Unix(0, 0), code); err != expected {
		t.Errorf("expected err (%v), got: %v", expected, err)
	}
	// config not loaded
	config := &totp.Config{
		Version:   1,
		Id:        [IDSize]byte{20},
		Secret:    [1024]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
		Period:    1,
		Algorithm: totp.AlgorithmMD5,
	}
	code = GenerateCode(time.Unix(0, 0), config)
	expected = ErrKeyNotFound
	if err := validator.Validate(time.Unix(0, 0), code); err != expected {
		t.Errorf("expected err (%v), got: %v", expected, err)
	}
	// code used
	code, now = genC.Next()
	expected = nil
	if err := validator.Validate(now, code); err != expected {
		t.Errorf("expected err (%v), got: %v", expected, err)
	}
	expected = ErrCodeAlreadyUsed
	if err := validator.Validate(now, code); err != expected {
		t.Errorf("expected err (%v), got: %v", expected, err)
	}
	// code mismatch
	code, now = genC.Next()
	expected = ErrCodeMismatch
	if err := validator.Validate(now.Add(time.Duration(validator.skew+1)*time.Second), code); err != expected {
		t.Errorf("expected err (%v), got: %v", expected, err)
	}
	// encoding error
	code = "-"
	if err := validator.Validate(time.Unix(0, 0), code); err == nil {
		t.Error("expected error, got nil")
	}
	// unexpected error
	for _, p := range configPaths {
		err = os.Remove(p)
		if err != nil {
			t.Fatalf("rm configC: %v", err)
		}
	}
	code, now = genC.Next()
	if err := validator.Validate(now, code); !errors.Is(err, os.ErrNotExist) {
		t.Error("expected error, got nil")
	}

	// NewValidator error
	_, err = NewValidator(configPaths, 2)
	if err == nil {
		t.Error("expected error, got nil")
	}
}
