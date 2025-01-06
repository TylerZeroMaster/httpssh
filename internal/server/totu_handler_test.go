package server

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"testing"
	"time"

	"github.com/TylerZeroMaster/httpssh/internal/totp"
	"github.com/TylerZeroMaster/httpssh/internal/totu"
)

type testHandler struct{}

func (t *testHandler) ServeHTTP(_ http.ResponseWriter, _ *http.Request) {}

func TestTOTUHandler(t *testing.T) {
	tmpdir := t.TempDir()
	configPaths := []string{path.Join(tmpdir, "a.bin")}
	configs := []*totp.Config{}
	for idx, p := range configPaths {
		config := &totp.Config{
			Version:   1,
			Id:        [totp.IDSize]byte{byte(idx)},
			Secret:    [1024]byte{byte(idx), 0, 1, 2, 3, 4, 5, 6, 7, 8, 9},
			Period:    1,
			Algorithm: totp.AlgorithmMD5,
		}
		fout, err := os.Create(p)
		if err != nil {
			t.Fatalf("create file error: %v (%v)", err, p)
		}
		config.WriteTo(fout)
		fout.Close()
		configs = append(configs, config)
	}
	validator, err := totu.NewValidator(configPaths, 0)
	if err != nil {
		t.Fatalf("new validator error: %v", err)
	}
	code := totu.GenerateCode(time.Now(), configs[0])
	middleware := NewTOTUHandler(validator, "code")
	baseHandler := &testHandler{}
	handler := middleware(baseHandler)

	var recorder *httptest.ResponseRecorder
	var req *http.Request
	var expectedStatus int

	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/"+code, nil)
	req.SetPathValue("code", code)
	handler.ServeHTTP(recorder, req)
	expectedStatus = 200
	if status := recorder.Result().StatusCode; status != expectedStatus {
		t.Fatalf("expected status (%v), got (%v)", expectedStatus, status)
	}

	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/"+code, nil)
	req.SetPathValue("code", code)
	handler.ServeHTTP(recorder, req)
	expectedStatus = 401
	if status := recorder.Result().StatusCode; status != 401 {
		t.Fatalf("expected status (%v), got (%v)", 401, status)
	}

	code = ""
	recorder = httptest.NewRecorder()
	req = httptest.NewRequest("GET", "/"+code, nil)
	req.SetPathValue("code", code)
	handler.ServeHTTP(recorder, req)
	expectedStatus = 404
	if status := recorder.Result().StatusCode; status != 404 {
		t.Fatalf("expected status (%v), got (%v)", 404, status)
	}
}
