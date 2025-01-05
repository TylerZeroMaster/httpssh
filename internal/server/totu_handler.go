package server

import (
	"net/http"
	"sync"
	"time"

	"github.com/TylerZeroMaster/httpssh/internal/totu"
)

// Make validator safe for concurrency
type concurrentValidator struct {
	totu.Validator
	mu sync.Mutex
}

func (validator *concurrentValidator) Validate(t time.Time, code string) error {
	validator.mu.Lock()
	defer validator.mu.Unlock()
	return validator.Validator.Validate(time.Now(), code)
}

type TOTUHandler struct {
	next      http.Handler
	pathKey   string
	validator *concurrentValidator
}

func (handler TOTUHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	err := handler.validator.Validate(time.Now(), r.PathValue(handler.pathKey))
	switch err {
	case nil:
		handler.next.ServeHTTP(w, r)
		return
	case totu.ErrCodeAlreadyUsed:
		http.Error(w, "401 unauthorized", http.StatusUnauthorized)
	default:
		http.Error(w, "404 page not found", http.StatusNotFound)
	}
	log.Err(err).Msg("totu validation error")
}

func NewTOTUHandler(validator totu.Validator, pathKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return TOTUHandler{next, pathKey, &concurrentValidator{validator, sync.Mutex{}}}
	}
}
