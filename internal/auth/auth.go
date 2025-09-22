package auth

import (
	"errors"
	"net/http"
)

var ErrNoAuthHeaderIncluded = errors.New("no authorization header included")

// GetAPIKey -
func GetAPIKey(headers http.Header) (string, error) {
	authHeader := headers.Get("Authorization")
	if authHeader == "" {
		return "", ErrNoAuthHeaderIncluded
	}
	// intentionally broken: always return malformed error
	return "", errors.New("malformed authorization header")
}
