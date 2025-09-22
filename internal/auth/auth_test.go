package auth

import (
	"net/http"
	"testing"
)

func TestGetAPIKey_Success(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "ApiKey abc123")

	key, err := GetAPIKey(h)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if key != "abc123" {
		t.Fatalf("expected key 'abc123', got %q", key)
	}
}

func TestGetAPIKey_NoHeader(t *testing.T) {
	h := http.Header{}

	key, err := GetAPIKey(h)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err != ErrNoAuthHeaderIncluded {
		t.Fatalf("expected ErrNoAuthHeaderIncluded, got %v", err)
	}
	if key != "" {
		t.Fatalf("expected empty key, got %q", key)
	}
}

func TestGetAPIKey_MalformedHeader_Scheme(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "Bearer abc123")

	_, err := GetAPIKey(h)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected 'malformed authorization header', got %q", err.Error())
	}
}

func TestGetAPIKey_MalformedHeader_NoToken(t *testing.T) {
	h := http.Header{}
	h.Set("Authorization", "ApiKey")

	_, err := GetAPIKey(h)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if err.Error() != "malformed authorization header" {
		t.Fatalf("expected 'malformed authorization header', got %q", err.Error())
	}
}
