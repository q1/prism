package management

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestAuthFileEntryPublishesLifecycleWithoutCredentials(t *testing.T) {
	expiry := time.Date(2026, 9, 4, 23, 0, 0, 0, time.UTC)
	refreshed := expiry.Add(-time.Hour)
	retry := expiry.Add(-time.Minute)
	for _, provider := range []string{"claude", "codex", "grok"} {
		t.Run(provider, func(t *testing.T) {
			h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, nil)
			auth := &coreauth.Auth{
				ID: "account.json", FileName: "account.json", Provider: provider,
				Attributes:      map[string]string{"runtime_only": "true"},
				Metadata:        map[string]any{"expired": expiry.Format(time.RFC3339), "access_token": "test-access-material", "refresh_token": "test-refresh-material"},
				LastRefreshedAt: refreshed, NextRefreshAfter: retry,
				LastError: &coreauth.Error{HTTPStatus: 401, Message: "test-private-error"},
			}
			entry := h.buildAuthFileEntry(auth)
			for key, expected := range map[string]time.Time{"expires_at": expiry, "last_refresh": refreshed, "next_refresh_after": retry} {
				actual, ok := entry[key].(time.Time)
				if !ok || !actual.Equal(expected) {
					t.Errorf("%s = %v, want %v", key, entry[key], expected)
				}
			}
			if entry["last_error_status"] != 401 {
				t.Errorf("last_error_status = %v", entry["last_error_status"])
			}
			encoded, err := json.Marshal(entry)
			if err != nil {
				t.Fatal(err)
			}
			for _, forbidden := range []string{"test-access-material", "test-refresh-material", "test-private-error"} {
				if strings.Contains(string(encoded), forbidden) {
					t.Error("entry exposes private credential material")
				}
			}
		})
	}
}

func TestAuthFileEntryOmitsUnknownLifecycle(t *testing.T) {
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, nil)
	auth := &coreauth.Auth{ID: "unknown.json", Provider: "codex", Attributes: map[string]string{"runtime_only": "true"}}
	entry := h.buildAuthFileEntry(auth)
	for _, key := range []string{"expires_at", "next_refresh_after", "last_refresh", "last_error_status"} {
		if _, ok := entry[key]; ok {
			t.Errorf("unknown %s should be omitted", key)
		}
	}
}

func TestAuthFileEntryUsesUpstreamNestedExpiryParser(t *testing.T) {
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: t.TempDir()}, nil)
	expiry := time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC)
	auth := &coreauth.Auth{ID: "nested.json", Provider: "claude", Attributes: map[string]string{"runtime_only": "true"}, Metadata: map[string]any{"token": map[string]any{"expires_at": expiry.Format(time.RFC3339)}}}
	entry := h.buildAuthFileEntry(auth)
	actual, ok := entry["expires_at"].(time.Time)
	if !ok || !actual.Equal(expiry) {
		t.Errorf("nested expiry = %v, want %v", entry["expires_at"], expiry)
	}
}
