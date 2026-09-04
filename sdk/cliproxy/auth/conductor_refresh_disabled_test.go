package auth

import (
	"context"
	"testing"
	"time"
)

func TestServingCredentialNeverRefreshes(t *testing.T) {
	for _, provider := range []string{"claude", "codex", "grok"} {
		t.Run(provider, func(t *testing.T) {
			manager := NewManager(nil, &RoundRobinSelector{}, nil)
			executor := &countingRefreshExecutor{id: provider}
			manager.RegisterExecutor(executor)
			credential := &Auth{ID: "serving", Provider: provider, Metadata: map[string]any{
				"access_token": "expired-test-access", "refresh_token": "retained-test-refresh",
				"expired": time.Now().Add(-time.Hour).Format(time.RFC3339), "refresh_disabled": true,
			}}
			if _, err := manager.Register(context.Background(), credential); err != nil {
				t.Fatal(err)
			}
			if manager.shouldRefresh(credential, time.Now()) {
				t.Fatal("serving credential scheduled for refresh")
			}
			if _, err := manager.refreshAuthForRequest(context.Background(), credential.ID, "expired-test-access"); err == nil {
				t.Fatal("explicit refresh was accepted")
			}
			if _, scheduled := nextRefreshCheckAt(time.Now(), credential, time.Second); scheduled {
				t.Fatal("serving credential queued for refresh")
			}
			if _, retried := manager.tryRefreshAfterUnauthorized(context.Background(), credential, &Error{HTTPStatus: 401}, false); retried {
				t.Fatal("serving credential refreshed after unauthorized response")
			}

			if executor.refreshCalls.Load() != 0 {
				t.Fatal("serving gateway called refresh executor")
			}
		})
	}
}
