package auth

import (
	"context"
	"testing"
	"time"
)

type rejectedRefreshExecutor struct{ countingRefreshExecutor }

func (e *rejectedRefreshExecutor) Refresh(context.Context, *Auth) (*Auth, error) {
	return nil, &Error{HTTPStatus: 400, Message: "invalid_grant"}
}
func TestTerminalRefreshFailureQuarantinesUnexpiredCredential(t *testing.T) {
	store := newMemoryAuthTestStore()
	manager := NewManager(store, &RoundRobinSelector{}, nil)
	executor := &rejectedRefreshExecutor{countingRefreshExecutor: countingRefreshExecutor{id: "codex"}}
	manager.RegisterExecutor(executor)
	credential := &Auth{ID: "rejected", Provider: "codex", Metadata: map[string]any{"access_token": "test-access", "refresh_token": "test-refresh", "expired": time.Now().Add(time.Hour).Format(time.RFC3339)}}
	if _, err := manager.Register(context.Background(), credential); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.refreshAuthForRequest(context.Background(), credential.ID, ""); err == nil {
		t.Fatal("expected rejected refresh")
	}
	current, ok := manager.GetByID(credential.ID)
	if !ok || !current.RequiresLogin() {
		t.Fatal("sign-in requirement missing")
	}
	if blocked, _, _ := isAuthBlockedForModel(current, "any-model", time.Now()); !blocked {
		t.Fatal("revoked account remains routable")
	}
	if manager.shouldRefresh(current, time.Now()) {
		t.Fatal("revoked credential retried without sign-in")
	}
	stored, err := store.List(context.Background())
	if err != nil || len(stored) != 1 || !stored[0].RequiresLogin() {
		t.Fatal("sign-in requirement was not persisted")
	}
	// The persisted metadata alone fences the credential after restart/sync.
	restored := &Auth{ID: current.ID, Provider: current.Provider, Metadata: current.Clone().Metadata}
	if blocked, _, _ := isAuthBlockedForModel(restored, "any-model", time.Now()); !blocked {
		t.Fatal("restart restored revoked credential")
	}
}
func TestTransientRefreshFailureDoesNotRequireLogin(t *testing.T) {
	for _, err := range []error{&Error{HTTPStatus: 429}, &Error{HTTPStatus: 503}} {
		if terminalRefreshFailure(err) {
			t.Fatal("transient failure requires sign-in")
		}
	}
}
