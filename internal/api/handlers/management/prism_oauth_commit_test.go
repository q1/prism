package management

import (
	"sync"
	"testing"
	"time"
)

func TestPrismOAuthCancellationCannotClaimRollbackAfterSaveBegins(t *testing.T) {
	store := newOAuthSessionStore(time.Minute)
	store.Register("fixture-save", "codex")
	began := make(chan struct{})
	finish := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		if !store.BeginSave("fixture-save", "codex") {
			return
		}
		close(began)
		<-finish
		store.Complete("fixture-save")
	}()
	<-began
	if store.Cancel("fixture-save") {
		t.Fatal("cancellation accepted while saving")
	}
	if store.BeginSave("fixture-save", "codex") {
		t.Fatal("second saver admitted")
	}
	close(finish)
	<-done
	session, exists := store.Get("fixture-save")
	if !exists || !session.Completed || session.Committing {
		t.Fatal("save did not finish truthfully")
	}
}

func TestPrismOAuthOnlyCancelOrSaveWins(t *testing.T) {
	for iteration := range 32 {
		store := newOAuthSessionStore(time.Minute)
		store.Register("fixture-race", "claude")
		start := make(chan struct{})
		var workers sync.WaitGroup
		workers.Add(2)
		var cancelled, saving bool
		go func() { defer workers.Done(); <-start; cancelled = store.Cancel("fixture-race") }()
		go func() { defer workers.Done(); <-start; saving = store.BeginSave("fixture-race", "claude") }()
		close(start)
		workers.Wait()
		if cancelled == saving {
			t.Fatalf("iteration %d: cancellation and persistence did not have one winner", iteration)
		}
	}
}

func TestPrismOAuthFailedCommitRemainsFailed(t *testing.T) {
	store := newOAuthSessionStore(time.Minute)
	store.Register("fixture-fail", "xai")
	if !store.BeginSave("fixture-fail", "xai") {
		t.Fatal("save did not begin")
	}
	store.SetError("fixture-fail", "credential storage unavailable")
	session, _ := store.Get("fixture-fail")
	if session.Committing || session.Completed || session.Status == "" {
		t.Fatal("failed save has incorrect lifecycle")
	}
	if store.Cancel("fixture-fail") {
		t.Fatal("failed account reported cancelled")
	}
}

func TestPrismOAuthExpiryCannotForgetAnActiveCommit(t *testing.T) {
	store := newOAuthSessionStore(time.Minute)
	store.Register("fixture-expiry", "codex")
	if !store.BeginSave("fixture-expiry", "codex") {
		t.Fatal("save did not begin")
	}
	store.mu.Lock()
	session := store.sessions["fixture-expiry"]
	session.ExpiresAt = time.Now().Add(-time.Minute)
	store.sessions["fixture-expiry"] = session
	store.mu.Unlock()
	if store.Cancel("fixture-expiry") {
		t.Fatal("expired active commit was cancelled")
	}
	store.Complete("fixture-expiry")
	session, exists := store.Get("fixture-expiry")
	if !exists || !session.Completed {
		t.Fatal("committed account disappeared from login status")
	}
}
