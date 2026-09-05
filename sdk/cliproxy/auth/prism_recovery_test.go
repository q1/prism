package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type prismRecoveryExecutor struct {
	schedulerProviderTestExecutor
	usage func(context.Context, *Auth) (http.Header, error)
	probe func(context.Context, *Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error)
}

func (e *prismRecoveryExecutor) PrismQuota(ctx context.Context, a *Auth) (http.Header, error) {
	return e.usage(ctx, a)
}
func (e *prismRecoveryExecutor) Execute(ctx context.Context, a *Auth, r cliproxyexecutor.Request, _ cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return e.probe(ctx, a, r)
}

func prismRecoveryFixture(t *testing.T) (*Manager, *Auth, *prismRecoveryWorker, *prismRecoveryExecutor) {
	t.Helper()
	m := NewManager(nil, &ResetPrioritySelector{}, nil)
	a := &Auth{ID: t.Name(), Provider: "claude", Metadata: map[string]any{"access_token": "synthetic-access", "type": "claude"}, Attributes: map[string]string{"auth_kind": "oauth"}}
	if _, err := m.Register(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	a, _ = m.GetByID(a.ID)
	e := &prismRecoveryExecutor{schedulerProviderTestExecutor: schedulerProviderTestExecutor{provider: "claude"}}
	e.usage = func(context.Context, *Auth) (http.Header, error) { return nil, nil }
	e.probe = func(context.Context, *Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		return cliproxyexecutor.Response{}, nil
	}
	m.RegisterExecutor(e)
	r := registry.GetGlobalRegistry()
	r.RegisterClient(a.ID, "claude", []*registry.ModelInfo{{ID: "claude-fable-5-1"}})
	t.Cleanup(func() { r.UnregisterClient(a.ID) })
	return m, a, newPrismRecoveryWorker(m), e
}

func TestPrismRecoveryUsesUsageBeforeBoundedProbe(t *testing.T) {
	m, a, w, e := prismRecoveryFixture(t)
	now := time.Now()
	w.now = func() time.Time { return now }
	usageCalls, probeCalls := 0, 0
	e.usage = func(context.Context, *Auth) (http.Header, error) { usageCalls++; return nil, nil }
	e.probe = func(_ context.Context, _ *Auth, request cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		probeCalls++
		if usageCalls != 1 {
			t.Fatal("probe ran before usage check")
		}
		var body map[string]any
		if json.Unmarshal(request.Payload, &body) != nil || body["max_tokens"] != float64(16) || body["tools"] != nil {
			t.Fatal("probe output/tools are not bounded")
		}
		return cliproxyexecutor.Response{}, nil
	}
	w.tick(context.Background())
	current, _ := m.GetByID(a.ID)
	if usageCalls != 1 || probeCalls != 1 || PrismAccountEligibility(current, "claude-fable-5-1", now).Reason != "quota_unknown" {
		t.Fatal("successful probe invented quota eligibility")
	}
	now = now.Add(3 * time.Minute)
	w.tick(context.Background())
	if usageCalls != 2 || probeCalls != 1 {
		t.Fatal("probe hourly bound was bypassed")
	}
}

func TestPrismRecoveryFreshUsageAvoidsInference(t *testing.T) {
	m, a, w, e := prismRecoveryFixture(t)
	now := time.Now()
	w.now = func() time.Time { return now }
	fresh := prismClaudeFixture("fixture", now, time.Hour, 24*time.Hour, 50)
	e.usage = func(context.Context, *Auth) (http.Header, error) {
		headers := http.Header{}
		for k, v := range fresh.Quota.Signals {
			headers.Set(k, v)
		}
		return headers, nil
	}
	e.probe = func(context.Context, *Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		t.Fatal("fresh usage must avoid probe")
		return cliproxyexecutor.Response{}, nil
	}
	w.tick(context.Background())
	current, _ := m.GetByID(a.ID)
	if !PrismAccountEligibility(current, "claude-fable-5-1", now).Available {
		t.Fatal("fresh observations did not restore eligibility")
	}
}

func TestPrismRecoverySingleFlightAndReplicaExclusion(t *testing.T) {
	m, a, w, e := prismRecoveryFixture(t)
	started, release, done := make(chan struct{}), make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	e.usage = func(context.Context, *Auth) (http.Header, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return nil, nil
	}
	go func() { w.recover(context.Background(), a, "claude-fable-5-1"); close(done) }()
	<-started
	w.recover(context.Background(), a, "claude-fable-5-1")
	close(release)
	<-done
	if calls.Load() != 1 {
		t.Fatal("overlapping recovery request")
	}
	a, _ = m.GetByID(a.ID)
	a.Metadata["refresh_disabled"] = true
	if _, err := m.Update(context.Background(), a); err != nil {
		t.Fatal(err)
	}
	w = newPrismRecoveryWorker(m)
	w.tick(context.Background())
	if calls.Load() != 1 {
		t.Fatal("serving replica started recovery side effects")
	}
}

func TestPrismRecoveryPersistentAuthFailureAndRevokedProbe(t *testing.T) {
	m, a, w, e := prismRecoveryFixture(t)
	e.probe = func(context.Context, *Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		return cliproxyexecutor.Response{}, &Error{HTTPStatus: 401, Code: "unauthorized", Message: "synthetic denial"}
	}
	w.tick(context.Background())
	current, _ := m.GetByID(a.ID)
	if !current.RequiresLogin() || PrismAccountEligibility(current, "claude-fable-5-1", time.Now()).Reason != "sign_in_required" {
		t.Fatal("unrecoverable auth was not quarantined")
	}
	ctx := context.WithValue(context.Background(), prismProbeGenerationKey{}, prismProbeGeneration{current.ID, current.Generation, current.RegistrationEpoch})
	m.MarkResult(ctx, Result{AuthID: a.ID, Provider: "claude", Model: "claude-fable-5-1", Success: true})
	current, _ = m.GetByID(a.ID)
	if !current.RequiresLogin() || current.Success != 0 {
		t.Fatal("revoked probe result mutated quarantined account")
	}
}

func TestPrismLeasedReplicaObservesUsageWithoutRefreshOrProbe(t *testing.T) {
	m, a, w, e := prismRecoveryFixture(t)
	now := time.Now()
	w.now = func() time.Time { return now }
	a.Metadata["refresh_disabled"] = true
	a.Metadata["prism_serving_expires_at"] = now.Add(time.Hour).Format(time.RFC3339)
	_, _ = m.Update(context.Background(), a)
	usageCalls := 0
	e.usage = func(context.Context, *Auth) (http.Header, error) { usageCalls++; return nil, nil }
	e.probe = func(context.Context, *Auth, cliproxyexecutor.Request) (cliproxyexecutor.Response, error) {
		t.Fatal("serving-only replica attempted synthetic inference recovery")
		return cliproxyexecutor.Response{}, nil
	}
	w.tick(context.Background())
	if usageCalls != 1 {
		t.Fatal("leased replica could not read provider usage")
	}
	now = now.Add(3 * time.Minute)
	fresh := prismClaudeFixture("fixture", now, time.Hour, 24*time.Hour, 50)
	e.usage = func(context.Context, *Auth) (http.Header, error) {
		usageCalls++
		headers := http.Header{}
		for key, value := range fresh.Quota.Signals {
			headers.Set(key, value)
		}
		return headers, nil
	}
	w.tick(context.Background())
	current, _ := m.GetByID(a.ID)
	if !PrismAccountEligibility(current, "claude-fable-5-1", now).Available || !authRefreshDisabled(current) || usageCalls != 2 {
		t.Fatal("usage-only observation did not restore leased serving eligibility")
	}
	now = now.Add(time.Hour)
	w.tick(context.Background())
	if usageCalls != 2 {
		t.Fatal("expired replica lease made a provider request")
	}
}
