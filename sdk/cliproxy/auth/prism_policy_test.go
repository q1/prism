package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

func prismClaudeFixture(id string, now time.Time, shortReset, weeklyReset time.Duration, fableRemaining float64) *Auth {
	return &Auth{ID: id, Provider: "claude", Attributes: map[string]string{"auth_kind": "oauth", "plan_type": "max_20x"}, Quota: QuotaState{
		ObservedAt: now,
		Signals: map[string]string{
			"Anthropic-Ratelimit-Unified-5h-Utilization":    "0.2",
			"Anthropic-Ratelimit-Unified-5h-Reset":          strconv.FormatInt(now.Add(shortReset).Unix(), 10),
			"Anthropic-Ratelimit-Unified-7d-Utilization":    "0.2",
			"Anthropic-Ratelimit-Unified-7d-Reset":          strconv.FormatInt(now.Add(weeklyReset).Unix(), 10),
			"Anthropic-Ratelimit-Unified-7d_oi-Utilization": strconv.FormatFloat((100-fableRemaining)/100, 'f', -1, 64),
			"Anthropic-Ratelimit-Unified-7d_oi-Reset":       strconv.FormatInt(now.Add(weeklyReset).Unix(), 10),
		},
	}}
}

func TestPrismEligibilityScenarioMatrix(t *testing.T) {
	now := time.Unix(1800000000, 0)
	cases := []struct {
		name, model, reason string
		change              func(*Auth)
	}{
		{"healthy", "claude-fable-5-1", "", func(a *Auth) {}},
		{"reserve threshold", "claude-fable-5-1", "reserve_avoided", func(a *Auth) { a.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Utilization"] = "0.97" }},
		{"hard exhaustion", "claude-fable-5-1", "provider_exhausted", func(a *Auth) { a.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Utilization"] = "1" }},
		{"fable does not block opus", "claude-opus-4-6", "", func(a *Auth) { a.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Utilization"] = "1" }},
		{"overall blocks fable", "claude-fable-5-1", "provider_exhausted", func(a *Auth) { a.Quota.Signals["Anthropic-Ratelimit-Unified-7d-Utilization"] = "1" }},
		{"missing quota", "claude-fable-5-1", "quota_unknown", func(a *Auth) { delete(a.Quota.Signals, "Anthropic-Ratelimit-Unified-7d_oi-Utilization") }},
		{"stale quota", "claude-fable-5-1", "quota_unknown", func(a *Auth) { a.Quota.ObservedAt = now.Add(-PrismQuotaMaxAge - time.Second) }},
		{"future quota", "claude-fable-5-1", "quota_unknown", func(a *Auth) { a.Quota.ObservedAt = now.Add(time.Second) }},
		{"reset requires remeasurement", "claude-fable-5-1", "quota_unknown", func(a *Auth) {
			a.Quota.Signals["Anthropic-Ratelimit-Unified-5h-Reset"] = strconv.FormatInt(now.Unix(), 10)
		}},
		{"disabled", "claude-fable-5-1", "disabled", func(a *Auth) { a.Disabled = true }},
		{"reserve disabled", "claude-fable-5-1", "", func(a *Auth) {
			a.Metadata = map[string]any{PrismReservePercentKey: nil}
			a.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Utilization"] = "0.99"
		}},
		{"reserve zero still honors provider", "claude-fable-5-1", "provider_exhausted", func(a *Auth) {
			a.Metadata = map[string]any{PrismReservePercentKey: float64(0)}
			a.Quota.Signals["Anthropic-Ratelimit-Unified-7d_oi-Utilization"] = "1"
		}},
		{"grok no invented subscription windows", "grok-4", "", func(a *Auth) { a.Provider = "grok"; a.Quota = QuotaState{} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := prismClaudeFixture("a", now, time.Hour, 24*time.Hour, 50)
			tc.change(a)
			state := PrismAccountEligibility(a, tc.model, now)
			if state.Reason != tc.reason || state.Available != (tc.reason == "") {
				t.Fatalf("eligibility = %+v, want reason %q", state, tc.reason)
			}
		})
	}
}

func TestPrismResetPriorityAcceptedExamples(t *testing.T) {
	now := time.Unix(1800000000, 0)
	cases := []struct {
		name     string
		accounts []*Auth
		want     string
	}{
		{"close resets favor weekly headroom", []*Auth{prismClaudeFixture("a", now, 20*time.Minute, 6*24*time.Hour, 5), prismClaudeFixture("b", now, 35*time.Minute, 24*time.Hour, 60)}, "b"},
		{"weekly expiry favors use now", []*Auth{prismClaudeFixture("a", now, time.Hour, 2*time.Hour, 10), prismClaudeFixture("b", now, time.Hour, 6*24*time.Hour, 60)}, "a"},
		{"reset tolerance is not transitive", []*Auth{prismClaudeFixture("a", now, 20*time.Minute, 6*24*time.Hour, 5), prismClaudeFixture("b", now, 45*time.Minute, 24*time.Hour, 60), prismClaudeFixture("c", now, 70*time.Minute, time.Hour, 90)}, "b"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := &ResetPrioritySelector{now: func() time.Time { return now }}
			picked, err := s.Pick(context.Background(), "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, tc.accounts)
			if err != nil || picked.ID != tc.want {
				t.Fatalf("picked %v, err %v, want %s", picked, err, tc.want)
			}
		})
	}
}

func TestPrismSelectionSpreadsInflightAndRotatesUnknownPlans(t *testing.T) {
	now := time.Unix(1800000000, 0)
	s := &ResetPrioritySelector{now: func() time.Time { return now }}
	a := prismClaudeFixture("a", now, time.Hour, 2*time.Hour, 10)
	b := prismClaudeFixture("b", now, time.Hour, 6*24*time.Hour, 60)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	picked, err := s.Pick(ctx, "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, []*Auth{a, b})
	if err != nil || picked.ID != "a" {
		t.Fatal("initial request should use expiring weekly quota")
	}
	picked, err = s.Pick(context.Background(), "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, []*Auth{a, b})
	if err != nil || picked.ID != "b" {
		t.Fatal("concurrent request should spread available capacity")
	}
	delete(a.Attributes, "plan_type")
	delete(b.Attributes, "plan_type")
	s = &ResetPrioritySelector{now: func() time.Time { return now }}
	for _, want := range []string{"a", "b", "a"} {
		picked, err = s.Pick(context.Background(), "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, []*Auth{a, b})
		if err != nil || picked.ID != want {
			t.Fatalf("unknown plans should rotate, want %s", want)
		}
	}
}

func TestPrismPoolErrorsSuppressFallbackAndExplainReserve(t *testing.T) {
	now := time.Unix(1800000000, 0)
	s := &ResetPrioritySelector{now: func() time.Time { return now }}
	a := prismClaudeFixture("private-account.json", now, time.Hour, 24*time.Hour, 3)
	_, err := s.Pick(context.Background(), "claude", "claude-fable-5-1", cliproxyexecutor.Options{}, []*Auth{a})
	var pool *prismPoolError
	if !errors.As(err, &pool) || pool.reason != "reserve_avoided" || pool.StatusCode() != http.StatusTooManyRequests || pool.Headers().Get("X-Prism-Fallback-Allowed") != "false" {
		t.Fatalf("bad pool error: %v", err)
	}
	if strings.Contains(err.Error(), a.ID) {
		t.Fatal("error leaked account identity")
	}
	var payload map[string]any
	if json.Unmarshal([]byte(err.Error()), &payload) != nil || payload["prism"].(map[string]any)["fallbackAllowed"] != false {
		t.Fatal("missing wire fallback refusal")
	}
}

func TestPrismManagerSelectionKeepsPoolClassification(t *testing.T) {
	now := time.Now()
	manager := NewManager(nil, &ResetPrioritySelector{}, nil)
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})
	a := prismClaudeFixture("prism-manager-test", now, time.Hour, 24*time.Hour, 3)
	_, err := manager.Register(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(a.ID, "claude", []*registry.ModelInfo{{ID: "claude-fable-5-1"}})
	t.Cleanup(func() { reg.UnregisterClient(a.ID) })
	_, err = manager.SelectAuth(context.Background(), "claude", "claude-fable-5-1", cliproxyexecutor.Options{})
	var pool *prismPoolError
	if !errors.As(err, &pool) || pool.reason != "reserve_avoided" {
		t.Fatalf("manager erased reserve reason: %v", err)
	}
}

func TestPrismPolicySurvivesBalancingStrategyChanges(t *testing.T) {
	for _, selector := range []Selector{&RoundRobinSelector{}, &WeightedRoundRobinSelector{}, &FillFirstSelector{}, NewSessionAffinitySelector(&RoundRobinSelector{})} {
		t.Run(fmt.Sprintf("%T", selector), func(t *testing.T) {
			manager := NewManager(nil, selector, nil)
			manager.SetConfig(&config.Config{Routing: config.RoutingConfig{PrismPolicy: true}})
			manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})
			a := prismClaudeFixture(t.Name(), time.Now(), time.Hour, 24*time.Hour, 3)
			_, err := manager.Register(context.Background(), a)
			if err != nil {
				t.Fatal(err)
			}
			reg := registry.GetGlobalRegistry()
			reg.RegisterClient(a.ID, "claude", []*registry.ModelInfo{{ID: "claude-fable-5-1"}})
			t.Cleanup(func() { reg.UnregisterClient(a.ID); manager.StopAutoRefresh() })
			_, err = manager.Execute(context.Background(), []string{"claude"}, cliproxyexecutor.Request{Model: "claude-fable-5-1"}, cliproxyexecutor.Options{})
			var pool *prismPoolError
			if !errors.As(err, &pool) || pool.reason != "reserve_avoided" {
				t.Fatalf("strategy bypassed policy: %v", err)
			}
			if state := manager.ModelEligibility(a, "claude-fable-5-1", time.Now()); state.Available || state.Reason != "reserve_avoided" {
				t.Fatal("aggregate disagrees with routing")
			}
		})
	}
}

func TestPrismServingLeaseIsMandatoryForEverySelector(t *testing.T) {
	now := time.Now()
	account := &Auth{ID: "leased-fixture", Provider: "xai", Metadata: map[string]any{
		"refresh_disabled": true, "prism_serving_expires_at": now.Add(-time.Minute).Format(time.RFC3339),
	}}
	for _, selector := range []Selector{&RoundRobinSelector{}, &WeightedRoundRobinSelector{}, &FillFirstSelector{}, &ResetPrioritySelector{}} {
		if _, errPick := selector.Pick(context.Background(), "xai", "grok", cliproxyexecutor.Options{}, []*Auth{account}); errPick == nil {
			t.Fatal("balancing strategy bypassed expired lease")
		}
	}
	if state := PrismAccountEligibility(account, "grok", now); state.Reason != "replica_lease_expired" {
		t.Fatal("expired lease classification missing")
	}
	account.Metadata["prism_serving_expires_at"] = now.Add(time.Hour).Format(time.RFC3339)
	if !PrismAccountEligibility(account, "grok", now).Available {
		t.Fatal("valid lease blocked native Grok eligibility")
	}
	account.Metadata["refresh_disabled"] = false
	if PrismAccountEligibility(account, "grok", now).Available {
		t.Fatal("serving lease admitted refresh authority")
	}
	account.Metadata["refresh_disabled"] = true
	account.Metadata["prism_serving_expires_at"] = 123
	if PrismAccountEligibility(account, "grok", now).Available {
		t.Fatal("malformed serving lease accepted")
	}
}

func TestPrismAffinityRechecksObservedQuotaAfterBinding(t *testing.T) {
	ctx := context.Background()
	selector := NewSessionAffinitySelector(&RoundRobinSelector{})
	t.Cleanup(selector.Stop)
	manager := NewManager(nil, selector, nil)
	manager.SetConfig(&config.Config{Routing: config.RoutingConfig{PrismPolicy: true}})
	manager.RegisterExecutor(schedulerProviderTestExecutor{provider: "claude"})
	const model = "claude-fable-5-1"
	account := prismClaudeFixture(t.Name(), time.Now(), time.Hour, 24*time.Hour, 50)
	if _, err := manager.Register(ctx, account); err != nil {
		t.Fatal(err)
	}
	reg := registry.GetGlobalRegistry()
	reg.RegisterClient(account.ID, "claude", []*registry.ModelInfo{{ID: model}})
	t.Cleanup(func() { reg.UnregisterClient(account.ID) })
	opts := cliproxyexecutor.Options{Headers: http.Header{"X-Session-Id": []string{"fixture-session"}}}
	if _, err := manager.SelectAuth(ctx, "claude", model, opts); err != nil {
		t.Fatal(err)
	}
	if _, status := manager.LookupSessionAffinity("claude", model, "fixture-session"); status != "bound" {
		t.Fatalf("expected established affinity, got %s", status)
	}
	update := func(quota QuotaState, reserve any) {
		t.Helper()
		current, _ := manager.GetByID(account.ID)
		current.Quota = quota
		current.Metadata = map[string]any{PrismReservePercentKey: reserve}
		if _, err := manager.Update(ctx, current); err != nil {
			t.Fatal(err)
		}
	}
	reserved := prismClaudeFixture(account.ID, time.Now(), time.Hour, 24*time.Hour, 2).Quota
	update(reserved, float64(3))
	assertBlocked := func(reason string) {
		t.Helper()
		_, err := manager.SelectAuth(ctx, "claude", model, opts)
		var pool *prismPoolError
		if !errors.As(err, &pool) || pool.reason != reason {
			t.Fatalf("bound session bypassed %s: %v", reason, err)
		}
	}
	assertBlocked("reserve_avoided")
	update(reserved, nil)
	if _, err := manager.SelectAuth(ctx, "claude", model, opts); err != nil {
		t.Fatalf("null reserve did not restore observed allowance: %v", err)
	}
	update(QuotaState{}, nil)
	assertBlocked("quota_unknown")
}
