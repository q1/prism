package auth

import (
	"testing"
	"time"
)

func TestObservedQuotaWindows(t *testing.T) {
	now := time.Unix(1000, 0)
	quota := QuotaState{ObservedAt: now, Signals: map[string]string{"X-Codex-Primary-Window-Minutes": "10080", "X-Codex-Primary-Used-Percent": "100", "X-Codex-Primary-Reset-After-Seconds": "120"}}
	windows := ObservedQuotaWindows("codex", quota, now)
	if _, ok := windows["five_hour"]; ok {
		t.Fatal("weekly quota mislabeled as session")
	}
	if windows["weekly"].UsedPercent != 100 || !windows["weekly"].Known {
		t.Fatal("weekly measurement missing")
	}
	auth := &Auth{Provider: "codex", Quota: quota}
	if blocked, _, until := isAuthBlockedForModel(auth, "model", now); !blocked || !until.Equal(now.Add(120*time.Second)) {
		t.Fatal("exhausted credential still routable")
	}
	if blocked, _, _ := isAuthBlockedForModel(auth, "model", now.Add(121*time.Second)); blocked {
		t.Fatal("reset did not restore eligibility")
	}
	quota.Signals["X-Codex-Active-Limit"] = "codex_other_model"
	if len(ObservedQuotaWindows("codex", quota, now)) != 0 {
		t.Fatal("model quota leaked into account quota")
	}
}
func TestClaudeMeasuredFractionAndUnknownQuota(t *testing.T) {
	now := time.Unix(1000, 0)
	quota := QuotaState{ObservedAt: now, Signals: map[string]string{"Anthropic-Ratelimit-Unified-5h-Utilization": "0.53", "Anthropic-Ratelimit-Unified-5h-Reset": "2000"}}
	windows := ObservedQuotaWindows("claude", quota, now)
	if windows["five_hour"].UsedPercent != 53 {
		t.Fatal("Claude fraction was not converted")
	}
	if len(ObservedQuotaWindows("claude", QuotaState{}, now)) != 0 {
		t.Fatal("unknown quota was invented")
	}
	quota.Signals["Anthropic-Ratelimit-Unified-5h-Utilization"] = "NaN"
	if len(ObservedQuotaWindows("claude", quota, now)) != 0 {
		t.Fatal("nonfinite quota accepted")
	}
	if len(ObservedQuotaWindows("grok", quota, now)) != 0 {
		t.Fatal("unsupported quota was invented")
	}
}

func TestClaudeFableAliasesPreserveStricterObservation(t *testing.T) {
	now := time.Unix(1000, 0)
	quota := QuotaState{ObservedAt: now, Signals: map[string]string{
		"Anthropic-Ratelimit-Unified-7d-fable-Utilization": "1",
		"Anthropic-Ratelimit-Unified-7d-fable-Reset":       "3000",
		"Anthropic-Ratelimit-Unified-7d-fable-Status":      "rejected",
		"Anthropic-Ratelimit-Unified-7d_oi-Utilization":    "0.1",
		"Anthropic-Ratelimit-Unified-7d_oi-Reset":          "2000",
	}}
	window := ObservedQuotaWindows("claude", quota, now)["fable"]
	if !window.Known || !window.HardLimited || window.UsedPercent != 100 || window.ResetAt == nil || window.ResetAt.Unix() != 3000 {
		t.Fatal("Fable alias erased a stricter measured limit")
	}
	auth := &Auth{Provider: "claude", Quota: quota}
	if blocked, _ := observedQuotaBlocked(auth, "claude-fable-5", now); !blocked {
		t.Fatal("Fable remained routable while an alias is exhausted")
	}
	if blocked, _ := observedQuotaBlocked(auth, "claude-sonnet-4-6", now); blocked {
		t.Fatal("Fable aliases blocked an unrelated model")
	}
}
