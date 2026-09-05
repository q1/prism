package auth

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

// PrismQuotaMaxAge is the conservative observation lifetime for reset-priority.
// Crossing a reset requires a fresh measurement, never a guessed empty allowance.
const PrismQuotaMaxAge = 15 * time.Minute
const PrismReservePercentKey = "reserve_percent"

// PrismReservePercent returns the centrally stored soft threshold. An explicit
// null disables it; malformed persisted values fail back to the default.
func PrismReservePercent(auth *Auth) *float64 {
	value := 3.0
	if auth != nil {
		if raw, exists := auth.Metadata[PrismReservePercentKey]; exists {
			if raw == nil {
				return nil
			}
			var parsed float64
			switch number := raw.(type) {
			case float64:
				parsed = number
			case json.Number:
				var errParse error
				parsed, errParse = number.Float64()
				if errParse != nil {
					return &value
				}
			case int:
				parsed = float64(number)
			default:
				return &value
			}
			if !math.IsNaN(parsed) && !math.IsInf(parsed, 0) && parsed >= 0 && parsed <= 100 {
				value = parsed
			}
		}
	}
	return &value
}

// PrismEligibility contains only a safe routing classification, never account identity.
type PrismEligibility struct {
	Available      bool       `json:"available"`
	Reason         string     `json:"reason,omitempty"`
	NextEligibleAt *time.Time `json:"nextEligibleAt,omitempty"`
}

func prismModel(auth *Auth, model string) string {
	if auth != nil && auth.Attributes["prism_selection_model"] != "" {
		return auth.Attributes["prism_selection_model"]
	}
	return model
}

func prismApplicableWindows(auth *Auth, model string, now time.Time) (map[string]ObservedQuotaWindow, time.Time) {
	quota := auth.Quota
	// Model-specific Codex observations can be stricter than the account snapshot.
	for key, state := range auth.ModelStates {
		if state != nil && canonicalModelKey(key) == canonicalModelKey(model) && state.Quota.ObservedAt.After(quota.ObservedAt) {
			quota = state.Quota
		}
	}
	windows := ObservedQuotaWindows(auth.Provider, quota, now)
	if !strings.Contains(strings.ToLower(model), "fable") {
		delete(windows, "fable")
	}
	return windows, quota.ObservedAt
}

func nativeAccountEligibility(auth *Auth, model string, now time.Time) PrismEligibility {
	if auth == nil {
		return PrismEligibility{Reason: "account_unavailable"}
	}
	model = prismModel(auth, model)
	if present, valid := prismServingLease(auth, now); present && !valid {
		return PrismEligibility{Reason: "replica_lease_expired"}
	}
	if auth.RequiresLogin() {
		return PrismEligibility{Reason: "sign_in_required"}
	}
	if auth.Disabled || auth.Status == StatusDisabled {
		return PrismEligibility{Reason: "disabled"}
	}
	if expiry, ok := auth.AccessTokenExpirationTime(); ok && !expiry.IsZero() && !expiry.After(now) {
		return PrismEligibility{Reason: "credential_expired"}
	}
	if blocked, reason, until := isAuthBlockedForModel(auth, model, now); blocked {
		result := PrismEligibility{Reason: "account_unavailable"}
		if reason == blockReasonCooldown {
			result.Reason = "provider_exhausted"
		}
		if until.After(now) {
			result.NextEligibleAt = &until
		}
		return result
	}
	return PrismEligibility{Available: true}
}

// A serving lease is independent of balancing strategy, quota freshness and
// provider token expiry. A malformed lease fails closed.
func prismServingLease(account *Auth, now time.Time) (bool, bool) {
	if account == nil {
		return false, false
	}
	raw, exists := account.Metadata["prism_serving_expires_at"]
	if !exists {
		return false, false
	}
	value, ok := raw.(string)
	if !ok {
		return true, false
	}
	expires, errParse := time.Parse(time.RFC3339Nano, value)
	return true, errParse == nil && expires.After(now) && authRefreshDisabled(account)
}

// PrismAccountEligibility adds subscription policy to native routing gates.
func PrismAccountEligibility(auth *Auth, model string, now time.Time) PrismEligibility {
	if state := nativeAccountEligibility(auth, model, now); !state.Available {
		return state
	}
	model = prismModel(auth, model)
	if !ProviderSupportsQuotaObservation(auth.Provider) || auth.AuthKind() == AuthKindAPIKey {
		return PrismEligibility{Available: true}
	}
	windows, observedAt := prismApplicableWindows(auth, model, now)
	if observedAt.IsZero() || observedAt.After(now) || now.Sub(observedAt) > PrismQuotaMaxAge {
		return PrismEligibility{Reason: "quota_unknown"}
	}
	required := []string{"five_hour", "seven_day"}
	if strings.EqualFold(auth.Provider, "codex") {
		required = []string{"five_hour", "weekly"}
	}
	if strings.EqualFold(auth.Provider, "claude") && strings.Contains(strings.ToLower(model), "fable") {
		required = append(required, "fable")
	}
	for _, name := range required {
		window, exists := windows[name]
		if !exists || !window.Known || window.ResetAt == nil || !window.ResetAt.After(now) {
			return PrismEligibility{Reason: "quota_unknown"}
		}
	}
	reserve := PrismReservePercent(auth)
	var exhaustion, avoidance time.Time
	for _, window := range windows {
		if !window.Known || window.ResetAt == nil {
			return PrismEligibility{Reason: "quota_unknown"}
		}
		if window.UsedPercent >= 100 || window.HardLimited {
			if window.ResetAt.After(exhaustion) {
				exhaustion = *window.ResetAt
			}
		} else if reserve != nil && 100-window.UsedPercent <= *reserve {
			if window.ResetAt.After(avoidance) {
				avoidance = *window.ResetAt
			}
		}
	}
	if !exhaustion.IsZero() {
		return PrismEligibility{Reason: "provider_exhausted", NextEligibleAt: &exhaustion}
	}
	if !avoidance.IsZero() {
		return PrismEligibility{Reason: "reserve_avoided", NextEligibleAt: &avoidance}
	}
	return PrismEligibility{Available: true}
}

func (m *Manager) prismPolicyEnabled(selector Selector) bool {
	cfg := m.runtimeConfigSnapshot()
	return resetPrioritySelector(selector) != nil || (cfg != nil && cfg.Routing.PrismPolicy)
}

// PrismPolicyEnabled separates central eligibility from the selected order.
func (m *Manager) PrismPolicyEnabled() bool { return m != nil && m.prismPolicyEnabled(m.Selector()) }

// ModelEligibility reports the same effective policy used by request selection.
func (m *Manager) ModelEligibility(account *Auth, model string, now time.Time) PrismEligibility {
	if m.PrismPolicyEnabled() {
		return PrismAccountEligibility(account, model, now)
	}
	return nativeAccountEligibility(account, model, now)
}

type prismPoolError struct {
	model, reason string
	next          *time.Time
}

func (e *prismPoolError) Error() string {
	body, _ := json.Marshal(map[string]any{
		"error": map[string]any{"code": "prism_" + e.reason, "message": "The selected model has no eligible account", "model": e.model, "reason": e.reason, "nextEligibleAt": e.next},
		"prism": map[string]any{"fallbackAllowed": false},
	})
	return string(body)
}
func (e *prismPoolError) StatusCode() int {
	if e.reason == "provider_exhausted" || e.reason == "reserve_avoided" {
		return http.StatusTooManyRequests
	}
	return http.StatusServiceUnavailable
}
func (e *prismPoolError) Headers() http.Header {
	return http.Header{"X-Prism-Fallback-Allowed": {"false"}}
}

// ResetPrioritySelector selects per inference request. It compares only windows
// with the same denominator, never percentages across plans or quota windows.
type ResetPrioritySelector struct {
	mu         sync.Mutex
	lastPicked map[string]string
	inFlight   map[string]int
	now        func() time.Time
}

func resetPrioritySelector(selector Selector) *ResetPrioritySelector {
	if policy, ok := selector.(*ResetPrioritySelector); ok {
		return policy
	}
	if affinity, ok := selector.(*SessionAffinitySelector); ok {
		return resetPrioritySelector(affinity.fallback)
	}
	return nil
}

func (s *ResetPrioritySelector) Pick(ctx context.Context, provider, model string, opts cliproxyexecutor.Options, auths []*Auth) (*Auth, error) {
	now := time.Now()
	if s.now != nil {
		now = s.now()
	}
	available := make([]*Auth, 0, len(auths))
	reasons := map[string]int{}
	var next *time.Time
	for _, account := range auths {
		state := PrismAccountEligibility(account, model, now)
		if state.Available {
			available = append(available, account)
		} else {
			reasons[state.Reason]++
			if state.NextEligibleAt != nil && (next == nil || state.NextEligibleAt.Before(*next)) {
				stamp := *state.NextEligibleAt
				next = &stamp
			}
		}
	}
	if len(available) == 0 {
		reason := "pool_unavailable"
		for _, candidate := range []string{"sign_in_required", "quota_unknown", "reserve_avoided", "provider_exhausted"} {
			if reasons[candidate] == len(auths) && len(auths) > 0 {
				reason = candidate
				break
			}
		}
		return nil, &prismPoolError{model: model, reason: reason, next: next}
	}
	available = highestPriorityAuths(available)
	available = preferCodexWebsocketAuths(ctx, provider, available)
	// Anchor the tolerance to the earliest reset, preventing transitive buckets.
	var earliest time.Time
	for _, account := range available {
		windows, _ := prismApplicableWindows(account, prismModel(account, model), now)
		if reset := windows["five_hour"].ResetAt; reset != nil && (earliest.IsZero() || reset.Before(earliest)) {
			earliest = *reset
		}
	}
	if !earliest.IsZero() {
		bucket := available[:0]
		for _, account := range available {
			windows, _ := prismApplicableWindows(account, prismModel(account, model), now)
			if reset := windows["five_hour"].ResetAt; reset != nil && !reset.After(earliest.Add(30*time.Minute)) {
				bucket = append(bucket, account)
			}
		}
		available = bucket
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.inFlight == nil {
		s.inFlight = map[string]int{}
		s.lastPicked = map[string]string{}
	}
	// Weekly capacity per time until reset expresses expiry urgency within each
	// account's own allowance. Compare only same-provider, same-plan candidates.
	score := func(account *Auth) float64 {
		windows, _ := prismApplicableWindows(account, prismModel(account, model), now)
		name := "seven_day"
		if account.Provider == "codex" {
			name = "weekly"
		}
		if strings.Contains(strings.ToLower(prismModel(account, model)), "fable") {
			name = "fable"
		}
		window := windows[name]
		if window.ResetAt == nil {
			return 0
		}
		return (100 - window.UsedPercent) / math.Max(1, window.ResetAt.Sub(now).Hours())
	}
	plan := func(account *Auth) string {
		tier := strings.TrimSpace(account.Attributes["plan_type"])
		if tier == "" {
			tier, _ = account.Metadata["plan_type"].(string)
		}
		if tier == "" {
			for key, value := range account.Quota.Signals {
				if strings.EqualFold(key, "X-Codex-Plan-Type") {
					tier = value
				}
			}
		}
		if tier == "" {
			return ""
		}
		return account.Provider + ":" + tier
	}
	commonPlan := plan(available[0])
	comparable := commonPlan != ""
	for _, account := range available[1:] {
		comparable = comparable && plan(account) == commonPlan
	}
	sort.Slice(available, func(i, j int) bool {
		a, b := available[i], available[j]
		// Spread concurrently admitted requests before spending another observed
		// allowance slice. This is a load estimate, not a token reservation.
		if s.inFlight[a.ID] != s.inFlight[b.ID] {
			return s.inFlight[a.ID] < s.inFlight[b.ID]
		}
		if comparable && score(a) != score(b) {
			return score(a) > score(b)
		}
		return a.ID < b.ID
	})
	best := available[0]
	// Equal scores rotate deterministically, including providers without quotas.
	peers := make([]*Auth, 0, len(available))
	for _, account := range available {
		if s.inFlight[account.ID] == s.inFlight[best.ID] && (!comparable || score(account) == score(best)) {
			peers = append(peers, account)
		}
	}
	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })
	key := provider + ":" + canonicalModelKey(model)
	best = peers[successorIndex(peers, s.lastPicked[key])]
	if len(s.lastPicked) >= 4096 {
		clear(s.lastPicked)
	}
	s.lastPicked[key] = best.ID
	if ctx != nil && ctx.Done() != nil {
		id := best.ID
		s.inFlight[id]++
		context.AfterFunc(ctx, func() {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.inFlight[id]--
			if s.inFlight[id] <= 0 {
				delete(s.inFlight, id)
			}
		})
	}
	return best, nil
}

// A signed lease extension does not invalidate measurements of an unchanged
// provider credential. The supervisor separately fences any signed policy or
// inventory change before replacement; this check is conservative on its own.
func prismSameServingCredential(current, next *Auth) bool {
	if current == nil || next == nil || current.Provider != next.Provider || current.Disabled != next.Disabled || current.Prefix != next.Prefix || current.ProxyURL != next.ProxyURL {
		return false
	}
	snapshot := func(account *Auth) ([]byte, bool) {
		if _, leased := account.Metadata["prism_serving_expires_at"]; !leased || account.Metadata["refresh_disabled"] != true {
			return nil, false
		}
		metadata := make(map[string]any, len(account.Metadata))
		for name, value := range account.Metadata {
			if name != "prism_serving_expires_at" {
				metadata[name] = value
			}
		}
		encoded, errEncode := json.Marshal(metadata)
		return encoded, errEncode == nil
	}
	a, okA := snapshot(current)
	b, okB := snapshot(next)
	return okA && okB && bytes.Equal(a, b)
}
