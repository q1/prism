package auth

import (
	"context"
	"encoding/json"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
	sdktranslator "github.com/router-for-me/CLIProxyAPI/v7/sdk/translator"
)

// PrismQuotaObserver is an optional provider usage-read operation. It must not
// refresh credentials: the manager's existing serialized refresh path owns that.
type PrismQuotaObserver interface {
	PrismQuota(context.Context, *Auth) (http.Header, error)
}

type prismProbeGenerationKey struct{}
type prismProbeGeneration struct {
	id                string
	generation, epoch uint64
}

func prismProbeMayCommit(ctx context.Context, account *Auth) bool {
	if ctx == nil {
		return true
	}
	stamp, probe := ctx.Value(prismProbeGenerationKey{}).(prismProbeGeneration)
	return !probe || (account != nil && account.ID == stamp.id && account.Generation == stamp.generation && account.RegistrationEpoch == stamp.epoch && !account.Disabled && !account.RequiresLogin() && !authRefreshDisabled(account))
}

type prismRecoveryState struct {
	inFlight   bool
	next       time.Time
	probeAfter time.Time
	failures   int
}

type prismRecoveryWorker struct {
	manager *Manager
	mu      sync.Mutex
	states  map[string]*prismRecoveryState
	now     func() time.Time
}

func newPrismRecoveryWorker(manager *Manager) *prismRecoveryWorker {
	return &prismRecoveryWorker{manager: manager, states: map[string]*prismRecoveryState{}, now: time.Now}
}

func (m *Manager) runPrismQuotaRecovery(ctx context.Context) {
	worker := newPrismRecoveryWorker(m)
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		worker.tick(ctx)
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// tick is deterministic with a supplied clock and never queues more work than
// the account inventory. One serialized worker bounds provider requests globally;
// the per-account guard also prevents overlapping explicit invocations in tests.
func (w *prismRecoveryWorker) tick(ctx context.Context) {
	if ctx.Err() != nil || w.manager.HomeEnabled() || !w.manager.PrismPolicyEnabled() {
		return
	}
	accounts := w.manager.List()
	sort.Slice(accounts, func(i, j int) bool { return accounts[i].ID < accounts[j].ID })
	live := map[string]bool{}
	for _, account := range accounts {
		live[account.ID] = true
		if ctx.Err() != nil {
			return
		}
		leased, leaseValid := prismServingLease(account, w.now())
		if account.Disabled || account.RequiresLogin() || (leased && !leaseValid) || (authRefreshDisabled(account) && !leased) || !ProviderSupportsQuotaObservation(account.Provider) || account.AuthKind() == AuthKindAPIKey {
			continue
		}
		models := registry.GetGlobalRegistry().GetModelsForClient(account.ID)
		sort.Slice(models, func(i, j int) bool { return models[i] != nil && (models[j] == nil || models[i].ID < models[j].ID) })
		for _, model := range models {
			if model == nil {
				continue
			}
			state := PrismAccountEligibility(account, model.ID, w.now())
			if state.Reason != "quota_unknown" && state.Reason != "credential_expired" {
				continue
			}
			w.recover(ctx, account, model.ID)
			break
		}
	}
	w.mu.Lock()
	for id, state := range w.states {
		if !live[id] && !state.inFlight {
			delete(w.states, id)
		}
	}
	w.mu.Unlock()
}

func (w *prismRecoveryWorker) recover(ctx context.Context, account *Auth, model string) {
	now := w.now()
	w.mu.Lock()
	state := w.states[account.ID]
	if state == nil {
		state = &prismRecoveryState{}
		w.states[account.ID] = state
	}
	if state.inFlight || state.next.After(now) {
		w.mu.Unlock()
		return
	}
	state.inFlight = true
	probeAllowed := !state.probeAfter.After(now)
	w.mu.Unlock()
	success := false
	defer func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		state.inFlight = false
		if success {
			state.failures = 0
			state.next = w.now().Add(PrismQuotaMaxAge / 2)
			return
		}
		if state.failures < 6 {
			state.failures++
		}
		state.next = w.now().Add(time.Minute * time.Duration(1<<state.failures))
	}()
	executor, exists := w.manager.Executor(account.Provider)
	if !exists {
		return
	}
	// Expired access is recovered through the same owner/lock as normal traffic.
	if expiry, ok := account.AccessTokenExpirationTime(); ok && !expiry.After(now) {
		if authRefreshDisabled(account) {
			return
		}
		updated, errRefresh := w.manager.refreshAuthForRequest(ctx, account.ID, authAccessToken(account))
		if errRefresh != nil || updated == nil {
			return
		}
		account = updated
	}
	refreshedAuth := false
	if observer, ok := executor.(PrismQuotaObserver); ok {
		headers, errQuota := observer.PrismQuota(ctx, account)
		if isUnauthorizedError(errQuota) && authHasRefreshCredential(account) && !authRefreshDisabled(account) {
			updated, errRefresh := w.manager.refreshAuthForRequest(ctx, account.ID, authAccessToken(account))
			if errRefresh != nil || updated == nil {
				return
			}
			account = updated
			refreshedAuth = true
			headers, errQuota = observer.PrismQuota(ctx, account)
		}
		if errQuota == nil {
			w.manager.observePrismQuota(account, headers, w.now())
			current, _ := w.manager.GetByID(account.ID)
			if current != nil && PrismAccountEligibility(current, model, w.now()).Reason != "quota_unknown" {
				success = true
				return
			}
		}
	}
	// Leased replicas may observe usage with their serving token, but never
	// perform token refresh or synthetic inference recovery.
	if ctx.Err() != nil || !probeAllowed || authRefreshDisabled(account) {
		return
	}
	current, exists := w.manager.GetByID(account.ID)
	if !exists || current.Disabled || current.RequiresLogin() || authRefreshDisabled(current) || current.RegistrationEpoch != account.RegistrationEpoch || authAccessToken(current) != authAccessToken(account) {
		return
	}
	account = current
	// At most one representative inference per account/hour. A completed response
	// with no measurements remains unknown and cannot restore normal routing.
	w.mu.Lock()
	state.probeAfter = now.Add(time.Hour)
	w.mu.Unlock()
	payload := map[string]any{"model": model, "max_tokens": 16, "messages": []map[string]any{{"role": "user", "content": "Reply with OK."}}}
	format := sdktranslator.FormatClaude
	if account.Provider == "codex" {
		payload = map[string]any{"model": model, "max_output_tokens": 16, "input": "Reply with OK.", "store": false}
		format = sdktranslator.FormatOpenAIResponse
	}
	body, _ := json.Marshal(payload)
	request := cliproxyexecutor.Request{Model: model, Payload: body}
	opts := cliproxyexecutor.Options{SourceFormat: format, OriginalRequest: body}
	probeCtx := newUpstreamAttemptContext(context.WithValue(ctx, prismProbeGenerationKey{}, prismProbeGeneration{account.ID, account.Generation, account.RegistrationEpoch}))
	response, errProbe := executor.Execute(probeCtx, account, request, opts)
	if isUnauthorizedError(errProbe) && !refreshedAuth && authHasRefreshCredential(account) {
		updated, errRefresh := w.manager.refreshAuthForRequest(ctx, account.ID, authAccessToken(account))
		if errRefresh != nil || updated == nil {
			return
		}
		account = updated
		refreshedAuth = true
		probeCtx = newUpstreamAttemptContext(context.WithValue(ctx, prismProbeGenerationKey{}, prismProbeGeneration{account.ID, account.Generation, account.RegistrationEpoch}))
		response, errProbe = executor.Execute(probeCtx, account, request, opts)
	}
	if ctx.Err() != nil {
		return
	}
	if isUnauthorizedError(errProbe) {
		w.manager.quarantinePrismAccount(ctx, account)
		return
	}
	result := Result{AuthID: account.ID, Provider: account.Provider, Model: model, Success: errProbe == nil, Options: opts}
	if errProbe != nil {
		result.Error = resultErrorFromError(errProbe)
		result.RetryAfter = retryAfterFromError(errProbe)
	}
	w.manager.MarkResult(probeCtx, result)
	if errProbe == nil {
		w.manager.observePrismQuota(account, response.Headers, w.now())
		current, _ := w.manager.GetByID(account.ID)
		success = current != nil && PrismAccountEligibility(current, model, w.now()).Reason != "quota_unknown"
	}
}

func (m *Manager) observePrismQuota(expected *Auth, headers http.Header, now time.Time) {
	m.mu.Lock()
	current := m.auths[expected.ID]
	if current == nil || current.RegistrationEpoch != expected.RegistrationEpoch || authAccessToken(current) != authAccessToken(expected) || current.Quota.ObservedAt.After(now) {
		m.mu.Unlock()
		return
	}
	if !current.Quota.ObserveResponseHeadersForProvider(current.Provider, headers, now) {
		m.mu.Unlock()
		return
	}
	current.Generation++
	updated := current.Clone()
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(updated)
	}
}

func (m *Manager) quarantinePrismAccount(ctx context.Context, expected *Auth) {
	m.mu.Lock()
	current := m.auths[expected.ID]
	if current == nil || current.RegistrationEpoch != expected.RegistrationEpoch || authAccessToken(current) != authAccessToken(expected) {
		m.mu.Unlock()
		return
	}
	updated := current.Clone()
	if updated.Metadata == nil {
		updated.Metadata = map[string]any{}
	}
	updated.Metadata["requires_login"] = true
	updated.StatusMessage = "Sign in again to restore this account"
	updated.Generation++
	if m.persist(ctx, updated) != nil {
		m.mu.Unlock()
		return
	}
	m.auths[updated.ID] = updated
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(updated)
	}
}
