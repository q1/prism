package auth

import (
	"context"
	"errors"
	"math"
	"strconv"
	"strings"
	"time"
)

// AccountPolicyPatch changes owner policy without copying provider credentials
// out of the manager. ReserveSet distinguishes an omitted reserve from null (off).
type AccountPolicyPatch struct {
	Disabled       *bool
	Weight         *int
	ReserveSet     bool
	ReservePercent *float64
}

var ErrAccountPolicyNotFound = errors.New("account not found")
var ErrAccountPolicyUnsupported = errors.New("account policy requires a persisted provider account")
var ErrAccountPolicyConflict = errors.New("account policy changed")

// UpdateAccountPolicy merges into the latest credential while holding the same
// lock as refresh commits. Persistence must succeed before routing observes the
// edit. A published write with uncertain durability updates runtime to match
// storage but returns an explicit failure rather than acknowledging durability.
func (m *Manager) UpdateAccountPolicy(ctx context.Context, id string, patch AccountPolicyPatch) (*Auth, error) {
	return m.UpdateAccountPolicyIf(ctx, id, patch, nil)
}

// CheckAccountPolicySnapshot prevents account additions/removals/policy commits
// while a related configuration transaction validates and persists its revision.
// The callback must not call back into the manager. It receives private clones.
func (m *Manager) CheckAccountPolicySnapshot(check func([]*Auth) error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return check(m.accountPolicySnapshotLocked())
}

func (m *Manager) accountPolicySnapshotLocked() []*Auth {
	accounts := make([]*Auth, 0, len(m.auths))
	for _, account := range m.auths {
		accounts = append(accounts, account.Clone())
	}
	return accounts
}

// UpdateAccountPolicyIf rechecks the full control revision under the manager's
// commit lock, including changes from file watchers and refresh completion.
// The optional check must not call any manager method.
func (m *Manager) UpdateAccountPolicyIf(ctx context.Context, id string, patch AccountPolicyPatch, check func([]*Auth) bool) (*Auth, error) {
	if patch.Weight != nil && (*patch.Weight < 0 || *patch.Weight > 1_000_000) {
		return nil, errors.New("invalid account weight")
	}
	if patch.ReserveSet && patch.ReservePercent != nil &&
		(math.IsNaN(*patch.ReservePercent) || math.IsInf(*patch.ReservePercent, 0) || *patch.ReservePercent < 0 || *patch.ReservePercent > 100) {
		return nil, errors.New("invalid account reserve")
	}
	if patch.Disabled == nil && patch.Weight == nil && !patch.ReserveSet {
		return nil, errors.New("empty account policy")
	}
	return m.EditAccountPolicyIf(ctx, id, check, func(updated *Auth) error {
		if patch.Disabled != nil {
			updated.Disabled = *patch.Disabled
			updated.Metadata["disabled"] = *patch.Disabled
			if *patch.Disabled {
				updated.Status = StatusDisabled
			} else if updated.Status == StatusDisabled {
				updated.Status = StatusActive
			}
		}
		if patch.Weight != nil {
			updated.Metadata[AttributeWeight] = *patch.Weight
			if updated.Attributes == nil {
				updated.Attributes = make(map[string]string)
			}
			updated.Attributes[AttributeWeight] = strconv.Itoa(*patch.Weight)
		}
		if patch.ReserveSet {
			if patch.ReservePercent == nil {
				updated.Metadata["reserve_percent"] = nil
			} else {
				updated.Metadata["reserve_percent"] = *patch.ReservePercent
			}
		}
		return nil
	})
}

// EditAccountPolicyIf applies a validated owner-policy edit to the latest
// credential under the refresh commit lock. The trusted callback must change
// owner policy only and must not call manager methods. Its input is a private
// clone; callback or pre-publication failure leaves live and stored state
// unchanged. A post-publication durability error publishes matching runtime and
// is returned for explicit reconciliation.
func (m *Manager) EditAccountPolicyIf(ctx context.Context, id string, check func([]*Auth) bool, edit func(*Auth) error) (*Auth, error) {
	if edit == nil {
		return nil, errors.New("empty account policy")
	}
	m.mu.Lock()
	if check != nil && !check(m.accountPolicySnapshotLocked()) {
		m.mu.Unlock()
		return nil, ErrAccountPolicyConflict
	}
	existing := m.auths[id]
	if existing == nil {
		m.mu.Unlock()
		return nil, ErrAccountPolicyNotFound
	}
	if _, leased := existing.Metadata["prism_serving_expires_at"]; leased {
		m.mu.Unlock()
		return nil, ErrAccountPolicyUnsupported
	}
	if m.store == nil || existing.Metadata == nil || IsConfigAPIKeyAuth(existing) || IsPluginVirtualAuth(existing) ||
		strings.EqualFold(strings.TrimSpace(existing.Attributes["runtime_only"]), "true") {
		m.mu.Unlock()
		return nil, ErrAccountPolicyUnsupported
	}
	updated := existing.Clone()
	if errEdit := edit(updated); errEdit != nil {
		m.mu.Unlock()
		return nil, errEdit
	}
	updated.UpdatedAt = time.Now()
	updated.Generation = existing.Generation + 1
	errPersist := m.persist(ctx, updated)
	if errPersist != nil && !errors.Is(errPersist, ErrPersistenceDurabilityUncertain) {
		m.mu.Unlock()
		return nil, errors.New("account policy could not be persisted")
	}
	m.auths[id] = updated.Clone()
	m.mu.Unlock()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(updated.Clone())
	}
	m.queueRefreshReschedule(id)
	if updated.Disabled {
		m.invalidateSessionAffinity(id)
	}
	m.hook.OnAuthUpdated(ctx, updated.Clone())
	return updated.Clone(), errPersist
}

// RemoveAccountPolicyIf fences pending refresh commits and deletes persisted
// state in the same policy transaction. It does not acknowledge a failed delete.
func (m *Manager) RemoveAccountPolicyIf(ctx context.Context, id string, check func([]*Auth) bool) error {
	m.mu.Lock()
	if check != nil && !check(m.accountPolicySnapshotLocked()) {
		m.mu.Unlock()
		return ErrAccountPolicyConflict
	}
	existing := m.auths[id]
	if existing == nil {
		m.mu.Unlock()
		return ErrAccountPolicyNotFound
	}
	if _, leased := existing.Metadata["prism_serving_expires_at"]; leased {
		m.mu.Unlock()
		return ErrAccountPolicyUnsupported
	}
	if m.store == nil || existing.Metadata == nil || IsConfigAPIKeyAuth(existing) || IsPluginVirtualAuth(existing) ||
		strings.EqualFold(strings.TrimSpace(existing.Attributes["runtime_only"]), "true") {
		m.mu.Unlock()
		return ErrAccountPolicyUnsupported
	}
	// Serialize deletion with older persistence calls that already left m.mu.
	lockValue, _ := m.persistLocks.LoadOrStore(id, &authPersistLock{})
	lock := lockValue.(*authPersistLock)
	lock.mu.Lock()
	if errDelete := m.store.Delete(ctx, id); errDelete != nil {
		lock.mu.Unlock()
		m.mu.Unlock()
		return errors.New("account could not be removed from storage")
	}
	provider, epoch, _ := m.removeAuthLocked(id)
	lock.lastEpoch, lock.lastGeneration = epoch, 0
	lock.mu.Unlock()
	m.mu.Unlock()
	m.afterAuthRemoval(ctx, id, provider, epoch)
	return nil
}

// RegisterAccountIf imports one complete credential file as a new registration.
// Storage publication precedes runtime publication; a fresh epoch fences all
// refresh and request-preparation work which started from the replaced
// credential. An uncertain durability error still publishes that epoch and is
// returned to the caller for reconciliation.
func (m *Manager) RegisterAccountIf(ctx context.Context, candidate *Auth, check func([]*Auth) bool) (*Auth, error) {
	if candidate == nil || strings.TrimSpace(candidate.ID) == "" || candidate.Metadata == nil || IsConfigAPIKeyAuth(candidate) || IsPluginVirtualAuth(candidate) || strings.EqualFold(strings.TrimSpace(candidate.Attributes["runtime_only"]), "true") {
		return nil, ErrAccountPolicyUnsupported
	}
	if _, leased := candidate.Metadata["prism_serving_expires_at"]; leased {
		return nil, ErrAccountPolicyUnsupported
	}
	updated := candidate.Clone()
	NormalizeCredentialMetadata(updated.Metadata)
	if errWeight := ValidateAuthWeight(updated); errWeight != nil {
		return nil, errors.New("invalid account weight")
	}
	m.mu.Lock()
	if m.store == nil {
		m.mu.Unlock()
		return nil, ErrAccountPolicyUnsupported
	}
	if check != nil && !check(m.accountPolicySnapshotLocked()) {
		m.mu.Unlock()
		return nil, ErrAccountPolicyConflict
	}
	if existing := m.auths[updated.ID]; existing != nil {
		if _, leased := existing.Metadata["prism_serving_expires_at"]; leased {
			m.mu.Unlock()
			return nil, ErrAccountPolicyUnsupported
		}
		updated.CreatedAt = existing.CreatedAt
	}
	if m.authEpochs == nil {
		m.authEpochs = make(map[string]uint64)
	}
	epoch := m.authEpochs[updated.ID]
	if existing := m.auths[updated.ID]; existing != nil && existing.RegistrationEpoch > epoch {
		epoch = existing.RegistrationEpoch
	}
	updated.RegistrationEpoch, updated.Generation = epoch+1, 1
	if updated.CreatedAt.IsZero() {
		updated.CreatedAt = time.Now()
	}
	updated.UpdatedAt = time.Now()
	updated.EnsureIndex()
	errPersist := m.persistAccount(ctx, updated, true)
	if errPersist != nil && !errors.Is(errPersist, ErrPersistenceDurabilityUncertain) {
		m.mu.Unlock()
		return nil, errors.New("account import could not be persisted")
	}
	m.authEpochs[updated.ID] = updated.RegistrationEpoch
	m.auths[updated.ID] = updated.Clone()
	m.mu.Unlock()
	m.rebuildAPIKeyModelAliasFromRuntimeConfig()
	if m.scheduler != nil {
		m.scheduler.upsertAuth(updated.Clone())
	}
	m.queueRefreshReschedule(updated.ID)
	m.invalidateSessionAffinity(updated.ID)
	m.hook.OnAuthRegistered(ctx, updated.Clone())
	return updated.Clone(), errPersist
}
