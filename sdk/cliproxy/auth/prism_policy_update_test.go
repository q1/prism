package auth

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

type prismPolicyStore struct {
	failSave       atomic.Bool
	failDelete     atomic.Bool
	committedError atomic.Bool
	writes         atomic.Int32
	deleted        atomic.Int32
}

func (s *prismPolicyStore) List(context.Context) ([]*Auth, error) { return nil, nil }
func (s *prismPolicyStore) Save(context.Context, *Auth) (string, error) {
	if s.failSave.Load() {
		return "", errors.New("synthetic storage unavailable")
	}
	s.writes.Add(1)
	if s.committedError.Load() {
		return "", &PersistenceCommittedError{Cause: errors.New("fixture post-publication failure")}
	}
	return "", nil
}
func (s *prismPolicyStore) SaveImported(ctx context.Context, account *Auth) (string, error) {
	return s.Save(ctx, account)
}
func (s *prismPolicyStore) Delete(context.Context, string) error {
	if s.failDelete.Load() {
		return errors.New("synthetic storage unavailable")
	}
	s.deleted.Add(1)
	return nil
}

func policyFixture(t *testing.T) (*Manager, *prismPolicyStore, *Auth) {
	t.Helper()
	store := &prismPolicyStore{}
	manager := NewManager(store, nil, nil)
	account, errRegister := manager.Register(context.Background(), &Auth{ID: "policy-test.json", FileName: "policy-test.json",
		Provider: "claude", Status: StatusActive, Metadata: map[string]any{"type": "claude", "access_token": "fixture-initial", "refresh_token": "fixture-refresh"}})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	return manager, store, account
}

func TestPrismPolicyPersistFailureDoesNotPublishAndFreshCredentialsSurvive(t *testing.T) {
	manager, store, base := policyFixture(t)
	fresh := base.Clone()
	fresh.Metadata["access_token"] = "fixture-refreshed"
	if _, errRefresh := manager.UpdateRefreshedAuth(context.Background(), base, fresh); errRefresh != nil {
		t.Fatal(errRefresh)
	}
	weight, disabled := 7, true
	store.failSave.Store(true)
	if _, errPatch := manager.UpdateAccountPolicy(context.Background(), base.ID, AccountPolicyPatch{Weight: &weight, Disabled: &disabled}); errPatch == nil {
		t.Fatal("failed storage accepted a policy mutation")
	}
	unchanged, _ := manager.GetByID(base.ID)
	if unchanged.Disabled || unchanged.Metadata[AttributeWeight] != nil || unchanged.Metadata["access_token"] != "fixture-refreshed" {
		t.Fatal("failed policy changed runtime or replaced refreshed credentials")
	}
	store.failSave.Store(false)
	updated, errPatch := manager.UpdateAccountPolicy(context.Background(), base.ID,
		AccountPolicyPatch{Weight: &weight, Disabled: &disabled, ReserveSet: true})
	if errPatch != nil {
		t.Fatal(errPatch)
	}
	if !updated.Disabled || updated.Metadata[AttributeWeight] != weight || updated.Metadata["access_token"] != "fixture-refreshed" {
		t.Fatal("policy not applied to the latest credential")
	}
	if reserve, exists := updated.Metadata["reserve_percent"]; !exists || reserve != nil {
		t.Fatal("explicit off reserve was not preserved")
	}
}

func TestPrismPolicyPreconditionAndDeleteFailureAreAtomic(t *testing.T) {
	manager, store, account := policyFixture(t)
	weight := 4
	writes := store.writes.Load()
	if _, errPatch := manager.UpdateAccountPolicyIf(context.Background(), account.ID, AccountPolicyPatch{Weight: &weight},
		func(accounts []*Auth) bool { return len(accounts) != 1 }); !errors.Is(errPatch, ErrAccountPolicyConflict) {
		t.Fatalf("stale guard returned %v", errPatch)
	}
	if store.writes.Load() != writes {
		t.Fatal("stale policy wrote storage")
	}
	store.failDelete.Store(true)
	if errDelete := manager.RemoveAccountPolicyIf(context.Background(), account.ID, func([]*Auth) bool { return true }); errDelete == nil {
		t.Fatal("failed delete was accepted")
	}
	if _, exists := manager.GetByID(account.ID); !exists {
		t.Fatal("failed delete removed runtime credential")
	}
	store.failDelete.Store(false)
	if errDelete := manager.RemoveAccountPolicyIf(context.Background(), account.ID, func([]*Auth) bool { return false }); !errors.Is(errDelete, ErrAccountPolicyConflict) {
		t.Fatal("stale delete not rejected")
	}
	if store.deleted.Load() != 0 {
		t.Fatal("stale delete touched storage")
	}
	if errDelete := manager.RemoveAccountPolicyIf(context.Background(), account.ID, func([]*Auth) bool { return true }); errDelete != nil {
		t.Fatal(errDelete)
	}
	if _, exists := manager.GetByID(account.ID); exists {
		t.Fatal("persisted removal did not remove runtime")
	}
	_, _ = manager.UpdateRefreshedAuth(context.Background(), account, account.Clone())
	if _, exists := manager.GetByID(account.ID); exists {
		t.Fatal("pending refresh resurrected removed credential")
	}
	if store.deleted.Load() != 1 {
		t.Fatal("delete did not execute exactly once")
	}
}

func TestPrismPolicyRejectsRuntimeOnlyAndInvalidPolicy(t *testing.T) {
	manager, _, account := policyFixture(t)
	for _, reserve := range []float64{-1, 101} {
		if _, errPatch := manager.UpdateAccountPolicy(context.Background(), account.ID,
			AccountPolicyPatch{ReserveSet: true, ReservePercent: &reserve}); errPatch == nil {
			t.Fatal("invalid reserve accepted")
		}
	}
	runtime := account.Clone()
	runtime.Attributes = map[string]string{"runtime_only": "true"}
	_, _ = manager.Update(context.Background(), runtime)
	weight := 3
	if _, errPatch := manager.UpdateAccountPolicy(context.Background(), account.ID, AccountPolicyPatch{Weight: &weight}); !errors.Is(errPatch, ErrAccountPolicyUnsupported) {
		t.Fatal("runtime-only credential reported durable policy")
	}
}

func TestPrismServingGenerationCannotBeRewrittenOrEdited(t *testing.T) {
	manager, store, account := policyFixture(t)
	account.Metadata["refresh_disabled"] = true
	account.Metadata["prism_serving_expires_at"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	writes := store.writes.Load()
	_, _ = manager.Update(context.Background(), account)
	if store.writes.Load() != writes {
		t.Fatal("leased generation was rewritten by a runtime update")
	}
	weight := 2
	if _, errEdit := manager.UpdateAccountPolicy(context.Background(), account.ID, AccountPolicyPatch{Weight: &weight}); !errors.Is(errEdit, ErrAccountPolicyUnsupported) {
		t.Fatal("leased replica changed centrally owned policy")
	}
	if errRemove := manager.RemoveAccountPolicyIf(context.Background(), account.ID, nil); !errors.Is(errRemove, ErrAccountPolicyUnsupported) {
		t.Fatal("leased replica removed a signed account file")
	}
}

func TestPrismAccountImportIsPersistedBeforePublicationAndFencesPendingRefresh(t *testing.T) {
	manager, store, base := policyFixture(t)
	imported := base.Clone()
	imported.Metadata["access_token"] = "fixture-imported"
	store.failSave.Store(true)
	if _, errImport := manager.RegisterAccountIf(context.Background(), imported, nil); errImport == nil {
		t.Fatal("failed import was acknowledged")
	}
	unchanged, _ := manager.GetByID(base.ID)
	if unchanged.Metadata["access_token"] != "fixture-initial" || unchanged.RegistrationEpoch != base.RegistrationEpoch {
		t.Fatal("failed import changed live registration")
	}
	store.failSave.Store(false)
	refreshed := base.Clone()
	refreshed.Metadata["access_token"] = "fixture-refreshed-after-failure"
	if _, errRefresh := manager.UpdateRefreshedAuth(context.Background(), base, refreshed); errRefresh != nil {
		t.Fatal(errRefresh)
	}
	beforeWrites := store.writes.Load()
	if _, errImport := manager.RegisterAccountIf(context.Background(), imported, func([]*Auth) bool { return false }); errImport != ErrAccountPolicyConflict {
		t.Fatal("import accepted stale policy snapshot")
	}
	if store.writes.Load() != beforeWrites {
		t.Fatal("stale import touched storage")
	}
	current, errImport := manager.RegisterAccountIf(context.Background(), imported, nil)
	if errImport != nil || current.RegistrationEpoch <= base.RegistrationEpoch {
		t.Fatal("import did not publish a new epoch")
	}
	_, _ = manager.UpdateRefreshedAuth(context.Background(), base, refreshed)
	current, _ = manager.GetByID(base.ID)
	if current.Metadata["access_token"] != "fixture-imported" {
		t.Fatal("pending refresh replaced imported credentials")
	}
}

func TestPrismUncertainPolicyPublishesRuntimeAndFencesOlderPersistence(t *testing.T) {
	manager, store, base := policyFixture(t)
	store.committedError.Store(true)
	weight, disabled := 8, true
	updated, errPolicy := manager.UpdateAccountPolicy(context.Background(), base.ID, AccountPolicyPatch{Weight: &weight, Disabled: &disabled})
	if !errors.Is(errPolicy, ErrPersistenceDurabilityUncertain) || updated == nil {
		t.Fatal("published policy did not preserve the durability error")
	}
	current, _ := manager.GetByID(base.ID)
	if !current.Disabled || current.Metadata[AttributeWeight] != weight || current.Generation <= base.Generation {
		t.Fatal("uncertain policy left runtime behind published storage")
	}
	writes := store.writes.Load()
	if errOld := manager.persist(context.Background(), base); errOld != nil {
		t.Fatal(errOld)
	}
	if store.writes.Load() != writes {
		t.Fatal("old pending persistence overwrote a published uncertain policy")
	}
	store.committedError.Store(false)
	refreshed := base.Clone()
	refreshed.Metadata["access_token"] = "fixture-refreshed-after-policy"
	if _, errRefresh := manager.UpdateRefreshedAuth(context.Background(), base, refreshed); errRefresh != nil {
		t.Fatal(errRefresh)
	}
	current, _ = manager.GetByID(base.ID)
	if !current.Disabled || current.Metadata[AttributeWeight] != weight || current.Metadata["access_token"] != "fixture-refreshed-after-policy" {
		t.Fatal("refresh discarded already-published owner policy")
	}
}

func TestPrismUncertainImportFencesPendingPersistenceWithOlderEpoch(t *testing.T) {
	manager, store, base := policyFixture(t)
	imported := base.Clone()
	imported.Metadata["access_token"] = "fixture-imported-uncertain"
	store.committedError.Store(true)
	updated, errImport := manager.RegisterAccountIf(context.Background(), imported, nil)
	if !errors.Is(errImport, ErrPersistenceDurabilityUncertain) || updated == nil || updated.RegistrationEpoch <= base.RegistrationEpoch {
		t.Fatal("published import lost its fresh registration epoch")
	}
	writes := store.writes.Load()
	base.Generation = 1_000_000
	if errOld := manager.persist(context.Background(), base); errOld != nil {
		t.Fatal(errOld)
	}
	if store.writes.Load() != writes {
		t.Fatal("older epoch with a higher generation replaced an uncertain import")
	}
}

func TestPrismServingLeaseRenewalPreservesMeasurementsOnlyForSameCredential(t *testing.T) {
	manager, _, base := policyFixture(t)
	now := time.Now().UTC()
	base.Metadata["prism_serving_expires_at"] = now.Add(time.Minute).Format(time.RFC3339)
	base.Metadata["refresh_disabled"] = true
	base.Quota = prismClaudeFixture("measurements", now, time.Hour, 24*time.Hour, 50).Quota
	_, _ = manager.Update(context.Background(), base)
	latest, _ := manager.GetByID(base.ID)
	fromWatcher := latest.Clone()
	fromWatcher.Metadata["prism_serving_expires_at"] = now.Add(10 * time.Minute).Format(time.RFC3339)
	fromWatcher.Quota = QuotaState{}
	_, _ = manager.Update(context.Background(), fromWatcher)
	renewed, _ := manager.GetByID(base.ID)
	if !renewed.Quota.ObservedAt.Equal(now) || !PrismAccountEligibility(renewed, "claude-fable-5-1", now).Available {
		t.Fatal("same-content lease renewal discarded usable provider measurement")
	}
	fromWatcher = renewed.Clone()
	fromWatcher.Metadata["access_token"] = "fixture-changed-serving-token"
	fromWatcher.Quota = QuotaState{}
	_, _ = manager.Update(context.Background(), fromWatcher)
	changed, _ := manager.GetByID(base.ID)
	if !changed.Quota.ObservedAt.IsZero() {
		t.Fatal("changed credential inherited an unrelated usage measurement")
	}
}
