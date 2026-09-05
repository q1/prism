package auth

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type failingAtomicTokenStorage struct{}

func (*failingAtomicTokenStorage) SaveTokenToFile(path string) error {
	if errWrite := os.WriteFile(path, []byte(`{"partial":"fixture"`), 0o600); errWrite != nil {
		return errWrite
	}
	return errors.New("synthetic serializer failure")
}

func TestPrismAtomicCredentialPostRenameFailureIsUncertainAndNoopRetriesSync(t *testing.T) {
	directory := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(directory)
	account := &coreauth.Auth{ID: "fixture.json", Provider: "claude", Metadata: map[string]any{"type": "claude", "access_token": "fixture-published"}}
	path := filepath.Join(directory, account.ID)
	cause := errors.New("fixture directory sync failure")
	attempts := 0
	syncDirectory := func(parent string) error {
		attempts++
		if parent != directory {
			t.Fatal("sync targeted a different directory")
		}
		visible, errRead := os.ReadFile(path)
		if errRead != nil || !strings.Contains(string(visible), "fixture-published") {
			t.Fatal("fault callback did not run after publication")
		}
		if attempts < 3 {
			return cause
		}
		return syncCredentialDirectory(parent)
	}
	for attempt := 1; attempt <= 3; attempt++ {
		before, _ := os.Stat(path)
		saved, errSave := store.saveWithDirectorySync(context.Background(), account, true, syncDirectory)
		if saved != path || account.Attributes[coreauth.AttributePath] != path {
			t.Fatal("published path was hidden by a durability error")
		}
		if attempt < 3 {
			var committed *coreauth.PersistenceCommittedError
			if !errors.Is(errSave, coreauth.ErrPersistenceDurabilityUncertain) || !errors.Is(errSave, cause) || !errors.As(errSave, &committed) {
				t.Fatal("post-publication error did not preserve committed semantics")
			}
		} else if errSave != nil {
			t.Fatal(errSave)
		}
		if attempts != attempt {
			t.Fatal("identical bytes bypassed unresolved durability")
		}
		after, _ := os.Stat(path)
		if before != nil && !os.SameFile(before, after) {
			t.Fatal("durability retry needlessly replaced an unchanged credential")
		}
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 1 {
		t.Fatal("atomic retry left staging credentials behind")
	}
}

type directorySyncFaultStore struct {
	*FileTokenStore
	fail atomic.Bool
}

func (s *directorySyncFaultStore) syncDirectory(path string) error {
	if s.fail.Load() {
		return errors.New("fixture post-rename directory failure")
	}
	return syncCredentialDirectory(path)
}

func (s *directorySyncFaultStore) Save(ctx context.Context, account *coreauth.Auth) (string, error) {
	return s.saveWithDirectorySync(ctx, account, false, s.syncDirectory)
}

func (s *directorySyncFaultStore) SaveImported(ctx context.Context, account *coreauth.Auth) (string, error) {
	return s.saveWithDirectorySync(ctx, account, true, s.syncDirectory)
}

func TestPrismUncertainCredentialImportPublishesEpochAndFencesOldRefresh(t *testing.T) {
	directory := t.TempDir()
	store := &directorySyncFaultStore{FileTokenStore: NewFileTokenStore()}
	store.SetBaseDir(directory)
	manager := coreauth.NewManager(store, nil, nil)
	base, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: "fixture.json", FileName: "fixture.json",
		Provider: "claude", Status: coreauth.StatusActive, Metadata: map[string]any{"type": "claude", "access_token": "fixture-before-import", "refresh_token": "fixture-old-refresh"}})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	imported := base.Clone()
	imported.Metadata["access_token"] = "fixture-imported"
	imported.Metadata["refresh_token"] = "fixture-imported-refresh"
	store.fail.Store(true)
	published, errImport := manager.RegisterAccountIf(context.Background(), imported, nil)
	if !errors.Is(errImport, coreauth.ErrPersistenceDurabilityUncertain) || published == nil || published.RegistrationEpoch <= base.RegistrationEpoch {
		t.Fatal("uncertain import did not publish its new epoch with an explicit error")
	}
	current, _ := manager.GetByID(base.ID)
	if current.RegistrationEpoch != published.RegistrationEpoch || current.Metadata["access_token"] != "fixture-imported" {
		t.Fatal("runtime did not match the published imported credential")
	}
	refreshed := base.Clone()
	refreshed.Metadata["access_token"] = "fixture-stale-refresh"
	if _, errRefresh := manager.UpdateRefreshedAuth(context.Background(), base, refreshed); errRefresh == nil {
		t.Fatal("a refresh from before the uncertain import was not fenced")
	}
	visible, errRead := os.ReadFile(filepath.Join(directory, base.ID))
	if errRead != nil || !strings.Contains(string(visible), "fixture-imported") || strings.Contains(string(visible), "fixture-stale-refresh") {
		t.Fatal("old refresh replaced the newly imported disk credential")
	}
	store.fail.Store(false)
	if _, errRetry := manager.RegisterAccountIf(context.Background(), imported, nil); errRetry != nil {
		t.Fatal(errRetry)
	}
}

func TestPrismAtomicCredentialSavePreservesOldFileAfterPartialSerializerFailure(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "fixture.json")
	original := []byte(`{"type":"claude","access_token":"fixture-original"}`)
	if errWrite := os.WriteFile(path, original, 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	store := NewFileTokenStore()
	store.SetBaseDir(directory)
	account := &coreauth.Auth{ID: "fixture.json", FileName: "fixture.json", Provider: "claude", Metadata: map[string]any{"type": "claude"}, Storage: &failingAtomicTokenStorage{}}
	if _, errSave := store.Save(context.Background(), account); errSave == nil {
		t.Fatal("partial serializer failure acknowledged")
	}
	after, _ := os.ReadFile(path)
	if string(after) != string(original) {
		t.Fatal("partial serializer damaged authoritative credential")
	}
	entries, _ := os.ReadDir(directory)
	if len(entries) != 1 {
		t.Fatal("failed private staging file remained")
	}
	account.Storage = nil
	account.Metadata["access_token"] = "fixture-replacement"
	if _, errSave := store.Save(context.Background(), account); errSave != nil {
		t.Fatal(errSave)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0o600 {
		t.Fatal("replacement credential was not private")
	}
	beforeNoop, _ := os.Stat(path)
	if _, errSave := store.Save(context.Background(), account); errSave != nil {
		t.Fatal(errSave)
	}
	afterNoop, _ := os.Stat(path)
	if !os.SameFile(beforeNoop, afterNoop) {
		t.Fatal("unchanged metadata created a watcher write loop")
	}
}
