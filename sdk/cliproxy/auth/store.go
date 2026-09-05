package auth

import (
	"context"
	"errors"
)

// ErrPersistenceDurabilityUncertain means the new credential is already visible
// in storage, but its crash durability was not confirmed. Callers must publish
// the matching runtime/epoch and reconcile the failure instead of retrying from
// an older credential or acknowledging durable success.
var ErrPersistenceDurabilityUncertain = errors.New("credential was published but storage durability is uncertain; reconcile current state")

// PersistenceCommittedError distinguishes a post-publication failure from a
// write that never replaced the old credential. Error deliberately omits paths
// and backend diagnostics; the wrapped cause remains available to errors.Is/As.
type PersistenceCommittedError struct {
	Cause error
}

func (e *PersistenceCommittedError) Error() string {
	return ErrPersistenceDurabilityUncertain.Error()
}

func (e *PersistenceCommittedError) Unwrap() error { return e.Cause }

func (e *PersistenceCommittedError) Is(target error) bool {
	return target == ErrPersistenceDurabilityUncertain
}

// Store abstracts persistence of Auth state across restarts.
type Store interface {
	// List returns all auth records stored in the backend.
	List(ctx context.Context) ([]*Auth, error)
	// Save persists the provided auth record, replacing any existing one with same ID.
	// A PersistenceCommittedError means publication occurred despite the error.
	Save(ctx context.Context, auth *Auth) (string, error)
	// Delete removes the auth record identified by id.
	Delete(ctx context.Context, id string) error
}
