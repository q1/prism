package auth

import (
	"testing"
	"time"
)

func TestPrismSchedulerDemotesExpiredServingLease(t *testing.T) {
	now := time.Date(2026, time.September, 8, 12, 0, 0, 0, time.UTC)
	account := &Auth{ID: "lease-fixture", Provider: "xai", Metadata: map[string]any{
		"refresh_disabled":         true,
		"prism_serving_expires_at": now.Add(time.Minute).Format(time.RFC3339),
		"expired":                  now.Add(time.Hour).Format(time.RFC3339),
	}}
	shard := &modelScheduler{modelKey: "grok", entries: make(map[string]*scheduledAuth)}
	shard.upsertEntryLocked(&scheduledAuthMeta{auth: account, supportedModelSet: map[string]struct{}{"grok": {}}}, now)
	if shard.entries[account.ID].state != scheduledStateReady {
		t.Fatal("valid serving lease was not ready")
	}
	shard.promoteExpiredLocked(now.Add(time.Minute))
	if shard.entries[account.ID].state != scheduledStateDisabled {
		t.Fatal("cached ready account survived serving lease expiry")
	}
}
