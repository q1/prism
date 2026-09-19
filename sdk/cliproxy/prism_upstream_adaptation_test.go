package cliproxy

import (
	"context"
	"testing"
	"time"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/config"
)

func TestPrismAntigravityRegistrationDoesNotWaitForCapabilities(t *testing.T) {
	svc := &Service{cfg: &config.Config{}}
	auth := &coreauth.Auth{ID: "fixture-async-registration", Provider: "antigravity",
		Attributes: map[string]string{"base_url": "https://fixture.invalid"},
		Metadata:   map[string]any{"access_token": "fixture-token"}}
	cacheKey := "https://fixture.invalid#" + svc.antigravityModelFetchProxyURL(auth)
	// Hold the capability cache to stop the probe without any network I/O.
	// Registration must publish baseline models before the probe can proceed.
	antigravityCapabilityMu.Lock()
	antigravityCapabilityCache[cacheKey] = antigravityCapabilityCacheEntry{expiresAt: time.Now().Add(time.Hour)}
	done := make(chan struct{})
	go func() {
		svc.registerModelsForAuth(context.Background(), auth)
		close(done)
	}()
	completed := false
	select {
	case <-done:
		completed = true
	case <-time.After(2 * time.Second): // Deadlock watchdog, not a timing assertion.
	}
	antigravityCapabilityMu.Unlock()
	<-done
	svc.WaitAntigravityProbes()
	t.Cleanup(func() {
		GlobalModelRegistry().UnregisterClient(auth.ID)
		antigravityCapabilityMu.Lock()
		delete(antigravityCapabilityCache, cacheKey)
		antigravityCapabilityMu.Unlock()
	})
	if !completed || len(GlobalModelRegistry().GetModelsForClient(auth.ID)) == 0 {
		t.Fatal("baseline registration waited for the upstream asynchronous capability probe")
	}
}
