package management

import (
	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"net/http"
	"time"
)

// GetQuotaSchedulerStatus supplies the subscription-window protocol consumed by T3 clients.
// Missing observations stay absent; this endpoint never makes provider requests.
func (h *Handler) GetQuotaSchedulerStatus(c *gin.Context) {
	accounts := make(map[string]any)
	if h != nil && h.authManager != nil {
		for _, auth := range h.authManager.List() {
			if auth == nil || !coreauth.ProviderSupportsQuotaObservation(auth.Provider) {
				continue
			}
			name := auth.FileName
			if name == "" {
				name = auth.ID
			}
			entry := map[string]any{"provider": auth.Provider}
			if !auth.Quota.ObservedAt.IsZero() {
				entry["fetched_at"] = auth.Quota.ObservedAt
			}
			if auth.Provider == "codex" {
				for key, value := range auth.Quota.Signals {
					if http.CanonicalHeaderKey(key) == "X-Codex-Plan-Type" {
						entry["plan"] = value
					}
				}
			}
			for key, window := range coreauth.ObservedQuotaWindows(auth.Provider, auth.Quota, time.Now()) {
				entry[key] = window
			}
			accounts[name] = entry
		}
	}
	c.JSON(http.StatusOK, gin.H{"accounts": accounts})
}
