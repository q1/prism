package management

import (
	"net/http"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

type prismModelAvailability struct {
	ID             string     `json:"id"`
	Provider       string     `json:"provider"`
	Available      bool       `json:"available"`
	UsableAccounts int        `json:"usableAccounts"`
	Warnings       []string   `json:"warnings"`
	Reason         string     `json:"reason,omitempty"`
	NextEligibleAt *time.Time `json:"nextEligibleAt,omitempty"`
}

// GetPrismModels emits only model aggregates suitable for inference users. It
// retains registered unavailable models without exposing credential identities.
func (h *Handler) GetPrismModels(c *gin.Context) {
	if h == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "model availability unavailable"})
		return
	}
	now := time.Now().UTC()
	models := map[string]*prismModelAvailability{}
	warnings := map[string]map[string]bool{}
	for _, account := range h.authManager.List() {
		if account == nil {
			continue
		}
		registered := registry.GetGlobalRegistry().GetModelsForClient(account.ID)
		catalog := registered
		if len(catalog) == 0 {
			catalog = registry.GetGlobalRegistry().GetPrismModelCatalogForClient(account.ID, account.Provider)
		}
		for _, model := range catalog {
			if model == nil || model.ID == "" {
				continue
			}
			key := account.Provider + ":" + model.ID
			entry := models[key]
			if entry == nil {
				entry = &prismModelAvailability{ID: model.ID, Provider: account.Provider, Warnings: []string{}}
				models[key] = entry
				warnings[key] = map[string]bool{}
			}
			state := h.authManager.ModelEligibility(account, model.ID, now)
			if state.Available && len(registered) == 0 {
				state.Available = false
				state.Reason = "model_unregistered"
				state.NextEligibleAt = nil
			}
			if state.Available {
				entry.UsableAccounts++
				entry.Available = true
			} else {
				warnings[key][state.Reason] = true
				if state.NextEligibleAt != nil && (entry.NextEligibleAt == nil || state.NextEligibleAt.Before(*entry.NextEligibleAt)) {
					entry.NextEligibleAt = state.NextEligibleAt
				}
			}
		}
	}
	result := make([]*prismModelAvailability, 0, len(models))
	for key, entry := range models {
		for reason := range warnings[key] {
			entry.Warnings = append(entry.Warnings, reason)
		}
		sort.Strings(entry.Warnings)
		if !entry.Available {
			entry.Reason = "pool_unavailable"
			if len(entry.Warnings) == 1 {
				entry.Reason = entry.Warnings[0]
			}
		} else {
			entry.NextEligibleAt = nil
		}
		result = append(result, entry)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Provider != result[j].Provider {
			return result[i].Provider < result[j].Provider
		}
		return result[i].ID < result[j].ID
	})
	c.JSON(http.StatusOK, gin.H{"observedAt": now, "models": result})
}

type prismQuotaWindow struct {
	ID          string     `json:"id"`
	Utilization float64    `json:"utilization"`
	ResetAt     *time.Time `json:"resetAt,omitempty"`
	ObservedAt  time.Time  `json:"observedAt"`
}

func prismQuotaWindows(account *coreauth.Auth, now time.Time) []prismQuotaWindow {
	windows := []prismQuotaWindow{}
	for id, window := range coreauth.ObservedQuotaWindows(account.Provider, account.Quota, now) {
		windows = append(windows, prismQuotaWindow{ID: id, Utilization: window.UsedPercent / 100, ResetAt: window.ResetAt, ObservedAt: account.Quota.ObservedAt})
	}
	sort.Slice(windows, func(i, j int) bool { return windows[i].ID < windows[j].ID })
	return windows
}
