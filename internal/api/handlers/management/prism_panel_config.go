package management

import (
	"bytes"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

// Legacy configuration setters run against an isolated candidate and private
// staging file. Their validation and field semantics are reused without exposing
// partial mutations to live routing or racing an OAuth/file-watcher commit.
func (h *Handler) prismPanelConfigTransaction(c *gin.Context) bool {
	candidate := &Handler{}
	handlers := map[string]gin.HandlerFunc{
		"PUT /quota-exceeded/switch-project":         candidate.PutSwitchProject,
		"PATCH /quota-exceeded/switch-project":       candidate.PutSwitchProject,
		"PUT /quota-exceeded/switch-preview-model":   candidate.PutSwitchPreviewModel,
		"PATCH /quota-exceeded/switch-preview-model": candidate.PutSwitchPreviewModel,
		"PUT /config.yaml":                           candidate.PutConfigYAML,
		"PUT /debug":                                 candidate.PutDebug,
		"PATCH /debug":                               candidate.PutDebug,
		"PUT /logging-to-file":                       candidate.PutLoggingToFile,
		"PATCH /logging-to-file":                     candidate.PutLoggingToFile,
		"PUT /logs-max-total-size-mb":                candidate.PutLogsMaxTotalSizeMB,
		"PATCH /logs-max-total-size-mb":              candidate.PutLogsMaxTotalSizeMB,
		"PUT /error-logs-max-files":                  candidate.PutErrorLogsMaxFiles,
		"PATCH /error-logs-max-files":                candidate.PutErrorLogsMaxFiles,
		"PUT /usage-statistics-enabled":              candidate.PutUsageStatisticsEnabled,
		"PATCH /usage-statistics-enabled":            candidate.PutUsageStatisticsEnabled,
		"PUT /proxy-url":                             candidate.PutProxyURL,
		"PATCH /proxy-url":                           candidate.PutProxyURL,
		"DELETE /proxy-url":                          candidate.DeleteProxyURL,
		"PUT /api-keys":                              candidate.PutAPIKeys,
		"PATCH /api-keys":                            candidate.PatchAPIKeys,
		"DELETE /api-keys":                           candidate.DeleteAPIKeys,
		"PUT /gemini-api-key":                        candidate.PutGeminiKeys,
		"PATCH /gemini-api-key":                      candidate.PatchGeminiKey,
		"DELETE /gemini-api-key":                     candidate.DeleteGeminiKey,
		"PUT /interactions-api-key":                  candidate.PutInteractionsKeys,
		"PATCH /interactions-api-key":                candidate.PatchInteractionsKey,
		"DELETE /interactions-api-key":               candidate.DeleteInteractionsKey,
		"PUT /request-log":                           candidate.PutRequestLog,
		"PATCH /request-log":                         candidate.PutRequestLog,
		"PUT /ws-auth":                               candidate.PutWebsocketAuth,
		"PATCH /ws-auth":                             candidate.PutWebsocketAuth,
		"PUT /request-retry":                         candidate.PutRequestRetry,
		"PATCH /request-retry":                       candidate.PutRequestRetry,
		"PUT /max-retry-credentials":                 candidate.PutMaxRetryCredentials,
		"PATCH /max-retry-credentials":               candidate.PutMaxRetryCredentials,
		"PUT /max-retry-interval":                    candidate.PutMaxRetryInterval,
		"PATCH /max-retry-interval":                  candidate.PutMaxRetryInterval,
		"PUT /force-model-prefix":                    candidate.PutForceModelPrefix,
		"PATCH /force-model-prefix":                  candidate.PutForceModelPrefix,
		"PUT /routing/strategy":                      candidate.PutRoutingStrategy,
		"PATCH /routing/strategy":                    candidate.PutRoutingStrategy,
		"PUT /claude-api-key":                        candidate.PutClaudeKeys,
		"PATCH /claude-api-key":                      candidate.PatchClaudeKey,
		"DELETE /claude-api-key":                     candidate.DeleteClaudeKey,
		"PUT /codex-api-key":                         candidate.PutCodexKeys,
		"PATCH /codex-api-key":                       candidate.PatchCodexKey,
		"DELETE /codex-api-key":                      candidate.DeleteCodexKey,
		"PUT /xai-api-key":                           candidate.PutXAIKeys,
		"PATCH /xai-api-key":                         candidate.PatchXAIKey,
		"DELETE /xai-api-key":                        candidate.DeleteXAIKey,
		"PUT /openai-compatibility":                  candidate.PutOpenAICompat,
		"PATCH /openai-compatibility":                candidate.PatchOpenAICompat,
		"DELETE /openai-compatibility":               candidate.DeleteOpenAICompat,
		"PUT /vertex-api-key":                        candidate.PutVertexCompatKeys,
		"PATCH /vertex-api-key":                      candidate.PatchVertexCompatKey,
		"DELETE /vertex-api-key":                     candidate.DeleteVertexCompatKey,
		"PUT /oauth-excluded-models":                 candidate.PutOAuthExcludedModels,
		"PATCH /oauth-excluded-models":               candidate.PatchOAuthExcludedModels,
		"DELETE /oauth-excluded-models":              candidate.DeleteOAuthExcludedModels,
		"PUT /oauth-model-alias":                     candidate.PutOAuthModelAlias,
		"PATCH /oauth-model-alias":                   candidate.PatchOAuthModelAlias,
		"DELETE /oauth-model-alias":                  candidate.DeleteOAuthModelAlias,
		"PUT /oauth-request-scoped-errors":           candidate.PutOAuthRequestScopedErrors,
		"PATCH /oauth-request-scoped-errors":         candidate.PatchOAuthRequestScopedErrors,
		"DELETE /oauth-request-scoped-errors":        candidate.DeleteOAuthRequestScopedErrors,
	}
	operation := handlers[c.Request.Method+" "+strings.TrimPrefix(c.Request.URL.Path, "/v0/management")]
	if operation == nil {
		return false
	}
	c.Abort()
	expected := c.GetHeader("X-Prism-Expected-Revision")
	h.mu.Lock()
	if h.cfg == nil || h.authManager == nil {
		h.mu.Unlock()
		c.JSON(503, gin.H{"error": "prism_control_unavailable"})
		return true
	}
	candidate.cfg = h.cfg.CloneForRuntime()
	h.mu.Unlock()
	directory, errTemp := os.MkdirTemp(filepath.Dir(h.configFilePath), ".prism-config-transaction-")
	if errTemp != nil {
		c.JSON(500, gin.H{"error": "prism_settings_persist_failed"})
		return true
	}
	defer func() { _ = os.RemoveAll(directory) }()
	candidate.configFilePath = filepath.Join(directory, "config.yaml")
	encoded, errEncode := yaml.Marshal(candidate.cfg)
	if errEncode != nil || os.WriteFile(candidate.configFilePath, encoded, 0o600) != nil {
		c.JSON(500, gin.H{"error": "prism_settings_persist_failed"})
		return true
	}
	// A second response buffer allows a failed commit to replace the staged
	// success response, so no successful acknowledgement escapes before commit.
	original := c.Writer
	staged := &prismPanelWriter{ResponseWriter: original, headers: make(http.Header), status: http.StatusOK}
	c.Writer = staged
	operation(c)
	c.Writer = original
	if staged.status >= 400 || staged.overflow {
		if staged.overflow {
			c.JSON(502, gin.H{"error": "prism_response_too_large"})
		} else {
			c.Data(staged.status, staged.headers.Get("Content-Type"), staged.body.Bytes())
		}
		return true
	}
	candidate.mu.Lock()
	desired := candidate.cfg.CloneForRuntime()
	candidate.mu.Unlock()
	h.mu.Lock()
	var snapshot configReloadSnapshot
	errCommit := h.authManager.CheckAccountPolicySnapshot(func(accounts []*coreauth.Auth) error {
		if h.prismRevisionFor(accounts, h.prismSettingsLocked()) != expected {
			return coreauth.ErrAccountPolicyConflict
		}
		if !prismSameRuntimeWiring(h.cfg, desired) {
			return errPrismRuntimeWiring
		}
		if errSave := config.SaveConfigPreserveComments(h.configFilePath, desired); errSave != nil {
			return errSave
		}
		h.cfg = desired
		snapshot = h.reloadSnapshotConfigLocked()
		return nil
	})
	h.mu.Unlock()
	if errCommit != nil {
		status, code := 500, "prism_settings_persist_failed"
		if errCommit == coreauth.ErrAccountPolicyConflict {
			status, code = 409, "prism_settings_conflict"
		}
		if errCommit == errPrismRuntimeWiring {
			status, code = 409, "prism_runtime_wiring_requires_operator"
		}
		c.JSON(status, gin.H{"error": code})
		return true
	}
	h.reloadConfigAfterManagementSave(c.Request.Context(), snapshot)
	for name, values := range staged.headers {
		c.Writer.Header()[name] = values
	}
	c.Data(staged.status, staged.headers.Get("Content-Type"), staged.body.Bytes())
	return true
}

var errPrismRuntimeWiring = errors.New("runtime wiring requires an operator")

func prismSameRuntimeWiring(current, desired *config.Config) bool {
	// These values bind the host, its private keys, plugin runtime and central
	// eligibility authority. They are not remotely editable panel preferences.
	a, _ := yaml.Marshal(map[string]any{"host": current.Host, "port": current.Port, "auth": current.AuthDir, "tls": current.TLS, "management": current.RemoteManagement, "keys": current.APIKeys, "replica": current.PrismReplica, "policy": current.Routing.PrismPolicy, "plugins": current.Plugins})
	b, _ := yaml.Marshal(map[string]any{"host": desired.Host, "port": desired.Port, "auth": desired.AuthDir, "tls": desired.TLS, "management": desired.RemoteManagement, "keys": desired.APIKeys, "replica": desired.PrismReplica, "policy": desired.Routing.PrismPolicy, "plugins": desired.Plugins})
	return bytes.Equal(a, b) && reflect.DeepEqual(current.Home, desired.Home)
}
