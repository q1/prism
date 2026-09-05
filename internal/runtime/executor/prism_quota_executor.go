package executor

import (
	"context"
	"errors"
	"net/http"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func (e *CodexAutoExecutor) PrismQuota(ctx context.Context, auth *cliproxyauth.Auth) (http.Header, error) {
	if e == nil || e.httpExec == nil {
		return nil, errors.New("quota observation unavailable")
	}
	return e.httpExec.PrismQuota(ctx, auth)
}

// PrismQuota reads usage without rotating OAuth credentials or running inference.
func (e *ClaudeExecutor) PrismQuota(ctx context.Context, auth *cliproxyauth.Auth) (http.Header, error) {
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, "https://api.anthropic.com/api/oauth/usage", nil)
	if errRequest != nil {
		return nil, errRequest
	}
	req.Header.Set("Anthropic-Beta", "oauth-2025-04-20")
	if errPrepare := e.PrepareRequest(req, auth); errPrepare != nil {
		return nil, errPrepare
	}
	client := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, errRequest := client.Do(req)
	if errRequest != nil {
		return nil, errors.New("quota observation unavailable")
	}
	return helps.ReadPrismQuotaResponse("claude", response)
}

// PrismQuota uses the subscription usage endpoint, preserving account binding.
func (e *CodexExecutor) PrismQuota(ctx context.Context, auth *cliproxyauth.Auth) (http.Header, error) {
	req, errRequest := http.NewRequestWithContext(ctx, http.MethodGet, "https://chatgpt.com/backend-api/wham/usage", nil)
	if errRequest != nil {
		return nil, errRequest
	}
	if accountID, ok := auth.Metadata["account_id"].(string); ok && accountID != "" {
		req.Header.Set("ChatGPT-Account-Id", accountID)
	}
	if errPrepare := e.PrepareRequest(req, auth); errPrepare != nil {
		return nil, errPrepare
	}
	client := helps.NewUtlsHTTPClient(ctx, e.cfg, auth, 0)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, errRequest := client.Do(req)
	if errRequest != nil {
		return nil, errors.New("quota observation unavailable")
	}
	return helps.ReadPrismQuotaResponse("codex", response)
}
