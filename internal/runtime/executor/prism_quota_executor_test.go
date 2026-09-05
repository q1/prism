package executor

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestPrismQuotaExecutorUsesFixedOriginAndRefusesRedirect(t *testing.T) {
	for _, provider := range []string{"claude", "codex"} {
		t.Run(provider, func(t *testing.T) {
			var observer cliproxyauth.PrismQuotaObserver
			if provider == "claude" {
				observer = NewClaudeExecutor(&config.Config{})
			} else {
				observer = NewCodexAutoExecutor(&config.Config{})
			}
			calls := 0
			ctx := context.WithValue(t.Context(), "cliproxy.roundtripper", roundTripperFunc(func(req *http.Request) (*http.Response, error) {
				calls++
				want := "https://api.anthropic.com/api/oauth/usage"
				if provider == "codex" {
					want = "https://chatgpt.com/backend-api/wham/usage"
				}
				if req.URL.String() != want || req.Method != http.MethodGet {
					t.Fatal("usage request escaped approved provider endpoint")
				}
				if req.Header.Get("Authorization") != "Bearer synthetic-access" {
					t.Fatal("missing owned account authorization")
				}
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://unrelated.example/collect"}}, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
			}))
			_, err := observer.PrismQuota(ctx, &cliproxyauth.Auth{Provider: provider, Metadata: map[string]any{"access_token": "synthetic-access", "account_id": "synthetic-account"}})
			if err == nil || calls != 1 {
				t.Fatal("provider redirect was followed or not classified")
			}
		})
	}
}
