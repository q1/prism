package management

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestPrismDevinSaveFencesCancellation(t *testing.T) {
	const state = "fixture-devin-save-fence"
	directory := t.TempDir()
	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: directory}, nil)
	RegisterOAuthSession(state, "devin")
	defer CompleteOAuthSession(state)
	path := filepath.Join(directory, ".oauth-devin-"+state+".oauth")
	if errWrite := os.WriteFile(path, []byte(`{"state":"`+state+`","code":"fixture-code"}`), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	called := false
	h.postAuthHook = func(context.Context, *coreauth.Auth) error {
		called = true
		if CancelOAuthSession(state) {
			t.Error("Devin login accepted cancellation after entering credential save")
		}
		return errors.New("fixture persistence failure")
	}
	h.completeDevinOAuth(context.Background(), directory, state, "fixture-verifier", &fakeDevinOAuthService{})
	_, status, exists := GetOAuthSession(state)
	if !called || !exists || status != "Failed to save authentication tokens" {
		t.Fatal("failed Devin commit lost its truthful lifecycle status")
	}
}

func TestPrismMetaSettingsRecheckRevisionAtCommit(t *testing.T) {
	for _, method := range []string{http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method, func(t *testing.T) {
			h, router, _ := controlFixture(t)
			h.cfg.MetaKey = []config.MetaKey{{APIKey: "fixture-meta-key", BaseURL: "https://example.invalid"}}
			revision := controlRevision(t, router)
			body := `[{"api-key":"fixture-replacement"}]`
			if method == http.MethodPatch {
				body = `{"index":0,"value":{"priority":7}}`
			}
			// Model an owner update after middleware admission but before commit.
			newer := h.cfg.CloneForRuntime()
			newer.Debug = true
			h.SetConfig(newer)
			before, errRead := os.ReadFile(h.configFilePath)
			if errRead != nil {
				t.Fatal(errRead)
			}
			response := httptest.NewRecorder()
			ctx, _ := gin.CreateTestContext(response)
			ctx.Request = httptest.NewRequest(method, "/v0/management/meta-api-key?index=0", strings.NewReader(body))
			ctx.Request.Header.Set("Content-Type", "application/json")
			ctx.Request.Header.Set("X-Prism-Expected-Revision", revision)
			if !h.prismPanelConfigTransaction(ctx) || response.Code != http.StatusConflict {
				t.Fatalf("Meta setter bypassed commit precondition: %d", response.Code)
			}
			after, _ := os.ReadFile(h.configFilePath)
			if string(before) != string(after) || len(h.cfg.MetaKey) != 1 || h.cfg.MetaKey[0].APIKey != "fixture-meta-key" || h.cfg.MetaKey[0].Priority != 0 {
				t.Fatal("stale Meta setter changed durable or runtime settings")
			}
		})
	}
}

func TestPrismQuotaRoutesPreservePluginOperatorBoundary(t *testing.T) {
	for _, path := range []string{"/quota/fetch", "/quota/reset"} {
		t.Run(path, func(t *testing.T) {
			h, router, _ := controlFixture(t)
			called := false
			router.POST("/v0/management"+path, h.PrismControlMiddleware(), func(c *gin.Context) { called = true })
			response := panelCall(router, http.MethodPost, "/v0/management"+path, controlRevision(t, router), "00000000-0000-4000-8000-000000000010", `{}`)
			if response.Code != http.StatusConflict || called || !strings.Contains(response.Body.String(), "prism_operation_requires_operator") {
				t.Fatal("credential quota route bypassed plugin operator boundary")
			}
		})
	}
}
