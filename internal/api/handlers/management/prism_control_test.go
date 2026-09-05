package management

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	fileauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/auth"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func controlFixture(t *testing.T) (*Handler, *gin.Engine, *coreauth.Manager) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	dir := t.TempDir()
	store := fileauth.NewFileTokenStore()
	store.SetBaseDir(dir)
	manager := coreauth.NewManager(store, nil, nil)
	_, errRegister := manager.Register(context.Background(), &coreauth.Auth{ID: "test.json", FileName: "test.json", Provider: "claude",
		Status: coreauth.StatusActive, Metadata: map[string]any{"type": "claude", "access_token": "fixture-access-token", "refresh_token": "fixture-refresh-token"}})
	if errRegister != nil {
		t.Fatal(errRegister)
	}
	cfg := &config.Config{AuthDir: dir, Routing: config.RoutingConfig{Strategy: "round-robin"}, RequestRetry: 2, MaxRetryInterval: 30}
	configPath := filepath.Join(dir, "config.yaml")
	if errWrite := os.WriteFile(configPath, []byte("routing:\n  strategy: round-robin\nrequest-retry: 2\nmax-retry-interval: 30\n"), 0o600); errWrite != nil {
		t.Fatal(errWrite)
	}
	handler := &Handler{cfg: cfg, configFilePath: configPath, authManager: manager, tokenStore: store}
	router := gin.New()
	group := router.Group("/v0/management", handler.PrismControlMiddleware())
	group.GET("/prism/control", handler.GetPrismControl)
	group.POST("/prism/control", handler.PostPrismControl)
	group.GET("/prism/logins/:id", handler.GetPrismLogin)
	group.PUT("/routing/strategy", handler.PutRoutingStrategy)
	return handler, router, manager
}

func controlCall(t *testing.T, router *gin.Engine, method, path string, data any) *httptest.ResponseRecorder {
	t.Helper()
	input, errEncode := json.Marshal(data)
	if errEncode != nil {
		t.Fatal(errEncode)
	}
	request := httptest.NewRequest(method, path, strings.NewReader(string(input)))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func controlRevision(t *testing.T, router *gin.Engine) string {
	t.Helper()
	response := controlCall(t, router, http.MethodGet, "/v0/management/prism/control", nil)
	if response.Code != 200 {
		t.Fatalf("snapshot returned %d", response.Code)
	}
	var data struct {
		SettingsRevision string `json:"settingsRevision"`
	}
	if errDecode := json.Unmarshal(response.Body.Bytes(), &data); errDecode != nil {
		t.Fatal(errDecode)
	}
	if len(data.SettingsRevision) != 64 {
		t.Fatal("snapshot revision missing")
	}
	return data.SettingsRevision
}

func operationBody(revision string, number int) gin.H {
	return gin.H{"actor": "fixture_admin", "operationId": fmt.Sprintf("00000000-0000-4000-8000-%012d", number),
		"expectedSettingsRevision": revision, "action": "settings.update",
		"settings": prismSettings{Strategy: "fill-first", SessionAffinity: false, RequestRetry: 1, MaxRetryInterval: 20}}
}

func TestPrismControlConcurrentCASIdempotencyAndLegacyPanel(t *testing.T) {
	handler, router, _ := controlFixture(t)
	var reloads atomic.Int32
	handler.configReloadHook = func(context.Context, *config.Config) { reloads.Add(1) }
	revision := controlRevision(t, router)
	requests := []gin.H{operationBody(revision, 1), operationBody(revision, 2)}
	responses := make([]*httptest.ResponseRecorder, 2)
	var workers sync.WaitGroup
	for index := range requests {
		workers.Add(1)
		go func(index int) {
			defer workers.Done()
			responses[index] = controlCall(t, router, "POST", "/v0/management/prism/control", requests[index])
		}(index)
	}
	workers.Wait()
	winner := 0
	if responses[0].Code != 200 {
		winner = 1
	}
	if responses[winner].Code != 200 || responses[1-winner].Code != 409 {
		t.Fatal("concurrent stale writes both committed")
	}
	if reloads.Load() != 1 {
		t.Fatal("settings did not reload exactly once")
	}
	replayed := controlCall(t, router, "POST", "/v0/management/prism/control", requests[winner])
	if replayed.Code != 200 || replayed.Body.String() != responses[winner].Body.String() || reloads.Load() != 1 {
		t.Fatal("receipt retry reapplied a mutation")
	}
	requests[winner]["settings"] = prismSettings{Strategy: "round-robin"}
	if controlCall(t, router, "POST", "/v0/management/prism/control", requests[winner]).Code != 409 {
		t.Fatal("operation ID reused for a different action")
	}
	beforePanel := controlRevision(t, router)
	if controlCall(t, router, "PUT", "/v0/management/routing/strategy", gin.H{"value": "round-robin"}).Code != 200 {
		t.Fatal("legacy panel edit failed")
	}
	if controlCall(t, router, "POST", "/v0/management/prism/control", operationBody(beforePanel, 3)).Code != 409 {
		t.Fatal("legacy panel did not invalidate revision")
	}
}

func TestPrismControlWatcherCommitChecksAndSettingsFailure(t *testing.T) {
	handler, router, manager := controlFixture(t)
	revision := controlRevision(t, router)
	account, _ := manager.GetByID("test.json")
	account.Disabled = true
	account.Metadata["disabled"] = true
	_, _ = manager.Update(context.Background(), account)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/v0/management/prism/control", nil)
	settings := prismSettings{Strategy: "fill-first", RequestRetry: 1, MaxRetryInterval: 20}
	if status, _ := handler.putPrismSettings(ctx, &settings, revision); status != 409 {
		t.Fatal("watcher update not checked at settings commit")
	}
	patch := map[string]json.RawMessage{"disabled": json.RawMessage(`false`)}
	if status, _ := handler.patchPrismAccount(ctx, "test.json", patch, revision); status != 409 {
		t.Fatal("watcher update not checked at account commit")
	}
	if status, _ := handler.removePrismAccount(ctx, "test.json", revision); status != 409 {
		t.Fatal("watcher update not checked at remove commit")
	}
	revision = controlRevision(t, router)
	handler.configFilePath = handler.cfg.AuthDir
	if controlCall(t, router, "POST", "/v0/management/prism/control", operationBody(revision, 1)).Code != 500 {
		t.Fatal("failed config persistence was acknowledged")
	}
	if handler.cfg.Routing.Strategy != "round-robin" || handler.cfg.RequestRetry != 2 {
		t.Fatal("failed settings save changed live values")
	}
}

func TestPrismControlPolicyReadbackRemovalAndRefreshIsolation(t *testing.T) {
	_, router, manager := controlFixture(t)
	revision := controlRevision(t, router)
	base, _ := manager.GetByID("test.json")
	fresh := base.Clone()
	fresh.Metadata["access_token"] = "fixture-new-access-token"
	_, _ = manager.UpdateRefreshedAuth(context.Background(), base, fresh)
	if controlRevision(t, router) != revision {
		t.Fatal("token refresh invalidated unrelated policy revision")
	}
	operation := operationBody(revision, 1)
	delete(operation, "settings")
	operation["action"], operation["account"], operation["patch"] = "account.update", "test.json", gin.H{"disabled": true, "weight": 7, "reservePercent": nil}
	response := controlCall(t, router, "POST", "/v0/management/prism/control", operation)
	if response.Code != 200 {
		t.Fatalf("policy returned %d", response.Code)
	}
	updated, _ := manager.GetByID("test.json")
	if !updated.Disabled || updated.Metadata["weight"] != 7 || updated.Metadata["access_token"] != "fixture-new-access-token" {
		t.Fatal("policy lost current credentials or did not apply")
	}
	for _, secret := range []string{"fixture-new-access-token", "fixture-refresh-token"} {
		if strings.Contains(response.Body.String(), secret) {
			t.Fatal("credential exposed in control snapshot")
		}
	}
	remove := operationBody(controlRevision(t, router), 2)
	delete(remove, "settings")
	remove["action"], remove["account"] = "account.remove", "test.json"
	if controlCall(t, router, "POST", "/v0/management/prism/control", remove).Code != 200 {
		t.Fatal("remove failed")
	}
	if _, exists := manager.GetByID("test.json"); exists {
		t.Fatal("removed account still routable")
	}
	if _, errFile := os.Stat(updated.Attributes["path"]); !os.IsNotExist(errFile) {
		t.Fatal("removed credential still on disk")
	}
}

func TestPrismControlLoginActorAndFinishedCancellation(t *testing.T) {
	handler, router, _ := controlFixture(t)
	_ = controlRevision(t, router)
	id := "prism_fixture_completed_login"
	RegisterOAuthSession(id, "codex")
	handler.prismControl.logins[id] = prismLogin{actor: "fixture_admin", provider: "codex", expiresAt: time.Now().Add(time.Minute)}
	CompleteOAuthSession(id)
	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest("POST", "/v0/management/prism/control", nil)
	if _, status, _ := handler.updatePrismLogin(ctx, prismControlRequest{Actor: "other_admin", SessionID: id, Action: "login.cancel"}); status != 404 {
		t.Fatal("another actor cancelled a login")
	}
	if _, status, _ := handler.updatePrismLogin(ctx, prismControlRequest{Actor: "fixture_admin", SessionID: id, Action: "login.cancel"}); status != 409 {
		t.Fatal("completed login reported cancelled")
	}
	result, status, _ := handler.prismLoginStatus("fixture_admin", id)
	if status != 200 || result["status"] != "completed" {
		t.Fatal("completed account state was hidden")
	}
}

func TestPrismControlRejectsIncompleteSettingsAndRestartReplay(t *testing.T) {
	handler, router, _ := controlFixture(t)
	revision := controlRevision(t, router)
	input := operationBody(revision, 1)
	input["settings"] = gin.H{"strategy": "fill-first"}
	if controlCall(t, router, "POST", "/v0/management/prism/control", input).Code != 400 {
		t.Fatal("missing settings silently defaulted")
	}
	input = operationBody(revision, 2)
	input["unknown"] = true
	if controlCall(t, router, "POST", "/v0/management/prism/control", input).Code != 400 {
		t.Fatal("unknown operation field accepted")
	}
	handler.prismControl = prismControlState{}
	if controlCall(t, router, "POST", "/v0/management/prism/control", operationBody(revision, 3)).Code != 409 {
		t.Fatal("old process revision admitted replay")
	}
}
