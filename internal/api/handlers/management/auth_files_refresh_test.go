package management

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/executor"
)

type refreshRecordExecutor struct {
	provider   string
	refreshCnt atomic.Int32
}

func (e *refreshRecordExecutor) Identifier() string {
	return e.provider
}

func (e *refreshRecordExecutor) Refresh(ctx context.Context, auth *coreauth.Auth) (*coreauth.Auth, error) {
	e.refreshCnt.Add(1)
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["access_token"] = "refreshed-token"
	auth.Metadata["refresh_token"] = "refresh-token"
	auth.Metadata["expires_in"] = int64(3600)
	auth.Metadata["expired"] = time.Now().Add(time.Hour).Format(time.RFC3339)
	return auth, nil
}

func (e *refreshRecordExecutor) Execute(ctx context.Context, auth *coreauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *refreshRecordExecutor) ExecuteStream(ctx context.Context, auth *coreauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (*cliproxyexecutor.StreamResult, error) {
	return nil, nil
}

func (e *refreshRecordExecutor) CountTokens(ctx context.Context, auth *coreauth.Auth, req cliproxyexecutor.Request, opts cliproxyexecutor.Options) (cliproxyexecutor.Response, error) {
	return cliproxyexecutor.Response{}, nil
}

func (e *refreshRecordExecutor) HttpRequest(ctx context.Context, auth *coreauth.Auth, req *http.Request) (*http.Response, error) {
	return nil, nil
}

func TestRefreshAuthFiles_AllAndSpecific(t *testing.T) {
	gin.SetMode(gin.TestMode)
	authDir := t.TempDir()

	fileA := filepath.Join(authDir, "antigravity-1.json")
	fileB := filepath.Join(authDir, "antigravity-2.json")
	_ = os.WriteFile(fileA, []byte(`{"type":"antigravity","refresh_token":"ref-1","access_token":"old-1"}`), 0o600)
	_ = os.WriteFile(fileB, []byte(`{"type":"antigravity","refresh_token":"ref-2","access_token":"old-2"}`), 0o600)

	manager := coreauth.NewManager(nil, nil, nil)
	exec := &refreshRecordExecutor{provider: "antigravity"}
	manager.RegisterExecutor(exec)

	auth1 := &coreauth.Auth{
		ID:       "antigravity-1.json",
		Provider: "antigravity",
		Status:   coreauth.StatusActive,
		Metadata: map[string]any{"type": "antigravity", "refresh_token": "ref-1", "access_token": "old-1"},
	}
	auth2 := &coreauth.Auth{
		ID:          "antigravity-2.json",
		Provider:    "antigravity",
		Status:      coreauth.StatusError,
		Unavailable: true,
		LastError:   &coreauth.Error{Message: "unauthorized"},
		Metadata:    map[string]any{"type": "antigravity", "refresh_token": "ref-2", "access_token": "old-2"},
	}
	_, _ = manager.Register(context.Background(), auth1)
	_, _ = manager.Register(context.Background(), auth2)

	h := NewHandlerWithoutConfigFilePath(&config.Config{AuthDir: authDir}, manager)

	engine := gin.New()
	engine.POST("/auth-files/refresh", h.RefreshAuthFiles)

	// 1. Refresh all
	req := httptest.NewRequest(http.MethodPost, "/auth-files/refresh?all=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if ok, _ := resp["ok"].(bool); !ok {
		t.Fatalf("expected ok=true, got %v", resp)
	}

	if cnt := exec.refreshCnt.Load(); cnt < 2 {
		t.Fatalf("expected at least 2 refreshes, got %d", cnt)
	}

	// 2. Auth2 was in StatusError, now should be active/recovering
	a2, exists := manager.GetByID("antigravity-2.json")
	if !exists || a2.Status == coreauth.StatusError {
		t.Fatalf("expected auth2 status to be recovered from error, got %+v", a2)
	}

	// 3. Refresh single file by name
	prevCnt := exec.refreshCnt.Load()
	reqSingle := httptest.NewRequest(http.MethodPost, "/auth-files/refresh?name=antigravity-1.json", nil)
	wSingle := httptest.NewRecorder()
	engine.ServeHTTP(wSingle, reqSingle)

	if wSingle.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", wSingle.Code, wSingle.Body.String())
	}
	if newCnt := exec.refreshCnt.Load(); newCnt != prevCnt+1 {
		t.Fatalf("expected cnt to increment by 1, was %d now %d", prevCnt, newCnt)
	}
	var receipt struct {
		OK   bool           `json:"ok"`
		Auth map[string]any `json:"auth"`
	}
	if err := json.Unmarshal(wSingle.Body.Bytes(), &receipt); err != nil {
		t.Fatal(err)
	}
	if !receipt.OK || receipt.Auth["id"] != auth1.ID || receipt.Auth["status"] != string(coreauth.StatusActive) {
		t.Fatal("refresh receipt lost account lifecycle state")
	}
	for _, field := range []string{"metadata", "attributes", "storage", "proxy_url", "access_token", "refresh_token"} {
		if _, exists := receipt.Auth[field]; exists {
			t.Fatalf("refresh receipt exposes private field %s", field)
		}
	}
	for _, token := range []string{"refreshed-token", "refresh-token", "old-1", "ref-1"} {
		if strings.Contains(wSingle.Body.String(), token) {
			t.Fatal("refresh receipt exposes fixture credential")
		}
	}

	// 4. Refresh nonexistent file
	reqMissing := httptest.NewRequest(http.MethodPost, "/auth-files/refresh?name=nonexistent.json", nil)
	wMissing := httptest.NewRecorder()
	engine.ServeHTTP(wMissing, reqMissing)

	if wMissing.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", wMissing.Code, wMissing.Body.String())
	}

	// 5. Refresh via chunked JSON request body (ContentLength = -1)
	chunkedBody := strings.NewReader(`{"name":"antigravity-1.json"}`)
	reqChunked := httptest.NewRequest(http.MethodPost, "/auth-files/refresh", chunkedBody)
	reqChunked.Header.Set("Content-Type", "application/json")
	reqChunked.TransferEncoding = []string{"chunked"}
	reqChunked.ContentLength = -1
	wChunked := httptest.NewRecorder()
	engine.ServeHTTP(wChunked, reqChunked)

	if wChunked.Code != http.StatusOK {
		t.Fatalf("expected chunked request status 200, got %d: %s", wChunked.Code, wChunked.Body.String())
	}

	// 6. Malformed JSON request body returns 400
	reqBadJSON := httptest.NewRequest(http.MethodPost, "/auth-files/refresh", strings.NewReader(`{invalid`))
	reqBadJSON.Header.Set("Content-Type", "application/json")
	wBadJSON := httptest.NewRecorder()
	engine.ServeHTTP(wBadJSON, reqBadJSON)

	if wBadJSON.Code != http.StatusBadRequest {
		t.Fatalf("expected malformed JSON to return 400, got %d", wBadJSON.Code)
	}
}

func TestRefreshAuthFilesPrismPanelRevisionAndReplay(t *testing.T) {
	handler, router, manager := controlFixture(t)
	executor := &refreshRecordExecutor{provider: "claude"}
	manager.RegisterExecutor(executor)
	const path = "/v0/management/auth-files/refresh"
	router.POST(path, handler.PrismReplicaMiddleware(), handler.PrismControlMiddleware(), handler.RefreshAuthFiles)
	revision := controlRevision(t, router)
	const operation = "00000000-0000-4000-8000-000000000091"
	response := panelCall(router, http.MethodPost, path, revision, operation, `{"name":"test.json"}`)
	if response.Code != http.StatusOK || executor.refreshCnt.Load() != 1 || response.Header().Get("X-Prism-Settings-Revision") == revision {
		t.Fatal("manual refresh did not participate in panel revision protocol")
	}
	replay := panelCall(router, http.MethodPost, path, revision, operation, `{"name":"test.json"}`)
	if replay.Code != http.StatusConflict || executor.refreshCnt.Load() != 1 {
		t.Fatal("replayed operation refreshed twice")
	}
	stale := panelCall(router, http.MethodPost, path, revision, "00000000-0000-4000-8000-000000000092", `{"all":true}`)
	if stale.Code != http.StatusConflict || executor.refreshCnt.Load() != 1 {
		t.Fatal("stale panel revision reached bulk refresh")
	}
	handler.cfg.PrismReplica = true
	blocked := panelCall(router, http.MethodPost, path, controlRevision(t, router), "00000000-0000-4000-8000-000000000093", `{"all":true}`)
	if blocked.Code != http.StatusForbidden || executor.refreshCnt.Load() != 1 {
		t.Fatal("replica reached manual refresh")
	}
}
