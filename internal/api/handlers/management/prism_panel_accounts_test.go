package management

import (
	"bytes"
	"context"
	"fmt"
	"github.com/gin-gonic/gin"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

func TestPrismPanelAccountFieldsPreserveLatestCredentialsAndRejectPartialEdits(t *testing.T) {
	handler, router, manager := controlFixture(t)
	router.PATCH("/v0/management/auth-files/fields", handler.PrismControlMiddleware(), handler.PatchAuthFileFields)
	router.PATCH("/v0/management/auth-files/status", handler.PrismControlMiddleware(), handler.PatchAuthFileStatus)
	revision := controlRevision(t, router)
	base, _ := manager.GetByID("test.json")
	refreshed := base.Clone()
	refreshed.Metadata["access_token"] = "fixture-refreshed-panel"
	_, _ = manager.UpdateRefreshedAuth(context.Background(), base, refreshed)
	response := panelCall(router, http.MethodPatch, "/v0/management/auth-files/fields", revision, "00000000-0000-4000-8000-000000000010", `{"name":"test.json","prefix":"example","excluded_models":["model-a"],"request_retry":4,"reserve_percent":null}`)
	updated, _ := manager.GetByID("test.json")
	if response.Code != http.StatusOK || updated.Prefix != "example" || updated.Metadata["access_token"] != "fixture-refreshed-panel" || updated.Metadata["request_retry"] != 4 {
		t.Fatalf("owner edit lost latest credentials or failed: %d", response.Code)
	}
	before, _ := os.ReadFile(filepath.Join(handler.cfg.AuthDir, "test.json"))
	response = panelCall(router, http.MethodPatch, "/v0/management/auth-files/fields", controlRevision(t, router), "00000000-0000-4000-8000-000000000011", `{"name":"test.json","prefix":"invalid-partial","reserve_percent":101}`)
	after, _ := os.ReadFile(filepath.Join(handler.cfg.AuthDir, "test.json"))
	updated, _ = manager.GetByID("test.json")
	if response.Code != http.StatusBadRequest || string(before) != string(after) || updated.Prefix != "example" {
		t.Fatal("invalid compound edit published partially")
	}
	response = panelCall(router, http.MethodPatch, "/v0/management/auth-files/fields", controlRevision(t, router), "00000000-0000-4000-8000-000000000012", `{"name":"test.json","access_token":"fixture-forbidden"}`)
	if response.Code != http.StatusConflict {
		t.Fatal("panel accepted raw credential replacement")
	}
	response = panelCall(router, http.MethodPatch, "/v0/management/auth-files/status", controlRevision(t, router), "00000000-0000-4000-8000-000000000013", `{"name":"test.json","disabled":true}`)
	updated, _ = manager.GetByID("test.json")
	if response.Code != http.StatusOK || !updated.Disabled || updated.Metadata["access_token"] != "fixture-refreshed-panel" {
		t.Fatal("status edit did not commit latest credentials atomically")
	}
}

func TestPrismPanelRejectsInvalidUploadAndDeletesOneAccountAtomically(t *testing.T) {
	handler, router, manager := controlFixture(t)
	router.POST("/v0/management/auth-files", handler.PrismControlMiddleware(), handler.UploadAuthFile)
	router.DELETE("/v0/management/auth-files", handler.PrismControlMiddleware(), handler.DeleteAuthFile)
	response := panelCall(router, http.MethodPost, "/v0/management/auth-files", controlRevision(t, router), "00000000-0000-4000-8000-000000000010", `{"type":"claude","access_token":"fixture-upload"}`)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "invalid_credential_file") {
		t.Fatal("legacy upload bypassed account transaction")
	}
	response = panelCall(router, http.MethodDelete, "/v0/management/auth-files?all=true", controlRevision(t, router), "00000000-0000-4000-8000-000000000011", "")
	if response.Code != http.StatusConflict {
		t.Fatal("nontransactional bulk delete accepted")
	}
	response = panelCall(router, http.MethodDelete, "/v0/management/auth-files?name=test.json", controlRevision(t, router), "00000000-0000-4000-8000-000000000012", "")
	if response.Code != http.StatusOK {
		t.Fatal("single account removal failed")
	}
	if _, exists := manager.GetByID("test.json"); exists {
		t.Fatal("account remained in routing")
	}
	if _, errStat := os.Stat(filepath.Join(handler.cfg.AuthDir, "test.json")); !os.IsNotExist(errStat) {
		t.Fatal("removed account retained in durable store")
	}
}

func TestPrismPanelAccountCommitRechecksWatcherChanges(t *testing.T) {
	handler, router, manager := controlFixture(t)
	revision := controlRevision(t, router)
	weight := 7
	_, _ = manager.UpdateAccountPolicy(context.Background(), "test.json", coreauth.AccountPolicyPatch{Weight: &weight})
	// The middleware accepted the original snapshot earlier; the commit callback
	// must independently reject a policy update from the watcher or another owner.
	response := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(response)
	ctx.Request = httptest.NewRequest(http.MethodPatch, "/v0/management/auth-files/fields", nil)
	ctx.Request.Header.Set("X-Prism-Expected-Revision", revision)
	handler.prismPanelPatchAccount(ctx, "test.json", func(account *coreauth.Auth) error { account.Prefix = "stale"; return nil })
	updated, _ := manager.GetByID("test.json")
	if response.Code != http.StatusConflict || updated.Prefix == "stale" || updated.Metadata["weight"] != weight {
		t.Fatal("watcher state was overwritten at panel account commit")
	}
}

func TestPrismPanelImportsOneCredentialAndFencesRefresh(t *testing.T) {
	handler, router, manager := controlFixture(t)
	router.POST("/v0/management/auth-files", handler.PrismControlMiddleware(), handler.UploadAuthFile)
	base, _ := manager.GetByID("test.json")
	response := panelCall(router, http.MethodPost, "/v0/management/auth-files?name=test.json", controlRevision(t, router), "00000000-0000-4000-8000-000000000020", `{"type":"claude","access_token":"fixture-imported","refresh_token":"fixture-new-refresh","weight":5}`)
	if response.Code != http.StatusOK {
		t.Fatalf("single import failed: %d", response.Code)
	}
	latest, _ := manager.GetByID("test.json")
	if latest.Metadata["access_token"] != "fixture-imported" || latest.RegistrationEpoch <= base.RegistrationEpoch {
		t.Fatal("imported file was not atomically registered")
	}
	pending := base.Clone()
	pending.Metadata["access_token"] = "fixture-stale-refresh"
	_, _ = manager.UpdateRefreshedAuth(context.Background(), base, pending)
	latest, _ = manager.GetByID("test.json")
	if latest.Metadata["access_token"] != "fixture-imported" {
		t.Fatal("old refresh replaced imported account")
	}
	before, _ := os.ReadFile(filepath.Join(handler.cfg.AuthDir, "test.json"))
	response = panelCall(router, http.MethodPost, "/v0/management/auth-files?name=test.json", controlRevision(t, router), "00000000-0000-4000-8000-000000000021", `{"type":"claude",`)
	after, _ := os.ReadFile(filepath.Join(handler.cfg.AuthDir, "test.json"))
	if response.Code != http.StatusBadRequest || string(before) != string(after) {
		t.Fatal("invalid import damaged stored account")
	}
	response = panelCall(router, http.MethodPost, "/v0/management/auth-files?name=disabled.json", controlRevision(t, router), "00000000-0000-4000-8000-000000000022", `{"type":"claude","access_token":"fixture-disabled-import","disabled":true}`)
	if response.Code != http.StatusOK {
		t.Fatal("disabled import failed")
	}
	if _, errStat := os.Stat(filepath.Join(handler.cfg.AuthDir, "disabled.json")); errStat != nil {
		t.Fatal("disabled import was acknowledged without a file")
	}
}

func TestPrismPanelMultipartImportIsOneBoundedCredentialTransaction(t *testing.T) {
	handler, router, manager := controlFixture(t)
	router.POST("/v0/management/auth-files", handler.PrismControlMiddleware(), handler.UploadAuthFile)
	for count := 1; count <= 2; count++ {
		var body bytes.Buffer
		form := multipart.NewWriter(&body)
		for index := 0; index < count; index++ {
			file, errCreate := form.CreateFormFile("file", fmt.Sprintf("multipart-%d.json", index))
			if errCreate != nil {
				t.Fatal(errCreate)
			}
			_, _ = file.Write([]byte(`{"type":"claude","access_token":"fixture-multipart"}`))
		}
		_ = form.Close()
		request := httptest.NewRequest(http.MethodPost, "/v0/management/auth-files", &body)
		request.Header.Set("Content-Type", form.FormDataContentType())
		request.Header.Set("X-Prism-Panel", "1")
		request.Header.Set("X-Prism-Actor", "fixture-admin")
		request.Header.Set("X-Prism-Expected-Revision", controlRevision(t, router))
		request.Header.Set("X-Prism-Operation-Id", fmt.Sprintf("00000000-0000-4000-8000-%012d", 30+count))
		response := httptest.NewRecorder()
		router.ServeHTTP(response, request)
		if count == 1 && response.Code != http.StatusOK || count == 2 && response.Code != http.StatusConflict {
			t.Fatalf("multipart count %d returned %d", count, response.Code)
		}
	}
	if _, exists := manager.GetByID("multipart-0.json"); !exists {
		t.Fatal("multipart import was not registered")
	}
	if _, exists := manager.GetByID("multipart-1.json"); exists {
		t.Fatal("rejected batch imported partially")
	}
}
