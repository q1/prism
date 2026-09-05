package management

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

func panelCall(router *gin.Engine, method, path, revision, operation, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("X-Prism-Panel", "1")
	request.Header.Set("X-Prism-Actor", "fixture-admin")
	request.Header.Set("X-Prism-Expected-Revision", revision)
	request.Header.Set("X-Prism-Operation-Id", operation)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	return response
}

func TestPrismPanelOperationReadCASAndBoundedReceipt(t *testing.T) {
	handler, router, _ := controlFixture(t)
	var writes int
	router.PATCH("/v0/management/panel-fixture", handler.PrismControlMiddleware(), func(c *gin.Context) {
		writes++
		c.JSON(http.StatusOK, gin.H{"fixture": "synthetic-provider-value"})
	})
	read := panelCall(router, http.MethodGet, "/v0/management/prism/control", "", "", "")
	revision := read.Header().Get("X-Prism-Settings-Revision")
	if read.Code != http.StatusOK || len(revision) != 64 {
		t.Fatal("panel read did not bind a revision")
	}
	operation := "00000000-0000-4000-8000-000000000001"
	applied := panelCall(router, http.MethodPatch, "/v0/management/panel-fixture", revision, operation, `{"value":true}`)
	if applied.Code != http.StatusOK || writes != 1 || applied.Header().Get("X-Prism-Settings-Revision") == revision {
		t.Fatal("panel operation did not commit exactly once")
	}
	replay := panelCall(router, http.MethodPatch, "/v0/management/panel-fixture", revision, operation, `{"value":true}`)
	if replay.Code != http.StatusConflict || writes != 1 || !strings.Contains(replay.Body.String(), "prism_operation_recorded") {
		t.Fatal("recorded operation was silently reapplied")
	}
	if strings.Contains(fmt.Sprintf("%#v", handler.prismControl.panelOperations), "synthetic-provider-value") {
		t.Fatal("upstream response retained in operation ledger")
	}
	conflict := panelCall(router, http.MethodPatch, "/v0/management/panel-fixture", revision, operation, `{"value":false}`)
	if conflict.Code != http.StatusConflict || writes != 1 || !strings.Contains(conflict.Body.String(), "prism_operation_conflict") {
		t.Fatal("operation ID reuse was accepted")
	}
	stale := panelCall(router, http.MethodPatch, "/v0/management/panel-fixture", revision, "00000000-0000-4000-8000-000000000002", `{}`)
	if stale.Code != http.StatusConflict || writes != 1 {
		t.Fatal("stale panel CAS accepted")
	}
}

func TestPrismPanelPartialFailureAdvancesRevisionAndRejectsLargeInput(t *testing.T) {
	handler, router, _ := controlFixture(t)
	writes := 0
	router.PATCH("/v0/management/panel-fixture", handler.PrismControlMiddleware(), func(c *gin.Context) { writes++; c.JSON(500, gin.H{"error": "synthetic failure"}) })
	revision := controlRevision(t, router)
	operation := "00000000-0000-4000-8000-000000000001"
	failed := panelCall(router, http.MethodPatch, "/v0/management/panel-fixture", revision, operation, `{}`)
	if failed.Code != 500 || failed.Header().Get("X-Prism-Settings-Revision") == revision {
		t.Fatal("partial failure retained a stale revision")
	}
	large := panelCall(router, http.MethodPatch, "/v0/management/panel-fixture", controlRevision(t, router), "00000000-0000-4000-8000-000000000002", strings.Repeat(" ", 1_048_577))
	if large.Code != 413 || writes != 1 {
		t.Fatal("oversized panel operation reached handler")
	}
}
