package management

import (
	"errors"
	"io"
	"net/http"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// Credential material and identity are replaced through the cancellable native
// login transaction. The panel metadata editor can change owner policy only.
func prismPanelOwnerField(path string) bool {
	if strings.Contains(path, ".") {
		return false
	}
	switch path {
	case "prefix", "proxy_url", "headers", "priority", "weight", "note", "websockets", "disabled", "excluded_models", "reserve_percent":
		return true
	default:
		return false
	}
}

func (h *Handler) prismPanelPatchAccount(c *gin.Context, id string, edit func(*coreauth.Auth) error) {
	expected := c.GetHeader("X-Prism-Expected-Revision")
	var validationError error
	h.mu.Lock()
	_, errCommit := h.authManager.EditAccountPolicyIf(c.Request.Context(), id, func(accounts []*coreauth.Auth) bool {
		return h.prismRevisionFor(accounts, h.prismSettingsLocked()) == expected
	}, func(latest *coreauth.Auth) error {
		validationError = edit(latest)
		return validationError
	})
	h.mu.Unlock()
	if validationError != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": validationError.Error()})
		return
	}
	if errCommit != nil {
		prismPanelAccountError(c, errCommit)
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func prismPanelAccountError(c *gin.Context, err error) {
	status, code := http.StatusInternalServerError, "prism_account_persist_failed"
	switch {
	case errors.Is(err, coreauth.ErrPersistenceDurabilityUncertain):
		status, code = http.StatusInternalServerError, "prism_account_persistence_uncertain"
	case errors.Is(err, coreauth.ErrAccountPolicyConflict):
		status, code = http.StatusConflict, "prism_settings_conflict"
	case errors.Is(err, coreauth.ErrAccountPolicyUnsupported):
		status, code = http.StatusConflict, "prism_account_requires_operator"
	case errors.Is(err, coreauth.ErrAccountPolicyNotFound):
		status, code = http.StatusNotFound, "prism_account_not_found"
	}
	c.JSON(status, gin.H{"error": code})
}

func (h *Handler) prismPanelAccountTransaction(c *gin.Context) bool {
	path := strings.TrimPrefix(c.Request.URL.Path, "/v0/management")
	// These legacy handlers replace files or mutate plugin runtimes before they
	// can validate a commit precondition. An explicit operator action is needed
	// until they have an atomic storage transaction like native account login.
	if path == "/auth-files" && c.Request.Method == http.MethodPost {
		c.Abort()
		h.prismPanelImportAccount(c)
		return true
	}
	if path == "/vertex/import" || strings.HasPrefix(path, "/plugins/") || strings.HasPrefix(path, "/plugin-store/") {
		c.AbortWithStatusJSON(http.StatusConflict, gin.H{"error": "prism_operation_requires_operator"})
		return true
	}
	if path != "/auth-files" || c.Request.Method != http.MethodDelete {
		return false
	}
	c.Abort()
	name := strings.TrimSpace(c.Query("name"))
	if name == "" || c.Query("all") != "" || h.authManager == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "prism_operation_requires_operator"})
		return true
	}
	target, _ := h.lookupAuthFile(name, strings.TrimSpace(c.Query("auth_index")))
	if target == nil {
		prismPanelAccountError(c, coreauth.ErrAccountPolicyNotFound)
		return true
	}
	h.mu.Lock()
	errRemove := h.authManager.RemoveAccountPolicyIf(c.Request.Context(), target.ID, func(accounts []*coreauth.Auth) bool {
		return h.prismRevisionFor(accounts, h.prismSettingsLocked()) == c.GetHeader("X-Prism-Expected-Revision")
	})
	h.mu.Unlock()
	if errRemove != nil {
		prismPanelAccountError(c, errRemove)
		return true
	}
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
	return true
}

// Upstream's normal upload UI issues one file per request. A whole credential is
// validated privately, then persisted and registered in one fenced transaction.
func (h *Handler) prismPanelImportAccount(c *gin.Context) {
	if h.authManager == nil {
		c.JSON(503, gin.H{"error": "prism_control_unavailable"})
		return
	}
	files, errMultipart := h.multipartAuthFileHeaders(c)
	if c.Request.MultipartForm != nil {
		defer func() { _ = c.Request.MultipartForm.RemoveAll() }()
	}
	if errMultipart != nil {
		c.JSON(400, gin.H{"error": "prism_invalid_credential_file"})
		return
	}
	if len(files) > 1 {
		c.JSON(409, gin.H{"error": "prism_upload_one_file_per_operation"})
		return
	}
	name := strings.TrimSpace(c.Query("name"))
	var reader io.Reader = c.Request.Body
	if len(files) == 1 {
		name = files[0].Filename
		file, errOpen := files[0].Open()
		if errOpen != nil {
			c.JSON(400, gin.H{"error": "prism_invalid_credential_file"})
			return
		}
		defer func() { _ = file.Close() }()
		reader = file
	}
	if isUnsafeAuthFileName(name) || filepath.Base(name) != name || !strings.HasSuffix(strings.ToLower(name), ".json") || strings.HasPrefix(name, ".") {
		c.JSON(400, gin.H{"error": "prism_invalid_credential_file"})
		return
	}
	data, errRead := io.ReadAll(io.LimitReader(reader, 262145))
	if errRead != nil || len(data) > 262144 {
		c.JSON(400, gin.H{"error": "prism_invalid_credential_file"})
		return
	}
	h.mu.Lock()
	// The isolated parser cannot capture a stale manager credential or invoke
	// account writes; only its parsed complete candidate enters the transaction.
	parser := &Handler{cfg: h.cfg.CloneForRuntime()}
	path := filepath.Join(parser.cfg.AuthDir, name)
	candidate, errParse := parser.buildAuthFromFileData(path, data)
	if errParse != nil || candidate == nil || candidate.Provider == "unknown" {
		h.mu.Unlock()
		c.JSON(400, gin.H{"error": "prism_invalid_credential_file"})
		return
	}
	_, errCommit := h.authManager.RegisterAccountIf(c.Request.Context(), candidate, func(accounts []*coreauth.Auth) bool {
		return h.prismRevisionFor(accounts, h.prismSettingsLocked()) == c.GetHeader("X-Prism-Expected-Revision")
	})
	h.mu.Unlock()
	if errCommit != nil {
		prismPanelAccountError(c, errCommit)
		return
	}
	c.JSON(200, gin.H{"status": "ok"})
}
