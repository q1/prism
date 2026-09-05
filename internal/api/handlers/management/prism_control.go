package management

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	coreauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
	"gopkg.in/yaml.v3"
)

type prismControlState struct {
	mu              sync.Mutex
	epoch           string
	generation      uint64
	receipts        map[string]prismReceipt
	logins          map[string]prismLogin
	panelOperations map[string]prismPanelOperation
}

type prismReceipt struct {
	fingerprint string
	createdAt   time.Time
	result      gin.H
}

type prismLogin struct {
	actor     string
	provider  string
	expiresAt time.Time
	cancelled bool
}

type prismSettings struct {
	Strategy         string `json:"strategy"`
	SessionAffinity  bool   `json:"sessionAffinity"`
	RequestRetry     int    `json:"requestRetry"`
	MaxRetryInterval int    `json:"maxRetryInterval"`
	configDigest     string
}

func (settings *prismSettings) UnmarshalJSON(data []byte) error {
	var input struct {
		Strategy         *string `json:"strategy"`
		SessionAffinity  *bool   `json:"sessionAffinity"`
		RequestRetry     *int    `json:"requestRetry"`
		MaxRetryInterval *int    `json:"maxRetryInterval"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if errDecode := decoder.Decode(&input); errDecode != nil {
		return errDecode
	}
	if input.Strategy == nil || input.SessionAffinity == nil || input.RequestRetry == nil || input.MaxRetryInterval == nil {
		return errors.New("all supported settings are required")
	}
	*settings = prismSettings{Strategy: *input.Strategy, SessionAffinity: *input.SessionAffinity, RequestRetry: *input.RequestRetry, MaxRetryInterval: *input.MaxRetryInterval}
	return nil
}

var prismOperationID = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)
var prismActorID = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,256}$`)

// PrismControlMiddleware serializes the versioned API with legacy panel edits.
// The mutex covers only administration; model traffic and token refresh do not
// depend on it. A fresh epoch invalidates pre-restart mutation preconditions.
func (h *Handler) PrismControlMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		panel := c.GetHeader("X-Prism-Panel") == "1"
		if !prismControlledPath(path) && !panel {
			c.Next()
			return
		}
		h.prismControl.mu.Lock()
		defer h.prismControl.mu.Unlock()
		if errInit := h.initPrismControl(); errInit != nil {
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{"error": "prism_control_unavailable"})
			return
		}
		if panel {
			h.prismPanelOperation(c)
			return
		}
		c.Next()
		if !strings.HasPrefix(path, "/v0/management/prism/") && c.Writer.Status() >= 200 && c.Writer.Status() < 300 &&
			(c.Request.Method != http.MethodGet || strings.HasSuffix(path, "-auth-url")) {
			h.prismControl.generation++
		}
	}
}

func prismControlledPath(path string) bool {
	const prefix = "/v0/management/"
	if !strings.HasPrefix(path, prefix) {
		return false
	}
	path = strings.TrimPrefix(path, prefix)
	return strings.HasPrefix(path, "prism/") || strings.HasPrefix(path, "auth-files") ||
		strings.HasPrefix(path, "routing/") || strings.HasPrefix(path, "config") ||
		strings.HasPrefix(path, "oauth-") || strings.HasSuffix(path, "-api-key") ||
		strings.HasSuffix(path, "-auth-url") || path == "request-retry" ||
		path == "max-retry-interval" || path == "max-retry-credentials"
}

func (h *Handler) initPrismControl() error {
	if h.prismControl.epoch != "" {
		return nil
	}
	var epoch [16]byte
	if _, errRandom := rand.Read(epoch[:]); errRandom != nil {
		return errRandom
	}
	h.prismControl.epoch = hex.EncodeToString(epoch[:])
	h.prismControl.receipts = make(map[string]prismReceipt)
	h.prismControl.logins = make(map[string]prismLogin)
	h.prismControl.panelOperations = make(map[string]prismPanelOperation)
	return nil
}

func (h *Handler) prismSettings() prismSettings {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.prismSettingsLocked()
}

func (h *Handler) prismSettingsLocked() prismSettings {
	if h.cfg == nil {
		return prismSettings{}
	}
	strategy, ok := normalizeRoutingStrategy(h.cfg.Routing.Strategy)
	if !ok {
		strategy = h.cfg.Routing.Strategy
	}
	// Config edits outside the four everyday fields must invalidate a panel
	// precondition too. Provider OAuth refresh material is held in account files,
	// not this configuration; a refresh therefore leaves this digest unchanged.
	encoded, _ := yaml.Marshal(h.cfg)
	digest := sha256.Sum256(encoded)
	return prismSettings{Strategy: strategy, SessionAffinity: h.cfg.Routing.SessionAffinity,
		RequestRetry: h.cfg.RequestRetry, MaxRetryInterval: h.cfg.MaxRetryInterval, configDigest: hex.EncodeToString(digest[:])}
}

// The revision excludes tokens, quota samples and counters: refreshing an
// account cannot invalidate an unrelated settings edit. Account identity and
// policy remain part of the precondition, including changes made by the panel
// or a file watcher. Only a digest leaves this process.
func (h *Handler) prismRevision() string {
	var auths []*coreauth.Auth
	if h.authManager != nil {
		auths = h.authManager.List()
	}
	return h.prismRevisionFor(auths, h.prismSettings())
}

func (h *Handler) prismRevisionFor(auths []*coreauth.Auth, settings prismSettings) string {
	policies := make([]gin.H, 0)
	for _, auth := range auths {
		if auth == nil {
			continue
		}
		reserve, exists := auth.Metadata["reserve_percent"]
		if !exists {
			reserve = float64(3)
		}
		policies = append(policies, gin.H{"id": auth.ID, "name": auth.FileName, "provider": auth.Provider,
			"disabled": auth.Disabled, "weight": auth.Metadata[coreauth.AttributeWeight], "reserve": reserve,
			"prefix": auth.Prefix, "excluded": auth.Metadata["excluded_models"],
			"proxy_url": auth.ProxyURL, "headers": auth.Metadata["headers"], "priority": auth.Metadata["priority"],
			"note": auth.Metadata["note"], "websockets": auth.Metadata["websockets"], "request_retry": auth.Metadata["request_retry"]})
	}
	sort.Slice(policies, func(i, j int) bool { return policies[i]["id"].(string) < policies[j]["id"].(string) })
	data, _ := json.Marshal(gin.H{"epoch": h.prismControl.epoch, "generation": h.prismControl.generation,
		"settings": settings, "config": settings.configDigest, "accounts": policies})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}

func (h *Handler) prismSnapshot() gin.H {
	files := make([]gin.H, 0)
	var auths []*coreauth.Auth
	if h.authManager != nil {
		auths = h.authManager.List()
		for _, auth := range auths {
			if auth != nil {
				if entry := h.buildAuthFileEntry(auth); entry != nil {
					files = append(files, entry)
				}
			}
		}
	}
	sort.Slice(files, func(i, j int) bool { return files[i]["name"].(string) < files[j]["name"].(string) })
	settings := h.prismSettings()
	return gin.H{"contractVersion": 1, "settingsRevision": h.prismRevisionFor(auths, settings), "settings": settings, "files": files}
}

func (h *Handler) GetPrismControl(c *gin.Context) {
	if h.cfg == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "prism_control_unavailable"})
		return
	}
	c.JSON(http.StatusOK, h.prismSnapshot())
}

type prismControlRequest struct {
	Actor                    string                     `json:"actor"`
	OperationID              string                     `json:"operationId"`
	ExpectedSettingsRevision string                     `json:"expectedSettingsRevision"`
	Action                   string                     `json:"action"`
	Account                  string                     `json:"account,omitempty"`
	Patch                    map[string]json.RawMessage `json:"patch,omitempty"`
	Settings                 *prismSettings             `json:"settings,omitempty"`
	Provider                 string                     `json:"provider,omitempty"`
	SessionID                string                     `json:"sessionId,omitempty"`
	RedirectURL              string                     `json:"redirectUrl,omitempty"`
}

func decodePrismJSON(reader io.Reader, value any) error {
	data, errRead := io.ReadAll(io.LimitReader(reader, 16_385))
	if errRead != nil || len(data) > 16_384 {
		return errors.New("invalid control body size")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if errDecode := decoder.Decode(value); errDecode != nil {
		return errDecode
	}
	if errTail := decoder.Decode(new(any)); errTail != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}

func (h *Handler) PostPrismControl(c *gin.Context) {
	var request prismControlRequest
	if errDecode := decodePrismJSON(c.Request.Body, &request); errDecode != nil ||
		!prismActorID.MatchString(request.Actor) || !prismOperationID.MatchString(request.OperationID) ||
		len(request.ExpectedSettingsRevision) != 64 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "prism_invalid_operation"})
		return
	}
	if h.cfg == nil || h.authManager == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "prism_control_unavailable"})
		return
	}
	encoded, _ := json.Marshal(request)
	hash := sha256.Sum256(encoded)
	fingerprint := hex.EncodeToString(hash[:])
	key := request.Actor + ":" + strings.ToLower(request.OperationID)
	if previous, found := h.prismControl.receipts[key]; found {
		if previous.fingerprint != fingerprint {
			c.JSON(http.StatusConflict, gin.H{"error": "prism_operation_conflict"})
			return
		}
		c.JSON(http.StatusOK, previous.result)
		return
	}
	if request.ExpectedSettingsRevision != h.prismRevision() {
		c.JSON(http.StatusConflict, gin.H{"error": "prism_settings_conflict"})
		return
	}
	var result gin.H
	var failure string
	status := http.StatusBadRequest
	switch request.Action {
	case "settings.update":
		status, failure = h.putPrismSettings(c, request.Settings, request.ExpectedSettingsRevision)
	case "account.update":
		status, failure = h.patchPrismAccount(c, request.Account, request.Patch, request.ExpectedSettingsRevision)
	case "account.remove":
		status, failure = h.removePrismAccount(c, request.Account, request.ExpectedSettingsRevision)
	case "login.start":
		result, status, failure = h.startPrismLogin(c, request.Actor, request.Provider)
	case "login.callback", "login.cancel":
		result, status, failure = h.updatePrismLogin(c, request)
	default:
		failure = "prism_invalid_operation"
	}
	if failure != "" {
		c.JSON(status, gin.H{"error": failure})
		return
	}
	h.prismControl.generation++
	if result == nil {
		result = h.prismSnapshot()
	}
	result["operationId"] = request.OperationID
	result["status"] = "applied"
	result["settingsRevision"] = h.prismRevision()
	// Receipts contain only sanitized settings/account observations and login
	// URLs already returned to this actor; they never contain provider tokens.
	now := time.Now()
	if len(h.prismControl.receipts) >= 2048 {
		oldestKey := ""
		var oldest time.Time
		for id, receipt := range h.prismControl.receipts {
			if now.Sub(receipt.createdAt) > time.Hour {
				delete(h.prismControl.receipts, id)
			} else if oldestKey == "" || receipt.createdAt.Before(oldest) {
				oldest, oldestKey = receipt.createdAt, id
			}
		}
		if len(h.prismControl.receipts) >= 2048 {
			delete(h.prismControl.receipts, oldestKey)
		}
	}
	h.prismControl.receipts[key] = prismReceipt{fingerprint, now, result}
	c.JSON(http.StatusOK, result)
}

func (h *Handler) putPrismSettings(c *gin.Context, settings *prismSettings, expectedRevision string) (int, string) {
	if settings == nil {
		return http.StatusBadRequest, "prism_invalid_settings"
	}
	strategy, valid := normalizeRoutingStrategy(settings.Strategy)
	if !valid || strategy != settings.Strategy || settings.RequestRetry < 0 || settings.RequestRetry > 10 ||
		settings.MaxRetryInterval < 0 || settings.MaxRetryInterval > 300 {
		return http.StatusBadRequest, "prism_invalid_settings"
	}
	h.mu.Lock()
	var snapshot configReloadSnapshot
	errSave := h.authManager.CheckAccountPolicySnapshot(func(accounts []*coreauth.Auth) error {
		if h.prismRevisionFor(accounts, h.prismSettingsLocked()) != expectedRevision {
			return coreauth.ErrAccountPolicyConflict
		}
		previous := h.cfg.CloneForRuntime()
		h.cfg.Routing.Strategy = strategy
		h.cfg.Routing.SessionAffinity = settings.SessionAffinity
		h.cfg.RequestRetry = settings.RequestRetry
		h.cfg.MaxRetryInterval = settings.MaxRetryInterval
		if errPersist := config.SaveConfigPreserveComments(h.configFilePath, h.cfg); errPersist != nil {
			*h.cfg = *previous
			return errPersist
		}
		snapshot = h.reloadSnapshotConfigLocked()
		return nil
	})
	h.mu.Unlock()
	if errors.Is(errSave, coreauth.ErrAccountPolicyConflict) {
		return http.StatusConflict, "prism_settings_conflict"
	}
	if errSave != nil {
		return http.StatusInternalServerError, "prism_settings_persist_failed"
	}
	h.reloadConfigAfterManagementSave(c.Request.Context(), snapshot)
	return http.StatusOK, ""
}

func (h *Handler) patchPrismAccount(c *gin.Context, name string, fields map[string]json.RawMessage, expectedRevision string) (int, string) {
	if isUnsafeAuthFileName(name) || !strings.HasSuffix(name, ".json") || len(fields) == 0 {
		return http.StatusBadRequest, "prism_invalid_account_patch"
	}
	patch := coreauth.AccountPolicyPatch{}
	for key, raw := range fields {
		switch key {
		case "disabled":
			var disabled bool
			if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &disabled) != nil {
				return http.StatusBadRequest, "prism_invalid_account_patch"
			}
			patch.Disabled = &disabled
		case "weight":
			var weight int
			if bytes.Equal(raw, []byte("null")) || json.Unmarshal(raw, &weight) != nil || weight < 0 || weight > 1_000_000 {
				return http.StatusBadRequest, "prism_invalid_account_patch"
			}
			patch.Weight = &weight
		case "reservePercent":
			patch.ReserveSet = true
			if !bytes.Equal(raw, []byte("null")) {
				var reserve float64
				if json.Unmarshal(raw, &reserve) != nil || reserve < 0 || reserve > 100 {
					return http.StatusBadRequest, "prism_invalid_account_patch"
				}
				patch.ReservePercent = &reserve
			}
		default:
			return http.StatusBadRequest, "prism_invalid_account_patch"
		}
	}
	account := h.findAuthForDelete(name)
	if account == nil {
		return http.StatusNotFound, "prism_account_not_found"
	}
	h.mu.Lock()
	_, errUpdate := h.authManager.UpdateAccountPolicyIf(c.Request.Context(), account.ID, patch, func(auths []*coreauth.Auth) bool {
		return h.prismRevisionFor(auths, h.prismSettingsLocked()) == expectedRevision
	})
	h.mu.Unlock()
	if errUpdate != nil {
		if errors.Is(errUpdate, coreauth.ErrPersistenceDurabilityUncertain) {
			return http.StatusInternalServerError, "prism_account_persistence_uncertain"
		}
		if errors.Is(errUpdate, coreauth.ErrAccountPolicyConflict) {
			return http.StatusConflict, "prism_settings_conflict"
		}
		if errors.Is(errUpdate, coreauth.ErrAccountPolicyNotFound) {
			return http.StatusNotFound, "prism_account_not_found"
		}
		if errors.Is(errUpdate, coreauth.ErrAccountPolicyUnsupported) {
			return http.StatusConflict, "prism_account_policy_unsupported"
		}
		return http.StatusInternalServerError, "prism_account_persist_failed"
	}
	return http.StatusOK, ""
}

func (h *Handler) removePrismAccount(c *gin.Context, name, expectedRevision string) (int, string) {
	if isUnsafeAuthFileName(name) || !strings.HasSuffix(name, ".json") {
		return http.StatusBadRequest, "prism_invalid_account"
	}
	account := h.findAuthForDelete(name)
	if account == nil {
		return http.StatusNotFound, "prism_account_not_found"
	}
	h.mu.Lock()
	errRemove := h.authManager.RemoveAccountPolicyIf(c.Request.Context(), account.ID, func(auths []*coreauth.Auth) bool {
		return h.prismRevisionFor(auths, h.prismSettingsLocked()) == expectedRevision
	})
	h.mu.Unlock()
	if errors.Is(errRemove, coreauth.ErrAccountPolicyConflict) {
		return http.StatusConflict, "prism_settings_conflict"
	}
	if errors.Is(errRemove, coreauth.ErrAccountPolicyUnsupported) {
		return http.StatusConflict, "prism_account_policy_unsupported"
	}
	if errRemove != nil {
		return http.StatusInternalServerError, "prism_account_remove_failed"
	}
	return http.StatusOK, ""
}

// invokePrismLogin preserves the upstream provider login implementation while
// giving its result an actor-bound, versioned envelope. No callback listener is
// requested: remote clients submit the provider's completed callback explicitly.
func invokePrismLogin(c *gin.Context, method, target string, body any, handler gin.HandlerFunc) (map[string]json.RawMessage, int) {
	originalRequest, originalWriter := c.Request, c.Writer
	defer func() { c.Request, c.Writer = originalRequest, originalWriter }()
	var input []byte
	if body != nil {
		input, _ = json.Marshal(body)
	}
	request := originalRequest.Clone(originalRequest.Context())
	request.Method = method
	request.URL, _ = url.Parse(target)
	request.RequestURI = target
	request.Body = io.NopCloser(bytes.NewReader(input))
	request.ContentLength = int64(len(input))
	request.Header = originalRequest.Header.Clone()
	request.Header.Set("Content-Type", "application/json")
	writer := &prismLoginWriter{ResponseWriter: originalWriter, header: make(http.Header), status: http.StatusOK}
	c.Request, c.Writer = request, writer
	handler(c)
	var result map[string]json.RawMessage
	if writer.overflow || json.Unmarshal(writer.body.Bytes(), &result) != nil {
		return nil, http.StatusBadGateway
	}
	return result, writer.status
}

type prismLoginWriter struct {
	gin.ResponseWriter
	header   http.Header
	body     bytes.Buffer
	status   int
	overflow bool
}

func (w *prismLoginWriter) Header() http.Header               { return w.header }
func (w *prismLoginWriter) WriteHeader(status int)            { w.status = status }
func (w *prismLoginWriter) WriteHeaderNow()                   {}
func (w *prismLoginWriter) Status() int                       { return w.status }
func (w *prismLoginWriter) Size() int                         { return w.body.Len() }
func (w *prismLoginWriter) Written() bool                     { return w.body.Len() > 0 }
func (w *prismLoginWriter) Flush()                            {}
func (w *prismLoginWriter) WriteString(s string) (int, error) { return w.Write([]byte(s)) }
func (w *prismLoginWriter) Write(data []byte) (int, error) {
	if w.body.Len()+len(data) > 16_384 {
		w.overflow = true
		return len(data), nil
	}
	return w.body.Write(data)
}

func (h *Handler) startPrismLogin(c *gin.Context, actor, provider string) (gin.H, int, string) {
	var handler gin.HandlerFunc
	switch provider {
	case "anthropic":
		handler = h.RequestAnthropicToken
	case "codex":
		handler = h.RequestCodexToken
	case "xai":
		handler = h.RequestXAIToken
	case "antigravity":
		handler = h.RequestAntigravityToken
	case "kimi":
		handler = h.RequestKimiToken
	default:
		return nil, http.StatusBadRequest, "prism_invalid_login_provider"
	}
	now := time.Now()
	for id, login := range h.prismControl.logins {
		if !login.expiresAt.After(now) {
			delete(h.prismControl.logins, id)
		}
	}
	if len(h.prismControl.logins) >= 64 {
		return nil, http.StatusTooManyRequests, "prism_login_capacity"
	}
	data, status := invokePrismLogin(c, http.MethodGet, "/v0/management/"+provider+"-auth-url", nil, handler)
	if status != http.StatusOK {
		return nil, status, "prism_login_start_failed"
	}
	var sessionID, authURL, flow, userCode string
	_ = json.Unmarshal(data["state"], &sessionID)
	_ = json.Unmarshal(data["url"], &authURL)
	_ = json.Unmarshal(data["flow"], &flow)
	_ = json.Unmarshal(data["user_code"], &userCode)
	parsed, errURL := url.Parse(authURL)
	if ValidateOAuthState(sessionID) != nil || errURL != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil {
		return nil, http.StatusBadGateway, "prism_invalid_login_response"
	}
	if flow != "device" {
		flow = "redirect"
	}
	h.prismControl.logins[sessionID] = prismLogin{actor: actor, provider: provider, expiresAt: now.Add(10 * time.Minute)}
	result := gin.H{"sessionId": sessionID, "authUrl": authURL, "flow": flow}
	if userCode != "" {
		result["userCode"] = userCode
	}
	return result, http.StatusOK, ""
}

func (h *Handler) prismLoginStatus(actor, id string) (gin.H, int, string) {
	login, found := h.prismControl.logins[id]
	if !found || login.actor != actor || !login.expiresAt.After(time.Now()) {
		return nil, http.StatusNotFound, "prism_login_not_found"
	}
	state := "pending"
	if login.cancelled {
		state = "cancelled"
	} else {
		_, failure, _, _, completed, exists := GetOAuthSessionDetails(id)
		if completed {
			state = "completed"
		} else if !exists || failure != "" {
			state = "failed"
		}
	}
	return gin.H{"sessionId": id, "status": state, "settingsRevision": h.prismRevision()}, http.StatusOK, ""
}

func (h *Handler) GetPrismLogin(c *gin.Context) {
	result, status, failure := h.prismLoginStatus(c.GetHeader("X-Prism-Actor"), c.Param("id"))
	if failure != "" {
		c.JSON(status, gin.H{"error": failure})
		return
	}
	c.JSON(status, result)
}

func (h *Handler) updatePrismLogin(c *gin.Context, request prismControlRequest) (gin.H, int, string) {
	login, found := h.prismControl.logins[request.SessionID]
	if !found || login.actor != request.Actor || !login.expiresAt.After(time.Now()) {
		return nil, http.StatusNotFound, "prism_login_not_found"
	}
	if request.Action == "login.cancel" {
		if !CancelOAuthSession(request.SessionID) {
			return nil, http.StatusConflict, "prism_login_already_finished"
		}
		login.cancelled = true
		h.prismControl.logins[request.SessionID] = login
		return gin.H{"sessionId": request.SessionID, "loginStatus": "cancelled"}, http.StatusOK, ""
	}
	parsed, errURL := url.Parse(request.RedirectURL)
	if login.cancelled || errURL != nil || parsed.User != nil || parsed.Fragment != "" ||
		(parsed.Scheme != "http" && parsed.Scheme != "https") ||
		(parsed.Hostname() != "localhost" && parsed.Hostname() != "127.0.0.1" && parsed.Hostname() != "::1") ||
		len(parsed.Query()["state"]) != 1 || parsed.Query().Get("state") != request.SessionID ||
		len(parsed.Query()["code"]) != 1 || parsed.Query().Get("code") == "" {
		return nil, http.StatusBadRequest, "prism_invalid_login_callback"
	}
	_, status := invokePrismLogin(c, http.MethodPost, "/v0/management/oauth-callback",
		gin.H{"state": request.SessionID, "redirect_url": request.RedirectURL}, h.PostOAuthCallback)
	if status != http.StatusOK {
		return nil, status, "prism_login_callback_failed"
	}
	return gin.H{"sessionId": request.SessionID, "loginStatus": "pending"}, http.StatusOK, ""
}
