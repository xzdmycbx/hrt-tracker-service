package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"hrt-tracker-service/config"
	"hrt-tracker-service/database"
	"hrt-tracker-service/middleware"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

// ─── OIDC State Store ─────────────────────────────────────────────────────────

type oidcStateEntry struct {
	Action    string // "login" or "bind"
	UserID    uint   // Only populated for "bind" action
	CreatedAt time.Time
}

var (
	oidcStatesMu sync.Mutex
	oidcStates   = map[string]*oidcStateEntry{}
)

func storeOIDCState(action string, userID uint) string {
	state := uuid.New().String()
	oidcStatesMu.Lock()
	defer oidcStatesMu.Unlock()
	oidcStates[state] = &oidcStateEntry{
		Action:    action,
		UserID:    userID,
		CreatedAt: time.Now(),
	}
	return state
}

func consumeOIDCState(state string) (*oidcStateEntry, bool) {
	oidcStatesMu.Lock()
	defer oidcStatesMu.Unlock()
	entry, ok := oidcStates[state]
	if !ok {
		return nil, false
	}
	if time.Since(entry.CreatedAt) > 10*time.Minute {
		delete(oidcStates, state)
		return nil, false
	}
	delete(oidcStates, state)
	return entry, true
}

func init() {
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			oidcStatesMu.Lock()
			for k, v := range oidcStates {
				if time.Since(v.CreatedAt) > 10*time.Minute {
					delete(oidcStates, k)
				}
			}
			oidcStatesMu.Unlock()
		}
	}()
}

// ─── OIDC Discovery ───────────────────────────────────────────────────────────

type oidcDiscovery struct {
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	UserinfoEndpoint      string `json:"userinfo_endpoint"`
}

var (
	discoveryMu        sync.Mutex
	cachedDiscovery    *oidcDiscovery
	discoveryFetchedAt time.Time
)

func getOIDCDiscovery() (*oidcDiscovery, error) {
	discoveryMu.Lock()
	defer discoveryMu.Unlock()
	if cachedDiscovery != nil && time.Since(discoveryFetchedAt) < time.Hour {
		return cachedDiscovery, nil
	}

	discoveryURL := strings.TrimRight(config.AppConfig.OIDCProviderURL, "/") + "/.well-known/openid-configuration"
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(discoveryURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch OIDC discovery document: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read OIDC discovery response: %w", err)
	}

	var d oidcDiscovery
	if err := json.Unmarshal(body, &d); err != nil {
		return nil, fmt.Errorf("failed to parse OIDC discovery document: %w", err)
	}
	if d.AuthorizationEndpoint == "" || d.TokenEndpoint == "" || d.UserinfoEndpoint == "" {
		return nil, fmt.Errorf("OIDC discovery document is missing required fields")
	}

	cachedDiscovery = &d
	discoveryFetchedAt = time.Now()
	return cachedDiscovery, nil
}

// ─── OIDC Token Exchange ──────────────────────────────────────────────────────

type oidcTokenResponse struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
	Error       string `json:"error"`
	ErrorDesc   string `json:"error_description"`
}

type oidcUserInfo struct {
	Sub               string `json:"sub"`
	Email             string `json:"email"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
}

func exchangeOIDCCode(tokenEndpoint, code string) (*oidcTokenResponse, error) {
	data := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {config.AppConfig.OIDCRedirectURI},
		"client_id":     {config.AppConfig.OIDCClientID},
		"client_secret": {config.AppConfig.OIDCClientSecret},
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.PostForm(tokenEndpoint, data)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	// Check HTTP status before parsing body
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("token endpoint returned HTTP %d: %s", resp.StatusCode, string(body))
	}

	var t oidcTokenResponse
	if err := json.Unmarshal(body, &t); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}
	if t.Error != "" {
		return nil, fmt.Errorf("OIDC token error: %s — %s", t.Error, t.ErrorDesc)
	}
	if t.AccessToken == "" {
		return nil, fmt.Errorf("no access_token in OIDC token response")
	}
	return &t, nil
}

func fetchOIDCUserInfo(userinfoEndpoint, accessToken string) (*oidcUserInfo, error) {
	req, err := http.NewRequest("GET", userinfoEndpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read userinfo response: %w", err)
	}

	// Check HTTP status before parsing body
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("userinfo endpoint returned HTTP %d", resp.StatusCode)
	}

	var info oidcUserInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("failed to parse userinfo response: %w", err)
	}
	if info.Sub == "" {
		return nil, fmt.Errorf("userinfo response missing 'sub' claim")
	}
	return &info, nil
}

// ─── Username Generation ──────────────────────────────────────────────────────

// usernameRegex allows full email addresses (including @ and .) as usernames,
// up to 100 characters. This supports OIDC auto-registration using the full email.
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_.@+\-]{3,100}$`)
var sanitizeRegex = regexp.MustCompile(`[^a-zA-Z0-9_]`)

func generateUsernameFromOIDC(info *oidcUserInfo) string {
	sanitize := func(s string) string {
		s = sanitizeRegex.ReplaceAllString(s, "_")
		if len(s) > 20 {
			s = s[:20]
		}
		for len(s) < 3 {
			s = s + "_"
		}
		return s
	}

	var candidates []string
	// 1. Full email address — primary source, most stable identifier
	if info.Email != "" {
		candidates = append(candidates, info.Email) // e.g., alice@example.com
	}
	// 2. Email local part as fallback (if full email is taken)
	if info.Email != "" {
		parts := strings.SplitN(info.Email, "@", 2)
		if len(parts[0]) > 0 {
			candidates = append(candidates, sanitize(parts[0]))
		}
	}
	// 3. preferred_username as fallback
	if info.PreferredUsername != "" {
		candidates = append(candidates, sanitize(info.PreferredUsername))
	}
	// 4. Display name as fallback
	if info.Name != "" {
		candidates = append(candidates, sanitize(strings.ReplaceAll(info.Name, " ", "_")))
	}
	// 5. Subject-based last resort
	if info.Sub != "" {
		sub := info.Sub
		if len(sub) > 12 {
			sub = sub[len(sub)-12:]
		}
		candidates = append(candidates, sanitize("u_"+sub))
	}
	candidates = append(candidates, "user")

	db := database.GetDB()
	for _, base := range candidates {
		if !usernameRegex.MatchString(base) {
			continue
		}
		var count int64
		db.Model(&models.User{}).Where("username = ?", base).Count(&count)
		if count == 0 {
			return base
		}
		for i := 1; i <= 999; i++ {
			candidate := fmt.Sprintf("%s_%d", base, i)
			if len(candidate) > 100 {
				break
			}
			db.Model(&models.User{}).Where("username = ?", candidate).Count(&count)
			if count == 0 {
				return candidate
			}
		}
	}
	return "user_" + uuid.New().String()[:8]
}

// ─── Shared helper ────────────────────────────────────────────────────────────

func createSessionAndTokens(c *gin.Context, userID uint) (*TokenResponse, error) {
	sessionID := generateSessionID()
	deviceInfo := parseDeviceInfo(c.GetHeader("User-Agent"))
	ipAddress := getRealIP(c)

	accessToken, err := utils.GenerateAccessToken(userID, sessionID)
	if err != nil {
		return nil, err
	}
	refreshToken, err := utils.GenerateRefreshToken(userID)
	if err != nil {
		return nil, err
	}

	db := database.GetDB()
	tokenModel := models.RefreshToken{
		UserID:     userID,
		Token:      utils.HashRefreshToken(refreshToken),
		ExpiresAt:  time.Time{},
		SessionID:  sessionID,
		DeviceInfo: deviceInfo,
		IPAddress:  ipAddress,
		LastUsedAt: time.Now(),
	}
	db.Create(&tokenModel)

	return &TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    config.AppConfig.AccessTokenExpireHours * 3600,
	}, nil
}

// ─── Handlers ─────────────────────────────────────────────────────────────────

// OIDCGetConfig returns OIDC availability info for the frontend
func OIDCGetConfig(c *gin.Context) {
	utils.SuccessResponse(c, map[string]interface{}{
		"oidc_enabled":          config.AppConfig.OIDCEnabled,
		"registration_disabled": config.AppConfig.RegistrationDisabled,
	})
}

// OIDCGetAuthorizeURL returns the authorization URL + state for the OIDC login flow
func OIDCGetAuthorizeURL(c *gin.Context) {
	if !config.AppConfig.OIDCEnabled {
		utils.ForbiddenResponse(c, "OIDC is not enabled on this server")
		return
	}

	discovery, err := getOIDCDiscovery()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to fetch OIDC provider configuration")
		return
	}

	state := storeOIDCState("login", 0)
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {config.AppConfig.OIDCClientID},
		"redirect_uri":  {config.AppConfig.OIDCRedirectURI},
		"scope":         {config.AppConfig.OIDCScopes},
		"state":         {state},
	}
	authURL := discovery.AuthorizationEndpoint + "?" + params.Encode()

	utils.SuccessResponse(c, map[string]interface{}{
		"auth_url": authURL,
		"state":    state,
	})
}

// OIDCCallbackRequest carries the authorization code and state from the OIDC provider
type OIDCCallbackRequest struct {
	Code  string `json:"code" binding:"required"`
	State string `json:"state" binding:"required"`
}

// OIDCCallback handles the OIDC login / auto-register callback
func OIDCCallback(c *gin.Context) {
	if !config.AppConfig.OIDCEnabled {
		utils.ForbiddenResponse(c, "OIDC is not enabled on this server")
		return
	}

	var req OIDCCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	entry, ok := consumeOIDCState(req.State)
	if !ok {
		utils.BadRequestResponse(c, "Invalid or expired state parameter")
		return
	}
	if entry.Action != "login" {
		utils.BadRequestResponse(c, "State was not issued for login")
		return
	}

	discovery, err := getOIDCDiscovery()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to fetch OIDC provider configuration")
		return
	}

	tokenResp, err := exchangeOIDCCode(discovery.TokenEndpoint, req.Code)
	if err != nil {
		utils.BadRequestResponse(c, "Failed to exchange authorization code")
		return
	}

	userInfo, err := fetchOIDCUserInfo(discovery.UserinfoEndpoint, tokenResp.AccessToken)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to fetch OIDC user info")
		return
	}

	db := database.GetDB()
	providerID := config.AppConfig.OIDCProviderURL

	var resultUser models.User
	isNewUser := false
	var newUsername string

	txErr := db.Transaction(func(tx *gorm.DB) error {
		// Find existing user by OIDC subject (inside transaction to prevent race)
		var existing models.User
		if err := tx.Where("oidc_subject = ? AND oidc_provider = ?", userInfo.Sub, providerID).First(&existing).Error; err == nil {
			resultUser = existing
			return nil
		} else if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("database error during user lookup: %w", err)
		}

		// User not found — check if auto-register is allowed
		if !config.AppConfig.OIDCAutoRegister {
			return errors.New("auto_register_disabled")
		}

		// Generate candidate username (email local part first)
		baseUsername := generateUsernameFromOIDC(userInfo)
		newUser := models.User{
			Username:     baseUsername,
			Password:     "", // OIDC-only account
			OIDCSubject:  userInfo.Sub,
			OIDCProvider: providerID,
			OIDCEmail:    userInfo.Email,
		}

		// Attempt INSERT with retry on username uniqueness conflict
		created := false
		for attempt := 0; attempt <= 99; attempt++ {
			if attempt > 0 {
				candidate := fmt.Sprintf("%s_%d", baseUsername, attempt)
				if len(candidate) > 100 {
					break
				}
				newUser.Username = candidate
			}
			if err := tx.Create(&newUser).Error; err != nil {
				if errors.Is(err, gorm.ErrDuplicatedKey) {
					newUser.ID = 0 // reset so GORM doesn't treat it as an UPDATE
					continue
				}
				return fmt.Errorf("failed to create user account: %w", err)
			}
			created = true
			break
		}
		if !created {
			return fmt.Errorf("could not find a unique username after retries")
		}

		// Create UserData in the same transaction (prevents half-initialized accounts)
		if err := tx.Create(&models.UserData{UserID: newUser.ID, IsEncrypted: false}).Error; err != nil {
			return fmt.Errorf("failed to initialize user data: %w", err)
		}

		resultUser = newUser
		newUsername = newUser.Username
		isNewUser = true
		return nil
	})

	if txErr != nil {
		if txErr.Error() == "auto_register_disabled" {
			utils.ForbiddenResponse(c, "No account is linked to this OIDC identity. Please contact the administrator.")
		} else {
			utils.InternalErrorResponse(c, "Failed to complete OIDC login")
		}
		return
	}

	tokens, err := createSessionAndTokens(c, resultUser.ID)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate tokens")
		return
	}

	resp := map[string]interface{}{
		"tokens":      tokens,
		"is_new_user": isNewUser,
	}
	if isNewUser {
		resp["username"] = newUsername
	}
	utils.SuccessResponse(c, resp)
}

// OIDCGetBindAuthorizeURL returns the authorization URL for binding OIDC to an existing account
func OIDCGetBindAuthorizeURL(c *gin.Context) {
	if !config.AppConfig.OIDCEnabled {
		utils.ForbiddenResponse(c, "OIDC is not enabled on this server")
		return
	}

	userID := middleware.GetUserID(c)
	discovery, err := getOIDCDiscovery()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to fetch OIDC provider configuration")
		return
	}

	state := storeOIDCState("bind", userID)
	params := url.Values{
		"response_type": {"code"},
		"client_id":     {config.AppConfig.OIDCClientID},
		"redirect_uri":  {config.AppConfig.OIDCRedirectURI},
		"scope":         {config.AppConfig.OIDCScopes},
		"state":         {state},
	}
	authURL := discovery.AuthorizationEndpoint + "?" + params.Encode()

	utils.SuccessResponse(c, map[string]interface{}{
		"auth_url": authURL,
		"state":    state,
	})
}

// OIDCBindCallback handles the OIDC bind callback for an authenticated user
func OIDCBindCallback(c *gin.Context) {
	if !config.AppConfig.OIDCEnabled {
		utils.ForbiddenResponse(c, "OIDC is not enabled on this server")
		return
	}

	userID := middleware.GetUserID(c)

	var req OIDCCallbackRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	entry, ok := consumeOIDCState(req.State)
	if !ok {
		utils.BadRequestResponse(c, "Invalid or expired state parameter")
		return
	}
	if entry.Action != "bind" || entry.UserID != userID {
		utils.BadRequestResponse(c, "State was not issued for this bind operation")
		return
	}

	discovery, err := getOIDCDiscovery()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to fetch OIDC provider configuration")
		return
	}

	tokenResp, err := exchangeOIDCCode(discovery.TokenEndpoint, req.Code)
	if err != nil {
		utils.BadRequestResponse(c, "Failed to exchange authorization code")
		return
	}

	userInfo, err := fetchOIDCUserInfo(discovery.UserinfoEndpoint, tokenResp.AccessToken)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to fetch OIDC user info")
		return
	}

	db := database.GetDB()
	providerID := config.AppConfig.OIDCProviderURL

	// Wrap conflict-check + save in a transaction to prevent race conditions
	var bindErr string
	txErr := db.Transaction(func(tx *gorm.DB) error {
		// Ensure this OIDC identity isn't already bound to a different account
		var conflict models.User
		err = tx.Where("oidc_subject = ? AND oidc_provider = ? AND id != ?", userInfo.Sub, providerID, userID).First(&conflict).Error
		if err == nil {
			bindErr = "This OIDC identity is already linked to another account"
			return errors.New(bindErr)
		}
		if !errors.Is(err, gorm.ErrRecordNotFound) {
			return fmt.Errorf("database error during conflict check: %w", err)
		}

		var user models.User
		if err := tx.First(&user, userID).Error; err != nil {
			bindErr = "User not found"
			return errors.New(bindErr)
		}
		if user.OIDCSubject != "" {
			bindErr = "An OIDC identity is already linked to this account"
			return errors.New(bindErr)
		}

		user.OIDCSubject = userInfo.Sub
		user.OIDCProvider = providerID
		user.OIDCEmail = userInfo.Email
		return tx.Save(&user).Error
	})

	if txErr != nil {
		if bindErr != "" {
			utils.BadRequestResponse(c, bindErr)
		} else {
			utils.InternalErrorResponse(c, "Failed to link OIDC identity")
		}
		return
	}

	utils.SuccessMessageResponse(c, "OIDC identity linked successfully", nil)
}

// OIDCBindStatus returns the OIDC binding status for the current user
func OIDCBindStatus(c *gin.Context) {
	userID := middleware.GetUserID(c)
	db := database.GetDB()

	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	data := map[string]interface{}{
		"bound":        user.OIDCSubject != "",
		"has_password": user.Password != "",
	}
	if user.OIDCSubject != "" {
		data["oidc_subject"] = user.OIDCSubject
		data["oidc_email"] = user.OIDCEmail
		data["provider"] = user.OIDCProvider
	}
	utils.SuccessResponse(c, data)
}
