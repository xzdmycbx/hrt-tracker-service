package handlers

import (
	"errors"
	"fmt"
	"hrt-tracker-service/config"
	"hrt-tracker-service/database"
	"hrt-tracker-service/middleware"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"gorm.io/gorm"
)

type RegisterRequest struct {
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
	TurnstileToken string `json:"turnstile_token"` // Optional when Turnstile is disabled
}

type LoginRequest struct {
	Username       string `json:"username" binding:"required"`
	Password       string `json:"password" binding:"required"`
	TurnstileToken string `json:"turnstile_token"` // Optional when Turnstile is disabled
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type TokenResponse struct {
	AccessToken      string `json:"access_token"`
	RefreshToken     string `json:"refresh_token"`
	ExpiresIn        int    `json:"expires_in"`
	RequiresOIDCBind bool   `json:"requires_oidc_bind,omitempty"` // true when REGISTRATION_DISABLED and OIDC not yet bound
}

// Register handles user registration
func Register(c *gin.Context) {
	// Check if registration is disabled
	if config.AppConfig.RegistrationDisabled {
		utils.ForbiddenResponse(c, "Registration is disabled on this server")
		return
	}

	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Verify Turnstile token
	remoteIP := getRealIP(c)
	// Pass empty action to make it optional (recommended: set data-action="register" on frontend)
	isInternalError, err := utils.VerifyTurnstileToken(req.TurnstileToken, remoteIP, "")
	if err != nil {
		if isInternalError {
			utils.InternalErrorResponse(c, "Failed to verify captcha")
		} else {
			utils.BadRequestResponse(c, "Invalid captcha")
		}
		return
	}

	// Validate username (alphanumeric and underscore, 3-20 characters)
	if !regexp.MustCompile(`^[a-zA-Z0-9_]{3,20}$`).MatchString(req.Username) {
		utils.BadRequestResponse(c, "Username must be 3-20 alphanumeric characters or underscore")
		return
	}

	// Validate password (minimum 6 characters)
	if len(req.Password) < 6 {
		utils.BadRequestResponse(c, "Password must be at least 6 characters")
		return
	}

	db := database.GetDB()

	// Check if username exists
	var existingUser models.User
	if err := db.Where("username = ?", req.Username).First(&existingUser).Error; err == nil {
		utils.BadRequestResponse(c, "Username already exists")
		return
	}

	// Generate salt and hash password
	salt, err := utils.GenerateSalt()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate salt")
		return
	}

	passwordHash := utils.HashPassword(req.Password, salt)

	// Create user
	user := models.User{
		Username: req.Username,
		Password: salt + ":" + passwordHash,
	}

	if err := db.Create(&user).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to create user")
		return
	}

	// Create empty user data entry
	userData := models.UserData{
		UserID:      user.ID,
		IsEncrypted: false,
	}
	db.Create(&userData)

	// Get session information
	sessionID := generateSessionID()
	deviceInfo := parseDeviceInfo(c.GetHeader("User-Agent"))
	ipAddress := getRealIP(c)

	// Generate tokens with session ID
	accessToken, err := utils.GenerateAccessToken(user.ID, sessionID)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate access token")
		return
	}
	refreshToken, err := utils.GenerateRefreshToken(user.ID)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate refresh token")
		return
	}

	// Store refresh token (hashed) with session information
	refreshTokenModel := models.RefreshToken{
		UserID:     user.ID,
		Token:      utils.HashRefreshToken(refreshToken),
		ExpiresAt:  time.Time{},
		SessionID:  sessionID,
		DeviceInfo: deviceInfo,
		IPAddress:  ipAddress,
		LastUsedAt: time.Now(),
	}
	db.Create(&refreshTokenModel)

	utils.SuccessResponse(c, TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    config.AppConfig.AccessTokenExpireHours * 3600,
	})
}

// Login handles user login
func Login(c *gin.Context) {
	var req LoginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Verify Turnstile token
	remoteIP := getRealIP(c)
	// Pass empty action to make it optional (recommended: set data-action="login" on frontend)
	isInternalError, err := utils.VerifyTurnstileToken(req.TurnstileToken, remoteIP, "")
	if err != nil {
		if isInternalError {
			utils.InternalErrorResponse(c, "Failed to verify captcha")
		} else {
			utils.BadRequestResponse(c, "Invalid captcha")
		}
		return
	}

	db := database.GetDB()

	// Find user
	var user models.User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			utils.UnauthorizedResponse(c, "Invalid username or password")
		} else {
			utils.InternalErrorResponse(c, "Database error during login")
		}
		return
	}

	password := strings.TrimSpace(user.Password)
	isOIDCBound := strings.TrimSpace(user.OIDCSubject) != "" && strings.TrimSpace(user.OIDCProvider) != ""

	// Check if this is an OIDC-only account (no password)
	if password == "" {
		if isOIDCBound {
			utils.BadRequestResponse(c, "This account uses OIDC authentication. Please log in with OIDC.")
		} else {
			utils.InternalErrorResponse(c, "Account password is missing. Please contact support.")
		}
		return
	}

	// Accounts with OIDC bound must use OIDC login exclusively
	if isOIDCBound {
		utils.BadRequestResponse(c, "This account has OIDC linked. Please log in with OIDC.")
		return
	}

	// Verify password
	parts := strings.SplitN(password, ":", 2)
	if len(parts) != 2 {
		utils.InternalErrorResponse(c, "Invalid password format")
		return
	}

	salt, hash := parts[0], parts[1]
	matched, needsRehash := utils.VerifyPassword(req.Password, salt, hash)
	if !matched {
		utils.UnauthorizedResponse(c, "Invalid username or password")
		return
	}
	if needsRehash {
		// Account was hashed with legacy iteration count — upgrade transparently on login
		if newSalt, err := utils.GenerateSalt(); err == nil {
			user.Password = newSalt + ":" + utils.HashPassword(req.Password, newSalt)
			db.Save(&user) // best-effort; login proceeds even if save fails
		}
	}

	// Get session information
	sessionID := generateSessionID()
	deviceInfo := parseDeviceInfo(c.GetHeader("User-Agent"))
	ipAddress := getRealIP(c)

	// Generate tokens with session ID
	accessToken, err := utils.GenerateAccessToken(user.ID, sessionID)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate access token")
		return
	}
	refreshToken, err := utils.GenerateRefreshToken(user.ID)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate refresh token")
		return
	}

	// Store refresh token (hashed) with session information
	refreshTokenModel := models.RefreshToken{
		UserID:     user.ID,
		Token:      utils.HashRefreshToken(refreshToken),
		ExpiresAt:  time.Time{},
		SessionID:  sessionID,
		DeviceInfo: deviceInfo,
		IPAddress:  ipAddress,
		LastUsedAt: time.Now(),
	}
	db.Create(&refreshTokenModel)

	utils.SuccessResponse(c, TokenResponse{
		AccessToken:      accessToken,
		RefreshToken:     refreshToken,
		ExpiresIn:        config.AppConfig.AccessTokenExpireHours * 3600,
		RequiresOIDCBind: config.AppConfig.RegistrationDisabled, // registration disabled → must bind OIDC
	})
}

// RefreshToken handles token refresh
func RefreshToken(c *gin.Context) {
	var req RefreshTokenRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Validate refresh token
	claims, err := utils.ValidateRefreshToken(req.RefreshToken)
	if err != nil {
		utils.UnauthorizedResponse(c, "Invalid refresh token")
		return
	}

	db := database.GetDB()

	// Check if refresh token exists in database (compare hashed tokens)
	var tokenModel models.RefreshToken
	hashedToken := utils.HashRefreshToken(req.RefreshToken)
	if err := db.Where("token = ? AND user_id = ?", hashedToken, claims.UserID).First(&tokenModel).Error; err != nil {
		utils.UnauthorizedResponse(c, "Invalid refresh token")
		return
	}

	// Preserve session information from old token
	sessionID := tokenModel.SessionID
	deviceInfo := tokenModel.DeviceInfo
	ipAddress := tokenModel.IPAddress

	// Delete old refresh token
	db.Delete(&tokenModel)

	// Generate new tokens with preserved session ID
	accessToken, err := utils.GenerateAccessToken(claims.UserID, sessionID)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate access token")
		return
	}
	newRefreshToken, err := utils.GenerateRefreshToken(claims.UserID)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate refresh token")
		return
	}

	// Store new refresh token (hashed) with preserved session info and updated LastUsedAt
	newTokenModel := models.RefreshToken{
		UserID:     claims.UserID,
		Token:      utils.HashRefreshToken(newRefreshToken),
		ExpiresAt:  time.Time{},
		SessionID:  sessionID,
		DeviceInfo: deviceInfo,
		IPAddress:  ipAddress,
		LastUsedAt: time.Now(),
	}
	db.Create(&newTokenModel)

	utils.SuccessResponse(c, TokenResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		ExpiresIn:    config.AppConfig.AccessTokenExpireHours * 3600,
	})
}

// Helper: Generate SessionID (UUID v4)
func generateSessionID() string {
	return uuid.New().String()
}

// Helper: Parse User-Agent to get device info
func parseDeviceInfo(userAgent string) string {
	if userAgent == "" {
		return "Unknown Device"
	}

	// Simple parsing - can be enhanced with a library like "mssola/user_agent"
	// For now, extract basic browser and OS info
	ua := userAgent

	// Detect browser
	browser := "Unknown Browser"
	if strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Edg") {
		browser = "Chrome"
	} else if strings.Contains(ua, "Safari") && !strings.Contains(ua, "Chrome") {
		browser = "Safari"
	} else if strings.Contains(ua, "Firefox") {
		browser = "Firefox"
	} else if strings.Contains(ua, "Edg") {
		browser = "Edge"
	}

	// Detect OS
	os := "Unknown OS"
	if strings.Contains(ua, "Windows NT 10") {
		os = "Windows 10"
	} else if strings.Contains(ua, "Windows NT 11") {
		os = "Windows 11"
	} else if strings.Contains(ua, "Windows") {
		os = "Windows"
	} else if strings.Contains(ua, "Macintosh") || strings.Contains(ua, "Mac OS X") {
		os = "macOS"
	} else if strings.Contains(ua, "iPhone") {
		os = "iPhone"
	} else if strings.Contains(ua, "iPad") {
		os = "iPad"
	} else if strings.Contains(ua, "Android") {
		os = "Android"
	} else if strings.Contains(ua, "Linux") {
		os = "Linux"
	}

	return browser + " on " + os
}

// Helper: Get real IP from request
// Uses Gin's built-in ClientIP() which respects trusted proxies configuration
func getRealIP(c *gin.Context) string {
	return c.ClientIP()
}

// ChangePasswordRequest represents the request body for changing login password
type ChangePasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

// ChangePassword handles changing user's login password
func ChangePassword(c *gin.Context) {
	userID := middleware.GetUserID(c)
	var req ChangePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Validate new password length
	if len(req.NewPassword) < 8 {
		utils.BadRequestResponse(c, "New password must be at least 8 characters long")
		return
	}

	// Check password complexity
	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(req.NewPassword)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(req.NewPassword)
	if !hasLetter || !hasNumber {
		utils.BadRequestResponse(c, "Password must contain both letters and numbers")
		return
	}

	// Prevent new password being same as old password
	if req.OldPassword == req.NewPassword {
		utils.BadRequestResponse(c, "New password must be different from old password")
		return
	}

	db := database.GetDB()

	// Get user
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	// OIDC-only accounts have no login password
	if user.Password == "" {
		utils.BadRequestResponse(c, "No login password set. Use POST /user/password to set an initial password.")
		return
	}

	// Extract salt and hash from user password
	salt, hash, err := extractSaltAndHash(user.Password)
	if err != nil {
		utils.InternalErrorResponse(c, "Invalid password format")
		return
	}

	// Verify old password
	matched, _ := utils.VerifyPassword(req.OldPassword, salt, hash)
	if !matched {
		utils.UnauthorizedResponse(c, "Authentication failed")
		return
	}

	// Generate new salt and hash for new password
	newSalt, err := utils.GenerateSalt()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate salt")
		return
	}

	newHash := utils.HashPassword(req.NewPassword, newSalt)

	// Combine salt and hash (format: salt:hash)
	user.Password = newSalt + ":" + newHash

	// Save updated password
	if err := db.Save(&user).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to update password")
		return
	}

	var tokenCount int64
	db.Model(&models.RefreshToken{}).Where("user_id = ?", userID).Count(&tokenCount)
	db.Where("user_id = ?", userID).Delete(&models.RefreshToken{})

	otherSessionsLoggedOut := int64(0)
	if tokenCount > 0 {
		otherSessionsLoggedOut = tokenCount - 1
	}

	utils.SuccessResponse(c, map[string]interface{}{
		"message":                   "Password changed successfully",
		"other_sessions_logged_out": otherSessionsLoggedOut,
	})
}

// Helper: Extract salt and hash from stored password
func extractSaltAndHash(password string) (string, string, error) {
	parts := strings.Split(password, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid password format")
	}
	return parts[0], parts[1], nil
}

// SetLoginPasswordRequest is used by OIDC-only users to set an initial login password
type SetLoginPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

// SetLoginPassword allows OIDC-only accounts to set a login password
func SetLoginPassword(c *gin.Context) {
	userID := middleware.GetUserID(c)
	var req SetLoginPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	db := database.GetDB()
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	if user.Password != "" {
		utils.BadRequestResponse(c, "Login password already set. Use PUT /user/password to change it.")
		return
	}

	if len(req.Password) < 8 {
		utils.BadRequestResponse(c, "Password must be at least 8 characters long")
		return
	}
	hasLetter := regexp.MustCompile(`[a-zA-Z]`).MatchString(req.Password)
	hasNumber := regexp.MustCompile(`[0-9]`).MatchString(req.Password)
	if !hasLetter || !hasNumber {
		utils.BadRequestResponse(c, "Password must contain both letters and numbers")
		return
	}

	salt, err := utils.GenerateSalt()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate salt")
		return
	}
	user.Password = salt + ":" + utils.HashPassword(req.Password, salt)
	if err := db.Save(&user).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to set password")
		return
	}

	utils.SuccessMessageResponse(c, "Login password set successfully", nil)
}

// RemoveLoginPasswordRequest confirms the deletion of a login password
type RemoveLoginPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

// RemoveLoginPassword removes the login password from an account that has OIDC bound
func RemoveLoginPassword(c *gin.Context) {
	userID := middleware.GetUserID(c)
	var req RemoveLoginPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	db := database.GetDB()
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	if user.Password == "" {
		utils.BadRequestResponse(c, "No login password to remove")
		return
	}

	// Require OIDC binding before removing password (prevents lockout)
	if user.OIDCSubject == "" {
		utils.BadRequestResponse(c, "Cannot remove login password without an OIDC identity linked. Please link an OIDC account first.")
		return
	}

	// Verify current password
	salt, hash, err := extractSaltAndHash(user.Password)
	if err != nil {
		utils.InternalErrorResponse(c, "Invalid password format")
		return
	}
	matched, _ := utils.VerifyPassword(req.Password, salt, hash)
	if !matched {
		utils.UnauthorizedResponse(c, "Incorrect password")
		return
	}

	user.Password = ""
	if err := db.Save(&user).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to remove password")
		return
	}

	// Revoke all current sessions — user must re-login via OIDC
	db.Where("user_id = ?", userID).Delete(&models.RefreshToken{})

	utils.SuccessMessageResponse(c, "Login password removed successfully. Please log in with OIDC.", nil)
}
