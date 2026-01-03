package handlers

import (
	"hrt-tracker-service/config"
	"hrt-tracker-service/database"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type RegisterRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type LoginRequest struct {
	Username string `json:"username" binding:"required"`
	Password string `json:"password" binding:"required"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" binding:"required"`
}

type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}

// Register handles user registration
func Register(c *gin.Context) {
	var req RegisterRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
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

	// Limit to 2 devices: if user has 2 or more refresh tokens, delete the oldest one
	// (This is defensive - new user should have no tokens, but keeping consistency)
	var tokenCount int64
	db.Model(&models.RefreshToken{}).Where("user_id = ?", user.ID).Count(&tokenCount)
	if tokenCount >= 2 {
		var oldestToken models.RefreshToken
		db.Where("user_id = ?", user.ID).Order("created_at ASC").First(&oldestToken)
		db.Delete(&oldestToken)
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
		ExpiresAt:  time.Now().Add(time.Hour * time.Duration(config.AppConfig.RefreshTokenExpireHours)),
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

	db := database.GetDB()

	// Find user
	var user models.User
	if err := db.Where("username = ?", req.Username).First(&user).Error; err != nil {
		utils.UnauthorizedResponse(c, "Invalid username or password")
		return
	}

	// Verify password
	parts := regexp.MustCompile(":").Split(user.Password, 2)
	if len(parts) != 2 {
		utils.InternalErrorResponse(c, "Invalid password format")
		return
	}

	salt, hash := parts[0], parts[1]
	if !utils.VerifyPassword(req.Password, salt, hash) {
		utils.UnauthorizedResponse(c, "Invalid username or password")
		return
	}

	// Limit to 2 devices: if user has 2 or more refresh tokens, delete the oldest one
	var tokenCount int64
	db.Model(&models.RefreshToken{}).Where("user_id = ?", user.ID).Count(&tokenCount)
	if tokenCount >= 2 {
		// Delete the oldest refresh token
		var oldestToken models.RefreshToken
		db.Where("user_id = ?", user.ID).Order("created_at ASC").First(&oldestToken)
		db.Delete(&oldestToken)
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
		ExpiresAt:  time.Now().Add(time.Hour * time.Duration(config.AppConfig.RefreshTokenExpireHours)),
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
		utils.UnauthorizedResponse(c, "Invalid or expired refresh token")
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
		ExpiresAt:  time.Now().Add(time.Hour * time.Duration(config.AppConfig.RefreshTokenExpireHours)),
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

// Helper: Get real IP from request headers
func getRealIP(c *gin.Context) string {
	// Priority: X-Forwarded-For > X-Real-IP > RemoteAddr
	forwarded := c.GetHeader("X-Forwarded-For")
	if forwarded != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		parts := strings.Split(forwarded, ",")
		return strings.TrimSpace(parts[0])
	}

	realIP := c.GetHeader("X-Real-IP")
	if realIP != "" {
		return realIP
	}

	return c.ClientIP()
}
