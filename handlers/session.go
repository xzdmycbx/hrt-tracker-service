package handlers

import (
	"hrt-tracker-service/database"
	"hrt-tracker-service/middleware"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"
	"regexp"

	"github.com/gin-gonic/gin"
)

type RevokeSessionRequest struct {
	Password string `json:"password" binding:"required"`
}

type SessionInfo struct {
	SessionID  string `json:"session_id"`
	DeviceInfo string `json:"device_info"`
	IPAddress  string `json:"ip_address"`
	CreatedAt  string `json:"created_at"`
	LastUsedAt string `json:"last_used_at"`
	IsCurrent  bool   `json:"is_current"`
}

// GetSessions returns all active sessions for the current user
func GetSessions(c *gin.Context) {
	userID := middleware.GetUserID(c)
	currentSessionID := middleware.GetSessionID(c)
	db := database.GetDB()

	// Get all refresh tokens for this user
	var tokens []models.RefreshToken
	if err := db.Where("user_id = ?", userID).Order("created_at DESC").Find(&tokens).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to fetch sessions")
		return
	}

	// Build session list
	sessions := make([]SessionInfo, 0, len(tokens))

	for _, token := range tokens {
		// Determine if this is the current session by matching session ID
		isCurrent := token.SessionID == currentSessionID

		sessions = append(sessions, SessionInfo{
			SessionID:  token.SessionID,
			DeviceInfo: token.DeviceInfo,
			IPAddress:  token.IPAddress,
			CreatedAt:  token.CreatedAt.Format("2006-01-02T15:04:05Z07:00"),
			LastUsedAt: token.LastUsedAt.Format("2006-01-02T15:04:05Z07:00"),
			IsCurrent:  isCurrent,
		})
	}

	utils.SuccessResponse(c, map[string]interface{}{
		"current_session_id": currentSessionID,
		"sessions":           sessions,
	})
}

// Logout revokes the current session's refresh token
func Logout(c *gin.Context) {
	userID := middleware.GetUserID(c)
	currentSessionID := middleware.GetSessionID(c)
	db := database.GetDB()

	result := db.Where("user_id = ? AND session_id = ?", userID, currentSessionID).Delete(&models.RefreshToken{})

	utils.SuccessMessageResponse(c, "Logged out successfully", map[string]interface{}{
		"revoked_count": result.RowsAffected,
	})
}

// RevokeSession revokes a specific session (requires login password)
func RevokeSession(c *gin.Context) {
	userID := middleware.GetUserID(c)
	currentSessionID := middleware.GetSessionID(c)
	sessionID := c.Param("session_id")

	var req RevokeSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Prevent revoking current session
	if sessionID == currentSessionID {
		utils.BadRequestResponse(c, "Cannot revoke current session")
		return
	}

	db := database.GetDB()

	// Get user to verify password
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	// Verify login password
	parts := regexp.MustCompile(":").Split(user.Password, 2)
	if len(parts) != 2 {
		utils.InternalErrorResponse(c, "Invalid password format")
		return
	}

	salt, hash := parts[0], parts[1]
	matched, _ := utils.VerifyPassword(req.Password, salt, hash)
	if !matched {
		utils.UnauthorizedResponse(c, "Invalid password")
		return
	}

	// Find the session to revoke
	var token models.RefreshToken
	if err := db.Where("user_id = ? AND session_id = ?", userID, sessionID).First(&token).Error; err != nil {
		utils.NotFoundResponse(c, "Session not found")
		return
	}

	// Delete the refresh token
	db.Delete(&token)

	utils.SuccessMessageResponse(c, "Session revoked successfully", nil)
}

// RevokeAllOtherSessions revokes all sessions except the current one (requires login password)
func RevokeAllOtherSessions(c *gin.Context) {
	userID := middleware.GetUserID(c)
	currentSessionID := middleware.GetSessionID(c)

	var req RevokeSessionRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	db := database.GetDB()

	// Get user to verify password
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	// Verify login password
	parts := regexp.MustCompile(":").Split(user.Password, 2)
	if len(parts) != 2 {
		utils.InternalErrorResponse(c, "Invalid password format")
		return
	}

	salt, hash := parts[0], parts[1]
	matched, _ := utils.VerifyPassword(req.Password, salt, hash)
	if !matched {
		utils.UnauthorizedResponse(c, "Invalid password")
		return
	}

	// Delete all refresh tokens except the current session
	result := db.Where("user_id = ? AND session_id != ?", userID, currentSessionID).Delete(&models.RefreshToken{})

	utils.SuccessMessageResponse(c, "Other sessions revoked successfully", map[string]interface{}{
		"revoked_count": result.RowsAffected,
	})
}
