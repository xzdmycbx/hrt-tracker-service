package middleware

import (
	"hrt-tracker-service/database"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"
	"strings"

	"github.com/gin-gonic/gin"
)

// AuthMiddleware validates the access token
func AuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			utils.UnauthorizedResponse(c, "Authorization header required")
			c.Abort()
			return
		}

		// Extract token from "Bearer <token>"
		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			utils.UnauthorizedResponse(c, "Invalid authorization header format")
			c.Abort()
			return
		}

		token := parts[1]
		claims, err := utils.ValidateAccessToken(token)
		if err != nil {
			utils.UnauthorizedResponse(c, "Invalid or expired token")
			c.Abort()
			return
		}

		// Validate session against database (prevent revoked tokens from working)
		if claims.SessionID != "" {
			var refreshToken models.RefreshToken
			db := database.GetDB()
			err := db.Where("session_id = ? AND user_id = ?", claims.SessionID, claims.UserID).First(&refreshToken).Error
			if err != nil {
				// Session not found or revoked
				utils.UnauthorizedResponse(c, "Session has been revoked")
				c.Abort()
				return
			}
		}

		// Store user ID and session ID in context
		c.Set("user_id", claims.UserID)
		c.Set("session_id", claims.SessionID)
		c.Next()
	}
}

// GetUserID retrieves the user ID from the context
func GetUserID(c *gin.Context) uint {
	userID, exists := c.Get("user_id")
	if !exists {
		return 0
	}
	return userID.(uint)
}

// GetSessionID retrieves the session ID from the context
func GetSessionID(c *gin.Context) string {
	sessionID, exists := c.Get("session_id")
	if !exists {
		return ""
	}
	return sessionID.(string)
}
