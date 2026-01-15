package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hrt-tracker-service/database"
	"hrt-tracker-service/middleware"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"
	"regexp"

	"github.com/gin-gonic/gin"
)

type CreateShareRequest struct {
	ShareType        string `json:"share_type" binding:"required"` // "realtime" or "copy"
	Password         string `json:"password"`
	SecurityPassword string `json:"security_password"`
	MaxAttempts      int    `json:"max_attempts"`
}

type UpdateSharePasswordRequest struct {
	Password string `json:"password"`
}

type UpdateShareLockRequest struct {
	MaxAttempts int `json:"max_attempts"`
}

type ViewShareRequest struct {
	Password string `json:"password"`
}

// generateShareID generates a random share ID
func generateShareID() (string, error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return hex.EncodeToString(bytes), nil
}

// CreateShare creates a new share
func CreateShare(c *gin.Context) {
	userID := middleware.GetUserID(c)
	var req CreateShareRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Validate share type
	if req.ShareType != "realtime" && req.ShareType != "copy" {
		utils.BadRequestResponse(c, "Share type must be 'realtime' or 'copy'")
		return
	}

	// Validate password if provided
	if req.Password != "" && !regexp.MustCompile(`^\d{6}$`).MatchString(req.Password) {
		utils.BadRequestResponse(c, "Share password must be exactly 6 digits")
		return
	}

	// Validate security password if provided
	if req.SecurityPassword != "" && !regexp.MustCompile(`^\d{6}$`).MatchString(req.SecurityPassword) {
		utils.BadRequestResponse(c, "Security password must be exactly 6 digits")
		return
	}

	// Validate max_attempts
	if req.MaxAttempts < 0 {
		utils.BadRequestResponse(c, "max_attempts cannot be negative")
		return
	}

	// If password is set but max_attempts is 0, set a sensible default to prevent unlimited brute-force
	if req.Password != "" && req.MaxAttempts == 0 {
		req.MaxAttempts = 5 // Default to 5 attempts for password-protected shares
	}

	db := database.GetDB()

	// Check if realtime share already exists
	if req.ShareType == "realtime" {
		var existingShare models.Share
		if err := db.Where("user_id = ? AND share_type = ?", userID, "realtime").First(&existingShare).Error; err == nil {
			utils.BadRequestResponse(c, "Realtime share already exists")
			return
		}
	}

	// Generate share ID
	shareID, err := generateShareID()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate share ID")
		return
	}

	share := models.Share{
		UserID:      userID,
		ShareType:   req.ShareType,
		ShareID:     shareID,
		MaxAttempts: req.MaxAttempts,
	}

	// Set password if provided
	if req.Password != "" {
		salt, err := utils.GenerateSalt()
		if err != nil {
			utils.InternalErrorResponse(c, "Failed to generate salt")
			return
		}
		share.PasswordSalt = salt
		hash, err := utils.HashPasswordArgon2id(req.Password, salt)
		if err != nil {
			utils.InternalErrorResponse(c, "Failed to hash password")
			return
		}
		share.PasswordHash = hash
	}

	// If copy type, snapshot the data
	if req.ShareType == "copy" {
		var user models.User
		if err := db.First(&user, userID).Error; err != nil {
			utils.NotFoundResponse(c, "User not found")
			return
		}

		hasSecurityPassword := user.SecurityPasswordHash != ""
		if hasSecurityPassword {
			if req.SecurityPassword == "" {
				utils.BadRequestResponse(c, "Security password required for copy share")
				return
			}

			if !utils.VerifyPasswordArgon2id(req.SecurityPassword, user.SecurityPasswordSalt, user.SecurityPasswordHash) {
				utils.UnauthorizedResponse(c, "Invalid security password")
				return
			}
		}

		var userData models.UserData
		if err := db.Where("user_id = ?", userID).First(&userData).Error; err == nil {
			// Cannot share encrypted data
			if userData.IsEncrypted {
				if !hasSecurityPassword {
					utils.BadRequestResponse(c, "Security password required")
					return
				}

				if user.MasterKeyServerWrapped == "" {
					utils.BadRequestResponse(c, "Dual key wrapping not initialized. Please contact support.")
					return
				}

				kekUser, err := utils.DeriveKeyArgon2id(req.SecurityPassword, user.MasterKeySalt)
				if err != nil {
					utils.InternalErrorResponse(c, "Failed to derive key")
					return
				}

				aadUser := fmt.Sprintf("user:%d", userID)
				masterKey, err := utils.UnwrapKey(user.MasterKeyUserWrapped, kekUser, aadUser)
				if err != nil {
					utils.UnauthorizedResponse(c, "Failed to unwrap master key")
					return
				}

				decrypted, err := decryptDataWithMasterKey(userData.EncryptedData, masterKey)
				if err != nil {
					utils.InternalErrorResponse(c, "Failed to decrypt data")
					return
				}
				share.SnapshotData = decrypted
			} else {
				share.SnapshotData = userData.EncryptedData
			}
		}
	}

	if err := db.Create(&share).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to create share")
		return
	}

	utils.SuccessResponse(c, map[string]interface{}{
		"share_id":   share.ShareID,
		"share_type": share.ShareType,
	})
}

// GetMyShares retrieves all shares created by the user
func GetMyShares(c *gin.Context) {
	userID := middleware.GetUserID(c)
	db := database.GetDB()

	var shares []models.Share
	db.Where("user_id = ?", userID).Find(&shares)

	// Format response
	result := make([]map[string]interface{}, len(shares))
	for i, share := range shares {
		result[i] = map[string]interface{}{
			"share_id":      share.ShareID,
			"share_type":    share.ShareType,
			"has_password":  share.PasswordHash != "",
			"view_count":    share.ViewCount,
			"attempt_count": share.AttemptCount,
			"max_attempts":  share.MaxAttempts,
			"is_locked":     share.IsLocked,
			"created_at":    share.CreatedAt,
		}
	}

	utils.SuccessResponse(c, result)
}

// DeleteShare deletes a share
func DeleteShare(c *gin.Context) {
	userID := middleware.GetUserID(c)
	shareID := c.Param("share_id")

	db := database.GetDB()

	var share models.Share
	if err := db.Where("share_id = ? AND user_id = ?", shareID, userID).First(&share).Error; err != nil {
		utils.NotFoundResponse(c, "Share not found")
		return
	}

	db.Delete(&share)

	utils.SuccessMessageResponse(c, "Share deleted successfully", nil)
}

// UpdateSharePassword updates the password of a share
func UpdateSharePassword(c *gin.Context) {
	userID := middleware.GetUserID(c)
	shareID := c.Param("share_id")
	var req UpdateSharePasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Validate password
	if req.Password != "" && !regexp.MustCompile(`^\d{6}$`).MatchString(req.Password) {
		utils.BadRequestResponse(c, "Share password must be exactly 6 digits")
		return
	}

	db := database.GetDB()

	var share models.Share
	if err := db.Where("share_id = ? AND user_id = ?", shareID, userID).First(&share).Error; err != nil {
		utils.NotFoundResponse(c, "Share not found")
		return
	}

	// Update password
	if req.Password == "" {
		share.PasswordHash = ""
		share.PasswordSalt = ""
	} else {
		salt, err := utils.GenerateSalt()
		if err != nil {
			utils.InternalErrorResponse(c, "Failed to generate salt")
			return
		}
		share.PasswordSalt = salt
		hash, err := utils.HashPasswordArgon2id(req.Password, salt)
		if err != nil {
			utils.InternalErrorResponse(c, "Failed to hash password")
			return
		}
		share.PasswordHash = hash
	}

	// Reset lock and attempts
	share.IsLocked = false
	share.AttemptCount = 0

	db.Save(&share)

	utils.SuccessMessageResponse(c, "Share password updated successfully", nil)
}

// UpdateShareLock updates the lock settings of a share
func UpdateShareLock(c *gin.Context) {
	userID := middleware.GetUserID(c)
	shareID := c.Param("share_id")
	var req UpdateShareLockRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Validate max_attempts
	if req.MaxAttempts < 0 {
		utils.BadRequestResponse(c, "max_attempts cannot be negative")
		return
	}

	db := database.GetDB()

	var share models.Share
	if err := db.Where("share_id = ? AND user_id = ?", shareID, userID).First(&share).Error; err != nil {
		utils.NotFoundResponse(c, "Share not found")
		return
	}

	share.MaxAttempts = req.MaxAttempts
	share.IsLocked = false
	share.AttemptCount = 0

	db.Save(&share)

	utils.SuccessMessageResponse(c, "Share lock settings updated successfully", nil)
}

// ViewShare views a shared data
func ViewShare(c *gin.Context) {
	shareID := c.Param("share_id")
	var req ViewShareRequest
	c.ShouldBindJSON(&req)

	db := database.GetDB()

	var share models.Share
	if err := db.Where("share_id = ?", shareID).First(&share).Error; err != nil {
		utils.NotFoundResponse(c, "Share not found")
		return
	}

	// Check if locked
	if share.IsLocked {
		utils.ForbiddenResponse(c, "Share is locked due to too many failed attempts")
		return
	}

	// Check password if set
	if share.PasswordHash != "" {
		if req.Password == "" {
			// Increment attempt count for missing password
			share.AttemptCount++
			if share.MaxAttempts > 0 && share.AttemptCount >= share.MaxAttempts {
				share.IsLocked = true
			}
			db.Save(&share)

			utils.BadRequestResponse(c, "Password required")
			return
		}

		if !utils.VerifyPasswordArgon2id(req.Password, share.PasswordSalt, share.PasswordHash) {
			// Increment attempt count
			share.AttemptCount++
			if share.MaxAttempts > 0 && share.AttemptCount >= share.MaxAttempts {
				share.IsLocked = true
			}
			db.Save(&share)

			utils.UnauthorizedResponse(c, "Invalid password")
			return
		}
	}

	var owner models.User
	if err := db.Select("username", "avatar", "security_password_hash").First(&owner, share.UserID).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to load share owner")
		return
	}

	if share.ShareType == "realtime" && owner.SecurityPasswordHash != "" {
		utils.ForbiddenResponse(c, "Owner has security password set; realtime share is disabled")
		return
	}

	baseResponse := map[string]interface{}{
		"owner_username": owner.Username,
		"owner_avatar":   owner.Avatar,
	}

	// Get data based on share type
	var data map[string]interface{}
	if share.ShareType == "realtime" {
		// Get current user data
		var userData models.UserData
		if err := db.Where("user_id = ?", share.UserID).First(&userData).Error; err != nil {
			// Increment view count even for null data
			share.ViewCount++
			db.Save(&share)

			utils.SuccessResponse(c, map[string]interface{}{
				"data":       nil,
				"share_type": "realtime",
				"owner":      baseResponse,
			})
			return
		}

		if userData.EncryptedData == "" {
			// Increment view count even for null data
			share.ViewCount++
			db.Save(&share)

			utils.SuccessResponse(c, map[string]interface{}{
				"data":       nil,
				"share_type": "realtime",
				"owner":      baseResponse,
			})
			return
		}

		// Note: Realtime shares show encrypted data as-is if user has security password
		// The share password is only for access control, not for decryption
		if userData.IsEncrypted {
			// We can't decrypt without the owner's security password
			// So we return an error or show that data is encrypted
			utils.ForbiddenResponse(c, "Owner's data is encrypted and cannot be shared in realtime")
			return
		}

		if err := json.Unmarshal([]byte(userData.EncryptedData), &data); err != nil {
			utils.InternalErrorResponse(c, "Failed to parse data")
			return
		}
	} else {
		// Copy type - return snapshot
		if share.SnapshotData == "" {
			// Increment view count even for null data
			share.ViewCount++
			db.Save(&share)

			utils.SuccessResponse(c, map[string]interface{}{
				"data":       nil,
				"share_type": "copy",
				"owner":      baseResponse,
			})
			return
		}

		if err := json.Unmarshal([]byte(share.SnapshotData), &data); err != nil {
			utils.InternalErrorResponse(c, "Failed to parse data")
			return
		}
	}

	// Increment view count on successful view
	share.ViewCount++
	db.Save(&share)

	utils.SuccessResponse(c, map[string]interface{}{
		"data":       data,
		"share_type": share.ShareType,
		"owner":      baseResponse,
	})
}
