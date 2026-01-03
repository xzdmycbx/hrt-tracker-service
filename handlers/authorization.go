package handlers

import (
	"encoding/json"
	"hrt-tracker-service/database"
	"hrt-tracker-service/middleware"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"

	"github.com/gin-gonic/gin"
)

type GrantAuthorizationRequest struct {
	ViewerUsername string `json:"viewer_username" binding:"required"`
}

type ViewAuthorizedDataRequest struct {
	OwnerUsername string `json:"owner_username" binding:"required"`
	Password      string `json:"password" binding:"required"`
}

// GrantAuthorization grants authorization to another user
func GrantAuthorization(c *gin.Context) {
	ownerID := middleware.GetUserID(c)
	var req GrantAuthorizationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	db := database.GetDB()

	// Find viewer user
	var viewer models.User
	if err := db.Where("username = ?", req.ViewerUsername).First(&viewer).Error; err != nil {
		utils.NotFoundResponse(c, "Viewer user not found")
		return
	}

	// Check if already authorized
	var existingAuth models.Authorization
	if err := db.Where("owner_id = ? AND viewer_id = ?", ownerID, viewer.ID).First(&existingAuth).Error; err == nil {
		utils.BadRequestResponse(c, "Authorization already exists")
		return
	}

	// Create authorization
	auth := models.Authorization{
		OwnerID:  ownerID,
		ViewerID: viewer.ID,
	}

	if err := db.Create(&auth).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to create authorization")
		return
	}

	utils.SuccessMessageResponse(c, "Authorization granted successfully", map[string]interface{}{
		"viewer_username": req.ViewerUsername,
	})
}

// RevokeAuthorization revokes authorization from another user
func RevokeAuthorization(c *gin.Context) {
	ownerID := middleware.GetUserID(c)
	viewerUsername := c.Param("viewer_username")

	db := database.GetDB()

	// Find viewer user
	var viewer models.User
	if err := db.Where("username = ?", viewerUsername).First(&viewer).Error; err != nil {
		utils.NotFoundResponse(c, "Viewer user not found")
		return
	}

	// Find and delete all matching authorizations (defensive: should only be one with unique constraint)
	result := db.Where("owner_id = ? AND viewer_id = ?", ownerID, viewer.ID).Delete(&models.Authorization{})
	if result.RowsAffected == 0 {
		utils.NotFoundResponse(c, "Authorization not found")
		return
	}

	utils.SuccessMessageResponse(c, "Authorization revoked successfully", nil)
}

// GetMyAuthorizations gets all users I've authorized
func GetMyAuthorizations(c *gin.Context) {
	ownerID := middleware.GetUserID(c)
	db := database.GetDB()

	var authorizations []models.Authorization
	db.Where("owner_id = ?", ownerID).Find(&authorizations)

	// Get viewer usernames
	result := make([]map[string]interface{}, len(authorizations))
	for i, auth := range authorizations {
		var viewer models.User
		db.First(&viewer, auth.ViewerID)
		result[i] = map[string]interface{}{
			"viewer_username": viewer.Username,
			"created_at":      auth.CreatedAt,
		}
	}

	utils.SuccessResponse(c, result)
}

// GetAuthorizedOwners gets all users who have authorized me
func GetAuthorizedOwners(c *gin.Context) {
	viewerID := middleware.GetUserID(c)
	db := database.GetDB()

	var authorizations []models.Authorization
	db.Where("viewer_id = ?", viewerID).Find(&authorizations)

	// Get owner usernames
	result := make([]map[string]interface{}, len(authorizations))
	for i, auth := range authorizations {
		var owner models.User
		db.First(&owner, auth.OwnerID)
		result[i] = map[string]interface{}{
			"owner_username": owner.Username,
			"created_at":     auth.CreatedAt,
		}
	}

	utils.SuccessResponse(c, result)
}

// ViewAuthorizedData views data from an authorized owner
func ViewAuthorizedData(c *gin.Context) {
	viewerID := middleware.GetUserID(c)
	var req ViewAuthorizedDataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	db := database.GetDB()

	// Find owner user
	var owner models.User
	if err := db.Where("username = ?", req.OwnerUsername).First(&owner).Error; err != nil {
		utils.NotFoundResponse(c, "Owner user not found")
		return
	}

	// Check authorization
	var auth models.Authorization
	if err := db.Where("owner_id = ? AND viewer_id = ?", owner.ID, viewerID).First(&auth).Error; err != nil {
		utils.ForbiddenResponse(c, "You are not authorized to view this user's data")
		return
	}

	// Get viewer's security password to verify
	var viewer models.User
	if err := db.First(&viewer, viewerID).Error; err != nil {
		utils.NotFoundResponse(c, "Viewer not found")
		return
	}

	// Verify viewer's security password
	if viewer.SecurityPasswordHash == "" {
		utils.BadRequestResponse(c, "You must set a security password first")
		return
	}

	if !utils.VerifyPasswordArgon2id(req.Password, viewer.SecurityPasswordSalt, viewer.SecurityPasswordHash) {
		utils.UnauthorizedResponse(c, "Invalid security password")
		return
	}

	// Get owner's data
	var userData models.UserData
	if err := db.Where("user_id = ?", owner.ID).First(&userData).Error; err != nil {
		utils.SuccessResponse(c, map[string]interface{}{
			"data":         nil,
			"owner":        req.OwnerUsername,
			"is_encrypted": false,
		})
		return
	}

	// If owner's data is encrypted, we can't view it
	if userData.IsEncrypted {
		utils.ForbiddenResponse(c, "Owner's data is encrypted and cannot be viewed")
		return
	}

	if userData.EncryptedData == "" {
		utils.SuccessResponse(c, map[string]interface{}{
			"data":         nil,
			"owner":        req.OwnerUsername,
			"is_encrypted": false,
		})
		return
	}

	// Parse and return data
	var data map[string]interface{}
	if err := json.Unmarshal([]byte(userData.EncryptedData), &data); err != nil {
		utils.InternalErrorResponse(c, "Failed to parse data")
		return
	}

	utils.SuccessResponse(c, map[string]interface{}{
		"data":         data,
		"owner":        req.OwnerUsername,
		"is_encrypted": false,
	})
}
