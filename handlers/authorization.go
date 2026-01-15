package handlers

import (
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
	utils.BadRequestResponse(c, "Authorization feature is disabled")
}

// RevokeAuthorization revokes authorization from another user
func RevokeAuthorization(c *gin.Context) {
	utils.BadRequestResponse(c, "Authorization feature is disabled")
}

// GetMyAuthorizations gets all users I've authorized
func GetMyAuthorizations(c *gin.Context) {
	utils.BadRequestResponse(c, "Authorization feature is disabled")
}

// GetAuthorizedOwners gets all users who have authorized me
func GetAuthorizedOwners(c *gin.Context) {
	utils.BadRequestResponse(c, "Authorization feature is disabled")
}

// ViewAuthorizedData views data from an authorized owner
func ViewAuthorizedData(c *gin.Context) {
	utils.BadRequestResponse(c, "Authorization feature is disabled")
}
