package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hrt-tracker-service/config"
	"hrt-tracker-service/database"
	"hrt-tracker-service/middleware"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"
	"regexp"

	"github.com/gin-gonic/gin"
)

type SetSecurityPasswordRequest struct {
	Password string `json:"password" binding:"required"`
}

type UpdateSecurityPasswordRequest struct {
	OldPassword string `json:"old_password" binding:"required"`
	NewPassword string `json:"new_password" binding:"required"`
}

type GetUserDataRequest struct {
	Password string `json:"password"`
}

type UpdateUserDataRequest struct {
	Password string                 `json:"password"`
	Data     map[string]interface{} `json:"data" binding:"required"`
}

// SetSecurityPassword sets the security password (first time only)
func SetSecurityPassword(c *gin.Context) {
	userID := middleware.GetUserID(c)
	var req SetSecurityPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Validate 6-digit password
	if !regexp.MustCompile(`^\d{6}$`).MatchString(req.Password) {
		utils.BadRequestResponse(c, "Security password must be exactly 6 digits")
		return
	}

	db := database.GetDB()

	// Get user
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	// Check if security password already exists
	if user.SecurityPasswordHash != "" {
		utils.BadRequestResponse(c, "Security password already set. Use PUT /user/security-password to update it.")
		return
	}

	// Generate master key Ku
	masterKey, err := utils.GenerateMasterKey()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate master key")
		return
	}

	// Generate salt for user key derivation
	saltUser, err := utils.GenerateSalt()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate salt")
		return
	}

	// Derive KEK_user using Argon2id
	kekUser, err := utils.DeriveKeyArgon2id(req.Password, saltUser)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to derive user key")
		return
	}

	// Wrap master key with user's key
	aadUser := fmt.Sprintf("user:%d", userID)
	wrappedUser, err := utils.WrapKey(masterKey, kekUser, aadUser)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to wrap user key")
		return
	}

	// Get server master key for current version
	currentVersion := config.AppConfig.MasterKeyServerCurrentVersion
	kekServer, err := config.GetServerMasterKey(currentVersion)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to get server key")
		return
	}

	// Wrap master key with server key
	aadServer := fmt.Sprintf("server:%d:%d", userID, currentVersion)
	wrappedServer, err := utils.WrapKey(masterKey, kekServer, aadServer)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to wrap server key")
		return
	}

	// If user data exists and not encrypted, encrypt it with master key first
	var userData models.UserData
	var encryptedData string
	if err := db.Where("user_id = ?", userID).First(&userData).Error; err == nil {
		if !userData.IsEncrypted && userData.EncryptedData != "" {
			// Encrypt existing plaintext data with master key
			encrypted, err := encryptDataWithMasterKey(userData.EncryptedData, masterKey)
			if err != nil {
				utils.InternalErrorResponse(c, "Failed to encrypt data")
				return
			}
			encryptedData = encrypted
		}
	}

	// Hash the security password for verification using Argon2id
	hash, err := utils.HashPasswordArgon2id(req.Password, saltUser)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to hash password")
		return
	}

	// Update user with all key material (only after encryption succeeds)
	user.SecurityPasswordSalt = saltUser
	user.SecurityPasswordHash = hash
	user.MasterKeyUserWrapped = wrappedUser
	user.MasterKeyServerWrapped = wrappedServer
	user.MasterKeySalt = saltUser
	user.MasterKeyVersion = currentVersion
	db.Save(&user)

	// Update encrypted data if we encrypted it
	if encryptedData != "" {
		userData.EncryptedData = encryptedData
		userData.IsEncrypted = true
		db.Save(&userData)
	}

	utils.SuccessMessageResponse(c, "Security password set successfully", nil)
}

// UpdateSecurityPassword updates the security password
func UpdateSecurityPassword(c *gin.Context) {
	userID := middleware.GetUserID(c)
	var req UpdateSecurityPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	// Validate passwords
	if !regexp.MustCompile(`^\d{6}$`).MatchString(req.OldPassword) || !regexp.MustCompile(`^\d{6}$`).MatchString(req.NewPassword) {
		utils.BadRequestResponse(c, "Security password must be exactly 6 digits")
		return
	}

	db := database.GetDB()

	// Get user
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	// Verify old password
	if user.SecurityPasswordHash == "" {
		utils.BadRequestResponse(c, "Security password not set")
		return
	}

	if !utils.VerifyPasswordArgon2id(req.OldPassword, user.SecurityPasswordSalt, user.SecurityPasswordHash) {
		utils.UnauthorizedResponse(c, "Invalid old password")
		return
	}

	// Check if user has set up dual key wrapping
	if user.MasterKeyServerWrapped == "" {
		utils.BadRequestResponse(c, "Dual key wrapping not initialized. Please contact support.")
		return
	}

	// Unwrap master key with old password
	kekUserOld, err := utils.DeriveKeyArgon2id(req.OldPassword, user.MasterKeySalt)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to derive old key")
		return
	}

	aadUser := fmt.Sprintf("user:%d", userID)
	masterKey, err := utils.UnwrapKey(user.MasterKeyUserWrapped, kekUserOld, aadUser)
	if err != nil {
		utils.UnauthorizedResponse(c, "Failed to unwrap master key with old password")
		return
	}

	// Generate new salt for new password
	saltNew, err := utils.GenerateSalt()
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to generate salt")
		return
	}

	// Derive new KEK_user from new password
	kekUserNew, err := utils.DeriveKeyArgon2id(req.NewPassword, saltNew)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to derive new key")
		return
	}

	// Re-wrap master key with new password
	wrappedUserNew, err := utils.WrapKey(masterKey, kekUserNew, aadUser)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to wrap master key with new password")
		return
	}

	// Generate new hash for password verification using Argon2id
	hashNew, err := utils.HashPasswordArgon2id(req.NewPassword, saltNew)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to hash new password")
		return
	}

	// Update user with new wrapped key and salt
	user.MasterKeyUserWrapped = wrappedUserNew
	user.MasterKeySalt = saltNew
	user.SecurityPasswordSalt = saltNew
	user.SecurityPasswordHash = hashNew
	// Keep MasterKeyServerWrapped and MasterKeyVersion unchanged
	db.Save(&user)

	utils.SuccessMessageResponse(c, "Security password updated successfully", nil)
}

// GetUserData retrieves user's data
func GetUserData(c *gin.Context) {
	userID := middleware.GetUserID(c)
	var req GetUserDataRequest
	c.ShouldBindJSON(&req)

	db := database.GetDB()

	// Get user
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	// Get user data
	var userData models.UserData
	if err := db.Where("user_id = ?", userID).First(&userData).Error; err != nil {
		utils.SuccessResponse(c, map[string]interface{}{
			"data":         nil,
			"is_encrypted": false,
		})
		return
	}

	// If encrypted, require password
	if userData.IsEncrypted {
		if req.Password == "" {
			utils.BadRequestResponse(c, "Security password required")
			return
		}

		// Verify password using Argon2id
		if !utils.VerifyPasswordArgon2id(req.Password, user.SecurityPasswordSalt, user.SecurityPasswordHash) {
			utils.UnauthorizedResponse(c, "Invalid security password")
			return
		}

		// Decrypt data
		var decrypted string
		var err error

		// Check if user has set up dual key wrapping
		if user.MasterKeyServerWrapped == "" {
			utils.BadRequestResponse(c, "Dual key wrapping not initialized. Please contact support.")
			return
		}

		// Unwrap master key with user password
		kekUser, err := utils.DeriveKeyArgon2id(req.Password, user.MasterKeySalt)
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

		// Decrypt data with master key
		decrypted, err = decryptDataWithMasterKey(userData.EncryptedData, masterKey)
		if err != nil {
			utils.InternalErrorResponse(c, "Failed to decrypt data")
			return
		}

		var data map[string]interface{}
		if err := json.Unmarshal([]byte(decrypted), &data); err != nil {
			utils.InternalErrorResponse(c, "Failed to parse data")
			return
		}

		utils.SuccessResponse(c, map[string]interface{}{
			"data":         data,
			"is_encrypted": true,
		})
		return
	}

	// Not encrypted
	if userData.EncryptedData == "" {
		utils.SuccessResponse(c, map[string]interface{}{
			"data":         nil,
			"is_encrypted": false,
		})
		return
	}

	var data map[string]interface{}
	if err := json.Unmarshal([]byte(userData.EncryptedData), &data); err != nil {
		utils.InternalErrorResponse(c, "Failed to parse data")
		return
	}

	utils.SuccessResponse(c, map[string]interface{}{
		"data":         data,
		"is_encrypted": false,
	})
}

// UpdateUserData updates user's data
func UpdateUserData(c *gin.Context) {
	userID := middleware.GetUserID(c)
	var req UpdateUserDataRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		utils.BadRequestResponse(c, "Invalid request body")
		return
	}

	db := database.GetDB()

	// Get user
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	// Check if security password is set
	hasSecurityPassword := user.SecurityPasswordHash != ""

	// If security password is set, verify it
	if hasSecurityPassword {
		if req.Password == "" {
			utils.BadRequestResponse(c, "Security password required")
			return
		}

		if !utils.VerifyPasswordArgon2id(req.Password, user.SecurityPasswordSalt, user.SecurityPasswordHash) {
			utils.UnauthorizedResponse(c, "Invalid security password")
			return
		}
	}

	// Convert data to JSON
	jsonData, err := json.Marshal(req.Data)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to serialize data")
		return
	}

	// Get or create user data
	var userData models.UserData
	db.Where("user_id = ?", userID).FirstOrCreate(&userData, models.UserData{UserID: userID})

	// Encrypt if security password is set
	if hasSecurityPassword {
		var encrypted string
		var err error

		// Check if user has set up dual key wrapping
		if user.MasterKeyServerWrapped == "" {
			utils.BadRequestResponse(c, "Dual key wrapping not initialized. Please contact support.")
			return
		}

		// Unwrap master key with user password
		kekUser, err := utils.DeriveKeyArgon2id(req.Password, user.MasterKeySalt)
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

		// Encrypt data with master key
		encrypted, err = encryptDataWithMasterKey(string(jsonData), masterKey)
		if err != nil {
			utils.InternalErrorResponse(c, "Failed to encrypt data")
			return
		}

		userData.EncryptedData = encrypted
		userData.IsEncrypted = true
	} else {
		userData.EncryptedData = string(jsonData)
		userData.IsEncrypted = false
	}

	db.Save(&userData)

	utils.SuccessMessageResponse(c, "Data updated successfully", nil)
}

// GetSecurityPasswordStatus checks if security password is set
func GetSecurityPasswordStatus(c *gin.Context) {
	userID := middleware.GetUserID(c)
	db := database.GetDB()

	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	utils.SuccessResponse(c, map[string]interface{}{
		"has_security_password": user.SecurityPasswordHash != "",
	})
}

// Helper function: encrypt data with master key
func encryptDataWithMasterKey(plaintext string, masterKey []byte) (string, error) {
	return utils.EncryptData(plaintext, base64.StdEncoding.EncodeToString(masterKey))
}

// Helper function: decrypt data with master key
func decryptDataWithMasterKey(ciphertext string, masterKey []byte) (string, error) {
	return utils.DecryptData(ciphertext, base64.StdEncoding.EncodeToString(masterKey))
}
