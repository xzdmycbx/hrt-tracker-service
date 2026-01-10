package handlers

import (
	"fmt"
	"hrt-tracker-service/config"
	"hrt-tracker-service/database"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"

	"github.com/gin-gonic/gin"
)

// ServerDecryptUserData demonstrates server-side decryption using the server master key
// This is for administrative operations only (e.g., data migration, format upgrades)
// NOT exposed as a public API endpoint for security reasons
func ServerDecryptUserData(userID uint) (string, error) {
	db := database.GetDB()

	// Get user
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		return "", fmt.Errorf("user not found")
	}

	// Check if dual key wrapping is set up
	if user.MasterKeyServerWrapped == "" || user.MasterKeyVersion == 0 {
		return "", fmt.Errorf("dual key wrapping not initialized for user")
	}

	// Get user data
	var userData models.UserData
	if err := db.Where("user_id = ?", userID).First(&userData).Error; err != nil {
		return "", fmt.Errorf("user data not found")
	}

	if !userData.IsEncrypted {
		// Data is not encrypted, return as-is
		return userData.EncryptedData, nil
	}

	// Get server master key for this user's version
	kekServer, err := config.GetServerMasterKey(user.MasterKeyVersion)
	if err != nil {
		return "", fmt.Errorf("failed to get server master key: %w", err)
	}

	// Unwrap master key using server key
	aadServer := fmt.Sprintf("server:%d:%d", userID, user.MasterKeyVersion)
	masterKey, err := utils.UnwrapKey(user.MasterKeyServerWrapped, kekServer, aadServer)
	if err != nil {
		return "", fmt.Errorf("failed to unwrap master key: %w", err)
	}

	// Decrypt user data with master key
	decryptedData, err := utils.DecryptDataWithKey(userData.EncryptedData, masterKey)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt data: %w", err)
	}

	return decryptedData, nil
}

// ServerUpdateUserData demonstrates server-side encryption using the server master key
// This is for administrative operations only (e.g., data migration, format upgrades)
// NOT exposed as a public API endpoint for security reasons
func ServerUpdateUserData(userID uint, newData string) error {
	db := database.GetDB()

	// Get user
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		return fmt.Errorf("user not found")
	}

	// Check if dual key wrapping is set up
	if user.MasterKeyServerWrapped == "" || user.MasterKeyVersion == 0 {
		return fmt.Errorf("dual key wrapping not initialized for user")
	}

	// Get server master key for this user's version
	kekServer, err := config.GetServerMasterKey(user.MasterKeyVersion)
	if err != nil {
		return fmt.Errorf("failed to get server master key: %w", err)
	}

	// Unwrap master key using server key
	aadServer := fmt.Sprintf("server:%d:%d", userID, user.MasterKeyVersion)
	masterKey, err := utils.UnwrapKey(user.MasterKeyServerWrapped, kekServer, aadServer)
	if err != nil {
		return fmt.Errorf("failed to unwrap master key: %w", err)
	}

	// Encrypt new data with master key
	encryptedData, err := utils.EncryptDataWithKey(newData, masterKey)
	if err != nil {
		return fmt.Errorf("failed to encrypt data: %w", err)
	}

	// Update user data
	var userData models.UserData
	if err := db.Where("user_id = ?", userID).First(&userData).Error; err != nil {
		// Create new user data if doesn't exist
		userData = models.UserData{
			UserID:        userID,
			EncryptedData: encryptedData,
			IsEncrypted:   true,
		}
		return db.Create(&userData).Error
	}

	// Update existing data
	userData.EncryptedData = encryptedData
	userData.IsEncrypted = true
	return db.Save(&userData).Error
}

// MigrateUserDataFormat is an example of how server-side decryption would be used
// for administrative data format migrations without requiring user passwords
// NOT exposed as a public API endpoint
func MigrateUserDataFormat(c *gin.Context) {
	// This is just an example - in production, you would:
	// 1. Add admin authentication
	// 2. Add proper logging
	// 3. Add transaction management
	// 4. Add rollback capability

	db := database.GetDB()
	var users []models.User

	// Get all users with dual key wrapping
	if err := db.Where("master_key_server_wrapped != ?", "").Find(&users).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to get users")
		return
	}

	migratedCount := 0
	failedCount := 0

	for _, user := range users {
		// Decrypt data using server key
		decryptedData, err := ServerDecryptUserData(user.ID)
		if err != nil {
			failedCount++
			continue
		}

		// Example: Perform data format transformation
		// transformedData := transformDataFormat(decryptedData)

		// Re-encrypt with server key
		err = ServerUpdateUserData(user.ID, decryptedData)
		if err != nil {
			failedCount++
			continue
		}

		migratedCount++
	}

	utils.SuccessResponse(c, map[string]interface{}{
		"migrated_count": migratedCount,
		"failed_count":   failedCount,
	})
}
