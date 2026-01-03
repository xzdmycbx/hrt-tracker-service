package handlers

import (
	"bytes"
	"fmt"
	"hrt-tracker-service/database"
	"hrt-tracker-service/middleware"
	"hrt-tracker-service/models"
	"hrt-tracker-service/utils"
	"image"
	"image/jpeg"
	_ "image/png"  // Register PNG decoder
	_ "image/gif"  // Register GIF decoder
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/nfnt/resize"
)

const (
	maxUploadSize     = 5 * 1024 * 1024  // 5MB
	maxCompressedSize = 1 * 1024 * 1024  // 1MB
	avatarDir         = "./avatars"
	jpegQuality       = 85 // Good quality, reasonable compression
	minJpegQuality    = 50 // Minimum quality threshold
)

// UploadAvatar handles avatar upload
func UploadAvatar(c *gin.Context) {
	userID := middleware.GetUserID(c)

	// Parse multipart form with max memory matching maxUploadSize
	if err := c.Request.ParseMultipartForm(maxUploadSize); err != nil {
		utils.BadRequestResponse(c, "Failed to parse form")
		return
	}

	file, header, err := c.Request.FormFile("avatar")
	if err != nil {
		utils.BadRequestResponse(c, "Avatar file required")
		return
	}
	defer file.Close()

	// Check file size
	if header.Size > maxUploadSize {
		utils.BadRequestResponse(c, fmt.Sprintf("File too large. Maximum size is %dMB", maxUploadSize/(1024*1024)))
		return
	}

	// Validate file type (check signature)
	fileBytes, err := io.ReadAll(file)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to read file")
		return
	}

	// Detect image format
	img, _, err := image.Decode(bytes.NewReader(fileBytes))
	if err != nil {
		utils.BadRequestResponse(c, "Invalid image file")
		return
	}

	// Ensure avatars directory exists
	if err := os.MkdirAll(avatarDir, 0750); err != nil {
		utils.InternalErrorResponse(c, "Failed to create avatar directory")
		return
	}

	// Generate unique filename (all avatars converted to JPEG format)
	filename := fmt.Sprintf("user_%d.jpg", userID)
	filePath := filepath.Join(avatarDir, filename)

	// Verify path safety (prevent directory traversal)
	absAvatarDir, err := filepath.Abs(avatarDir)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to resolve avatar directory")
		return
	}
	absFilePath, err := filepath.Abs(filePath)
	if err != nil {
		utils.InternalErrorResponse(c, "Failed to resolve file path")
		return
	}
	if !strings.HasPrefix(absFilePath, absAvatarDir) {
		utils.InternalErrorResponse(c, "Invalid file path")
		return
	}

	// Compress if needed
	var outputBytes []byte
	needsCompression := len(fileBytes) > maxCompressedSize

	if needsCompression {
		// Compress image
		var buf bytes.Buffer

		// Calculate new size to fit under 1MB
		// Use a quality reduction approach
		quality := jpegQuality
		for {
			buf.Reset()
			if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: quality}); err != nil {
				utils.InternalErrorResponse(c, "Failed to compress image")
				return
			}

			if buf.Len() <= maxCompressedSize || quality <= minJpegQuality {
				break
			}
			quality -= 5
		}

		// If still too large, resize image
		if buf.Len() > maxCompressedSize {
			// Calculate resize ratio
			targetSize := 0.8 * float64(maxCompressedSize)
			ratio := targetSize / float64(buf.Len())
			newWidth := uint(float64(img.Bounds().Dx()) * ratio)

			// Resize
			resized := resize.Resize(newWidth, 0, img, resize.Lanczos3)

			buf.Reset()
			if err := jpeg.Encode(&buf, resized, &jpeg.Options{Quality: jpegQuality}); err != nil {
				utils.InternalErrorResponse(c, "Failed to resize image")
				return
			}
		}

		outputBytes = buf.Bytes()
	} else {
		// No compression needed, but still convert to JPEG for consistency
		var buf bytes.Buffer
		if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: jpegQuality}); err != nil {
			utils.InternalErrorResponse(c, "Failed to encode image")
			return
		}
		outputBytes = buf.Bytes()
	}

	// Save to file with restrictive permissions
	if err := os.WriteFile(filePath, outputBytes, 0640); err != nil {
		utils.InternalErrorResponse(c, "Failed to save avatar")
		return
	}

	// Update user avatar path in database
	db := database.GetDB()
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		// Cleanup uploaded file
		os.Remove(filePath)
		utils.NotFoundResponse(c, "User not found")
		return
	}

	// Delete old avatar if exists (after DB confirms user)
	if user.Avatar != "" && user.Avatar != filename {
		oldPath := filepath.Join(avatarDir, user.Avatar)
		os.Remove(oldPath) // Ignore error, old file may not exist
	}

	user.Avatar = filename
	if err := db.Save(&user).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to update user")
		return
	}

	utils.SuccessResponse(c, map[string]interface{}{
		"avatar":        filename,
		"original_size": header.Size,
		"final_size":    len(outputBytes),
		"compressed":    needsCompression,
	})
}

// GetAvatar serves the avatar file
func GetAvatar(c *gin.Context) {
	username := c.Param("username")

	db := database.GetDB()
	var user models.User
	if err := db.Where("username = ?", username).First(&user).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	if user.Avatar == "" {
		utils.NotFoundResponse(c, "Avatar not set")
		return
	}

	// Validate filename format using whitelist (only allow user_数字.jpg)
	if !regexp.MustCompile(`^user_\d+\.jpg$`).MatchString(user.Avatar) {
		utils.NotFoundResponse(c, "Invalid avatar path")
		return
	}

	avatarPath := filepath.Join(avatarDir, user.Avatar)

	// Check if file exists
	if _, err := os.Stat(avatarPath); os.IsNotExist(err) {
		utils.NotFoundResponse(c, "Avatar file not found")
		return
	}

	// Set caching and content type headers
	c.Header("Content-Type", "image/jpeg")
	c.Header("Cache-Control", "public, max-age=86400") // Cache for 1 day
	c.Header("ETag", fmt.Sprintf(`"%d"`, user.UpdatedAt.Unix()))

	c.File(avatarPath)
}

// DeleteAvatar removes user's avatar
func DeleteAvatar(c *gin.Context) {
	userID := middleware.GetUserID(c)

	db := database.GetDB()
	var user models.User
	if err := db.First(&user, userID).Error; err != nil {
		utils.NotFoundResponse(c, "User not found")
		return
	}

	if user.Avatar == "" {
		utils.BadRequestResponse(c, "No avatar to delete")
		return
	}

	// Delete file first
	avatarPath := filepath.Join(avatarDir, user.Avatar)
	if err := os.Remove(avatarPath); err != nil && !os.IsNotExist(err) {
		utils.InternalErrorResponse(c, "Failed to delete avatar file")
		return
	}

	// Update database only after file deletion succeeds
	user.Avatar = ""
	if err := db.Save(&user).Error; err != nil {
		utils.InternalErrorResponse(c, "Failed to update database")
		return
	}

	utils.SuccessMessageResponse(c, "Avatar deleted successfully", nil)
}
