package models

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user account
type User struct {
	ID                   uint      `gorm:"primaryKey" json:"id"`
	Username             string    `gorm:"uniqueIndex;not null" json:"username"`
	Password             string    `gorm:"not null" json:"-"`
	SecurityPasswordHash string    `gorm:"" json:"-"`
	SecurityPasswordSalt string    `gorm:"" json:"-"`
	Avatar               string    `gorm:"" json:"avatar"` // Avatar file path (relative to avatars directory)

	// Master key wrapping fields (only set when security password is configured)
	MasterKeyUserWrapped   string `gorm:"type:text" json:"-"` // Ku wrapped with user's password-derived key
	MasterKeyServerWrapped string `gorm:"type:text" json:"-"` // Ku wrapped with server key
	MasterKeySalt          string `gorm:"" json:"-"`          // Salt for user key derivation
	MasterKeyVersion       int    `gorm:"default:0" json:"-"` // Server key version (0 = not using wrapping)

	CreatedAt            time.Time `json:"created_at"`
	UpdatedAt            time.Time `json:"updated_at"`
}

// UserData represents user's encrypted JSON data
type UserData struct {
	ID            uint      `gorm:"primaryKey" json:"id"`
	UserID        uint      `gorm:"uniqueIndex;not null" json:"user_id"`
	EncryptedData string    `gorm:"type:text" json:"-"`
	IsEncrypted   bool      `gorm:"default:false" json:"is_encrypted"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// RefreshToken stores refresh tokens for users
type RefreshToken struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	UserID    uint      `gorm:"index;not null" json:"user_id"`
	Token     string    `gorm:"uniqueIndex;not null" json:"-"`
	ExpiresAt time.Time `gorm:"not null" json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`

	// Session management fields
	SessionID  string    `gorm:"index" json:"session_id"`        // Session identifier (UUIDv4)
	DeviceInfo string    `gorm:"" json:"device_info"`            // Device information (from User-Agent)
	IPAddress  string    `gorm:"" json:"ip_address"`             // Login IP address
	LastUsedAt time.Time `gorm:"" json:"last_used_at,omitempty"` // Last used time (updated on refresh)
}

// Share represents a data share (realtime or copy)
type Share struct {
	ID           uint      `gorm:"primaryKey" json:"id"`
	UserID       uint      `gorm:"not null" json:"user_id"`
	ShareType    string    `gorm:"not null" json:"share_type"` // "realtime" or "copy"
	ShareID      string    `gorm:"uniqueIndex;not null" json:"share_id"`
	PasswordHash string    `gorm:"" json:"-"`
	PasswordSalt string    `gorm:"" json:"-"`
	ViewCount    int       `gorm:"default:0" json:"view_count"`
	AttemptCount int       `gorm:"default:0" json:"attempt_count"`
	MaxAttempts  int       `gorm:"default:0" json:"max_attempts"` // 0 means unlimited
	IsLocked     bool      `gorm:"default:false" json:"is_locked"`
	SnapshotData string    `gorm:"type:text" json:"-"` // Only for copy type
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// TableName specifies the table name for Share
func (Share) TableName() string {
	return "shares"
}

// BeforeCreate adds unique constraint for realtime shares
func (s *Share) BeforeCreate(tx *gorm.DB) error {
	if s.ShareType == "realtime" {
		// Check if realtime share already exists for this user
		var count int64
		tx.Model(&Share{}).Where("user_id = ? AND share_type = ?", s.UserID, "realtime").Count(&count)
		if count > 0 {
			return gorm.ErrDuplicatedKey
		}
	}
	return nil
}

// Authorization represents authorization for one user to view another's data
type Authorization struct {
	ID        uint      `gorm:"primaryKey" json:"id"`
	OwnerID   uint      `gorm:"not null" json:"owner_id"`  // User who grants access
	ViewerID  uint      `gorm:"not null" json:"viewer_id"` // User who gets access
	CreatedAt time.Time `json:"created_at"`
}

// TableName specifies the table name for Authorization
func (Authorization) TableName() string {
	return "authorizations"
}

// BeforeCreate ensures unique authorization per owner-viewer pair
func (a *Authorization) BeforeCreate(tx *gorm.DB) error {
	// Check if authorization already exists
	var count int64
	tx.Model(&Authorization{}).Where("owner_id = ? AND viewer_id = ?", a.OwnerID, a.ViewerID).Count(&count)
	if count > 0 {
		return gorm.ErrDuplicatedKey
	}
	return nil
}

// AutoMigrate runs database migrations
func AutoMigrate(db *gorm.DB) error {
	return db.AutoMigrate(
		&User{},
		&UserData{},
		&RefreshToken{},
		&Share{},
		&Authorization{},
	)
}
