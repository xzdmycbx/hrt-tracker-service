package database

import (
	"hrt-tracker-service/models"
	"log"
	"os"
	"path/filepath"

	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// InitDB initializes the database connection
func InitDB(dbPath string) error {
	// Create directory if it doesn't exist
	dir := filepath.Dir(dbPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Verify directory is writable by attempting to create a test file
	testFile := filepath.Join(dir, ".write_test")
	if err := os.WriteFile(testFile, []byte("test"), 0644); err != nil {
		return err
	}
	os.Remove(testFile) // Clean up test file

	// Open database connection
	db, err := gorm.Open(sqlite.Open(dbPath), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return err
	}

	DB = db

	// Run migrations
	if err := models.AutoMigrate(DB); err != nil {
		return err
	}

	// Explicitly ensure OIDC columns exist on the users table.
	// AutoMigrate may not reliably add new columns to an existing table on all
	// SQLite deployments, so we check and add them manually as a safety net.
	if err := ensureOIDCColumns(db); err != nil {
		return err
	}

	log.Println("Database initialized successfully")
	return nil
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return DB
}

// ensureOIDCColumns checks that the OIDC columns exist on the users table and
// adds them if missing. SQLite cannot detect column absence via GORM AutoMigrate
// in all deployment scenarios, so this acts as an explicit safety net.
func ensureOIDCColumns(db *gorm.DB) error {
	type colDef struct {
		field string
		sql   string
	}
	cols := []colDef{
		{"OIDCSubject", "ALTER TABLE users ADD COLUMN oidc_subject TEXT"},
		{"OIDCProvider", "ALTER TABLE users ADD COLUMN oidc_provider TEXT"},
		{"OIDCEmail", "ALTER TABLE users ADD COLUMN oidc_email TEXT"},
	}
	for _, c := range cols {
		if !db.Migrator().HasColumn(&models.User{}, c.field) {
			if err := db.Exec(c.sql).Error; err != nil {
				return err
			}
			log.Printf("Added missing column: %s", c.field)
		}
	}
	// Ensure index on oidc_subject exists
	db.Exec("CREATE INDEX IF NOT EXISTS idx_users_oidc_subject ON users(oidc_subject)")
	return nil
}
