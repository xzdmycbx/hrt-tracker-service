package database

import (
	"hrt-tracker-service/models"
	"log"
	"os"
	"path/filepath"
	"strings"

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

	// Explicitly ensure OIDC columns exist. We use PRAGMA table_info (raw SQL)
	// rather than GORM's HasColumn, which has known reliability issues on SQLite.
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

// ensureOIDCColumns uses PRAGMA table_info to reliably detect missing columns
// and adds them with ALTER TABLE. SQLite does not support IF NOT EXISTS in
// ALTER TABLE, so we check first via PRAGMA and ignore "duplicate column" errors
// as a fallback.
func ensureOIDCColumns(db *gorm.DB) error {
	// Read existing columns from the actual SQLite schema
	type pragmaRow struct {
		Name string `gorm:"column:name"`
	}
	var rows []pragmaRow
	if err := db.Raw("PRAGMA table_info(users)").Scan(&rows).Error; err != nil {
		return err
	}
	existing := make(map[string]bool, len(rows))
	for _, r := range rows {
		existing[strings.ToLower(r.Name)] = true
	}

	additions := []struct {
		col string
		ddl string
	}{
		{"oidc_subject", "ALTER TABLE users ADD COLUMN oidc_subject TEXT NOT NULL DEFAULT ''"},
		{"oidc_provider", "ALTER TABLE users ADD COLUMN oidc_provider TEXT NOT NULL DEFAULT ''"},
		{"oidc_email", "ALTER TABLE users ADD COLUMN oidc_email TEXT NOT NULL DEFAULT ''"},
	}

	for _, a := range additions {
		if !existing[a.col] {
			if err := db.Exec(a.ddl).Error; err != nil {
				return err
			}
			log.Printf("Migration: added missing column %q to users table", a.col)
		}
	}

	db.Exec("CREATE INDEX IF NOT EXISTS idx_users_oidc_subject ON users(oidc_subject)")
	return nil
}
