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

	// Run GORM auto-migrations (adds new tables and columns)
	if err := models.AutoMigrate(DB); err != nil {
		return err
	}

	// Step 1: Ensure the canonical OIDC column names exist and migrate data
	// from any old GORM-generated column names (e.g. o_i_d_c_subject).
	if err := migrateOIDCColumnNames(db); err != nil {
		return err
	}

	// Step 2: Normalize NULL/whitespace-only fields from legacy rows.
	if err := normalizeLegacyAuthFields(db); err != nil {
		return err
	}

	// Step 3: Repair common legacy password storage issues.
	if err := repairLegacyPasswordStorage(db); err != nil {
		return err
	}

	// Step 4: Remove duplicate OIDC users, keeping the earliest account.
	if err := cleanupDuplicateOIDCUsers(db); err != nil {
		return err
	}

	// Step 5: Add a partial unique index to prevent future duplicates.
	db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_oidc_identity ON users(oidc_subject, oidc_provider) WHERE oidc_subject != '' AND oidc_provider != ''")

	log.Println("Database initialized successfully")
	return nil
}

// GetDB returns the database instance
func GetDB() *gorm.DB {
	return DB
}

// pragmaColumns returns a set of lowercase column names for the given table.
func pragmaColumns(db *gorm.DB, table string) map[string]bool {
	type row struct {
		Name string `gorm:"column:name"`
	}
	var rows []row
	db.Raw("PRAGMA table_info(" + table + ")").Scan(&rows)
	cols := make(map[string]bool, len(rows))
	for _, r := range rows {
		cols[strings.ToLower(r.Name)] = true
	}
	return cols
}

// normalizeLegacyAuthFields ensures NULL and whitespace-only auth fields are
// replaced with empty strings. This prevents unexpected behaviour when the
// Go code does equality comparisons against "".
func normalizeLegacyAuthFields(db *gorm.DB) error {
	// Warn about users with NULL password - these would be treated as OIDC-only
	// accounts after normalization. This should never happen under normal operation;
	// if it does, it indicates a prior migration or data-integrity issue.
	var nullPasswordCount int64
	if err := db.Raw("SELECT COUNT(*) FROM users WHERE password IS NULL").Scan(&nullPasswordCount).Error; err == nil && nullPasswordCount > 0 {
		log.Printf("Migration WARNING: %d user(s) have a NULL password field. They will be normalized to empty string (OIDC-only). If these users did not intend to be OIDC-only and have no OIDC identity linked, they will be locked out and require administrator intervention to restore access.", nullPasswordCount)
	}

	statements := []string{
		"UPDATE users SET password = '' WHERE password IS NULL",
		"UPDATE users SET oidc_subject = '' WHERE oidc_subject IS NULL",
		"UPDATE users SET oidc_provider = '' WHERE oidc_provider IS NULL",
		"UPDATE users SET oidc_email = '' WHERE oidc_email IS NULL",
		"UPDATE users SET oidc_subject = TRIM(oidc_subject), oidc_provider = TRIM(oidc_provider), oidc_email = TRIM(oidc_email)",
	}
	for _, stmt := range statements {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}
	return nil
}

// repairLegacyPasswordStorage normalizes password field quirks found in legacy
// datasets so they can be parsed and verified consistently by the login flow.
func repairLegacyPasswordStorage(db *gorm.DB) error {
	statements := []string{
		"UPDATE users SET password = TRIM(password) WHERE password IS NOT NULL",
		// Some manual imports used full-width colon as delimiter.
		"UPDATE users SET password = REPLACE(password, CHAR(65306), ':') WHERE INSTR(password, CHAR(65306)) > 0",
		// Strip CR/LF that may be introduced by CSV/manual copy operations.
		"UPDATE users SET password = REPLACE(REPLACE(password, CHAR(13), ''), CHAR(10), '') WHERE INSTR(password, CHAR(13)) > 0 OR INSTR(password, CHAR(10)) > 0",
	}
	for _, stmt := range statements {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}

	var malformed int64
	if err := db.Raw("SELECT COUNT(*) FROM users WHERE password != '' AND INSTR(password, ':') = 0").Scan(&malformed).Error; err == nil && malformed > 0 {
		log.Printf("Migration WARNING: %d user(s) still have non-empty password fields without a ':' delimiter and may not be able to log in until repaired.", malformed)
	}

	return nil
}

// migrateOIDCColumnNames ensures the canonical column names (oidc_subject,
// oidc_provider, oidc_email) exist on the users table.
//
// GORM's default naming strategy may have created columns under alternative
// names (e.g. o_i_d_c_subject) depending on the version. This function
// detects those variants, adds the canonical columns if missing, copies any
// existing data, and is safe to run repeatedly.
func migrateOIDCColumnNames(db *gorm.DB) error {
	cols := pragmaColumns(db, "users")

	// Mapping: canonical name -> possible old GORM-generated names to check
	migrations := []struct {
		canonical string
		ddl       string
		oldNames  []string
	}{
		{
			"oidc_subject",
			"ALTER TABLE users ADD COLUMN oidc_subject TEXT NOT NULL DEFAULT ''",
			[]string{"o_i_d_c_subject", "o_id_c_subject", "oidcsubject"},
		},
		{
			"oidc_provider",
			"ALTER TABLE users ADD COLUMN oidc_provider TEXT NOT NULL DEFAULT ''",
			[]string{"o_i_d_c_provider", "o_id_c_provider", "oidcprovider"},
		},
		{
			"oidc_email",
			"ALTER TABLE users ADD COLUMN oidc_email TEXT NOT NULL DEFAULT ''",
			[]string{"o_i_d_c_email", "o_id_c_email", "oidcemail"},
		},
	}

	for _, m := range migrations {
		// Ensure the canonical column exists
		if !cols[m.canonical] {
			if err := db.Exec(m.ddl).Error; err != nil {
				return err
			}
			log.Printf("Migration: added column %q to users", m.canonical)
			cols[m.canonical] = true
		}

		// Copy data from any old-named column into the canonical one
		for _, old := range m.oldNames {
			if !cols[old] {
				continue
			}
			res := db.Exec(
				"UPDATE users SET " + m.canonical + " = " + old +
					" WHERE (" + m.canonical + " IS NULL OR " + m.canonical + " = '') AND " + old + " != ''",
			)
			if res.Error != nil {
				log.Printf("Migration warning: could not copy %q -> %q: %v", old, m.canonical, res.Error)
			} else if res.RowsAffected > 0 {
				log.Printf("Migration: copied %d rows from %q to %q", res.RowsAffected, old, m.canonical)
			}
		}
	}
	return nil
}

// cleanupDuplicateOIDCUsers removes duplicate accounts that share the same
// (oidc_subject, oidc_provider) pair, keeping only the account with the
// smallest ID (earliest registration). All associated records in
// refresh_tokens, user_data, shares, and authorizations are also removed.
func cleanupDuplicateOIDCUsers(db *gorm.DB) error {
	// Find all (oidc_subject, oidc_provider) groups that have more than one user
	type dupeGroup struct {
		OIDCSubject  string `gorm:"column:oidc_subject"`
		OIDCProvider string `gorm:"column:oidc_provider"`
		MinID        uint   `gorm:"column:min_id"`
	}
	var groups []dupeGroup
	db.Raw(`
		SELECT oidc_subject, oidc_provider, MIN(id) AS min_id
		FROM users
		WHERE oidc_subject != '' AND oidc_provider != ''
		GROUP BY oidc_subject, oidc_provider
		HAVING COUNT(*) > 1
	`).Scan(&groups)

	if len(groups) == 0 {
		return nil
	}

	for _, g := range groups {
		// Collect IDs of the duplicate accounts (everyone except the earliest)
		var dupIDs []uint
		db.Raw(`
			SELECT id FROM users
			WHERE oidc_subject = ? AND oidc_provider = ? AND id != ?
		`, g.OIDCSubject, g.OIDCProvider, g.MinID).Scan(&dupIDs)

		if len(dupIDs) == 0 {
			continue
		}

		// Cascade-delete associated records
		db.Where("user_id IN ?", dupIDs).Delete(&models.RefreshToken{})
		db.Where("user_id IN ?", dupIDs).Delete(&models.UserData{})
		db.Where("user_id IN ?", dupIDs).Delete(&models.Share{})
		db.Where("owner_id IN ? OR viewer_id IN ?", dupIDs, dupIDs).Delete(&models.Authorization{})

		// Delete the duplicate user records
		result := db.Where("id IN ?", dupIDs).Delete(&models.User{})

		log.Printf("Migration: removed %d duplicate OIDC user(s) for subject %q (kept user ID %d)",
			result.RowsAffected, g.OIDCSubject, g.MinID)
	}

	return nil
}
