package config

import (
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

type Config struct {
	Port                          string
	DBPath                        string
	JWTAccessSecret               string
	JWTRefreshSecret              string
	AccessTokenExpireHours        int
	MasterKeyServerCurrentVersion int // Current version of server master key
}

var AppConfig *Config

func LoadConfig() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	accessExpire, _ := strconv.Atoi(getEnv("ACCESS_TOKEN_EXPIRE_HOURS", "1"))
	masterKeyVersion, _ := strconv.Atoi(getEnv("MASTER_KEY_SERVER_CURRENT_VERSION", "1"))

	// Get required secrets (no defaults)
	jwtAccessSecret := os.Getenv("JWT_ACCESS_SECRET")
	jwtRefreshSecret := os.Getenv("JWT_REFRESH_SECRET")

	AppConfig = &Config{
		Port:                          getEnv("PORT", "8080"),
		DBPath:                        getEnv("DB_PATH", "./data/hrt-tracker.db"),
		JWTAccessSecret:               jwtAccessSecret,
		JWTRefreshSecret:              jwtRefreshSecret,
		AccessTokenExpireHours:        accessExpire,
		MasterKeyServerCurrentVersion: masterKeyVersion,
	}

	// Validate critical security configuration
	if err := validateConfig(); err != nil {
		log.Fatalf("Configuration validation failed: %v", err)
	}
}

func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// GetServerMasterKey retrieves the server master key for a specific version
func GetServerMasterKey(version int) ([]byte, error) {
	keyHex := os.Getenv(fmt.Sprintf("MASTER_KEY_SERVER_V%d", version))
	if keyHex == "" {
		return nil, fmt.Errorf("server master key version %d not found in environment", version)
	}

	key, err := hex.DecodeString(keyHex)
	if err != nil {
		return nil, fmt.Errorf("invalid server master key format: %w", err)
	}

	if len(key) != 32 {
		return nil, fmt.Errorf("server master key must be 256 bits (32 bytes), got %d bytes", len(key))
	}

	return key, nil
}

// validateConfig validates critical security configuration at startup
func validateConfig() error {
	// Validate JWT secrets
	if AppConfig.JWTAccessSecret == "" {
		return fmt.Errorf("JWT_ACCESS_SECRET is required but not set")
	}
	if AppConfig.JWTRefreshSecret == "" {
		return fmt.Errorf("JWT_REFRESH_SECRET is required but not set")
	}

	// Enforce minimum secret strength (at least 32 characters)
	if len(AppConfig.JWTAccessSecret) < 32 {
		return fmt.Errorf("JWT_ACCESS_SECRET must be at least 32 characters long for security")
	}
	if len(AppConfig.JWTRefreshSecret) < 32 {
		return fmt.Errorf("JWT_REFRESH_SECRET must be at least 32 characters long for security")
	}

	// Validate server master key for current version
	if AppConfig.MasterKeyServerCurrentVersion > 0 {
		_, err := GetServerMasterKey(AppConfig.MasterKeyServerCurrentVersion)
		if err != nil {
			return fmt.Errorf("server master key validation failed: %w", err)
		}
	}

	return nil
}
