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
	Port                        string
	DBPath                      string
	JWTAccessSecret             string
	JWTRefreshSecret            string
	AccessTokenExpireHours      int
	RefreshTokenExpireHours     int
	MasterKeyServerCurrentVersion int // Current version of server master key
}

var AppConfig *Config

func LoadConfig() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	accessExpire, _ := strconv.Atoi(getEnv("ACCESS_TOKEN_EXPIRE_HOURS", "1"))
	refreshExpire, _ := strconv.Atoi(getEnv("REFRESH_TOKEN_EXPIRE_HOURS", "168"))
	masterKeyVersion, _ := strconv.Atoi(getEnv("MASTER_KEY_SERVER_CURRENT_VERSION", "1"))

	AppConfig = &Config{
		Port:                        getEnv("PORT", "8080"),
		DBPath:                      getEnv("DB_PATH", "./data/hrt-tracker.db"),
		JWTAccessSecret:             getEnv("JWT_ACCESS_SECRET", "default-access-secret"),
		JWTRefreshSecret:            getEnv("JWT_REFRESH_SECRET", "default-refresh-secret"),
		AccessTokenExpireHours:      accessExpire,
		RefreshTokenExpireHours:     refreshExpire,
		MasterKeyServerCurrentVersion: masterKeyVersion,
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
