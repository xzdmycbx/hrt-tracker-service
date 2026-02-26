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
	MasterKeyServerCurrentVersion int    // Current version of server master key
	TurnstileSecretKey            string // Cloudflare Turnstile secret key
	TurnstileEnabled              bool   // Whether Turnstile verification is enabled
	TurnstileAllowedHostname      string // Optional: allowed hostname for Turnstile verification

	// Registration & OIDC
	RegistrationDisabled bool   // Disable local username/password registration
	OIDCEnabled          bool   // Enable OIDC/OAuth2 login
	OIDCProviderURL      string // OIDC provider base URL (discovery at /.well-known/openid-configuration)
	OIDCClientID         string // OAuth2 client ID
	OIDCClientSecret     string // OAuth2 client secret
	OIDCRedirectURI      string // Frontend redirect URI after OIDC auth (the frontend callback page URL)
	OIDCScopes           string // Space-separated scopes (default: "openid profile email")
	OIDCAutoRegister     bool   // Auto-register new users who log in via OIDC

	// CORS
	CORSAllowedOrigins string // Comma-separated allowed origins, or "*" for all (default: "*")
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

	// Turnstile configuration
	turnstileEnabledStr := getEnv("TURNSTILE_ENABLED", "true")
	turnstileEnabled, err := strconv.ParseBool(turnstileEnabledStr)
	if err != nil {
		log.Fatalf("Invalid TURNSTILE_ENABLED value: %s (must be true or false)", turnstileEnabledStr)
	}
	turnstileSecretKey := os.Getenv("TURNSTILE_SECRET_KEY")

	// OIDC / Registration configuration
	parseBoolEnv := func(key, defaultVal string) bool {
		raw := getEnv(key, defaultVal)
		v, err := strconv.ParseBool(raw)
		if err != nil {
			log.Printf("WARNING: Invalid boolean value for %s=%q — using default (%s)", key, raw, defaultVal)
			v, _ = strconv.ParseBool(defaultVal)
		}
		return v
	}
	oidcEnabled := parseBoolEnv("OIDC_ENABLED", "false")
	oidcAutoRegister := parseBoolEnv("OIDC_AUTO_REGISTER", "true")
	registrationDisabled := parseBoolEnv("REGISTRATION_DISABLED", "false")

	AppConfig = &Config{
		Port:                          getEnv("PORT", "8080"),
		DBPath:                        getEnv("DB_PATH", "./data/hrt-tracker.db"),
		JWTAccessSecret:               jwtAccessSecret,
		JWTRefreshSecret:              jwtRefreshSecret,
		AccessTokenExpireHours:        accessExpire,
		MasterKeyServerCurrentVersion: masterKeyVersion,
		TurnstileSecretKey:            turnstileSecretKey,
		TurnstileEnabled:              turnstileEnabled,
		TurnstileAllowedHostname:      os.Getenv("TURNSTILE_ALLOWED_HOSTNAME"),
		RegistrationDisabled:          registrationDisabled,
		OIDCEnabled:                   oidcEnabled,
		OIDCProviderURL:               os.Getenv("OIDC_PROVIDER_URL"),
		OIDCClientID:                  os.Getenv("OIDC_CLIENT_ID"),
		OIDCClientSecret:              os.Getenv("OIDC_CLIENT_SECRET"),
		OIDCRedirectURI:               os.Getenv("OIDC_REDIRECT_URI"),
		OIDCScopes:                    getEnv("OIDC_SCOPES", "openid profile email"),
		OIDCAutoRegister:              oidcAutoRegister,
		CORSAllowedOrigins:            getEnv("CORS_ALLOWED_ORIGINS", "*"),
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

	// Validate Turnstile configuration
	if AppConfig.TurnstileEnabled && AppConfig.TurnstileSecretKey == "" {
		return fmt.Errorf("TURNSTILE_SECRET_KEY is required when TURNSTILE_ENABLED is true")
	}

	// Log warning if Turnstile is disabled
	if !AppConfig.TurnstileEnabled {
		log.Println("WARNING: Turnstile verification is disabled. This should only be used in development.")
	}

	// Validate OIDC configuration
	if AppConfig.OIDCEnabled {
		if AppConfig.OIDCProviderURL == "" {
			return fmt.Errorf("OIDC_PROVIDER_URL is required when OIDC_ENABLED is true")
		}
		if AppConfig.OIDCClientID == "" {
			return fmt.Errorf("OIDC_CLIENT_ID is required when OIDC_ENABLED is true")
		}
		if AppConfig.OIDCClientSecret == "" {
			return fmt.Errorf("OIDC_CLIENT_SECRET is required when OIDC_ENABLED is true")
		}
		if AppConfig.OIDCRedirectURI == "" {
			return fmt.Errorf("OIDC_REDIRECT_URI is required when OIDC_ENABLED is true")
		}
	}

	if AppConfig.RegistrationDisabled {
		log.Println("INFO: Local registration is disabled. Users must log in via OIDC.")
	}

	return nil
}
