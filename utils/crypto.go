package utils

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/pbkdf2"
)

const (
	saltSize   = 16
	keySize    = 32
	iterations = 100000 // Increased from 10000 for better security

	// Argon2id parameters
	argon2Memory      = 64 * 1024 // 64 MB
	argon2Iterations  = 3
	argon2Parallelism = 4
	argon2KeyLen      = 32
)

// GenerateSalt generates a random salt
func GenerateSalt() (string, error) {
	salt := make([]byte, saltSize)
	if _, err := rand.Read(salt); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(salt), nil
}

// HashPassword hashes a password with a salt using PBKDF2
func HashPassword(password, salt string) string {
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		// If salt decode fails, return empty string (this should never happen with valid salts)
		return ""
	}
	hash := pbkdf2.Key([]byte(password), saltBytes, iterations, keySize, sha256.New)
	return base64.StdEncoding.EncodeToString(hash)
}

// VerifyPassword verifies a password against a hash using constant-time comparison
func VerifyPassword(password, salt, hash string) bool {
	computedHash := HashPassword(password, salt)
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(computedHash), []byte(hash)) == 1
}

// HashPasswordArgon2id hashes a password with a salt using Argon2id (for 6-digit security passwords)
// Uses stronger parameters suitable for short passwords
func HashPasswordArgon2id(password, salt string) (string, error) {
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return "", err
	}

	// Use stronger parameters for short 6-digit passwords
	// Memory: 64 MB, Iterations: 4 (more than key derivation), Parallelism: 4
	hash := argon2.IDKey(
		[]byte(password),
		saltBytes,
		4,                // iterations (more than the 3 used for key derivation)
		argon2Memory,     // 64 MB memory
		argon2Parallelism, // 4 threads
		argon2KeyLen,     // 32 bytes output
	)

	return base64.StdEncoding.EncodeToString(hash), nil
}

// VerifyPasswordArgon2id verifies a password against an Argon2id hash using constant-time comparison
func VerifyPasswordArgon2id(password, salt, hash string) bool {
	computedHash, err := HashPasswordArgon2id(password, salt)
	if err != nil {
		return false
	}
	// Use constant-time comparison to prevent timing attacks
	return subtle.ConstantTimeCompare([]byte(computedHash), []byte(hash)) == 1
}

// EncryptData encrypts data using AES-256-GCM with a password
func EncryptData(data, password string) (string, error) {
	// Derive key from password
	salt, err := GenerateSalt()
	if err != nil {
		return "", err
	}
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return "", err
	}
	key := pbkdf2.Key([]byte(password), saltBytes, iterations, keySize, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)

	// Prepend salt to ciphertext
	result := append(saltBytes, ciphertext...)
	return base64.StdEncoding.EncodeToString(result), nil
}

// DecryptData decrypts data using AES-256-GCM with a password
func DecryptData(encryptedData, password string) (string, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	if len(data) < saltSize {
		return "", errors.New("invalid encrypted data")
	}

	// Extract salt and ciphertext
	salt := data[:saltSize]
	ciphertext := data[saltSize:]

	// Derive key from password
	key := pbkdf2.Key([]byte(password), salt, iterations, keySize, sha256.New)

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < gcm.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}

	// Extract nonce and encrypted data
	nonce := ciphertext[:gcm.NonceSize()]
	ciphertext = ciphertext[gcm.NonceSize():]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

// DeriveKeyArgon2id derives a key from password using Argon2id
func DeriveKeyArgon2id(password, salt string) ([]byte, error) {
	saltBytes, err := base64.StdEncoding.DecodeString(salt)
	if err != nil {
		return nil, err
	}

	key := argon2.IDKey(
		[]byte(password),
		saltBytes,
		argon2Iterations,
		argon2Memory,
		argon2Parallelism,
		argon2KeyLen,
	)

	return key, nil
}

// GenerateMasterKey generates a random 256-bit master key
func GenerateMasterKey() ([]byte, error) {
	key := make([]byte, 32) // 256 bits
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	return key, nil
}

// WrapKey wraps a key using AES-256-GCM with AAD
// Returns: base64(nonce || ciphertext || tag)
func WrapKey(plainKey, kek []byte, aad string) (string, error) {
	// Create AES cipher
	block, err := aes.NewCipher(kek)
	if err != nil {
		return "", err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Generate random nonce (12 bytes for GCM)
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt with AAD
	// Seal appends the ciphertext and tag to nonce
	sealed := gcm.Seal(nonce, nonce, plainKey, []byte(aad))

	// Return base64 encoded: nonce || ciphertext || tag
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// UnwrapKey unwraps a key using AES-256-GCM with AAD
// Input: base64(nonce || ciphertext || tag)
func UnwrapKey(wrappedKey string, kek []byte, aad string) ([]byte, error) {
	// Decode base64
	sealed, err := base64.StdEncoding.DecodeString(wrappedKey)
	if err != nil {
		return nil, err
	}

	// Create AES cipher
	block, err := aes.NewCipher(kek)
	if err != nil {
		return nil, err
	}

	// Create GCM mode
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// Check minimum length
	nonceSize := gcm.NonceSize()
	if len(sealed) < nonceSize {
		return nil, errors.New("wrapped key too short")
	}

	// Extract nonce and ciphertext+tag
	nonce := sealed[:nonceSize]
	ciphertextAndTag := sealed[nonceSize:]

	// Decrypt and verify
	plainKey, err := gcm.Open(nil, nonce, ciphertextAndTag, []byte(aad))
	if err != nil {
		return nil, fmt.Errorf("failed to unwrap key: %w", err)
	}

	return plainKey, nil
}

// EncryptDataWithKey encrypts data using a specific key (for use with unwrapped master key)
func EncryptDataWithKey(data string, key []byte) (string, error) {
	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	// Create nonce
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	// Encrypt (nonce || ciphertext || tag)
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// DecryptDataWithKey decrypts data using a specific key (for use with unwrapped master key)
func DecryptDataWithKey(encryptedData string, key []byte) (string, error) {
	// Decode base64
	data, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	// Create cipher
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	if len(data) < gcm.NonceSize() {
		return "", errors.New("invalid ciphertext")
	}

	// Extract nonce and encrypted data
	nonce := data[:gcm.NonceSize()]
	ciphertext := data[gcm.NonceSize():]

	// Decrypt
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

