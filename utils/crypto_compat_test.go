package utils

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/pbkdf2"
)

func derivePBKDF2(password string, salt []byte, iters, keyLen int) []byte {
	return pbkdf2.Key([]byte(password), salt, iters, keyLen, sha256.New)
}

func TestVerifyPasswordCompatibility(t *testing.T) {
	password := "LegacyPass123"
	saltBytes := []byte("1234567890abcdef")
	saltB64 := base64.StdEncoding.EncodeToString(saltBytes)

	current := derivePBKDF2(password, saltBytes, iterations, keySize)
	legacy := derivePBKDF2(password, saltBytes, iterationsLegacy, keySize)
	legacyLong := derivePBKDF2(password, saltBytes, iterationsLegacy, 48)

	tests := []struct {
		name        string
		salt        string
		hash        string
		wantMatch   bool
		wantRehash  bool
		wrongPassOk bool
	}{
		{
			name:       "current canonical base64",
			salt:       saltB64,
			hash:       base64.StdEncoding.EncodeToString(current),
			wantMatch:  true,
			wantRehash: false,
		},
		{
			name:       "current raw base64 hash",
			salt:       saltB64,
			hash:       base64.RawStdEncoding.EncodeToString(current),
			wantMatch:  true,
			wantRehash: true,
		},
		{
			name:       "current base64url hash",
			salt:       saltB64,
			hash:       base64.RawURLEncoding.EncodeToString(current),
			wantMatch:  true,
			wantRehash: true,
		},
		{
			name:       "legacy iteration base64",
			salt:       saltB64,
			hash:       base64.StdEncoding.EncodeToString(legacy),
			wantMatch:  true,
			wantRehash: true,
		},
		{
			name:       "legacy iteration hex salt and hex hash",
			salt:       hex.EncodeToString(saltBytes),
			hash:       hex.EncodeToString(legacy),
			wantMatch:  true,
			wantRehash: true,
		},
		{
			name:       "legacy longer key length",
			salt:       saltB64,
			hash:       base64.StdEncoding.EncodeToString(legacyLong),
			wantMatch:  true,
			wantRehash: true,
		},
		{
			name:       "invalid salt format",
			salt:       "not-a-valid-salt@@@",
			hash:       base64.StdEncoding.EncodeToString(current),
			wantMatch:  false,
			wantRehash: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matched, needsRehash := VerifyPassword(password, tt.salt, tt.hash)
			if matched != tt.wantMatch || needsRehash != tt.wantRehash {
				t.Fatalf("VerifyPassword() = (%v, %v), want (%v, %v)", matched, needsRehash, tt.wantMatch, tt.wantRehash)
			}

			matchedWrong, _ := VerifyPassword("WrongPassword!@#", tt.salt, tt.hash)
			if matchedWrong {
				t.Fatal("VerifyPassword() unexpectedly matched wrong password")
			}
		})
	}
}
