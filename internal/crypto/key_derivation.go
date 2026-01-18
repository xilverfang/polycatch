package crypto

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters based on OWASP recommendations (2023)
// https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
//
// OWASP recommends Argon2id with:
// - Minimum memory: 19 MiB (we use 64 MiB for better security)
// - Minimum iterations: 2 (we use 3)
// - Parallelism: 1 (we use 4 for modern multi-core CPUs)
//
// These parameters provide strong resistance against:
// - GPU/ASIC attacks (memory-hard)
// - Time-memory tradeoff attacks (Argon2id hybrid mode)
// - Side-channel attacks (data-independent memory access in first pass)
const (
	// Argon2idTime is the number of iterations (passes over memory)
	// Higher = more CPU time, more secure
	Argon2idTime uint32 = 3

	// Argon2idMemory is the memory usage in KiB
	// 64 MiB = 65536 KiB - provides strong GPU resistance
	Argon2idMemory uint32 = 64 * 1024

	// Argon2idParallelism is the number of parallel threads
	// Should match target CPU cores for best performance
	Argon2idParallelism uint8 = 4

	// Argon2idKeyLength is the derived key length in bytes
	// 32 bytes = 256 bits for AES-256
	Argon2idKeyLength uint32 = 32

	// Argon2idSaltLength is the minimum salt length in bytes
	// 16 bytes = 128 bits per OWASP recommendation
	Argon2idSaltLength = 32 // We use 256 bits for extra margin

	// MinPasswordLength is the minimum acceptable password length
	MinPasswordLength = 12
)

// Key derivation errors
var (
	ErrPasswordTooShort = errors.New("password must be at least 12 characters")
	ErrInvalidSalt      = errors.New("invalid salt")
	ErrInvalidHash      = errors.New("invalid password hash format")
)

// DeriveKey derives a 256-bit encryption key from a password using Argon2id.
// The salt must be unique per user and stored alongside the encrypted data.
//
// Security properties:
// - Memory-hard: Requires 64 MiB RAM, making GPU attacks expensive
// - Time-hard: 3 iterations provide computational cost
// - Hybrid mode: Combines Argon2i (side-channel resistant) and Argon2d (GPU resistant)
func DeriveKey(password string, salt []byte) ([]byte, error) {
	if len(password) < MinPasswordLength {
		return nil, ErrPasswordTooShort
	}

	if len(salt) < 16 {
		return nil, ErrInvalidSalt
	}

	key := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2idTime,
		Argon2idMemory,
		Argon2idParallelism,
		Argon2idKeyLength,
	)

	return key, nil
}

// HashPassword creates a password hash for verification purposes.
// Returns a string in the format: $argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>
// This format is compatible with many password verification libraries.
func HashPassword(password string) (string, error) {
	if len(password) < MinPasswordLength {
		return "", ErrPasswordTooShort
	}

	// Generate random salt
	salt := make([]byte, Argon2idSaltLength)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key (hash)
	hash := argon2.IDKey(
		[]byte(password),
		salt,
		Argon2idTime,
		Argon2idMemory,
		Argon2idParallelism,
		Argon2idKeyLength,
	)

	// Format: $argon2id$v=19$m=65536,t=3,p=4$<base64-salt>$<base64-hash>
	saltB64 := base64.RawStdEncoding.EncodeToString(salt)
	hashB64 := base64.RawStdEncoding.EncodeToString(hash)

	encoded := fmt.Sprintf(
		"$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version,
		Argon2idMemory,
		Argon2idTime,
		Argon2idParallelism,
		saltB64,
		hashB64,
	)

	return encoded, nil
}

// VerifyPassword verifies a password against a hash string.
// Uses constant-time comparison to prevent timing attacks.
func VerifyPassword(password, encodedHash string) (bool, error) {
	// Parse the encoded hash
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return false, ErrInvalidHash
	}

	if parts[1] != "argon2id" {
		return false, ErrInvalidHash
	}

	// Parse parameters
	var version int
	var memory, time uint32
	var parallelism uint8

	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil {
		return false, ErrInvalidHash
	}

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &parallelism)
	if err != nil {
		return false, ErrInvalidHash
	}

	// Decode salt and hash
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return false, ErrInvalidHash
	}

	expectedHash, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return false, ErrInvalidHash
	}

	// Compute hash with same parameters
	computedHash := argon2.IDKey(
		[]byte(password),
		salt,
		time,
		memory,
		parallelism,
		uint32(len(expectedHash)),
	)

	// Constant-time comparison
	return ConstantTimeCompare(computedHash, expectedHash), nil
}

// DeriveKeyFromHash extracts the salt from a password hash and derives the encryption key.
// This is useful when you need to derive the same key later for decryption.
func DeriveKeyFromHash(password, encodedHash string) ([]byte, error) {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 6 {
		return nil, ErrInvalidHash
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return nil, ErrInvalidHash
	}

	return DeriveKey(password, salt)
}

// PasswordStrength represents the strength level of a password
type PasswordStrength int

const (
	PasswordWeak      PasswordStrength = iota // < 12 chars or common patterns
	PasswordFair                              // 12-15 chars, some complexity
	PasswordStrong                            // 16-19 chars, good complexity
	PasswordExcellent                         // 20+ chars, high complexity
)

// CheckPasswordStrength evaluates password strength.
// Returns the strength level and a list of suggestions for improvement.
func CheckPasswordStrength(password string) (PasswordStrength, []string) {
	var suggestions []string
	length := len(password)

	// Check length
	if length < MinPasswordLength {
		suggestions = append(suggestions, fmt.Sprintf("Use at least %d characters", MinPasswordLength))
		return PasswordWeak, suggestions
	}

	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, c := range password {
		switch {
		case c >= 'A' && c <= 'Z':
			hasUpper = true
		case c >= 'a' && c <= 'z':
			hasLower = true
		case c >= '0' && c <= '9':
			hasDigit = true
		default:
			hasSpecial = true
		}
	}

	// Calculate complexity score
	complexity := 0
	if hasUpper {
		complexity++
	} else {
		suggestions = append(suggestions, "Add uppercase letters")
	}
	if hasLower {
		complexity++
	} else {
		suggestions = append(suggestions, "Add lowercase letters")
	}
	if hasDigit {
		complexity++
	} else {
		suggestions = append(suggestions, "Add numbers")
	}
	if hasSpecial {
		complexity++
	} else {
		suggestions = append(suggestions, "Add special characters (!@#$%^&*)")
	}

	// Determine strength based on length and complexity
	if length >= 20 && complexity >= 3 {
		return PasswordExcellent, nil
	}
	if length >= 16 && complexity >= 3 {
		if length < 20 {
			suggestions = append(suggestions, "Consider using 20+ characters for maximum security")
		}
		return PasswordStrong, suggestions
	}
	if length >= 12 && complexity >= 2 {
		suggestions = append(suggestions, "Add more character types for better security")
		return PasswordFair, suggestions
	}

	return PasswordWeak, suggestions
}
