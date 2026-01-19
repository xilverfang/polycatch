package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/polycatch/internal/crypto"
)

// UserRepository handles user data operations
type UserRepository struct {
	db *Database
}

// NewUserRepository creates a new user repository
func NewUserRepository(db *Database) *UserRepository {
	return &UserRepository{db: db}
}

// Create creates a new user with encrypted credentials
// The password is used to derive an encryption key, then immediately cleared
func (r *UserRepository) Create(ctx context.Context, telegramID int64, username, password string, creds *UserCredentials) error {
	if telegramID <= 0 {
		return ErrInvalidTelegramID
	}

	if err := creds.Validate(); err != nil {
		return err
	}

	// Check password strength
	strength, _ := crypto.CheckPasswordStrength(password)
	if strength == crypto.PasswordWeak {
		return crypto.ErrPasswordTooShort
	}

	// Generate salt for this user
	salt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive encryption key from password
	key, err := crypto.DeriveKey(password, salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}
	defer crypto.SecureZero(key)

	// Serialize and encrypt credentials
	credsJSON, err := creds.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize credentials: %w", err)
	}
	defer crypto.SecureZero(credsJSON)

	// Encrypt with AAD (telegram_id binds ciphertext to this user)
	aad := []byte(fmt.Sprintf("telegram:%d", telegramID))
	encryptedCreds, err := crypto.EncryptWithAAD(credsJSON, key, aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Serialize default settings
	settings := DefaultSettings()
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to serialize settings: %w", err)
	}

	// Insert user
	now := time.Now()
	_, err = r.db.db.ExecContext(ctx, `
		INSERT INTO users (
			telegram_id, username, salt, encrypted_credentials, settings,
			is_active, created_at, updated_at, last_active_at
		) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?)
	`, telegramID, username, salt, encryptedCreds, string(settingsJSON), now, now, now)

	if err != nil {
		// Check for unique constraint violation
		if isUniqueConstraintError(err) {
			return ErrUserExists
		}
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByTelegramID retrieves a user by their Telegram ID
func (r *UserRepository) GetByTelegramID(ctx context.Context, telegramID int64) (*User, error) {
	if telegramID <= 0 {
		return nil, ErrInvalidTelegramID
	}

	row := r.db.db.QueryRowContext(ctx, `
		SELECT telegram_id, username, salt, encrypted_credentials, settings,
			   is_active, created_at, updated_at, last_active_at
		FROM users
		WHERE telegram_id = ?
	`, telegramID)

	user := &User{}
	var settingsJSON string
	err := row.Scan(
		&user.TelegramID,
		&user.Username,
		&user.Salt,
		&user.EncryptedCredentials,
		&settingsJSON,
		&user.IsActive,
		&user.CreatedAt,
		&user.UpdatedAt,
		&user.LastActiveAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrUserNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	// Parse settings
	if err := json.Unmarshal([]byte(settingsJSON), &user.Settings); err != nil {
		// Use defaults if settings are corrupted
		user.Settings = DefaultSettings()
	}

	return user, nil
}

// DecryptCredentials decrypts a user's credentials using their password
func (r *UserRepository) DecryptCredentials(ctx context.Context, telegramID int64, password string) (*UserCredentials, error) {
	user, err := r.GetByTelegramID(ctx, telegramID)
	if err != nil {
		return nil, err
	}

	if !user.IsActive {
		return nil, ErrAccountInactive
	}

	// Derive key from password and stored salt
	key, err := crypto.DeriveKey(password, user.Salt)
	if err != nil {
		return nil, err
	}
	defer crypto.SecureZero(key)

	// Decrypt with AAD
	aad := []byte(fmt.Sprintf("telegram:%d", telegramID))
	decrypted, err := crypto.DecryptWithAAD(user.EncryptedCredentials, key, aad)
	if err != nil {
		// Don't reveal whether user exists or password is wrong
		return nil, ErrInvalidPassword
	}
	defer crypto.SecureZero(decrypted)

	// Parse credentials
	creds, err := UserCredentialsFromJSON(decrypted)
	if err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	return creds, nil
}

// UpdateCredentials updates a user's encrypted credentials
func (r *UserRepository) UpdateCredentials(ctx context.Context, telegramID int64, password string, creds *UserCredentials) error {
	if err := creds.Validate(); err != nil {
		return err
	}

	user, err := r.GetByTelegramID(ctx, telegramID)
	if err != nil {
		return err
	}

	// Derive key from password and stored salt
	key, err := crypto.DeriveKey(password, user.Salt)
	if err != nil {
		return err
	}
	defer crypto.SecureZero(key)

	// Verify password by trying to decrypt existing credentials
	aad := []byte(fmt.Sprintf("telegram:%d", telegramID))
	_, err = crypto.DecryptWithAAD(user.EncryptedCredentials, key, aad)
	if err != nil {
		return ErrInvalidPassword
	}

	// Encrypt new credentials
	credsJSON, err := creds.ToJSON()
	if err != nil {
		return fmt.Errorf("failed to serialize credentials: %w", err)
	}
	defer crypto.SecureZero(credsJSON)

	encryptedCreds, err := crypto.EncryptWithAAD(credsJSON, key, aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Update user
	now := time.Now()
	_, err = r.db.db.ExecContext(ctx, `
		UPDATE users SET encrypted_credentials = ?, updated_at = ? WHERE telegram_id = ?
	`, encryptedCreds, now, telegramID)

	if err != nil {
		return fmt.Errorf("failed to update credentials: %w", err)
	}

	return nil
}

// ChangePassword changes a user's password (re-encrypts credentials with new key)
func (r *UserRepository) ChangePassword(ctx context.Context, telegramID int64, oldPassword, newPassword string) error {
	// Check new password strength
	strength, _ := crypto.CheckPasswordStrength(newPassword)
	if strength == crypto.PasswordWeak {
		return crypto.ErrPasswordTooShort
	}

	user, err := r.GetByTelegramID(ctx, telegramID)
	if err != nil {
		return err
	}

	// Decrypt with old password
	oldKey, err := crypto.DeriveKey(oldPassword, user.Salt)
	if err != nil {
		return err
	}
	defer crypto.SecureZero(oldKey)

	aad := []byte(fmt.Sprintf("telegram:%d", telegramID))
	decrypted, err := crypto.DecryptWithAAD(user.EncryptedCredentials, oldKey, aad)
	if err != nil {
		return ErrInvalidPassword
	}
	defer crypto.SecureZero(decrypted)

	// Generate new salt
	newSalt, err := crypto.GenerateSalt()
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive new key
	newKey, err := crypto.DeriveKey(newPassword, newSalt)
	if err != nil {
		return err
	}
	defer crypto.SecureZero(newKey)

	// Re-encrypt with new key
	newEncrypted, err := crypto.EncryptWithAAD(decrypted, newKey, aad)
	if err != nil {
		return fmt.Errorf("failed to encrypt credentials: %w", err)
	}

	// Update user with new salt and encrypted credentials
	now := time.Now()
	_, err = r.db.db.ExecContext(ctx, `
		UPDATE users SET salt = ?, encrypted_credentials = ?, updated_at = ? WHERE telegram_id = ?
	`, newSalt, newEncrypted, now, telegramID)

	if err != nil {
		return fmt.Errorf("failed to update password: %w", err)
	}

	return nil
}

// UpdateSettings updates a user's settings
func (r *UserRepository) UpdateSettings(ctx context.Context, telegramID int64, settings UserSettings) error {
	settingsJSON, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("failed to serialize settings: %w", err)
	}

	now := time.Now()
	result, err := r.db.db.ExecContext(ctx, `
		UPDATE users SET settings = ?, updated_at = ? WHERE telegram_id = ?
	`, string(settingsJSON), now, telegramID)

	if err != nil {
		return fmt.Errorf("failed to update settings: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

// UpdateLastActive updates the user's last active timestamp
func (r *UserRepository) UpdateLastActive(ctx context.Context, telegramID int64) error {
	now := time.Now()
	_, err := r.db.db.ExecContext(ctx, `
		UPDATE users SET last_active_at = ? WHERE telegram_id = ?
	`, now, telegramID)

	if err != nil {
		return fmt.Errorf("failed to update last active: %w", err)
	}

	return nil
}

// Deactivate deactivates a user's account
func (r *UserRepository) Deactivate(ctx context.Context, telegramID int64) error {
	now := time.Now()
	result, err := r.db.db.ExecContext(ctx, `
		UPDATE users SET is_active = 0, updated_at = ? WHERE telegram_id = ?
	`, now, telegramID)

	if err != nil {
		return fmt.Errorf("failed to deactivate user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

// Delete permanently deletes a user and all their data
func (r *UserRepository) Delete(ctx context.Context, telegramID int64) error {
	result, err := r.db.db.ExecContext(ctx, `
		DELETE FROM users WHERE telegram_id = ?
	`, telegramID)

	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	rows, _ := result.RowsAffected()
	if rows == 0 {
		return ErrUserNotFound
	}

	return nil
}

// Exists checks if a user exists
func (r *UserRepository) Exists(ctx context.Context, telegramID int64) (bool, error) {
	var count int
	err := r.db.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM users WHERE telegram_id = ?
	`, telegramID).Scan(&count)

	if err != nil {
		return false, fmt.Errorf("failed to check user existence: %w", err)
	}

	return count > 0, nil
}

// CountActive returns the number of active users
func (r *UserRepository) CountActive(ctx context.Context) (int, error) {
	var count int
	err := r.db.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM users WHERE is_active = 1
	`).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to count active users: %w", err)
	}

	return count, nil
}

// isUniqueConstraintError checks if an error is a unique constraint violation
func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	// SQLite returns "UNIQUE constraint failed" for unique violations
	return err.Error() == "UNIQUE constraint failed: users.telegram_id" ||
		err.Error()[:17] == "UNIQUE constraint"
}
