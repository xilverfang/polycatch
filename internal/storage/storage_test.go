package storage

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"
)

// testDB creates a temporary database for testing
func testDB(t *testing.T) (*Database, func()) {
	t.Helper()

	// Create temp file
	f, err := os.CreateTemp("", "polycatch_test_*.db")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	f.Close()

	cfg := Config{
		Path:            f.Name(),
		MaxOpenConns:    5,
		MaxIdleConns:    2,
		ConnMaxLifetime: time.Minute,
	}

	db, err := Open(cfg)
	if err != nil {
		os.Remove(f.Name())
		t.Fatalf("Failed to open database: %v", err)
	}

	cleanup := func() {
		db.Close()
		os.Remove(f.Name())
		os.Remove(f.Name() + "-wal")
		os.Remove(f.Name() + "-shm")
	}

	return db, cleanup
}

func TestDatabaseOpen(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	if db == nil {
		t.Fatal("Database should not be nil")
	}

	// Verify migrations ran
	var count int
	err := db.db.QueryRow("SELECT COUNT(*) FROM migrations").Scan(&count)
	if err != nil {
		t.Fatalf("Failed to query migrations: %v", err)
	}

	if count != 4 {
		t.Errorf("Expected 4 migrations, got %d", count)
	}
}

func TestUserRepository_Create(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	creds := &UserCredentials{
		SignerPrivateKey: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		FunderAddress:    "0xabcdef1234567890abcdef1234567890abcdef12",
		APIKey:           "550e8400-e29b-41d4-a716-446655440000",
		APISecret:        "base64SecretKey==",
		APIPassphrase:    "testpassphrase",
	}

	// Create user
	err := repo.Create(ctx, 12345, "testuser", "SecurePassword123!", creds)
	if err != nil {
		t.Fatalf("Create failed: %v", err)
	}

	// Verify user exists
	exists, _ := repo.Exists(ctx, 12345)
	if !exists {
		t.Error("User should exist after creation")
	}

	// Duplicate should fail
	err = repo.Create(ctx, 12345, "testuser", "SecurePassword123!", creds)
	if err != ErrUserExists {
		t.Errorf("Expected ErrUserExists, got: %v", err)
	}
}

func TestUserRepository_DecryptCredentials(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	creds := &UserCredentials{
		SignerPrivateKey: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		FunderAddress:    "0xabcdef1234567890abcdef1234567890abcdef12",
		APIKey:           "550e8400-e29b-41d4-a716-446655440000",
		APISecret:        "base64SecretKey==",
		APIPassphrase:    "testpassphrase",
	}

	password := "SecurePassword123!"
	repo.Create(ctx, 12345, "testuser", password, creds)

	// Decrypt with correct password
	decrypted, err := repo.DecryptCredentials(ctx, 12345, password)
	if err != nil {
		t.Fatalf("DecryptCredentials failed: %v", err)
	}

	if decrypted.SignerPrivateKey != creds.SignerPrivateKey {
		t.Error("SignerPrivateKey mismatch")
	}
	if decrypted.FunderAddress != creds.FunderAddress {
		t.Error("FunderAddress mismatch")
	}
	if decrypted.APIKey != creds.APIKey {
		t.Error("APIKey mismatch")
	}

	// Wrong password should fail
	_, err = repo.DecryptCredentials(ctx, 12345, "WrongPassword123!")
	if err != ErrInvalidPassword {
		t.Errorf("Expected ErrInvalidPassword, got: %v", err)
	}
}

func TestUserRepository_ChangePassword(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	creds := &UserCredentials{
		SignerPrivateKey: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		FunderAddress:    "0xabcdef1234567890abcdef1234567890abcdef12",
		APIKey:           "550e8400-e29b-41d4-a716-446655440000",
		APISecret:        "base64SecretKey==",
		APIPassphrase:    "testpassphrase",
	}

	oldPassword := "SecurePassword123!"
	newPassword := "NewSecurePassword456!"

	repo.Create(ctx, 12345, "testuser", oldPassword, creds)

	// Change password
	err := repo.ChangePassword(ctx, 12345, oldPassword, newPassword)
	if err != nil {
		t.Fatalf("ChangePassword failed: %v", err)
	}

	// Old password should fail
	_, err = repo.DecryptCredentials(ctx, 12345, oldPassword)
	if err != ErrInvalidPassword {
		t.Error("Old password should not work")
	}

	// New password should work
	decrypted, err := repo.DecryptCredentials(ctx, 12345, newPassword)
	if err != nil {
		t.Fatalf("New password should work: %v", err)
	}

	if decrypted.APIKey != creds.APIKey {
		t.Error("Credentials corrupted after password change")
	}
}

func TestUserRepository_UpdateSettings(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	creds := &UserCredentials{
		SignerPrivateKey: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		FunderAddress:    "0xabcdef1234567890abcdef1234567890abcdef12",
		APIKey:           "550e8400-e29b-41d4-a716-446655440000",
		APISecret:        "base64SecretKey==",
		APIPassphrase:    "testpassphrase",
	}

	repo.Create(ctx, 12345, "testuser", "SecurePassword123!", creds)

	// Update settings
	newSettings := UserSettings{
		MinDepositAmount:  5000,
		SlippageTolerance: 2.0,
		MinTradeAmount:    5.0,
		MaxTradePercent:   50,
		AutoTrade:         true,
	}

	err := repo.UpdateSettings(ctx, 12345, newSettings)
	if err != nil {
		t.Fatalf("UpdateSettings failed: %v", err)
	}

	// Verify settings
	user, _ := repo.GetByTelegramID(ctx, 12345)
	if user.Settings.MinDepositAmount != 5000 {
		t.Error("MinDepositAmount not updated")
	}
	if user.Settings.AutoTrade != true {
		t.Error("AutoTrade not updated")
	}
}

func TestUserRepository_Deactivate(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	repo := NewUserRepository(db)
	ctx := context.Background()

	creds := &UserCredentials{
		SignerPrivateKey: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		FunderAddress:    "0xabcdef1234567890abcdef1234567890abcdef12",
		APIKey:           "550e8400-e29b-41d4-a716-446655440000",
		APISecret:        "base64SecretKey==",
		APIPassphrase:    "testpassphrase",
	}

	repo.Create(ctx, 12345, "testuser", "SecurePassword123!", creds)

	// Deactivate
	err := repo.Deactivate(ctx, 12345)
	if err != nil {
		t.Fatalf("Deactivate failed: %v", err)
	}

	// Should not be able to decrypt
	_, err = repo.DecryptCredentials(ctx, 12345, "SecurePassword123!")
	if err != ErrAccountInactive {
		t.Errorf("Expected ErrAccountInactive, got: %v", err)
	}
}

func TestTradeRepository_Create(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	// Create user first (for foreign key)
	userRepo := NewUserRepository(db)
	ctx := context.Background()

	creds := &UserCredentials{
		SignerPrivateKey: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		FunderAddress:    "0xabcdef1234567890abcdef1234567890abcdef12",
		APIKey:           "550e8400-e29b-41d4-a716-446655440000",
		APISecret:        "base64SecretKey==",
		APIPassphrase:    "testpassphrase",
	}
	userRepo.Create(ctx, 12345, "testuser", "SecurePassword123!", creds)

	// Create trade
	tradeRepo := NewTradeRepository(db)

	trade := &Trade{
		TelegramID:     12345,
		TokenID:        "token123",
		MarketQuestion: "Will X happen?",
		Side:           TradeSideBuy,
		Outcome:        TradeOutcomeYes,
		Price:          0.65,
		AmountUSD:      100.0,
		Shares:         153.85,
		Status:         TradeStatusSuccess,
		InsiderAddress: "0xinsider123",
		InsiderAmount:  50000,
		OrderID:        "order-456",
		ExecutedAt:     time.Now(),
	}

	id, err := tradeRepo.Create(ctx, trade)
	if err != nil {
		t.Fatalf("Create trade failed: %v", err)
	}

	if id <= 0 {
		t.Error("Trade ID should be positive")
	}

	// Get trade
	retrieved, err := tradeRepo.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}

	if retrieved.TokenID != trade.TokenID {
		t.Error("TokenID mismatch")
	}
	if retrieved.AmountUSD != trade.AmountUSD {
		t.Error("AmountUSD mismatch")
	}
}

func TestTradeRepository_GetStats(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	userRepo := NewUserRepository(db)
	ctx := context.Background()

	creds := &UserCredentials{
		SignerPrivateKey: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
		FunderAddress:    "0xabcdef1234567890abcdef1234567890abcdef12",
		APIKey:           "550e8400-e29b-41d4-a716-446655440000",
		APISecret:        "base64SecretKey==",
		APIPassphrase:    "testpassphrase",
	}
	userRepo.Create(ctx, 12345, "testuser", "SecurePassword123!", creds)

	tradeRepo := NewTradeRepository(db)

	// Create some trades
	trades := []*Trade{
		{TelegramID: 12345, TokenID: "t1", Side: TradeSideBuy, Outcome: TradeOutcomeYes, Price: 0.5, AmountUSD: 100, Status: TradeStatusSuccess, InsiderAddress: "0x1", ExecutedAt: time.Now()},
		{TelegramID: 12345, TokenID: "t2", Side: TradeSideBuy, Outcome: TradeOutcomeYes, Price: 0.6, AmountUSD: 200, Status: TradeStatusSuccess, InsiderAddress: "0x2", ExecutedAt: time.Now()},
		{TelegramID: 12345, TokenID: "t3", Side: TradeSideBuy, Outcome: TradeOutcomeNo, Price: 0.4, AmountUSD: 50, Status: TradeStatusFailed, InsiderAddress: "0x3", ExecutedAt: time.Now()},
	}

	for _, trade := range trades {
		tradeRepo.Create(ctx, trade)
	}

	// Get stats
	stats, err := tradeRepo.GetStats(ctx, 12345)
	if err != nil {
		t.Fatalf("GetStats failed: %v", err)
	}

	if stats.TotalCount != 3 {
		t.Errorf("Expected 3 total, got %d", stats.TotalCount)
	}
	if stats.SuccessCount != 2 {
		t.Errorf("Expected 2 success, got %d", stats.SuccessCount)
	}
	if stats.FailedCount != 1 {
		t.Errorf("Expected 1 failed, got %d", stats.FailedCount)
	}
	if stats.SuccessAmount != 300 {
		t.Errorf("Expected 300 success amount, got %f", stats.SuccessAmount)
	}
}

func TestAuditRepository_Log(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	repo := NewAuditRepository(db)
	ctx := context.Background()

	// Log some actions
	err := repo.LogRegister(ctx, 12345, "testuser")
	if err != nil {
		t.Fatalf("LogRegister failed: %v", err)
	}

	err = repo.LogLogin(ctx, 12345)
	if err != nil {
		t.Fatalf("LogLogin failed: %v", err)
	}

	err = repo.LogLoginFailed(ctx, 12345, "wrong password")
	if err != nil {
		t.Fatalf("LogLoginFailed failed: %v", err)
	}

	// Get logs
	logs, err := repo.GetByUser(ctx, 12345, 10, 0)
	if err != nil {
		t.Fatalf("GetByUser failed: %v", err)
	}

	if len(logs) != 3 {
		t.Errorf("Expected 3 logs, got %d", len(logs))
	}
}

func TestAuditRepository_SanitizeDetails(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	repo := NewAuditRepository(db)
	ctx := context.Background()

	// Log with sensitive data (should be redacted)
	details := map[string]interface{}{
		"username": "testuser",
		"password": "supersecret", // Should be redacted
		"api_key":  "key123",      // Should be redacted
		"amount":   100.0,
	}

	err := repo.Log(ctx, 12345, AuditActionSettingsUpdate, true, details)
	if err != nil {
		t.Fatalf("Log failed: %v", err)
	}

	// Retrieve and verify
	logs, _ := repo.GetByUser(ctx, 12345, 1, 0)
	if len(logs) != 1 {
		t.Fatal("Expected 1 log")
	}

	if logs[0].Details["password"] != "[REDACTED]" {
		t.Error("Password should be redacted")
	}
	if logs[0].Details["api_key"] != "[REDACTED]" {
		t.Error("API key should be redacted")
	}
	if logs[0].Details["username"] != "testuser" {
		t.Error("Username should not be redacted")
	}
}

func TestAuditRepository_GetFailedLogins(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	repo := NewAuditRepository(db)
	ctx := context.Background()

	// Create some failed logins
	for i := 0; i < 5; i++ {
		repo.LogLoginFailed(ctx, 12345, "wrong password")
	}

	// Count recent failures
	since := time.Now().Add(-time.Hour)
	count, err := repo.GetFailedLogins(ctx, 12345, since)
	if err != nil {
		t.Fatalf("GetFailedLogins failed: %v", err)
	}

	if count != 5 {
		t.Errorf("Expected 5 failed logins, got %d", count)
	}
}

func TestTransaction(t *testing.T) {
	db, cleanup := testDB(t)
	defer cleanup()

	ctx := context.Background()

	// Test successful transaction
	err := db.Transaction(ctx, func(tx *sql.Tx) error {
		// This would normally do database operations
		return nil
	})
	if err != nil {
		t.Errorf("Transaction should succeed: %v", err)
	}
}
