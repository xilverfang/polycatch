// Package storage provides database models and repository patterns for Polycatch.
package storage

import (
	"encoding/json"
	"time"
)

// UserCredentials contains the sensitive data that gets encrypted.
// This is serialized to JSON, encrypted, and stored in the database.
type UserCredentials struct {
	// SignerPrivateKey is the MetaMask private key for signing EIP-712 orders
	// Format: "0x..." (64 hex chars after prefix)
	SignerPrivateKey string `json:"signer_private_key"`

	// FunderAddress is the Polymarket proxy wallet address
	// Format: "0x..." (40 hex chars after prefix)
	FunderAddress string `json:"funder_address"`

	// APIKey is the Polymarket Builder API key
	// Format: UUID "550e8400-e29b-41d4-a716-446655440000"
	APIKey string `json:"api_key"`

	// APISecret is the Polymarket Builder API secret for HMAC-SHA256
	// Format: Base64 encoded string
	APISecret string `json:"api_secret"`

	// APIPassphrase is the Polymarket Builder API passphrase
	APIPassphrase string `json:"api_passphrase"`
}

// Validate checks if all required fields are present
func (c *UserCredentials) Validate() error {
	if c.SignerPrivateKey == "" {
		return ErrMissingSignerKey
	}
	if c.FunderAddress == "" {
		return ErrMissingFunderAddress
	}
	if c.APIKey == "" {
		return ErrMissingAPIKey
	}
	if c.APISecret == "" {
		return ErrMissingAPISecret
	}
	if c.APIPassphrase == "" {
		return ErrMissingAPIPassphrase
	}
	return nil
}

// ToJSON serializes credentials to JSON bytes
func (c *UserCredentials) ToJSON() ([]byte, error) {
	return json.Marshal(c)
}

// UserCredentialsFromJSON deserializes credentials from JSON bytes
func UserCredentialsFromJSON(data []byte) (*UserCredentials, error) {
	var creds UserCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, err
	}
	return &creds, nil
}

// UserSettings contains non-sensitive user preferences
type UserSettings struct {
	// MinDepositAmount is the minimum deposit to monitor (in USD)
	MinDepositAmount float64 `json:"min_deposit_amount"`

	// SlippageTolerance is the maximum slippage percentage allowed
	SlippageTolerance float64 `json:"slippage_tolerance"`

	// MinTradeAmount is the minimum trade size (in USD)
	MinTradeAmount float64 `json:"min_trade_amount"`

	// MaxTradePercent is the maximum percentage of balance per trade
	MaxTradePercent int `json:"max_trade_percent"`

	// AutoTrade enables automatic trade execution without confirmation
	AutoTrade bool `json:"auto_trade"`

	// NotifyDeposits enables notifications for high-value deposits
	NotifyDeposits bool `json:"notify_deposits"`

	// NotifyTrades enables notifications for detected trades
	NotifyTrades bool `json:"notify_trades"`
}

// DefaultSettings returns the default user settings
func DefaultSettings() UserSettings {
	return UserSettings{
		MinDepositAmount:  50000, // $10,000
		SlippageTolerance: 3.0,   // 3%
		MinTradeAmount:    1.0,   // $1
		MaxTradePercent:   100,   // 100% of balance
		AutoTrade:         false, // Require confirmation
		NotifyDeposits:    true,
		NotifyTrades:      true,
	}
}

// User represents a Telegram user in the database
type User struct {
	// TelegramID is the unique Telegram user identifier (primary key)
	TelegramID int64 `json:"telegram_id"`

	// Username is the Telegram username (without @)
	Username string `json:"username"`

	// Salt is the unique salt for key derivation (32 bytes)
	Salt []byte `json:"salt"`

	// EncryptedCredentials is the AES-256-GCM encrypted credentials blob
	EncryptedCredentials string `json:"encrypted_credentials"`

	// Settings contains non-sensitive user preferences (stored as JSON)
	Settings UserSettings `json:"settings"`

	// IsActive indicates if the user's account is active
	IsActive bool `json:"is_active"`

	// CreatedAt is when the user registered
	CreatedAt time.Time `json:"created_at"`

	// UpdatedAt is when the user record was last updated
	UpdatedAt time.Time `json:"updated_at"`

	// LastActiveAt is when the user was last active
	LastActiveAt time.Time `json:"last_active_at"`
}

// TradeStatus represents the status of a trade
type TradeStatus string

const (
	TradeStatusPending   TradeStatus = "PENDING"
	TradeStatusExecuting TradeStatus = "EXECUTING"
	TradeStatusSuccess   TradeStatus = "SUCCESS"
	TradeStatusFailed    TradeStatus = "FAILED"
	TradeStatusSkipped   TradeStatus = "SKIPPED"
)

// TradeSide represents the side of a trade
type TradeSide string

const (
	TradeSideBuy  TradeSide = "BUY"
	TradeSideSell TradeSide = "SELL"
)

// TradeOutcome represents the outcome being traded
type TradeOutcome string

const (
	TradeOutcomeYes TradeOutcome = "YES"
	TradeOutcomeNo  TradeOutcome = "NO"
)

// Trade represents a trade executed by the bot
type Trade struct {
	// ID is the unique trade identifier
	ID int64 `json:"id"`

	// TelegramID is the user who executed the trade
	TelegramID int64 `json:"telegram_id"`

	// TokenID is the Polymarket token ID
	TokenID string `json:"token_id"`

	// MarketQuestion is the market question/title
	MarketQuestion string `json:"market_question"`

	// Side is BUY or SELL
	Side TradeSide `json:"side"`

	// Outcome is YES or NO
	Outcome TradeOutcome `json:"outcome"`

	// Price is the price per share
	Price float64 `json:"price"`

	// AmountUSD is the total USD amount spent/received
	AmountUSD float64 `json:"amount_usd"`

	// Shares is the number of shares bought/sold
	Shares float64 `json:"shares"`

	// Status is the trade execution status
	Status TradeStatus `json:"status"`

	// ErrorMessage contains error details if Status is FAILED
	ErrorMessage string `json:"error_message,omitempty"`

	// InsiderAddress is the address that triggered the signal
	InsiderAddress string `json:"insider_address"`

	// InsiderAmount is the amount the insider traded
	InsiderAmount float64 `json:"insider_amount"`

	// OrderID is the Polymarket order ID (if successful)
	OrderID string `json:"order_id,omitempty"`

	// TransactionHash is the on-chain transaction hash (if applicable)
	TransactionHash string `json:"transaction_hash,omitempty"`

	// ExecutedAt is when the trade was executed
	ExecutedAt time.Time `json:"executed_at"`
}

// AuditAction represents the type of audited action
type AuditAction string

const (
	AuditActionRegister       AuditAction = "REGISTER"
	AuditActionLogin          AuditAction = "LOGIN"
	AuditActionLogout         AuditAction = "LOGOUT"
	AuditActionLoginFailed    AuditAction = "LOGIN_FAILED"
	AuditActionSettingsUpdate AuditAction = "SETTINGS_UPDATE"
	AuditActionTradeExecuted  AuditAction = "TRADE_EXECUTED"
	AuditActionTradeFailed    AuditAction = "TRADE_FAILED"
	AuditActionMonitorStart   AuditAction = "MONITOR_START"
	AuditActionMonitorStop    AuditAction = "MONITOR_STOP"
	AuditActionAccountDelete  AuditAction = "ACCOUNT_DELETE"
	AuditActionPasswordChange AuditAction = "PASSWORD_CHANGE"
)

// AuditLog represents an audit log entry
type AuditLog struct {
	// ID is the unique log identifier
	ID int64 `json:"id"`

	// TelegramID is the user who performed the action (0 for system)
	TelegramID int64 `json:"telegram_id"`

	// Action is the type of action performed
	Action AuditAction `json:"action"`

	// Success indicates if the action was successful
	Success bool `json:"success"`

	// Details contains additional context (no sensitive data!)
	Details map[string]interface{} `json:"details,omitempty"`

	// IPAddress is the IP address (if available, for security alerts)
	IPAddress string `json:"ip_address,omitempty"`

	// CreatedAt is when the action occurred
	CreatedAt time.Time `json:"created_at"`
}

// DepositSignal represents a detected high-value deposit
type DepositSignal struct {
	// ID is the unique signal identifier
	ID int64 `json:"id"`

	// Address is the Polymarket proxy wallet that received the deposit
	Address string `json:"address"`

	// Amount is the deposit amount in USD
	Amount float64 `json:"amount"`

	// TransactionHash is the deposit transaction hash
	TransactionHash string `json:"transaction_hash"`

	// BlockNumber is the block containing the deposit
	BlockNumber uint64 `json:"block_number"`

	// DetectedAt is when the deposit was detected
	DetectedAt time.Time `json:"detected_at"`

	// TradesDetected is the number of trades detected from this address
	TradesDetected int `json:"trades_detected"`
}
