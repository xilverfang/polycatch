package config

import (
	"bufio"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
)

// Config holds all configuration for the Polymarket bot
type Config struct {
	// Polygon Network Configuration
	PolygonWSSURL string
	ChainID       int64
	USDCContract  string // USDC.e contract address on Polygon

	// Wallet Configuration
	SignerPrivateKey string
	FunderAddress    string
	SignatureType    int // POLY_GNOSIS_SAFE = 2

	// Polymarket Builder API Credentials
	BuilderAPIKey     string
	BuilderSecret     string
	BuilderPassphrase string

	// Polymarket API Endpoints
	GammaAPIURL string
	DataAPIURL  string
	CLOBAPIURL  string

	// Polymarket Proxy Factory Addresses (for reference)
	// These are the factory contracts that deploy proxy wallets
	GnosisSafeFactory      string // Gnosis Safe factory (type 2) - 0xaacfeea03eb1561c4e67d661e40682bd20e3541b
	PolymarketProxyFactory string // Polymarket Proxy factory (type 1) - 0xaB45c5A4B0c941a2F231C04C3f49182e1A254052

	// Trading Configuration
	MinDepositAmount  *big.Int // Minimum deposit in USDC.e (wei units, 6 decimals for USDC)
	SlippageTolerance int      // Percentage (e.g., 3 for 3%)
	MaxTradePercent   int      // Maximum percentage of balance to use per trade (0-100, default 100)
	MinTradeAmount    *big.Int // Minimum trade amount in USDC.e (default $3 = 3000000)
	InteractiveMode   bool     // If true, prompt for trade amount instead of auto-scaling
}

// Load reads configuration from environment variables and .env file
func Load() (*Config, error) {
	// Load .env file if it exists
	if err := loadEnvFile(".env"); err != nil {
		// Don't fail if .env doesn't exist, just log
		// Environment variables can still be set manually
	}
	cfg := &Config{
		PolygonWSSURL:          getEnv("POLYGON_WSS_URL", ""),
		ChainID:                137, // Polygon mainnet
		USDCContract:           "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
		SignatureType:          2, // POLY_GNOSIS_SAFE
		GammaAPIURL:            "https://gamma-api.polymarket.com",
		DataAPIURL:             "https://data-api.polymarket.com",
		CLOBAPIURL:             "https://clob.polymarket.com",
		GnosisSafeFactory:      "0xaacfeea03eb1561c4e67d661e40682bd20e3541b", // Gnosis Safe factory (type 2)
		PolymarketProxyFactory: "0xaB45c5A4B0c941a2F231C04C3f49182e1A254052", // Polymarket Proxy factory (type 1)
		SlippageTolerance:      3,                                            // Default 3%
	}

	// Required fields
	cfg.SignerPrivateKey = getEnv("SIGNER_PRIVATE_KEY", "")
	cfg.FunderAddress = getEnv("FUNDER_ADDRESS", "")
	cfg.BuilderAPIKey = getEnv("BUILDER_API_KEY", "")
	cfg.BuilderSecret = getEnv("BUILDER_SECRET", "")
	cfg.BuilderPassphrase = getEnv("BUILDER_PASSPHRASE", "")

	// Optional: Minimum deposit amount (default $10,000)
	minDepositStr := getEnv("MIN_DEPOSIT_AMOUNT", "10000")
	minDeposit, err := parseUSDCAmount(minDepositStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MIN_DEPOSIT_AMOUNT: %w", err)
	}
	cfg.MinDepositAmount = minDeposit

	// Optional: Slippage tolerance
	if slippageStr := getEnv("SLIPPAGE_TOLERANCE", ""); slippageStr != "" {
		slippage, err := strconv.Atoi(slippageStr)
		if err != nil {
			return nil, fmt.Errorf("invalid SLIPPAGE_TOLERANCE: %w", err)
		}
		cfg.SlippageTolerance = slippage
	}

	// Optional: Max trade percentage (default 100% - use all available balance)
	maxTradePercentStr := getEnv("MAX_TRADE_PERCENT", "100")
	maxTradePercent, err := strconv.Atoi(maxTradePercentStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MAX_TRADE_PERCENT: %w", err)
	}
	if maxTradePercent < 1 || maxTradePercent > 100 {
		return nil, fmt.Errorf("MAX_TRADE_PERCENT must be between 1 and 100")
	}
	cfg.MaxTradePercent = maxTradePercent

	// Optional: Minimum trade amount (default $3 = 3,000,000 in USDC units)
	minTradeStr := getEnv("MIN_TRADE_AMOUNT", "3")
	minTrade, err := parseUSDCAmount(minTradeStr)
	if err != nil {
		return nil, fmt.Errorf("invalid MIN_TRADE_AMOUNT: %w", err)
	}
	cfg.MinTradeAmount = minTrade

	// Optional: Interactive mode (prompt for trade amount)
	interactiveStr := getEnv("INTERACTIVE_MODE", "true") // Default to true for user control
	cfg.InteractiveMode = strings.ToLower(interactiveStr) == "true" || interactiveStr == "1"

	// Validate configuration
	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return cfg, nil
}

// Validate checks that all required configuration fields are set and valid
func (c *Config) Validate() error {
	var errs []string

	if c.PolygonWSSURL == "" {
		errs = append(errs, "POLYGON_WSS_URL is required")
	} else if !strings.HasPrefix(c.PolygonWSSURL, "wss://") && !strings.HasPrefix(c.PolygonWSSURL, "ws://") {
		errs = append(errs, "POLYGON_WSS_URL must be a WebSocket URL (wss:// or ws://)")
	}

	if c.SignerPrivateKey == "" {
		errs = append(errs, "SIGNER_PRIVATE_KEY is required")
	} else if !strings.HasPrefix(c.SignerPrivateKey, "0x") || len(c.SignerPrivateKey) != 66 {
		errs = append(errs, "SIGNER_PRIVATE_KEY must be a valid hex private key (0x + 64 chars)")
	}

	// FUNDER_ADDRESS is only required for the Executor (your own trading address)
	// The Listener monitors ALL addresses, so this is optional for monitoring
	// But required if you want to execute trades
	if c.FunderAddress != "" && !isValidAddress(c.FunderAddress) {
		errs = append(errs, "FUNDER_ADDRESS must be a valid Ethereum address (0x + 40 chars)")
	}

	if c.BuilderAPIKey == "" {
		errs = append(errs, "BUILDER_API_KEY is required")
	}

	if c.BuilderSecret == "" {
		errs = append(errs, "BUILDER_SECRET is required")
	}

	if c.BuilderPassphrase == "" {
		errs = append(errs, "BUILDER_PASSPHRASE is required")
	}

	if !isValidAddress(c.USDCContract) {
		errs = append(errs, "USDCContract must be a valid Ethereum address")
	}

	if c.MinDepositAmount == nil || c.MinDepositAmount.Sign() <= 0 {
		errs = append(errs, "MIN_DEPOSIT_AMOUNT must be greater than 0")
	}

	if c.SlippageTolerance < 0 || c.SlippageTolerance > 100 {
		errs = append(errs, "SLIPPAGE_TOLERANCE must be between 0 and 100")
	}

	if c.ChainID != 137 {
		errs = append(errs, "ChainID must be 137 (Polygon mainnet)")
	}

	if c.SignatureType != 2 {
		errs = append(errs, "SignatureType must be 2 (POLY_GNOSIS_SAFE)")
	}

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// loadEnvFile loads environment variables from a .env file
func loadEnvFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err // File doesn't exist, which is okay
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse KEY=VALUE format
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue // Skip malformed lines
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		// Remove quotes if present
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') ||
				(value[0] == '\'' && value[len(value)-1] == '\'') {
				value = value[1 : len(value)-1]
			}
		}

		// Only set if not already in environment (env vars take precedence)
		if os.Getenv(key) == "" {
			os.Setenv(key, value)
		}
	}

	return scanner.Err()
}

// getEnv retrieves an environment variable or returns a default value
func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// parseUSDCAmount parses a USDC amount string (in dollars) and converts to wei units
// USDC has 6 decimals, so $10,000 = 10,000 * 10^6 = 10,000,000,000 (10 billion)
func parseUSDCAmount(amountStr string) (*big.Int, error) {
	amountStr = strings.TrimSpace(amountStr)
	if amountStr == "" {
		return nil, errors.New("amount cannot be empty")
	}

	// Parse as float to handle decimal values
	amountFloat, err := strconv.ParseFloat(amountStr, 64)
	if err != nil {
		return nil, fmt.Errorf("invalid amount format: %w", err)
	}

	if amountFloat <= 0 {
		return nil, errors.New("amount must be greater than 0")
	}

	// Convert to USDC units (6 decimals)
	// Multiply by 10^6
	multiplier := big.NewInt(1_000_000)
	amountBig := new(big.Float).SetFloat64(amountFloat)
	amountBig.Mul(amountBig, new(big.Float).SetInt(multiplier))

	// Convert to big.Int (truncate decimals)
	result := new(big.Int)
	amountBig.Int(result)

	return result, nil
}

// isValidAddress checks if a string is a valid Ethereum address format
func isValidAddress(addr string) bool {
	addr = strings.TrimSpace(addr)
	if !strings.HasPrefix(addr, "0x") {
		return false
	}
	if len(addr) != 42 { // 0x + 40 hex chars
		return false
	}
	// Check if remaining characters are valid hex
	for _, c := range addr[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
