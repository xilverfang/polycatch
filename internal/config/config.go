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

	// Polymarket Trading Contracts
	CTFContract        string // CTF (ERC1155) conditional tokens contract
	CTFExchange        string // CTF Exchange (regular markets)
	NegRiskCTFExchange string // Neg Risk CTF Exchange (neg risk markets)
	NegRiskAdapter     string // Neg Risk Adapter (helper for neg risk markets)

	// Wallet Configuration
	SignerPrivateKey string
	FunderAddress    string
	SignatureType    int // 0=EOA, 1=POLY_PROXY (email/Google), 2=POLY_GNOSIS_SAFE (browser wallet)

	// Polymarket Builder API Credentials
	BuilderAPIKey     string
	BuilderSecret     string
	BuilderPassphrase string

	// Polymarket CLOB API Credentials (L2 auth)
	CLOBAPIKey        string
	CLOBAPISecret     string
	CLOBAPIPassphrase string

	// Polymarket API Endpoints
	GammaAPIURL string
	DataAPIURL  string
	CLOBAPIURL  string

	// Polymarket Proxy Factory Addresses (for reference)
	// These are the factory contracts that deploy proxy wallets
	GnosisSafeFactory      string // Gnosis Safe factory (type 2) - 0xaacfeea03eb1561c4e67d661e40682bd20e3541b
	PolymarketProxyFactory string // Polymarket Proxy factory (type 1) - 0xaB45c5A4B0c941a2F231C04C3f49182e1A254052

	// Polymarket Relayer Configuration (for proxy/safe approvals)
	RelayerURL             string
	RelayerProxyFactory    string
	RelayerRelayHub        string
	RelayerSafeFactory     string
	RelayerSafeMultisend   string
	RelayerSafeInitCode    string
	RelayerProxyInitCode   string
	RelayerSafeFactoryName string
	RelayerProxyGasLimit   uint64

	// Trading Configuration
	MinDepositAmount  *big.Int // Minimum deposit in USDC.e (wei units, 6 decimals for USDC)
	SlippageTolerance int      // Percentage (e.g., 3 for 3%)
	MaxTradePercent   int      // Maximum percentage of balance to use per trade (0-100, default 100)
	MinTradeAmount    *big.Int // Minimum trade amount in USDC.e (default $1 = 1000000)
	InteractiveMode   bool     // If true, prompt for trade amount instead of auto-scaling
}

// Load reads configuration from environment variables and .env file
func Load() (*Config, error) {
	// Load .env file if it exists
	if err := LoadEnvFile(".env"); err != nil {
		// Don't fail if .env doesn't exist, just log
		// Environment variables can still be set manually
	}
	cfg := &Config{
		PolygonWSSURL:          getEnv("POLYGON_WSS_URL", ""),
		ChainID:                137, // Polygon mainnet
		USDCContract:           "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
		CTFContract:            "0x4d97dcd97ec945f40cf65f87097ace5ea0476045",
		CTFExchange:            "0x4bFb41d5B3570DeFd03C39a9A4D8dE6Bd8B8982E",
		NegRiskCTFExchange:     "0xC5d563A36AE78145C45a50134d48A1215220f80a",
		NegRiskAdapter:         "0xd91E80cF2E7be2e162c6513ceD06f1dD0dA35296",
		SignatureType:          1, // POLY_PROXY (email/Google login) - change to 2 for browser wallet, 0 for EOA
		GammaAPIURL:            "https://gamma-api.polymarket.com",
		DataAPIURL:             "https://data-api.polymarket.com",
		CLOBAPIURL:             "https://clob.polymarket.com",
		GnosisSafeFactory:      "0xaacfeea03eb1561c4e67d661e40682bd20e3541b", // Gnosis Safe factory (type 2)
		PolymarketProxyFactory: "0xaB45c5A4B0c941a2F231C04C3f49182e1A254052", // Polymarket Proxy factory (type 1)
		RelayerURL:             "https://relayer-v2.polymarket.com",
		RelayerProxyFactory:    "0xaB45c5A4B0c941a2F231C04C3f49182e1A254052",
		RelayerRelayHub:        "0xD216153c06E857cD7f72665E0aF1d7D82172F494",
		RelayerSafeFactory:     "0xaacFeEa03eb1561C4e67d661e40682Bd20E3541b",
		RelayerSafeMultisend:   "0xA238CBeb142c10Ef7Ad8442C6D1f9E89e07e7761",
		RelayerSafeInitCode:    "0x2bce2127ff07fb632d16c8347c4ebf501f4841168bed00d9e6ef715ddb6fcecf",
		RelayerProxyInitCode:   "0xd21df8dc65880a8606f09fe0ce3df9b8869287ab0b058be05aa9e8af6330a00b",
		RelayerSafeFactoryName: "Polymarket Contract Proxy Factory",
		RelayerProxyGasLimit:   10_000_000,
		SlippageTolerance:      3, // Default 3%
	}

	// Required fields
	cfg.SignerPrivateKey = getEnv("SIGNER_PRIVATE_KEY", "")
	cfg.FunderAddress = getEnv("FUNDER_ADDRESS", "")
	cfg.BuilderAPIKey = getEnv("BUILDER_API_KEY", "")
	cfg.BuilderSecret = getEnv("BUILDER_SECRET", "")
	cfg.BuilderPassphrase = getEnv("BUILDER_PASSPHRASE", "")
	cfg.CLOBAPIKey = getEnv("CLOB_API_KEY", "")
	cfg.CLOBAPISecret = getEnv("CLOB_API_SECRET", "")
	cfg.CLOBAPIPassphrase = getEnv("CLOB_API_PASSPHRASE", "")
	if signatureTypeStr := getEnv("SIGNATURE_TYPE", ""); signatureTypeStr != "" {
		signatureType, err := strconv.Atoi(signatureTypeStr)
		if err != nil {
			return nil, fmt.Errorf("invalid SIGNATURE_TYPE: %w", err)
		}
		cfg.SignatureType = signatureType
	}
	cfg.RelayerURL = getEnv("RELAYER_URL", cfg.RelayerURL)
	cfg.RelayerProxyFactory = getEnv("RELAYER_PROXY_FACTORY", cfg.RelayerProxyFactory)
	cfg.RelayerRelayHub = getEnv("RELAYER_RELAY_HUB", cfg.RelayerRelayHub)
	cfg.RelayerSafeFactory = getEnv("RELAYER_SAFE_FACTORY", cfg.RelayerSafeFactory)
	cfg.RelayerSafeMultisend = getEnv("RELAYER_SAFE_MULTISEND", cfg.RelayerSafeMultisend)
	cfg.RelayerSafeInitCode = getEnv("RELAYER_SAFE_INIT_CODE", cfg.RelayerSafeInitCode)
	cfg.RelayerProxyInitCode = getEnv("RELAYER_PROXY_INIT_CODE", cfg.RelayerProxyInitCode)
	cfg.RelayerSafeFactoryName = getEnv("RELAYER_SAFE_FACTORY_NAME", cfg.RelayerSafeFactoryName)
	if gasLimitStr := getEnv("RELAYER_PROXY_GAS_LIMIT", ""); gasLimitStr != "" {
		gasLimit, err := strconv.ParseUint(gasLimitStr, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("invalid RELAYER_PROXY_GAS_LIMIT: %w", err)
		}
		cfg.RelayerProxyGasLimit = gasLimit
	}

	// Optional: Minimum deposit amount (default $10,000)
	minDepositStr := getEnv("MIN_DEPOSIT_AMOUNT", "50000")
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

	// Optional: Minimum trade amount (default $1 = 1,000,000 in USDC units)
	minTradeStr := getEnv("MIN_TRADE_AMOUNT", "1")
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

	if c.CLOBAPIKey == "" {
		errs = append(errs, "CLOB_API_KEY is required")
	}
	if c.CLOBAPISecret == "" {
		errs = append(errs, "CLOB_API_SECRET is required")
	}
	if c.CLOBAPIPassphrase == "" {
		errs = append(errs, "CLOB_API_PASSPHRASE is required")
	}

	if !isValidAddress(c.USDCContract) {
		errs = append(errs, "USDCContract must be a valid Ethereum address")
	}
	if !isValidAddress(c.CTFContract) {
		errs = append(errs, "CTFContract must be a valid Ethereum address")
	}
	if !isValidAddress(c.CTFExchange) {
		errs = append(errs, "CTFExchange must be a valid Ethereum address")
	}
	if !isValidAddress(c.NegRiskCTFExchange) {
		errs = append(errs, "NegRiskCTFExchange must be a valid Ethereum address")
	}
	if !isValidAddress(c.NegRiskAdapter) {
		errs = append(errs, "NegRiskAdapter must be a valid Ethereum address")
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

	if c.RelayerURL == "" {
		errs = append(errs, "RelayerURL must be set")
	} else if !strings.HasPrefix(c.RelayerURL, "https://") && !strings.HasPrefix(c.RelayerURL, "http://") {
		errs = append(errs, "RelayerURL must be an HTTP(S) URL")
	}
	if !isValidAddress(c.RelayerProxyFactory) {
		errs = append(errs, "RelayerProxyFactory must be a valid Ethereum address")
	}
	if !isValidAddress(c.RelayerRelayHub) {
		errs = append(errs, "RelayerRelayHub must be a valid Ethereum address")
	}
	if !isValidAddress(c.RelayerSafeFactory) {
		errs = append(errs, "RelayerSafeFactory must be a valid Ethereum address")
	}
	if !isValidAddress(c.RelayerSafeMultisend) {
		errs = append(errs, "RelayerSafeMultisend must be a valid Ethereum address")
	}
	if !isValidHex32(c.RelayerSafeInitCode) {
		errs = append(errs, "RelayerSafeInitCode must be a 32-byte hex string")
	}
	if !isValidHex32(c.RelayerProxyInitCode) {
		errs = append(errs, "RelayerProxyInitCode must be a 32-byte hex string")
	}
	if strings.TrimSpace(c.RelayerSafeFactoryName) == "" {
		errs = append(errs, "RelayerSafeFactoryName must be set")
	}
	if c.RelayerProxyGasLimit == 0 {
		errs = append(errs, "RelayerProxyGasLimit must be greater than 0")
	}

	// SignatureType: 0=EOA, 1=POLY_PROXY (email/Google login), 2=POLY_GNOSIS_SAFE (browser wallet)
	if c.SignatureType < 0 || c.SignatureType > 2 {
		errs = append(errs, "SignatureType must be 0 (EOA), 1 (POLY_PROXY), or 2 (POLY_GNOSIS_SAFE)")
	}

	// Builder keys are only required when submitting relayer approvals.

	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}

	return nil
}

// LoadEnvFile loads environment variables from a .env file.
// Call this at the start of main() to ensure all env vars are available.
func LoadEnvFile(filename string) error {
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

func isValidHex32(value string) bool {
	value = strings.TrimSpace(value)
	if !strings.HasPrefix(value, "0x") {
		return false
	}
	if len(value) != 66 {
		return false
	}
	for _, c := range value[2:] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}
