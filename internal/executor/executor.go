package executor

import (
	"bufio"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"

	"github.com/polywatch/internal/config"
	"github.com/polywatch/internal/ipc"
	"github.com/polywatch/internal/types"
	"github.com/polywatch/internal/utils"
)

// Executor executes trades based on trade signals from the Analyst
type Executor struct {
	config         *config.Config
	client         *ethclient.Client
	tradeSignalsCh <-chan *types.TradeSignal
	errorsCh       chan error
	stopCh         chan struct{}
	running        bool
	httpClient     *http.Client
	ipcReader      *ipc.Reader // IPC reader for receiving signals from monitor
	useIPC         bool        // Whether to use IPC instead of channel
	signerAddress  string      // Signer address derived from private key
}

// New creates a new Executor instance
func New(cfg *config.Config) (*Executor, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}

	// Validate executor-specific requirements
	if cfg.FunderAddress == "" {
		return nil, errors.New("FUNDER_ADDRESS is required for executor")
	}
	if cfg.SignerPrivateKey == "" {
		return nil, errors.New("SIGNER_PRIVATE_KEY is required for executor")
	}

	// Validate Builder API credentials
	if strings.TrimSpace(cfg.BuilderAPIKey) == "" {
		return nil, errors.New("BUILDER_API_KEY is required and cannot be empty")
	}
	if strings.TrimSpace(cfg.BuilderSecret) == "" {
		return nil, errors.New("BUILDER_SECRET is required and cannot be empty")
	}
	if strings.TrimSpace(cfg.BuilderPassphrase) == "" {
		return nil, errors.New("BUILDER_PASSPHRASE is required and cannot be empty")
	}

	// Derive signer address from private key
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.SignerPrivateKey, "0x"))
	if err != nil {
		return nil, fmt.Errorf("invalid private key: %w", err)
	}
	publicKey := crypto.PubkeyToAddress(privateKey.PublicKey)
	signerAddress := publicKey.Hex()

	// Log credential status (without exposing values)
	log.Printf("Executor | API credentials loaded: Key=%d chars, Secret=%d chars, Passphrase=%d chars",
		len(strings.TrimSpace(cfg.BuilderAPIKey)),
		len(strings.TrimSpace(cfg.BuilderSecret)),
		len(strings.TrimSpace(cfg.BuilderPassphrase)))
	log.Printf("Executor | Signer address: %s", signerAddress)

	// Create HTTP client with connection reuse
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     90 * time.Second,
		},
	}

	// Initialize IPC reader for receiving signals from monitor via Unix socket
	socketPath := ipc.GetDefaultSocketPath()
	ipcReader := ipc.NewReader(socketPath)

	return &Executor{
		config:        cfg,
		errorsCh:      make(chan error, 10),
		stopCh:        make(chan struct{}),
		running:       false,
		httpClient:    httpClient,
		ipcReader:     ipcReader,
		useIPC:        false,
		signerAddress: signerAddress,
	}, nil
}

// Start starts the executor goroutine (G3)
// If tradeSignalsCh is nil, executor will use IPC to read signals from monitor
func (e *Executor) Start(ctx context.Context, tradeSignalsCh <-chan *types.TradeSignal) error {
	if e.running {
		return errors.New("executor is already running")
	}

	e.running = true

	// If channel is nil, use IPC mode
	if tradeSignalsCh == nil {
		e.useIPC = true
		log.Println("Executor attempting connection with monitor...")
		// Start IPC reader and connect to socket
		go func() {
			if err := e.ipcReader.Start(); err != nil {
				e.errorsCh <- fmt.Errorf("IPC reader failed to start: %w", err)
				return
			}

			log.Println("Connection established. Waiting for trade signals...")

			// Create internal channel for IPC signals
			ipcSignalCh := make(chan *types.TradeSignal, 100)
			ipcErrorCh := make(chan error, 10)

			// Start reading signals from IPC
			go e.ipcReader.ReadSignals(ipcSignalCh, ipcErrorCh)

			// Handle IPC errors
			go func() {
				for err := range ipcErrorCh {
					e.errorsCh <- err
				}
			}()

			// Start executor worker with IPC channel
			e.tradeSignalsCh = ipcSignalCh
			e.executorWorker(ctx)
		}()
	} else {
		// Use provided channel (in-process communication)
		e.useIPC = false
		e.tradeSignalsCh = tradeSignalsCh
		go e.executorWorker(ctx)
	}

	return nil
}

// Stop stops the executor
func (e *Executor) Stop() {
	if !e.running {
		return
	}
	close(e.stopCh)
	if e.useIPC && e.ipcReader != nil {
		if err := e.ipcReader.Stop(); err != nil {
			log.Printf("ERROR | Executor: Failed to stop IPC reader: %v", err)
		}
	}
	e.running = false
}

// Errors returns the channel that emits errors
func (e *Executor) Errors() <-chan error {
	return e.errorsCh
}

// executorWorker processes trade signals and executes orders (G3 goroutine)
func (e *Executor) executorWorker(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-e.stopCh:
			return
		case signal := <-e.tradeSignalsCh:
			if signal == nil {
				continue
			}

			// Validate signal
			if !signal.IsValid() {
				e.errorsCh <- fmt.Errorf("invalid trade signal: missing required fields")
				continue
			}

			// Execute the trade
			if err := e.executeTrade(ctx, signal); err != nil {
				e.errorsCh <- fmt.Errorf("failed to execute trade: %w", err)
				continue
			}
		}
	}
}

// executeTrade executes a trade based on a trade signal
func (e *Executor) executeTrade(ctx context.Context, signal *types.TradeSignal) error {
	log.Println("═══════════════════════════════════════════════════════════")
	log.Printf("EXECUTING TRADE | Token: %s | Side: %s | Price: %s | Size: %s",
		signal.TokenID, signal.Side, signal.Price, signal.Size)

	// 1. Check slippage
	if err := e.checkSlippage(ctx, signal); err != nil {
		return fmt.Errorf("slippage check failed: %w", err)
	}

	// 2. Check balance and scale trade size if needed
	scaledSize, err := e.checkAndScaleBalance(ctx, signal)
	if err != nil {
		return fmt.Errorf("balance check failed: %w", err)
	}

	// Update signal size to scaled amount if it was adjusted
	if scaledSize != signal.Size {
		log.Printf("Trade scaled: Original size: %s → Scaled size: %s (based on available balance)",
			signal.Size, scaledSize)
		signal.Size = scaledSize
	}

	// 3. Generate EIP-712 signature
	signature, err := e.generateSignature(signal)
	if err != nil {
		return fmt.Errorf("failed to generate signature: %w", err)
	}

	// 4. Submit order to CLOB API
	orderID, err := e.submitOrder(ctx, signal, signature)
	if err != nil {
		return fmt.Errorf("failed to submit order: %w", err)
	}

	// Log success
	headers := []string{"Status", "Order ID", "Token ID", "Side", "Price", "Size"}
	rows := [][]string{
		{
			"EXECUTED",
			orderID,
			signal.TokenID,
			string(signal.Side),
			signal.Price,
			signal.Size,
		},
	}
	log.Print(utils.FormatTable(headers, rows))
	log.Println("═══════════════════════════════════════════════════════════")

	return nil
}

// checkSlippage verifies that price hasn't moved beyond tolerance
func (e *Executor) checkSlippage(ctx context.Context, signal *types.TradeSignal) error {
	// Get current market price (requires side parameter for BUY/SELL price)
	currentPrice, err := e.getCurrentPrice(ctx, signal.TokenID, signal.Side)
	if err != nil {
		return fmt.Errorf("failed to get current price: %w", err)
	}

	// Parse prices
	signalPrice, err := strconv.ParseFloat(signal.Price, 64)
	if err != nil {
		return fmt.Errorf("invalid signal price: %w", err)
	}

	// Calculate slippage
	slippage, err := utils.CalculateSlippage(signal.Price, currentPrice)
	if err != nil {
		return fmt.Errorf("failed to calculate slippage: %w", err)
	}

	// Check if slippage exceeds tolerance
	if slippage > float64(signal.MaxSlippage) {
		return fmt.Errorf("slippage %.2f%% exceeds tolerance of %d%% (signal price: %.4f, current: %s)",
			slippage, signal.MaxSlippage, signalPrice, currentPrice)
	}

	log.Printf("Slippage check passed: %.2f%% (tolerance: %d%%)", slippage, signal.MaxSlippage)
	return nil
}

// checkAndScaleBalance verifies balance and scales trade size if needed
// Returns the scaled size (may be smaller than original if balance is insufficient)
func (e *Executor) checkAndScaleBalance(ctx context.Context, signal *types.TradeSignal) (string, error) {
	// Connect to Polygon if not already connected
	if e.client == nil {
		client, err := ethclient.DialContext(ctx, strings.Replace(e.config.PolygonWSSURL, "wss://", "https://", 1))
		if err != nil {
			return "", fmt.Errorf("failed to connect to Polygon: %w", err)
		}
		e.client = client
	}

	// For BUY orders, we need to check USDC balance
	if signal.Side != types.OrderSideBuy {
		// For SELL orders, we check if we have the shares (simplified for now)
		return signal.Size, nil
	}

	// Get USDC.e balance using ERC20 balanceOf
	usdcContract := common.HexToAddress(e.config.USDCContract)
	funderAddr := common.HexToAddress(e.config.FunderAddress)

	// ERC20 balanceOf(address) function signature
	// balanceOf(address) = 0x70a08231
	balanceOfSig := common.Hex2Bytes("70a08231")
	addressParam := common.LeftPadBytes(funderAddr.Bytes(), 32)
	balanceOfData := append(balanceOfSig, addressParam...)

	// Call the contract
	result, err := e.client.CallContract(ctx, ethereum.CallMsg{
		To:   &usdcContract,
		Data: balanceOfData,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("failed to get USDC balance: %w", err)
	}

	balance := new(big.Int).SetBytes(result)

	// Parse order size and price
	sizeFloat, err := strconv.ParseFloat(signal.Size, 64)
	if err != nil {
		return "", fmt.Errorf("invalid size: %w", err)
	}
	priceFloat, err := strconv.ParseFloat(signal.Price, 64)
	if err != nil {
		return "", fmt.Errorf("invalid price: %w", err)
	}

	// Calculate required USDC (size * price, in USDC units with 6 decimals)
	requiredAmount := big.NewInt(int64(sizeFloat * priceFloat * 1_000_000))

	// Calculate max usable balance (based on MaxTradePercent)
	maxUsableBalance := new(big.Int).Div(new(big.Int).Mul(balance, big.NewInt(int64(e.config.MaxTradePercent))), big.NewInt(100))

	// Convert to dollar amounts for logging
	balanceDollars := new(big.Float).Quo(new(big.Float).SetInt(balance), big.NewFloat(1_000_000))
	requiredDollars := new(big.Float).Quo(new(big.Float).SetInt(requiredAmount), big.NewFloat(1_000_000))
	balanceDollarStr, _ := balanceDollars.Float64()
	requiredDollarStr, _ := requiredDollars.Float64()

	// Check if balance is below minimum
	if balance.Cmp(e.config.MinTradeAmount) < 0 {
		balanceDollarStr, _ := balanceDollars.Float64()
		minTradeDollarStr, _ := new(big.Float).Quo(new(big.Float).SetInt(e.config.MinTradeAmount), big.NewFloat(1_000_000)).Float64()
		return "", fmt.Errorf("insufficient balance: have $%.2f, need at least $%.2f (minimum trade amount)",
			balanceDollarStr, minTradeDollarStr)
	}

	// Interactive mode: prompt user for trade amount
	if e.config.InteractiveMode {
		userAmount, err := e.promptTradeAmount(balanceDollarStr, requiredDollarStr, priceFloat)
		if err != nil {
			return "", fmt.Errorf("user input cancelled or invalid: %w", err)
		}

		// Calculate shares from user-entered dollar amount
		// shares = (userAmount / price)
		userAmountUSDC := big.NewInt(int64(userAmount * 1_000_000))
		priceInUSDC := big.NewInt(int64(priceFloat * 1_000_000))
		userShares := new(big.Int).Div(new(big.Int).Mul(userAmountUSDC, big.NewInt(1_000_000)), priceInUSDC)

		// Verify minimum trade amount
		userTradeCost := new(big.Int).Mul(userShares, priceInUSDC)
		userTradeCost.Div(userTradeCost, big.NewInt(1_000_000))
		if userTradeCost.Cmp(e.config.MinTradeAmount) < 0 {
			minTradeDollarStr, _ := new(big.Float).Quo(new(big.Float).SetInt(e.config.MinTradeAmount), big.NewFloat(1_000_000)).Float64()
			return "", fmt.Errorf("entered amount $%.2f is below minimum trade amount $%.2f", userAmount, minTradeDollarStr)
		}

		// Verify user has enough balance
		if userAmountUSDC.Cmp(balance) > 0 {
			return "", fmt.Errorf("entered amount $%.2f exceeds available balance $%.2f", userAmount, balanceDollarStr)
		}

		scaledSize := userShares.String()
		log.Printf("User entered: $%.2f → %s shares at $%.4f", userAmount, scaledSize, priceFloat)
		return scaledSize, nil
	}

	// Auto-scaling mode: scale down if needed
	log.Printf("Balance: $%.2f | Required: $%.2f | Max usable: %d%%",
		balanceDollarStr, requiredDollarStr, e.config.MaxTradePercent)

	// If we have enough balance, use original size
	if maxUsableBalance.Cmp(requiredAmount) >= 0 {
		log.Printf("Balance check passed: sufficient funds available")
		return signal.Size, nil
	}

	// Scale down: calculate how many shares we can buy with available balance
	// shares = (available_balance / price) / 1_000_000
	priceInUSDC := big.NewInt(int64(priceFloat * 1_000_000))
	scaledShares := new(big.Int).Div(new(big.Int).Mul(maxUsableBalance, big.NewInt(1_000_000)), priceInUSDC)

	// Check minimum trade amount
	minTradeCost := new(big.Int).Mul(scaledShares, priceInUSDC)
	minTradeCost.Div(minTradeCost, big.NewInt(1_000_000))

	if minTradeCost.Cmp(e.config.MinTradeAmount) < 0 {
		minTradeCostDollars, _ := new(big.Float).Quo(new(big.Float).SetInt(minTradeCost), big.NewFloat(1_000_000)).Float64()
		minTradeAmountDollars, _ := new(big.Float).Quo(new(big.Float).SetInt(e.config.MinTradeAmount), big.NewFloat(1_000_000)).Float64()
		return "", fmt.Errorf("scaled trade amount ($%.2f) below minimum ($%.2f)",
			minTradeCostDollars, minTradeAmountDollars)
	}

	scaledSize := scaledShares.String()
	scaledDollars := new(big.Float).Quo(new(big.Float).SetInt(minTradeCost), big.NewFloat(1_000_000))
	scaledDollarStr, _ := scaledDollars.Float64()

	log.Printf("Trade scaled down: Original: %s shares ($%.2f) → Scaled: %s shares ($%.2f)",
		signal.Size, requiredDollarStr, scaledSize, scaledDollarStr)

	return scaledSize, nil
}

// promptTradeAmount prompts the user to enter the trade amount in dollars
// Returns the dollar amount entered by the user
func (e *Executor) promptTradeAmount(balance, required, price float64) (float64, error) {
	log.Println("═══════════════════════════════════════════════════════════")
	log.Printf("TRADE SIGNAL RECEIVED")
	log.Printf("  Available Balance: $%.2f", balance)
	log.Printf("  Original Trade Size: $%.2f", required)
	log.Printf("  Price per share: $%.4f", price)
	log.Println("═══════════════════════════════════════════════════════════")
	log.Print("Enter amount to spend (USD, minimum $3) or 'skip' to cancel: ")

	// Create a channel to receive user input
	inputChan := make(chan string, 1)
	errChan := make(chan error, 1)

	// Read input in a goroutine with timeout
	go func() {
		reader := bufio.NewReader(os.Stdin)
		input, err := reader.ReadString('\n')
		if err != nil {
			errChan <- err
			return
		}
		inputChan <- strings.TrimSpace(input)
	}()

	// Wait for input with 30 second timeout
	select {
	case input := <-inputChan:
		// User entered input
		if strings.ToLower(input) == "skip" || strings.ToLower(input) == "cancel" {
			return 0, fmt.Errorf("user cancelled")
		}

		// Parse dollar amount
		amount, err := strconv.ParseFloat(input, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid amount: %w", err)
		}

		if amount < 3.0 {
			return 0, fmt.Errorf("amount must be at least $3.00")
		}

		return amount, nil

	case err := <-errChan:
		return 0, fmt.Errorf("failed to read input: %w", err)

	case <-time.After(30 * time.Second):
		return 0, fmt.Errorf("timeout: no input received within 30 seconds")
	}
}

// generateSignature generates an EIP-712 signature for the order
func (e *Executor) generateSignature(signal *types.TradeSignal) (string, error) {
	// Parse private key
	privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(e.config.SignerPrivateKey, "0x"))
	if err != nil {
		return "", fmt.Errorf("invalid private key: %w", err)
	}

	// EIP-712 domain separator for Polygon
	domain := map[string]interface{}{
		"name":              "Polymarket",
		"version":           "1",
		"chainId":           e.config.ChainID,
		"verifyingContract": "0x0000000000000000000000000000000000000000",
	}

	// Order message
	message := map[string]interface{}{
		"tokenId":       signal.TokenID,
		"side":          string(signal.Side),
		"price":         signal.Price,
		"size":          signal.Size,
		"makerAddress":  e.config.FunderAddress,
		"signatureType": e.config.SignatureType,
	}

	// Generate EIP-712 hash
	hash, err := e.generateEIP712Hash(domain, message)
	if err != nil {
		return "", fmt.Errorf("failed to generate EIP-712 hash: %w", err)
	}

	// Sign hash
	signature, err := crypto.Sign(hash, privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign hash: %w", err)
	}

	// Add recovery ID (v = 27 or 28)
	signature[64] += 27

	return hexutil.Encode(signature), nil
}

// generateEIP712Hash generates EIP-712 compliant hash
// This is a simplified version - full EIP-712 implementation would use proper encoding
func (e *Executor) generateEIP712Hash(domain, message map[string]interface{}) ([]byte, error) {
	// Simplified EIP-712 hash generation
	// In production, use a proper EIP-712 library
	// For now, we'll create a hash from the message components
	messageStr := fmt.Sprintf("%s%s%s%s%s%d",
		message["tokenId"],
		message["side"],
		message["price"],
		message["size"],
		message["makerAddress"],
		message["signatureType"],
	)

	hash := crypto.Keccak256([]byte(messageStr))
	return hash, nil
}

// submitOrder submits an order to the CLOB API
func (e *Executor) submitOrder(ctx context.Context, signal *types.TradeSignal, signature string) (string, error) {
	// Construct order payload
	orderPayload := map[string]interface{}{
		"tokenId":       signal.TokenID,
		"side":          string(signal.Side),
		"price":         signal.Price,
		"size":          signal.Size,
		"makerAddress":  e.config.FunderAddress,
		"signatureType": e.config.SignatureType,
		"signature":     signature,
	}

	payloadBytes, err := json.Marshal(orderPayload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal order: %w", err)
	}

	// Create request
	url := fmt.Sprintf("%s/orders", e.config.CLOBAPIURL)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(string(payloadBytes)))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers with L2 authentication (HMAC-SHA256)
	req.Header.Set("Content-Type", "application/json")

	// Trim whitespace from credentials (common issue when copying from UI)
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)

	// Validate credentials are not empty
	if apiKey == "" {
		return "", fmt.Errorf("BUILDER_API_KEY is empty")
	}
	if apiSecret == "" {
		return "", fmt.Errorf("BUILDER_SECRET is empty")
	}
	if apiPassphrase == "" {
		return "", fmt.Errorf("BUILDER_PASSPHRASE is empty")
	}

	// Generate L2 authentication headers according to Polymarket docs
	// Headers: POLY_ADDRESS, POLY_SIGNATURE (HMAC-SHA256), POLY_TIMESTAMP, POLY_API_KEY, POLY_PASSPHRASE
	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create message for HMAC: method + path + body + timestamp
	path := "/orders"
	body := string(payloadBytes)
	message := fmt.Sprintf("%s%s%s%s", "POST", path, body, timestamp)

	// Generate HMAC-SHA256 signature
	secretBytes, decodeErr := base64.StdEncoding.DecodeString(apiSecret)
	if decodeErr != nil {
		// If not base64, use as-is
		secretBytes = []byte(apiSecret)
	}
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))
	hmacSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Set L2 authentication headers
	req.Header.Set("POLY_ADDRESS", e.signerAddress)
	req.Header.Set("POLY_SIGNATURE", hmacSignature)
	req.Header.Set("POLY_TIMESTAMP", timestamp)
	req.Header.Set("POLY_API_KEY", apiKey)
	req.Header.Set("POLY_PASSPHRASE", apiPassphrase)

	// Execute request
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	// Read response
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	// Check status code
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	// Parse response
	var orderResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &orderResponse); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract order ID
	orderID, ok := orderResponse["orderId"].(string)
	if !ok {
		// Try alternative field names
		if id, ok := orderResponse["id"].(string); ok {
			orderID = id
		} else {
			return "", fmt.Errorf("order ID not found in response: %s", string(bodyBytes))
		}
	}

	return orderID, nil
}

// getCurrentPrice fetches the current market price for a token using CLOB API
// side is required because prices differ for BUY vs SELL orders
// Uses L2 authentication for authenticated requests
func (e *Executor) getCurrentPrice(ctx context.Context, tokenID string, side types.OrderSide) (string, error) {
	// Use CLOB API to get current price (requires side parameter)
	path := fmt.Sprintf("/price?token_id=%s&side=%s", tokenID, string(side))
	url := fmt.Sprintf("%s%s", e.config.CLOBAPIURL, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add L2 authentication headers
	apiKey := strings.TrimSpace(e.config.BuilderAPIKey)
	apiSecret := strings.TrimSpace(e.config.BuilderSecret)
	apiPassphrase := strings.TrimSpace(e.config.BuilderPassphrase)

	timestamp := strconv.FormatInt(time.Now().Unix(), 10)

	// Create message for HMAC: method + path + body + timestamp (body is empty for GET)
	message := fmt.Sprintf("%s%s%s", "GET", path, timestamp)

	// Generate HMAC-SHA256 signature
	secretBytes, decodeErr := base64.StdEncoding.DecodeString(apiSecret)
	if decodeErr != nil {
		// If not base64, use as-is
		secretBytes = []byte(apiSecret)
	}
	mac := hmac.New(sha256.New, secretBytes)
	mac.Write([]byte(message))
	hmacSignature := base64.StdEncoding.EncodeToString(mac.Sum(nil))

	// Set L2 authentication headers
	req.Header.Set("POLY_ADDRESS", e.signerAddress)
	req.Header.Set("POLY_SIGNATURE", hmacSignature)
	req.Header.Set("POLY_TIMESTAMP", timestamp)
	req.Header.Set("POLY_API_KEY", apiKey)
	req.Header.Set("POLY_PASSPHRASE", apiPassphrase)

	resp, err := e.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to execute request: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("API returned status %d: %s", resp.StatusCode, string(bodyBytes))
	}

	var priceResponse map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &priceResponse); err != nil {
		return "", fmt.Errorf("failed to parse response: %w", err)
	}

	// Extract price (adjust based on actual API response structure)
	price, ok := priceResponse["price"].(string)
	if !ok {
		if priceFloat, ok := priceResponse["price"].(float64); ok {
			price = fmt.Sprintf("%.6f", priceFloat)
		} else {
			return "", fmt.Errorf("price not found in response: %s", string(bodyBytes))
		}
	}

	return price, nil
}
