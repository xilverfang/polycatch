package analyst

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum/crypto"

	"github.com/polywatch/internal/config"
	"github.com/polywatch/internal/ipc"
	"github.com/polywatch/internal/types"
	"github.com/polywatch/internal/utils"
)

// WatchedAddress tracks an address we're monitoring for trades
type WatchedAddress struct {
	Address       string
	Deposit       *types.Deposit
	LastChecked   time.Time
	AddedAt       time.Time
	SeenPositions map[string]bool // Track positions we've already seen (by token ID)
}

// Analyst identifies insider trading activity by analyzing orders
type Analyst struct {
	config         *config.Config
	client         *http.Client
	depositsCh     <-chan *types.Deposit
	tradeSignalsCh chan *types.TradeSignal
	errorsCh       chan error
	stopCh         chan struct{}
	watchlist      map[string]*WatchedAddress // Address -> WatchedAddress
	running        bool
	ipcWriter      *ipc.Writer // IPC writer for sending signals to executor
	signerAddress  string      // Signer address derived from private key (for L2 auth)
}

// New creates a new Analyst instance
func New(cfg *config.Config, depositsCh <-chan *types.Deposit) (*Analyst, error) {
	if cfg == nil {
		return nil, errors.New("config cannot be nil")
	}
	if depositsCh == nil {
		return nil, errors.New("deposits channel cannot be nil")
	}

	// Create HTTP client with connection reuse and timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			MaxIdleConns:        10,
			MaxIdleConnsPerHost: 5,
			IdleConnTimeout:     30 * time.Second,
		},
	}

	// Initialize IPC writer for sending signals to executor via Unix socket
	socketPath, err := ipc.EnsureSocketDir(ipc.GetDefaultSocketPath())
	if err != nil {
		return nil, fmt.Errorf("failed to ensure socket directory: %w", err)
	}
	ipcWriter := ipc.NewWriter(socketPath)

	// Derive signer address from private key for L2 authentication
	var signerAddress string
	if cfg.SignerPrivateKey != "" {
		privateKey, err := crypto.HexToECDSA(strings.TrimPrefix(cfg.SignerPrivateKey, "0x"))
		if err == nil {
			publicKey := crypto.PubkeyToAddress(privateKey.PublicKey)
			signerAddress = publicKey.Hex()
		}
	}

	return &Analyst{
		config:         cfg,
		client:         client,
		depositsCh:     depositsCh,
		tradeSignalsCh: make(chan *types.TradeSignal, 50), // Buffered channel
		errorsCh:       make(chan error, 10),
		stopCh:         make(chan struct{}),
		watchlist:      make(map[string]*WatchedAddress),
		running:        false,
		ipcWriter:      ipcWriter,
		signerAddress:  signerAddress,
	}, nil
}

// TradeSignals returns the channel that emits TradeSignal
func (a *Analyst) TradeSignals() <-chan *types.TradeSignal {
	return a.tradeSignalsCh
}

// Errors returns the channel that emits errors
func (a *Analyst) Errors() <-chan error {
	return a.errorsCh
}

// Start begins analyzing deposits and identifying insider orders
// This should be run in a goroutine (G2 from specs)
func (a *Analyst) Start(ctx context.Context) error {
	if a.running {
		return errors.New("analyst is already running")
	}
	a.running = true

	// Start IPC writer server (waits for executor to connect)
	go func() {
		if err := a.ipcWriter.Start(); err != nil {
			a.errorsCh <- fmt.Errorf("IPC writer failed: %w", err)
		}
	}()

	// Start processing deposits
	go a.processDeposits(ctx)

	// Start ticker-based watchlist checker (G2 from specs)
	go a.watchlistChecker(ctx)

	return nil
}

// Stop stops the analyst
func (a *Analyst) Stop() {
	if !a.running {
		return
	}
	close(a.stopCh)
	a.running = false
	close(a.tradeSignalsCh)
	close(a.errorsCh)
}

// processDeposits processes deposit signals and analyzes insider orders
func (a *Analyst) processDeposits(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case deposit, ok := <-a.depositsCh:
			if !ok {
				return // Channel closed
			}
			// Analyze deposit immediately
			if err := a.analyzeDeposit(ctx, deposit); err != nil {
				a.errorsCh <- fmt.Errorf("error analyzing deposit: %w", err)
			}
		}
	}
}

// analyzeDeposit analyzes a deposit to identify insider trading activity
func (a *Analyst) analyzeDeposit(ctx context.Context, deposit *types.Deposit) error {
	// First, verify this is actually a Polymarket address
	// We do this by checking if the address has any Polymarket activity
	// If it's a new address with no activity, we'll still monitor it (it might be a new Polymarket user)
	// But we'll skip addresses that we can't verify are Polymarket-related

	// Fetch current positions to verify it's a Polymarket address
	orders, err := a.fetchOrders(ctx, deposit.FunderAddress)
	if err != nil {
		// If API call fails, we can't verify - skip this address silently
		return fmt.Errorf("failed to verify Polymarket address: %w", err)
	}

	// Add address to watchlist (establishes baseline of existing positions)
	a.addToWatchlist(deposit)

	// Get watchlist entry (should exist since addToWatchlist was called)
	normalizedAddr := strings.ToLower(deposit.FunderAddress)
	watched, exists := a.watchlist[normalizedAddr]
	if !exists {
		return fmt.Errorf("address not in watchlist: %s", deposit.FunderAddress)
	}

	// Filter for NEW positions only (not in baseline snapshot)
	// The baseline snapshot in addToWatchlist marked all existing positions as seen
	// So any position not in SeenPositions is NEW (opened after deposit)
	var newOrders []*types.Order
	for _, order := range orders {
		// Only process active positions (not ended)
		if !order.IsOpen() {
			continue
		}

		// Check if this is a new position (not in baseline snapshot)
		if !watched.SeenPositions[order.TokenID] {
			newOrders = append(newOrders, order)
		}
	}

	// Process each new order and create trade signals
	// Only display and process NEW trades (opened after deposit)
	for _, order := range newOrders {
		// Mark as seen to avoid duplicate alerts
		watched.SeenPositions[order.TokenID] = true

		// Display trade details in clean table format
		a.displayTradeDetails(deposit, order)

		// Create and send trade signal (fetches price from CLOB API)
		tradeSignal := a.createTradeSignal(ctx, deposit, order)
		if tradeSignal != nil && tradeSignal.IsValid() {
			// Send to channel (for in-process communication)
			select {
			case a.tradeSignalsCh <- tradeSignal:
			case <-ctx.Done():
				return ctx.Err()
			case <-a.stopCh:
				return nil
			default:
				// Channel full, log error but continue
				a.errorsCh <- errors.New("trade signals channel is full, dropping signal")
			}

			// Also send via IPC socket (for inter-process communication)
			if a.ipcWriter != nil && a.ipcWriter.IsConnected() {
				if err := a.ipcWriter.WriteSignal(tradeSignal); err != nil {
					// Log error but don't fail - executor might not be running
					log.Printf("WARNING | Analyst: Failed to write signal to IPC: %v", err)
				}
			}
		}
	}

	return nil
}

// addToWatchlist adds an address to the watchlist for periodic checking
// It also establishes a baseline of existing positions to avoid alerting on old positions
func (a *Analyst) addToWatchlist(deposit *types.Deposit) {
	normalizedAddr := strings.ToLower(deposit.FunderAddress)
	if _, exists := a.watchlist[normalizedAddr]; !exists {
		watched := &WatchedAddress{
			Address:       deposit.FunderAddress,
			Deposit:       deposit,
			LastChecked:   time.Now(),
			AddedAt:       time.Now(),
			SeenPositions: make(map[string]bool),
		}

		// Establish baseline: fetch current positions and mark them all as "seen"
		// This ensures we only alert on NEW positions opened AFTER the deposit
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		existingOrders, err := a.fetchOrders(ctx, deposit.FunderAddress)
		if err == nil {
			// Mark all existing positions as already seen
			for _, order := range existingOrders {
				if order.TokenID != "" {
					watched.SeenPositions[order.TokenID] = true
				}
			}
		}

		a.watchlist[normalizedAddr] = watched
	}
}

// watchlistChecker periodically checks watched addresses for new orders (G2 goroutine)
func (a *Analyst) watchlistChecker(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second) // Check every 10 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-a.stopCh:
			return
		case <-ticker.C:
			a.checkWatchlist(ctx)
		}
	}
}

// checkWatchlist checks all watched addresses for new orders
func (a *Analyst) checkWatchlist(ctx context.Context) {
	for addr, watched := range a.watchlist {
		// Skip if checked recently (within last 5 seconds)
		if time.Since(watched.LastChecked) < 5*time.Second {
			continue
		}

		// Check for new orders
		orders, err := a.fetchOrders(ctx, watched.Address)
		if err != nil {
			// If API call fails repeatedly, we might want to remove from watchlist
			// For now, just log and continue
			a.errorsCh <- fmt.Errorf("error checking watchlist address %s: %w", addr, err)
			continue
		}

		// If address has no positions after multiple checks and it's been a while,
		// it might not be a Polymarket address - we could remove it to save API calls
		// But for now, we'll keep monitoring in case it's a new user
		if len(orders) == 0 && time.Since(watched.AddedAt) > 10*time.Minute {
			// After 10 minutes with no positions, likely not a Polymarket address
			// Remove from watchlist to save API calls
			headers := []string{"Status", "Address", "Duration", "Action"}
			rows := [][]string{
				{
					"REMOVED",
					watched.Address,
					utils.FormatDuration(time.Since(watched.AddedAt)),
					"No positions found - not a Polymarket address",
				},
			}
			log.Print(utils.FormatTable(headers, rows))
			delete(a.watchlist, addr)
			continue
		}

		// Filter for orders placed after the deposit
		recentOrders := a.filterOrdersAfterDeposit(orders, watched.Deposit)

		// Process new orders (only ones we haven't seen before - opened after deposit)
		for _, order := range recentOrders {
			// Check if we've already seen this position
			if watched.SeenPositions[order.TokenID] {
				continue // Skip positions we've already processed
			}

			// Mark as seen
			watched.SeenPositions[order.TokenID] = true

			// Display trade details in clean table format (only NEW trades)
			a.displayTradeDetails(watched.Deposit, order)

			// Create and send trade signal (fetches price from CLOB API)
			tradeSignal := a.createTradeSignal(ctx, watched.Deposit, order)
			if tradeSignal != nil && tradeSignal.IsValid() {
				// Send to channel (for in-process communication)
				select {
				case a.tradeSignalsCh <- tradeSignal:
				case <-ctx.Done():
					return
				case <-a.stopCh:
					return
				default:
					a.errorsCh <- errors.New("trade signals channel is full, dropping signal")
				}

				// Also send via IPC socket (for inter-process communication)
				if a.ipcWriter != nil && a.ipcWriter.IsConnected() {
					if err := a.ipcWriter.WriteSignal(tradeSignal); err != nil {
						// Log error but don't fail - executor might not be running
						log.Printf("WARNING | Analyst: Failed to write signal to IPC: %v", err)
					}
				}
			}
		}

		watched.LastChecked = time.Now()

		// Remove from watchlist if older than 1 hour (to prevent memory leak)
		if time.Since(watched.AddedAt) > 1*time.Hour {
			delete(a.watchlist, addr)
		}
	}
}

// filterOrdersAfterDeposit filters orders/positions placed after the deposit timestamp
// Since Data API doesn't provide creation timestamps, we rely on the baseline snapshot
// approach: positions not in SeenPositions are considered new (opened after deposit)
func (a *Analyst) filterOrdersAfterDeposit(orders []*types.Order, deposit *types.Deposit) []*types.Order {
	var recentOrders []*types.Order

	for _, order := range orders {
		// Only include active positions (not ended)
		if !order.IsOpen() {
			continue
		}

		// If we have CreatedAt timestamp, use it for precise filtering
		if !order.CreatedAt.IsZero() {
			// Order must be placed after the deposit
			if order.CreatedAt.After(deposit.Timestamp) {
				// Check if within reasonable time window (e.g., 5 minutes)
				timeDiff := order.CreatedAt.Sub(deposit.Timestamp)
				if timeDiff <= 5*time.Minute {
					recentOrders = append(recentOrders, order)
				}
			}
			continue
		}

		// For positions without CreatedAt (Data API positions):
		// We rely on the baseline snapshot approach - positions not in SeenPositions
		// are considered new. The checkWatchlist function will handle this.
		// For now, include all active positions and let the SeenPositions check filter them
		recentOrders = append(recentOrders, order)
	}

	return recentOrders
}

// isPositionActive checks if a position is currently active (not ended)
// Uses endDate from the Data API response
func (a *Analyst) isPositionActive(endDateStr string) bool {
	if endDateStr == "" {
		return true // No end date means it's active
	}

	endDate := parseTime(endDateStr)
	if endDate.IsZero() {
		return true // Can't parse, assume active
	}

	// Position is active if endDate is in the future
	return endDate.After(time.Now())
}

// displayTradeDetails displays detailed trade information in table format
func (a *Analyst) displayTradeDetails(deposit *types.Deposit, order *types.Order) {
	dollarAmount := deposit.ToDollarAmount()
	dollarStr, _ := dollarAmount.Float64()

	// Parse price to show as percentage
	priceFloat, _ := strconv.ParseFloat(order.Price, 64)
	pricePercent := priceFloat * 100

	// Determine choice (Yes/No) based on token ID pattern
	choice := a.determineChoice(order.TokenID)

	// Format as table
	headers := []string{"Type", "Address", "Side", "Choice", "Price", "Size", "Token ID", "Status", "Deposit"}
	rows := [][]string{
		{
			"TRADE DETECTED",
			deposit.FunderAddress,
			string(order.Side),
			choice,
			fmt.Sprintf("$%.4f (%.2f%%)", priceFloat, pricePercent),
			fmt.Sprintf("%s shares", order.Size),
			order.TokenID,
			string(order.Status),
			fmt.Sprintf("$%.2f", dollarStr),
		},
	}
	log.Print(utils.FormatTable(headers, rows))
}

// determineChoice attempts to determine if the trade is for Yes or No
// This is a simplified version - in production, you'd query the market API
func (a *Analyst) determineChoice(tokenID string) string {
	// Polymarket token IDs for binary markets typically have patterns
	// This is a heuristic - for accurate results, query the Gamma API for market data
	// For now, return "UNKNOWN" - this can be enhanced with market API integration
	return "UNKNOWN (query market API for Yes/No)"
}

// fetchOrders queries the Data API for trades from a specific user address
// The Data API /trades endpoint accepts a user address parameter
func (a *Analyst) fetchOrders(ctx context.Context, makerAddress string) ([]*types.Order, error) {
	// Use Data API: GET /trades?user={address}
	// This returns trades/orders for a specific user address
	url := fmt.Sprintf("%s/trades?user=%s", a.config.DataAPIURL, makerAddress)

	return a.tryFetchOrders(ctx, url)
}

// tryFetchOrders attempts to fetch orders from a specific URL
func (a *Analyst) tryFetchOrders(ctx context.Context, url string) ([]*types.Order, error) {
	// Create request with context
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	// Set headers
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "polywatch/1.0")

	// Make request
	resp, err := a.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		bodyStr := string(body)
		if bodyStr == "" {
			bodyStr = "(empty response)"
		}
		return nil, fmt.Errorf("API returned status %d: %s | URL: %s", resp.StatusCode, bodyStr, url)
	}

	// Read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	// Parse response - Data API returns trades/positions as an array
	var dataTrades []DataAPITradeResponse
	if err := json.Unmarshal(bodyBytes, &dataTrades); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w (body: %s)", err, string(bodyBytes))
	}

	// Convert Data API trades to internal Order types
	orders := make([]*types.Order, 0, len(dataTrades))
	for _, trade := range dataTrades {
		order := a.convertDataAPITrade(trade)
		if order != nil {
			orders = append(orders, order)
		}
	}

	return orders, nil
}

// filterRecentOrders filters orders placed within the specified duration of the deposit
func (a *Analyst) filterRecentOrders(orders []*types.Order, deposit *types.Deposit, within time.Duration) []*types.Order {
	var recentOrders []*types.Order

	for _, order := range orders {
		// Check if order was created within the time window
		if order.CreatedAt.IsZero() {
			continue
		}

		// Calculate time difference
		timeDiff := order.CreatedAt.Sub(deposit.Timestamp)
		if timeDiff < 0 {
			timeDiff = -timeDiff // Absolute value
		}

		// Check if within time window
		if timeDiff <= within {
			recentOrders = append(recentOrders, order)
		}
	}

	return recentOrders
}

// createTradeSignal creates a TradeSignal from a deposit and insider order
// Fetches current price from CLOB API for accurate pricing
func (a *Analyst) createTradeSignal(ctx context.Context, deposit *types.Deposit, insiderOrder *types.Order) *types.TradeSignal {
	// Fetch current price from CLOB API (more accurate than Data API)
	price := insiderOrder.Price // Fallback to order price if CLOB API fails

	if a.config.BuilderAPIKey != "" && a.signerAddress != "" {
		clobPrice, err := a.getPriceFromCLOB(ctx, insiderOrder.TokenID, insiderOrder.Side)
		if err == nil && clobPrice != "" && clobPrice != "0.000000" {
			price = clobPrice
			log.Printf("Price from CLOB API: %s (was: %s)", price, insiderOrder.Price)
		} else {
			// Log warning but continue with order price
			log.Printf("WARNING | Failed to fetch price from CLOB API for token %s: %v, using order price: %s",
				insiderOrder.TokenID, err, insiderOrder.Price)
		}
	}

	// Mirror the insider's trade (buy what they buy, sell what they sell)
	return &types.TradeSignal{
		Deposit:      deposit,
		InsiderOrder: insiderOrder,
		TokenID:      insiderOrder.TokenID,
		Side:         insiderOrder.Side, // Mirror the insider's side
		Price:        price,             // Use CLOB API price if available
		Size:         insiderOrder.Size,
		MaxSlippage:  a.config.SlippageTolerance,
		CreatedAt:    time.Now(),
		ExecutedAt:   nil,
		OrderID:      "",
	}
}

// getPriceFromCLOB fetches the current market price from CLOB API using L2 authentication
func (a *Analyst) getPriceFromCLOB(ctx context.Context, tokenID string, side types.OrderSide) (string, error) {
	path := fmt.Sprintf("/price?token_id=%s&side=%s", tokenID, string(side))
	url := fmt.Sprintf("%s%s", a.config.CLOBAPIURL, path)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}

	// Add L2 authentication headers if credentials are available
	if a.config.BuilderAPIKey != "" && a.config.BuilderSecret != "" && a.signerAddress != "" {
		apiKey := strings.TrimSpace(a.config.BuilderAPIKey)
		apiSecret := strings.TrimSpace(a.config.BuilderSecret)
		apiPassphrase := strings.TrimSpace(a.config.BuilderPassphrase)

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
		req.Header.Set("POLY_ADDRESS", a.signerAddress)
		req.Header.Set("POLY_SIGNATURE", hmacSignature)
		req.Header.Set("POLY_TIMESTAMP", timestamp)
		req.Header.Set("POLY_API_KEY", apiKey)
		req.Header.Set("POLY_PASSPHRASE", apiPassphrase)
	}

	resp, err := a.client.Do(req)
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

// convertDataAPITrade converts a Data API trade/position response to internal Order type
func (a *Analyst) convertDataAPITrade(trade DataAPITradeResponse) *types.Order {
	// Filter out ended positions - only process active ones
	if !a.isPositionActive(trade.EndDate) {
		return nil // Skip ended positions
	}

	// Determine side based on outcome and position
	// If outcome is "Yes" and we have a position, it's likely a BUY
	// This is a heuristic - we'll use the asset/conditionId as token ID
	side := types.OrderSideBuy // Default to BUY for positions
	if trade.NegativeRisk {
		// Negative risk might indicate a SELL position
		side = types.OrderSideSell
	}

	// Use asset as token ID (this is the token identifier for the specific outcome)
	// In Polymarket, each outcome (YES/NO) has a unique token ID
	// The Asset field is the token ID for the specific outcome the trader bought
	tokenID := trade.Asset
	if tokenID == "" {
		// Fallback to conditionId if asset is empty (shouldn't happen normally)
		tokenID = trade.ConditionID
	}

	// Convert price to string (current price or average price)
	// The Data API returns curPrice (current market price) and avgPrice (average entry price)
	// We prefer curPrice as it's the current market price, fallback to avgPrice
	// If both are 0, use 0.000000 (spreads or newly opened positions may have 0 prices initially)
	var price string
	if trade.CurPrice > 0 {
		price = fmt.Sprintf("%.6f", trade.CurPrice)
	} else if trade.AvgPrice > 0 {
		price = fmt.Sprintf("%.6f", trade.AvgPrice)
	} else {
		// Both are 0 - use 0.000000 (still send to executor as it's a fresh trade)
		price = "0.000000"
	}

	// Convert size to string
	size := fmt.Sprintf("%.0f", trade.Size)

	// For positions, we don't have a created timestamp from the API
	// We'll use current time as approximation, but the filtering will
	// check against deposit timestamp in filterOrdersAfterDeposit
	createdAt := time.Now()

	// Determine status based on whether position is active
	status := types.OrderStatusOpen
	if !a.isPositionActive(trade.EndDate) {
		status = types.OrderStatusFilled // Ended positions are considered filled
	}

	return &types.Order{
		TokenID:       tokenID,
		Side:          side,
		Price:         price,
		Size:          size,
		MakerAddress:  trade.ProxyWallet,
		Status:        status,
		OrderID:       "", // Data API doesn't provide order ID
		CreatedAt:     createdAt,
		FilledAt:      nil,
		ChainID:       a.config.ChainID,
		SignatureType: a.config.SignatureType,
		Signature:     "",
	}
}

// convertAPIOrder converts a CLOB API order response to internal Order type
// (Kept for potential future use with CLOB API)
func (a *Analyst) convertAPIOrder(apiOrder CLOBOrderResponse) *types.Order {
	// Parse side
	var side types.OrderSide
	if strings.ToUpper(apiOrder.Side) == "BUY" {
		side = types.OrderSideBuy
	} else if strings.ToUpper(apiOrder.Side) == "SELL" {
		side = types.OrderSideSell
	} else {
		return nil // Invalid side
	}

	// Parse status
	var status types.OrderStatus
	switch strings.ToUpper(apiOrder.Status) {
	case "OPEN":
		status = types.OrderStatusOpen
	case "FILLED":
		status = types.OrderStatusFilled
	case "CANCELLED":
		status = types.OrderStatusCancelled
	case "EXPIRED":
		status = types.OrderStatusExpired
	default:
		status = types.OrderStatusOpen // Default
	}

	// Parse timestamps
	createdAt := parseTime(apiOrder.CreatedAt)
	var filledAt *time.Time
	if apiOrder.FilledAt != "" {
		ft := parseTime(apiOrder.FilledAt)
		if !ft.IsZero() {
			filledAt = &ft
		}
	}

	return &types.Order{
		TokenID:       apiOrder.TokenID,
		Side:          side,
		Price:         apiOrder.Price,
		Size:          apiOrder.Size,
		MakerAddress:  apiOrder.MakerAddress,
		Status:        status,
		OrderID:       apiOrder.OrderID,
		CreatedAt:     createdAt,
		FilledAt:      filledAt,
		ChainID:       a.config.ChainID,
		SignatureType: a.config.SignatureType,
		Signature:     apiOrder.Signature,
	}
}

// DataAPITradeResponse represents the trade/position structure from Polymarket Data API
type DataAPITradeResponse struct {
	ProxyWallet        string  `json:"proxyWallet"`
	Asset              string  `json:"asset"`
	ConditionID        string  `json:"conditionId"`
	Size               float64 `json:"size"`
	AvgPrice           float64 `json:"avgPrice"` // Average entry price
	InitialValue       float64 `json:"initialValue"`
	CurrentValue       float64 `json:"currentValue"`
	CashPnl            float64 `json:"cashPnl"`
	PercentPnl         float64 `json:"percentPnl"`
	TotalBought        float64 `json:"totalBought"`
	RealizedPnl        float64 `json:"realizedPnl"`
	PercentRealizedPnl float64 `json:"percentRealizedPnl"`
	CurPrice           float64 `json:"curPrice"` // Current market price
	Redeemable         bool    `json:"redeemable"`
	Mergeable          bool    `json:"mergeable"`
	Title              string  `json:"title"`
	Slug               string  `json:"slug"`
	Icon               string  `json:"icon"`
	EventSlug          string  `json:"eventSlug"`
	Outcome            string  `json:"outcome"`
	OutcomeIndex       int     `json:"outcomeIndex"`
	OppositeOutcome    string  `json:"oppositeOutcome"`
	OppositeAsset      string  `json:"oppositeAsset"`
	EndDate            string  `json:"endDate"`
	NegativeRisk       bool    `json:"negativeRisk"`
}

// CLOBOrderResponse represents the order structure from Polymarket CLOB API (for order creation)
type CLOBOrderResponse struct {
	OrderID      string `json:"order_id"`
	TokenID      string `json:"token_id"`
	Side         string `json:"side"`
	Price        string `json:"price"`
	Size         string `json:"size"`
	MakerAddress string `json:"maker_address"`
	Status       string `json:"status"`
	CreatedAt    string `json:"created_at"`
	FilledAt     string `json:"filled_at,omitempty"`
	Signature    string `json:"signature,omitempty"`
}

// parseTime parses a time string from the API
// Handles various time formats that might be returned
func parseTime(timeStr string) time.Time {
	if timeStr == "" {
		return time.Time{}
	}

	// Try RFC3339 format first
	if t, err := time.Parse(time.RFC3339, timeStr); err == nil {
		return t
	}

	// Try RFC3339Nano
	if t, err := time.Parse(time.RFC3339Nano, timeStr); err == nil {
		return t
	}

	// Try Unix timestamp (as string)
	// This is a fallback, API should use RFC3339

	return time.Time{} // Return zero time if parsing fails
}
