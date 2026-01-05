package types

import (
	"math/big"
	"time"
)

// Transfer represents a USDC.e transfer event from the blockchain
type Transfer struct {
	// Transfer details
	From  string   // Sender address (0x...)
	To    string   // Recipient address (0x...) - Polymarket Funder/Proxy address
	Value *big.Int // Transfer amount in USDC.e units (6 decimals)

	// Blockchain metadata
	BlockNumber     uint64    // Block number where transfer occurred
	BlockHash       string    // Block hash
	TransactionHash string    // Transaction hash
	LogIndex        uint      // Log index within the transaction
	Timestamp       time.Time // Block timestamp

	// Contract information
	ContractAddress string // USDC.e contract address (0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174)
}

// IsHighValue checks if the transfer amount meets the minimum deposit threshold
// amount is in USDC.e units (6 decimals), threshold is also in USDC.e units
func (t *Transfer) IsHighValue(threshold *big.Int) bool {
	if t.Value == nil || threshold == nil {
		return false
	}
	return t.Value.Cmp(threshold) >= 0
}

// ToDeposit converts a Transfer to a Deposit signal
// This is used when a high-value transfer is detected
func (t *Transfer) ToDeposit() *Deposit {
	return &Deposit{
		FunderAddress: t.To,
		Amount:        t.Value,
		BlockNumber:   t.BlockNumber,
		TxHash:        t.TransactionHash,
		Timestamp:     t.Timestamp,
	}
}

// Deposit represents a high-value deposit signal that triggers market analysis
type Deposit struct {
	FunderAddress string    // The Polymarket Funder/Proxy address that received the deposit
	Amount        *big.Int  // Deposit amount in USDC.e units (6 decimals)
	BlockNumber   uint64    // Block number
	TxHash        string    // Transaction hash
	Timestamp     time.Time // When the deposit occurred
}

// IsRecent checks if the deposit occurred within the specified duration
// Used to filter orders placed within seconds of the deposit
func (d *Deposit) IsRecent(within time.Duration) bool {
	if d.Timestamp.IsZero() {
		return false
	}
	return time.Since(d.Timestamp) <= within
}

// ToDollarAmount converts the deposit amount from USDC.e units to dollar amount
// USDC has 6 decimals, so divide by 10^6
func (d *Deposit) ToDollarAmount() *big.Float {
	if d.Amount == nil {
		return big.NewFloat(0)
	}
	amountFloat := new(big.Float).SetInt(d.Amount)
	divisor := big.NewFloat(1_000_000) // 10^6
	amountFloat.Quo(amountFloat, divisor)
	return amountFloat
}

// OrderSide represents the side of an order (BUY or SELL)
type OrderSide string

const (
	OrderSideBuy  OrderSide = "BUY"
	OrderSideSell OrderSide = "SELL"
)

// OrderStatus represents the status of an order
type OrderStatus string

const (
	OrderStatusOpen      OrderStatus = "OPEN"
	OrderStatusFilled    OrderStatus = "FILLED"
	OrderStatusCancelled OrderStatus = "CANCELLED"
	OrderStatusExpired   OrderStatus = "EXPIRED"
)

// Order represents a Polymarket CLOB API order
type Order struct {
	// Core order fields
	TokenID string    // Token identifier for the outcome share
	Side    OrderSide // BUY or SELL
	Price   string    // Price as a string (e.g., "0.65" for 65% probability)
	Size    string    // Order size as a string

	// Order metadata
	MakerAddress string      // Address that created the order (Funder address)
	Status       OrderStatus // Current order status
	OrderID      string      // Unique order identifier (from API response)
	CreatedAt    time.Time   // When the order was created
	FilledAt     *time.Time  // When the order was filled (nil if not filled)

	// EIP-712 signing fields (for order creation)
	ChainID       int64  // Polygon chain ID (137)
	SignatureType int    // Signature type (2 for POLY_GNOSIS_SAFE)
	Signature     string // EIP-712 signature (hex string with 0x prefix)
}

// IsBuy returns true if the order is a buy order
func (o *Order) IsBuy() bool {
	return o.Side == OrderSideBuy
}

// IsSell returns true if the order is a sell order
func (o *Order) IsSell() bool {
	return o.Side == OrderSideSell
}

// IsFilled returns true if the order has been filled
func (o *Order) IsFilled() bool {
	return o.Status == OrderStatusFilled
}

// IsOpen returns true if the order is still open
func (o *Order) IsOpen() bool {
	return o.Status == OrderStatusOpen
}

// TradeSignal represents a signal to execute a trade based on insider activity
type TradeSignal struct {
	// Source information
	Deposit      *Deposit  // The deposit that triggered this signal
	InsiderOrder *Order    // The insider's order that was detected
	TokenID      string    // Token ID to trade
	Side         OrderSide // BUY or SELL (mirror the insider's trade)

	// Trading parameters
	Price       string // Price to execute at (from insider order or calculated)
	Size        string // Size to trade
	MaxSlippage int    // Maximum slippage tolerance (percentage)

	// Execution metadata
	CreatedAt  time.Time  // When the signal was created
	ExecutedAt *time.Time // When the trade was executed (nil if not executed)
	OrderID    string     // Order ID if executed
}

// IsValid checks if the trade signal has all required fields
func (ts *TradeSignal) IsValid() bool {
	if ts == nil {
		return false
	}
	if ts.Deposit == nil || ts.InsiderOrder == nil {
		return false
	}
	if ts.TokenID == "" || ts.Price == "" || ts.Size == "" {
		return false
	}
	if ts.Side != OrderSideBuy && ts.Side != OrderSideSell {
		return false
	}
	return true
}
