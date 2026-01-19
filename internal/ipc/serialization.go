package ipc

import (
	"fmt"
	"math/big"
	"time"

	"github.com/polycatch/internal/types"
)

// tradeSignalJSON is a JSON-serializable version of TradeSignal
// Handles big.Int and time.Time properly
type tradeSignalJSON struct {
	Deposit      *depositJSON `json:"deposit"`
	InsiderOrder *orderJSON   `json:"insiderOrder"`
	TokenID      string       `json:"tokenId"`
	Side         string       `json:"side"`
	Price        string       `json:"price"`
	Size         string       `json:"size"`
	MaxSlippage  int          `json:"maxSlippage"`
	CreatedAt    string       `json:"createdAt"`  // RFC3339
	ExecutedAt   *string      `json:"executedAt"` // RFC3339 or null
	OrderID      string       `json:"orderId"`
}

type depositJSON struct {
	FunderAddress string `json:"funderAddress"`
	Amount        string `json:"amount"` // big.Int as string
	BlockNumber   uint64 `json:"blockNumber"`
	TxHash        string `json:"txHash"`
	Timestamp     string `json:"timestamp"` // RFC3339
}

type orderJSON struct {
	TokenID       string  `json:"tokenId"`
	Side          string  `json:"side"`
	Price         string  `json:"price"`
	Size          string  `json:"size"`
	MakerAddress  string  `json:"makerAddress"`
	Status        string  `json:"status"`
	OrderID       string  `json:"orderId"`
	CreatedAt     string  `json:"createdAt"` // RFC3339
	FilledAt      *string `json:"filledAt"`  // RFC3339 or null
	ChainID       int64   `json:"chainId"`
	SignatureType int     `json:"signatureType"`
	Signature     string  `json:"signature"`
}

// convertTradeSignalToJSON converts a TradeSignal to JSON-serializable format
func convertTradeSignalToJSON(signal *types.TradeSignal) tradeSignalJSON {
	result := tradeSignalJSON{
		TokenID:     signal.TokenID,
		Side:        string(signal.Side),
		Price:       signal.Price,
		Size:        signal.Size,
		MaxSlippage: signal.MaxSlippage,
		CreatedAt:   signal.CreatedAt.Format(time.RFC3339),
		OrderID:     signal.OrderID,
	}

	// Handle ExecutedAt (nullable)
	if signal.ExecutedAt != nil {
		executedAtStr := signal.ExecutedAt.Format(time.RFC3339)
		result.ExecutedAt = &executedAtStr
	}

	// Convert Deposit
	if signal.Deposit != nil {
		result.Deposit = &depositJSON{
			FunderAddress: signal.Deposit.FunderAddress,
			Amount:        signal.Deposit.Amount.String(),
			BlockNumber:   signal.Deposit.BlockNumber,
			TxHash:        signal.Deposit.TxHash,
			Timestamp:     signal.Deposit.Timestamp.Format(time.RFC3339),
		}
	}

	// Convert InsiderOrder
	if signal.InsiderOrder != nil {
		orderJSON := &orderJSON{
			TokenID:       signal.InsiderOrder.TokenID,
			Side:          string(signal.InsiderOrder.Side),
			Price:         signal.InsiderOrder.Price,
			Size:          signal.InsiderOrder.Size,
			MakerAddress:  signal.InsiderOrder.MakerAddress,
			Status:        string(signal.InsiderOrder.Status),
			OrderID:       signal.InsiderOrder.OrderID,
			CreatedAt:     signal.InsiderOrder.CreatedAt.Format(time.RFC3339),
			ChainID:       signal.InsiderOrder.ChainID,
			SignatureType: signal.InsiderOrder.SignatureType,
			Signature:     signal.InsiderOrder.Signature,
		}

		// Handle FilledAt (nullable)
		if signal.InsiderOrder.FilledAt != nil {
			filledAtStr := signal.InsiderOrder.FilledAt.Format(time.RFC3339)
			orderJSON.FilledAt = &filledAtStr
		}

		result.InsiderOrder = orderJSON
	}

	return result
}

// convertJSONToTradeSignal converts JSON format back to TradeSignal
func convertJSONToTradeSignal(jsonSignal tradeSignalJSON) (*types.TradeSignal, error) {
	signal := &types.TradeSignal{
		TokenID:     jsonSignal.TokenID,
		Side:        types.OrderSide(jsonSignal.Side),
		Price:       jsonSignal.Price,
		Size:        jsonSignal.Size,
		MaxSlippage: jsonSignal.MaxSlippage,
		OrderID:     jsonSignal.OrderID,
	}

	// Parse CreatedAt
	createdAt, err := time.Parse(time.RFC3339, jsonSignal.CreatedAt)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CreatedAt: %w", err)
	}
	signal.CreatedAt = createdAt

	// Parse ExecutedAt (nullable)
	if jsonSignal.ExecutedAt != nil {
		executedAt, err := time.Parse(time.RFC3339, *jsonSignal.ExecutedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse ExecutedAt: %w", err)
		}
		signal.ExecutedAt = &executedAt
	}

	// Convert Deposit
	if jsonSignal.Deposit != nil {
		amount := new(big.Int)
		amount, ok := amount.SetString(jsonSignal.Deposit.Amount, 10)
		if !ok {
			return nil, fmt.Errorf("failed to parse deposit amount: %s", jsonSignal.Deposit.Amount)
		}

		timestamp, err := time.Parse(time.RFC3339, jsonSignal.Deposit.Timestamp)
		if err != nil {
			return nil, fmt.Errorf("failed to parse deposit timestamp: %w", err)
		}

		signal.Deposit = &types.Deposit{
			FunderAddress: jsonSignal.Deposit.FunderAddress,
			Amount:        amount,
			BlockNumber:   jsonSignal.Deposit.BlockNumber,
			TxHash:        jsonSignal.Deposit.TxHash,
			Timestamp:     timestamp,
		}
	}

	// Convert InsiderOrder
	if jsonSignal.InsiderOrder != nil {
		createdAt, err := time.Parse(time.RFC3339, jsonSignal.InsiderOrder.CreatedAt)
		if err != nil {
			return nil, fmt.Errorf("failed to parse order CreatedAt: %w", err)
		}

		order := &types.Order{
			TokenID:       jsonSignal.InsiderOrder.TokenID,
			Side:          types.OrderSide(jsonSignal.InsiderOrder.Side),
			Price:         jsonSignal.InsiderOrder.Price,
			Size:          jsonSignal.InsiderOrder.Size,
			MakerAddress:  jsonSignal.InsiderOrder.MakerAddress,
			Status:        types.OrderStatus(jsonSignal.InsiderOrder.Status),
			OrderID:       jsonSignal.InsiderOrder.OrderID,
			CreatedAt:     createdAt,
			ChainID:       jsonSignal.InsiderOrder.ChainID,
			SignatureType: jsonSignal.InsiderOrder.SignatureType,
			Signature:     jsonSignal.InsiderOrder.Signature,
		}

		// Parse FilledAt (nullable)
		if jsonSignal.InsiderOrder.FilledAt != nil {
			filledAt, err := time.Parse(time.RFC3339, *jsonSignal.InsiderOrder.FilledAt)
			if err != nil {
				return nil, fmt.Errorf("failed to parse order FilledAt: %w", err)
			}
			order.FilledAt = &filledAt
		}

		signal.InsiderOrder = order
	}

	return signal, nil
}
