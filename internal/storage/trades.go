package storage

import (
	"context"
	"database/sql"
	"fmt"
	"time"
)

// TradeRepository handles trade data operations
type TradeRepository struct {
	db *Database
}

// NewTradeRepository creates a new trade repository
func NewTradeRepository(db *Database) *TradeRepository {
	return &TradeRepository{db: db}
}

// Create creates a new trade record
func (r *TradeRepository) Create(ctx context.Context, trade *Trade) (int64, error) {
	result, err := r.db.db.ExecContext(ctx, `
		INSERT INTO trades (
			telegram_id, token_id, market_question, side, outcome,
			price, amount_usd, shares, status, error_message,
			insider_address, insider_amount, order_id, transaction_hash, executed_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		trade.TelegramID,
		trade.TokenID,
		trade.MarketQuestion,
		trade.Side,
		trade.Outcome,
		trade.Price,
		trade.AmountUSD,
		trade.Shares,
		trade.Status,
		trade.ErrorMessage,
		trade.InsiderAddress,
		trade.InsiderAmount,
		trade.OrderID,
		trade.TransactionHash,
		trade.ExecutedAt,
	)

	if err != nil {
		return 0, fmt.Errorf("failed to create trade: %w", err)
	}

	id, err := result.LastInsertId()
	if err != nil {
		return 0, fmt.Errorf("failed to get trade ID: %w", err)
	}

	return id, nil
}

// GetByID retrieves a trade by ID
func (r *TradeRepository) GetByID(ctx context.Context, id int64) (*Trade, error) {
	row := r.db.db.QueryRowContext(ctx, `
		SELECT id, telegram_id, token_id, market_question, side, outcome,
			   price, amount_usd, shares, status, error_message,
			   insider_address, insider_amount, order_id, transaction_hash, executed_at
		FROM trades
		WHERE id = ?
	`, id)

	return r.scanTrade(row)
}

// GetByUser retrieves all trades for a user
func (r *TradeRepository) GetByUser(ctx context.Context, telegramID int64, limit, offset int) ([]*Trade, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	rows, err := r.db.db.QueryContext(ctx, `
		SELECT id, telegram_id, token_id, market_question, side, outcome,
			   price, amount_usd, shares, status, error_message,
			   insider_address, insider_amount, order_id, transaction_hash, executed_at
		FROM trades
		WHERE telegram_id = ?
		ORDER BY executed_at DESC
		LIMIT ? OFFSET ?
	`, telegramID, limit, offset)

	if err != nil {
		return nil, fmt.Errorf("failed to get trades: %w", err)
	}
	defer rows.Close()

	return r.scanTrades(rows)
}

// GetRecent retrieves recent trades across all users
func (r *TradeRepository) GetRecent(ctx context.Context, limit int) ([]*Trade, error) {
	if limit <= 0 {
		limit = 20
	}
	if limit > 100 {
		limit = 100
	}

	rows, err := r.db.db.QueryContext(ctx, `
		SELECT id, telegram_id, token_id, market_question, side, outcome,
			   price, amount_usd, shares, status, error_message,
			   insider_address, insider_amount, order_id, transaction_hash, executed_at
		FROM trades
		ORDER BY executed_at DESC
		LIMIT ?
	`, limit)

	if err != nil {
		return nil, fmt.Errorf("failed to get recent trades: %w", err)
	}
	defer rows.Close()

	return r.scanTrades(rows)
}

// GetByInsiderAddress retrieves trades associated with an insider address
func (r *TradeRepository) GetByInsiderAddress(ctx context.Context, address string, limit int) ([]*Trade, error) {
	if limit <= 0 {
		limit = 20
	}

	rows, err := r.db.db.QueryContext(ctx, `
		SELECT id, telegram_id, token_id, market_question, side, outcome,
			   price, amount_usd, shares, status, error_message,
			   insider_address, insider_amount, order_id, transaction_hash, executed_at
		FROM trades
		WHERE insider_address = ?
		ORDER BY executed_at DESC
		LIMIT ?
	`, address, limit)

	if err != nil {
		return nil, fmt.Errorf("failed to get trades by insider: %w", err)
	}
	defer rows.Close()

	return r.scanTrades(rows)
}

// UpdateStatus updates a trade's status
func (r *TradeRepository) UpdateStatus(ctx context.Context, id int64, status TradeStatus, errorMsg string) error {
	_, err := r.db.db.ExecContext(ctx, `
		UPDATE trades SET status = ?, error_message = ? WHERE id = ?
	`, status, errorMsg, id)

	if err != nil {
		return fmt.Errorf("failed to update trade status: %w", err)
	}

	return nil
}

// UpdateOrderID updates a trade's order ID after successful execution
func (r *TradeRepository) UpdateOrderID(ctx context.Context, id int64, orderID string) error {
	_, err := r.db.db.ExecContext(ctx, `
		UPDATE trades SET order_id = ?, status = ? WHERE id = ?
	`, orderID, TradeStatusSuccess, id)

	if err != nil {
		return fmt.Errorf("failed to update order ID: %w", err)
	}

	return nil
}

// GetStats returns trade statistics for a user
func (r *TradeRepository) GetStats(ctx context.Context, telegramID int64) (*TradeStats, error) {
	stats := &TradeStats{}

	// Get counts by status
	rows, err := r.db.db.QueryContext(ctx, `
		SELECT status, COUNT(*), COALESCE(SUM(amount_usd), 0)
		FROM trades
		WHERE telegram_id = ?
		GROUP BY status
	`, telegramID)
	if err != nil {
		return nil, fmt.Errorf("failed to get trade stats: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var status string
		var count int
		var amount float64
		if err := rows.Scan(&status, &count, &amount); err != nil {
			continue
		}

		switch TradeStatus(status) {
		case TradeStatusSuccess:
			stats.SuccessCount = count
			stats.SuccessAmount = amount
		case TradeStatusFailed:
			stats.FailedCount = count
		case TradeStatusSkipped:
			stats.SkippedCount = count
		case TradeStatusPending:
			stats.PendingCount = count
		}
	}

	stats.TotalCount = stats.SuccessCount + stats.FailedCount + stats.SkippedCount + stats.PendingCount

	return stats, nil
}

// GetDailyVolume returns the total trading volume for today
func (r *TradeRepository) GetDailyVolume(ctx context.Context, telegramID int64) (float64, error) {
	today := time.Now().Truncate(24 * time.Hour)

	var volume float64
	err := r.db.db.QueryRowContext(ctx, `
		SELECT COALESCE(SUM(amount_usd), 0)
		FROM trades
		WHERE telegram_id = ? AND status = ? AND executed_at >= ?
	`, telegramID, TradeStatusSuccess, today).Scan(&volume)

	if err != nil {
		return 0, fmt.Errorf("failed to get daily volume: %w", err)
	}

	return volume, nil
}

// scanTrade scans a single trade row
func (r *TradeRepository) scanTrade(row *sql.Row) (*Trade, error) {
	trade := &Trade{}
	var errorMessage sql.NullString
	var orderID sql.NullString
	var txHash sql.NullString

	err := row.Scan(
		&trade.ID,
		&trade.TelegramID,
		&trade.TokenID,
		&trade.MarketQuestion,
		&trade.Side,
		&trade.Outcome,
		&trade.Price,
		&trade.AmountUSD,
		&trade.Shares,
		&trade.Status,
		&errorMessage,
		&trade.InsiderAddress,
		&trade.InsiderAmount,
		&orderID,
		&txHash,
		&trade.ExecutedAt,
	)

	if err == sql.ErrNoRows {
		return nil, ErrTradeNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("failed to scan trade: %w", err)
	}

	if errorMessage.Valid {
		trade.ErrorMessage = errorMessage.String
	}
	if orderID.Valid {
		trade.OrderID = orderID.String
	}
	if txHash.Valid {
		trade.TransactionHash = txHash.String
	}

	return trade, nil
}

// scanTrades scans multiple trade rows
func (r *TradeRepository) scanTrades(rows *sql.Rows) ([]*Trade, error) {
	var trades []*Trade

	for rows.Next() {
		trade := &Trade{}
		var errorMessage sql.NullString
		var orderID sql.NullString
		var txHash sql.NullString

		err := rows.Scan(
			&trade.ID,
			&trade.TelegramID,
			&trade.TokenID,
			&trade.MarketQuestion,
			&trade.Side,
			&trade.Outcome,
			&trade.Price,
			&trade.AmountUSD,
			&trade.Shares,
			&trade.Status,
			&errorMessage,
			&trade.InsiderAddress,
			&trade.InsiderAmount,
			&orderID,
			&txHash,
			&trade.ExecutedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan trade: %w", err)
		}

		if errorMessage.Valid {
			trade.ErrorMessage = errorMessage.String
		}
		if orderID.Valid {
			trade.OrderID = orderID.String
		}
		if txHash.Valid {
			trade.TransactionHash = txHash.String
		}

		trades = append(trades, trade)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating trades: %w", err)
	}

	return trades, nil
}

// TradeStats contains trade statistics
type TradeStats struct {
	TotalCount    int     `json:"total_count"`
	SuccessCount  int     `json:"success_count"`
	FailedCount   int     `json:"failed_count"`
	SkippedCount  int     `json:"skipped_count"`
	PendingCount  int     `json:"pending_count"`
	SuccessAmount float64 `json:"success_amount"`
}
