package storage

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// AuditRepository handles audit log operations
type AuditRepository struct {
	db *Database
}

// NewAuditRepository creates a new audit repository
func NewAuditRepository(db *Database) *AuditRepository {
	return &AuditRepository{db: db}
}

// Log creates a new audit log entry
// IMPORTANT: Never include sensitive data (passwords, keys, secrets) in details
func (r *AuditRepository) Log(ctx context.Context, telegramID int64, action AuditAction, success bool, details map[string]interface{}) error {
	var detailsJSON sql.NullString
	if details != nil {
		// Sanitize details to ensure no sensitive data
		sanitized := sanitizeDetails(details)
		data, err := json.Marshal(sanitized)
		if err == nil {
			detailsJSON = sql.NullString{String: string(data), Valid: true}
		}
	}

	_, err := r.db.db.ExecContext(ctx, `
		INSERT INTO audit_logs (telegram_id, action, success, details, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, telegramID, action, success, detailsJSON, time.Now())

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// LogWithIP creates an audit log entry with IP address
func (r *AuditRepository) LogWithIP(ctx context.Context, telegramID int64, action AuditAction, success bool, details map[string]interface{}, ipAddress string) error {
	var detailsJSON sql.NullString
	if details != nil {
		sanitized := sanitizeDetails(details)
		data, err := json.Marshal(sanitized)
		if err == nil {
			detailsJSON = sql.NullString{String: string(data), Valid: true}
		}
	}

	_, err := r.db.db.ExecContext(ctx, `
		INSERT INTO audit_logs (telegram_id, action, success, details, ip_address, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, telegramID, action, success, detailsJSON, ipAddress, time.Now())

	if err != nil {
		return fmt.Errorf("failed to create audit log: %w", err)
	}

	return nil
}

// GetByUser retrieves audit logs for a user
func (r *AuditRepository) GetByUser(ctx context.Context, telegramID int64, limit, offset int) ([]*AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}
	if limit > 100 {
		limit = 100
	}

	rows, err := r.db.db.QueryContext(ctx, `
		SELECT id, telegram_id, action, success, details, ip_address, created_at
		FROM audit_logs
		WHERE telegram_id = ?
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`, telegramID, limit, offset)

	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs: %w", err)
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// GetByAction retrieves audit logs by action type
func (r *AuditRepository) GetByAction(ctx context.Context, action AuditAction, limit int) ([]*AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := r.db.db.QueryContext(ctx, `
		SELECT id, telegram_id, action, success, details, ip_address, created_at
		FROM audit_logs
		WHERE action = ?
		ORDER BY created_at DESC
		LIMIT ?
	`, action, limit)

	if err != nil {
		return nil, fmt.Errorf("failed to get audit logs by action: %w", err)
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// GetRecent retrieves recent audit logs across all users
func (r *AuditRepository) GetRecent(ctx context.Context, limit int) ([]*AuditLog, error) {
	if limit <= 0 {
		limit = 50
	}

	rows, err := r.db.db.QueryContext(ctx, `
		SELECT id, telegram_id, action, success, details, ip_address, created_at
		FROM audit_logs
		ORDER BY created_at DESC
		LIMIT ?
	`, limit)

	if err != nil {
		return nil, fmt.Errorf("failed to get recent audit logs: %w", err)
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// GetFailedLogins retrieves recent failed login attempts for a user
func (r *AuditRepository) GetFailedLogins(ctx context.Context, telegramID int64, since time.Time) (int, error) {
	var count int
	err := r.db.db.QueryRowContext(ctx, `
		SELECT COUNT(*)
		FROM audit_logs
		WHERE telegram_id = ? AND action = ? AND success = 0 AND created_at >= ?
	`, telegramID, AuditActionLoginFailed, since).Scan(&count)

	if err != nil {
		return 0, fmt.Errorf("failed to count failed logins: %w", err)
	}

	return count, nil
}

// GetSecurityAlerts retrieves suspicious activity for a user
func (r *AuditRepository) GetSecurityAlerts(ctx context.Context, telegramID int64, limit int) ([]*AuditLog, error) {
	if limit <= 0 {
		limit = 20
	}

	// Get failed logins and password changes
	rows, err := r.db.db.QueryContext(ctx, `
		SELECT id, telegram_id, action, success, details, ip_address, created_at
		FROM audit_logs
		WHERE telegram_id = ? AND (action = ? OR action = ? OR (action = ? AND success = 0))
		ORDER BY created_at DESC
		LIMIT ?
	`, telegramID, AuditActionLoginFailed, AuditActionPasswordChange, AuditActionTradeExecuted, limit)

	if err != nil {
		return nil, fmt.Errorf("failed to get security alerts: %w", err)
	}
	defer rows.Close()

	return r.scanAuditLogs(rows)
}

// Cleanup removes old audit logs older than the specified duration
func (r *AuditRepository) Cleanup(ctx context.Context, olderThan time.Duration) (int64, error) {
	cutoff := time.Now().Add(-olderThan)

	result, err := r.db.db.ExecContext(ctx, `
		DELETE FROM audit_logs WHERE created_at < ?
	`, cutoff)

	if err != nil {
		return 0, fmt.Errorf("failed to cleanup audit logs: %w", err)
	}

	rows, _ := result.RowsAffected()
	return rows, nil
}

// scanAuditLogs scans multiple audit log rows
func (r *AuditRepository) scanAuditLogs(rows *sql.Rows) ([]*AuditLog, error) {
	var logs []*AuditLog

	for rows.Next() {
		log := &AuditLog{}
		var telegramID sql.NullInt64
		var detailsJSON sql.NullString
		var ipAddress sql.NullString

		err := rows.Scan(
			&log.ID,
			&telegramID,
			&log.Action,
			&log.Success,
			&detailsJSON,
			&ipAddress,
			&log.CreatedAt,
		)

		if err != nil {
			return nil, fmt.Errorf("failed to scan audit log: %w", err)
		}

		if telegramID.Valid {
			log.TelegramID = telegramID.Int64
		}
		if detailsJSON.Valid {
			json.Unmarshal([]byte(detailsJSON.String), &log.Details)
		}
		if ipAddress.Valid {
			log.IPAddress = ipAddress.String
		}

		logs = append(logs, log)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating audit logs: %w", err)
	}

	return logs, nil
}

// sensitizeDetails removes any potentially sensitive keys from details
func sanitizeDetails(details map[string]interface{}) map[string]interface{} {
	sensitiveKeys := map[string]bool{
		"password":    true,
		"secret":      true,
		"key":         true,
		"private_key": true,
		"api_key":     true,
		"api_secret":  true,
		"passphrase":  true,
		"token":       true,
		"bearer":      true,
		"credential":  true,
		"auth":        true,
	}

	sanitized := make(map[string]interface{})
	for k, v := range details {
		if sensitiveKeys[k] {
			sanitized[k] = "[REDACTED]"
		} else {
			sanitized[k] = v
		}
	}
	return sanitized
}

// Convenience functions for common audit actions

// LogRegister logs a user registration
func (r *AuditRepository) LogRegister(ctx context.Context, telegramID int64, username string) error {
	return r.Log(ctx, telegramID, AuditActionRegister, true, map[string]interface{}{
		"username": username,
	})
}

// LogLogin logs a successful login
func (r *AuditRepository) LogLogin(ctx context.Context, telegramID int64) error {
	return r.Log(ctx, telegramID, AuditActionLogin, true, nil)
}

// LogLoginFailed logs a failed login attempt
func (r *AuditRepository) LogLoginFailed(ctx context.Context, telegramID int64, reason string) error {
	return r.Log(ctx, telegramID, AuditActionLoginFailed, false, map[string]interface{}{
		"reason": reason,
	})
}

// LogLogout logs a logout
func (r *AuditRepository) LogLogout(ctx context.Context, telegramID int64) error {
	return r.Log(ctx, telegramID, AuditActionLogout, true, nil)
}

// LogSettingsUpdate logs a settings update
func (r *AuditRepository) LogSettingsUpdate(ctx context.Context, telegramID int64, changedFields []string) error {
	return r.Log(ctx, telegramID, AuditActionSettingsUpdate, true, map[string]interface{}{
		"changed_fields": changedFields,
	})
}

// LogTradeExecuted logs a successful trade
func (r *AuditRepository) LogTradeExecuted(ctx context.Context, telegramID int64, tradeID int64, amount float64, market string) error {
	return r.Log(ctx, telegramID, AuditActionTradeExecuted, true, map[string]interface{}{
		"trade_id": tradeID,
		"amount":   amount,
		"market":   market,
	})
}

// LogTradeFailed logs a failed trade
func (r *AuditRepository) LogTradeFailed(ctx context.Context, telegramID int64, reason string, market string) error {
	return r.Log(ctx, telegramID, AuditActionTradeFailed, false, map[string]interface{}{
		"reason": reason,
		"market": market,
	})
}

// LogMonitorStart logs starting the monitor
func (r *AuditRepository) LogMonitorStart(ctx context.Context, telegramID int64) error {
	return r.Log(ctx, telegramID, AuditActionMonitorStart, true, nil)
}

// LogMonitorStop logs stopping the monitor
func (r *AuditRepository) LogMonitorStop(ctx context.Context, telegramID int64) error {
	return r.Log(ctx, telegramID, AuditActionMonitorStop, true, nil)
}

// LogAccountDelete logs account deletion
func (r *AuditRepository) LogAccountDelete(ctx context.Context, telegramID int64) error {
	return r.Log(ctx, telegramID, AuditActionAccountDelete, true, nil)
}

// LogPasswordChange logs a password change
func (r *AuditRepository) LogPasswordChange(ctx context.Context, telegramID int64) error {
	return r.Log(ctx, telegramID, AuditActionPasswordChange, true, nil)
}
