package utils

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CalculateSlippage calculates the slippage percentage between two prices
// Returns the absolute percentage difference
func CalculateSlippage(originalPrice, currentPrice string) (float64, error) {
	// Parse prices as floats
	orig, err := parsePrice(originalPrice)
	if err != nil {
		return 0, err
	}
	curr, err := parsePrice(currentPrice)
	if err != nil {
		return 0, err
	}

	if orig == 0 {
		return 0, nil
	}

	// Calculate percentage difference
	diff := (curr - orig) / orig * 100
	if diff < 0 {
		diff = -diff // Absolute value
	}
	return diff, nil
}

// parsePrice parses a price string to float64
func parsePrice(priceStr string) (float64, error) {
	// Remove any whitespace
	priceStr = strings.TrimSpace(priceStr)
	if priceStr == "" {
		return 0, nil
	}
	price, err := strconv.ParseFloat(priceStr, 64)
	if err != nil {
		return 0, err
	}
	return price, nil
}

// TruncateAddress truncates an address for display
func TruncateAddress(address string) string {
	if len(address) <= 12 {
		return address
	}
	return address[:10] + "..."
}

// TruncateTxHash truncates a transaction hash for display
func TruncateTxHash(txHash string) string {
	if len(txHash) <= 18 {
		return txHash
	}
	return txHash[:16] + "..."
}

// FormatTable formats data as a table with headers
func FormatTable(headers []string, rows [][]string) string {
	if len(headers) == 0 {
		return ""
	}

	// Calculate column widths
	widths := make([]int, len(headers))
	for i, header := range headers {
		widths[i] = len(header)
	}
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	var builder strings.Builder

	// Header row
	builder.WriteString("\n")
	builder.WriteString("┌")
	for i, width := range widths {
		if i > 0 {
			builder.WriteString("┬")
		}
		builder.WriteString(strings.Repeat("─", width+2))
	}
	builder.WriteString("┐\n")

	builder.WriteString("│")
	for i, header := range headers {
		if i > 0 {
			builder.WriteString(" │")
		}
		builder.WriteString(fmt.Sprintf(" %-*s ", widths[i], header))
	}
	builder.WriteString("│\n")

	// Separator
	builder.WriteString("├")
	for i, width := range widths {
		if i > 0 {
			builder.WriteString("┼")
		}
		builder.WriteString(strings.Repeat("─", width+2))
	}
	builder.WriteString("┤\n")

	// Data rows
	for _, row := range rows {
		builder.WriteString("│")
		for i := 0; i < len(headers); i++ {
			if i > 0 {
				builder.WriteString(" │")
			}
			cell := ""
			if i < len(row) {
				cell = row[i]
			}
			builder.WriteString(fmt.Sprintf(" %-*s ", widths[i], cell))
		}
		builder.WriteString("│\n")
	}

	// Footer
	builder.WriteString("└")
	for i, width := range widths {
		if i > 0 {
			builder.WriteString("┴")
		}
		builder.WriteString(strings.Repeat("─", width+2))
	}
	builder.WriteString("┘\n")

	return builder.String()
}

// FormatTime formats a time for table display
func FormatTime(t time.Time) string {
	return t.Format("15:04:05")
}

// FormatDuration formats a duration for table display
func FormatDuration(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%.0fs", d.Seconds())
	}
	if d < time.Hour {
		return fmt.Sprintf("%.0fm", d.Minutes())
	}
	return fmt.Sprintf("%.1fh", d.Hours())
}
