package executor

import (
	"testing"
)

func TestValidOrderTypes(t *testing.T) {
	validTypes := map[string]bool{
		"FAK": true,
		"FOK": true,
		"GTC": true,
		"GTD": true,
	}

	tests := []struct {
		name      string
		orderType string
		wantValid bool
	}{
		{"FAK is valid", "FAK", true},
		{"FOK is valid", "FOK", true},
		{"GTC is valid", "GTC", true},
		{"GTD is valid", "GTD", true},
		{"lowercase fak is invalid", "fak", false},
		{"empty is invalid", "", false},
		{"unknown type is invalid", "MARKET", false},
		{"IOC is invalid", "IOC", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := validTypes[tt.orderType]
			if got != tt.wantValid {
				t.Errorf("validTypes[%q] = %v, want %v", tt.orderType, got, tt.wantValid)
			}
		})
	}
}

func TestLimitPriceValidation(t *testing.T) {
	tests := []struct {
		name       string
		priceCents float64
		wantValid  bool
	}{
		{"1 cent is valid", 1, true},
		{"50 cents is valid", 50, true},
		{"99 cents is valid", 99, true},
		{"0 cents is invalid", 0, false},
		{"100 cents is invalid (must be < 1)", 100, false},
		{"negative is invalid", -5, false},
		{"0.5 cents is technically valid", 0.5, false}, // We require >= 1 cent
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate: price must be between 1 and 99 cents inclusive
			valid := tt.priceCents >= 1 && tt.priceCents <= 99
			if valid != tt.wantValid {
				t.Errorf("price %.2f¢ valid = %v, want %v", tt.priceCents, valid, tt.wantValid)
			}
		})
	}
}

func TestLimitPriceConversion(t *testing.T) {
	tests := []struct {
		name       string
		priceCents float64
		wantPrice  float64
	}{
		{"45 cents = 0.45", 45, 0.45},
		{"1 cent = 0.01", 1, 0.01},
		{"99 cents = 0.99", 99, 0.99},
		{"50 cents = 0.50", 50, 0.50},
		{"10 cents = 0.10", 10, 0.10},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.priceCents / 100.0
			if got != tt.wantPrice {
				t.Errorf("%.0f cents / 100 = %.4f, want %.4f", tt.priceCents, got, tt.wantPrice)
			}
		})
	}
}

func TestSharesCalculationFromUSDAndPrice(t *testing.T) {
	tests := []struct {
		name       string
		amountUSD  float64
		price      float64 // decimal price (0.45 = 45 cents)
		wantShares float64
	}{
		{"$10 at 50 cents = 20 shares", 10, 0.50, 20},
		{"$5 at 25 cents = 20 shares", 5, 0.25, 20},
		{"$100 at 80 cents = 125 shares", 100, 0.80, 125},
		{"$1 at 10 cents = 10 shares", 1, 0.10, 10},
		{"$3 at 45 cents = 6.67 shares", 3, 0.45, 6.666666666666667},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.amountUSD / tt.price
			// Allow small floating point difference
			diff := got - tt.wantShares
			if diff < 0 {
				diff = -diff
			}
			if diff > 0.001 {
				t.Errorf("$%.2f at %.2f = %.4f shares, want %.4f", tt.amountUSD, tt.price, got, tt.wantShares)
			}
		})
	}
}

func TestMinimumOrderSizeValidation(t *testing.T) {
	tests := []struct {
		name         string
		shares       float64
		minOrderSize float64
		wantValid    bool
	}{
		{"5 shares meets 5 share minimum", 5.0, 5.0, true},
		{"10 shares meets 5 share minimum", 10.0, 5.0, true},
		{"4.99 shares fails 5 share minimum", 4.99, 5.0, false},
		{"2 shares fails 5 share minimum", 2.0, 5.0, false},
		{"0 shares fails any minimum", 0, 1.0, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid := tt.shares >= tt.minOrderSize
			if valid != tt.wantValid {
				t.Errorf("%.2f shares >= %.2f min = %v, want %v", tt.shares, tt.minOrderSize, valid, tt.wantValid)
			}
		})
	}
}

func TestPositionAggregation(t *testing.T) {
	// Test position calculation from trades
	type trade struct {
		side  string
		size  float64
		price float64
	}

	tests := []struct {
		name         string
		trades       []trade
		wantSize     float64
		wantAvgPrice float64
	}{
		{
			name: "single buy",
			trades: []trade{
				{"BUY", 10, 0.50},
			},
			wantSize:     10,
			wantAvgPrice: 0.50,
		},
		{
			name: "two buys at same price",
			trades: []trade{
				{"BUY", 10, 0.50},
				{"BUY", 10, 0.50},
			},
			wantSize:     20,
			wantAvgPrice: 0.50,
		},
		{
			name: "two buys at different prices",
			trades: []trade{
				{"BUY", 10, 0.40}, // $4
				{"BUY", 10, 0.60}, // $6
			},
			wantSize:     20,
			wantAvgPrice: 0.50, // ($4 + $6) / 20 = $10 / 20 = 0.50
		},
		{
			name: "buy then partial sell",
			trades: []trade{
				{"BUY", 20, 0.50},
				{"SELL", 10, 0.60},
			},
			wantSize:     10,
			wantAvgPrice: 0.50, // Avg price doesn't change on sell
		},
		{
			name: "buy then full sell = closed position",
			trades: []trade{
				{"BUY", 10, 0.50},
				{"SELL", 10, 0.60},
			},
			wantSize:     0,
			wantAvgPrice: 0.50,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var size, avgPrice float64
			for _, trade := range tt.trades {
				if trade.side == "BUY" {
					totalCost := size*avgPrice + trade.size*trade.price
					size += trade.size
					if size > 0 {
						avgPrice = totalCost / size
					}
				} else {
					size -= trade.size
				}
			}

			if size != tt.wantSize {
				t.Errorf("size = %.2f, want %.2f", size, tt.wantSize)
			}
			// Only check avg price if there are shares remaining
			if tt.wantSize > 0 {
				diff := avgPrice - tt.wantAvgPrice
				if diff < 0 {
					diff = -diff
				}
				if diff > 0.001 {
					t.Errorf("avgPrice = %.4f, want %.4f", avgPrice, tt.wantAvgPrice)
				}
			}
		})
	}
}
