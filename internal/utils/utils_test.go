package utils

import (
	"testing"
)

func TestCalculateSlippage(t *testing.T) {
	tests := []struct {
		name          string
		originalPrice string
		currentPrice  string
		want          float64
		wantErr       bool
	}{
		{
			name:          "no slippage",
			originalPrice: "0.65",
			currentPrice:  "0.65",
			want:          0.0,
			wantErr:       false,
		},
		{
			name:          "3% slippage increase",
			originalPrice: "0.65",
			currentPrice:  "0.6695", // 0.65 * 1.03
			want:          3.0,
			wantErr:       false,
		},
		{
			name:          "3% slippage decrease",
			originalPrice: "0.65",
			currentPrice:  "0.6305", // 0.65 * 0.97
			want:          3.0,
			wantErr:       false,
		},
		{
			name:          "5% slippage",
			originalPrice: "0.50",
			currentPrice:  "0.525", // 0.50 * 1.05
			want:          5.0,
			wantErr:       false,
		},
		{
			name:          "zero original price",
			originalPrice: "0",
			currentPrice:  "0.65",
			want:          0.0,
			wantErr:       false,
		},
		{
			name:          "invalid original price",
			originalPrice: "invalid",
			currentPrice:  "0.65",
			want:          0.0,
			wantErr:       true,
		},
		{
			name:          "invalid current price",
			originalPrice: "0.65",
			currentPrice:  "invalid",
			want:          0.0,
			wantErr:       true,
		},
		{
			name:          "empty original price",
			originalPrice: "",
			currentPrice:  "0.65",
			want:          0.0,
			wantErr:       false,
		},
		{
			name:          "empty current price",
			originalPrice: "0.65",
			currentPrice:  "",
			want:          0.0,
			wantErr:       false,
		},
		{
			name:          "price with whitespace",
			originalPrice: "  0.65  ",
			currentPrice:  " 0.70 ",
			want:          7.692307692307692,
			wantErr:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := CalculateSlippage(tt.originalPrice, tt.currentPrice)
			if (err != nil) != tt.wantErr {
				t.Errorf("CalculateSlippage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				// Allow small floating point differences
				diff := got - tt.want
				if diff < 0 {
					diff = -diff
				}
				if diff > 0.01 {
					t.Errorf("CalculateSlippage() = %v, want %v", got, tt.want)
				}
			}
		})
	}
}

func TestParsePrice(t *testing.T) {
	tests := []struct {
		name     string
		priceStr string
		want     float64
		wantErr  bool
	}{
		{
			name:     "valid price",
			priceStr: "0.65",
			want:     0.65,
			wantErr:  false,
		},
		{
			name:     "price with whitespace",
			priceStr: "  0.65  ",
			want:     0.65,
			wantErr:  false,
		},
		{
			name:     "empty string",
			priceStr: "",
			want:     0.0,
			wantErr:  false,
		},
		{
			name:     "invalid format",
			priceStr: "invalid",
			want:     0.0,
			wantErr:  true,
		},
		{
			name:     "zero",
			priceStr: "0",
			want:     0.0,
			wantErr:  false,
		},
		{
			name:     "one",
			priceStr: "1",
			want:     1.0,
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parsePrice(tt.priceStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePrice() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("parsePrice() = %v, want %v", got, tt.want)
			}
		})
	}
}
