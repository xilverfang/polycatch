package executor

import (
	"fmt"
	"math/big"
	"testing"
)

func TestValidateAmountPrecision(t *testing.T) {
	tests := []struct {
		name        string
		microAmount int64
		maxDecimals int
		label       string
		wantErr     bool
	}{
		// 2 decimals = must be divisible by 10000
		{"2 decimals - valid 1.00", 1_000_000, 2, "USDC", false},
		{"2 decimals - valid 0.99", 990_000, 2, "USDC", false},
		{"2 decimals - valid 5.26", 5_260_000, 2, "shares", false},
		{"2 decimals - invalid 0.999", 999_000, 2, "USDC", true},
		{"2 decimals - invalid 0.9994", 999_400, 2, "USDC", true},
		{"2 decimals - invalid 2.439", 2_439_000, 2, "shares", true},

		// 4 decimals = must be divisible by 100
		{"4 decimals - valid 0.9994", 999_400, 4, "USDC", false},
		{"4 decimals - valid 1.0000", 1_000_000, 4, "USDC", false},
		{"4 decimals - invalid 0.99941", 999_410, 4, "USDC", true},

		// 5 decimals = must be divisible by 10
		{"5 decimals - valid 2.43902", 2_439_020, 5, "shares", false},
		{"5 decimals - invalid 2.439021", 2_439_021, 5, "shares", true},

		// 6 decimals = any value is valid
		{"6 decimals - valid anything", 1_234_567, 6, "shares", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateAmountPrecision(tt.microAmount, tt.maxDecimals, tt.label)
			if (err != nil) != tt.wantErr {
				t.Errorf("validateAmountPrecision(%d, %d, %q) error = %v, wantErr %v",
					tt.microAmount, tt.maxDecimals, tt.label, err, tt.wantErr)
			}
		})
	}
}

func TestRoundRatDown(t *testing.T) {
	tests := []struct {
		name     string
		input    string // rational as "num/denom" or just "num"
		decimals int
		want     string // expected result as decimal string
	}{
		{"round 1.999 to 2 decimals", "1999/1000", 2, "1.99"},
		{"round 0.9994 to 2 decimals", "9994/10000", 2, "0.99"},
		{"round 5.2678 to 2 decimals", "52678/10000", 2, "5.26"},
		{"round 2.43902 to 2 decimals", "243902/100000", 2, "2.43"},
		{"round 0.9994 to 4 decimals", "9994/10000", 4, "0.9994"},
		{"round 1.0 to 2 decimals", "1", 2, "1.00"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, ok := new(big.Rat).SetString(tt.input)
			if !ok {
				t.Fatalf("failed to parse input %q", tt.input)
			}
			result := roundRatDown(input, tt.decimals)
			resultFloat, _ := result.Float64()
			// Format with expected decimals for comparison
			wantFloat := 0.0
			_, _ = fmt.Sscanf(tt.want, "%f", &wantFloat)

			// Compare as micro-units to avoid float precision issues
			resultMicro := int64(resultFloat * 1_000_000)
			wantMicro := int64(wantFloat * 1_000_000)

			if resultMicro != wantMicro {
				t.Errorf("roundRatDown(%s, %d) = %v (%d micro), want %s (%d micro)",
					tt.input, tt.decimals, result, resultMicro, tt.want, wantMicro)
			}
		})
	}
}

func TestRoundConfigForTickSize(t *testing.T) {
	tests := []struct {
		tickSize   string
		wantPrice  int
		wantSize   int
		wantAmount int
		wantErr    bool
	}{
		{"0.1", 1, 2, 3, false},
		{"0.01", 2, 2, 4, false},
		{"0.001", 3, 2, 5, false},
		{"0.0001", 4, 2, 6, false},
		{"0.5", 0, 0, 0, true}, // Unsupported
		{"invalid", 0, 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.tickSize, func(t *testing.T) {
			rc, err := roundConfigForTickSize(tt.tickSize)
			if (err != nil) != tt.wantErr {
				t.Errorf("roundConfigForTickSize(%q) error = %v, wantErr %v", tt.tickSize, err, tt.wantErr)
				return
			}
			if err == nil {
				if rc.priceDecimals != tt.wantPrice || rc.sizeDecimals != tt.wantSize || rc.amountDecimals != tt.wantAmount {
					t.Errorf("roundConfigForTickSize(%q) = {%d, %d, %d}, want {%d, %d, %d}",
						tt.tickSize, rc.priceDecimals, rc.sizeDecimals, rc.amountDecimals,
						tt.wantPrice, tt.wantSize, tt.wantAmount)
				}
			}
		})
	}
}
