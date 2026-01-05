package config

import (
	"math/big"
	"testing"
)

func TestIsValidAddress(t *testing.T) {
	tests := []struct {
		name    string
		address string
		want    bool
	}{
		// Valid addresses
		{
			name:    "valid lowercase address",
			address: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174",
			want:    true,
		},
		{
			name:    "valid uppercase address",
			address: "0x2791BCA1F2DE4661ED88A30C99A7A9449AA84174",
			want:    true,
		},
		{
			name:    "valid mixed case address",
			address: "0x2791Bca1F2De4661Ed88A30C99A7a9449Aa84174",
			want:    true,
		},
		{
			name:    "valid address with leading/trailing spaces",
			address: "  0x2791bca1f2de4661ed88a30c99a7a9449aa84174  ",
			want:    true,
		},
		{
			name:    "valid address - all zeros",
			address: "0x0000000000000000000000000000000000000000",
			want:    true,
		},
		{
			name:    "valid address - all f's",
			address: "0xffffffffffffffffffffffffffffffffffffffff",
			want:    true,
		},
		{
			name:    "valid address - example from specs",
			address: "0xcF37B9b89DdD67Ff8f0569DE9eddd76878053B68",
			want:    true,
		},
		// Invalid addresses
		{
			name:    "empty string",
			address: "",
			want:    false,
		},
		{
			name:    "missing 0x prefix",
			address: "2791bca1f2de4661ed88a30c99a7a9449aa84174",
			want:    false,
		},
		{
			name:    "too short - missing characters",
			address: "0x2791bca1f2de4661ed88a30c99a7a9449aa8417",
			want:    false,
		},
		{
			name:    "too long - extra characters",
			address: "0x2791bca1f2de4661ed88a30c99a7a9449aa84174a",
			want:    false,
		},
		{
			name:    "invalid character - g",
			address: "0x2791bca1f2de4661ed88a30c99a7a9449aa8417g",
			want:    false,
		},
		{
			name:    "invalid character - z",
			address: "0x2791bca1f2de4661ed88a30c99a7a9449aa8417z",
			want:    false,
		},
		{
			name:    "invalid character - special char",
			address: "0x2791bca1f2de4661ed88a30c99a7a9449aa8417!",
			want:    false,
		},
		{
			name:    "invalid character - space in middle",
			address: "0x2791bca1f2de4661ed88a30c99a7a9449aa84 74",
			want:    false,
		},
		{
			name:    "only 0x prefix",
			address: "0x",
			want:    false,
		},
		{
			name:    "wrong prefix - 0X",
			address: "0X2791bca1f2de4661ed88a30c99a7a9449aa84174",
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidAddress(tt.address)
			if got != tt.want {
				t.Errorf("isValidAddress(%q) = %v, want %v", tt.address, got, tt.want)
			}
		})
	}
}

func TestParseUSDCAmount(t *testing.T) {
	tests := []struct {
		name      string
		amountStr string
		want      *big.Int
		wantErr   bool
		errMsg    string
	}{
		// Valid amounts
		{
			name:      "exact $10,000 - minimum deposit",
			amountStr: "10000",
			want:      big.NewInt(10_000_000_000), // 10,000 * 10^6
			wantErr:   false,
		},
		{
			name:      "$10,000 with comma",
			amountStr: "10,000",
			want:      nil, // Will fail to parse, but testing behavior
			wantErr:   true,
		},
		{
			name:      "$5,000",
			amountStr: "5000",
			want:      big.NewInt(5_000_000_000), // 5,000 * 10^6
			wantErr:   false,
		},
		{
			name:      "$1 - minimum unit",
			amountStr: "1",
			want:      big.NewInt(1_000_000), // 1 * 10^6
			wantErr:   false,
		},
		{
			name:      "$0.50 - decimal amount",
			amountStr: "0.5",
			want:      big.NewInt(500_000), // 0.5 * 10^6
			wantErr:   false,
		},
		{
			name:      "$0.01 - smallest cent",
			amountStr: "0.01",
			want:      big.NewInt(10_000), // 0.01 * 10^6
			wantErr:   false,
		},
		{
			name:      "$100,000 - large amount",
			amountStr: "100000",
			want:      big.NewInt(100_000_000_000), // 100,000 * 10^6
			wantErr:   false,
		},
		{
			name:      "$10,000.50 - decimal with cents",
			amountStr: "10000.50",
			want:      big.NewInt(10_000_500_000), // 10,000.50 * 10^6
			wantErr:   false,
		},
		{
			name:      "amount with leading/trailing spaces",
			amountStr: "  10000  ",
			want:      big.NewInt(10_000_000_000),
			wantErr:   false,
		},
		{
			name:      "$0.000001 - very small decimal",
			amountStr: "0.000001",
			want:      big.NewInt(1), // 0.000001 * 10^6 = 1 (truncated)
			wantErr:   false,
		},
		// Invalid amounts
		{
			name:      "empty string",
			amountStr: "",
			want:      nil,
			wantErr:   true,
			errMsg:    "amount cannot be empty",
		},
		{
			name:      "only spaces",
			amountStr: "   ",
			want:      nil,
			wantErr:   true,
			errMsg:    "amount cannot be empty",
		},
		{
			name:      "zero",
			amountStr: "0",
			want:      nil,
			wantErr:   true,
			errMsg:    "amount must be greater than 0",
		},
		{
			name:      "negative amount",
			amountStr: "-1000",
			want:      nil,
			wantErr:   true,
			errMsg:    "amount must be greater than 0",
		},
		{
			name:      "invalid format - letters",
			amountStr: "abc",
			want:      nil,
			wantErr:   true,
		},
		{
			name:      "invalid format - mixed",
			amountStr: "10abc",
			want:      nil,
			wantErr:   true,
		},
		{
			name:      "invalid format - special characters",
			amountStr: "$1000",
			want:      nil,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUSDCAmount(tt.amountStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUSDCAmount(%q) error = %v, wantErr %v", tt.amountStr, err, tt.wantErr)
				return
			}
			if tt.wantErr {
				if tt.errMsg != "" && err != nil && err.Error() != tt.errMsg {
					t.Errorf("parseUSDCAmount(%q) error = %v, want error message containing %q", tt.amountStr, err, tt.errMsg)
				}
				return
			}
			if got.Cmp(tt.want) != 0 {
				t.Errorf("parseUSDCAmount(%q) = %v, want %v", tt.amountStr, got, tt.want)
			}
		})
	}
}

// TestParseUSDCAmountPrecision tests decimal precision handling
func TestParseUSDCAmountPrecision(t *testing.T) {
	tests := []struct {
		name      string
		amountStr string
		want      *big.Int
	}{
		{
			name:      "truncate beyond 6 decimals",
			amountStr: "1.1234567",
			want:      big.NewInt(1_123_456), // Truncates to 6 decimals
		},
		{
			name:      "many decimal places",
			amountStr: "10.123456789",
			want:      big.NewInt(10_123_456), // Truncates to 6 decimals
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseUSDCAmount(tt.amountStr)
			if err != nil {
				t.Fatalf("parseUSDCAmount(%q) unexpected error: %v", tt.amountStr, err)
			}
			if got.Cmp(tt.want) != 0 {
				t.Errorf("parseUSDCAmount(%q) = %v, want %v", tt.amountStr, got, tt.want)
			}
		})
	}
}

// TestParseUSDCAmountEdgeCases tests edge cases and boundary conditions
func TestParseUSDCAmountEdgeCases(t *testing.T) {
	tests := []struct {
		name      string
		amountStr string
		wantErr   bool
	}{
		{
			name:      "very large number",
			amountStr: "999999999.99",
			wantErr:   false,
		},
		{
			name:      "scientific notation - valid input",
			amountStr: "1e6",
			wantErr:   false,
		},
		{
			name:      "multiple decimal points",
			amountStr: "10.50.25",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseUSDCAmount(tt.amountStr)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseUSDCAmount(%q) error = %v, wantErr %v", tt.amountStr, err, tt.wantErr)
			}
		})
	}
}
