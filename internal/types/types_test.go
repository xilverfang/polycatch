package types

import (
	"math/big"
	"testing"
	"time"

	"github.com/polycatch/internal/utils"
)

func TestTransfer_IsHighValue(t *testing.T) {
	tests := []struct {
		name      string
		transfer  *Transfer
		threshold *big.Int
		want      bool
	}{
		{
			name: "transfer exceeds threshold",
			transfer: &Transfer{
				Value: big.NewInt(10_000_000_000), // $10,000
			},
			threshold: big.NewInt(5_000_000_000), // $5,000
			want:      true,
		},
		{
			name: "transfer equals threshold",
			transfer: &Transfer{
				Value: big.NewInt(10_000_000_000), // $10,000
			},
			threshold: big.NewInt(10_000_000_000), // $10,000
			want:      true,
		},
		{
			name: "transfer below threshold",
			transfer: &Transfer{
				Value: big.NewInt(1_000_000_000), // $1,000
			},
			threshold: big.NewInt(10_000_000_000), // $10,000
			want:      false,
		},
		{
			name: "nil value",
			transfer: &Transfer{
				Value: nil,
			},
			threshold: big.NewInt(10_000_000_000),
			want:      false,
		},
		{
			name: "nil threshold",
			transfer: &Transfer{
				Value: big.NewInt(10_000_000_000),
			},
			threshold: nil,
			want:      false,
		},
		{
			name: "both nil",
			transfer: &Transfer{
				Value: nil,
			},
			threshold: nil,
			want:      false,
		},
		{
			name: "very large transfer",
			transfer: &Transfer{
				Value: big.NewInt(100_000_000_000), // $100,000
			},
			threshold: big.NewInt(10_000_000_000), // $10,000
			want:      true,
		},
		{
			name: "small transfer",
			transfer: &Transfer{
				Value: big.NewInt(100_000), // $0.10
			},
			threshold: big.NewInt(10_000_000_000), // $10,000
			want:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.transfer.IsHighValue(tt.threshold)
			if got != tt.want {
				t.Errorf("Transfer.IsHighValue() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTransfer_ToDeposit(t *testing.T) {
	now := time.Now()
	transfer := &Transfer{
		From:            "0x1111111111111111111111111111111111111111",
		To:              "0x2222222222222222222222222222222222222222",
		Value:           big.NewInt(10_000_000_000), // $10,000
		BlockNumber:     12345,
		BlockHash:       "0xblockhash",
		TransactionHash: "0xtxhash",
		LogIndex:        5,
		Timestamp:       now,
		ContractAddress: "0x2791Bca1f2de4661ED88A30C99A7a9449Aa84174",
	}

	deposit := transfer.ToDeposit()

	if deposit.FunderAddress != transfer.To {
		t.Errorf("ToDeposit().FunderAddress = %v, want %v", deposit.FunderAddress, transfer.To)
	}
	if deposit.Amount.Cmp(transfer.Value) != 0 {
		t.Errorf("ToDeposit().Amount = %v, want %v", deposit.Amount, transfer.Value)
	}
	if deposit.BlockNumber != transfer.BlockNumber {
		t.Errorf("ToDeposit().BlockNumber = %v, want %v", deposit.BlockNumber, transfer.BlockNumber)
	}
	if deposit.TxHash != transfer.TransactionHash {
		t.Errorf("ToDeposit().TxHash = %v, want %v", deposit.TxHash, transfer.TransactionHash)
	}
	if !deposit.Timestamp.Equal(transfer.Timestamp) {
		t.Errorf("ToDeposit().Timestamp = %v, want %v", deposit.Timestamp, transfer.Timestamp)
	}
}

func TestTransfer_ToDeposit_HandlesNilValue(t *testing.T) {
	transfer := &Transfer{
		To:              "0x2222222222222222222222222222222222222222",
		Value:           nil,
		BlockNumber:     12345,
		TransactionHash: "0xtxhash",
		Timestamp:       time.Now(),
	}

	deposit := transfer.ToDeposit()

	if deposit == nil {
		t.Fatal("ToDeposit() returned nil")
	}
	if deposit.Amount != nil {
		t.Errorf("ToDeposit().Amount should be nil when transfer value is nil, got %v", deposit.Amount)
	}
}

func TestDeposit_IsRecent(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name    string
		deposit *Deposit
		within  time.Duration
		want    bool
	}{
		{
			name: "recent deposit within 10 seconds",
			deposit: &Deposit{
				Timestamp: now.Add(-5 * time.Second),
			},
			within: 10 * time.Second,
			want:   true,
		},
		{
			name: "old deposit outside window",
			deposit: &Deposit{
				Timestamp: now.Add(-20 * time.Second),
			},
			within: 10 * time.Second,
			want:   false,
		},
		{
			name: "deposit at exact boundary",
			deposit: &Deposit{
				Timestamp: now.Add(-10 * time.Second),
			},
			within: 10 * time.Second,
			want:   true,
		},
		{
			name: "zero timestamp",
			deposit: &Deposit{
				Timestamp: time.Time{},
			},
			within: 10 * time.Second,
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.deposit.IsRecent(tt.within)
			if got != tt.want {
				t.Errorf("Deposit.IsRecent() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDeposit_ToDollarAmount(t *testing.T) {
	tests := []struct {
		name    string
		deposit *Deposit
		want    float64
	}{
		{
			name: "$10,000 deposit",
			deposit: &Deposit{
				Amount: big.NewInt(10_000_000_000), // 10,000 * 10^6
			},
			want: 10000.0,
		},
		{
			name: "$1 deposit",
			deposit: &Deposit{
				Amount: big.NewInt(1_000_000), // 1 * 10^6
			},
			want: 1.0,
		},
		{
			name: "$0.50 deposit",
			deposit: &Deposit{
				Amount: big.NewInt(500_000), // 0.5 * 10^6
			},
			want: 0.5,
		},
		{
			name: "nil amount",
			deposit: &Deposit{
				Amount: nil,
			},
			want: 0.0,
		},
		{
			name: "zero amount",
			deposit: &Deposit{
				Amount: big.NewInt(0),
			},
			want: 0.0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.deposit.ToDollarAmount()
			gotFloat, _ := got.Float64()
			if gotFloat != tt.want {
				t.Errorf("Deposit.ToDollarAmount() = %v, want %v", gotFloat, tt.want)
			}
		})
	}
}

func TestOrder_IsBuy(t *testing.T) {
	tests := []struct {
		name  string
		order *Order
		want  bool
	}{
		{
			name: "buy order",
			order: &Order{
				Side: OrderSideBuy,
			},
			want: true,
		},
		{
			name: "sell order",
			order: &Order{
				Side: OrderSideSell,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.order.IsBuy()
			if got != tt.want {
				t.Errorf("Order.IsBuy() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOrder_IsSell(t *testing.T) {
	tests := []struct {
		name  string
		order *Order
		want  bool
	}{
		{
			name: "sell order",
			order: &Order{
				Side: OrderSideSell,
			},
			want: true,
		},
		{
			name: "buy order",
			order: &Order{
				Side: OrderSideBuy,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.order.IsSell()
			if got != tt.want {
				t.Errorf("Order.IsSell() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOrder_IsFilled(t *testing.T) {
	tests := []struct {
		name  string
		order *Order
		want  bool
	}{
		{
			name: "filled order",
			order: &Order{
				Status: OrderStatusFilled,
			},
			want: true,
		},
		{
			name: "open order",
			order: &Order{
				Status: OrderStatusOpen,
			},
			want: false,
		},
		{
			name: "cancelled order",
			order: &Order{
				Status: OrderStatusCancelled,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.order.IsFilled()
			if got != tt.want {
				t.Errorf("Order.IsFilled() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestOrder_IsOpen(t *testing.T) {
	tests := []struct {
		name  string
		order *Order
		want  bool
	}{
		{
			name: "open order",
			order: &Order{
				Status: OrderStatusOpen,
			},
			want: true,
		},
		{
			name: "filled order",
			order: &Order{
				Status: OrderStatusFilled,
			},
			want: false,
		},
		{
			name: "cancelled order",
			order: &Order{
				Status: OrderStatusCancelled,
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.order.IsOpen()
			if got != tt.want {
				t.Errorf("Order.IsOpen() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTradeSignal_IsValid(t *testing.T) {
	now := time.Now()
	deposit := &Deposit{
		FunderAddress: "0x2222222222222222222222222222222222222222",
		Amount:        big.NewInt(10_000_000_000),
		Timestamp:     now,
	}
	insiderOrder := &Order{
		TokenID: "0x123",
		Side:    OrderSideBuy,
		Price:   "0.65",
		Size:    "100",
	}

	tests := []struct {
		name        string
		tradeSignal *TradeSignal
		want        bool
	}{
		{
			name: "valid trade signal",
			tradeSignal: &TradeSignal{
				Deposit:      deposit,
				InsiderOrder: insiderOrder,
				TokenID:      "0x123",
				Side:         OrderSideBuy,
				Price:        "0.65",
				Size:         "100",
			},
			want: true,
		},
		{
			name:        "nil trade signal",
			tradeSignal: nil,
			want:        false,
		},
		{
			name: "nil deposit",
			tradeSignal: &TradeSignal{
				Deposit:      nil,
				InsiderOrder: insiderOrder,
				TokenID:      "0x123",
				Side:         OrderSideBuy,
				Price:        "0.65",
				Size:         "100",
			},
			want: false,
		},
		{
			name: "nil insider order",
			tradeSignal: &TradeSignal{
				Deposit:      deposit,
				InsiderOrder: nil,
				TokenID:      "0x123",
				Side:         OrderSideBuy,
				Price:        "0.65",
				Size:         "100",
			},
			want: false,
		},
		{
			name: "empty token ID",
			tradeSignal: &TradeSignal{
				Deposit:      deposit,
				InsiderOrder: insiderOrder,
				TokenID:      "",
				Side:         OrderSideBuy,
				Price:        "0.65",
				Size:         "100",
			},
			want: false,
		},
		{
			name: "empty price",
			tradeSignal: &TradeSignal{
				Deposit:      deposit,
				InsiderOrder: insiderOrder,
				TokenID:      "0x123",
				Side:         OrderSideBuy,
				Price:        "",
				Size:         "100",
			},
			want: false,
		},
		{
			name: "empty size",
			tradeSignal: &TradeSignal{
				Deposit:      deposit,
				InsiderOrder: insiderOrder,
				TokenID:      "0x123",
				Side:         OrderSideBuy,
				Price:        "0.65",
				Size:         "",
			},
			want: false,
		},
		{
			name: "invalid side",
			tradeSignal: &TradeSignal{
				Deposit:      deposit,
				InsiderOrder: insiderOrder,
				TokenID:      "0x123",
				Side:         OrderSide("INVALID"),
				Price:        "0.65",
				Size:         "100",
			},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.tradeSignal.IsValid()
			if got != tt.want {
				t.Errorf("TradeSignal.IsValid() = %v, want %v", got, tt.want)
			}
		})
	}
}

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := utils.CalculateSlippage(tt.originalPrice, tt.currentPrice)
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
