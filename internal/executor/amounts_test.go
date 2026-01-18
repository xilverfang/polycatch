package executor

import "testing"

func TestComputeOrderMicroAmounts_LimitBuy_UsesFourDecimalsCap(t *testing.T) {
	// Reproduces:
	// price = 0.299
	// sharesRounded (2dp) = 6.66
	// maker USD = 6.66 * 0.299 = 1.99134 -> expected 1.9913 (4dp, rounded down)
	rc, err := roundConfigForTickSize("0.001")
	if err != nil {
		t.Fatalf("roundConfigForTickSize: %v", err)
	}

	amountUSDCMicro := int64(1_991_340) // $1.99134
	usdcMicro, sharesMicro, err := computeOrderMicroAmounts(rc, "GTC", "0.299", amountUSDCMicro)
	if err != nil {
		t.Fatalf("computeOrderMicroAmounts: %v", err)
	}

	if sharesMicro != 6_660_000 {
		t.Fatalf("sharesMicro=%d, want %d", sharesMicro, int64(6_660_000))
	}
	if usdcMicro != 1_991_300 {
		t.Fatalf("usdcMicro=%d, want %d", usdcMicro, int64(1_991_300))
	}
}

func TestComputeOrderMicroAmounts_MarketBuy_UsesTwoDecimals(t *testing.T) {
	rc, err := roundConfigForTickSize("0.001")
	if err != nil {
		t.Fatalf("roundConfigForTickSize: %v", err)
	}

	amountUSDCMicro := int64(1_991_340) // $1.99134
	usdcMicro, sharesMicro, err := computeOrderMicroAmounts(rc, "FAK", "0.299", amountUSDCMicro)
	if err != nil {
		t.Fatalf("computeOrderMicroAmounts: %v", err)
	}

	// Shares rounding doesn't change between market/limit in our flow (2dp sizing).
	if sharesMicro != 6_660_000 {
		t.Fatalf("sharesMicro=%d, want %d", sharesMicro, int64(6_660_000))
	}
	// USDC maker amount must be <= 2 decimals for market orders.
	if usdcMicro != 1_990_000 {
		t.Fatalf("usdcMicro=%d, want %d", usdcMicro, int64(1_990_000))
	}
}
