package telegram

import (
	"fmt"
	"io"
	"log"
	"math/big"
	"sync"
	"testing"
	"time"

	"github.com/polycatch/internal/types"
)

func BenchmarkMonitorDepositPipeline(b *testing.B) {
	prev := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prev)

	sizes := []int{1, 10, 50, 100, 250}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("subs_%d", size), func(b *testing.B) {
			sl := &SharedListener{
				subscribers: make(map[int64]chan *types.Deposit, size),
			}

			stop := make(chan struct{})
			var wg sync.WaitGroup
			for i := 0; i < size; i++ {
				ch := make(chan *types.Deposit, 1024)
				sl.subscribers[int64(i)] = ch
				wg.Add(1)
				go func(c <-chan *types.Deposit) {
					defer wg.Done()
					for {
						select {
						case <-stop:
							return
						case d, ok := <-c:
							if !ok {
								return
							}
							_ = d.IsRecent(2 * time.Second)
							_ = d.ToDollarAmount()
						}
					}
				}(ch)
			}

			deposit := &types.Deposit{
				FunderAddress: "0x0000000000000000000000000000000000000000",
				Amount:        big.NewInt(1_000_000),
				BlockNumber:   1,
				TxHash:        "0x0",
				Timestamp:     time.Now(),
			}

			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				sl.broadcast(deposit)
			}
			b.StopTimer()

			close(stop)
			for _, ch := range sl.subscribers {
				close(ch)
			}
			wg.Wait()
		})
	}
}
