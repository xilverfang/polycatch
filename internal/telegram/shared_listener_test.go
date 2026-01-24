package telegram

import (
	"fmt"
	"io"
	"log"
	"math/big"
	"testing"
	"time"

	"github.com/polycatch/internal/types"
)

func BenchmarkSharedListenerBroadcast(b *testing.B) {
	prev := log.Writer()
	log.SetOutput(io.Discard)
	defer log.SetOutput(prev)

	sizes := []int{1, 10, 50, 100, 250, 500}
	for _, size := range sizes {
		b.Run(fmt.Sprintf("subs_%d", size), func(b *testing.B) {
			sl := &SharedListener{
				subscribers: make(map[int64]chan *types.Deposit, size),
			}

			stop := make(chan struct{})
			for i := 0; i < size; i++ {
				ch := make(chan *types.Deposit, 1024)
				sl.subscribers[int64(i)] = ch
				go func(c <-chan *types.Deposit) {
					for {
						select {
						case <-stop:
							return
						case <-c:
						}
					}
				}(ch)
			}

			deposit := &types.Deposit{
				FunderAddress: "0x0000000000000000000000000000000000000000",
				Amount:        big.NewInt(1),
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
		})
	}
}
