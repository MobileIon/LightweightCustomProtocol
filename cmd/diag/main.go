package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/MobileIon/LightweightCustomProtocol/pkg/transport"
	"github.com/quic-go/quic-go"
)

func main() {
	targets := []string{
		"49.232.234.137:856",
		"[2402:4e00:c052:d00:2aa8:2352:24a8:2]:856",
		"49.232.234.137:855",
		"[2402:4e00:c052:d00:2aa8:2352:24a8:2]:855",
	}

	quicCfg := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  10 * time.Second,
	}

	for _, target := range targets {
		fmt.Printf("\n--- Dialing %s ---\n", target)
		for _, skipVerify := range []bool{false, true} {
			tlsCfg := &tls.Config{
				ServerName:         "mc.potatolight.cn",
				NextProtos:         []string{transport.AlpnProtocol},
				InsecureSkipVerify: skipVerify,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			start := time.Now()
			conn, err := quic.DialAddr(ctx, target, tlsCfg, quicCfg)
			cancel()
			dur := time.Since(start)
			if err != nil {
				fmt.Printf("InsecureSkipVerify=%v: FAILED in %v: %v\n", skipVerify, dur, err)
			} else {
				fmt.Printf("InsecureSkipVerify=%v: SUCCESS in %v! Remote: %s\n", skipVerify, dur, conn.RemoteAddr())
				conn.CloseWithError(0, "done")
			}
		}
	}
}
