package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MobileIon/LightweightCustomProtocol/pkg/mctunnel"
	"github.com/MobileIon/LightweightCustomProtocol/pkg/transport"
)

func main() {
	listenAddr := flag.String("listen", "127.0.0.1:25565", "Local TCP listen address for Minecraft Client to connect to")
	serverHost := flag.String("server", "mc.potatolight.cn", "Remote LCP Minecraft Server domain / SNI")
	portStrict := flag.Int("port-strict", transport.DefaultPortStrict, "Remote LCP strict UDP port (856)")
	portDisaster := flag.Int("port-disaster", transport.DefaultPortDisaster, "Remote LCP disaster UDP port (855)")
	spkiHash := flag.String("spki", "", "Pinned SPKI SHA-256 hex hash for disaster recovery port (855)")
	fallbackIPv4 := flag.String("fallback-ip", "49.232.234.137", "Static IPv4 fallback if DNS fails")
	insecureSkipCA := flag.Bool("insecure-test", false, "Skip CA validation on strict port (testing only)")
	flag.Parse()

	fmt.Println("=================================================================")
	fmt.Println("    LCP Minecraft Client Bridge (Local TCP -> Remote QUIC UDP)   ")
	fmt.Println("                  v1.2.1-FINAL Production                        ")
	fmt.Println("=================================================================")
	fmt.Printf("[Local Listen] Minecraft connects to: %s\n", *listenAddr)
	fmt.Printf("[Remote LCP]   Target Server:        %s (Ports %d / %d)\n", *serverHost, *portStrict, *portDisaster)
	if *fallbackIPv4 != "" {
		fmt.Printf("[Fallback IP]  Static IPv4 Fallback: %s\n", *fallbackIPv4)
	}
	fmt.Println("=================================================================")

	var pinnedHashes []string
	if *spkiHash != "" {
		pinnedHashes = append(pinnedHashes, *spkiHash)
	}

	client := transport.NewClient(transport.ClientConfig{
		ServerHost:         *serverHost,
		PortStrict:         *portStrict,
		PortDisaster:       *portDisaster,
		PinnedSPKIHashes:   pinnedHashes,
		IPv6RaceWindow:     1000 * time.Millisecond,
		StaticFallbackIPv4: *fallbackIPv4,
		InsecureSkipCA:     *insecureSkipCA,
	})
	defer client.Close()

	// 1. Listen on local TCP port for Minecraft client
	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		log.Fatalf("Failed to listen on %s: %v", *listenAddr, err)
	}
	defer listener.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 2. Handle OS signals
	go func() {
		sigChan := make(chan os.Signal, 1)
		signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
		<-sigChan
		log.Println("[LCP-MC-Client] Shutting down bridge listener...")
		_ = listener.Close()
		cancel()
	}()

	actualAddr := listener.Addr().String()
	fmt.Printf("[LCP-MC-Client] LISTENING_ON %s\n", actualAddr)
	log.Printf("[LCP-MC-Client] Ready! You can now join Minecraft server via: %s", actualAddr)

	for {
		clientTCP, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[LCP-MC-Client] Accept error: %v", err)
				return
			}
		}

		log.Printf("[LCP-MC-Client] Minecraft client connected from %s! Establishing LCP QUIC stream...", clientTCP.RemoteAddr())

		go func(local net.Conn) {
			defer local.Close()

			dialCtx, dialCancel := context.WithTimeout(ctx, 8*time.Second)
			defer dialCancel()

			stream, err := client.OpenStream(dialCtx)
			if err != nil {
				log.Printf("[LCP-MC-Client] Failed to open QUIC stream to remote server: %v", err)
				return
			}
			defer func() {
				_ = stream.Close()
				stream.CancelRead(0)
			}()

			log.Printf("[LCP-MC-Client] QUIC Stream #%d established! Tunneling game traffic...", stream.StreamID())

			// Bidirectional relay between Minecraft client TCP and LCP QUIC stream
			mctunnel.BidirectionalRelay(local, stream)

			log.Printf("[LCP-MC-Client] Minecraft session closed for %s", local.RemoteAddr())
		}(clientTCP)
	}
}
