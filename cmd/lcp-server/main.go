package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/MobileIon/LightweightCustomProtocol/pkg/chunking"
	"github.com/MobileIon/LightweightCustomProtocol/pkg/protocol"
	"github.com/MobileIon/LightweightCustomProtocol/pkg/transport"
	"github.com/quic-go/quic-go"
)

func main() {
	portStrict := flag.Int("port-strict", transport.DefaultPortStrict, "UDP port for strict TLS 1.3 (Web PKI CA)")
	portDisaster := flag.Int("port-disaster", transport.DefaultPortDisaster, "UDP port for disaster recovery (SPKI Pinning)")
	certStrictPath := flag.String("cert-strict", "", "Path to public CA certificate file for port 856")
	keyStrictPath := flag.String("key-strict", "", "Path to private key file for port 856")
	certDisasterPath := flag.String("cert-disaster", "", "Path to dedicated long-lived cert file for port 855")
	keyDisasterPath := flag.String("key-disaster", "", "Path to private key file for port 855")
	storageDir := flag.String("storage", "./data", "Directory for chunk storage and file distribution")
	flag.Parse()

	fmt.Println("=================================================================")
	fmt.Println("       LCP (Lightweight Custom Protocol) Server Daemon           ")
	fmt.Println("                  v1.2.1-FINAL Production                        ")
	fmt.Println("=================================================================")

	if err := os.MkdirAll(*storageDir, 0755); err != nil {
		log.Fatalf("Failed to create storage directory %s: %v", *storageDir, err)
	}

	// 1. Load or generate certificates
	strictCert, err := loadOrGenerateCert(*certStrictPath, *keyStrictPath, "platform.potatolight.cn", "Strict CA")
	if err != nil {
		log.Fatalf("Failed to initialize strict certificate: %v", err)
	}

	disasterCert, err := loadOrGenerateCert(*certDisasterPath, *keyDisasterPath, "lcp-disaster-recovery", "Disaster SPKI")
	if err != nil {
		log.Fatalf("Failed to initialize disaster certificate: %v", err)
	}

	// Display SPKI SHA-256 fingerprint for clients to pin
	disasterParsed, _ := x509.ParseCertificate(disasterCert.Certificate[0])
	spkiHex := transport.ComputeSPKIHex(disasterParsed)
	fmt.Printf("[SPKI Pinning] Port %d Disaster Public Key SHA-256 Fingerprint:\n", *portDisaster)
	fmt.Printf("               >> %s <<\n", spkiHex)
	fmt.Println("=================================================================")

	// 2. Setup server stream handler
	handler := func(ctx context.Context, stream *quic.Stream) {
		req, err := protocol.ReadPacket(stream)
		if err != nil {
			return
		}

		// Handle chunk upload (EXT_CHUNK present)
		var chunkHdr *protocol.ChunkHeader
		var integHdr *protocol.IntegrityHeader
		for _, ext := range req.Extensions {
			switch e := ext.(type) {
			case *protocol.ChunkHeader:
				chunkHdr = e
			case *protocol.IntegrityHeader:
				integHdr = e
			}
		}

		if chunkHdr != nil && (chunkHdr.Flags&protocol.ChunkFlagData) != 0 {
			// Chunk data received: Write to storage pipeline
			targetFile := filepath.Join(*storageDir, fmt.Sprintf("stream_%d.bin", stream.StreamID()))
			cw, err := chunking.NewChunkWriter(targetFile, req.Header.SourceID, "active-stream", int64(chunkHdr.Offset)+int64(len(req.Payload)), len(req.Payload))
			if err == nil {
				var hash *[32]byte
				if integHdr != nil {
					hash = &integHdr.Hash
				}
				_ = cw.WriteChunk(chunkHdr, hash, req.Payload)
				if (chunkHdr.Flags & protocol.ChunkFlagEOF) != 0 {
					_ = cw.Finish()
				} else {
					_ = cw.Close()
				}
			}

			// Respond with ACK frame
			ackPacket := &protocol.Packet{
				Header: protocol.BaseHeader{
					Magic:        protocol.LcpMagic,
					Version:      protocol.LcpVersion,
					TrafficClass: 0,
					FlowLabel:    req.Header.FlowLabel,
					SourceID:     req.Header.DestID,
					DestID:       req.Header.SourceID,
				},
				Extensions: []protocol.Extension{
					&protocol.ChunkHeader{
						Flags:       protocol.ChunkFlagAck,
						ChunkIndex:  chunkHdr.ChunkIndex,
						TotalChunks: chunkHdr.TotalChunks,
						Offset:      chunkHdr.Offset,
					},
				},
			}
			_ = protocol.WritePacket(stream, ackPacket)
			return
		}

		// Standard Echo / Ping response
		resp := &protocol.Packet{
			Header: protocol.BaseHeader{
				Magic:        protocol.LcpMagic,
				Version:      protocol.LcpVersion,
				TrafficClass: req.Header.TrafficClass,
				FlowLabel:    req.Header.FlowLabel + 1,
				CustomFlags:  req.Header.CustomFlags,
				SourceID:     req.Header.DestID,
				DestID:       req.Header.SourceID,
			},
			Payload: append([]byte("LCP_ACK: "), req.Payload...),
		}
		_ = protocol.WritePacket(stream, resp)
	}

	// 3. Initialize Server
	srv := transport.NewServer(transport.ServerConfig{
		StrictCert:   strictCert,
		DisasterCert: disasterCert,
		PortStrict:   *portStrict,
		PortDisaster: *portDisaster,
		Handler:      handler,
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	if err := srv.Start(ctx); err != nil {
		log.Fatalf("Server startup failed: %v", err)
	}

	// 4. Wait for OS signals for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("[LCP Server] Received signal %v, initiating graceful shutdown...", sig)

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	_ = shutdownCtx
	if err := srv.Close(); err != nil {
		log.Printf("[LCP Server] Close error: %v", err)
	}

	log.Println("[LCP Server] Graceful shutdown completed cleanly.")
}

func loadOrGenerateCert(certPath, keyPath, defaultHost, desc string) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		return tls.LoadX509KeyPair(certPath, keyPath)
	}

	log.Printf("[Security Notice] No %s certificate specified, generating ephemeral ECDSA P-256 cert for '%s'...", desc, defaultHost)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"LCP Protocol Daemon"},
			CommonName:   defaultHost,
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour), // 10 years for disaster recovery
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{defaultHost},
	}

	if ip := net.ParseIP(defaultHost); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}, nil
}
