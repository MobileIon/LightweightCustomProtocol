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
	"syscall"
	"time"

	"github.com/MobileIon/LightweightCustomProtocol/pkg/mctunnel"
	"github.com/MobileIon/LightweightCustomProtocol/pkg/transport"
	"github.com/quic-go/quic-go"
)

func main() {
	portStrict := flag.Int("port-strict", transport.DefaultPortStrict, "LCP strict TLS 1.3 UDP port")
	portDisaster := flag.Int("port-disaster", transport.DefaultPortDisaster, "LCP disaster recovery UDP port")
	targetMC := flag.String("target", "[::1]:25565", "Local Minecraft dedicated server TCP address")
	enableProxyProto := flag.Bool("proxy-protocol", false, "Send HAProxy Proxy Protocol v2 header to MC server (Paper/Velocity real IP)")
	certStrictPath := flag.String("cert-strict", "", "Path to public CA certificate file")
	keyStrictPath := flag.String("key-strict", "", "Path to public CA private key file")
	certDisasterPath := flag.String("cert-disaster", "", "Path to dedicated disaster recovery certificate")
	keyDisasterPath := flag.String("key-disaster", "", "Path to dedicated disaster recovery private key")
	flag.Parse()

	fmt.Println("=================================================================")
	fmt.Println("    LCP Minecraft Server Gateway (QUIC UDP -> Local TCP)         ")
	fmt.Println("                  v1.2.1-FINAL Production                        ")
	fmt.Println("=================================================================")

	// 1. Certificates
	strictCert, err := loadOrGenCert(*certStrictPath, *keyStrictPath, "mc.potatolight.cn", "Strict CA")
	if err != nil {
		log.Fatalf("Failed to initialize strict certificate: %v", err)
	}

	disasterCert, err := loadOrGenCert(*certDisasterPath, *keyDisasterPath, "lcp-mc-disaster", "Disaster SPKI")
	if err != nil {
		log.Fatalf("Failed to initialize disaster certificate: %v", err)
	}

	disasterParsed, _ := x509.ParseCertificate(disasterCert.Certificate[0])
	spkiHex := transport.ComputeSPKIHex(disasterParsed)
	fmt.Printf("[SPKI Pinning] Port %d Disaster Public Key SHA-256 Fingerprint:\n", *portDisaster)
	fmt.Printf("               >> %s <<\n", spkiHex)
	fmt.Printf("[MC Target] Forwarding all LCP player streams to TCP: %s\n", *targetMC)
	if *enableProxyProto {
		fmt.Println("[Proxy Protocol] Enabled (HAProxy Protocol v2 will be sent to MC server)")
	}
	fmt.Println("=================================================================")

	// 2. Stream Handler: bridges QUIC stream <---> Minecraft Local TCP
	handler := func(ctx context.Context, stream *quic.Stream, conn *quic.Conn) {
		mcConn, err := net.DialTimeout("tcp", *targetMC, 3*time.Second)
		if err != nil {
			log.Printf("[LCP-MC-Gateway] Failed to connect to local MC server %s: %v", *targetMC, err)
			return
		}
		defer mcConn.Close()

		// Optional: Prepend HAProxy Proxy Protocol v2 header with real client IP
		if *enableProxyProto {
			ppv2Header := mctunnel.BuildProxyProtocolV2Header(conn.RemoteAddr(), mcConn.LocalAddr())
			if _, err := mcConn.Write(ppv2Header); err != nil {
				log.Printf("[LCP-MC-Gateway] Failed to write Proxy Protocol v2 header: %v", err)
				return
			}
		}

		// Bidirectional data pipe between QUIC stream and Minecraft TCP socket
		mctunnel.BidirectionalRelay(mcConn, stream)
	}

	// 3. Start LCP Server
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

	// 4. Wait for OS signals
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("[LCP-MC-Gateway] Received signal %v, shutting down...", sig)
	_ = srv.Close()
	log.Println("[LCP-MC-Gateway] Shutdown complete.")
}

func loadOrGenCert(certPath, keyPath, defaultHost, desc string) (tls.Certificate, error) {
	if certPath != "" && keyPath != "" {
		return tls.LoadX509KeyPair(certPath, keyPath)
	}

	log.Printf("[Notice] Generating ephemeral ECDSA cert for %s (%s)...", desc, defaultHost)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject: pkix.Name{
			Organization: []string{"LCP Minecraft Gateway"},
			CommonName:   defaultHost,
		},
		NotBefore: time.Now().Add(-24 * time.Hour),
		NotAfter:  time.Now().Add(10 * 365 * 24 * time.Hour),
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
