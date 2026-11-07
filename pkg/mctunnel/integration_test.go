package mctunnel

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/MobileIon/LightweightCustomProtocol/pkg/transport"
	"github.com/quic-go/quic-go"
)

func generateTestCert(t *testing.T, host string) (tls.Certificate, string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LCP MC Test"},
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageServerAuth,
		},
		DNSNames: []string{host},
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}
	parsed, _ := x509.ParseCertificate(der)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: priv}, transport.ComputeSPKIHex(parsed)
}

func TestMinecraftTunnelEndToEnd(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Mock Minecraft Dedicated Server listening on local TCP
	mcListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock MC server: %v", err)
	}
	defer mcListener.Close()
	mcServerAddr := mcListener.Addr().String()

	// Mock MC server: Echoes received packets
	go func() {
		for {
			conn, err := mcListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				n, err := c.Read(buf)
				if err == nil && n > 0 {
					_, _ = c.Write(append([]byte("MC_PONG: "), buf[:n]...))
				}
			}(conn)
		}
	}()

	// 2. Start LCP MC Server Gateway (QUIC UDP -> Local TCP)
	certStrict, _ := generateTestCert(t, "127.0.0.1")
	certDisaster, spkiDisaster := generateTestCert(t, "127.0.0.1")

	portStrict := 38856
	portDisaster := 38855

	lcpServer := transport.NewServer(transport.ServerConfig{
		StrictCert:   certStrict,
		DisasterCert: certDisaster,
		PortStrict:   portStrict,
		PortDisaster: portDisaster,
		Handler: func(sCtx context.Context, stream *quic.Stream, conn *quic.Conn) {
			mcConn, err := net.Dial("tcp", mcServerAddr)
			if err != nil {
				return
			}
			defer mcConn.Close()
			BidirectionalRelay(mcConn, stream)
		},
	})

	if err := lcpServer.Start(ctx); err != nil {
		t.Fatalf("lcpServer.Start failed: %v", err)
	}
	defer lcpServer.Close()

	// 3. Start LCP MC Client Bridge (Local TCP -> Remote QUIC UDP)
	lcpClient := transport.NewClient(transport.ClientConfig{
		ServerHost:       "127.0.0.1",
		PortStrict:       portStrict,
		PortDisaster:     portDisaster,
		PinnedSPKIHashes: []string{spkiDisaster},
		InsecureSkipCA:   true,
	})
	defer lcpClient.Close()

	localBridgeListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start local bridge: %v", err)
	}
	defer localBridgeListener.Close()
	localBridgeAddr := localBridgeListener.Addr().String()

	go func() {
		for {
			clientConn, err := localBridgeListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				stream, err := lcpClient.OpenStream(ctx)
				if err != nil {
					return
				}
				defer func() {
					_ = stream.Close()
					stream.CancelRead(0)
				}()
				BidirectionalRelay(c, stream)
			}(clientConn)
		}
	}()

	// 4. Mock Minecraft Client connects to localBridgeAddr (simulating Minecraft game joining)
	clientConn, err := net.Dial("tcp", localBridgeAddr)
	if err != nil {
		t.Fatalf("Minecraft client failed to connect to local bridge: %v", err)
	}
	defer clientConn.Close()

	mcHandshakePayload := []byte("MinecraftHandshakePacket_v1.20.1")
	if _, err := clientConn.Write(mcHandshakePayload); err != nil {
		t.Fatalf("Failed to write to local bridge: %v", err)
	}

	buf := make([]byte, 1024)
	n, err := clientConn.Read(buf)
	if err != nil {
		t.Fatalf("Failed to read response from local bridge: %v", err)
	}

	expected := fmt.Sprintf("MC_PONG: %s", string(mcHandshakePayload))
	actual := string(buf[:n])

	if actual != expected {
		t.Fatalf("Tunnel response mismatch:\nExpected: %s\nActual:   %s", expected, actual)
	}

	t.Logf("[SUCCESS] Minecraft traffic tunneled cleanly: MC Client -> Local Bridge -> LCP QUIC -> LCP Server -> MC Server -> Response Echoed!")
}
