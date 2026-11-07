package transport

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

	"github.com/MobileIon/LightweightCustomProtocol/pkg/protocol"
	"github.com/quic-go/quic-go"
)

// generateTestCertificate generates an in-memory ECDSA certificate for testing.
func generateTestCertificate(t *testing.T, host string) (tls.Certificate, string) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey failed: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"LCP Test Suite"},
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

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("CreateCertificate failed: %v", err)
	}

	parsedCert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate failed: %v", err)
	}

	spkiHex := ComputeSPKIHex(parsedCert)

	tlsCert := tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  priv,
	}

	return tlsCert, spkiHex
}

func TestTransportEchoAndSPKIPinning(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	certStrict, _ := generateTestCertificate(t, "127.0.0.1")
	certDisaster, spkiDisasterHex := generateTestCertificate(t, "127.0.0.1")

	portStrict := 28856
	portDisaster := 28855

	// Server echo handler
	handler := func(sCtx context.Context, st *quic.Stream, conn *quic.Conn) {
		req, err := protocol.ReadPacket(st)
		if err != nil {
			return
		}

		// Echo back with FlowLabel + 1
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
			Payload: append([]byte("Echo: "), req.Payload...),
		}
		_ = protocol.WritePacket(st, resp)
	}

	srv := NewServer(ServerConfig{
		StrictCert:   certStrict,
		DisasterCert: certDisaster,
		PortStrict:   portStrict,
		PortDisaster: portDisaster,
		Handler:      handler,
	})

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Server.Start failed: %v", err)
	}
	defer srv.Close()

	// 1. Test Strict Port (28856) with InsecureSkipCA (simulating valid CA)
	clientStrict := NewClient(ClientConfig{
		ServerHost:     "127.0.0.1",
		PortStrict:     portStrict,
		PortDisaster:   portDisaster,
		InsecureSkipCA: true,
	})
	defer clientStrict.Close()

	reqPacket := &protocol.Packet{
		Header: protocol.BaseHeader{
			Magic:        protocol.LcpMagic,
			Version:      protocol.LcpVersion,
			TrafficClass: 4,
			FlowLabel:    100,
		},
		Payload: []byte("Hello via LCP over QUIC!"),
	}

	respPacket, err := clientStrict.SendPacket(ctx, reqPacket)
	if err != nil {
		t.Fatalf("Strict SendPacket failed: %v", err)
	}

	if respPacket.Header.FlowLabel != 101 {
		t.Fatalf("Expected FlowLabel 101, got %d", respPacket.Header.FlowLabel)
	}
	if string(respPacket.Payload) != "Echo: Hello via LCP over QUIC!" {
		t.Fatalf("Unexpected payload: %s", string(respPacket.Payload))
	}

	// 2. Test Disaster Port (28855) with SPKI Pinning (Success)
	clientDisaster := NewClient(ClientConfig{
		ServerHost:       "127.0.0.1",
		PortStrict:       9999, // Intentional non-existent strict port to force fallback!
		PortDisaster:     portDisaster,
		PinnedSPKIHashes: []string{spkiDisasterHex},
	})
	defer clientDisaster.Close()

	respDisaster, err := clientDisaster.SendPacket(ctx, reqPacket)
	if err != nil {
		t.Fatalf("Disaster SendPacket with valid SPKI failed: %v", err)
	}
	if respDisaster.Header.FlowLabel != 101 {
		t.Fatalf("Disaster response FlowLabel mismatch: %d", respDisaster.Header.FlowLabel)
	}

	// 3. Test Disaster Port with Wrong SPKI Pinning (Must be rejected with MITM protection!)
	clientBadSPKI := NewClient(ClientConfig{
		ServerHost:       "127.0.0.1",
		PortStrict:       9999, // Force fallback to disaster
		PortDisaster:     portDisaster,
		PinnedSPKIHashes: []string{"0000000000000000000000000000000000000000000000000000000000000000"}, // Fake wrong hash!
	})
	defer clientBadSPKI.Close()

	_, errBad := clientBadSPKI.SendPacket(ctx, reqPacket)
	if errBad == nil {
		t.Fatalf("Expected connection with bad SPKI to be rejected, but it succeeded!")
	}
	fmt.Printf("[Test Verified] MITM protection intercepted invalid SPKI: %v\n", errBad)
}
