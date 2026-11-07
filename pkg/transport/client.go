package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/MobileIon/LightweightCustomProtocol/pkg/protocol"
	"github.com/quic-go/quic-go"
)

var (
	ErrAllTiersFailed = errors.New("lcp: all connection tiers (IPv6/IPv4, Strict/Disaster) failed")
)

// ClientConfig configuration options for LcpClient.
type ClientConfig struct {
	ServerHost         string        // Server domain / SNI hostname
	PortStrict         int           // Default 856
	PortDisaster       int           // Default 855
	PinnedSPKIHashes   []string      // Uppercase hex SPKI SHA-256 hashes for port 855
	IPv6RaceWindow     time.Duration // Default 1000ms
	StaticFallbackIPv4 string        // Optional hardcoded IPv4 fallback
	InsecureSkipCA     bool          // For local testing
}

// LcpClient manages connections, failover, and stream dispatch.
type LcpClient struct {
	cfg  ClientConfig
	mu   sync.Mutex
	conn *quic.Conn
}

// NewClient creates a new LcpClient.
func NewClient(cfg ClientConfig) *LcpClient {
	if cfg.PortStrict == 0 {
		cfg.PortStrict = DefaultPortStrict
	}
	if cfg.PortDisaster == 0 {
		cfg.PortDisaster = DefaultPortDisaster
	}
	if cfg.IPv6RaceWindow == 0 {
		cfg.IPv6RaceWindow = 1000 * time.Millisecond
	}

	return &LcpClient{
		cfg: cfg,
	}
}

// Dial establishes an active QUIC connection using the multi-tier failover state machine.
func (c *LcpClient) Dial(ctx context.Context) (*quic.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.conn != nil && !isConnClosed(c.conn) {
		return c.conn, nil
	}

	// 1. Resolve host addresses
	v6Addrs, v4Addrs := c.resolveAddresses(ctx, c.cfg.ServerHost)
	if len(v4Addrs) == 0 && c.cfg.StaticFallbackIPv4 != "" {
		v4Addrs = append(v4Addrs, net.ParseIP(c.cfg.StaticFallbackIPv4))
	}

	hasGlobalV6 := hasGlobalIPv6Route()

	quicCfg := &quic.Config{
		EnableDatagrams: true,
		MaxIdleTimeout:  60 * time.Second,
		KeepAlivePeriod: 15 * time.Second,
	}

	// Tier 1: IPv6 + Port 856 (Strict Web PKI CA) with 1000ms race window
	if hasGlobalV6 && len(v6Addrs) > 0 {
		targetV6Strict := net.JoinHostPort(v6Addrs[0].String(), fmt.Sprintf("%d", c.cfg.PortStrict))
		raceCtx, raceCancel := context.WithTimeout(ctx, c.cfg.IPv6RaceWindow)

		tlsStrict := c.buildTLSConfig(false, c.cfg.ServerHost)
		conn, err := quic.DialAddr(raceCtx, targetV6Strict, tlsStrict, quicCfg)
		raceCancel()

		if err == nil {
			c.conn = conn
			return conn, nil
		}

		// If error is certificate-related, immediately attempt Tier 3 (IPv6 Disaster 855)
		if isCertificateError(err) && len(c.cfg.PinnedSPKIHashes) > 0 {
			targetV6Disaster := net.JoinHostPort(v6Addrs[0].String(), fmt.Sprintf("%d", c.cfg.PortDisaster))
			tlsDisaster := c.buildTLSConfig(true, c.cfg.ServerHost)
			connD, errD := quic.DialAddr(ctx, targetV6Disaster, tlsDisaster, quicCfg)
			if errD == nil {
				c.conn = connD
				return connD, nil
			}
		}
	}

	// Tier 2: IPv4 + Port 856 (Strict Web PKI CA)
	if len(v4Addrs) > 0 {
		targetV4Strict := net.JoinHostPort(v4Addrs[0].String(), fmt.Sprintf("%d", c.cfg.PortStrict))
		tlsStrict := c.buildTLSConfig(false, c.cfg.ServerHost)
		conn, err := quic.DialAddr(ctx, targetV4Strict, tlsStrict, quicCfg)
		if err == nil {
			c.conn = conn
			return conn, nil
		}

		// If certificate error, jump to Tier 4
		if isCertificateError(err) && len(c.cfg.PinnedSPKIHashes) > 0 {
			targetV4Disaster := net.JoinHostPort(v4Addrs[0].String(), fmt.Sprintf("%d", c.cfg.PortDisaster))
			tlsDisaster := c.buildTLSConfig(true, c.cfg.ServerHost)
			connD, errD := quic.DialAddr(ctx, targetV4Disaster, tlsDisaster, quicCfg)
			if errD == nil {
				c.conn = connD
				return connD, nil
			}
		}
	}

	// Tier 3: IPv6 + Port 855 (Disaster Recovery with SPKI Pinning)
	if hasGlobalV6 && len(v6Addrs) > 0 && len(c.cfg.PinnedSPKIHashes) > 0 {
		targetV6Disaster := net.JoinHostPort(v6Addrs[0].String(), fmt.Sprintf("%d", c.cfg.PortDisaster))
		tlsDisaster := c.buildTLSConfig(true, c.cfg.ServerHost)
		conn, err := quic.DialAddr(ctx, targetV6Disaster, tlsDisaster, quicCfg)
		if err == nil {
			c.conn = conn
			return conn, nil
		}
	}

	// Tier 4: IPv4 + Port 855 (Disaster Recovery with SPKI Pinning)
	if len(v4Addrs) > 0 && len(c.cfg.PinnedSPKIHashes) > 0 {
		targetV4Disaster := net.JoinHostPort(v4Addrs[0].String(), fmt.Sprintf("%d", c.cfg.PortDisaster))
		tlsDisaster := c.buildTLSConfig(true, c.cfg.ServerHost)
		conn, err := quic.DialAddr(ctx, targetV4Disaster, tlsDisaster, quicCfg)
		if err == nil {
			c.conn = conn
			return conn, nil
		}
	}

	return nil, ErrAllTiersFailed
}

// OpenStream dials if necessary and opens a new bidirectional QUIC stream.
func (c *LcpClient) OpenStream(ctx context.Context) (*quic.Stream, error) {
	conn, err := c.Dial(ctx)
	if err != nil {
		return nil, err
	}

	st, err := conn.OpenStreamSync(ctx)
	if err != nil {
		// Connection might be stale, retry once
		c.mu.Lock()
		c.conn = nil
		c.mu.Unlock()

		conn, err = c.Dial(ctx)
		if err != nil {
			return nil, err
		}
		return conn.OpenStreamSync(ctx)
	}

	return st, nil
}

// SendPacket sends a packet on a new stream and reads back the response packet.
func (c *LcpClient) SendPacket(ctx context.Context, req *protocol.Packet) (*protocol.Packet, error) {
	st, err := c.OpenStream(ctx)
	if err != nil {
		return nil, err
	}
	defer func() {
		_ = st.Close()
		st.CancelRead(0)
	}()

	if err := protocol.WritePacket(st, req); err != nil {
		return nil, err
	}

	return protocol.ReadPacket(st)
}

// Close closes the active connection if any.
func (c *LcpClient) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		err := c.conn.CloseWithError(0, "client closed")
		c.conn = nil
		return err
	}
	return nil
}

func (c *LcpClient) buildTLSConfig(isDisaster bool, serverName string) *tls.Config {
	if isDisaster {
		return &tls.Config{
			ServerName:         serverName,
			NextProtos:         []string{AlpnProtocol},
			InsecureSkipVerify: true, // We verify SPKI manually in VerifyPeerCertificate
			VerifyPeerCertificate: func(rawCerts [][]byte, _ [][]*x509.Certificate) error {
				return ValidateSPKIPinning(rawCerts, c.cfg.PinnedSPKIHashes)
			},
		}
	}

	return &tls.Config{
		ServerName:         serverName,
		NextProtos:         []string{AlpnProtocol},
		InsecureSkipVerify: c.cfg.InsecureSkipCA,
	}
}

func (c *LcpClient) resolveAddresses(ctx context.Context, host string) ([]net.IP, []net.IP) {
	var v6Addrs, v4Addrs []net.IP

	// If host is directly an IP literal
	if ip := net.ParseIP(host); ip != nil {
		if ip.To4() != nil {
			return nil, []net.IP{ip}
		}
		return []net.IP{ip}, nil
	}

	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, nil
	}

	for _, ip := range ips {
		if ip.To4() != nil {
			// Skip fake-IP proxy ranges
			if !isFakeIP(ip) {
				v4Addrs = append(v4Addrs, ip)
			}
		} else {
			// Only consider global unicast IPv6 (2000::/3)
			if isGlobalUnicastIPv6(ip) {
				v6Addrs = append(v6Addrs, ip)
			}
		}
	}

	return v6Addrs, v4Addrs
}

func isFakeIP(ip net.IP) bool {
	// 198.18.0.0/15
	if len(ip) == 4 || ip.To4() != nil {
		ip4 := ip.To4()
		return ip4[0] == 198 && (ip4[1]&0xFE) == 18
	}
	return false
}

func isGlobalUnicastIPv6(ip net.IP) bool {
	if len(ip) != net.IPv6len || ip.To4() != nil {
		return false
	}
	// Must start with 2000::/3 (i.e. 0x20 to 0x3F)
	return (ip[0] & 0xE0) == 0x20
}

func hasGlobalIPv6Route() bool {
	ifaces, err := net.Interfaces()
	if err != nil {
		return false
	}
	for _, iface := range ifaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if isGlobalUnicastIPv6(ip) {
				return true
			}
		}
	}
	return false
}

func isCertificateError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "certificate") ||
		strings.Contains(msg, "x509") ||
		strings.Contains(msg, "bad certificate") ||
		strings.Contains(msg, "unknown authority")
}

func isConnClosed(conn *quic.Conn) bool {
	select {
	case <-conn.Context().Done():
		return true
	default:
		return false
	}
}
