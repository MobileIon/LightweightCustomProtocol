package transport

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	DefaultPortStrict   = 856
	DefaultPortDisaster = 855
	AlpnProtocol        = "lcp-v1"
)

var (
	ErrServerClosed = errors.New("lcp: server is already closed")
)

// StreamHandler handles an incoming QUIC stream.
type StreamHandler func(ctx context.Context, stream *quic.Stream)

// ServerConfig defines server options.
type ServerConfig struct {
	StrictCert   tls.Certificate // Used on port 856 (Web PKI / public CA)
	DisasterCert tls.Certificate // Used on port 855 (Dedicated long-lived cert with SPKI Pinning)
	PortStrict   int             // Default 856
	PortDisaster int             // Default 855
	Handler      StreamHandler
	MaxStreams   int64           // Default 1024
	IdleTimeout  time.Duration   // Default 60s
	KeepAlive    time.Duration   // Default 15s
}

// LcpServer provides dual-port (856/855), dual-stack (IPv6/IPv4) QUIC listening.
type LcpServer struct {
	cfg       ServerConfig
	listener1 *quic.Listener
	listener2 *quic.Listener
	cancel    context.CancelFunc
	wg        sync.WaitGroup
	mu        sync.Mutex
	isClosed  bool
}

// NewServer creates a new LcpServer instance.
func NewServer(cfg ServerConfig) *LcpServer {
	if cfg.PortStrict == 0 {
		cfg.PortStrict = DefaultPortStrict
	}
	if cfg.PortDisaster == 0 {
		cfg.PortDisaster = DefaultPortDisaster
	}
	if cfg.MaxStreams == 0 {
		cfg.MaxStreams = 1024
	}
	if cfg.IdleTimeout == 0 {
		cfg.IdleTimeout = 60 * time.Second
	}
	if cfg.KeepAlive == 0 {
		cfg.KeepAlive = 15 * time.Second
	}

	return &LcpServer{
		cfg: cfg,
	}
}

// Start begins listening on both ports concurrently.
func (s *LcpServer) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	s.cancel = cancel

	tlsStrict := &tls.Config{
		Certificates: []tls.Certificate{s.cfg.StrictCert},
		NextProtos:   []string{AlpnProtocol},
	}

	tlsDisaster := &tls.Config{
		Certificates: []tls.Certificate{s.cfg.DisasterCert},
		NextProtos:   []string{AlpnProtocol},
	}

	quicCfg := &quic.Config{
		EnableDatagrams:    true,
		MaxIdleTimeout:     s.cfg.IdleTimeout,
		KeepAlivePeriod:    s.cfg.KeepAlive,
		MaxIncomingStreams: s.cfg.MaxStreams,
	}

	addrStrict := fmt.Sprintf("[::]:%d", s.cfg.PortStrict)
	addrDisaster := fmt.Sprintf("[::]:%d", s.cfg.PortDisaster)

	lStrict, err := quic.ListenAddr(addrStrict, tlsStrict, quicCfg)
	if err != nil {
		// Fallback to IPv4 only if dual-stack IPv6 is unsupported by system
		lStrict, err = quic.ListenAddr(fmt.Sprintf("0.0.0.0:%d", s.cfg.PortStrict), tlsStrict, quicCfg)
		if err != nil {
			return fmt.Errorf("failed to listen on strict port %d: %w", s.cfg.PortStrict, err)
		}
	}
	s.listener1 = lStrict

	lDisaster, err := quic.ListenAddr(addrDisaster, tlsDisaster, quicCfg)
	if err != nil {
		lDisaster, err = quic.ListenAddr(fmt.Sprintf("0.0.0.0:%d", s.cfg.PortDisaster), tlsDisaster, quicCfg)
		if err != nil {
			_ = lStrict.Close()
			return fmt.Errorf("failed to listen on disaster port %d: %w", s.cfg.PortDisaster, err)
		}
	}
	s.listener2 = lDisaster

	log.Printf("[LCP Server] Active on port %d (Strict CA) and port %d (SPKI Disaster)", s.cfg.PortStrict, s.cfg.PortDisaster)

	s.wg.Add(2)
	go s.serveListener(ctx, s.listener1)
	go s.serveListener(ctx, s.listener2)

	return nil
}

// AddrStrict returns the net.Addr for the strict listener.
func (s *LcpServer) AddrStrict() net.Addr {
	if s.listener1 != nil {
		return s.listener1.Addr()
	}
	return nil
}

// AddrDisaster returns the net.Addr for the disaster listener.
func (s *LcpServer) AddrDisaster() net.Addr {
	if s.listener2 != nil {
		return s.listener2.Addr()
	}
	return nil
}

func (s *LcpServer) serveListener(ctx context.Context, l *quic.Listener) {
	defer s.wg.Done()

	for {
		conn, err := l.Accept(ctx)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				return
			}
		}

		s.wg.Add(1)
		go s.handleConnection(ctx, conn)
	}
}

func (s *LcpServer) handleConnection(ctx context.Context, conn *quic.Conn) {
	defer s.wg.Done()

	for {
		stream, err := conn.AcceptStream(ctx)
		if err != nil {
			return
		}

		s.wg.Add(1)
		go func(st *quic.Stream) {
			defer s.wg.Done()
			// Defensive cleanup: both write and read directions must be closed to avoid handle/buffer leaks
			defer func() {
				_ = st.Close()
				st.CancelRead(0)
			}()

			if s.cfg.Handler != nil {
				s.cfg.Handler(ctx, st)
			}
		}(stream)
	}
}

// Close gracefully closes the listeners and active connections.
func (s *LcpServer) Close() error {
	s.mu.Lock()
	if s.isClosed {
		s.mu.Unlock()
		return nil
	}
	s.isClosed = true
	s.mu.Unlock()

	if s.cancel != nil {
		s.cancel()
	}

	var err1, err2 error
	if s.listener1 != nil {
		err1 = s.listener1.Close()
	}
	if s.listener2 != nil {
		err2 = s.listener2.Close()
	}

	s.wg.Wait()

	if err1 != nil {
		return err1
	}
	return err2
}
