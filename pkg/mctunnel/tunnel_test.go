package mctunnel

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"
)

func TestProxyProtocolV2IPv4(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("192.168.1.100"), Port: 54321}
	dst := &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 25565}

	hdr := BuildProxyProtocolV2Header(src, dst)
	if len(hdr) != 28 {
		t.Fatalf("Expected 28 bytes for IPv4 PPv2, got %d", len(hdr))
	}

	// Verify signature
	if !bytes.Equal(hdr[0:12], ppv2Signature) {
		t.Fatalf("Invalid PPv2 signature")
	}

	// Version 2 + PROXY command (0x21)
	if hdr[12] != 0x21 {
		t.Fatalf("Expected 0x21, got 0x%X", hdr[12])
	}

	// AF_INET + STREAM (0x11)
	if hdr[13] != 0x11 {
		t.Fatalf("Expected 0x11, got 0x%X", hdr[13])
	}
}

func TestProxyProtocolV2IPv6(t *testing.T) {
	src := &net.TCPAddr{IP: net.ParseIP("2402:4e00::1"), Port: 60000}
	dst := &net.TCPAddr{IP: net.ParseIP("2402:4e00::2"), Port: 25565}

	hdr := BuildProxyProtocolV2Header(src, dst)
	if len(hdr) != 52 {
		t.Fatalf("Expected 52 bytes for IPv6 PPv2, got %d", len(hdr))
	}

	// Version 2 + PROXY command (0x21)
	if hdr[12] != 0x21 {
		t.Fatalf("Expected 0x21, got 0x%X", hdr[12])
	}

	// AF_INET6 + STREAM (0x21)
	if hdr[13] != 0x21 {
		t.Fatalf("Expected 0x21, got 0x%X", hdr[13])
	}
}

type dummyPipe struct {
	r *io.PipeReader
	w *io.PipeWriter
}

func (d *dummyPipe) Read(p []byte) (n int, err error)  { return d.r.Read(p) }
func (d *dummyPipe) Write(p []byte) (n int, err error) { return d.w.Write(p) }
func (d *dummyPipe) Close() error {
	_ = d.r.Close()
	return d.w.Close()
}

func TestBidirectionalRelay(t *testing.T) {
	r1, w1 := io.Pipe()
	r2, w2 := io.Pipe()

	a := &dummyPipe{r: r1, w: w2}
	b := &dummyPipe{r: r2, w: w1}

	done := make(chan struct{})
	go func() {
		BidirectionalRelay(a, b)
		close(done)
	}()

	// Send data from a to b
	msg := []byte("Minecraft Packet Handshake")
	go func() {
		_, _ = a.Write(msg)
		_ = a.Close()
	}()

	buf := make([]byte, len(msg))
	_, err := io.ReadFull(b, buf)
	if err != nil {
		t.Fatalf("ReadFull failed: %v", err)
	}

	if !bytes.Equal(buf, msg) {
		t.Fatalf("Relayed data mismatch: %s vs %s", string(buf), string(msg))
	}

	_ = b.Close()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("BidirectionalRelay did not terminate in time")
	}
}
