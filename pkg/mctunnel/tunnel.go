package mctunnel

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
)

// Proxy Protocol v2 Header Magic: \r\n\r\n\0\r\nQUIT\n
var ppv2Signature = []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}

// BuildProxyProtocolV2Header generates an HAProxy Proxy Protocol v2 binary header.
// This allows Minecraft servers (Paper, Velocity, Bungee, Forge with ProxyProtocol mod)
// to accurately recognize the real player IP and port even when tunneled over LCP.
func BuildProxyProtocolV2Header(srcAddr, dstAddr net.Addr) []byte {
	srcTCP, okSrc := srcAddr.(*net.TCPAddr)
	dstTCP, okDst := dstAddr.(*net.TCPAddr)

	var srcIP, dstIP net.IP
	var srcPort, dstPort int

	if okSrc && okDst {
		srcIP = srcTCP.IP
		dstIP = dstTCP.IP
		srcPort = srcTCP.Port
		dstPort = dstTCP.Port
	} else {
		// Fallback for UDP or other addresses
		srcIP = net.ParseIP("::1")
		dstIP = net.ParseIP("::1")
		srcPort = 25565
		dstPort = 25565
	}

	isIPv6 := srcIP.To4() == nil

	if !isIPv6 {
		// IPv4: 16 bytes base header + 12 bytes address info = 28 bytes
		header := make([]byte, 28)
		copy(header[0:12], ppv2Signature)
		header[12] = 0x21 // Protocol version 2, PROXY command
		header[13] = 0x11 // AF_INET (IPv4), STREAM (TCP)
		binary.BigEndian.PutUint16(header[14:16], 12)

		src4 := srcIP.To4()
		dst4 := dstIP.To4()
		copy(header[16:20], src4)
		copy(header[20:24], dst4)
		binary.BigEndian.PutUint16(header[24:26], uint16(srcPort))
		binary.BigEndian.PutUint16(header[26:28], uint16(dstPort))
		return header
	} else {
		// IPv6: 16 bytes base header + 36 bytes address info = 52 bytes
		header := make([]byte, 52)
		copy(header[0:12], ppv2Signature)
		header[12] = 0x21 // Protocol version 2, PROXY command
		header[13] = 0x21 // AF_INET6 (IPv6), STREAM (TCP)
		binary.BigEndian.PutUint16(header[14:16], 36)

		src16 := srcIP.To16()
		dst16 := dstIP.To16()
		copy(header[16:32], src16)
		copy(header[32:48], dst16)
		binary.BigEndian.PutUint16(header[48:50], uint16(srcPort))
		binary.BigEndian.PutUint16(header[50:52], uint16(dstPort))
		return header
	}
}

// BidirectionalRelay pipes data between two ReadWriteClosers with a shared buffer pool.
func BidirectionalRelay(a, b io.ReadWriteCloser) {
	var wg sync.WaitGroup
	wg.Add(2)

	pipe := func(dst io.WriteCloser, src io.Reader) {
		defer wg.Done()
		buf := make([]byte, 32*1024) // 32KB buffer for low Minecraft network latency
		_, _ = io.CopyBuffer(dst, src, buf)
		_ = dst.Close()
	}

	go pipe(a, b)
	go pipe(b, a)

	wg.Wait()
}
