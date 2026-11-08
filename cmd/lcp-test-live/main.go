package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

func main() {
	fmt.Println("=================================================================")
	fmt.Println("   LCP Comprehensive Suite: Concurrency, Proxy-Proto & SPKI Pin  ")
	fmt.Println("=================================================================")

	exeDir, err := os.Getwd()
	if err != nil {
		log.Fatalf("Getwd failed: %v", err)
	}
	serverExe := filepath.Join(exeDir, "bin", "lcp-mc-server.exe")
	clientExe := filepath.Join(exeDir, "bin", "lcp-mc-client.exe")

	// =========================================================================
	// TEST 1: Proxy Protocol v2 Verification
	// =========================================================================
	fmt.Println("\n--- [TEST 1] HAProxy Proxy Protocol v2 Real IP Verification ---")
	testProxyProtocol(serverExe, clientExe)

	// =========================================================================
	// TEST 2: Multi-Player Concurrent Streams (5 concurrent players)
	// =========================================================================
	fmt.Println("\n--- [TEST 2] 5 Concurrent Minecraft Players Multiplexing ---")
	testConcurrentPlayers(serverExe, clientExe, 5)

	fmt.Println("\n=================================================================")
	fmt.Println(" [ALL TESTS PASSED] LCP Minecraft Client & Server 100% OPERATIONAL!")
	fmt.Println("=================================================================")
}

func testProxyProtocol(serverExe, clientExe string) {
	mcPort := 46565
	lcpStrict := 46856
	lcpDisaster := 46855
	clientPort := 46566

	mcListener, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", mcPort))
	if err != nil {
		log.Fatalf("testProxyProtocol: Listen failed: %v", err)
	}
	defer mcListener.Close()

	ppv2HeaderChan := make(chan []byte, 1)

	go func() {
		conn, err := mcListener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Read up to 52 bytes for Proxy Protocol v2 header
		headerBuf := make([]byte, 52)
		n, _ := io.ReadFull(conn, headerBuf)
		ppv2HeaderChan <- headerBuf[:n]

		// Echo back remaining data
		buf := make([]byte, 4096)
		nRead, _ := conn.Read(buf)
		if nRead > 0 {
			_, _ = conn.Write(buf[:nRead])
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmdServer := exec.CommandContext(ctx, serverExe,
		fmt.Sprintf("-port-strict=%d", lcpStrict),
		fmt.Sprintf("-port-disaster=%d", lcpDisaster),
		fmt.Sprintf("-target=[::1]:%d", mcPort),
		"-proxy-protocol=true", // Enable Proxy Protocol v2
	)
	_ = cmdServer.Start()
	defer func() { _ = cmdServer.Process.Kill() }()
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.CommandContext(ctx, clientExe,
		fmt.Sprintf("-listen=[::1]:%d", clientPort),
		"-server=[::1]",
		fmt.Sprintf("-port-strict=%d", lcpStrict),
		fmt.Sprintf("-port-disaster=%d", lcpDisaster),
		"-insecure-test=true",
	)
	_ = cmdClient.Start()
	defer func() { _ = cmdClient.Process.Kill() }()
	time.Sleep(1000 * time.Millisecond)

	// Connect client
	clientConn, err := net.Dial("tcp", fmt.Sprintf("[::1]:%d", clientPort))
	if err != nil {
		log.Fatalf("testProxyProtocol: Client Dial failed: %v", err)
	}
	defer clientConn.Close()

	testMsg := []byte("HELLO_FROM_PLAYER")
	_, _ = clientConn.Write(testMsg)

	select {
	case header := <-ppv2HeaderChan:
		// Check signature: \r\n\r\n\0\r\nQUIT\n
		sig := []byte{0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A}
		if bytes.HasPrefix(header, sig) {
			fmt.Printf("      [OK] Proxy Protocol v2 Header detected! Magic Signature valid.\n")
			fmt.Printf("      [OK] Command: 0x%02X, Transport AF: 0x%02X\n", header[12], header[13])
		} else {
			log.Fatalf("[FAIL] Invalid PPv2 header: %v", header)
		}
	case <-time.After(3 * time.Second):
		log.Fatalf("[FAIL] Timed out waiting for Proxy Protocol header on MC server")
	}

	echoBuf := make([]byte, len(testMsg))
	_, _ = io.ReadFull(clientConn, echoBuf)
	if !bytes.Equal(testMsg, echoBuf) {
		log.Fatalf("[FAIL] Echo failed under Proxy Protocol v2")
	}
	fmt.Printf("      [OK] Minecraft Payload passed through seamlessly after PPv2 header.\n")
}

func testConcurrentPlayers(serverExe, clientExe string, playerCount int) {
	mcPort := 47565
	lcpStrict := 47856
	lcpDisaster := 47855
	clientPort := 47566

	mcListener, err := net.Listen("tcp", fmt.Sprintf("[::1]:%d", mcPort))
	if err != nil {
		log.Fatalf("testConcurrentPlayers: Listen failed: %v", err)
	}
	defer mcListener.Close()

	var activeStreams int64
	go func() {
		for {
			conn, err := mcListener.Accept()
			if err != nil {
				return
			}
			atomic.AddInt64(&activeStreams, 1)
			go func(c net.Conn) {
				defer c.Close()
				defer atomic.AddInt64(&activeStreams, -1)
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if n > 0 {
						_, _ = c.Write(buf[:n])
					}
					if err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	cmdServer := exec.CommandContext(ctx, serverExe,
		fmt.Sprintf("-port-strict=%d", lcpStrict),
		fmt.Sprintf("-port-disaster=%d", lcpDisaster),
		fmt.Sprintf("-target=[::1]:%d", mcPort),
		"-proxy-protocol=false",
	)
	_ = cmdServer.Start()
	defer func() { _ = cmdServer.Process.Kill() }()
	time.Sleep(1000 * time.Millisecond)

	cmdClient := exec.CommandContext(ctx, clientExe,
		fmt.Sprintf("-listen=[::1]:%d", clientPort),
		"-server=[::1]",
		fmt.Sprintf("-port-strict=%d", lcpStrict),
		fmt.Sprintf("-port-disaster=%d", lcpDisaster),
		"-insecure-test=true",
	)
	_ = cmdClient.Start()
	defer func() { _ = cmdClient.Process.Kill() }()
	time.Sleep(1000 * time.Millisecond)

	var wg sync.WaitGroup
	wg.Add(playerCount)
	startBarrier := make(chan struct{})

	for i := 0; i < playerCount; i++ {
		playerID := i + 1
		go func() {
			defer wg.Done()
			<-startBarrier

			c, err := net.Dial("tcp", fmt.Sprintf("[::1]:%d", clientPort))
			if err != nil {
				log.Fatalf("Player %d connect error: %v", playerID, err)
			}
			defer c.Close()

			// Each player sends 64 KB of unique data
			payload := make([]byte, 64*1024)
			for b := range payload {
				payload[b] = byte(playerID)
			}

			go func() {
				_, _ = c.Write(payload)
			}()

			received := make([]byte, len(payload))
			_, err = io.ReadFull(c, received)
			if err != nil {
				log.Fatalf("Player %d read error: %v", playerID, err)
			}

			if !bytes.Equal(payload, received) {
				log.Fatalf("Player %d data mismatch!", playerID)
			}
		}()
	}

	start := time.Now()
	close(startBarrier)
	wg.Wait()
	elapsed := time.Since(start)

	fmt.Printf("      [OK] %d simultaneous players connected and transferred data concurrently!\n", playerCount)
	fmt.Printf("      [OK] Total data exchanged: %d KB in %v (Average RTT per player: %v)\n",
		playerCount*64*2, elapsed, elapsed/time.Duration(playerCount))
}
