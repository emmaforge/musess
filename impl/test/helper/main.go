// Test helper for the musess milestone-1 end-to-end test.
// Subcommands:
//
//	keygen                       print a fresh X25519 private/public key pair (base64 raw-url)
//	dest -addr -cert -key -body -sidlog
//	                             HTTPS stand-in for the borrowed destination;
//	                             appends the hex session ID of every ClientHello it
//	                             receives to -sidlog (this is how the test proves a
//	                             connection was forwarded to the destination)
//	sniff -listen -target -capture
//	                             TCP relay that records the client->server byte
//	                             stream to -capture (used to capture a genuine
//	                             authenticated ClientHello)
//	replay -addr -file           write the captured bytes to a fresh connection,
//	                             then report the first response bytes
//	sid -file                    print the hex session ID inside a captured ClientHello
//	udpecho -addr                UDP echo server (payload returned verbatim)
//	shim -listen -target -delay-ms -hold-prob -hold-ms -chunk
//	                             user-space TCP impairment shim (delay/hold
//	                             model, NOT packet loss; see runShim)
//	bulkserver -port             stream an endless repeating pattern on TCP
//	bulkclient -addr [-socks] -bytes
//	                             read exactly -bytes as fast as possible and
//	                             print bytes/seconds/mbps
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: helper <keygen|dest|sniff|replay|sid|udpecho|shim|bulkserver|bulkclient> [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "keygen":
		err = runKeygen()
	case "dest":
		err = runDest(os.Args[2:])
	case "dest2":
		err = runDest2(os.Args[2:])
	case "sniff":
		err = runSniff(os.Args[2:])
	case "replay":
		err = runReplay(os.Args[2:])
	case "sid":
		err = runSID(os.Args[2:])
	case "udpecho":
		err = runUDPEcho(os.Args[2:])
	case "udpclient":
		err = runUDPClient(os.Args[2:])
	case "shim":
		err = runShim(os.Args[2:])
	case "bulkserver":
		err = runBulkServer(os.Args[2:])
	case "bulkclient":
		err = runBulkClient(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper:", err)
		os.Exit(1)
	}
}

func runKeygen() error {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	fmt.Printf("private=%s\n", base64.RawURLEncoding.EncodeToString(privateKey.Bytes()))
	fmt.Printf("public=%s\n", base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()))
	return nil
}

// replayConn replays peeked bytes before reading from the socket.
type replayConn struct {
	net.Conn
	reader io.Reader
}

func (c *replayConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

// sessionIDOf extracts the legacy_session_id from a raw ClientHello
// record (first record of a TLS stream).
func sessionIDOf(record []byte) ([]byte, error) {
	rec, err := firstTLSRecord(record)
	if err != nil {
		return nil, err
	}
	hs := rec[5:]
	if len(hs) < 4+2+32+1 {
		return nil, fmt.Errorf("handshake too short")
	}
	sidLength := int(hs[4+2+32])
	if len(hs) < 4+2+32+1+sidLength {
		return nil, fmt.Errorf("session id truncated")
	}
	return hs[4+2+32+1 : 4+2+32+1+sidLength], nil
}

func runDest(args []string) error {
	fs := flag.NewFlagSet("dest", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:18443", "listen address")
	certFile := fs.String("cert", "", "certificate file")
	keyFile := fs.String("key", "", "key file")
	bodyFile := fs.String("body", "", "file whose contents are served for every request")
	sidLog := fs.String("sidlog", "", "append received ClientHello session IDs (hex) to this file")
	_ = fs.Parse(args)

	body, err := os.ReadFile(*bodyFile)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{certificate}}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	fmt.Println("dest listening on", *addr)
	var mutex sync.Mutex
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
			// Peek the ClientHello to log its session ID: this log is
			// how the test proves a connection reached the destination.
			reader := bufio.NewReader(conn)
			header := make([]byte, 5)
			if _, err := io.ReadFull(reader, header); err != nil {
				return
			}
			recLen := int(header[3])<<8 | int(header[4])
			record := make([]byte, 5+recLen)
			copy(record, header)
			if _, err := io.ReadFull(reader, record[5:]); err != nil {
				return
			}
			if sid, err := sessionIDOf(record); err == nil && *sidLog != "" {
				mutex.Lock()
				if f, ferr := os.OpenFile(*sidLog, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); ferr == nil {
					fmt.Fprintf(f, "%s\n", hex.EncodeToString(sid))
					f.Close()
				}
				mutex.Unlock()
			}
			replay := &replayConn{Conn: conn, reader: io.MultiReader(bytes.NewReader(record), reader)}
			tlsConn := tls.Server(replay, tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return
			}
			buffer := make([]byte, 4096)
			_, _ = tlsConn.Read(buffer)
			fmt.Fprintf(tlsConn, "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", len(body))
			_, _ = tlsConn.Write(body)
		}(conn)
	}
}

// runDest2 is an HTTPS destination built on net/http (so it negotiates
// HTTP/2 like a real site). It exists for the fallback benchmark: the
// tree's REALITY server requires a TLS 1.3 + H2 handshake target,
// which the hand-rolled `dest` stand-in does not provide.
func runDest2(args []string) error {
	fs := flag.NewFlagSet("dest2", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:18443", "listen address")
	certFile := fs.String("cert", "", "certificate file")
	keyFile := fs.String("key", "", "key file")
	bodyFile := fs.String("body", "", "file whose contents are served for every request")
	_ = fs.Parse(args)

	body, err := os.ReadFile(*bodyFile)
	if err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", *addr)
	if err != nil {
		return err
	}
	server := &http.Server{
		Addr:      *addr,
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain")
			_, _ = w.Write(body)
		}),
	}
	fmt.Println("dest2 (net/http, h2-capable) listening on", *addr)
	return server.ServeTLS(listener, "", "")
}

func runSniff(args []string) error {
	fs := flag.NewFlagSet("sniff", flag.ExitOnError)
	listenAddr := fs.String("listen", "", "listen address")
	target := fs.String("target", "", "forward target address")
	captureFile := fs.String("capture", "", "file to record the client->server stream into")
	_ = fs.Parse(args)

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return err
	}
	fmt.Println("sniff listening on", *listenAddr)
	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}
		go func(client net.Conn) {
			defer client.Close()
			server, err := net.DialTimeout("tcp", *target, 5*time.Second)
			if err != nil {
				return
			}
			defer server.Close()
			capture, err := os.Create(*captureFile)
			if err != nil {
				return
			}
			defer capture.Close()
			go func() {
				_, _ = io.Copy(client, server)
			}()
			_, _ = io.Copy(io.MultiWriter(server, capture), client)
		}(client)
	}
}

func runReplay(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	addr := fs.String("addr", "", "server address to replay against")
	file := fs.String("file", "", "captured client stream to replay")
	_ = fs.Parse(args)

	payload, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	// Only the first TLS record (the ClientHello) is replayed: that is
	// the handshake a prober could capture off the wire.
	record, err := firstTLSRecord(payload)
	if err != nil {
		return err
	}
	conn, err := net.DialTimeout("tcp", *addr, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	if _, err = conn.Write(record); err != nil {
		return err
	}
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	response := make([]byte, 4096)
	n, _ := conn.Read(response)
	if n > 0 {
		fmt.Printf("replay response: %d bytes, first bytes: %s\n", n, hex.EncodeToString(response[:min(n, 16)]))
		if response[0] == 0x16 {
			fmt.Println("replay response is a TLS handshake record (the destination answered)")
		}
	} else {
		fmt.Println("replay response: 0 bytes (connection closed without a TLS answer)")
	}
	return nil
}

// firstTLSRecord extracts the first complete TLS record from a stream.
func firstTLSRecord(stream []byte) ([]byte, error) {
	if len(stream) < 5 || stream[0] != 0x16 {
		return nil, fmt.Errorf("stream does not start with a TLS handshake record")
	}
	length := int(stream[3])<<8 | int(stream[4])
	if len(stream) < 5+length {
		return nil, fmt.Errorf("incomplete first record: have %d, want %d", len(stream), 5+length)
	}
	return stream[:5+length], nil
}

func runSID(args []string) error {
	fs := flag.NewFlagSet("sid", flag.ExitOnError)
	file := fs.String("file", "", "captured client stream")
	_ = fs.Parse(args)

	stream, err := os.ReadFile(*file)
	if err != nil {
		return err
	}
	sid, err := sessionIDOf(stream)
	if err != nil {
		return err
	}
	fmt.Println(hex.EncodeToString(sid))
	return nil
}

// connectedReplySocket returns a UDP socket bound to local (with
// SO_REUSEADDR, sharing the echo listener's address) and connected to
// remote, so replies originate from the echo address itself.
func connectedReplySocket(local, remote *net.UDPAddr) (net.Conn, error) {
	fd, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return nil, err
	}
	if err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	localAddr := &syscall.SockaddrInet4{Port: local.Port}
	copy(localAddr.Addr[:], local.IP.To4())
	if err = syscall.Bind(fd, localAddr); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	remoteAddr := &syscall.SockaddrInet4{Port: remote.Port}
	copy(remoteAddr.Addr[:], remote.IP.To4())
	if err = syscall.Connect(fd, remoteAddr); err != nil {
		syscall.Close(fd)
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "udp-reply")
	conn, err := net.FileConn(file)
	if err != nil {
		file.Close()
		return nil, err
	}
	return conn, nil
}

// runUDPClient performs a SOCKS5 UDP-associate against the client
// sing-box, sends one framed packet to the UDP echo server through the
// relay, and verifies the echo payload returns verbatim.
func runUDPClient(args []string) error {
	fs := flag.NewFlagSet("udpclient", flag.ExitOnError)
	socksAddr := fs.String("socks", "127.0.0.1:11080", "SOCKS5 address of the client sing-box")
	echoAddr := fs.String("echo", "127.0.0.1:15353", "UDP echo server address")
	_ = fs.Parse(args)

	payload := []byte("musess-udp-probe-0123456789")
	ctrl, err := net.DialTimeout("tcp", *socksAddr, 5*time.Second)
	if err != nil {
		return err
	}
	defer ctrl.Close()
	_ = ctrl.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err = ctrl.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	authResp := make([]byte, 2)
	if _, err = io.ReadFull(ctrl, authResp); err != nil {
		return err
	}
	if authResp[0] != 0x05 || authResp[1] != 0x00 {
		return fmt.Errorf("no-auth negotiation rejected: %x", authResp)
	}
	// UDP ASSOCIATE request
	if _, err = ctrl.Write([]byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}
	head := make([]byte, 4)
	if _, err = io.ReadFull(ctrl, head); err != nil {
		return err
	}
	if head[1] != 0x00 || head[3] != 0x01 {
		return fmt.Errorf("associate failed: %x", head)
	}
	relayIP := make([]byte, 4)
	if _, err = io.ReadFull(ctrl, relayIP); err != nil {
		return err
	}
	relayPortBytes := make([]byte, 2)
	if _, err = io.ReadFull(ctrl, relayPortBytes); err != nil {
		return err
	}
	relayAddr := &net.UDPAddr{
		IP:   net.IP(relayIP),
		Port: int(relayPortBytes[0])<<8 | int(relayPortBytes[1]),
	}
	fmt.Println("udp relay bound at", relayAddr.String())

	echoUDP, err := net.ResolveUDPAddr("udp", *echoAddr)
	if err != nil {
		return err
	}
	udpConn, err := net.DialUDP("udp", nil, relayAddr)
	if err != nil {
		return err
	}
	defer udpConn.Close()
	_ = udpConn.SetDeadline(time.Now().Add(10 * time.Second))
	packet := []byte{0x00, 0x00, 0x00, 0x01}
	packet = append(packet, echoUDP.IP.To4()...)
	packet = append(packet, byte(echoUDP.Port>>8), byte(echoUDP.Port))
	packet = append(packet, payload...)
	if _, err = udpConn.Write(packet); err != nil {
		return err
	}
	response := make([]byte, 65535)
	n, err := udpConn.Read(response)
	if err != nil {
		return fmt.Errorf("no echo received: %w", err)
	}
	if n < len(payload) || string(response[n-len(payload):n]) != string(payload) {
		return fmt.Errorf("echo payload mismatch: %q", response[:n])
	}
	fmt.Println("UDP TEST PASS: echo payload returned verbatim through the tunnel")
	return nil
}

func runUDPEcho(args []string) error {
	fs := flag.NewFlagSet("udpecho", flag.ExitOnError)
	addr := fs.String("addr", "127.0.0.1:15353", "listen address")
	_ = fs.Parse(args)

	udpAddr, err := net.ResolveUDPAddr("udp", *addr)
	if err != nil {
		return err
	}
	// SO_REUSEADDR on the listener as well, so per-peer reply sockets
	// can bind the same address (see connectedReplySocket).
	listenConfig := net.ListenConfig{Control: func(network, address string, c syscall.RawConn) error {
		return c.Control(func(fd uintptr) {
			_ = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1)
		})
	}}
	packetConn, err := listenConfig.ListenPacket(context.Background(), "udp", *addr)
	if err != nil {
		return err
	}
	conn := packetConn.(*net.UDPConn)
	fmt.Println("udpecho listening on", *addr)
	buffer := make([]byte, 65535)
	// Replies must come from this same address (a connected peer
	// socket filters by source port) and must use a CONNECTED socket:
	// this sandbox drops sendto() on unconnected UDP sockets with
	// EPERM, while connected sockets work (verified empirically;
	// stock sing-box's unconnected direct-outbound UDP fails here
	// for the same reason). So each peer gets a reply socket that is
	// bound to the echo address with SO_REUSEADDR and connected to
	// the peer.
	peers := make(map[string]net.Conn)
	for {
		n, remote, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "udpecho: got %d bytes from %s: %q\n", n, remote, buffer[:n])
		peer, ok := peers[remote.String()]
		if !ok {
			peer, err = connectedReplySocket(udpAddr, remote)
			if err != nil {
				fmt.Fprintf(os.Stderr, "udpecho: reply socket error: %v\n", err)
				continue
			}
			peers[remote.String()] = peer
		}
		if _, werr := peer.Write(buffer[:n]); werr != nil {
			fmt.Fprintf(os.Stderr, "udpecho: reply write error: %v\n", werr)
		}
	}
}

// ---------------------------------------------------------------------------
// shim: user-space TCP impairment shim (milestone-2 bench infrastructure)
//
// Model (be precise — this is NOT packet loss and NOT netem):
//   - The shim is a plain TCP relay: it listens on -listen, dials -target
//     for each accepted connection, and splices the two directions.
//   - Each direction reads the source in -chunk KiB reads. Every chunk is
//     timestamped on arrival and released to the destination no earlier
//     than arrival + -delay-ms (fixed store-and-forward delay, per chunk,
//     per direction), strictly preserving chunk order: a single writer
//     goroutine per direction sleeps until the head chunk's release time
//     and writes chunks in arrival order.
//   - Hold model (-hold-prob P, -hold-ms M): each chunk independently,
//     with probability P, has M extra milliseconds added to its own
//     release time. Because the writer is strictly ordered, a held chunk
//     blocks every chunk queued behind it until it is released — this
//     emulates the head-of-line stall a lost segment causes on a TCP
//     byte stream (where the receiver cannot deliver later bytes until
//     the retransmission arrives). No bytes are ever dropped, duplicated
//     or reordered; all impairment is delay. Reports and scripts must
//     describe it as a "delay/hold" model, never as packet loss.
//   - Throughput note: chunks are pipelined through a deep release queue
//     (4096 chunks), so a fixed delay adds latency without capping
//     steady-state throughput until the queue's bytes/delay ceiling
//     (4096*chunkKiB per delay interval) is reached.
//   - On SIGINT/SIGTERM the shim prints total forwarded byte counts per
//     direction and the connection count, then exits.
func runShim(args []string) error {
	fs := flag.NewFlagSet("shim", flag.ExitOnError)
	listenAddr := fs.String("listen", "", "listen address, e.g. 127.0.0.1:15451")
	targetAddr := fs.String("target", "", "forward target address, e.g. 127.0.0.1:14443")
	delayMs := fs.Int("delay-ms", 0, "fixed store-and-forward delay per chunk, milliseconds")
	holdProb := fs.Float64("hold-prob", 0, "probability a chunk gets an extra hold (0..1)")
	holdMs := fs.Int("hold-ms", 0, "extra hold added to a chunk's release time, milliseconds")
	chunkKB := fs.Int("chunk", 16, "read chunk size, KiB")
	_ = fs.Parse(args)
	if *listenAddr == "" || *targetAddr == "" {
		return fmt.Errorf("shim requires -listen and -target")
	}
	if *holdProb < 0 || *holdProb > 1 {
		return fmt.Errorf("shim: -hold-prob must be in [0,1]")
	}

	var bytesUp, bytesDown, connCount atomic.Int64

	listener, err := net.Listen("tcp", *listenAddr)
	if err != nil {
		return err
	}
	fmt.Printf("shim listening on %s -> %s (delay/hold model, NOT packet loss: delay=%dms hold-prob=%g hold=%dms chunk=%dKiB)\n",
		*listenAddr, *targetAddr, *delayMs, *holdProb, *holdMs, *chunkKB)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Printf("shim exit: bytes client->target=%d target->client=%d connections=%d\n",
			bytesUp.Load(), bytesDown.Load(), connCount.Load())
		os.Exit(0)
	}()

	for {
		client, err := listener.Accept()
		if err != nil {
			return err
		}
		connCount.Add(1)
		go func(client net.Conn) {
			defer client.Close()
			target, err := net.DialTimeout("tcp", *targetAddr, 10*time.Second)
			if err != nil {
				return
			}
			defer target.Close()
			done := make(chan struct{}, 2)
			go func() {
				shimPump(client, target, *delayMs, *holdProb, *holdMs, *chunkKB, &bytesUp)
				done <- struct{}{}
			}()
			go func() {
				shimPump(target, client, *delayMs, *holdProb, *holdMs, *chunkKB, &bytesDown)
				done <- struct{}{}
			}()
			<-done
		}(client)
	}
}

// shimPump forwards src -> dst applying the delay/hold model described
// on runShim. It half-closes dst's write side when src reaches EOF so
// the peer sees a clean end of stream, and adds forwarded bytes to
// counter.
func shimPump(src, dst net.Conn, delayMs int, holdProb float64, holdMs int, chunkKB int, counter *atomic.Int64) {
	type timedChunk struct {
		data    []byte
		release time.Time
	}
	// Deep queue: pipelining headroom so fixed delay does not become a
	// throughput cap at bench rates (see runShim comment).
	queue := make(chan timedChunk, 4096)
	writerDone := make(chan struct{})
	go func() {
		defer close(writerDone)
		for tc := range queue {
			if wait := time.Until(tc.release); wait > 0 {
				time.Sleep(wait)
			}
			data := tc.data
			for len(data) > 0 {
				n, err := dst.Write(data)
				if err != nil {
					// Drain the queue so the reader never blocks on a
					// dead destination, then stop.
					go func() {
						for range queue {
						}
					}()
					return
				}
				counter.Add(int64(n))
				data = data[n:]
			}
		}
	}()
	rng := mrand.New(mrand.NewSource(time.Now().UnixNano()))
	delay := time.Duration(delayMs) * time.Millisecond
	hold := time.Duration(holdMs) * time.Millisecond
	buf := make([]byte, chunkKB*1024)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			arrival := time.Now()
			release := arrival.Add(delay)
			if holdProb > 0 && rng.Float64() < holdProb {
				release = release.Add(hold)
			}
			chunk := make([]byte, n)
			copy(chunk, buf[:n])
			queue <- timedChunk{data: chunk, release: release}
		}
		if err != nil {
			break
		}
	}
	close(queue)
	<-writerDone
	if tcpConn, ok := dst.(*net.TCPConn); ok {
		_ = tcpConn.CloseWrite()
	}
}

// ---------------------------------------------------------------------------
// bulkserver / bulkclient: bulk-transfer goodput tools
//
// bulkserver listens on 127.0.0.1:-port and, per connection, streams an
// endless repeating 64 KiB pattern until the peer goes away.
//
// bulkclient dials -addr (optionally through a SOCKS5 proxy given by
// -socks, in which case -addr is the ultimate target), reads exactly
// -bytes bytes as fast as it can, and prints one line:
//
//	bytes=<n> seconds=<f> mbps=<f>
//
// The timer starts just before dialling (so connection/handshake cost
// of the leg under test is included) and stops when the last byte has
// been read. mbps is decimal megabits per second (bytes*8/seconds/1e6).
func runBulkServer(args []string) error {
	fs := flag.NewFlagSet("bulkserver", flag.ExitOnError)
	port := fs.Int("port", 0, "TCP port to listen on (127.0.0.1)")
	_ = fs.Parse(args)
	if *port <= 0 {
		return fmt.Errorf("bulkserver requires -port")
	}
	listener, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(*port))
	if err != nil {
		return err
	}
	fmt.Println("bulkserver listening on", listener.Addr())
	pattern := make([]byte, 64*1024)
	for i := range pattern {
		pattern[i] = byte(i % 251)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go func(conn net.Conn) {
			defer conn.Close()
			for {
				if _, err := conn.Write(pattern); err != nil {
					return
				}
			}
		}(conn)
	}
}

func runBulkClient(args []string) error {
	fs := flag.NewFlagSet("bulkclient", flag.ExitOnError)
	addr := fs.String("addr", "", "target address host:port to read from")
	socks := fs.String("socks", "", "optional SOCKS5 proxy address host:port; -addr is then the target reached through it")
	numBytes := fs.Int64("bytes", 32<<20, "number of bytes to read")
	_ = fs.Parse(args)
	if *addr == "" {
		return fmt.Errorf("bulkclient requires -addr")
	}

	start := time.Now()
	var conn net.Conn
	var err error
	if *socks != "" {
		conn, err = socks5Dial(*socks, *addr)
	} else {
		conn, err = net.DialTimeout("tcp", *addr, 10*time.Second)
	}
	if err != nil {
		return err
	}
	defer conn.Close()

	buf := make([]byte, 256*1024)
	var got int64
	for got < *numBytes {
		want := int64(len(buf))
		if rem := *numBytes - got; rem < want {
			want = rem
		}
		n, rerr := conn.Read(buf[:want])
		got += int64(n)
		if rerr != nil {
			return fmt.Errorf("bulkclient: read %d of %d bytes: %w", got, *numBytes, rerr)
		}
	}
	seconds := time.Since(start).Seconds()
	mbps := float64(got) * 8 / seconds / 1e6
	fmt.Printf("bytes=%d seconds=%.3f mbps=%.2f\n", got, seconds, mbps)
	return nil
}

// socks5Dial connects to targetAddr (IPv4 host:port) through the
// SOCKS5 proxy at proxyAddr using no-auth CONNECT, and returns the
// tunnelled connection.
func socks5Dial(proxyAddr, targetAddr string) (net.Conn, error) {
	host, portStr, err := net.SplitHostPort(targetAddr)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("bulkclient: -addr host must be an IPv4 address, got %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, err
	}
	fail := func(err error) (net.Conn, error) {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return fail(err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return fail(err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		return fail(fmt.Errorf("bulkclient: SOCKS no-auth negotiation rejected: %x", resp))
	}
	req := []byte{0x05, 0x01, 0x00, 0x01}
	req = append(req, ip.To4()...)
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return fail(err)
	}
	head := make([]byte, 4)
	if _, err := io.ReadFull(conn, head); err != nil {
		return fail(err)
	}
	if head[1] != 0x00 {
		return fail(fmt.Errorf("bulkclient: SOCKS CONNECT failed, rep=%d", head[1]))
	}
	switch head[3] {
	case 0x01:
		skip := make([]byte, 4+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			return fail(err)
		}
	case 0x03:
		lenByte := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenByte); err != nil {
			return fail(err)
		}
		skip := make([]byte, int(lenByte[0])+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			return fail(err)
		}
	case 0x04:
		skip := make([]byte, 16+2)
		if _, err := io.ReadFull(conn, skip); err != nil {
			return fail(err)
		}
	default:
		return fail(fmt.Errorf("bulkclient: SOCKS reply has unknown atyp %d", head[3]))
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}
