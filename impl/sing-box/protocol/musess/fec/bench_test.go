package fec

// Head-to-head candidate comparison harness (Emma's method: test
// several approaches on the same rig, pick by measurement in the
// order goodput > camouflage/overhead > latency).
//
// Carrier: an ordered stream (net.Pipe) with a record-aware shim
// that drops/delays whole FEC records — the loss unit is one FEC
// record, matching the future one-record-per-datagram QUIC
// mapping. Delay is applied by blocking the shim's Write until the
// record's release time, so backpressure propagates into the
// sender's queue (and its saturation signal) exactly as a slow
// link would cause. This is a user-space record shim, NOT kernel
// netem; numbers are labelled "measured in this environment".
//
// Run with: MUSESS_FEC_BENCH=1 go test -run TestBenchComparison -v ./protocol/musess/fec/

import (
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"sort"
	"sync"
	"testing"
	"time"
)

// shimConn wraps the write side of a connection: it parses whole
// FEC records out of the byte stream, applies the loss model, and
// releases records in order at a fixed per-record service time.
type shimConn struct {
	net.Conn
	mu        sync.Mutex
	buf       []byte
	rng       *rand.Rand
	loss      float64
	burst     bool // Gilbert-style: bad state drops at burstLoss
	inBad     bool
	burstLoss float64
	pBad      float64 // P(good -> bad) per record
	pGood     float64 // P(bad -> good) per record
	service   time.Duration
	nextFree  time.Time
	dropped   int
	forwarded int
}

func newShimConn(conn net.Conn, loss float64, seed int64, service time.Duration) *shimConn {
	return &shimConn{Conn: conn, rng: rand.New(rand.NewSource(seed)), loss: loss, service: service}
}

func (c *shimConn) drop() bool {
	if c.burst {
		if c.inBad {
			if c.rng.Float64() < c.pGood {
				c.inBad = false
			}
		} else if c.rng.Float64() < c.pBad {
			c.inBad = true
		}
		if c.inBad {
			return c.rng.Float64() < c.burstLoss
		}
		return false
	}
	return c.rng.Float64() < c.loss
}

func (c *shimConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = append(c.buf, p...)
	for len(c.buf) >= recordHeaderLen {
		payloadLen := int(binary.BigEndian.Uint16(c.buf[8:10]))
		total := recordHeaderLen + payloadLen
		if len(c.buf) < total {
			break
		}
		rec := append([]byte(nil), c.buf[:total]...)
		c.buf = c.buf[total:]
		// Feedback records are control traffic: forward undropped
		// but still through the service delay.
		isFeedback := rec[0] == recordFeedback
		if !isFeedback && c.drop() {
			c.dropped++
			continue
		}
		if c.service > 0 {
			now := time.Now()
			if c.nextFree.Before(now) {
				c.nextFree = now
			}
			c.nextFree = c.nextFree.Add(c.service)
			if wait := time.Until(c.nextFree); wait > 0 {
				time.Sleep(wait)
			}
		}
		if _, err := c.Conn.Write(rec); err != nil {
			return 0, err
		}
		c.forwarded++
	}
	return len(p), nil
}

type benchResult struct {
	label       string
	sent        int
	delivered   int
	goodputMbps float64
	delivery    float64
	overhead    float64
	recovered   uint64
	lost        uint64
	finalRedund float64
	p50Ms       float64
	p95Ms       float64
}

func runTransfer(t *testing.T, codec Codec, ctrl Controller, loss float64, burst bool, offeredMbps float64, linkMbps float64, count int, size int, seed int64) benchResult {
	t.Helper()
	a, b := net.Pipe()
	// Service time per record emulates the link rate for records
	// of ~size bytes. Non-saturation runs set the link ~18% above
	// the offered load so queues stay short; saturation runs set
	// the link far below the offered load.
	service := time.Duration(float64(size+recordHeaderLen) * 8 / (linkMbps * 1e6) * float64(time.Second))
	shimAB := newShimConn(a, loss, seed, service)
	shimBA := newShimConn(b, 0, seed+1, service)
	if burst {
		// Gilbert model tuned for the target average loss with a
		// mean burst length of ~8 records: pGood = 1/8; average
		// loss = pi_bad * burstLoss; choose burstLoss = 0.5 and
		// pi_bad = loss/0.5 -> pBad from stationary distribution.
		shimAB.burst = true
		shimAB.burstLoss = 0.5
		shimAB.pGood = 1.0 / 8
		piBad := loss / 0.5
		if piBad >= 0.95 {
			piBad = 0.95
		}
		shimAB.pBad = piBad * shimAB.pGood / (1 - piBad)
	}
	opts := Options{
		Mode:             ModePacket,
		MaxShard:         1400,
		FlushInterval:    5 * time.Millisecond, // production default
		FeedbackInterval: 100 * time.Millisecond,
		GroupTimeout:     150 * time.Millisecond,
	}
	sender := NewConn(shimAB, codec, ctrl, opts)
	receiver := NewConn(shimBA, codec, staticController{}, opts)
	defer sender.Close()
	defer receiver.Close()

	payload := make([]byte, size)
	rand.New(rand.NewSource(5)).Read(payload)
	interval := time.Duration(float64(size) * 8 / (offeredMbps * 1e6) * float64(time.Second))
	start := time.Now()
	sendDone := make(chan struct{})
	go func() {
		defer close(sendDone)
		for i := 0; i < count; i++ {
			msg := make([]byte, size)
			copy(msg, payload)
			binary.BigEndian.PutUint32(msg[0:4], uint32(i))
			binary.BigEndian.PutUint64(msg[8:16], uint64(time.Now().UnixNano()))
			if err := sender.WriteMessage(msg); err != nil {
				return
			}
			if interval > 0 {
				target := start.Add(time.Duration(i+1) * interval)
				if wait := time.Until(target); wait > 0 {
					time.Sleep(wait)
				}
			}
		}
	}()

	delivered := 0
	var latencies []float64
	seen := make(map[uint32]bool)
	recvDeadline := time.After(60 * time.Second)
	drainUntil := time.Now().Add(60 * time.Second)
loop:
	for delivered < count && time.Now().Before(drainUntil) {
		type res struct {
			msg []byte
			err error
		}
		ch := make(chan res, 1)
		go func() {
			msg, err := receiver.ReadMessage()
			ch <- res{msg, err}
		}()
		select {
		case r := <-ch:
			if r.err != nil {
				break loop
			}
			seq := binary.BigEndian.Uint32(r.msg[0:4])
			if !seen[seq] {
				seen[seq] = true
				delivered++
				sentNs := int64(binary.BigEndian.Uint64(r.msg[8:16]))
				latencies = append(latencies, float64(time.Now().UnixNano()-sentNs)/1e6)
			}
		case <-recvDeadline:
			break loop
		}
	}
	<-sendDone
	elapsed := time.Since(start).Seconds()
	stats := sender.Stats()
	res := benchResult{
		sent:        count,
		delivered:   delivered,
		delivery:    float64(delivered) / float64(count),
		goodputMbps: float64(delivered*size) * 8 / elapsed / 1e6,
		overhead:    stats.OverheadRatio(),
		recovered:   receiver.Stats().ShardsRecovered,
		lost:        receiver.Stats().ShardsLost,
		finalRedund: sender.Redundancy(),
	}
	if len(latencies) > 0 {
		sort.Float64s(latencies)
		res.p50Ms = latencies[len(latencies)/2]
		res.p95Ms = latencies[int(float64(len(latencies))*0.95)]
	}
	return res
}

func TestBenchComparison(t *testing.T) {
	if os.Getenv("MUSESS_FEC_BENCH") == "" {
		t.Skip("set MUSESS_FEC_BENCH=1 to run the comparison harness")
	}
	const count = 4000
	const size = 1200
	const offered = 20.0 // Mbps

	fmt.Println("\n=== FEC candidate comparison (record shim, ordered stream carrier, 20 Mbps offered, 4000x1200B) ===")
	fmt.Printf("%-28s %6s %8s %9s %8s %9s %9s %7s\n", "config", "loss%", "deliv%", "goodput", "ovhd%", "recov", "lost", "finalR%")
	losses := []float64{0, 0.01, 0.03, 0.05, 0.10, 0.15}
	configs := []struct {
		label string
		codec func() Codec
		ctrl  func() Controller
	}{
		{"none (baseline)", func() Codec { return NewRSCodec(16) }, func() Controller { return staticController{r: 0} }},
		{"xor + fixed-step", func() Codec { return XORCodec{} }, func() Controller { return NewController("fixed-step", 0) }},
		{"xor + estimator", func() Codec { return XORCodec{} }, func() Controller { return NewController("estimator", 0) }},
		{"rs + fixed-step", func() Codec { return NewRSCodec(16) }, func() Controller { return NewController("fixed-step", 0) }},
		{"rs + estimator", func() Codec { return NewRSCodec(16) }, func() Controller { return NewController("estimator", 0) }},
	}
	for _, cfg := range configs {
		for _, loss := range losses {
			res := runTransfer(t, cfg.codec(), cfg.ctrl(), loss, false, offered, offered/0.85, count, size, 1234)
			fmt.Printf("%-28s %6.0f %8.2f %8.2fM %8.2f %9d %9d %7.1f\n",
				cfg.label, loss*100, res.delivery*100, res.goodputMbps, res.overhead*100, res.recovered, res.lost, res.finalRedund*100)
		}
	}

	fmt.Println("\n=== burst loss (Gilbert, mean burst ~8 records, burst drop 50%) ===")
	for _, cfg := range configs[1:] {
		for _, loss := range []float64{0.05, 0.10} {
			res := runTransfer(t, cfg.codec(), cfg.ctrl(), loss, true, offered, offered/0.85, count, size, 777)
			fmt.Printf("%-28s %6.0f %8.2f %8.2fM %8.2f %9d %9d %7.1f\n",
				cfg.label+" (burst)", loss*100, res.delivery*100, res.goodputMbps, res.overhead*100, res.recovered, res.lost, res.finalRedund*100)
		}
	}

	fmt.Println("\n=== saturation: offered 100 Mbps into a 23 Mbps service-rate shim ===")
	for _, cfg := range configs[1:] {
		res := runTransfer(t, cfg.codec(), cfg.ctrl(), 0.05, false, 100.0, 23.0, count, size, 4242)
		fmt.Printf("%-28s %6.0f %8.2f %8.2fM %8.2f %9d %9d %7.1f\n",
			cfg.label+" (sat)", 5.0, res.delivery*100, res.goodputMbps, res.overhead*100, res.recovered, res.lost, res.finalRedund*100)
	}
	// No-yield control: raw inner controllers without the wrapper.
	fmt.Println("--- saturation, yield wrapper disabled (control) ---")
	for _, inner := range []struct {
		label string
		codec Codec
		ctrl  Controller
	}{
		{"rs + estimator (noyield)", NewRSCodec(16), NewEstimatorController()},
		{"rs + fixed-step (noyield)", NewRSCodec(16), NewStepController()},
	} {
		res := runTransfer(t, inner.codec, inner.ctrl, 0.05, false, 100.0, 23.0, count, size, 4242)
		fmt.Printf("%-28s %6.0f %8.2f %8.2fM %8.2f %9d %9d %7.1f\n",
			inner.label, 5.0, res.delivery*100, res.goodputMbps, res.overhead*100, res.recovered, res.lost, res.finalRedund*100)
	}

	fmt.Println("\n=== latency: 100 msg/s trickle, 5% uniform loss (delivered messages only) ===")
	for _, cfg := range configs {
		res := runTransfer(t, cfg.codec(), cfg.ctrl(), 0.05, false, 0.96, 1.13, 300, size, 31337)
		fmt.Printf("%-28s deliv=%6.2f%% p50=%7.1fms p95=%7.1fms ovhd=%5.2f%%\n",
			cfg.label, res.delivery*100, res.p50Ms, res.p95Ms, res.overhead*100)
	}
}

// Codec CPU cost: encode+reconstruct throughput on 16x1400B groups.
func BenchmarkCodecEncode(b *testing.B) {
	data := make([][]byte, 16)
	for i := range data {
		data[i] = make([]byte, 1400)
		rand.New(rand.NewSource(int64(i))).Read(data[i])
	}
	b.Run("xor", func(b *testing.B) {
		codec := XORCodec{}
		b.SetBytes(16 * 1400)
		for i := 0; i < b.N; i++ {
			if _, err := codec.Encode(data, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("reed-solomon-r3", func(b *testing.B) {
		codec := NewRSCodec(16)
		b.SetBytes(16 * 1400)
		for i := 0; i < b.N; i++ {
			if _, err := codec.Encode(data, 3); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func BenchmarkCodecReconstruct(b *testing.B) {
	data := make([][]byte, 16)
	for i := range data {
		data[i] = make([]byte, 1400)
		rand.New(rand.NewSource(int64(i))).Read(data[i])
	}
	b.Run("xor-1-loss", func(b *testing.B) {
		codec := XORCodec{}
		parity, _ := codec.Encode(data, 1)
		b.SetBytes(16 * 1400)
		for i := 0; i < b.N; i++ {
			shards := append(cloneShards(data), parity[0])
			shards[3] = nil
			if _, err := codec.Reconstruct(shards, 16, 1); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("reed-solomon-3-loss", func(b *testing.B) {
		codec := NewRSCodec(16)
		parity, _ := codec.Encode(data, 3)
		b.SetBytes(16 * 1400)
		for i := 0; i < b.N; i++ {
			shards := append(cloneShards(data), cloneShards(parity)...)
			shards[2] = nil
			shards[9] = nil
			shards[14] = nil
			if _, err := codec.Reconstruct(shards, 16, 3); err != nil {
				b.Fatal(err)
			}
		}
	})
}
