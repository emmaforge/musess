package fec

import (
	"encoding/binary"
	"io"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// uoActive reports whether unordered packet delivery is in
// effect for this Conn (experiment flag, packet mode only).
func (c *Conn) uoActive() bool {
	return c.opts.PacketOutOfOrder && c.opts.Mode == ModePacket
}

// Mode selects how the application payload maps to shards.
type Mode int

const (
	// ModeStream treats the payload as a byte stream: Write splits
	// into shard-size chunks, Read reassembles. An unrecoverable
	// group is fatal (a byte stream cannot skip bytes).
	ModeStream Mode = iota
	// ModePacket treats each WriteMessage call as one message (one
	// shard). Unrecoverable shards are dropped and counted, which
	// is the correct semantics for proxied UDP packets.
	ModePacket
)

// Options tunes a Conn. Zero values get the defaults noted.
type Options struct {
	Mode             Mode
	MaxShard         int           // max data shard payload, default 1400
	FlushInterval    time.Duration // partial-group flush delay, default 5ms
	FeedbackInterval time.Duration // receiver report period, default 200ms
	GroupTimeout     time.Duration // receiver group expiry, default 250ms
	SaturationBytes  int           // send-queue backlog threshold, default 256KiB
	// OnClose, if set, receives the final connection accounting
	// when the Conn is closed (DESIGN.md 5.4: per-connection
	// shaping overhead must be observable).
	OnClose func(Stats)

	// --- experiment fields (flagged observations, 2026-11-05) ---
	// All default to the milestone-2 production behaviour; they
	// exist so the treatments in experiment.go's README verdicts
	// can be measured in the fixed harness and the e2e. They are
	// measurement scaffolding, not product surface.

	// PacketOutOfOrder (packet mode only): deliver each group as
	// soon as it resolves instead of in strict group order, so a
	// fully-lost group no longer stalls recoverable data behind
	// it (partial preservation, DESIGN.md 5.2). Stream mode
	// ignores it: a byte stream cannot skip.
	PacketOutOfOrder bool
	// EagerGapSynthesis: declare a never-seen group lost as soon
	// as a later group's arrival proves it (the record carrier is
	// ordered, so a later record is proof the earlier slot's
	// records were dropped), instead of waiting for arrivals to
	// pause for a full GroupTimeout. This feeds feedback — and
	// ordered delivery — mid-stream instead of after pauses.
	EagerGapSynthesis bool
	// GapProofGrace is how long after that proof the eager
	// declaration waits; 0 fires at the first expiry tick. It
	// exists for future unordered carriers (QUIC datagrams),
	// where reordering makes instant proof unsound.
	GapProofGrace time.Duration
}

func (o *Options) applyDefaults() {
	if o.MaxShard <= 0 {
		o.MaxShard = 1400
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = 5 * time.Millisecond
	}
	if o.FeedbackInterval <= 0 {
		o.FeedbackInterval = 200 * time.Millisecond
	}
	if o.GroupTimeout <= 0 {
		o.GroupTimeout = 250 * time.Millisecond
	}
	if o.SaturationBytes <= 0 {
		o.SaturationBytes = 256 * 1024
	}
}

// rawChunkSize is the payload size of raw (ungrouped) records used
// in stream mode while redundancy is zero: header cost ~0.03%.
const rawChunkSize = 32768

// Stats is the per-connection accounting used for the shaping
// budget (DESIGN.md 5.4): overhead = (HeaderBytes + ParityBytes) /
// WireBytes, all measurable locally per connection.
type Stats struct {
	AppBytesOut     uint64 // payload bytes accepted from the application
	WireBytesOut    uint64 // all record bytes written
	HeaderBytesOut  uint64
	ParityBytesOut  uint64 // parity record payloads (incl. length trailers)
	AppBytesIn      uint64
	WireBytesIn     uint64
	GroupsSent      uint64
	GroupsReceived  uint64
	ShardsRecovered uint64
	ShardsLost      uint64
}

// OverheadRatio returns the fraction of outgoing wire bytes that
// were not application payload (headers + parity + padding).
func (s Stats) OverheadRatio() float64 {
	if s.WireBytesOut == 0 {
		return 0
	}
	return float64(s.HeaderBytesOut+s.ParityBytesOut) / float64(s.WireBytesOut)
}

type queuedMessage struct {
	data []byte
	raw  bool // emit as raw record, not as a group shard
}

// Conn is one FEC-protected direction pair over an underlying
// ordered connection: it sends with the local codec+controller and
// receives with the same codec, reporting feedback to the peer and
// consuming the peer's feedback into the local controller. It
// implements net.Conn (stream mode) and a message API (packet mode).
type Conn struct {
	conn  net.Conn
	codec Codec
	ctrl  Controller
	opts  Options

	sendQueue  chan queuedMessage
	ctrlQueue  chan record
	delivered  chan []byte
	closing    chan struct{}
	sendDone   chan struct{}
	recvDone   chan struct{}
	closeOnce  sync.Once
	queuedByte atomic.Int64
	backlogged atomic.Bool

	recvMu       sync.Mutex
	recvGroups   map[uint32]*recvGroup
	pending      map[uint32]*groupResult
	deliverNext  uint32
	started      bool // delivery starts at the first group ID seen
	recvFinished bool
	maxGroupSeen uint32
	maxGroupTime time.Time
	feedbackAcc  Feedback
	readErr      error
	readBuf      []byte

	// Experiment state (only touched when the matching Options
	// flag is on): uoDelivered tracks groups already handed to
	// the consumer out of order, feeding the stale-record guard;
	// gapProof* records when a later group first proved the
	// cursor group never arrived.
	uoDelivered  map[uint32]bool
	gapProofSet  bool
	gapProofFor  uint32
	gapProofTime time.Time

	stats struct {
		appOut     atomic.Uint64
		wireOut    atomic.Uint64
		headerOut  atomic.Uint64
		parityOut  atomic.Uint64
		appIn      atomic.Uint64
		wireIn     atomic.Uint64
		groupsSent atomic.Uint64
		groupsRecv atomic.Uint64
		recovered  atomic.Uint64
		lost       atomic.Uint64
	}
}

// NewConn starts the FEC layer over conn. codec and ctrl govern the
// sending direction; the receiving direction uses the same codec
// (both ends are built from the same musess version and the group
// headers carry k/r, so the receiver needs no negotiation).
func NewConn(conn net.Conn, codec Codec, ctrl Controller, opts Options) *Conn {
	opts.applyDefaults()
	c := &Conn{
		conn:       conn,
		codec:      codec,
		ctrl:       ctrl,
		opts:       opts,
		sendQueue:  make(chan queuedMessage, 4096),
		ctrlQueue:  make(chan record, 64),
		delivered:  make(chan []byte, 1024),
		closing:    make(chan struct{}),
		sendDone:   make(chan struct{}),
		recvDone:   make(chan struct{}),
		recvGroups: make(map[uint32]*recvGroup),
		pending:    make(map[uint32]*groupResult),
	}
	if c.uoActive() {
		c.uoDelivered = make(map[uint32]bool)
	}
	go c.sendLoop()
	go c.recvLoop()
	go c.feedbackLoop()
	go c.expiryLoop()
	return c
}

// --- sending ---

// Write implements io.Writer for stream mode: p is split into
// shards (or raw chunks while redundancy is zero) and queued.
func (c *Conn) Write(p []byte) (int, error) {
	if c.opts.Mode != ModeStream {
		return 0, ErrClosed
	}
	select {
	case <-c.closing:
		return 0, ErrClosed
	default:
	}
	written := 0
	for len(p) > 0 {
		if c.ctrl.Redundancy() <= 0 {
			chunk := p
			if len(chunk) > rawChunkSize {
				chunk = chunk[:rawChunkSize]
			}
			if err := c.enqueue(queuedMessage{data: append([]byte(nil), chunk...), raw: true}); err != nil {
				return written, err
			}
			written += len(chunk)
			p = p[len(chunk):]
		} else {
			chunk := p
			if len(chunk) > c.opts.MaxShard {
				chunk = chunk[:c.opts.MaxShard]
			}
			if err := c.enqueue(queuedMessage{data: append([]byte(nil), chunk...)}); err != nil {
				return written, err
			}
			written += len(chunk)
			p = p[len(chunk):]
		}
	}
	c.stats.appOut.Add(uint64(written))
	return written, nil
}

// WriteMessage queues one message (packet mode). Messages larger
// than MaxShard bypass grouping as raw records (they cannot be
// protected without fragmentation; see README). All other messages
// are grouped even at zero redundancy — groups with r=0 still give
// the receiver the accounting it needs to report loss feedback, so
// an adaptive controller can engage later; raw-at-zero would
// starve the feedback loop (found by test).
func (c *Conn) WriteMessage(p []byte) error {
	if c.opts.Mode != ModePacket {
		return ErrClosed
	}
	msg := queuedMessage{data: append([]byte(nil), p...), raw: len(p) > c.opts.MaxShard}
	if err := c.enqueue(msg); err != nil {
		return err
	}
	c.stats.appOut.Add(uint64(len(p)))
	return nil
}

// writeHighWater bounds how far ahead of the wire the async
// writer may run. Without it, a fast producer on a slow link
// accumulates unbounded queue, and Close-time semantics drift
// from the synchronous net.Conn contract callers expect.
const writeHighWater = 4 * 1024 * 1024

func (c *Conn) enqueue(msg queuedMessage) error {
	// Backpressure: block while the queue is far ahead of the
	// wire, so Write behaves like a bounded kernel send buffer.
	for c.queuedByte.Load() > writeHighWater {
		select {
		case <-c.closing:
			return ErrClosed
		case <-time.After(2 * time.Millisecond):
		}
	}
	c.queuedByte.Add(int64(len(msg.data)))
	select {
	case c.sendQueue <- msg:
		return nil
	case <-c.closing:
		c.queuedByte.Add(-int64(len(msg.data)))
		return ErrClosed
	}
}

func (c *Conn) sendLoop() {
	defer close(c.sendDone)
	var group [][]byte
	var groupK int
	var groupRho float64
	var groupID uint32
	flushTimer := time.NewTimer(c.opts.FlushInterval)
	if !flushTimer.Stop() {
		<-flushTimer.C
	}
	timerArmed := false
	armTimer := func() {
		if !timerArmed {
			flushTimer.Reset(c.opts.FlushInterval)
			timerArmed = true
		}
	}
	disarmTimer := func() {
		if timerArmed {
			if !flushTimer.Stop() {
				select {
				case <-flushTimer.C:
				default:
				}
			}
			timerArmed = false
		}
	}
	failWrite := func() {
		// A dead write side means the connection is over: closing
		// it unblocks the receive loop and the application.
		c.conn.Close()
	}
	emitRaw := func(data []byte) {
		n, err := writeRecord(c.conn, record{typ: recordRaw, group: groupID, payload: data})
		if err != nil {
			failWrite()
			return
		}
		groupID++
		c.stats.wireOut.Add(uint64(n))
		c.stats.headerOut.Add(recordHeaderLen)
		c.stats.groupsSent.Add(1)
	}
	emitGroup := func() {
		if len(group) == 0 {
			return
		}
		// Parity is priced against the group that actually exists,
		// not the planned size: partial groups at flush boundaries
		// must not inherit a full group's parity bill.
		k, r := len(group), c.codec.ParityFor(len(group), groupRho)
		// Records: data first, then parity (ordered transport means
		// the receiver can resolve as soon as the group is whole).
		for i, shard := range group {
			n, err := writeRecord(c.conn, record{typ: recordData, group: groupID, index: i, k: k, r: r, payload: shard})
			if err != nil {
				failWrite()
				break
			}
			c.stats.wireOut.Add(uint64(n))
			c.stats.headerOut.Add(recordHeaderLen)
		}
		if r > 0 {
			parity, err := c.encodeGroup(group, r)
			if err == nil {
				for i, p := range parity {
					payload := parityPayload(group, p)
					n, werr := writeRecord(c.conn, record{typ: recordParity, group: groupID, index: i, k: k, r: r, payload: payload})
					if werr != nil {
						failWrite()
						break
					}
					c.stats.wireOut.Add(uint64(n))
					c.stats.headerOut.Add(recordHeaderLen)
					c.stats.parityOut.Add(uint64(len(payload)))
				}
			}
		}
		c.stats.groupsSent.Add(1)
		groupID++
		group = nil
		disarmTimer()
	}
	for {
		// Saturation signal for the controller's yield rule.
		backlogged := c.queuedByte.Load() > int64(c.opts.SaturationBytes)
		if backlogged != c.backlogged.Load() {
			c.backlogged.Store(backlogged)
			c.ctrl.SetBacklogged(backlogged)
		}
		select {
		case rec := <-c.ctrlQueue:
			if n, err := writeRecord(c.conn, rec); err == nil {
				c.stats.wireOut.Add(uint64(n))
				c.stats.headerOut.Add(recordHeaderLen)
			} else {
				failWrite()
			}
		case msg := <-c.sendQueue:
			c.queuedByte.Add(-int64(len(msg.data)))
			if msg.raw {
				emitGroup()
				emitRaw(msg.data)
				continue
			}
			if len(group) == 0 {
				groupRho = c.ctrl.Redundancy()
				groupK, _ = c.codec.Plan(groupRho)
			}
			group = append(group, msg.data)
			if len(group) >= groupK {
				emitGroup()
			} else {
				armTimer()
			}
		case <-flushTimer.C:
			timerArmed = false
			emitGroup()
		case <-c.closing:
			// Drain everything still queued before the final
			// flush: Write is asynchronous (queue-based), so
			// bytes the application believes are written may
			// still sit in sendQueue at Close time, and dropping
			// them corrupts the tail of the stream (found by the
			// milestone-2 FEC e2e at 1MiB scale).
			for {
				select {
				case msg := <-c.sendQueue:
					c.queuedByte.Add(-int64(len(msg.data)))
					if msg.raw {
						emitGroup()
						emitRaw(msg.data)
						continue
					}
					if len(group) == 0 {
						groupRho = c.ctrl.Redundancy()
						groupK, _ = c.codec.Plan(groupRho)
					}
					group = append(group, msg.data)
					if len(group) >= groupK {
						emitGroup()
					}
				default:
					emitGroup()
					return
				}
			}
		}
	}
}

func (c *Conn) encodeGroup(group [][]byte, r int) ([][]byte, error) {
	maxLen := 0
	for _, shard := range group {
		if len(shard) > maxLen {
			maxLen = len(shard)
		}
	}
	padded := make([][]byte, len(group))
	for i, shard := range group {
		p := make([]byte, maxLen)
		copy(p, shard)
		padded[i] = p
	}
	return c.codec.Encode(padded, r)
}

// parityPayload prefixes the parity bytes with the true lengths of
// all data shards (uint16 each), so a rebuilt shard can be
// truncated to its real length.
func parityPayload(group [][]byte, parity []byte) []byte {
	payload := make([]byte, 2*len(group)+len(parity))
	for i, shard := range group {
		binary.BigEndian.PutUint16(payload[2*i:], uint16(len(shard)))
	}
	copy(payload[2*len(group):], parity)
	return payload
}

// --- receiving ---

type recvGroup struct {
	k, r      int
	data      [][]byte // true payloads, nil = missing
	parity    [][]byte // padded parity bytes, nil = missing
	lens      []int    // true data lengths from the parity trailer, -1 = unknown
	paddedLen int
	seen      int // records seen for this group
	firstSeen time.Time
}

type groupResult struct {
	messages  [][]byte // recovered data messages in order (packet mode: lost shards omitted)
	delivered int      // messages already handed to the delivered channel
	lost      int
	recovered int
	received  int
	expected  int
	fatal     bool // stream mode with unrecovered shards
}

func (c *Conn) recvLoop() {
	defer close(c.recvDone)
	for {
		rec, n, err := readRecord(c.conn)
		if err != nil {
			c.finishReceive(err)
			return
		}
		c.stats.wireIn.Add(uint64(n))
		switch rec.typ {
		case recordFeedback:
			if f, ok := decodeFeedback(rec.payload); ok {
				c.ctrl.OnFeedback(f)
			}
		case recordData, recordParity, recordRaw:
			c.handleShardRecord(rec)
		}
	}
}

func (c *Conn) handleShardRecord(rec record) {
	c.recvMu.Lock()
	defer c.recvMu.Unlock()
	if !c.started {
		c.started = true
		c.deliverNext = rec.group
	}
	// Stale record guard: a group that already resolved (in
	// pending) or was delivered (below deliverNext) must not be
	// recreated by its late parity records — that once produced
	// phantom all-lost resolutions polluting stats and feedback.
	if rec.group < c.deliverNext {
		return
	}
	if _, resolved := c.pending[rec.group]; resolved {
		return
	}
	if c.uoActive() && c.uoDelivered[rec.group] {
		return
	}
	if rec.group > c.maxGroupSeen {
		c.maxGroupSeen = rec.group
		c.maxGroupTime = time.Now()
	}
	// Eager gap proof (experiment): on this ordered carrier, a
	// record of a later group proves the cursor group's records
	// were all dropped if that group has no trace anywhere.
	// Record when the proof was first observed; the expiry loop
	// turns it into a lost-group declaration without waiting
	// for an arrival pause.
	if c.opts.EagerGapSynthesis && c.deliverNext < rec.group {
		if _, ok := c.recvGroups[c.deliverNext]; !ok {
			if !c.gapProofSet || c.gapProofFor != c.deliverNext {
				c.gapProofSet = true
				c.gapProofFor = c.deliverNext
				c.gapProofTime = time.Now()
			}
		}
	}
	// A record of a newer group closes all older open groups.
	for id, g := range c.recvGroups {
		if rec.group > id {
			c.resolveLocked(id, g)
		}
	}
	if rec.typ == recordRaw {
		res := &groupResult{messages: [][]byte{rec.payload}, expected: 1, received: 1}
		c.pending[rec.group] = res
		c.feedbackAcc.Expected++
		c.feedbackAcc.Received++
		c.stats.groupsRecv.Add(1)
		c.pumpDeliverLocked()
		return
	}
	defer c.pumpDeliverLocked()
	g, ok := c.recvGroups[rec.group]
	if !ok {
		g = &recvGroup{
			k: rec.k, r: rec.r,
			data:      make([][]byte, rec.k),
			parity:    make([][]byte, rec.r),
			lens:      make([]int, rec.k),
			firstSeen: time.Now(),
		}
		for i := range g.lens {
			g.lens[i] = -1
		}
		c.recvGroups[rec.group] = g
	}
	g.seen++
	switch rec.typ {
	case recordData:
		if rec.index < g.k && g.data[rec.index] == nil {
			g.data[rec.index] = rec.payload
			g.lens[rec.index] = len(rec.payload)
		}
	case recordParity:
		if rec.index < g.r && len(rec.payload) >= 2*g.k {
			for i := 0; i < g.k; i++ {
				g.lens[i] = int(binary.BigEndian.Uint16(rec.payload[2*i:]))
			}
			parity := rec.payload[2*g.k:]
			g.parity[rec.index] = parity
			g.paddedLen = len(parity)
		}
	}
	// Resolve immediately when the group is provably complete:
	// all data present, or every record of the group has arrived.
	if g.allDataPresent() || g.seen >= g.k+g.r {
		c.resolveLocked(rec.group, g)
	}
}

func (g *recvGroup) allDataPresent() bool {
	for _, d := range g.data {
		if d == nil {
			return false
		}
	}
	return true
}

// resolveLocked closes a group: reconstructs from parity if
// possible, accounts feedback, and queues the result for ordered
// delivery. Caller holds recvMu.
func (c *Conn) resolveLocked(id uint32, g *recvGroup) {
	if _, done := c.pending[id]; done {
		return
	}
	delete(c.recvGroups, id)
	res := &groupResult{expected: g.k}
	received := 0
	for _, d := range g.data {
		if d != nil {
			received++
		}
	}
	res.received = received
	missing := g.k - received
	if missing > 0 && g.r > 0 {
		// Build the padded shard array for the codec.
		paddedLen := g.paddedLen
		if paddedLen == 0 {
			for _, d := range g.data {
				if len(d) > paddedLen {
					paddedLen = len(d)
				}
			}
		}
		shards := make([][]byte, g.k+g.r)
		for i := 0; i < g.k; i++ {
			if g.data[i] != nil {
				p := make([]byte, paddedLen)
				copy(p, g.data[i])
				shards[i] = p
			}
		}
		copy(shards[g.k:], g.parity)
		if recovered, err := c.codec.Reconstruct(shards, g.k, g.r); err == nil && recovered > 0 {
			for i := 0; i < g.k; i++ {
				if g.data[i] == nil && shards[i] != nil {
					length := g.lens[i]
					if length < 0 || length > len(shards[i]) {
						length = len(shards[i])
					}
					g.data[i] = shards[i][:length]
				}
			}
			res.recovered = recovered
			missing -= recovered
		}
	}
	res.lost = missing
	for i := 0; i < g.k; i++ {
		if g.data[i] != nil {
			res.messages = append(res.messages, g.data[i])
		}
	}
	if missing > 0 && c.opts.Mode == ModeStream {
		res.fatal = true
	}
	c.feedbackAcc.Expected += uint32(res.expected)
	c.feedbackAcc.Received += uint32(res.received)
	c.feedbackAcc.Recovered += uint32(res.recovered)
	c.feedbackAcc.Lost += uint32(res.lost)
	c.stats.recovered.Add(uint64(res.recovered))
	c.stats.lost.Add(uint64(res.lost))
	c.stats.groupsRecv.Add(1)
	c.pending[id] = res
}

// pumpDeliverLocked moves resolved groups into the delivered
// channel. Caller holds recvMu. Delivery blocks if the consumer
// is slow: that backpressure is intended, but it must not hold
// recvMu while blocked, so this is only called with results
// ready and a buffered channel; if the channel is full we return
// and retry on the next event. With the PacketOutOfOrder
// experiment flag the packet-mode variant runs instead: every
// resolved group is delivered as soon as it resolves, in
// resolution order, and deliverNext degrades to a pure
// accounting cursor (gap synthesis still walks it so fully-lost
// groups are accounted exactly once).
func (c *Conn) pumpDeliverLocked() {
	if c.recvFinished {
		return
	}
	if c.uoActive() {
		c.pumpDeliverUOLocked()
		return
	}
	for {
		res, ok := c.pending[c.deliverNext]
		if !ok {
			return
		}
		if res.fatal && c.readErr == nil {
			c.readErr = ErrGroupLost
		}
		for res.delivered < len(res.messages) {
			select {
			case c.delivered <- res.messages[res.delivered]:
				c.stats.appIn.Add(uint64(len(res.messages[res.delivered])))
				res.delivered++
			default:
				return // retry on next event; progress is kept in res.delivered
			}
		}
		delete(c.pending, c.deliverNext)
		c.deliverNext++
	}
}

// pumpDeliverUOLocked is the unordered packet-mode pump
// (experiment): deliver every resolved group now, lowest ID first
// for determinism, regardless of gaps at the cursor. Feedback
// accounting is unaffected — it happens in resolveLocked when a
// group resolves, not here. Caller holds recvMu.
func (c *Conn) pumpDeliverUOLocked() {
	ids := make([]uint32, 0, len(c.pending))
	for id := range c.pending {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	for _, id := range ids {
		res := c.pending[id]
		for res.delivered < len(res.messages) {
			select {
			case c.delivered <- res.messages[res.delivered]:
				c.stats.appIn.Add(uint64(len(res.messages[res.delivered])))
				res.delivered++
			default:
				c.advanceCursorUOLocked()
				return // channel full; progress kept in res.delivered
			}
		}
		delete(c.pending, id)
		c.uoDelivered[id] = true
	}
	c.advanceCursorUOLocked()
}

// advanceCursorUOLocked moves the accounting cursor past groups
// already delivered out of order, so gap synthesis only ever
// synthesises slots nobody has accounted for. Caller holds
// recvMu.
func (c *Conn) advanceCursorUOLocked() {
	for c.uoDelivered[c.deliverNext] {
		c.deliverNext++
	}
}

// synthesiseGapLocked declares the cursor group fully lost
// without any record of it ever arriving, accounting it as one
// unit (exact for raw and k=1 groups, a floor for fully-lost
// shard groups). Caller holds recvMu.
func (c *Conn) synthesiseGapLocked() {
	res := &groupResult{expected: 1, lost: 1}
	if c.opts.Mode == ModeStream {
		res.fatal = true
	}
	c.feedbackAcc.Expected++
	c.feedbackAcc.Lost++
	c.stats.lost.Add(1)
	c.stats.groupsRecv.Add(1)
	c.pending[c.deliverNext] = res
}

func (c *Conn) expiryLoop() {
	ticker := time.NewTicker(c.opts.GroupTimeout / 2)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			c.recvMu.Lock()
			now := time.Now()
			for id, g := range c.recvGroups {
				if now.Sub(g.firstSeen) > c.opts.GroupTimeout {
					c.resolveLocked(id, g)
				}
			}
			// Gap synthesis: a group whose every record was lost
			// leaves no trace in recvGroups, and without a result
			// ordered delivery would stall behind it forever. If a
			// newer group has been seen and the missing ID has had
			// a full timeout to arrive, declare it lost (counted
			// as one unit: exact for raw groups, a floor for fully
			// lost shard groups, which need every record dropped).
			// The EagerGapSynthesis experiment adds a second trigger:
			// a later group's arrival already proved this slot lost
			// (ordered carrier), so declare it once the proof is
			// older than GapProofGrace — no arrival pause needed.
			for c.started && c.deliverNext < c.maxGroupSeen {
				if _, ok := c.pending[c.deliverNext]; ok {
					break
				}
				if _, ok := c.recvGroups[c.deliverNext]; ok {
					break
				}
				// Chained gaps: when the pump just advanced the
				// cursor past a synthesised gap, the next missing
				// slot is *already* proven lost (a later group was
				// seen before this tick), even though no record has
				// arrived since it became the cursor. Establish its
				// proof now (grace restarts — conservative) so one
				// tick clears the whole run of gaps instead of one
				// gap per tick.
				if c.opts.EagerGapSynthesis &&
					(!c.gapProofSet || c.gapProofFor != c.deliverNext) {
					c.gapProofSet = true
					c.gapProofFor = c.deliverNext
					c.gapProofTime = now
				}
				eager := c.opts.EagerGapSynthesis && c.gapProofSet &&
					c.gapProofFor == c.deliverNext &&
					now.Sub(c.gapProofTime) >= c.opts.GapProofGrace
				if !eager && now.Sub(c.maxGroupTime) <= c.opts.GroupTimeout {
					break
				}
				before := c.deliverNext
				c.synthesiseGapLocked()
				c.pumpDeliverLocked()
				if c.deliverNext == before {
					break // delivered channel full; retry next tick
				}
			}
			c.pumpDeliverLocked()
			c.recvMu.Unlock()
		case <-c.recvDone:
			return
		}
	}
}

// finishReceive runs when the record stream ends: resolve every
// open group with what has arrived, deliver, and record the error
// that Read/ReadMessage will surface after the buffer drains.
func (c *Conn) finishReceive(err error) {
	c.recvMu.Lock()
	for id, g := range c.recvGroups {
		c.resolveLocked(id, g)
	}
	c.pumpDeliverLocked()
	c.recvFinished = true
	if c.readErr == nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			c.readErr = io.EOF
		} else {
			c.readErr = err
		}
	}
	c.recvMu.Unlock()
	close(c.delivered)
}

func (c *Conn) feedbackLoop() {
	ticker := time.NewTicker(c.opts.FeedbackInterval)
	defer ticker.Stop()
	var seq uint32
	for {
		select {
		case <-ticker.C:
			c.recvMu.Lock()
			acc := c.feedbackAcc
			c.feedbackAcc = Feedback{}
			c.recvMu.Unlock()
			if acc.Expected == 0 {
				continue
			}
			seq++
			rec := record{typ: recordFeedback, group: seq, payload: encodeFeedback(acc)}
			select {
			case c.ctrlQueue <- rec:
			default: // never block the feedback loop on a busy sender
			}
		case <-c.recvDone:
			return
		}
	}
}

// --- application-facing reads ---

// Read implements io.Reader for stream mode.
func (c *Conn) Read(p []byte) (int, error) {
	for len(c.readBuf) == 0 {
		msg, err := c.nextMessage()
		if err != nil {
			return 0, err
		}
		c.readBuf = msg // skip empty messages: Read must not return (0, nil)
	}
	n := copy(p, c.readBuf)
	c.readBuf = c.readBuf[n:]
	return n, nil
}

// ReadMessage returns the next delivered message (packet mode).
func (c *Conn) ReadMessage() ([]byte, error) {
	return c.nextMessage()
}

func (c *Conn) nextMessage() ([]byte, error) {
	msg, ok := <-c.delivered
	if !ok {
		c.recvMu.Lock()
		err := c.readErr
		c.recvMu.Unlock()
		if err != nil {
			return nil, err
		}
		return nil, io.EOF
	}
	return msg, nil
}

// Stats returns a snapshot of the connection accounting.
func (c *Conn) Stats() Stats {
	return Stats{
		AppBytesOut:     c.stats.appOut.Load(),
		WireBytesOut:    c.stats.wireOut.Load(),
		HeaderBytesOut:  c.stats.headerOut.Load(),
		ParityBytesOut:  c.stats.parityOut.Load(),
		AppBytesIn:      c.stats.appIn.Load(),
		WireBytesIn:     c.stats.wireIn.Load(),
		GroupsSent:      c.stats.groupsSent.Load(),
		GroupsReceived:  c.stats.groupsRecv.Load(),
		ShardsRecovered: c.stats.recovered.Load(),
		ShardsLost:      c.stats.lost.Load(),
	}
}

// Redundancy returns the sender controller's current target.
func (c *Conn) Redundancy() float64 { return c.ctrl.Redundancy() }

// Close flushes pending groups and closes the underlying conn.
func (c *Conn) Close() error {
	var err error
	c.closeOnce.Do(func() {
		close(c.closing)
		select {
		case <-c.sendDone:
		case <-time.After(2 * time.Second):
		}
		err = c.conn.Close()
		if c.opts.OnClose != nil {
			c.opts.OnClose(c.Stats())
		}
	})
	return err
}

// net.Conn plumbing delegated to the underlying connection.

func (c *Conn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *Conn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
