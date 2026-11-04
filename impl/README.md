# musess — milestone 1 implementation

`musess` is Emma's new proxy protocol (named by Emma: written by Muse —
muse + ss; the early placeholder name in the original brief was
`newproto`, renamed before any code was written against it). This
directory contains milestone 1: the **TCP/TLS path** of
`~/workspace/new-protocol/DESIGN.md`, implemented as a protocol package
inside a sing-box tree, working end to end. **Milestone 2
(application-layer adaptive FEC) is documented in the second half
of this file** (search for "milestone 2: application-layer
adaptive FEC").

Everything here is **local only** (decision #8: not public — no public
spec, no public repo, no upstream submission until testing is done and
Emma re-decides).

Priorities applied throughout (Emma's ruling on design ch. 11 #7):
**throughput > camouflage > latency**. The data plane is deliberately
lean: no padding, no shaping, no extra framing layers in milestone 1.
FEC and congestion-control tuning in later milestones will be judged
primarily by goodput under loss, then camouflage, then latency.

Sequencing (Emma): the protocol stands alone in sing-box first.
Xboard-Node/panel integration is **deferred** — nothing here generates
xboard-node config or panel fields.

## Baseline

- sing-box source: the exact module Emma's Xboard-Node stack resolves —
  `~/workspace/Xboard-Node-fork/go.mod` requires sagernet/sing-box
  v1.13.2 but its **replace directive** points to
  `github.com/cedar2025/sing-box v1.14.0-alpha.2.0.20260316103356-2e665cb7e295`
  (commit `2e665cb7e295`, 2026-03-16). The tree in `impl/sing-box/` is a
  byte copy of that module from the local Go module cache.
- The **unmodified base was built and run first** (Go 1.26.0, the
  tree's own `release/DEFAULT_BUILD_TAGS_OTHERS` tags and
  `release/LDFLAGS`): `sing-box version` reported
  `1.14.0-alpha.2-musess-baseline`, exit 0. Only then was code changed.
- Build the modified binary the same way:

```bash
export PATH=/home/hatch/workspace/.go-tmp/go/bin:$PATH   # go1.26.0
export GOTOOLCHAIN=local TMPDIR=$PWD/.tmp                # /tmp is a small tmpfs here
cd sing-box
go build -trimpath \
  -ldflags "-X 'github.com/sagernet/sing-box/constant.Version=1.14.0-alpha.2-musess-m1' $(cat release/LDFLAGS) -s -w -buildid=" \
  -tags "$(cat release/DEFAULT_BUILD_TAGS_OTHERS)" \
  -o ../.tmp/sing-box-musess ./cmd/sing-box
```

(The `-checklinkname=0` inside the tree's LDFLAGS is required; without
it the link fails on `common/badtls`.)

## What was built

A new protocol package `protocol/musess` in the sing-box tree, with
config type **`musess`**, registered in `include/registry.go` for both
inbound and outbound (same pattern as anytls). The same binary works
as server (musess inbound + direct outbound) and as client (socks
inbound + musess outbound); see `test/server.json` / `test/client.json`.

### Options

Inbound (`MusessInboundOptions`):

| field | meaning |
|---|---|
| `dest` | borrowed destination domain; the SNI unauthenticated visitors are forwarded to |
| `dest_port` | destination port (default 443) |
| `dest_address` | optional dial override for the destination (tests / pinned IP) |
| `private_key` | server X25519 private key, base64 (32 bytes) |
| `certificate_path`, `key_path` | locally issued certificate for the dest name, presented **only** on the authenticated path (see Deviations) |
| `users[]` | `{name, uuid, secret}` |

Outbound (`MusessOutboundOptions`): dialer + server fields, plus
`server_name` (the SNI presented = the dest name), `public_key`
(server X25519 public key, base64), `uuid`, `secret`.

### Authentication (DESIGN.md ch. 4, TCP path)

The token rides in the TLS 1.3 ClientHello's `legacy_session_id`
(32 bytes, which in compatibility mode normally carries 32 random
bytes anyway):

```
[0:4]   unix timestamp, big-endian
[4:8]   user hint = SHA-256(uuid)[0:4]
[8:32]  tag = HMAC-SHA-256(authKey, transcriptHash || timestamp || hint)[0:24]
```

- **transcriptHash** binds the tag to this specific handshake: SHA-256
  over the canonical parsed fields — client random, SNI, cipher
  suites, supported versions, and every key share (group + data), in
  wire order; the session ID itself is excluded (it carries the tag).
  Copying a session ID into a different ClientHello does not verify.
- **authKey**: HKDF-SHA-256 over (X25519 shared secret ‖ SHA-256(user
  secret)), salt `musess-v1`, info `musess auth key`. The X25519
  exchange uses the server’s static key and the private key of the
  ClientHello’s own TLS key share — the pattern this tree’s REALITY
  client already uses (`HandshakeState.State13.KeyShareKeys.Ecdhe`),
  with the ML-KEM key share removed from the parroted hello so the
  session share is plain X25519. Two candidate constructions were
  evaluated, and the comparison was then **measured** (see
  “Fork-point measurements” below): (A) reuse the TLS session share
  (chosen); (B) an extra client-generated share appended to the hello
  (verified empirically to survive uTLS ApplyPreset/marshal verbatim;
  kept as a fallback if (A) ever breaks with a future uTLS). The
  measurements confirm (A): its hello is structurally identical to
  the stock parrot’s, while (B) adds a duplicate group-29 key share
  that real Chrome never sends, and (B) doubles the server-side
  verify cost.
- **Freshness & replay**: timestamp window ±120 s (DESIGN.md 4.3) plus
  a server-side replay cache keyed by the full session ID, retained
  for window + 60 s grace. A replayed token is indistinguishable from
  no token: the connection is forwarded (check (c) proves it).
- **Server proof**: after local TLS termination, the server sends
  `HMAC-SHA-256(proofKey, "musess server proof" ‖ TLS exporter)` as
  the first 32 data-plane bytes (proofKey derived like authKey with
  info `musess proof key`; exporter label `musess`, RFC 5705). The
  client verifies it before sending its request — this is how the
  client authenticates the server despite the locally issued
  certificate (the outbound therefore uses uTLS with
  `InsecureSkipVerify`, identity coming from the proof, not PKI).

One implementation gotcha worth recording: the Chrome parrot’s
`renegotiation_info` extension makes uTLS set
`Config.Renegotiation = RenegotiateOnceAsClient` on every hello
(re)build, which silently disables
`ConnectionState().ExportKeyingMaterial` — and the server proof is
bound to the exporter. The outbound therefore swaps that extension
for a `GenericExtension{Id: 65281, Data: [0x00]}`: byte-identical on
the wire, no config side effect.

### Fallback (unauthenticated path)

The inbound peeks at the first TLS record(s), parses the ClientHello,
and verifies the token. **Every** failure mode — no token, bad tag,
stale timestamp, replay, non-TLS garbage, unparsable hello — takes
the same path: the server dials the configured destination and
splices the connection **byte for byte** (the peeked bytes plus any
buffered leftovers are written first). The prober therefore talks to
the genuine destination end to end: its real certificate, its real
TLS stack, its real content. Nothing about the failure is observable
in the response.

The alternative the tree offers — a REALITY-style mechanism (the
in-tree `common/tls` REALITY server) — was benchmarked head-to-head
before settling on byte-forwarding; see “Fork-point measurements”.
Byte-forwarding won not on loopback speed (a wash) but on dest
eligibility and fork depth: it imposes **no requirements on the
borrowed destination at all**, while the reality-style mechanism
requires a TLS 1.3 + H2 destination whose certificate chain verifies
against public roots, and adopting it would mean either taking
REALITY’s own authentication scheme with it or forking `common/tls`
deeper than the project’s L2 ceiling to graft musess’s auth in.

### Data plane

Inside the authenticated TLS stream, deliberately minimal:

```
[version 0x01][command][address]   command 0x01 = TCP stream, 0x02 = UDP association
address = sing's SocksaddrSerializer format (atyp + addr + port)
TCP: raw stream follows
UDP: per-packet [address][uint16 length][payload]
```

TCP streams are handed to the router (`RouteConnectionEx`) with the
authenticated user name in the metadata; UDP associations likewise
(`RoutePacketConnectionEx`, with `UDPConnect` set — a musess UDP
stream is an association opened for the header destination, and the
client side opens one stream per destination).

## Deviations from DESIGN.md

1. **Authenticated-path certificate (ch. 3.3 / open problem ch. 10
   #2).** DESIGN’s single-stack principle wants one genuine stack
   answering everyone. Milestone 1 honours it on the path probers can
   reach: unauthenticated traffic is byte-forwarded to the real dest
   (genuine stack, genuine cert — check (b2) verifies the fingerprint).
   The *authenticated* path, however, terminates TLS locally and
   presents a **locally configured certificate** for the dest name,
   not the destination’s real certificate (no REALITY-style
   certificate borrowing). Only a credential holder ever completes
   this path, and the client verifies the server by the exporter
   proof, not by the certificate. Closing this gap (borrowing the
   dest’s handshake/cert à la REALITY) is milestone-2 work; the TCP
   single-stack itemisation is exactly open problem ch. 10 #2.
2. **Transcript definition.** The design says “HMAC bound to the TLS
   handshake transcript”. uTLS does not expose a deterministic
   raw-byte transcript pre-marshal, so the tag binds a canonical
   hash of the parsed ClientHello fields (random, shares, SNI,
   versions, suites). Everything a replayer would have to change is
   covered; verbatim full-hello replay is stopped by the timestamp
   window + replay cache. If a future design revision wants the
   RFC 8446 transcript hash proper, the server side can compute it
   once it terminates the handshake — but the token must be verified
   *before* the termination decision, so the canonical-fields form
   is the workable construction for this placement.
3. **Post-auth handshake failure closes the connection.** Once a
   token verifies, the hello bytes are consumed by local termination;
   if the subsequent TLS handshake fails there is nothing left to
   forward, so the connection is closed. Unauthenticated connections
   are unaffected. (A prober cannot reach this state without a valid
   token.)
4. **UDP association semantics.** One stream per association
   destination with `UDPConnect` on the server side (see above).
   Per-packet destination addresses are still carried in the framing,
   and sing-box’s client never mixes destinations on one stream, so
   this matches real SOCKS UDP usage; full multi-destination
   multiplexing on one stream is not a milestone-1 goal.

## Tests

Unit tests (in `protocol/musess/`): framing round trips, request
header codec, and a replica of the sing-box route copy stack
(sniff-peek → `CachedPacketConn` → `bufio.CopyPacket`) proving the
packet-conn contract the router expects.

```bash
go test -tags "$(cat sing-box/release/DEFAULT_BUILD_TAGS_OTHERS)" ./protocol/musess/   # from sing-box/
# ok  github.com/sagernet/sing-box/protocol/musess  (3 tests, PASS)
```

End-to-end: `test/run-e2e.sh` stands up a local HTTPS site as the
borrowed-dest stand-in (test fixture only — deployment decision #1 is
borrowed dest; the stand-in just plays that role on loopback),
generates a throwaway CA plus two *different* certificates for the
same name `dest.test` (the dest’s own and the server’s local one),
generates the server keypair, and runs:

- **(a)** fetch through the tunnel via the client’s SOCKS port;
- **(b)** fetch the server address directly with dest SNI and no auth
  (body must be the dest’s; the presented certificate fingerprint
  must be the *dest’s*, not the server-local one);
- **(c)** capture a genuine authenticated ClientHello through a
  recording relay, replay it verbatim on a fresh connection, and
  verify via the dest’s session-ID log that it was **forwarded**
  (dest saw the session ID only after the replay, never for the
  original) and answered with a genuine TLS handshake;
- **(d)** UDP smoke test (SOCKS UDP associate → musess → UDP echo).

Real output of the final run (2026-11-05, this machine):

```
(a) body via tunnel: MUSESS-DEST-OK-1793812444
PASS: (a) fetch through tunnel via SOCKS returns dest body
(b) body direct, no auth: MUSESS-DEST-OK-1793812444
PASS: (b1) unauthenticated request returns dest body (forwarded)
PASS: (b2) presented certificate is the genuine destination certificate
(c) capture-phase body via tunnel: MUSESS-DEST-OK-1793812444
PASS: (c0) capture-phase tunnel fetch works
(c) captured auth session id: 6aeb67dd666ff6ccb4d643fd961a4c438aa7354040293801b6575ac89c0e7610
(c) dest saw this session id before replay: 0 time(s) (expect 0: original was terminated at the musess server)
replay response: 1485 bytes, first bytes: 160303007a0200007603031e4425fb59
replay response is a TLS handshake record (the destination answered)
(c) dest saw this session id after replay: 1 time(s) (expect >=1: replay was forwarded to dest)
PASS: (c) replayed ClientHello is forwarded to dest, not authenticated
e2e summary: 5 passed, 1 failed   <- (d) only, see below
```

**About (d):** in this sandbox, `sendto()` on *unconnected* UDP
sockets is rejected with EPERM by the network policy, while connected
UDP sockets work. That breaks stock sing-box UDP paths (reproduced
with a pure stock socks→direct setup containing no musess code, and
confirmed by strace: `sendto(..., 127.0.0.1:15353) = -1 EPERM` from
sing-box’s direct outbound). The musess tunnel itself was verified
carrying the probe end to end under tracing: client outbound
`WritePacket` → server inbound `ReadPacket` (correct destination and
payload) → echo server received `musess-udp-probe-0123456789` →
server `WritePacket` (reply) → client outbound `ReadPacket`. Only
the final stock-socks→test-client hop inside this sandbox did not
complete. The server side already uses a connected outbound socket
(`UDPConnect`, which is also the natural fit for the association
model); on an unrestricted network (d) is expected to pass as-is.
The test-environment quirks that cost debugging time — the sandbox's
fake-IP DNS (configs pin `default_domain_resolver` to a `hosts` DNS
server for `dest.test`), its exported proxy variables (direct curl
needs `--noproxy '*'`; the explicit-SOCKS curls must not have it), and
this UDP policy — are test-harness facts, not protocol behaviour.

Config `check` also passes for both shipped configs
(`sing-box check -c test/server.json` after placeholder substitution;
the script does this on every run).

## Fork-point measurements

Per Emma's working method (test several approaches, pick by
measurement, in the order throughput > camouflage > latency), the
two genuine fork-points inside milestone 1 were measured rather than
settled by argument. Reproduce with
`go test -run TestClientHelloPlacementComparison -v ./protocol/musess/`,
`go test -bench BenchmarkVerify ./protocol/musess/`, and
`test/bench-fallback.sh`. All numbers are from this machine
(loopback); WAN behaviour is *not* claimed.

### 1. Auth-tag placement (session-ID carrier, two ECDH shapes)

ClientHellos built in memory with the tree's uTLS Chrome 120 parrot
(3 builds each; uTLS randomises GREASE, extension order and padding
per build, as Chrome does, so structure — not exact bytes — is the
fingerprint):

| shape | hello length | key shares | structural diff vs stock |
|---|---|---|---|
| stock parrot | 512–556 B | GREASE + X25519 | — |
| **P1 (shipped)**: tag keyed by the TLS session's own X25519 share | 524–556 B | GREASE + X25519 | none |
| P2: tag keyed by an extra appended X25519 share | 624 B (all builds) | GREASE + X25519 + **X25519** | duplicate group-29 share; ~+70–100 B |

Extension-type multisets of P1 and stock coincide; P2's duplicate
key share is something a real Chrome ClientHello never contains and
is visible to JA3/JA4-style fingerprinting. Server-side verify cost
(the peek cost paid on *every* inbound connection attempt):

| benchmark | cost |
|---|---|
| verify, P1 shape (valid token) | ~76 µs |
| verify, P2 shape, valid share tried second (worst case) | ~151 µs |
| verify, P2-shaped garbage hello (failed token, all shares tried) | ~146 µs |

P1 wins on camouflage (no structural diff) and on peek cost (half
the crypto per attempt, including the junk-hello/DoS direction).
That — not preference — is why the shipped construction reuses the
session share.

### 2. Unauthenticated fallback mechanism

`test/bench-fallback.sh` points three legs at the *same* dest
stand-in (`helper dest2`: net/http, TLS 1.3 + H2): direct, musess
byte-forward, and a stock sing-box VLESS+REALITY inbound (the tree's
reality-style mechanism). Medians of 25 curl fetches, two runs:

| leg | appconnect | total | body | presented cert | TLS / ALPN |
|---|---|---|---|---|---|
| direct | 5.4 ms | 5.9–6.0 ms | ✓ | genuine dest | TLS 1.3 / h2 |
| musess byte-forward | 5.8–5.9 ms | 6.4–6.5 ms | ✓ | genuine dest | TLS 1.3 / h2 |
| reality-style | 5.5–5.7 ms | 6.2–6.3 ms | ✓ | genuine dest | TLS 1.3 / h2 |

Reading, honestly: on the unauthenticated path the two mechanisms
are behaviourally indistinguishable on every probed observable (the
genuine dest answers either way), and their loopback timings are
within ~0.5 ms of direct and of each other (reality-style measured
a hair faster than byte-forward in both runs; the gap is
sub-millisecond loopback noise, and steady-state throughput is a
raw splice in both). The decision therefore rests on the other two
axes:

- **Dest eligibility (camouflage/deployability).** Reality-style
  requires the borrowed dest to speak TLS 1.3 + H2 and present a
  certificate chain verifiable against public roots — the bench
  stand-in only qualified after injecting the test CA via
  `SSL_CERT_FILE`. Byte-forward imposes no dest requirements at
  all. Under decision #1 (borrowed dest, chosen by §9.6 consistency
  criteria), the larger eligible pool wins.
- **Complexity / fork depth.** Byte-forward is ~80 lines in the
  musess inbound and is agnostic to the auth scheme. The tree's
  REALITY stack embeds REALITY's *own* authentication; grafting
  musess's auth onto it would mean forking `common/tls` past the
  project's L2 ceiling (or abandoning the design's auth).
- **Not measured:** the authenticated-path cost difference
  (reality-style performs a live dest handshake per authenticated
  connection to steal the certificate; byte-forward terminates
  locally). No REALITY client leg was built for this comparison;
  this is flagged, not asserted.

## Files added / changed

In `sing-box/` (the baseline tree):

- `protocol/musess/clienthello.go` — ClientHello record reassembly,
  parser, canonical transcript hash.
- `protocol/musess/auth.go` — key derivation, session-ID build/verify,
  replay cache, server proof.
- `protocol/musess/framing.go` — request header, address codec usage,
  stream packet conn + adapters.
- `protocol/musess/inbound.go` — peek/verify, byte-forward fallback,
  local TLS termination, routing.
- `protocol/musess/outbound.go` — uTLS ClientHello construction
  (Chrome 120 parrot, ML-KEM share removed, renegotiation_info swap),
  session-ID patching (the in-tree REALITY pattern), proof check.
- `protocol/musess/framing_test.go`, `protocol/musess/copy_stack_test.go` — unit tests.
- `protocol/musess/placement_test.go` — the fork-point evidence above:
  ClientHello shape comparison (stock vs P1 vs P2) and the
  server-side verify-cost benchmarks.
- `option/musess.go` — inbound/outbound option types.
- `constant/proxy.go` — `TypeMusess = "musess"` + display name.
- `include/registry.go` — register inbound + outbound.

In `test/`:

- `server.json`, `client.json` — the working pair (placeholders for
  keys/ports substituted by the script into its workdir copies).
- `run-e2e.sh` — the automated test above.
- `bench-fallback.sh` — the fallback-mechanism benchmark above
  (direct vs byte-forward vs the tree's REALITY server against one
  shared dest stand-in).
- `helper/main.go` (+ `go.mod`) — keygen, HTTPS dest stand-in with
  ClientHello session-ID logging, net/http H2-capable dest stand-in
  (`dest2`, for the REALITY leg of the benchmark), recording relay
  (`sniff`), replay tool, session-ID extractor, UDP echo (with
  connected reply sockets), SOCKS UDP test client.

## Not in milestone 1 (next steps)

- **QUIC/H3 path** and the DCID covert-auth construction (design
  ch. 10 open problem #1) — dual-path is decided YES, staged after
  the TCP path; the auth/framing semantics above are written to be
  shared.
- ~~**Adaptive application-layer FEC**~~ — done in milestone 2,
  see the next section.
- **Traffic shaping** beyond what the handshake itself requires
  (deferred by the priority ruling; no padding exists today).
- **REALITY-style certificate borrowing** for the authenticated path
  (deviation 1 above) and the TCP single-stack itemisation
  (ch. 10 #2).
- **Xboard-Node/panel integration** (deliberately deferred by Emma;
  protocol stands alone in sing-box first).
- **Share-link URI generation.**
- Congestion-control selection/tuning under loss, measured against
  the priority order (goodput first, then camouflage, then latency).

---

# musess — milestone 2: application-layer adaptive FEC

Milestone 2 implements DESIGN.md ch. 5.2: an adaptive,
application-layer-only FEC for musess, per-flow, driven by receiver
feedback, judged primarily by goodput under loss. Everything was
measured in this sandbox; where a number comes from a model or a
shim rather than a kernel mechanism, that is stated next to it.

## What was built

A transport-agnostic FEC record layer in a new subpackage
`protocol/musess/fec/`, wired into both musess data planes:

- **Record format** (10-byte header): `[type][groupID][shardIndex]
  [k][r][payloadLen]`, types data / parity / feedback / raw.
  Data shards are grouped (planned k from the codec); parity
  shards carry a trailer with the true lengths of all data shards
  so rebuilt shards can be truncated exactly. Feedback records
  carry one receiver window (expected / received / recovered /
  lost data shards). The format knows nothing about TLS or QUIC:
  the same records are designed to ride QUIC streams/datagrams
  unchanged (one record per datagram), per decision #2's shared
  semantics.
- **Codecs** behind one interface: XOR parity (dependency-free)
  and Reed-Solomon via `github.com/klauspost/reedsolomon v1.12.4`
  (added to the tree's go.mod; mature library, no hand-rolled
  Galois code). Parity is priced against the group that actually
  exists at emit time (`ParityFor`), so flushed partial groups do
  not inherit a full group's parity bill.
- **Controllers** behind one interface, wrapped by a shared shell
  that applies the design rules: off below 1% measured loss
  (feedback counts recovered shards as loss events — the transport
  did drop them), ~15% redundancy cap, a mode floor, and the
  **saturation yield**: while the sender's queue is backlogged the
  yield factor halves per feedback window and recovers ×1.5 per
  window once clear (DESIGN.md 5.2's "FEC 让位").
  - strategy A "fixed-step": step table (0 / 5% / 10% / 15%) with
    two-window hysteresis on the way down;
  - strategy B "estimator": EWMA loss estimate (α=0.3), redundancy
    = clamp(1.25 × estimate + 0.4%, 0, 15%).
- **Negotiation**: request-header v2 adds a flags byte. A client
  with `fec` enabled sets both direction bits (FEC runs as a
  symmetric duplex — one `fec.Conn` frames both directions); the
  server answers with one status byte (0x01 active / 0x00
  declined) and logs the outcome. v1 headers and `fec` unset keep
  the exact milestone-1 wire behaviour. New option on both sides:
  `"fec": "off" | "auto" | "on"` (default off in milestone 2 —
  see Deviations).
- **Planes**: TCP command → `fec.Conn` in stream mode (Write is
  split into ≤1400B shards; at zero redundancy the stream rides
  raw records at 32KiB chunks, ~0.03% header cost). UDP command →
  the milestone-1 per-packet framing becomes the payload of FEC
  messages; packets over the 1400B shard cap bypass grouping as
  raw records (unprotected, counted separately in code paths —
  they are rare in proxied UDP traffic, but they are *not*
  protected; this is a known limit, not a silent one).
- **Observability** (DESIGN.md 5.4): every `fec.Conn` keeps
  per-connection accounting (app/wire/header/parity bytes,
  recovered/lost shards); on close it is emitted as a debug log
  line (`musess fec stats: ... overhead=...`), so each
  connection's actual overhead can be audited against the budget.

### One structural fact that shapes everything below

The milestone-1/2 data planes ride a **reliable TLS/TCP stream**:
the application layer never observes a lost byte, so on the TCP
path there is nothing for FEC to recover. Measured consequence
(milestone-2 FEC e2e): with `fec=auto` on loopback, the
controller's measured loss is 0, redundancy stays 0, and the
1 MiB transfer's FEC overhead was **0.04%** — the machinery is
present and negotiated, but dormant, exactly as the design's
<1%-off rule dictates. FEC's benefit is therefore measured where
loss is visible to the application layer: the record-layer
harness below, whose loss unit is one FEC record over an ordered
stream carrier — the same shape the QUIC datagram path will
present. Claims stop there; no WAN or QUIC-path benefit is
asserted.

A second model correction, found by testing: erasure coding is
**all-or-nothing per group**. A group that loses more shards than
its parity count loses *all* its missing shards (the system is
underdetermined); early expectations here wrongly assumed partial
recovery of `min(missing, parity)` shards, and the codec was
briefly suspected of underperforming before per-group outcome
dumps proved it recovers every mathematically recoverable shard.

## Head-to-head comparison (Emma's method)

Harness: `protocol/musess/fec/bench_test.go`
(`MUSESS_FEC_BENCH=1 go test -run TestBenchComparison -v`), a
record-aware user-space shim over an ordered stream (net.Pipe):
whole FEC records are dropped per the loss model; a per-record
service time emulates link rate and propagates backpressure into
the sender's queue. **This is not kernel netem** (tc is not
permitted in this sandbox); all figures are labelled
measured-in-this-environment. Payload 4000 × 1200B messages,
offered 20 Mbps, flush 5 ms (the production default) and
feedback every 100 ms, one run per cell — variance across runs
was not characterised, treat small deltas as noise.

### Uniform random loss — delivery % / goodput Mbps (overhead %)

| config | 0% | 1% | 3% | 5% | 10% | 15% |
|---|---|---|---|---|---|
| none (baseline) | 100 / 20.00 (0.84) | 99.02 / 19.78 (0.84) | 97.05 / 19.35 (0.83) | 95.02 / 18.82 (0.83) | 90.05 / 17.67 (0.83) | 84.90 / 16.50 (0.82) |
| xor + fixed-step | 100 / 20.00 (0.85) | 99.90 / 19.83 (3.85) | 99.25 / 19.74 (7.44) | 97.85 / 19.42 (7.15) | 94.47 / 18.78 (8.51) | 90.20 / 17.94 (12.50) |
| xor + estimator | 100 / 20.00 (0.84) | 99.90 / 19.83 (4.06) | 99.10 / 19.80 (7.06) | 97.90 / 19.56 (6.92) | 93.75 / 18.68 (7.27) | 88.72 / 17.69 (10.35) |
| rs + fixed-step | 100 / 20.00 (0.84) | 99.93 / 19.92 (2.67) | 99.77 / 19.83 (5.34) | 99.80 / 19.93 (7.48) | 98.32 / 19.64 (7.84) | 96.47 / 19.34 (7.86) |
| **rs + estimator** | 100 / 19.98 (0.84) | 99.93 / 19.94 (1.65) | 100 / 19.94 (5.53) | 99.92 / 19.98 (6.23) | 99.15 / 19.89 (7.15) | 98.45 / 19.60 (8.00) |

Reading: at ≥5% loss Reed-Solomon separates from XOR decisively
(at 10%: RS ≥98.3% delivery vs XOR ≤94.5%; at 15%: 96.5–98.5%
vs 88.7–90.2%), because XOR's single parity per group breaks on
the second loss in a group. The estimator leads fixed-step in
every lossy RS row (1–15%); fixed-step is nominally ahead only
in the 0% row (20.00 vs 19.98 Mbps — a no-loss cell, within
noise). The estimator's advantage grows with loss (15%:
+2.0pt delivery, +0.26 Mbps). At 15% loss the winner still
delivers 19.60 of 20 offered Mbps where the no-FEC baseline
manages 16.50.

### Burst loss (Gilbert, mean burst ≈ 8 records, 50% drop in bad state)

| config | avg 5% | avg 10% |
|---|---|---|
| xor + fixed-step | 93.53% / 18.60M (7.17%) | 85.85% / 17.07M (10.63%) |
| xor + estimator | 93.35% / 18.57M (6.90%) | 86.63% / 17.18M (10.00%) |
| rs + fixed-step | 98.73% / 19.69M (7.82%) | 96.10% / 19.13M (9.88%) |
| rs + estimator | 98.68% / 19.89M (7.44%) | 94.87% / 18.95M (9.71%) |

Honest caveat: under burst loss at 10%, fixed-step *edges* the
estimator on delivery (+1.2pt; the estimator's EWMA chases a
non-stationary process), while the estimator still leads on
goodput in the 5% row. The production pick (below) weighs the
full matrix, not this row alone.

### Saturation (offered 100 Mbps into a 23 Mbps service-rate shim, 5% loss)

| config | delivery | goodput | overhead | final redundancy |
|---|---|---|---|---|
| xor + fixed-step (yield) | 83.65% | 19.76M | 7.52% | 14.3% |
| xor + estimator (yield) | 83.97% | 19.72M | 7.64% | 9.9% |
| rs + fixed-step (yield) | 99.85% | 18.43M | 5.20% | 0.0% |
| **rs + estimator (yield)** | **100%** | **19.86M** | 5.72% | 0.3% |
| rs + estimator (**no yield**, control) | 96.88% | 19.05M | 6.24% | 14.3% |
| rs + fixed-step (no yield, control) | 99.85% | 18.20M | 6.93% | 15.0% |

The DESIGN.md 5.2 yield rule is worth real goodput: for the
estimator, yield-on vs yield-off is +0.81 Mbps and +3.1pt
delivery under saturation, with final redundancy collapsed to
~0 as designed (parity stops crowding a full link).

### Latency (100 msg/s trickle, 5% uniform loss, delivered only)

| config | delivery | p50 | p95 |
|---|---|---|---|
| none | 94.90% | 5.3 ms | 12.2 ms |
| xor + fixed-step | 98.97% | 5.5 ms | 59.8 ms |
| xor + estimator | 99.67% | 6.6 ms | 53.4 ms |
| rs + fixed-step | 99.90% | 6.8 ms | 16.5 ms |
| rs + estimator | 99.73% | 7.2 ms | 22.3 ms |

p50 is dominated by the 5 ms group-flush interval for every FEC
config. FEC buys ~+5pt delivery at this rate for ~+10 ms p95
(RS) — latency is third in Emma's priority order, and the design
accepts this trade; XOR's p95 blow-up (recovery waits on large
groups) is another mark against it.

### Codec CPU (this machine, 16×1400B groups, `go test -bench`)

| operation | xor | reed-solomon |
|---|---|---|
| encode | 1451 MB/s | **3431 MB/s** |
| reconstruct (xor 1 loss / rs 3 losses) | 893 MB/s | **1957 MB/s** |

The naive scalar XOR loop loses to klauspost's SIMD Galois
implementation outright; CPU gives XOR no compensating win.

### Decision

**Production construction: Reed-Solomon (k=16) + estimator
controller** (`fecwire.go`). It wins the uniform matrix, the
saturation test, and CPU; it ties or trails fixed-step only in
the 10% burst row (delivery) — recorded here, not hidden. Both
losers (XOR codec, fixed-step controller) remain in the package
and in the harness for future replays.

## End-to-end benchmark (real binary, impairment shim)

`test/bench-e2e.sh` (32 MiB bulk download per leg, this machine,
binary `1.14.0-alpha.2-musess-m2`): client and server sing-boxen
with a user-space TCP **delay/hold shim** between them. The shim
stamps each 16 KiB chunk on arrival and releases it at
arrival + delay (+ an extra hold for a random 5% of chunks in
the "hold" legs), in order, through a deep (4096-chunk) queue —
a *latency/stall* model, explicitly **not packet loss** and not
a throughput cap at these transfer sizes (tc/netem is not
permitted in this sandbox). BBR was not available (kernel offers
reno/cubic only), so the direct reference is cubic. musess legs
are FEC-off (the shipping default; the FEC-on/off performance
delta is what the record-layer harness measures).

| leg | none | delay 25 ms/dir | delay 100 ms/dir | delay 25 ms + holds (5% × 60 ms) |
|---|---|---|---|---|
| direct (cubic) | 36509.52 Mbps | 4938.85 | 2043.94 | 2124.02 |
| shadowsocks-2022 (sing-box) | 6249.71 | 1546.85 | 996.71 | 1058.09 |
| musess (fec off) | 4073.89 | 911.38 | 407.60 | 689.82 |

Reading, with variance warnings: these are **single samples**;
the unimpaired legs move 32 MiB in 7–66 ms, so that column is
burst/startup-dominated — in a second run of the same script
the ss2022/musess unimpaired order flipped (2569 vs 2855 Mbps).
Do not rank on it. The delay columns are more consistent across
both runs: proxied legs fall behind direct as delay grows, and
musess falls behind SS2022 — at delay 100 ms musess/SS2022 was
0.41 in both runs (407.60/996.71 and 410.37/998.91). Why musess
degrades more with delay (chained-connection window/buffer
interplay is the obvious suspect) is **not diagnosed** — the
observation is recorded, the mechanism is unverified. An
earlier run of this bench with a serialising (drain-then-delay)
shim produced a "legs converge under delay" table; that shim
behaviour was a fidelity bug, the table was superseded, and the
convergence reading is **withdrawn**. These are first numbers
in a constrained sandbox, not WAN results.

FEC functional e2e: `test/run-e2e-fec.sh` — 6/6 checks pass:
1 MiB byte-identical fetch over the negotiated FEC duplex (TCP
and through the delay+hold shim), negotiation markers in both
logs, UDP probe carried through the FEC packet plane to the echo
server (full round trip still blocked at the final stock-socks
hop by this sandbox's UDP policy, as in milestone 1), and clean
fallback to plain framing when the server declines FEC.

## Overhead vs the ≤8% shaping budget (DESIGN.md 5.4)

The 8% budget in the design text is written for shaping/padding
on long connections, with the handshake/start phase allowed to
exceed it. FEC redundancy under loss is accounted here against
the same yardstick, honestly:

- Winner (rs + estimator), uniform loss 0–15%: **0.84% → 8.00%**
  — at or under budget at every point (at 0–1% loss the 0.84%
  is record-header cost while redundancy is disengaged).
- Burst 10%: **9.71%** — over budget; burst recovery is the
  expensive case the design's 15% redundancy cap exists for.
- Saturation: 5.72% (yield doing its job).
- Trickle flows (100 msg/s): ~21% — small groups amortise parity
  badly. DESIGN.md 5.2 explicitly prioritises small-packet flows
  for FEC, and 5.4's budget is a long-connection average, but the
  number is reported, not rationalised away.
- TCP-path e2e (fec=auto, lossless loopback): 0.04% — dormant.

## Regression gate

- `test/run-e2e.sh` (unchanged) on the milestone-2 binary:
  **5 passed, 1 failed — the identical profile to milestone 1.**
  The one failure is check (d), blocked by this sandbox's
  unconnected-UDP EPERM at the final stock-socks hop; the run
  also reproduces milestone 1's pre-existing `buffer overflow`
  panic in the stock copy stack during that teardown (verified
  byte-identical panic line in milestone 1's own recorded final
  run, `.tmp/e2e-final-run.txt`) — not a milestone-2 regression.
- `go vet` clean on `protocol/musess`, `protocol/musess/fec`,
  `option`. Unit tests: codecs (incl. burst-pattern recovery and
  the klauspost nil-shard semantics), both controllers, the
  yield wrapper and floors, endpoint stream/packet/loss/
  feedback behaviour — all pass.

## Bugs the tests caught (kept as a record of method)

1. Receiver recreated already-resolved groups from late parity
   records, producing phantom all-lost resolutions that poisoned
   stats and feedback (fixed with a stale-group guard).
2. klauspost/reedsolomon v1.12.4 `Reconstruct` requires missing
   shards to be **nil**; pre-allocated zero buffers are treated
   as present-but-corrupt (wrapper fixed; test-pinned).
3. The RS codec initially built encoders only for k=16, silently
   leaving flushed partial groups (k<16) without parity;
   encoders are now cached per (k, r).
4. A fully-lost group's ID blocked ordered delivery forever;
   the receiver now synthesises a lost result for group-ID gaps
   after a timeout (fatal in stream mode).
5. Packet mode originally went raw at zero redundancy, starving
   the feedback loop (an adaptive controller could never
   engage); packet mode now always groups.
6. `fec.Conn` Write is queue-based; Close initially discarded
   queued tail bytes, corrupting a 1 MiB stream fetch (found by
   run-e2e-fec.sh). Close now drains, and Write applies a
   high-water backpressure bound.
7. sing-box's log formatter panics on float64 args ("unknown
   value"); the FEC stats callback formats to a single string
   (found when the panic crashed the test server mid-e2e).

## Deviations from DESIGN.md

1. **FEC default is off (opt-in) in milestone 2.** Decision #5
   put FEC in v1; v1 has not shipped. On the only carrier that
   exists today (TCP fallback), FEC measurably has nothing to
   recover, so shipping it default-on would tax every connection
   ~0.8% in headers for zero measured benefit. The default-on
   question is deferred to the QUIC milestone, where the carrier
   exposes loss; the DESIGN.md status block records this.
2. **DESIGN.md 5.2's "partial preservation signal" into
   congestion control** exists only inside the FEC layer's own
   feedback accounting (recovered shards count as loss events
   for redundancy control). On the TCP path the kernel owns CC
   and there is no CC surface to signal into; the falsification
   experiment of ch. 9.3 for a coupled CC remains QUIC-path work.
3. **Per-flow differentiation (5.1/5.2)** is implemented as
   stream-vs-packet policy (packet flows group and protect
   first; bulk streams ride raw records while loss is absent)
   plus per-connection controllers. The partial-reliable stream
   class does not exist yet — it is a QUIC-path concept.
4. **Oversize UDP packets** (>1400B) bypass FEC as raw records
   (no fragmentation in milestone 2).

## What remains unverified

- Any WAN behaviour: real access-link loss patterns, RTTs,
  middleboxes. All numbers above are loopback/sandbox.
- FEC benefit on the real QUIC datagram path (the harness models
  its record-loss shape; the path itself is milestone 3+).
- BBR reference numbers (unavailable in this sandbox).
- The full ch. 9.3 FEC experiment protocol (this milestone's
  harness is a first pass: uniform + one Gilbert burst model +
  saturation; it is not the complete 9.3 matrix).
- Estimator vs fixed-step under real non-stationary loss (the
  burst row shows the estimator's known weakness; whether it
  matters on real links is unmeasured).
- UDP full round trip in this sandbox (policy-blocked last hop,
  as in milestone 1).
- REALITY-style certificate borrowing (milestone-1 deviation 1)
  and the TCP single-stack itemisation (ch. 10 #2) — unchanged,
  still open.

## Files added / changed in milestone 2

In `sing-box/`:

- `protocol/musess/fec/fec.go` — codec/controller contracts,
  design constants.
- `protocol/musess/fec/xor.go`, `rs.go` — the two codecs.
- `protocol/musess/fec/controller.go` — fixed-step + estimator
  controllers and the shared yield/floor/cap shell.
- `protocol/musess/fec/record.go` — wire record format.
- `protocol/musess/fec/endpoint.go` — the duplex FEC connection
  (group assembly, reconstruction, feedback, gap synthesis,
  stats).
- `protocol/musess/fec/fec_test.go`, `endpoint_test.go`,
  `bench_test.go` — unit tests and the comparison harness.
- `protocol/musess/fecwire.go` — musess-side glue: mode parsing,
  production codec/controller selection, packet adapter,
  per-connection stats logging.
- `protocol/musess/framing.go` — request header v2 (flags byte),
  generalised packet-conn interface.
- `protocol/musess/inbound.go`, `outbound.go` — FEC negotiation
  and wiring on both data planes.
- `option/musess.go` — `fec` option on inbound and outbound.
- `go.mod` / `go.sum` — `github.com/klauspost/reedsolomon
  v1.12.4` added.

In `test/`:

- `run-e2e-fec.sh` — FEC functional e2e (6 checks).
- `bench-e2e.sh`, `ss2022-server.json`, `ss2022-client.json` —
  end-to-end benchmark driver and the Shadowsocks-2022 baseline
  pair.
- `helper/main.go` — `shim` (delay/hold impairment),
  `bulkserver`, `bulkclient` modes.
