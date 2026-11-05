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
feedback every 100 ms, one run per cell in the tables
immediately below. A 3× idle-machine repetition of the uniform
matrix and of the e2e bench is reported in "Repetition re-run
(idle machine, 3×)" further down; several absolutes from this
single run did **not** reproduce there — read the two together.

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

Repetition note (2026-11-05): in the 3× idle-machine re-run
reported below, the codec half of this decision reproduced in
every run (the RS pair sits above the XOR pair above the
no-FEC baseline at every loss level, on delivery); the
controller half did not separate — estimator and fixed-step
were tied within ±0.27pt across all lossy RS cells. Treat
"estimator > fixed-step" as unconfirmed and "RS > XOR" as
confirmed; see "Repetition re-run (idle machine, 3×)".

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
in a constrained sandbox, not WAN results. A 3× idle-machine
repetition of this bench is reported in "Repetition re-run
(idle machine, 3×)" below: the delay-column ordering and the
100 ms musess/SS2022 ratio reproduced (0.39, per-run
0.38–0.40, against 0.41 here).

FEC functional e2e: `test/run-e2e-fec.sh` — 6/6 checks pass:
1 MiB byte-identical fetch over the negotiated FEC duplex (TCP
and through the delay+hold shim), negotiation markers in both
logs, UDP probe carried through the FEC packet plane to the echo
server (full round trip still blocked at the final stock-socks
hop by this sandbox's UDP policy, as in milestone 1), and clean
fallback to plain framing when the server declines FEC.

### Repetition re-run (idle machine, 3×)

On 2026-11-05 the uniform-loss matrix and the e2e delay bench
above were re-run 3 times each on this machine, strictly
sequentially, with nothing else running (load average 1-min
0.05–0.36 in the before/after readings for every reported
run, after an initial settling period that saw readings up to
~1.4 from session startup). Raw logs: `.tmp/rerun/fec-rerun{A,B,C}.log`
and `.tmp/rerun/bench-e2e-run{1,2,3}.log`. One preliminary
invocation was discarded as incomplete — it hit the default
10-minute `go test` timeout after three cells. The three
reported FEC runs used a 30-minute timeout and were stopped
once the uniform section completed; the burst / saturation /
latency tables above remain single-run.

**The headline: the single-run absolutes above did not
reproduce, and the failure sits in the harness's interaction
with this environment, not in general machine slowness.**
Cross-checks from the same period: the codec CPU benchmark
reproduces (XOR encode 1468 MB/s vs 1451 above), single-core
speed and CPU idle time are normal, and the real-binary delay
bench (below) reproduces its absolutes. But in the
record-shim harness:

- at 0% loss, goodput is ≈8.8 Mbps of 20 offered in all three
  runs (transfer elapsed ≈4.4 s against the 1.92 s offered
  schedule). A ≈8.7–8.8 Mbps 0% figure had previously been
  seen only in a run under heavy parallel load; here it
  occurred at load ≤0.4, so load alone does not explain the
  harness's sensitivity;
- in every lossy cell the receive loop runs to the harness's
  60 s drain (`drainUntil` in bench_test.go), so the printed
  "goodput" is 0.54–0.64 Mbps for every config — it measures
  the drain, not the link. The goodput column of the original
  uniform table is therefore **not reproduced** and should
  not be quoted until the harness's elapsed accounting is
  revisited (a follow-up; no harness change was made during
  this re-run);
- recovered-shard counts collapse to the tens per cell (RS
  rows at 10–15% loss: 60–95 recovered per run, against the
  several hundred the original table's delivery figures
  imply), and FEC's delivery advantage shrinks with them.

What reproduced exactly: the no-FEC baseline's delivery at
every loss level — identical in all 3 runs and within
0.35pt of the original at every level. The loss floor of the
model is stable; it is the recovery path that varies.

Delivery % — median (range) over the 3 runs:

| config | 0% | 1% | 3% | 5% | 10% | 15% |
|---|---|---|---|---|---|---|
| none (baseline) | 100 (100–100) | 98.88 (98.88–98.88) | 96.97 (96.97–96.97) | 94.90 (94.90–94.90) | 89.70 (89.70–89.70) | 85.10 (85.10–85.10) |
| xor + fixed-step | 100 (100–100) | 99.40 (99.35–99.50) | 97.60 (97.55–97.65) | 95.62 (95.53–95.62) | 90.25 (90.25–90.38) | 85.28 (85.25–85.32) |
| xor + estimator | 100 (100–100) | 99.28 (99.28–99.28) | 97.58 (97.47–97.58) | 95.28 (95.25–95.40) | 89.95 (89.95–90.00) | 85.20 (85.10–85.40) |
| rs + fixed-step | 100 (100–100) | 99.67 (99.65–99.72) | 98.58 (98.58–98.70) | 96.97 (96.97–96.97) | 91.70 (91.70–91.88) | 86.28 (86.28–86.28) |
| rs + estimator | 100 (100–100) | 99.45 (99.40–99.58) | 98.70 (98.58–98.70) | 96.97 (96.97–97.08) | 91.67 (91.67–91.90) | 86.28 (86.25–86.28) |

Goodput Mbps — median (range): only the 0% column is a
transfer measurement (medians 8.76–8.80 across configs,
ranges ≤0.16 wide); every lossy cell sits at the drain
artefact (0.54–0.64, ranges ≤0.02) and carries no information
beyond the delivery column, so it is not tabulated per cell.
Overhead % — median (range): the RS rows at ≥3% loss match
the original closely (6.89–7.43 vs 5.34–8.00); at 1% both RS
controllers ran hotter than the original (rs + estimator
4.45 (3.81–4.64), rs + fixed-step 6.31 (6.26–6.31), vs 1.65 /
2.67); XOR overhead was far lower than the original (medians
1.98–4.70 across lossy cells vs 6.92–12.50), consistent with
the reduced recovery activity in this environment.

**Ranking verdict.** On delivery, the production ranking's
codec level — RS pair > XOR pair > none — held at every loss
level in all 3 runs, with a single boundary tie
(xor + estimator = none at 15% in run A, 85.10 = 85.10;
strictly above in runs B and C). The controller level —
estimator > fixed-step — did **not** hold: across the 15
lossy RS cells the estimator was ahead in 3, fixed-step in
6, and 6 were tied, with no delta above 0.27pt; fixed-step
was nominally ahead at 1% in all 3 runs. The absolute RS
advantage is also far smaller here than in the single run
(at 10%: 91.67–91.70 vs 98.32–99.15; at 15%: 86.28 vs
96.47–98.45). Net: the RS half of the production decision is
confirmed by repetition; the estimator half and the single
run's goodput/delivery absolutes are not — they are
environment-sensitive in a way this re-run exposes but does
not explain (no mechanism diagnosed here).

Delay bench — Mbps, median (range) over the 3 runs:

| leg | none | delay 25 ms/dir | delay 100 ms/dir | delay 25 ms + holds (5% × 60 ms) |
|---|---|---|---|---|
| direct (cubic) | 33667.43 (26619.68–36207.98) | 4374.48 (4126.60–4848.26) | 2019.52 (2008.68–2065.14) | 2323.27 (2303.15–2374.16) |
| shadowsocks-2022 (sing-box) | 4634.28 (3353.02–5890.49) | 1447.31 (1389.22–1836.59) | 1022.28 (1004.90–1038.18) | 1682.41 (1516.35–1729.47) |
| musess (fec off) | 3839.93 (2665.92–6504.75) | 1308.86 (986.14–1318.33) | 406.72 (383.37–410.66) | 895.37 (840.96–966.07) |

**The 0.41 observation: confirmed.** musess/SS2022 at
100 ms/dir was 0.392 / 0.382 / 0.402 in the three runs
(median 0.392), against 0.409 / 0.411 in the two original
samples — five samples now span 0.38–0.41, a stable ≈0.4×
relationship. musess's absolute reproduces almost exactly
(383.37–410.66 vs 407.60 / 410.37 originally); SS2022 ran
slightly faster here (1004.90–1038.18 vs 996.71 / 998.91),
which accounts for the small ratio shift. The unimpaired
column remains burst-dominated with wide ranges, as warned
above. As with the original observation, no mechanism is
diagnosed here — reproducibility only.

#### 20% supplement (lossy direction, 3×)

Emma's real lines run 0–20% loss, above this matrix's 15%
ceiling, and the loss is directional: heavy on the
foreign→China downlink, light on the reverse. The harness
already models exactly that shape (loss on the forward
record path, clean reverse), so these 20% cells are the
lossy-direction figures. Method: the committed harness has
no 20% cells, so they were run from a checksum-verified
byte-identical copy of the fec package kept outside the
tree (scratch only; no production or harness code changed),
with the same parameters and seeds as the main matrix,
3 runs each, idle and sequential. Logs:
`.tmp/rerun/fec-supp{1,2,3}.log`.

Uniform 20% — delivery % median (range), overhead % median:

| config | delivery | overhead |
|---|---|---|
| none (baseline) | 80.58 (80.58–80.58) | 0.83 |
| xor + estimator | 80.80 (80.75–80.80) | 4.74 |
| rs + fixed-step | 80.97 (80.77–81.05) | 7.41 |
| rs + estimator | 81.00 (81.00–81.05) | 7.43 |

Gilbert burst 20% — delivery % median (range), overhead %
median:

| config | delivery | overhead |
|---|---|---|
| none (baseline) | 81.00 (81.00–81.00) | 0.83 |
| rs + fixed-step | 83.00 (82.88–83.28) | 7.52 |
| rs + estimator | 82.88 (82.73–82.93) | 7.39 |

Goodput prints 0.52–0.53 Mbps in every supplement cell —
the same 60 s drain artefact as the main re-run, not a link
measurement. In this environment the FEC edge at 20% is
small: +0.2 to +0.5pt over no FEC (uniform) and +1.9 to
+2.3pt (burst) — the same compressed recovery as the 0–15%
re-run, not the original single run's margins. The
estimator-vs-fixed-step ordering at 20% is again a coin
flip (uniform: within 0.28pt; burst: fixed-step nominally
ahead in 2 of 3 runs).

**Estimator vs the 15% cap at 20% loss.** The rs+estimator
cells were additionally instrumented (in the scratch copy
only) to read the production estimator's final EWMA loss
estimate after each run; its uncapped request follows by
its own rule (1.25 × estimate + 0.4%, before the
MaxRedundancy clamp):

- uniform 20%: EWMA estimate 25.43% (25.02–25.96) →
  uncapped request **32.19%** (31.67–32.85), ≈2.1× the cap;
  the applied redundancy ended at the 15.00% cap in all
  3 runs;
- burst 20%: EWMA estimate 16.20% (11.71–17.59 — the
  end-of-run snapshot is noisier under a Gilbert process) →
  uncapped request **20.65%** (15.04–22.39); applied again
  15.00% in all 3 runs.

So at 20% loss the estimator presses against the cap
essentially continuously in both loss models — the cap,
not the estimator, decides how much redundancy is sent.
(The uniform-loss estimate settling ~5pt above the
configured 20% drop rate is recorded, not explained.) What
raising the cap would buy in delivery cannot be answered
from this environment's compressed recovery; the cap
re-evaluation should wait for the harness fix flagged
above. No cap or production change was made here.

### Harness fix and re-measurement (2026-11-05)

The follow-up the re-run above called for. The harness
(`protocol/musess/fec/bench_test.go`) was diagnosed
forensically, fixed, and everything re-measured. Production
FEC code was NOT changed; three production-behaviour
observations are flagged at the end for design decisions.

#### Diagnosis: why the three runs disagreed

1. **The original table did not come from the committed
   harness (proven, not inferred).** The no-FEC baseline's
   drop count is fully determined by the harness's seeded
   loss model: seed 1234 over 4000 records drops exactly
   45/121/204/412/596 records at 1/3/5/10/15% loss. Every
   re-run and supplement cell matches those counts exactly;
   the original table's counts (39/118/199/398/604) match
   none of them. Separately, the original goodput column is
   impossible under the committed receive loop, which could
   only exit a lossy cell via its 60 s drain timer — the
   original rows imply ~2 s elapsed at every loss level.
   The original absolutes must have been produced by a
   pre-final development state of the harness; what state
   exactly is not recoverable from surviving artifacts. The
   original tables above stay as labelled history; their
   absolute delivery/goodput figures are superseded by this
   section and should not be quoted.
2. **The re-run's recovery compression is fully
   mechanised.** In the old synchronous shim, each record's
   service time was a relative sleep; on this VM
   `time.Sleep(411µs)` actually takes ~1.08 ms (500 sleeps:
   541 ms vs 206 ms nominal), so the wire drained ~2.7×
   slower than the pacer filled it. The FEC send queue sat
   above the saturation threshold for most of each transfer,
   and the production yield wrapper — behaving as written —
   halved its factor per feedback window down to its 0.2
   floor, pinning applied redundancy at ~2–3% (r=1 per
   k=16 group) while feedback reported 11–14% loss
   (instrumented trace at 10% loss: requested rho
   0.140→0.150, applied 0.075→0.032→0.022; r=1 for 40 of 63
   groups; delivery 92.80%, matching the binomial bound for
   r=1 ≈ 91.8% and the re-run's observed 91.67%). Control
   experiments on the same cell: with the yield signal
   disabled, delivery 95.20% at 14.89% overhead; with a
   static rho=0.129, 97.10% at 16.87%. So the original
   pairing (99.15% delivery AND 7.15% overhead) fits no
   regime of the committed code — sustained r=3 costs
   ~15–17% overhead; r=1 caps delivery near 92%.
3. The supplement's EWMA overshoot (~25.4% read at 20%
   configured loss) is the same accounting shape as the
   trickle probe below: the value was sampled after the
   60 s drain, when the only feedback windows still moving
   are tail windows enriched with gap-synthesis all-loss
   accounting. Mid-transfer windows centre on the true
   rate. The fixed harness reads controller state at
   quiescence, not after a drain.
4. Minor: the old receive loop spawned a reader goroutine
   per message; at loop exit one message could be swallowed
   uncounted.

#### The fix (harness only)

- Asynchronous shim: `Write` parses records, applies the
  seeded loss model, and enqueues survivors; a forwarder
  goroutine releases them in order on an absolute schedule
  using timer waits (measured ~nominal on this VM, vs the
  2.6× overshoot of relative sleeps).
- The release queue is finite (512 records), modelling a
  link buffer: backpressure propagates to the FEC send
  queue as it would in a real stack. (An unbounded queue
  silently stopped the saturation cells from saturating
  anything; a busy-spin on a closed channel in the first
  fix version was caught by its own smoke run and fixed.)
- Completion is quiescence: sender done, both shims
  drained, and the receiver's resolution accounting frozen
  for 2 s. Elapsed (the goodput denominator) is the last
  delivered message's arrival time; wall time is printed
  alongside. Shim drop/forward counters are printed per
  cell, so realised drops audit against the seeded
  prediction (the no-FEC rows match exactly in every run
  below; a ≤0.2pt tail-accounting tolerance remains on
  individual cells, from tail groups resolved by expiry).
- Rig parameters unchanged otherwise (4000×1200 B,
  FeedbackInterval 100 ms in-harness vs the 200 ms
  production default — pre-existing harness choice).

#### Corrected results

Repetitions — 10 reps, per-rep seeds shared across configs
(paired), link at 43% headroom so the wire never saturates
and the cap is the binding constraint. Medians (ranges):

| config | loss | delivery % | goodput Mbps | overhead % |
|---|---|---|---|---|
| none | 5% | 95.01 (94.50–95.20) | 8.60 (7.48–8.85) | 0.83 |
| none | 10% | 90.05 (89.38–90.60) | 8.37 (5.44–8.80) | 0.83 |
| none | 15% | 85.06 (84.25–86.02) | 8.42 (5.45–8.83) | 0.83 |
| none | 20% | 80.00 (79.00–80.77) | 8.33 (5.81–8.83) | 0.83 |
| rs + fixed-step | 5% | 97.49 (97.22–97.95) | 8.06 (6.22–8.42) | 8.60 (7.32–8.88) |
| rs + fixed-step | 10% | 92.93 (92.15–93.58) | 7.94 (6.15–8.28) | 9.34 (8.13–9.60) |
| rs + fixed-step | 15% | 87.85 (86.67–88.98) | 7.89 (6.80–8.36) | 9.70 (8.41–9.85) |
| rs + fixed-step | 20% | 81.99 (81.23–82.95) | 7.81 (5.21–8.20) | 10.21 (8.45–10.35) |
| rs + estimator | 5% | 97.28 (97.05–97.50) | 8.40 (6.29–8.49) | 7.41 (6.73–8.12) |
| rs + estimator | 10% | 93.11 (92.27–93.70) | 8.12 (7.18–8.39) | 9.06 (8.58–9.53) |
| rs + estimator | 15% | 87.75 (87.08–89.08) | 8.01 (5.67–8.33) | 9.71 (9.49–9.83) |
| rs + estimator | 20% | 82.24 (81.27–83.45) | 7.94 (6.77–8.28) | 10.23 (9.91–10.37) |

Full matrix (single run, seed 1234, the historical 18%
headroom link), delivery %: uniform — none 98.88/96.78/
94.80/89.70/85.10 at 1/3/5/10/15%; xor pairs 99.2–99.4 /
97.5/95.6–95.8/90.8–91.1/86.3; rs pairs 99.4–99.7/98.6/
97.0–97.2/92.3–92.5/87.3–87.7. Burst (5%/10%): rs
94.7–95.0/89.6–90.0, xor 94.4–94.5/89.2–89.3. Saturation
(100 into 23 Mbps, 5% loss): with the yield wrapper,
rs rows deliver 96.9% at ~5.9% overhead and 8.52 Mbps
goodput; the no-yield control delivers 98.3% at
9.5–11.9% overhead but only 7.75–7.99 Mbps — the yield
rule trades ~1.4pt delivery for ~+0.6 Mbps goodput and
half the overhead under saturation, which is its design
purpose read on the goodput metric (the milestone-2
"+3.1pt delivery" framing of the same rule was
one-sided). Codec ranking RS > XOR > none holds in every
regime measured.

Trickle (100 msg/s, 5% loss): eventual delivery
94.7–96.7%, but p50 latency ≈ 1.5 s for every config —
see flagged observation 2 below. Its overhead/delivery
split is regime-dependent (probe-verified): when the host
batches messages into groups of k≥2, partial losses are
visible to feedback and the estimator engages (22.78%
overhead, 96.67% delivery in the matrix run); when groups
stay k=1, observation 3 applies and no parity is sent at
all (0.83% overhead, 94.67%).

Cap experiment at 20% loss (3 reps; harness-side clones of
the production estimator+yield with a parameterised cap —
fidelity gate: clone@15% vs production@15% delivery
medians within 0.05pt and overhead identical, so the
clone is trusted):

| config | uniform delivery % | uniform goodput | burst delivery % | overhead % (u/b) |
|---|---|---|---|---|
| cap 15% (production) | 82.17 (81.03–82.65) | 7.83 | 83.05 (80.95–83.53) | 10.24 / 10.14 |
| cap 30% (clone) | 83.33 (83.28–83.58) | 7.78 | 83.40 (83.08–84.35) | 13.49 / 12.49 |

Doubling the cap buys **+1.16pt delivery (uniform) /
+0.35pt (burst), no goodput gain** (medians −0.05/−0.38
Mbps, inside jitter), for **+3.25/+2.35pt wire
overhead**. The estimator's uncapped request at 20% loss
still ends at 21.5–22.8% (uniform) / 25.5–34.2% (burst)
in this rig, and the yield wrapper moderates the average
applied spend well below either cap. Pricing recorded
for the cap decision; no change made.

#### Verdicts

- **Codec: RS > XOR > none — confirmed** in all regimes,
  consistent with every prior run.
- **Controller: the estimator pick stands, on different
  grounds than originally claimed.** Delivery is a
  statistical tie: paired median differences (estimator −
  fixed-step) are −0.22pt at 5% (fixed-step wins 9/10
  pairs — it steps straight to 10% redundancy while the
  estimator asks ~6.7%), +0.12 at 10%, 0.00 at 15%,
  +0.35pt at 20% (estimator 7/10). But on goodput — the
  first priority — the estimator's median is higher at
  all four loss levels (+0.11/+0.16/+0.13/+0.13 Mbps,
  winning 30 of 40 pairs), and it spends less overhead at
  low loss (−0.87pt at 5%, in all 10 pairs). The original
  delivery blowout (99.15% vs 98.3% at 10%) does not
  reproduce and is withdrawn; the margin for the
  estimator is real but small, and fixed-step remains a
  legitimate simpler alternative within delivery noise.
- **FEC's corrected edge** over no FEC in this rig:
  +2.2 to +3.1pt delivery across 5–20% uniform loss at
  ~7–10% applied overhead (yield-moderated). Absolutes
  remain environment-bound (this rig completes every
  config, FEC or not, at ~8–9 Mbps — receiver-processing
  paced); deltas and rankings are the content. FEC
  benefit on a real QUIC path or WAN is still unmeasured.

#### Flagged production observations (no change made)

1. **Yield-wrapper depth.** Under a sustained send-queue
   backlog the factor halves per feedback window to its
   0.2 floor (and recovers ×1.5/window), so adaptive
   redundancy effectively disengages to ~1 parity per
   group for as long as the queue stays full — regardless
   of measured loss. That is the wrapper behaving as
   written; whether DESIGN 5.2's saturation rule intends
   disengagement this complete is a design question, to
   settle with a real saturated-link test, not this rig.
2. **Ordered-delivery head-of-line stall.** One fully-lost
   group blocks delivery of everything behind it until
   arrivals pause for >GroupTimeout (150 ms) and gap
   synthesis advances the cursor. Quantified at trickle:
   p50 ≈ 1.5 s at 100 msg/s with 5% loss, for FEC and
   no-FEC alike. Bulk groups (k=16) make full-group loss
   ~impossible at these rates, but the packet/UDP plane
   with small groups is exposed — and real UDP semantics
   would not stall. A design question for the QUIC
   milestone.
3. **Feedback blindness at small group sizes.** A
   fully-lost group contributes nothing to any feedback
   window until gap synthesis runs (post-pause); the loss
   then lands as a single all-loss window (probe at
   trickle: 31 consecutive ratio-0.000 windows during a
   5%-loss stream, then one window of exp=16, lost=16,
   ratio=1.000 after it ended, slamming both controllers
   to the cap with nothing left to protect). Controllers
   are blind to trickle loss mid-stream and see a loss
   spike after pauses; any future interactive-traffic FEC
   behaviour must reckon with this accounting shape.

### Flagged observations: design treatment (2026-11-05)

The three observations above were analysed, prototyped behind
experiment flags, and measured in the fixed harness (paired
seeds, 3 reps per cell, medians; runs sequential, host load
checked <0.5 on 4 cores before each bench; logs in
`.tmp/exp-obs/`). Production defaults are unchanged: the
treatments live behind `fec.NewControllerWithYieldPolicy`,
the `Options` experiment fields (`PacketOutOfOrder`,
`EagerGapSynthesis`, `GapProofGrace`), and — for e2e only —
the `MUSESS_FEC_EXP` environment variable read in
`fecwire.go` (unset = production options exactly). As a
behaviour-neutral check on the endpoint refactor this work
required, today's production arms reproduce the harness-fix
tables almost exactly (bulk rs+estimator at 5%: delivery
97.28 vs 97.28, overhead 7.38 vs 7.41; saturation production
96.88 vs ~96.9; trickle production p50 1555 ms vs ~1.5 s).

#### Observation 1 — yield-wrapper depth

Mechanism: the wrapper's factor halves per feedback window
while the FEC send queue exceeds 256 KiB, floored at 0.2,
recovering ×1.5/window; three backlogged windows reach the
floor, and applied redundancy = inner × 0.2 regardless of the
loss the feedback is reporting (at 20% loss: capped inner
0.15 → applied 0.03, one parity per k=16 group against ~3.2
expected losses per group). The schedule is a function of
backlog duration only. It bites on bulk transfers over links
that are simultaneously saturated and lossy (the foreign→China
downlink at peak), and the signal is a proxy: queue depth also
fires for producer bursts and slow receivers, which the
wrapper cannot distinguish from link saturation.

Treatments prototyped: **(A) loss-aware yield floor** — yield
may trim only the margin above a measured-loss cover,
cover = p/(1+p) from the wrapper's own feedback EWMA (the
parity fraction at which a group carries as many parity
shards as its expected losses); **(B) shallower blind floor**
(factor floor 0.4). A harness-side fidelity gate came first:
the experimental wrapper with a zero policy reproduces the
production controller's output exactly on a scripted
feedback/backlog sequence (unit test) and on the saturation
cell its per-rep rows are identical to production's
(delivery 96.88, overhead 5.90 — the clone is the same
controller, not a near miss).

Saturation cell (100 into 23 Mbps, 5% loss), medians
(ranges) over 3 reps:

| arm | delivery % | goodput Mbps | overhead % |
|---|---|---|---|
| production (floor 0.2, blind) | 96.88 (96.45–97.22) | 8.49 | 5.90 |
| yield-clone (fidelity) | 96.88 | 8.52 | 5.90 |
| loss-aware floor | 97.15 (96.65–97.20) | 8.25 | 6.35 |
| blind floor 0.4 | 96.88 | 8.54 | 5.90 |

On the saturation cell the differences are small: the
loss-aware floor's +0.27pt delivery sits inside overlapping
ranges, its overhead is +0.45pt, and its goodput is
nominally the lowest of the four arms. The blind 0.4 floor
never differentiates from production in these cells at all
(per-rep deliveries identical) — the factor evidently does
not bind below 0.4 long enough here for the floor value to
matter, so this rig says nothing for or against it.

The unsaturated spot cells (43% headroom link) are where
the cover actually binds — transient backlogs in this rig
engage the production yield even without a saturated link,
and the cover blocks that throttling:

| loss | arm | delivery % | goodput Mbps | overhead % |
|---|---|---|---|---|
| 5% | production | 97.40 | 8.38 | 7.42 |
| 5% | loss-aware | 97.40 | 8.45 | 7.40 |
| 10% | production | 93.42 | 8.13 | 9.39 |
| 10% | loss-aware | 95.43 | 8.22 | 13.06 |
| 20% | production | 82.00 | 7.83 | 10.22 |
| 20% | loss-aware | 85.40 | 7.70 | 16.52 |

At 5% the two are indistinguishable. At 10–20% the cover
buys real delivery (**+2.01pt at 10%, +3.40pt at 20%**) at
real cost (**+3.67pt / +6.30pt overhead**), and goodput does
not follow (+0.09 / −0.13 Mbps): in this rig goodput is
receiver-paced, so recovered shards do not convert into
throughput the way they would where a loss means an
upper-layer retransmission stall. The mechanism is proven —
the cover demonstrably spends, and delivers, exactly where
the blind yield was collapsing protection — but the *net*
value is not established here: on Emma's first-priority
metric (goodput) the measured gain is zero.

**Verdict: defer.** Do not change the production yield
wrapper on this evidence. What is missing is a test where
recovery converts to goodput under combined saturation and
loss — a real saturated lossy link, or the QUIC datagram
path where FEC recovery is load-bearing — which is the
same missing input as the signal question below (queue
depth vs true wire saturation). If that test shows the
cover's delivery gains converting to goodput, the
prototyped change is ready to land as-is; if it shows the
overhead crowding out data on a truly saturated link, the
production collapse is the lesser evil and this becomes
accept-and-document. Signal hygiene stays open for the
same reason: it needs the real saturated-link test this
rig cannot provide.

#### Observation 2 — ordered-delivery head-of-line stall

Mechanism: one delivery cursor (`pumpDeliverLocked`) serves
both modes; a fully-lost group has no receiver-side trace, so
the cursor waits for gap synthesis, whose trigger is an
arrival *pause* longer than GroupTimeout (every new group
refreshes `maxGroupTime`). Under continuous arrivals the
pause never comes mid-stream: the first fully-lost group
blocks everything behind it until the stream ends. At trickle
the groups are k=1 (5 ms flush vs 10 ms spacing), so one
dropped record is one fully-lost group — and observation 3
guarantees those groups carry no parity. Packet mode
inherits the stall by construction; nothing in UDP semantics
asks for it.

Treatments prototyped: **(A) delivery-semantics split** —
packet mode delivers each group as it resolves (partial
preservation, DESIGN.md 5.2), stream mode keeps the ordered
cursor; the cursor degrades to an accounting role so gap
synthesis still accounts each lost group exactly once;
**(B) gap-timeout tuning** (150 → 50 / 25 ms); **(C) eager
gap synthesis** (observation 3's treatment) as a mitigation.

Trickle cell (100 msg/s, 5% loss), medians over 3 reps,
identical for the no-FEC, fixed-step and estimator rows
unless noted:

| arm | delivery % | p50 | p95 | overhead % |
|---|---|---|---|---|
| ordered GT150 (production) | 94.33 | 1555 ms | 2905 ms | 0.83 |
| **unordered (A)** | 94.33 | **14.7 ms** | **14.9 ms** | 0.83 |
| ordered GT50 (B) | 94.33 | 1405 ms | 2755 ms | 0.83 |
| ordered GT25 (B) | 95.0–96.0 | 1040–1468 ms | 2380–2839 ms | 9.6–23.4 |
| eager (C), FEC engaged | 97.3–99.0 | 583–945 ms | 1010–1926 ms | 34.9–46.8 |

Unordered delivery is a pure win in this rig: **p50 falls
~100× (1555 → 14.7 ms) and p95 ~200×, at identical delivery
and identical overhead** — the same messages are lost, they
are just not waited on. Bulk spot cells (5/10/20%) show no
regression (delivery within 0.2pt of ordered, overhead
identical). Timeout tuning is rejected on measurement: the
trigger is pause-based, so the value barely matters under
continuous arrivals (GT50: −150 ms of 1555), and GT25 is
*unstable across runs* (overhead 9.6% in one run, 23.4% in
the next) — at this link's ~8.6 ms/record service time a
group of k+r ≥ 3 records spans more than 25 ms on the wire,
so GT25 resolves in-flight groups as lost, manufactures
feedback loss, and the spend/expiry loop's gain varies run
to run. (General form: GroupTimeout must exceed a group's
wire span; that coupling is itself an argument against
tuning as the lever.) Eager synthesis helps — its engaged
rows recover delivery to 97.3–99.0% — but its latency stays
dominated by parity-spend queueing (see observation 3), so
it is a mitigation, not the fix, for this observation.

**Verdict: adopt (as a recommendation to Emma) for the
packet plane: make unordered delivery the packet-mode
default** — it is DESIGN 5.2's partial preservation arriving
via measurement. Two adoption prerequisites, both noted for
the landing change, not prototyped here: the delivered-set
map must become a bounded sliding window (the prototype's
map grows with connection lifetime), and same-destination
UDP flows will observe reordering around losses (legal for
UDP, and the in-tree packet path processes each framed
packet independently, but not re-verified against every
sing-box packet consumer). **Stream mode:
accept-and-document** — ordered delivery is semantically
mandatory for a byte stream; the stall there is bounded by
gap synthesis after pauses, and the structural answer is
the QUIC milestone's stream/datagram split, not anything
this layer can do.

#### Observation 3 — feedback blindness at small group sizes

Mechanism: the feedback accumulator is fed only by group
resolution and by (post-pause) gap synthesis, so a
fully-lost group is invisible while the stream runs; at
trickle that is the dominant loss mode. The harness trace
reproduces the flagged probe exactly: production shows 32
feedback windows of which the first 31 are ratio 0.000, then
one window at t=3.31 s with exp=16, lost=16, ratio 1.000,
slamming redundancy to the 0.15 cap after the stream is
over. A unit-level run pins the same shape: production
mid-stream redundancy is exactly 0 throughout a 5%-loss
trickle, and jumps to the cap only after a post-stream
pause. The controllers are not at fault; the accounting
shape starves any controller identically. (The harness-fix
note's tail-window EWMA overshoot is this same shape seen
from the other side.)

Treatment prototyped: **eager gap synthesis** — on the
ordered record carrier, a later group's first record is
proof that an unseen earlier slot's records were dropped
(they precede it in the stream), so the receiver declares
the slot lost on that proof (plus an optional grace,
`GapProofGrace`) instead of waiting for a pause. Receiver-
local: no wire or format change. A chained-gap refinement
(one expiry tick clears a whole run of consecutive gaps, not
one gap per tick) was measured separately: it cut the
no-FEC eager arm's p95 from 141 to 60 ms, and did not move
the FEC-engaged arms — their latency is queueing, not
synthesis (below).

Trace with eager synthesis: first nonzero window at #3
(t=0.41 s, ratio 0.091), 12–14 nonzero windows spread across
the stream, redundancy tracking the losses as they happen
(0.038–0.150) instead of arriving as one post-mortem spike.
Consequences in the trickle cell: the controllers engage
mid-stream and delivery rises 94.33 → 97.33% (fixed-step) /
99.00% (estimator). Two costs, both measured and neither
hidden:

- **Small-group spend**: an engaged controller puts r=1 on
  every k=1 group (`ParityFor(1, ρ) = 1`), ~100% parity per
  protected group; trickle overhead lands at 34.9–46.8%.
- **Spend queueing**: on the trickle link (18% headroom over
  payload), engaged parity roughly doubles wire demand
  (~1.9 vs 1.13 Mbps), so latency stays queue-dominated
  (p50 583–945 ms) even though delivery is fixed. The
  no-FEC eager arm (p50 14.7 ms) isolates the accounting
  path itself as fast; the engaged arms' latency is the
  spend, not the synthesis.

Bulk cells show eager synthesis is behaviour-neutral where
groups are large (delivery within 0.3pt of ordered at
5/10/20%, mixed sign; overhead identical) — fully-lost
groups barely exist there; what changes is only *when* the
rare one is declared, which also cleans up the tail-window
accounting.

**Verdict: adopt (as a recommendation to Emma) the
accounting change — eager gap synthesis on ordered
carriers.** It fixes the signal every controller and every
future cap/yield decision reads, at zero wire cost, and is
bulk-neutral. **Deferred, as a required companion before
FEC-on can be a default for interactive flows: a
small-group spend policy** (batching toward k≥4 at low
rates, or parity priced by group size). That is a separate
design question — it trades latency (batching delay) for
overhead on exactly the flows whose latency matters — and
it has not been measured yet; eager synthesis plus today's
spend policy at trickle trades 35–47% overhead for
+2.7–4.7pt delivery, which fails DESIGN 5.4's budget and
should not ship as a default. Cumulative feedback (the
carrier-independent form of this fix, needed where records
can reorder) is designed but not prototyped: it belongs to
the QUIC milestone's feedback design, with `GapProofGrace`
as the bridge for datagram carriers. Sender-side loss
inference was rejected on inspection: off-harness, the
sender cannot distinguish a lost group from lost feedback.

#### Regression gates for this work

- `go vet` clean (`protocol/musess/fec`, `protocol/musess`,
  `option`); full fec and musess unit tests pass, including
  five new experiment tests (yield-clone fidelity,
  loss-aware floor bounds, both blind-floor arms, unordered
  endpoint delivery, eager feedback engagement).
- FEC e2e (`test/run-e2e-fec.sh`): **6/6 with flags off and
  6/6 with `MUSESS_FEC_EXP=uo,eager`** on the rebuilt binary.
- Milestone-1 e2e (`test/run-e2e.sh`): **5 passed, 1 failed —
  the established profile**; the failure is check (d), the
  sandbox's unconnected-UDP EPERM at the final stock-socks
  hop, with the same pre-existing stock `buffer overflow`
  panic in that teardown.
- Nothing in the production construction paths changed
  defaults: `NewController`, the `Options` zero value, and
  the musess `fec` option surface behave exactly as in
  milestone 2 unless an experiment flag is explicitly set.

#### Still open after this work

- The real saturated-link test for observation 1's signal
  question (queue depth vs wire saturation), and any WAN
  validation of all three verdicts — every number above is
  this sandbox's record shim, as before.
- QUIC milestone inputs: partial-reliable delivery semantics
  (observation 2's split is the TCP/UDP-plane preview),
  cumulative feedback for reordering carriers and the
  reordering window `GapProofGrace` must cover
  (observation 3), and the small-group spend policy —
  batching vs size-priced parity — which gates FEC-on for
  interactive flows on any carrier.
- Files: `protocol/musess/fec/experiment.go` (yield policy),
  `experiment_test.go`, `exp_bench_test.go` (the three
  `TestExp*` entry points), experiment fields and pumps in
  `endpoint.go`, the `runTransferMod` split in
  `bench_test.go` (nil modifier = the fixed harness,
  unchanged), and the env-gated flag application in
  `protocol/musess/fecwire.go`. Bench logs:
  `.tmp/exp-obs/{yield,trickle,trickle2,uobulk}.log`.

#### Small-group spend policy (observation-3 companion, 2026-11-05)

The deferred required companion from observation 3's verdict:
eager gap synthesis makes the controllers engage at trickle,
and the engaged spend is what fails DESIGN 5.4's budget.
Prototype + measurement only — production defaults are
unchanged; everything lives behind the `Spend*` Options
fields and the credit codec (`spend.go`), reachable only
from tests, with no `fecwire.go` wiring.

The defect, priced: parity is charged per group
(`ParityFor(k, rho) >= 1` for any positive target) but rho is
a byte fraction, so the minimum nonzero spend on a group is
1/k of it. At trickle the packet plane's groups are k=1
(5 ms flush vs 10 ms spacing), and the estimator's ask at 5%
loss is ~6.7% — a ~15x per-group overspend, blended by the
yield wrapper and the engagement ramp to the measured
incumbent: **99.33% delivery at 46.82% overhead, goodput
0.57 Mbps against the no-FEC arm's 0.90, p50 873 ms** (this
run's re-measurement of the eager arm; the observation-3
record's 34.9–46.8% range stands).

Candidates (analysis in `spend.go`): **(A) batching** — hold
a protected group until k >= MinK or a delay budget expires,
amortising the one-shard minimum price; **(B) fractional
parity credit** — bank the exact fractional parity the
target implies and spend whole shards only when the credit
reaches one, so long-run spend equals the target;
**(C) minimum-group gate** — groups below MinK ride raw
unless the target reaches a high-loss gate. (B) was
predicted dominated before measurement: the estimator's
formula is a *coverage* fraction for populations where
parity spreads across a group, and concentrating the spend
on a rho-fraction of k=1 groups recovers only ~rho of the
losses. It was prototyped anyway (a wrapper codec) so the
prediction is falsified or confirmed by numbers, not taste.

Method: fixed harness throughout, eager synthesis ON in
every cell (the exposing configuration), paired seeds
(trickle 31337+rep*7919, bulk 1234+rep*7919), 3 reps per
cell, medians (ranges), sequential; host load checked
<0.5 on 4 cores before each bench. Logs in `.tmp/spend/`.

Pure batching price, isolated on the wire (sender Conn over
a raw pipe, no loss/shim/receiver, static rho=0.10, hold =
WriteMessage -> the message's data record on the wire):

| setting | hold p50 | hold p95 | hold max |
|---|---|---|---|
| current (5 ms flush) | 5.2 ms | 5.3 ms | 5.3 ms |
| batch k4 / 40 ms | 16.2 ms | 31.5 ms | 31.6 ms |
| batch k8 / 80 ms | 43.1 ms | 73.6 ms | 83.2 ms |
| batch k12 / 130 ms | 59.4 ms | 114.8 ms | 115.0 ms |

Trickle cell (100 msg/s, 300x1200B, 5% uniform loss),
rs + estimator, medians (ranges) over 3 reps:

| arm | delivery % | goodput | p50 | p95 | overhead % |
|---|---|---|---|---|---|
| eager current | 99.33 (98.33–99.67) | 0.57 | 873 ms | 1924 ms | 46.82 |
| batch k4 b40 | 97.00 (97.00–98.67) | 0.86 | 164 ms | 289 ms | 18.58 |
| **batch k8 b80** | **97.67 (97.00–98.00)** | **0.90** | **123 ms** | **175 ms** | **11.31** |
| batch k12 b130 | 97.00 (96.33–98.00) | 0.88 | 201 ms | 275 ms | 11.91 |
| gate kmin4 r.12 | 94.33 (93.67–94.67) | 0.90 | 52 ms | 150 ms | 6.74 |
| hybrid v1 (b8 + emit-gate) | 97.33 (97.00–98.67) | 0.89 | 146 ms | 212 ms | 12.11 |
| credit | 94.00 (93.33–95.67) | 0.90 | 24 ms | 55 ms | 7.03 |
| eager noFEC (reference) | 94.33 (92.33–94.67) | 0.90 | 14.7 ms | 56 ms | 0.83 |

Fixed-step subset, same cell: current 96.00 / 0.70 /
427 ms / 32.57%; batch k8 97.00 / 0.87 / 197 ms / 16.12%;
gate 97.33 / 0.68 / 527 ms / 35.36% (delivery / goodput /
p50 / overhead).

Readings, in Emma's priority order (goodput, then
overhead/budget, then latency):

- **Batching k8/b80 dominates the incumbent on all three
  metrics at once**: goodput 0.57 -> 0.90 (back to the
  no-FEC level — the incumbent's parity spend was saturating
  the 18%-headroom trickle link), overhead 46.82 -> 11.31%,
  p50 873 -> 123 ms, for −1.66pt delivery. The 43 ms wire
  hold is real but the end-to-end latency *falls* ~750 ms:
  the incumbent's latency was spend queueing, not synthesis.
  The frontier bends at k8: k4 is too coarse (r=1 over k=4
  is a 20% achieved rate, 18.58% measured), and k12 buys
  nothing — equal overhead (11.91%; ask-spike groups pay
  r=2–3 even at k=12, because the estimator's instantaneous
  target distribution has a fat upper tail on small
  feedback windows), slightly lower delivery (larger groups
  at r=1 fail on >=2 losses more often), and more hold.
- **Credit is falsified as predicted**: spend tracks the
  ask (7.03% measured vs ~6.7% ask + ~0.8% headers) and
  delivery gain is nil (94.00 vs noFEC 94.33 — inside
  noise of zero). Aligning spend with the target's
  accounting identity surrenders the outcome the target
  exists for. Rejected.
- **The gate alone is controller-dependent**, because it
  thresholds the controller's *instantaneous* target: with
  the estimator (smooth ~6.7% ask at 5% loss) it stays shut
  except on noise crossings — 6.74% spent on randomly
  opened windows for exactly the no-FEC delivery (94.33).
  With fixed-step (quantised 0.10/0.15 targets) the top
  step clears the 0.12 gate and protection engages
  (97.33% delivery, at 35.36% overhead). A gate threshold
  cannot be chosen controller-agnostically; recorded as a
  property of the mechanism, not a tuning miss.
- **At 20% loss the ranking inverts** (same cell, 20%
  uniform): current 95.33 / 0.62 / 696 ms / 49.44%; batch
  k8 **86.00** (83.67–89.67) / 0.78 / 128 ms / 20.22%;
  gate 95.33 / 0.63 / 658 ms / 48.66%; hybrid v1 87.67 /
  0.78 / 129 ms / 20.01%. Batching amortises parity by
  spreading the *capped* target thinner, and at 20% loss
  the binding constraint is loss clustering, not
  quantisation: P(>=3 losses in k=8) ~ 20% against r=2,
  while an unbatched k=1 group at r=1 recovers whenever
  its parity shard survives (delivery ~ 0.80 + 0.20*0.80
  = 0.96, matching the incumbent). The gate arm *is* the
  incumbent at 20% (the estimator sits at the 0.15 cap,
  above the gate) — the two regimes need opposite group
  shapes, and the switch has to be the target itself.

Composed arm (batching + gate on one boundary; the hold
disengages at targets >= the gate, the emit gate covers
groups still small at flush), two boundary settings, both
trickle cells, 3 reps:

| arm | @5%: delivery / goodput / p50 / overhead | @20%: delivery / goodput / p50 / overhead |
|---|---|---|
| hybrid2, boundary 0.12 | 97.33 / 0.83 / 157–267 ms / 14.36–17.21% (two median sets) | 95.67 / 0.63 / 652–689 ms / 49.44–49.53% |
| hybrid3, boundary 0.15 | 97.33 / 0.85 / 124 ms / 10.77% | 94.67 / 0.63 / 693 ms / 47.76% |

The 0.12 boundary sits *inside* the estimator's ask noise
at 5% loss (small feedback windows push the EWMA to the
cap in isolated spikes), so it chatters: two independent
3-rep runs of the same arm gave overhead medians of 14.36
and 17.21% and p50 of 157 and 267 ms — a variable tax for
recovering the incumbent exactly at 20%. The 0.15 boundary
(at the cap) is quiet at 5% (10.77% overhead, p50 124 ms —
statistically the batch-k8 row) and near-incumbent at 20%
(delivery −0.66pt vs current, ranges overlapping:
93.33–95.33 vs 95.00–95.67; the residual tax is windows
where the EWMA dips just below the cap and a few groups
batch). An instantaneous threshold cannot distinguish
"touching the cap" from "pinned at the cap"; a
persistence-qualified boundary (target at cap for N
consecutive windows) is the refinement a landing change
should carry — designed here, **not measured**.

Composition evidence (traces, seed 31337, estimator stack
with the yield wrapper inside the trace): every arm's
first nonzero feedback window is #3 at t=0.41s, ratio
0.091 — eager accounting is policy-invariant, as it must
be. Applied-redundancy ranges: current [0.018, 0.150] with
5 post-engagement zero windows (the yield wrapper
collapsing under the spend's own backlog); batch k8
[0.020, 0.150] with **0**; gate [0.028, 0.135] with 0;
credit [0.028, 0.127] with 0; hybrid v1 2. No arm shows
engage/disengage oscillation; batching is
composition-*positive* (it removes the backlog that was
driving the yield flapping), the gate and credit are
stateless at emit/pricing time and cannot feed back into
the controller. The fixed-step subset above cross-checks
batching under the second controller (helps there too:
overhead 32.57 -> 16.12%, delivery +1.0pt, goodput
0.70 -> 0.87).

Bulk no-regression (uniform spot cells, repetitions link,
eager on, rs + estimator, medians over 3 reps): at 5%
every arm delivers 97.15–97.30% at 7.33–7.63% overhead;
at 10%, 92.90–93.60% at 9.27–9.51%; at 20%, 81.73–82.33%
at 10.09–10.29% (full table in `.tmp/spend/bulk.log`).
No arm regresses any bulk cell beyond jitter (delivery
spread across arms <=0.15pt at 5%, <=0.70pt at 10%,
<=0.60pt at 20%; overhead spread <=0.30pt): at bulk
arrival rates the holds never bind except at flush
tails, the gate's k threshold sits below natural group
sizes, and the credit codec delegates at k>=4 by
construction.

**Verdict — the policy that should gate FEC-on for
interactive flows is the composed one**: batch toward
k>=8 under an 80 ms budget while the target is below the
boundary; boundary at the cap end (0.15 measured quiet,
0.12 measured chattery); groups still below k=8 when the
budget expires ride raw below the boundary (the emit
gate) rather than paying 1/k at a low target; at or above
the boundary, today's behaviour (immediate small groups
at full parity). Priced at 5% loss (hybrid3 vs incumbent):
overhead 46.82 -> 10.77%, goodput 0.57 -> 0.85, p50
873 -> 124 ms, delivery 99.33 -> 97.33%. At 20% loss:
delivery −0.66pt and overhead −1.7pt against the
incumbent — the policy is regime-shaped on purpose.
Thresholds the measurements support: **MinK 8** (k4 too
coarse, k12 no gain), **budget 80 ms** (the 130 ms arm
buys nothing; the pure hold at k8/b80 is p50 43 / p95
74 ms, and end-to-end it is repaid by un-queueing in
this cell), **boundary 0.15, not 0.12**, **gate threshold
= batch MinK**. Two honest limits on the win: 10.77%
still exceeds DESIGN 5.4's 8% budget at 5% loss — no
measured arm reaches <=8% while actually protecting
(credit and gate get under it only by not protecting) —
and the composed policy's high-loss spend is the
incumbent's ~48%, which is the measured price of 95%
delivery at 20% loss on k=1-shaped flows, not a saving.

Still unmeasured: the persistence-qualified boundary;
the batching hold as a *pure addition* on an uncongested
link (in this cell it is repaid by un-queueing — a
higher-headroom trickle link would isolate it); message
rates other than 100/s (at 500/s a k=8 batch fills in
~14 ms and the hold nearly vanishes; below 100/s the
budget expires with k<8 more often and the gate carries
more weight); burst loss at trickle; composition with
unordered packet delivery switched on (all spend cells
ran ordered + eager); anything off this rig (WAN, QUIC
carrier) — as everywhere in this record.

Regression gates for this work: `go vet` clean (fec,
musess, option); full fec and musess unit tests pass,
including four new spend tests (credit accounting and
delegation, gate below/above/off at the endpoint, batching
formation + budget expiry + regime-boundary disengage).
FEC e2e (`test/run-e2e-fec.sh`) **6/6 with flags off** on
the rebuilt binary; milestone-1 e2e **5 passed, 1 failed —
the established profile** (check (d), sandbox UDP EPERM).
Nothing in production construction paths changed: the
`Spend*` zero values and an unwrapped codec reproduce
milestone-2 behaviour exactly, and `fecwire.go` does not
reference the spend fields. Files: `spend.go` (analysis +
credit codec), `spend_test.go`, `spend_bench_test.go`
(`TestSpendTrickle{,20}`, `TestSpendHybrid2`,
`TestSpendBulk`, `TestSpendTraces`, `TestSpendHoldWire`),
the `Spend*` fields + emit gate + flush hold in
`endpoint.go`. Bench logs: `.tmp/spend/`.

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


---

# musess — rate attack, phase 1 (2026-11-05)

Emma's directive: if the rate is not good, find out why, test
candidates head-to-head, combine winners, and invent a new
high-rate approach if the structure is the ceiling. Selection stays
measurement-based; priority 速率 > 伪装 > 延迟. Phase 1 =
diagnosis + individual screens. **No production code was changed
by phase 1**: the prototype lives in `impl/.tmp/exp-tree/` (a copy
of the tree) and the lab scripts in `impl/.tmp/rate-lab/`; the
production tree's only working-copy changes belong to the parallel
FEC task.

## Target fact (reproduced)

On `test/bench-e2e.sh` (32 MiB, user-space delay/hold shim — a
latency model, NOT packet loss, NOT netem), musess (TCP, FEC off)
falls behind Shadowsocks-2022 as delay grows: at 100 ms/dir,
musess ≈ 390–400 Mbps vs SS2022 ≈ 1000 Mbps in a fast window
(ratio ≈ 0.39; re-verified 2026-11-05: 398 vs 1014).

Environment honesty: sandbox, loopback, cubic only (no BBR), 4
cores shared with a parallel task. Absolute sandbox Mbps move
with machine state — SS2022's own delay100 figure ranged
555–1056 Mbps across windows on the same day — so the load-bearing
quantities below are the load-insensitive ones: time-to-first-byte
(TTFB, the musess leg is setup-bound and its times repeat to the
millisecond) and within-window medians of total time.

## Diagnosis

**Experiment 1 — delivery profile** (progress-reporting bulk
client, 256 MiB, delay100): musess delivers its first byte at
t ≈ 0.61 s, then flows at rates comparable to SS2022; SS2022's
first byte arrives at t ≈ 0.24 s. The deficit is concentrated
*before* the data flows, not in the flow.

**Experiment 2 — steady state** (1 GiB, delay100, 3 runs each):
musess 2632 / 2780 / 2503 Mbps vs SS2022 2378 / 2689 / 2438 Mbps —
statistical parity. There is **no steady-state throughput
deficit**, so the chained-TCP window/buffer-meltdown hypothesis
is rejected by measurement: with `tcp_wmem` capped at 4 MiB both
protocols sustain ~2.5 Gbps through the same shim, and the direct
leg through the same shim reaches ~2.0 Gbps at delay100.

**Root cause — connection-setup flight serialisation.** Counting
one-way flights through the impaired leg (delay d each):

| step | stock musess | SS2022 |
|---|---|---|
| handshake flight 1 (ClientHello / SS header+request) | d | d |
| handshake flight 2 (server flight / first relayed data) | d | d |
| client Finished (Go's std `tls.Server` handshake returns only after reading it) | d | — |
| server proof flight (inbound writes proof, *then* reads the request) | d | — |
| request flight (outbound reads proof, *then* writes the request) | d | — |
| first relayed data flight | d | — |
| **TTFB at d = 100 ms (model)** | **0.60 s** | **0.20 s** |
| **TTFB measured (1 MiB, median of 3)** | **0.611 s** | **0.241 s** |

The code serialises the last two flights by construction
(`inbound.go`: `HandshakeContext` → `Write(ServerProof)` →
`readRequest`; `outbound.go`: read proof → verify → `writeRequest`).
At the bench's 32 MiB the transfer is almost entirely setup:
0.61 s of setup + ~0.08 s of flow reproduces the stock bench
totals (0.68–0.71 s) and hence the ≈0.39 ratio. On a real WAN path
the same arithmetic applies with RTT/2 per flight: musess pays
~3 RTT before first byte, SS2022 ~1 RTT. (The milestone-1 stock
copy-stack buffer-overflow panic in a UDP teardown was not
reproduced in phase 1 and has no evidenced link to this gap.)

## Candidate screen: early request (pipelined, sealed)

Design: with the new both-peers option `early_request`, the client
sends its request header **with** its handshake-completing flight
instead of after the proof flight — AEAD-sealed (AES-256-GCM)
under a key HKDF-derived from the session proof key, wire form
`[0x00][len][nonce][ct]` inside the TLS stream. The server reads
the request before writing its proof; the proof still precedes any
relayed data, so the client never consumes data from an unproven
server, and sealing keeps the destination confidential even from
a TLS-terminating impostor (without the musess session keys the
header is opaque). Authenticated path only; pre-handshake wire
shape and the unauthenticated fallback are byte-identical to
stock. Flight count: 6 → 4.

Measured (same bench, medians of 3 interleaved reps; seconds are
primary, Mbps = 32 MiB / median seconds):

| tier | stock musess | early-request | SS2022 (same windows) |
|---|---|---|---|
| TTFB proxy, delay100 (1 MiB total time) | 0.611 s | **0.411 s** | 0.241 s |
| none, 32 MiB | 0.114 s / 2355 | 0.103 s / 2607 | noisy, burst regime |
| delay25, 32 MiB | 0.310 s / 866 | **0.225 s / 1193** | 0.208–0.320 s |
| delay100, 32 MiB | 0.688 s / 390 | **0.520 s / 516** | 0.305–0.484 s (load-varying) |
| delay25+hold, 32 MiB | 0.279 s / 962 | 0.272 s / 987 | ≈ parity tier |

The TTFB saving is 0.200 s at d = 100 ms — exactly the two
serialised flights removed, as the model predicts; in the first
clean window the delay100 ratio vs SS2022 moved 0.39 → 0.62
(544 vs 881). At the hold tier the gain washes out (stalls
dominate). Regression: milestone-1 e2e on the experiment binary
shows the identical 5-pass / 1-fail profile with the option OFF
**and** ON (the one failure is the pre-existing sandbox
unconnected-UDP EPERM, unrelated); `go vet` clean; musess unit
tests pass.

Residual gap: TTFB 0.41 vs SS2022's 0.24 s is the price of having
a real TLS handshake plus an exporter-bound server proof at all —
SS2022 has no handshake. Removing more flights crosses decided
red lines (see disqualified list).

## Other candidates

- **Server early proof** (send proof with the server's handshake
  flight, e.g. via a uTLS server): screened out analytically —
  the validated flight model shows the critical path runs through
  the *request's* arrival at the server, so this cannot beat the
  early-request 4 flights; not prototyped.
- **Buffer/window/copy-path tuning**: screened out by Experiment
  2 — steady state is already at parity; there is nothing for
  tuning to recover.
- **Multi-connection striping**: does not reduce setup wall-clock
  (setups overlap, TTFB unchanged) and steady state needs no
  help. Not shortlisted for this gap.
- **Packet-up style framing**: orthogonal (upload chunking /
  CDN-shaped paths); no effect on this bottleneck. Not
  shortlisted here.
- **First-flight request** (request bytes in or beside the
  ClientHello flight; model TTFB ≈ 0.2 s): **DISQUALIFIED** —
  extra non-ClientHello bytes in the client's first flight are a
  fingerprint surface real Chrome never produces; violates the
  camouflage / single-stack red line.
- **0-RTT carrying the request**: **DISQUALIFIED** by Emma's
  standing decision #4 (0-RTT for authentication data disabled).
- **Multiplexing / persistent-connection reuse**: not prototyped
  in phase 1, but the motivation is quantified — 10 sequential
  1 MiB transfers at delay100 take **6.50 s stock / 4.47 s
  early-request**, because every flow repays full TTFB; a muxed
  musess connection would pay setup once (≈1 s total by the same
  model). For many-small-flow workloads (web browsing) this
  dwarfs the bulk-bench effect.

## Shortlist for the combination round

1. **early-request** (proven above; keep behind its option,
   default off, until adopted) — combines with everything.
2. **multiplexed stream framing** on one musess connection
   (amortises setup across flows) — prototype next; measure
   TTFB-per-stream and the sequential-small-flow total.
3. Combined: early-request × mux, re-run the delay bench +
   sequential-small-flow test; also re-check FEC negotiation
   with early-request on (code-consistent, not yet benched).

## What remains unverified

- Everything WAN: real RTT/loss/middleboxes, BBR (unavailable in
  this sandbox), paths where the target is not loopback-local.
- FEC-on × early-request: functionally code-consistent (v2
  header sealed the same way; status byte after proof) but the
  FEC e2e was not re-run with `early_request` enabled.
- Hold-model behaviour under real loss (the shim never drops);
  the delay25+hold tier showed no measurable early-request gain.
- Whether the gateway's larger lesson — setup cost dominates
  short flows — shifts design priorities for the QUIC path
  (where 0-RTT transport resumption is allowed for non-auth
  data): noted for the QUIC milestone, not decided here.

# musess — rate attack, phase 2 (2026-11-05)

Phase 2 = land the proven fix, prototype the mux, bench the
combination. Same bench discipline as phase 1: user-space
delay/hold shim (latency model, NOT packet loss, NOT netem),
interleaved repetitions (3 per cell, config order rotated per
rep), medians reported with raw values, load gate before every
boot (1-minute load < 2.5 on this 4-core sandbox shared with a
parallel task; observed medians 1.4–1.9). Scripts:
`impl/.tmp/rate-lab/bench-p2.sh` + `bench-p2-drive.sh`, raw
results in `impl/.tmp/rate-lab/p2-results.txt`.

## 1. early_request landed in the production tree

The phase-1 experiment diff (5 files: `option/musess.go`,
`protocol/musess/auth.go`, `framing.go`, `inbound.go`,
`outbound.go`) was ported into `impl/sing-box` code-identically
(verified: non-comment diff vs the experiment tree is empty),
plus one new unit-test file (`early_request_test.go`, 6 tests:
sealed round-trip for v1 and v2 headers, tampered ciphertext /
nonce / tag / wrong-key rejection, plain-header passthrough for
mixed peers, stock reader rejecting a sealed header, stream
boundary and nonce randomness). Landed behind the
`early_request` option, default off at landing time; the
default was flipped to on by the follow-up in section 4
("Outcome"), ratified 2026-11-05.

**One deliberate deviation from the experiment, forced by a
test the brief required.** The experiment's server read the
request *before* writing its proof. Exercising the asymmetric
peer combinations end-to-end showed that a server with the
option on and a stock client **deadlocks**: the stock client
waits for the proof before sending anything, the experiment
server waits for the request before proving (server log: the
authenticated connection sat in the request read for 41 s until
the client gave up). The landed server keeps the *stock order* —
proof first, then `readRequestAuto`. The flight saving is the
client's pipelining, not the server's order (phase 1's own model
says the critical path runs through the request's arrival), and
the combination bench below confirms the saving survives intact
(TTFB 0.611 → 0.410 s, matching phase 1's 0.611 → 0.411). With
proof-first, a server-side enable is safe for **any** client:
stock clients get the byte-identical stock exchange plus a
server that can also parse sealed headers. The remaining
asymmetry is inherent and fails cleanly: an early client against
a server with the option off is rejected post-authentication
exactly like a malformed header (server log: "unsupported
framing version") — never forwarded, never mistaken for an
unauthenticated connection (authentication precedes the header).

Regression evidence (production binary
`1.14.0-alpha.2-musess-p2`):

- `go vet` clean (`option`, `protocol/musess/...`); full musess
  package tests pass, including the fec subpackage.
- Milestone-1 e2e (`test/run-e2e.sh`): **identical 5-pass /
  1-fail profile with early_request off, on, and server-only**
  (the one failure is the pre-existing sandbox unconnected-UDP
  EPERM, unrelated). Client-only fails check (a) by design, as
  analysed above; fallback checks (b1/b2/c) pass in every
  combination — the unauthenticated path is untouched.
- FEC e2e (`test/run-e2e-fec.sh`) with `early_request` enabled
  on both peers (variant script
  `impl/.tmp/rate-lab/run-e2e-fec-p2-er.sh`): **6/6 pass**,
  identical to early-off on the same binary — the sealed v2
  header, the proof and the FEC status byte compose.

## 2. Mux prototype (experiment tree only)

Implemented in `.tmp/exp-tree` (re-synced from the landed
production tree, then extended), behind a new off-by-default
`mux` option on both peers. Design in brief
(`protocol/musess/mux.go` there):

- A musess connection opened with the new command `0x03`
  becomes a stream session; the request destination is a
  placeholder, each stream carries its own. Frames:
  `[streamID u32][type u8][length u32][payload]`; open carries
  `[command][SOCKS address]`, data is chunked at 32 KiB, plus
  close (write-close) and reset frames. Only the client opens
  streams (odd IDs); TCP only — a UDP open is reset.
- The outbound keeps one lazily dialed session per process
  (handshake + proof exactly as the plain path, early_request
  included when enabled), redialed after death with one retry;
  the inbound routes each stream independently through the
  normal router.
- Unit tests (`mux_test.go`, also run under `-race`, clean):
  echo round-trip, 5 sequential streams on one session, 3
  concurrent streams with distinct 70–130 KB payloads, reset of
  an unsupported (UDP) open, session death failing open streams.

Stated prototype limitations (not discovered later, chosen):
no per-stream flow-control window — a full stream inbox (64
chunks) backpressures the session reader, coupling streams
head-of-line; **FEC is not composed with mux** (mux sessions run
over the plain TLS stream regardless of the fec option); stream
deadlines are no-ops; one session per outbound (no pooling).

## 3. Combination bench

Workloads: **ttfb** = a single 1 MiB transfer (setup-dominated);
**bulk32 / bulk256** = single 32 / 256 MiB transfers; **seq10**
= 10 sequential 1 MiB transfers against one long-lived client
process, wall-clock. For mux configs the session is established
by the ttfb workload and stays warm for the rest of the boot; a
separate cold variant ran seq10 first on a fresh boot
(`bench-p2-seqfirst.sh`). Seconds are primary; Mbps =
size / median seconds. SS2022 legs use the milestone-2 configs.

Delay 100 ms/dir, medians of 3 (raw values in the results file):

| workload | stock | early | mux | combo | SS2022 |
|---|---|---|---|---|---|
| ttfb | 0.611 | **0.410** | 0.616 | 0.613 | 0.205 |
| bulk32 | 0.667 | 0.457 | **0.432** | 0.460 | 0.271 |
| bulk256 | 1.277 | **1.067** | 1.179 | 1.200 | 1.001 |
| seq10 (warm session) | 6.279 | 4.299 | **2.727** | 3.411 | 2.150 |
| seq10 (cold session) | — | — | 3.547 | 3.196 | — |

Delay 25 ms/dir, medians of 3:

| workload | stock | early | mux | combo | SS2022 |
|---|---|---|---|---|---|
| ttfb | 0.159 | **0.109** | 0.166 | 0.162 | 0.056 |
| bulk32 | 0.220 | **0.159** | 0.213 | 0.253 | 0.118 |
| bulk256 | 0.890 | **0.798** | 1.069 | 1.072 | 0.893 |
| seq10 | 1.776 | 1.235 | 1.771 | 1.393 | 0.651 |

Readings, each tied to the numbers above:

- **Early-request reproduces on the production binary**, with
  the proof-order fix: ttfb −0.201 s at delay100 and −0.050 s at
  delay25 — exactly the two flights of the phase-1 model, at
  both delays. bulk32 delay100 improves 0.667 → 0.457 (Mbps
  ratio vs SS2022 0.69 of SS's time; phase 1 measured the same
  effect in a dirtier window). At bulk256 the gap to SS nearly
  closes (1.067 vs 1.001), consistent with phase 1's
  steady-state parity.
- **Mux's first flow gains nothing, by construction**: a mux
  session's setup is the stock musess setup, and the first
  stream's data cannot return until its OPEN frame has crossed
  the leg (one round trip). Combo proves the decomposition: the
  client log timestamps the (early) session establishment at
  406 ms — the saving is real — yet ttfb lands at 0.613,
  because the stream-open round trip costs back the 0.2 s the
  session setup saved. From the second flow on, the win is
  real: seq10 delay100 falls 6.279 (stock) → 4.299 (early) →
  **2.727 warm / 3.547 cold (mux)**. Per-flow residual after
  setup is ~0.21–0.29 s at delay100 for every config — a
  transfer/ramp floor through the delay shim (SS2022's seq10,
  2.150, sits at ~0.215/flow of almost pure setup), not
  something either candidate removes.
- **Combo adds nothing measurable over mux for streams** —
  expected, since after session establishment the two data
  planes are byte-identical by construction; their seq10
  difference (3.411 vs 2.727 warm) is inside the observed
  spread (combo raw 2.589–4.093) and is not read as an effect.
  Combo's only real edge over mux is a faster *session*
  establishment, which matters when sessions are short-lived.
- **Mux taxes bulk**: bulk256 at delay25 is 1.069 (mux) vs
  0.890 (stock) / 0.798 (early); at delay100, 1.179 vs 1.067
  (early). A consistent ~10–20% at 256 MiB, growing with size
  — consistent with per-frame demux cost in the prototype
  (32 KiB frames, one reader goroutine); not profiled further
  this phase. At 32 MiB the warm session's skipped setup hides
  the tax (0.432, best musess at delay100).

## 4. Defaults recommendation (priority 速率 > 伪装 > 延迟)

**early_request: default ON, both peers.** The gain is the
largest measured setup improvement available (ttfb −33% and
seq10 −32% at delay100; −31% ttfb at delay25) and it costs
nothing measured anywhere else: pre-handshake wire bytes and
the unauthenticated fallback are byte-identical (milestone-1
e2e b/c checks pass in every combination), the sealed header
replaces the stock header flight inside the TLS stream — if
anything it removes one application flight from the setup's
shape — and the proof still gates all relayed data. Server-side
default-on is safe unconditionally (proof-first order makes the
server accept stock clients unchanged, verified). Client-side
default-on is safe in the only ecosystem that exists: musess is
pre-release with no deployed legacy base, and a client enabled
against a server that has the option *manually disabled* fails
cleanly and visibly (post-auth close), never silently. Rollout
rule to document with the flip: servers first (they accept
everyone), then clients. Implementation note: the option is a
plain bool today, so default-on needs a tri-state (e.g.
`badoption.Bool`) to keep an explicit `false` meaningful; that
schema change is the follow-up commit, not done in this phase
(the landing brief specified default-off for now).

**mux: ship as an opt-in option, default OFF.** The seq10 win
is the biggest single-workload improvement measured in both
phases (−44% cold / −57% warm vs stock at delay100), and for
browsing-shaped traffic it is the only structural answer. But
default-on would contradict the priority order today: it taxes
bulk throughput ~10–20% (速率 is first), it ships without
per-stream flow control (head-of-line coupling between streams
is unmeasured under mixed concurrent load), it does not compose
with FEC yet, and its camouflage balance is genuinely two-sided
— multiplexing itself is browser-normal (HTTP/2, HTTP/3), but
concentrating all of a user's traffic into one long-lived,
high-volume connection to a borrowed destination is a different
shape from the many short connections that destination normally
sees, and the mux frame/record pattern has not been compared
against browser H2 record shapes. Opt-in for browsing-heavy
deployments now; revisit the default after flow control, FEC
composition, and a record-shape comparison exist.

**combo**: no separate decision — where mux is enabled,
early_request should be enabled with it (it only accelerates
the session's own establishment).

**Outcome (2026-11-05): both recommendations RATIFIED by Emma
as written.** early_request is now **default ON** on both
peers; mux stays an opt-in experiment-tree prototype, default
off, not promoted. The flip is a schema change only — no wire
behaviour changed in any peer combination:

- The option is now tri-state: `early_request` is a `*bool`
  on both option structs, resolved by `EarlyRequestEnabled()`
  (unset and explicit true = on; only an explicit false =
  off). This follows the tree's established default-on pattern
  (`UDPFragment *bool` + consumption-site default): the
  `badoption.Bool` type guessed above does not exist in this
  tree's sing version (v0.8.2), whose badoption package has no
  boolean type. The JSON field name is unchanged, and an unset
  option still marshals to no field, so existing configs are
  untouched byte for byte.
- Rollout rule, now recorded on the option itself: **deploy
  servers first, then clients.** A server with the feature on
  accepts stock and early clients alike (proof-first order);
  a client with it on against a server with it explicitly off
  fails cleanly after authentication ("unsupported framing
  version", post-auth close) — never forwarded, never treated
  as unauthenticated.
- Verification of the flipped tree: `go vet` clean; the six
  landing unit tests pass unchanged, plus three new ones
  (`early_request_option_test.go`: tri-state resolution for
  both peers through the real config-parse path, marshal
  stability of unset vs explicit-false, and the full
  3-state x 3-state client/server combination matrix at the
  framing level — every combination succeeds except
  client-on x server-off, which rejects cleanly). Milestone-1
  e2e with configs that **omit** `early_request` entirely:
  the established 5-pass / 1-sandbox-fail profile, and a
  phase-2-shaped TTFB spot check (1 MiB raw-TCP through the
  delay shim at 100 ms/dir, 3 reps) puts the omitted-config
  pair in the early class — median 0.457 s vs 0.640 s for the
  same pair with explicit `"early_request": false` on both
  peers (phase-2 reference: early 0.410 / stock 0.611). The
  explicit-false milestone-1 e2e reproduces the old 5/1
  profile exactly. FEC e2e with the option omitted (so early
  now composes with FEC by default): **6/6**, matching the
  phase-2 explicit-on run.

## What remains unverified

- Everything WAN, as in phase 1 (real RTT/loss/middleboxes,
  BBR, non-loopback targets); all phase-2 numbers are sandbox
  loopback through the delay shim.
- Mux under concurrent mixed load (many simultaneous streams,
  mixed sizes): the head-of-line coupling is designed-in and
  unit-tested for correctness, but no throughput/fairness
  numbers exist yet.
- Mux frame/record shape vs real browser H2 record patterns
  (camouflage comparison not attempted).
- The mux bulk tax mechanism (per-frame demux cost is the
  consistent explanation; no profiling run was done).
- FEC × mux composition (explicitly out of prototype scope).
- The estimator-vs-step FEC controller question (parallel
  task's re-run left it unconfirmed) is untouched by phase 2;
  early_request composes with the *negotiated* FEC path as
  proven by the FEC e2e, independent of controller choice.
