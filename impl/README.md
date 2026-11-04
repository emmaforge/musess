# musess — milestone 1 implementation

`musess` is Emma's new proxy protocol (named by Emma: written by Muse —
muse + ss; the early placeholder name in the original brief was
`newproto`, renamed before any code was written against it). This
directory contains milestone 1: the **TCP/TLS path** of
`~/workspace/new-protocol/DESIGN.md`, implemented as a protocol package
inside a sing-box tree, working end to end.

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
- **Adaptive application-layer FEC** (decided IN for v1, app-layer,
  adaptive, per-flow, judged by goodput first).
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
