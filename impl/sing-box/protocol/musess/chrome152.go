// Chrome 152 ClientHello parrot (musess outbound).
//
// The musess client parrots the current Chrome ClientHello so its JA4
// matches a real Chrome 152 browser (Android). The base is uTLS
// HelloChrome_133 (the newest preset in metacubex/utls); on top of it this
// file applies the two Chrome 152 wire changes:
//
//   - signature_algorithms: a per-connection GREASE value first, then the
//     ML-DSA schemes (mldsa44/65/87, 0x0904/0x0905/0x0906, shipped by
//     Chrome 150) ahead of the eight classical schemes. The list below is
//     the Chrome 152 (Android) list.
//   - trust_anchors (0xCA34, draft-ietf-tls-trust-anchor-ids): the Chrome
//     root-store identifier list Chrome ships from version 152. The
//     identifiers below are the Android snapshot (28 entries, in the order
//     the preset carries them); the extension body is a u16 list length
//     followed by one-byte-length-prefixed identifiers, exactly as
//     BoringSSL emits it.
//
// The cipher suites, extension set and key-share groups are unchanged from
// Chrome 133 through Chrome 152, so the base preset already carries them.
// The JA4 of the resulting ClientHello is
// t13d1517h2_8daaf6152771_cb7bf5808d99 (official FoxIO form: decimal
// counts, 15 ciphers / 17 extensions, cipher hash 8daaf6152771,
// extensions+signatures hash cb7bf5808d99).
//
// Source for the signature list and trust anchors: the Chrome 152 Android
// preset (measured captures), via the httpcloak fingerprint preset
// chrome-152-android.json. The trust-anchor list is a snapshot of the
// Chrome root store and will drift as the store changes; refreshing it is
// a data update, not a code change.

package musess

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"

	utls "github.com/metacubex/utls"
)

// chrome152TrustAnchors are the trust anchor identifiers (encoded relative
// object identifiers) carried in the trust_anchors extension. Each entry is
// a hex string; entries are at most 255 bytes.
var chrome152TrustAnchors = []string{
	"d6790901",
	"839a648c9b2d0108",
	"82df130201",
	"82df13020e",
	"82df130214",
	"82df13020d",
	"839a648c9b2d010c",
	"d6790904",
	"839a648c9b2d0109",
	"d6790908",
	"839a648c9b2d0107",
	"d679090c",
	"839a648c9b2d010d",
	"d679090b",
	"839a648c9b2d010a",
	"839a648c9b2d0113",
	"d679090f",
	"839a648c9b2d010b",
	"d679090d",
	"82df130213",
	"d6790905",
	"839a648c9b2d0112",
	"82df130206",
	"d6790906",
	"82df13020f",
	"82df130212",
	"d679090a",
	"d6790907",
}

// chrome152SignatureAlgorithmsBase is the Chrome 152 signature_algorithms
// list without the leading GREASE value. The GREASE value is prepended fresh
// per connection by chrome152SignatureAlgorithms (Chrome randomises it).
var chrome152SignatureAlgorithmsBase = []utls.SignatureScheme{
	0x0904, // mldsa44
	0x0905, // mldsa65
	0x0906, // mldsa87
	0x0403, // ecdsa_secp256r1_sha256
	0x0804, // rsa_pss_rsae_sha256
	0x0401, // rsa_pkcs1_sha256
	0x0503, // ecdsa_secp384r1_sha384
	0x0805, // rsa_pss_rsae_sha384
	0x0501, // rsa_pkcs1_sha384
	0x0806, // rsa_pss_rsae_sha512
	0x0601, // rsa_pkcs1_sha512
}

// chrome152SignatureAlgorithms returns the full Chrome 152
// signature_algorithms list: one random GREASE value first, then the
// ML-DSA schemes ahead of the classical schemes. The GREASE value is drawn
// per connection, as Chrome does.
func chrome152SignatureAlgorithms() []utls.SignatureScheme {
	out := make([]utls.SignatureScheme, 0, len(chrome152SignatureAlgorithmsBase)+1)
	out = append(out, utls.SignatureScheme(greaseValue()))
	out = append(out, chrome152SignatureAlgorithmsBase...)
	return out
}

// greaseValue returns a random GREASE value (RFC 8701). GREASE values are
// 0x?a?a: both bytes equal, low nibble 0xa (0x0a0a, 0x1a1a, ..., 0xfafa).
// A value like 0x0b0b is NOT a GREASE value and would be hashed as a real
// signature algorithm, breaking the JA4.
func greaseValue() uint16 {
	var b [1]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0x0a0a
	}
	v := uint16(b[0]&0x0f)<<4 | 0x0a
	return v<<8 | v
}

// chrome152Spec returns the ClientHelloSpec the musess client parrots: the
// uTLS HelloChrome_133 base (newest preset in metacubex/utls, carrying the
// Chrome 132+ cipher list, extension set and key-share groups unchanged
// through Chrome 152) with the musess filters and the Chrome 152 wire
// changes applied. The ML-KEM share/curve are removed so the TLS session
// share is a plain X25519 share (the musess auth ephemeral, P1 placement);
// renegotiation_info is emitted as a byte-identical GenericExtension so it
// does not disable the TLS exporter the server proof is bound to.
func chrome152Spec() (utls.ClientHelloSpec, error) {
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_133)
	if err != nil {
		return spec, err
	}
	for i, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.KeyShareExtension:
			ext.KeyShares = filterKeyShares(ext.KeyShares)
		case *utls.SupportedCurvesExtension:
			ext.Curves = filterCurves(ext.Curves)
		case *utls.SignatureAlgorithmsExtension:
			// Chrome 152: GREASE + ML-DSA (0x0904/0x0905/0x0906) ahead of
			// the classical schemes (Chrome 150+).
			ext.SupportedSignatureAlgorithms = chrome152SignatureAlgorithms()
		case *utls.RenegotiationInfoExtension:
			// The parrot's renegotiation_info extension makes uTLS set
			// Config.Renegotiation = RenegotiateOnceAsClient whenever
			// the hello state is (re)built, which disables
			// ConnectionState().ExportKeyingMaterial after the
			// handshake - and the musess server proof is bound to the
			// TLS exporter. A GenericExtension emits the identical
			// wire bytes (type 65281, one zero byte) without the
			// config side effect.
			spec.Extensions[i] = &utls.GenericExtension{Id: 65281, Data: []byte{0x00}}
		}
	}
	// Chrome 152: trust_anchors (0xCA34) with the Chrome root-store IDs.
	// Appended after the preset's extensions; Chrome shuffles extension
	// order per connection, so the position is not a fingerprint signal.
	spec.Extensions = append(spec.Extensions, trustAnchorsExtension())
	return spec, nil
}

func filterKeyShares(shares []utls.KeyShare) []utls.KeyShare {
	out := shares[:0]
	for _, s := range shares {
		if s.Group != utls.X25519MLKEM768 {
			out = append(out, s)
		}
	}
	return out
}

func filterCurves(curves []utls.CurveID) []utls.CurveID {
	out := curves[:0]
	for _, c := range curves {
		if c != utls.X25519MLKEM768 {
			out = append(out, c)
		}
	}
	return out
}
func trustAnchorsExtension() *utls.GenericExtension {
	listLen := 0
	anchors := make([][]byte, 0, len(chrome152TrustAnchors))
	for _, h := range chrome152TrustAnchors {
		b, err := hex.DecodeString(h)
		if err != nil {
			// The table above is a compile-time constant; a bad entry is a
			// programming error, so skip it rather than emitting a corrupt
			// extension.
			continue
		}
		anchors = append(anchors, b)
		listLen += 1 + len(b)
	}
	body := make([]byte, 0, 2+listLen)
	var tmp [2]byte
	binary.BigEndian.PutUint16(tmp[:], uint16(listLen))
	body = append(body, tmp[:]...)
	for _, a := range anchors {
		body = append(body, byte(len(a)))
		body = append(body, a...)
	}
	return &utls.GenericExtension{Id: 0xCA34, Data: body}
}
