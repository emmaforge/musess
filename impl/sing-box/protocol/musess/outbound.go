package musess

import (
	"context"
	"crypto/ecdh"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	utls "github.com/metacubex/utls"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.MusessOutboundOptions](registry, C.TypeMusess, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger       logger.ContextLogger
	dialer       N.Dialer
	serverAddr   M.Socksaddr
	serverName   string
	serverPublic *ecdh.PublicKey
	uuid         string
	secret       string
	fecMode      fecMode
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MusessOutboundOptions) (adapter.Outbound, error) {
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	serverPublic, err := ParsePublicKey(options.PublicKey)
	if err != nil {
		return nil, E.Cause(err, "musess: parse public_key")
	}
	serverName := options.ServerName
	if serverName == "" {
		serverName = options.Server
	}
	mode, err := parseFECMode(options.FEC)
	if err != nil {
		return nil, err
	}
	return &Outbound{
		Adapter:      outbound.NewAdapterWithDialerOptions(C.TypeMusess, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		logger:       logger,
		dialer:       outboundDialer,
		serverAddr:   options.ServerOptions.Build(),
		serverName:   serverName,
		serverPublic: serverPublic,
		uuid:         options.UUID,
		secret:       options.Secret,
		fecMode:      mode,
	}, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		stream, fecActive, err := h.dialStream(ctx, commandTCP, destination)
		if err != nil {
			return nil, err
		}
		if fecActive {
			return newFECConn(stream, h.fecMode, false, h.logger), nil
		}
		return stream, nil
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		packetConn, err := h.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return newPacketStreamConn(packetConn.(framedPacketConn), destination), nil
	default:
		return nil, E.New("unsupported network: ", network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	stream, fecActive, err := h.dialStream(ctx, commandUDP, destination)
	if err != nil {
		return nil, err
	}
	if fecActive {
		return newFECPacketConn(newFECConn(stream, h.fecMode, true, h.logger)), nil
	}
	return newStreamPacketConn(stream), nil
}

// dialStream establishes one authenticated musess TLS connection and
// sends the request header for the given command and destination.
//
// The ClientHello is built with uTLS following the same pattern as
// this tree's REALITY client: the ML-KEM key share is removed so the
// session key share is a plain X25519 share whose private key the
// handshake state exposes; that private key doubles as the musess
// auth ephemeral, binding the auth tag to the very key exchange that
// becomes the TLS session.
// dialStream establishes one authenticated musess TLS connection
// and sends the request header. It returns the raw TLS connection
// and whether FEC was negotiated (v2 header + server status byte).
func (h *Outbound) dialStream(ctx context.Context, command byte, destination M.Socksaddr) (net.Conn, bool, error) {
	rawConn, err := h.dialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, false, err
	}
	tlsConn, sessionAuth, err := h.clientHandshake(ctx, rawConn)
	if err != nil {
		rawConn.Close()
		return nil, false, err
	}
	connState := tlsConn.ConnectionState()
	exporter, err := connState.ExportKeyingMaterial("musess", nil, 32)
	if err != nil {
		tlsConn.Close()
		return nil, false, E.Cause(err, "musess: export keying material")
	}
	proof := make([]byte, serverProofLength)
	if _, err = io.ReadFull(tlsConn, proof); err != nil {
		tlsConn.Close()
		return nil, false, E.Cause(err, "musess: read server proof")
	}
	if !sessionAuth.VerifyServerProof(proof, exporter) {
		tlsConn.Close()
		return nil, false, E.New("musess: server proof mismatch (wrong server key or secret?)")
	}
	if !h.fecMode.enabled() {
		// Milestone-1 wire behaviour, unchanged.
		if err = writeRequest(tlsConn, command, destination); err != nil {
			tlsConn.Close()
			return nil, false, err
		}
		return tlsConn, false, nil
	}
	if err = writeRequestV2(tlsConn, command, destination, fecFlagForward|fecFlagReverse); err != nil {
		tlsConn.Close()
		return nil, false, err
	}
	var status [1]byte
	if _, err = io.ReadFull(tlsConn, status[:]); err != nil {
		tlsConn.Close()
		return nil, false, E.Cause(err, "musess: read FEC status")
	}
	if status[0] == 0x01 {
		h.logger.InfoContext(ctx, "musess: FEC negotiated with server for ", destination)
		return tlsConn, true, nil
	}
	h.logger.InfoContext(ctx, "musess: server declined FEC, continuing without it")
	return tlsConn, false, nil
}

func (h *Outbound) clientHandshake(ctx context.Context, rawConn net.Conn) (*utls.UConn, *ClientSessionAuth, error) {
	uConfig := &utls.Config{
		ServerName:             h.serverName,
		InsecureSkipVerify:     true, // server identity is verified by the musess proof, not by PKI: the presented certificate belongs to the borrowed destination's name and is locally issued (milestone 1; see README)
		SessionTicketsDisabled: true,
		MinVersion:             utls.VersionTLS13,
	}
	uConn := utls.UClient(rawConn, uConfig, utls.HelloCustom)
	spec, err := utls.UTLSIdToSpec(utls.HelloChrome_120)
	if err != nil {
		return nil, nil, err
	}
	for i, extension := range spec.Extensions {
		switch ext := extension.(type) {
		case *utls.KeyShareExtension:
			ext.KeyShares = common.Filter(ext.KeyShares, func(share utls.KeyShare) bool {
				return share.Group != utls.X25519MLKEM768
			})
		case *utls.SupportedCurvesExtension:
			ext.Curves = common.Filter(ext.Curves, func(curve utls.CurveID) bool {
				return curve != utls.X25519MLKEM768
			})
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
	if err = uConn.ApplyPreset(&spec); err != nil {
		return nil, nil, err
	}
	if err = uConn.BuildHandshakeState(); err != nil {
		return nil, nil, err
	}
	hello := uConn.HandshakeState.Hello
	if len(hello.Raw) < 39+sessionIDLength {
		return nil, nil, E.New("musess: unexpected client hello layout")
	}
	hello.SessionId = make([]byte, sessionIDLength)
	copy(hello.Raw[39:], hello.SessionId)
	fields, err := ParseClientHello(hello.Raw)
	if err != nil {
		return nil, nil, E.Cause(err, "musess: parse own client hello")
	}
	keyShareKeys := uConn.HandshakeState.State13.KeyShareKeys
	if keyShareKeys == nil || keyShareKeys.Ecdhe == nil {
		return nil, nil, E.New("musess: no X25519 key share in client hello")
	}
	sessionAuth, err := NewClientSessionAuth(h.serverPublic, keyShareKeys.Ecdhe, h.uuid, h.secret)
	if err != nil {
		return nil, nil, err
	}
	sessionID := sessionAuth.SessionID(fields, time.Now())
	hello.SessionId = sessionID
	copy(hello.Raw[39:], sessionID)
	if err = uConn.HandshakeContext(ctx); err != nil {
		return nil, nil, err
	}
	return uConn, sessionAuth, nil
}
