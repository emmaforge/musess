package musess

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdh"
	stdtls "crypto/tls"
	"io"
	"net"
	"strconv"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func RegisterInbound(registry *inbound.Registry) {
	inbound.Register[option.MusessInboundOptions](registry, C.TypeMusess, NewInbound)
}

type Inbound struct {
	inbound.Adapter
	router       adapter.ConnectionRouterEx
	logger       logger.ContextLogger
	listener     *listener.Listener
	destName     string
	destDialAddr string
	privateKey   *ecdh.PrivateKey
	certificate  stdtls.Certificate
	users        []userEntry
	replay       *replayCache
	fecMode      fecMode
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.MusessInboundOptions) (adapter.Inbound, error) {
	routerEx, ok := router.(adapter.ConnectionRouterEx)
	if !ok {
		return nil, E.New("musess: router does not support connection routing")
	}
	if options.Dest == "" {
		return nil, E.New("musess: dest is required")
	}
	privateKey, err := ParsePrivateKey(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "musess: parse private_key")
	}
	certificate, err := stdtls.LoadX509KeyPair(options.CertificatePath, options.KeyPath)
	if err != nil {
		return nil, E.Cause(err, "musess: load certificate")
	}
	destPort := options.DestPort
	if destPort == 0 {
		destPort = 443
	}
	destHost := options.DestAddress
	if destHost == "" {
		destHost = options.Dest
	}
	mode, err := parseFECMode(options.FEC)
	if err != nil {
		return nil, err
	}
	inbound := &Inbound{
		Adapter:      inbound.NewAdapter(C.TypeMusess, tag),
		router:       routerEx,
		logger:       logger,
		destName:     options.Dest,
		destDialAddr: net.JoinHostPort(destHost, strconv.Itoa(int(destPort))),
		privateKey:   privateKey,
		certificate:  certificate,
		replay:       newReplayCache(),
		fecMode:      mode,
	}
	for _, user := range options.Users {
		inbound.users = append(inbound.users, makeUserEntry(user.Name, user.UUID, user.Secret))
	}
	if len(inbound.users) == 0 {
		return nil, E.New("musess: at least one user is required")
	}
	inbound.listener = listener.New(listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	})
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return h.listener.Start()
}

func (h *Inbound) Close() error {
	return common.Close(h.listener)
}

// prefixConn replays bytes already consumed while peeking (the raw
// ClientHello bytes, followed by anything left in the buffered reader)
// before reading from the socket again.
type prefixConn struct {
	net.Conn
	reader io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.reader.Read(p)
}

func (h *Inbound) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	reader := bufio.NewReaderSize(conn, 16384)
	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	rawHello, fields, helloErr := ReadClientHello(reader)
	_ = conn.SetReadDeadline(time.Time{})
	var verified *verifiedAuth
	if helloErr == nil && fields != nil {
		verified = verifyClientHello(fields, h.users, h.privateKey, h.replay, time.Now())
	}
	if verified == nil {
		// Unauthenticated, invalid, replayed, or not TLS at all:
		// the connection is forwarded to the real destination and
		// answered by it, byte for byte. Nothing about this path
		// may differ from a direct connection to the destination.
		h.forwardToDest(ctx, conn, reader, rawHello, metadata.Source)
		return
	}
	h.serveAuthenticated(ctx, conn, reader, rawHello, verified, metadata, onClose)
}

func (h *Inbound) forwardToDest(ctx context.Context, conn net.Conn, reader *bufio.Reader, rawHello []byte, source M.Socksaddr) {
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	destConn, err := dialer.DialContext(ctx, N.NetworkTCP, h.destDialAddr)
	if err != nil {
		h.logger.DebugContext(ctx, "musess: forward to ", h.destDialAddr, " failed for ", source, ": ", err)
		conn.Close()
		return
	}
	defer destConn.Close()
	defer conn.Close()
	if len(rawHello) > 0 {
		if _, err = destConn.Write(rawHello); err != nil {
			return
		}
	}
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(conn, destConn)
		done <- struct{}{}
	}()
	go func() {
		// reader still holds any bytes buffered past the ClientHello.
		_, _ = io.Copy(destConn, reader)
		done <- struct{}{}
	}()
	<-done
}

func (h *Inbound) serveAuthenticated(ctx context.Context, conn net.Conn, reader *bufio.Reader, rawHello []byte, verified *verifiedAuth, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	tlsConfig := &stdtls.Config{
		Certificates: []stdtls.Certificate{h.certificate},
		MinVersion:   stdtls.VersionTLS13,
	}
	replay := io.MultiReader(bytes.NewReader(rawHello), reader)
	tlsConn := stdtls.Server(&prefixConn{Conn: conn, reader: replay}, tlsConfig)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		h.logger.DebugContext(ctx, "musess: TLS handshake with authenticated client failed: ", err)
		conn.Close()
		return
	}
	connState := tlsConn.ConnectionState()
	exporter, err := connState.ExportKeyingMaterial("musess", nil, 32)
	if err != nil {
		h.logger.DebugContext(ctx, "musess: export keying material failed: ", err)
		conn.Close()
		return
	}
	if _, err = tlsConn.Write(ServerProof(verified.proofKey, exporter)); err != nil {
		conn.Close()
		return
	}
	version, command, flags, destination, err := readRequest(tlsConn)
	if err != nil {
		h.logger.DebugContext(ctx, "musess: read request failed: ", err)
		conn.Close()
		return
	}
	// FEC negotiation: a v2 client that set both direction bits
	// gets a one-byte answer — 0x01 if this inbound also has FEC
	// enabled (duplex active), 0x00 otherwise. A v1 client never
	// reads a status byte and never gets one.
	fecActive := false
	if version == framingVersion2 {
		fecActive = h.fecMode.enabled() && flags&fecFlagForward != 0 && flags&fecFlagReverse != 0
		status := byte(0x00)
		if fecActive {
			status = 0x01
		}
		if _, err = tlsConn.Write([]byte{status}); err != nil {
			conn.Close()
			return
		}
		if flags&fecFlagForward != 0 && !fecActive {
			h.logger.DebugContext(ctx, "musess: client requested FEC but inbound fec mode is ", h.fecMode.optionString())
		}
		if fecActive {
			h.logger.InfoContext(ctx, "musess: FEC duplex active (mode ", h.fecMode.optionString(), ") for ", metadata.Source)
		}
	}
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	metadata.User = verified.user.name
	metadata.Destination = destination
	switch command {
	case commandTCP:
		h.logger.InfoContext(ctx, "[", verified.user.name, "] inbound connection to ", destination)
		if fecActive {
			h.router.RouteConnectionEx(ctx, newFECConn(tlsConn, h.fecMode, false, h.logger), metadata, onClose)
		} else {
			h.router.RouteConnectionEx(ctx, tlsConn, metadata, onClose)
		}
	case commandUDP:
		h.logger.InfoContext(ctx, "[", verified.user.name, "] inbound packet connection to ", destination)
		// A musess UDP stream is an association opened for the
		// destination in its request header (the client creates one
		// stream per destination), so the router may use a connected
		// UDP socket for the outbound hop. Per-packet addresses are
		// still carried in the framing, and the client side never
		// mixes destinations on one stream.
		metadata.UDPConnect = true
		if fecActive {
			h.router.RoutePacketConnectionEx(ctx, newFECPacketConn(newFECConn(tlsConn, h.fecMode, true, h.logger)), metadata, onClose)
		} else {
			h.router.RoutePacketConnectionEx(ctx, newStreamPacketConn(tlsConn), metadata, onClose)
		}
	default:
		h.logger.DebugContext(ctx, "musess: unknown command ", command)
		conn.Close()
	}
}
