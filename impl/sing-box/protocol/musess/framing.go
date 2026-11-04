package musess

import (
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

// Data-plane framing inside the authenticated TLS stream. Deliberately
// minimal (Emma's priority order: throughput first): a one-byte version,
// a one-byte command, a SOCKS-style address, then either the raw stream
// (TCP) or length-prefixed addressed packets (UDP). No padding, no
// extra layers.

const (
	framingVersion = 0x01
	commandTCP     = 0x01
	commandUDP     = 0x02
	serverProofLength = 32
)

func writeRequest(w io.Writer, command byte, destination M.Socksaddr) error {
	header := buf.NewSize(2 + M.MaxSocksaddrLength)
	header.WriteByte(framingVersion)
	header.WriteByte(command)
	err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	_, err = w.Write(header.Bytes())
	return err
}

func readRequest(r io.Reader) (command byte, destination M.Socksaddr, err error) {
	var preamble [2]byte
	if _, err = io.ReadFull(r, preamble[:]); err != nil {
		return 0, M.Socksaddr{}, err
	}
	if preamble[0] != framingVersion {
		return 0, M.Socksaddr{}, errors.New("musess: unsupported framing version")
	}
	destination, err = M.SocksaddrSerializer.ReadAddrPort(r)
	if err != nil {
		return 0, M.Socksaddr{}, err
	}
	return preamble[1], destination, nil
}

// streamPacketConn adapts the framed TLS stream to sing's PacketConn:
// each packet is [address][2-byte length][payload].
type streamPacketConn struct {
	net.Conn
	writeMutex sync.Mutex
}

func newStreamPacketConn(conn net.Conn) *streamPacketConn {
	return &streamPacketConn{Conn: conn}
}

func (c *streamPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	destination, err := M.SocksaddrSerializer.ReadAddrPort(c.Conn)
	if err != nil {
		return M.Socksaddr{}, err
	}
	var lengthBytes [2]byte
	if _, err = io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		return M.Socksaddr{}, err
	}
	length := int(binary.BigEndian.Uint16(lengthBytes[:]))
	buffer.Reset()
	if _, err = io.CopyN(buffer, c.Conn, int64(length)); err != nil {
		return M.Socksaddr{}, err
	}
	return destination, nil
}

func (c *streamPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	c.writeMutex.Lock()
	defer c.writeMutex.Unlock()
	header := buf.NewSize(M.MaxSocksaddrLength + 2)
	err := M.SocksaddrSerializer.WriteAddrPort(header, destination)
	if err != nil {
		return err
	}
	var lengthBytes [2]byte
	binary.BigEndian.PutUint16(lengthBytes[:], uint16(buffer.Len()))
	header.Write(lengthBytes[:])
	_, err = c.Conn.Write(header.Bytes())
	header.Release()
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(buffer.Bytes())
	return err
}

// ReadFrom implements net.PacketConn on top of the framed stream.
func (c *streamPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	buffer := buf.NewSize(len(p))
	destination, err := c.ReadPacket(buffer)
	if err != nil {
		return 0, nil, err
	}
	n := copy(p, buffer.Bytes())
	buffer.Release()
	return n, destination.UDPAddr(), nil
}

// WriteTo implements net.PacketConn on top of the framed stream.
func (c *streamPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	buffer := buf.NewSize(len(p))
	buffer.Write(p)
	err := c.WritePacket(buffer, destination)
	buffer.Release()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// packetStreamConn adapts a packet connection bound to one fixed
// destination to a net.Conn (used for outbound DialContext with UDP).
type packetStreamConn struct {
	packetConn *streamPacketConn
	destination M.Socksaddr
	leftover   []byte
}

func newPacketStreamConn(packetConn *streamPacketConn, destination M.Socksaddr) *packetStreamConn {
	return &packetStreamConn{packetConn: packetConn, destination: destination}
}

func (c *packetStreamConn) Read(p []byte) (int, error) {
	if len(c.leftover) == 0 {
		buffer := buf.NewSize(64 * 1024)
		_, err := c.packetConn.ReadPacket(buffer)
		if err != nil {
			return 0, err
		}
		c.leftover = append(c.leftover[:0], buffer.Bytes()...)
		buffer.Release()
	}
	n := copy(p, c.leftover)
	c.leftover = c.leftover[n:]
	return n, nil
}

func (c *packetStreamConn) Write(p []byte) (int, error) {
	buffer := buf.NewSize(len(p))
	buffer.Write(p)
	err := c.packetConn.WritePacket(buffer, c.destination)
	buffer.Release()
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *packetStreamConn) Close() error         { return c.packetConn.Close() }
func (c *packetStreamConn) LocalAddr() net.Addr  { return c.packetConn.LocalAddr() }
func (c *packetStreamConn) RemoteAddr() net.Addr { return c.packetConn.RemoteAddr() }
func (c *packetStreamConn) SetDeadline(t time.Time) error {
	return c.packetConn.SetDeadline(t)
}
func (c *packetStreamConn) SetReadDeadline(t time.Time) error {
	return c.packetConn.SetReadDeadline(t)
}
func (c *packetStreamConn) SetWriteDeadline(t time.Time) error {
	return c.packetConn.SetWriteDeadline(t)
}
