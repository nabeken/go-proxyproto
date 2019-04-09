// Package proxyproto implements Proxy Protocol (v1 and v2) parser and writer, as per specification:
// http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt

package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
)

var (
	// Protocol
	SIGV1 = []byte{'\x50', '\x52', '\x4F', '\x58', '\x59'}
	SIGV2 = []byte{'\x0D', '\x0A', '\x0D', '\x0A', '\x00', '\x0D', '\x0A', '\x51', '\x55', '\x49', '\x54', '\x0A'}

	ErrCantReadProtocolVersionAndCommand    = errors.New("proxyproto: can't read proxy protocol version and command")
	ErrCantReadAddressFamilyAndProtocol     = errors.New("proxyproto: can't read address family or protocol")
	ErrCantReadLength                       = errors.New("proxyproto: can't read length")
	ErrNoProxyProtocol                      = errors.New("proxyproto: proxy protocol signature not present")
	ErrUnknownProxyProtocolVersion          = errors.New("proxyproto: unknown proxy protocol version")
	ErrUnsupportedProtocolVersionAndCommand = errors.New("proxyproto: unsupported proxy protocol version and command")
	ErrUnsupportedAddressFamilyAndProtocol  = errors.New("proxyproto: unsupported address family and protocol")
	ErrInvalidLength                        = errors.New("proxyproto: invalid length")
	ErrInvalidAddress                       = errors.New("proxyproto: invalid address")
	ErrInvalidPortNumber                    = errors.New("proxyproto: invalid port number")
)

// ProtocolVersionAndCommand represents proxy protocol version and command.
type ProtocolVersionAndCommand byte

const (
	LOCAL = '\x20'
	PROXY = '\x21'

	CRLF = "\r\n"
)

func isSupportedCommand(command ProtocolVersionAndCommand) bool {
	switch command {
	case LOCAL, PROXY:
		return true
	}
	return false
}

// IsLocal returns true if the protocol version is \x2 and command is LOCAL, false otherwise.
func (pvc ProtocolVersionAndCommand) IsLocal() bool {
	return 0x20 == pvc&0xF0 && 0x00 == pvc&0x0F
}

// IsProxy returns true if the protocol version is \x2 and command is PROXY, false otherwise.
func (pvc ProtocolVersionAndCommand) IsProxy() bool {
	return 0x20 == pvc&0xF0 && 0x01 == pvc&0x0F
}

// IsUnspec returns true if the protocol version or command is unspecified, false otherwise.
func (pvc ProtocolVersionAndCommand) IsUnspec() bool {
	return !(pvc.IsLocal() || pvc.IsProxy())
}

// AddressFamilyAndProtocol represents address family and transport protocol.
type AddressFamilyAndProtocol byte

const (
	UNSPEC = '\x00'
	TCPv4  = '\x11'
	UDPv4  = '\x12'
	TCPv6  = '\x21'
	UDPv6  = '\x22'
)

func isSupportedTransportProtocol(proto AddressFamilyAndProtocol) bool {
	switch proto {
	case TCPv4, UDPv4, TCPv6, UDPv6:
		return true
	}
	return false
}

// IsIPv4 returns true if the address family is IPv4 (AF_INET4), false otherwise.
func (ap AddressFamilyAndProtocol) IsIPv4() bool {
	return 0x10 == ap&0xF0
}

// IsIPv6 returns true if the address family is IPv6 (AF_INET6), false otherwise.
func (ap AddressFamilyAndProtocol) IsIPv6() bool {
	return 0x20 == ap&0xF0
}

// IsStream returns true if the transport protocol is TCP or STREAM (SOCK_STREAM), false otherwise.
func (ap AddressFamilyAndProtocol) IsStream() bool {
	return 0x01 == ap&0x0F
}

// IsDatagram returns true if the transport protocol is UDP or DGRAM (SOCK_DGRAM), false otherwise.
func (ap AddressFamilyAndProtocol) IsDatagram() bool {
	return 0x02 == ap&0x0F
}

// IsUnspec returns true if the transport protocol or address family is unspecified, false otherwise.
func (ap AddressFamilyAndProtocol) IsUnspec() bool {
	return (0x00 == ap&0xF0) || (0x00 == ap&0x0F)
}

func validateLeastAddressLen(ap AddressFamilyAndProtocol, len uint16) bool {
	switch {
	case ap.IsIPv4():
		return len >= v4AddrLen
	case ap.IsIPv6():
		return len >= v6AddrLen
	}
	return false
}

// Header is the placeholder for proxy protocol header.
type Header struct {
	Version int

	// v1 and v2
	SrcAddr net.IP
	DstAddr net.IP
	SrcPort uint16
	DstPort uint16

	// v2 specific
	Command           ProtocolVersionAndCommand
	TransportProtocol AddressFamilyAndProtocol
}

func (h *Header) addr(addr net.IP, port uint16) net.Addr {
	switch {
	case h.TransportProtocol.IsStream():
		return &net.TCPAddr{
			IP:   addr,
			Port: int(port),
		}
	case h.TransportProtocol.IsDatagram():
		return &net.UDPAddr{
			IP:   addr,
			Port: int(port),
		}
	}
	// return empty net.IPAddr to indicate there is no valid address here
	return &net.IPAddr{}
}

func (h *Header) RemoteAddr() net.Addr {
	return h.addr(h.SrcAddr, h.SrcPort)
}

func (h *Header) LocalAddr() net.Addr {
	return h.addr(h.DstAddr, h.DstPort)
}

// WriteTo renders a proxy protocol header in a format to write over the wire.
func (h *Header) WriteTo(w io.Writer) (int64, error) {
	switch h.Version {
	case 1:
		return h.writeVersion1(w)
	case 2:
		return h.writeVersion2(w)
	default:
		return 0, ErrUnknownProxyProtocolVersion
	}
}

// Read identifies the proxy protocol version and reads the remaining of
// the header, accordingly.
//
// If proxy protocol header signature is not present, the reader buffer remains untouched
// and is safe for reading outside of this code.
//
// If proxy protocol header signature is present but an error is raised while processing
// the remaining header, assume the reader buffer to be in a corrupt state.
// Also, this operation will block until enough bytes are available for peeking.
func Read(br *bufio.Reader) (*Header, error) {
	b1, err := br.Peek(1)
	if err != nil {
		return nil, ErrNoProxyProtocol
	}

	// In order to improve speed for small non-PROXYed packets, take a peek at the first byte alone.
	if !bytes.Equal(b1[:1], SIGV1[:1]) && !bytes.Equal(b1[:1], SIGV2[:1]) {
		return nil, ErrNoProxyProtocol
	}

	v1Peek, err := br.Peek(5)
	if err != nil {
		return nil, ErrNoProxyProtocol
	}
	if bytes.Equal(v1Peek[:5], SIGV1) {
		return parseVersion1(br)
	}

	v2Sig, err := br.Peek(12)
	if err != nil {
		return nil, ErrNoProxyProtocol
	}
	if bytes.Equal(v2Sig[:12], SIGV2) {
		return parseVersion2(br)
	}

	return nil, ErrNoProxyProtocol
}
