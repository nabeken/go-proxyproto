// Package proxyproto implements Proxy Protocol (v1 and v2) parser and writer, as per specification:
// http://www.haproxy.org/download/1.5/doc/proxy-protocol.txt

package proxyproto

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"time"
)

var (
	// Protocol
	SIGV1 = []byte{'\x50', '\x52', '\x4F', '\x58', '\x59'}
	SIGV2 = []byte{'\x0D', '\x0A', '\x0D', '\x0A', '\x00', '\x0D', '\x0A', '\x51', '\x55', '\x49', '\x54', '\x0A'}

	ErrCantReadProtocolVersionAndCommand    = errors.New("Can't read proxy protocol version and command")
	ErrCantReadAddressFamilyAndProtocol     = errors.New("Can't read address family or protocol")
	ErrCantReadLength                       = errors.New("Can't read length")
	ErrNoProxyProtocol                      = errors.New("Proxy protocol signature not present")
	ErrUnknownProxyProtocolVersion          = errors.New("Unknown proxy protocol version")
	ErrUnsupportedProtocolVersionAndCommand = errors.New("Unsupported proxy protocol version and command")
	ErrUnsupportedAddressFamilyAndProtocol  = errors.New("Unsupported address family and protocol")
	ErrInvalidLength                        = errors.New("Invalid length")
	ErrInvalidAddress                       = errors.New("Invalid address")
	ErrInvalidPortNumber                    = errors.New("Invalid port number")
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
	Version byte

	// v1 and v2
	SrcAddr net.IP
	DstAddr net.IP
	SrcPort uint16
	DstPort uint16

	// v2 specific
	Command           ProtocolVersionAndCommand
	TransportProtocol AddressFamilyAndProtocol
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
func Read(reader *bufio.Reader) (*Header, error) {
	// In order to improve speed for small non-PROXYed packets, take a peek at the first byte alone.
	if b1, err := reader.Peek(1); err == nil && (bytes.Equal(b1[:1], SIGV1[:1]) || bytes.Equal(b1[:1], SIGV2[:1])) {
		if signature, err := reader.Peek(5); err == nil && bytes.Equal(signature[:5], SIGV1) {
			return parseVersion1(reader)
		} else if signature, err := reader.Peek(12); err == nil && bytes.Equal(signature[:12], SIGV2) {
			return parseVersion2(reader)
		}
	}

	return nil, ErrNoProxyProtocol
}

// ReadTimeout acts as Read but takes a timeout. If that timeout is reached, it's assumed
// there's no proxy protocol header.
func ReadTimeout(reader *bufio.Reader, timeout time.Duration) (*Header, error) {
	type header struct {
		h *Header
		e error
	}
	read := make(chan *header, 1)

	go func() {
		h := &header{}
		h.h, h.e = Read(reader)
		read <- h
	}()

	timer := time.NewTimer(timeout)
	select {
	case result := <-read:
		timer.Stop()
		return result.h, result.e
	case <-timer.C:
		return nil, ErrNoProxyProtocol
	}
}
