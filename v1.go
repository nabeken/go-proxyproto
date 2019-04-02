package proxyproto

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"strconv"
	"strings"
)

const (
	CRLF      = "\r\n"
	SEPARATOR = " "
)

func parseVersion1(reader *bufio.Reader) (*Header, error) {
	// Make sure we have a v1 header
	line, err := reader.ReadString('\n')
	if !strings.HasSuffix(line, CRLF) {
		return nil, ErrCantReadProtocolVersionAndCommand
	}
	tokens := strings.Split(line[:len(line)-2], SEPARATOR)
	if len(tokens) < 6 {
		return nil, ErrCantReadProtocolVersionAndCommand
	}

	hdr := &Header{
		Version: 1,
	}

	// Read address family and protocol
	switch tokens[1] {
	case "TCP4":
		hdr.TransportProtocol = TCPv4
	case "TCP6":
		hdr.TransportProtocol = TCPv6
	default:
		hdr.TransportProtocol = UNSPEC
	}

	// Read addresses and ports
	hdr.SourceAddress, err = parseV1IPAddress(hdr.TransportProtocol, tokens[2])
	if err != nil {
		return nil, err
	}
	hdr.DestinationAddress, err = parseV1IPAddress(hdr.TransportProtocol, tokens[3])
	if err != nil {
		return nil, err
	}
	hdr.SourcePort, err = parseV1PortNumber(tokens[4])
	if err != nil {
		return nil, err
	}
	hdr.DestinationPort, err = parseV1PortNumber(tokens[5])
	if err != nil {
		return nil, err
	}
	return hdr, nil
}

func (h *Header) writeVersion1(w io.Writer) (int64, error) {
	// As of version 1, only "TCP4" ( \x54 \x43 \x50 \x34 ) for TCP over IPv4,
	// and "TCP6" ( \x54 \x43 \x50 \x36 ) for TCP over IPv6 are allowed.
	proto := "UNKNOWN"
	switch h.TransportProtocol {
	case TCPv4:
		proto = "TCP4"
	case TCPv6:
		proto = "TCP6"
	}

	var buf bytes.Buffer
	buf.Write(SIGV1)
	buf.WriteString(SEPARATOR)
	buf.WriteString(proto)
	buf.WriteString(SEPARATOR)
	buf.WriteString(h.SourceAddress.String())
	buf.WriteString(SEPARATOR)
	buf.WriteString(h.DestinationAddress.String())
	buf.WriteString(SEPARATOR)
	buf.WriteString(strconv.Itoa(int(h.SourcePort)))
	buf.WriteString(SEPARATOR)
	buf.WriteString(strconv.Itoa(int(h.DestinationPort)))
	buf.WriteString(CRLF)

	return buf.WriteTo(w)
}

// FIXME add test
func parseV1PortNumber(portStr string) (uint16, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, err
	}
	if port < 0 || port > 65535 {
		return 0, ErrInvalidPortNumber
	}
	return uint16(port), nil
}

// FIXME add test
func parseV1IPAddress(proto AddressFamilyAndProtocol, addrStr string) (net.IP, error) {
	addr := net.ParseIP(addrStr)
	v4 := addr.To4()
	if (proto == TCPv4 && v4 == nil) || (proto == TCPv6 && v4 != nil) {
		return nil, ErrInvalidAddress
	}
	return addr, nil
}
