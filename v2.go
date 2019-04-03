package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
)

const (
	v4AddrLen = 12
	v6AddrLen = 36
)

var (
	fixedV4AddrLen = fixedAddrLen2Bytes(v4AddrLen)
	fixedV6AddrLen = fixedAddrLen2Bytes(v6AddrLen)
)

type _ports struct {
	SrcPort uint16
	DstPort uint16
}

type _addr4 struct {
	Src [4]byte
	Dst [4]byte
	_ports
}

type _addr6 struct {
	Src [16]byte
	Dst [16]byte
	_ports
}

func parseVersion2(br *bufio.Reader) (*Header, error) {
	// Skip first 12 bytes (signature)
	n, err := br.Discard(len(SIGV2))
	if err != nil || n != len(SIGV2) {
		return nil, ErrCantReadProtocolVersionAndCommand
	}

	hdr := &Header{
		Version: 2,
	}

	// Read the 13th byte, protocol version and command
	b13, err := br.ReadByte()
	if err != nil {
		return nil, ErrCantReadProtocolVersionAndCommand
	}

	hdr.Command = ProtocolVersionAndCommand(b13)
	if !isSupportedCommand(hdr.Command) {
		return nil, ErrUnsupportedProtocolVersionAndCommand
	}

	// If command is LOCAL, header ends here
	if hdr.Command.IsLocal() {
		return hdr, nil
	}

	// Read the 14th byte, address family and protocol
	b14, err := br.ReadByte()
	if err != nil {
		return nil, ErrCantReadAddressFamilyAndProtocol
	}
	hdr.TransportProtocol = AddressFamilyAndProtocol(b14)
	if !isSupportedTransportProtocol(hdr.TransportProtocol) {
		return nil, ErrUnsupportedAddressFamilyAndProtocol
	}

	// Make sure there are enough bytes available for the address family and protocol
	var len uint16
	if err := binary.Read(io.LimitReader(br, 2), binary.BigEndian, &len); err != nil {
		return nil, ErrCantReadLength
	}
	if !validateLeastAddressLen(hdr.TransportProtocol, len) {
		return nil, ErrInvalidLength
	}

	if _, err := br.Peek(int(len)); err != nil {
		return nil, ErrInvalidLength
	}

	// Length-limited reader for payload section
	lr := io.LimitReader(br, int64(len))

	// Read addresses and ports
	switch {
	case hdr.TransportProtocol.IsIPv4():
		var addr _addr4
		if err := binary.Read(lr, binary.BigEndian, &addr); err != nil {
			return nil, ErrInvalidAddress
		}
		hdr.SrcAddr = addr.Src[:]
		hdr.DstAddr = addr.Dst[:]
		hdr.SrcPort = addr.SrcPort
		hdr.DstPort = addr.DstPort
	case hdr.TransportProtocol.IsIPv6():
		var addr _addr6
		if err := binary.Read(lr, binary.BigEndian, &addr); err != nil {
			return nil, ErrInvalidAddress
		}
		hdr.SrcAddr = addr.Src[:]
		hdr.DstAddr = addr.Dst[:]
		hdr.SrcPort = addr.SrcPort
		hdr.DstPort = addr.DstPort
	}

	// TODO add encapsulated TLV support

	// Drain the remaining padding
	io.Copy(ioutil.Discard, lr)

	return hdr, nil
}

func (h *Header) writeVersion2(w io.Writer) (int64, error) {
	buf := &bytes.Buffer{}
	buf.Write(SIGV2)
	buf.WriteByte(byte(h.Command))

	if h.Command.IsLocal() {
		return buf.WriteTo(w)
	}

	buf.WriteByte(byte(h.TransportProtocol))

	// TODO add encapsulated TLV length
	switch {
	case h.TransportProtocol.IsIPv4():
		buf.Write(fixedV4AddrLen[:])
		buf.Write(h.SrcAddr.To4())
		buf.Write(h.DstAddr.To4())
	case h.TransportProtocol.IsIPv6():
		buf.Write(fixedV6AddrLen[:])
		buf.Write(h.SrcAddr.To16())
		buf.Write(h.DstAddr.To16())
	}

	binary.Write(buf, binary.BigEndian, h.SrcPort)
	binary.Write(buf, binary.BigEndian, h.DstPort)
	return buf.WriteTo(w)
}

func fixedAddrLen2Bytes(len uint16) [2]byte {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], len)
	return b
}
