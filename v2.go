package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
)

var (
	lengthV4   = uint16(12)
	lengthV6   = uint16(36)
	lengthUnix = uint16(218)

	lengthV4Bytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, lengthV4)
		return a
	}()
	lengthV6Bytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, lengthV6)
		return a
	}()
	lengthUnixBytes = func() []byte {
		a := make([]byte, 2)
		binary.BigEndian.PutUint16(a, lengthUnix)
		return a
	}()
)

type _ports struct {
	SrcPort uint16
	DstPort uint16
}

type _addr4 struct {
	Src     [4]byte
	Dst     [4]byte
	SrcPort uint16
	DstPort uint16
}

type _addr6 struct {
	Src [16]byte
	Dst [16]byte
	_ports
}

type _addrUnix struct {
	Src [108]byte
	Dst [108]byte
}

func newV2Header() *Header {
	return &Header{
		Version: 2,
	}
}

func parseVersion2(br *bufio.Reader) (*Header, error) {
	// Skip first 12 bytes (signature)
	n, err := br.Discard(len(SIGV2))
	if err != nil || n != len(SIGV2) {
		return nil, ErrCantReadProtocolVersionAndCommand
	}

	hdr := newV2Header()

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
		hdr.SourceAddress = addr.Src[:]
		hdr.DestinationAddress = addr.Dst[:]
		hdr.SourcePort = addr.SrcPort
		hdr.DestinationPort = addr.DstPort
	case hdr.TransportProtocol.IsIPv6():
		var addr _addr6
		if err := binary.Read(lr, binary.BigEndian, &addr); err != nil {
			return nil, ErrInvalidAddress
		}
		hdr.SourceAddress = addr.Src[:]
		hdr.DestinationAddress = addr.Dst[:]
		hdr.SourcePort = addr.SrcPort
		hdr.DestinationPort = addr.DstPort
	case hdr.TransportProtocol.IsUnix():
		// TODO fully support Unix addresses
	}

	// TODO add encapsulated TLV support

	// Drain the remaining padding
	io.Copy(ioutil.Discard, lr)

	return hdr, nil
}

func (header *Header) writeVersion2(w io.Writer) (int64, error) {
	var buf bytes.Buffer
	buf.Write(SIGV2)
	buf.WriteByte(byte(header.Command))
	if !header.Command.IsLocal() {
		buf.WriteByte(byte(header.TransportProtocol))
		// TODO add encapsulated TLV length
		var addrSrc, addrDst []byte
		if header.TransportProtocol.IsIPv4() {
			buf.Write(lengthV4Bytes)
			addrSrc = header.SourceAddress.To4()
			addrDst = header.DestinationAddress.To4()
		} else if header.TransportProtocol.IsIPv6() {
			buf.Write(lengthV6Bytes)
			addrSrc = header.SourceAddress.To16()
			addrDst = header.DestinationAddress.To16()
		} else if header.TransportProtocol.IsUnix() {
			buf.Write(lengthUnixBytes)
			// TODO is below right?
			addrSrc = []byte(header.SourceAddress.String())
			addrDst = []byte(header.DestinationAddress.String())
		}
		buf.Write(addrSrc)
		buf.Write(addrDst)

		portSrcBytes := func() []byte {
			a := make([]byte, 2)
			binary.BigEndian.PutUint16(a, header.SourcePort)
			return a
		}()
		buf.Write(portSrcBytes)

		portDstBytes := func() []byte {
			a := make([]byte, 2)
			binary.BigEndian.PutUint16(a, header.DestinationPort)
			return a
		}()
		buf.Write(portDstBytes)

	}

	return buf.WriteTo(w)
}
