package proxyproto

import (
	"bufio"
	"bytes"
	"testing"
)

var (
	invalidRune = byte('\x99')

	// Lengths to use in tests
	paddedLen = uint16(84)

	emptyAddrLen  = writeUint16ByBE(0)
	paddedAddrLen = writeUint16ByBE(paddedLen)

	// If life gives you lemons, make mojitos
	portBytes = writeUint16ByBE(PORT)

	// Tests don't care if source and destination addresses and ports are the same
	addressesIPv4 = catBytes(v4addr.To4(), v4addr.To4())
	addressesIPv6 = catBytes(v6addr.To16(), v6addr.To16())
	ports         = catBytes(portBytes[:], portBytes[:])

	// Fixtures to use in tests
	fixtureIPv4Address  = catBytes(addressesIPv4, ports)
	fixtureIPv4V2       = catBytes(fixedV4AddrLen[:], fixtureIPv4Address)
	fixtureIPv4V2Padded = catBytes(paddedAddrLen[:], fixtureIPv4Address, make([]byte, paddedLen-v4AddrLen))

	fixtureIPv6Address  = catBytes(addressesIPv6, ports)
	fixtureIPv6V2       = catBytes(fixedV6AddrLen[:], fixtureIPv6Address)
	fixtureIPv6V2Padded = catBytes(paddedAddrLen[:], fixtureIPv6Address, make([]byte, paddedLen-v6AddrLen))
)

func TestReadV2Invalid(t *testing.T) {
	for _, tt := range []struct {
		reader        *bufio.Reader
		expectedError error
	}{
		{
			newBufioReader(SIGV2[2:]),
			ErrNoProxyProtocol,
		},
		{
			newBufioReader([]byte(NO_PROTOCOL)),
			ErrNoProxyProtocol,
		},
		{
			newBufioReader(SIGV2),
			ErrCantReadProtocolVersionAndCommand,
		},
		{
			newBufioReader(append(SIGV2, invalidRune)),
			ErrUnsupportedProtocolVersionAndCommand,
		},
		{
			newBufioReader(append(SIGV2, PROXY)),
			ErrCantReadAddressFamilyAndProtocol,
		},
		{
			newBufioReader(append(SIGV2, PROXY, invalidRune)),
			ErrUnsupportedAddressFamilyAndProtocol,
		},
		{
			newBufioReader(append(SIGV2, PROXY, TCPv4)),
			ErrCantReadLength,
		},
		{
			newBufioReader(append(SIGV2, PROXY, TCPv4, invalidRune)),
			ErrCantReadLength,
		},
		{
			newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixedV4AddrLen[:]...)),
			ErrInvalidLength,
		},
		{
			newBufioReader(append(append(SIGV2, PROXY, TCPv6), fixedV6AddrLen[:]...)),
			ErrInvalidLength,
		},
		{
			newBufioReader(append(append(append(SIGV2, PROXY, TCPv4), emptyAddrLen[:]...), fixtureIPv6Address...)),
			ErrInvalidLength,
		},
		{
			newBufioReader(append(append(append(SIGV2, PROXY, TCPv6), fixedV6AddrLen[:]...), fixtureIPv4Address...)),
			ErrInvalidLength,
		},
	} {
		t.Run("", func(t *testing.T) {
			if _, err := Read(tt.reader); err != tt.expectedError {
				t.Fatalf("expected %s, actual %s", tt.expectedError, err)
			}
		})
	}
}

func TestReadWriteV2Valid(t *testing.T) {
	for _, tt := range []struct {
		reader         *bufio.Reader
		expectedHeader *Header
	}{
		// LOCAL
		{
			newBufioReader(append(SIGV2, LOCAL)),
			&Header{
				Version: 2,
				Command: LOCAL,
			},
		},
		// PROXY TCP IPv4
		{
			newBufioReader(append(append(SIGV2, PROXY, TCPv4), fixtureIPv4V2...)),
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SrcAddr:           v4addr,
				DstAddr:           v4addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
		// PROXY TCP IPv6
		{
			newBufioReader(append(append(SIGV2, PROXY, TCPv6), fixtureIPv6V2...)),
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv6,
				SrcAddr:           v6addr,
				DstAddr:           v6addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
		// PROXY UDP IPv4
		{
			newBufioReader(append(append(SIGV2, PROXY, UDPv4), fixtureIPv4V2...)),
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UDPv4,
				SrcAddr:           v4addr,
				DstAddr:           v4addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
		// PROXY UDP IPv6
		{
			newBufioReader(append(append(SIGV2, PROXY, UDPv6), fixtureIPv6V2...)),
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UDPv6,
				SrcAddr:           v6addr,
				DstAddr:           v6addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
		// TODO add tests for Unix stream and datagram
	} {
		t.Run("Read", func(t *testing.T) {
			actual, err := Read(tt.reader)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if !actual.EqualTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, actual)
			}
		})

		t.Run("Write", func(t *testing.T) {
			buf := &bytes.Buffer{}
			bw := bufio.NewWriter(buf)
			if _, err := tt.expectedHeader.WriteTo(bw); err != nil {
				t.Fatal("unexpected error:", err)
			}
			bw.Flush()

			// Read written bytes to validate written header
			br := bufio.NewReader(buf)
			actual, err := Read(br)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}

			if !actual.EqualTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, actual)
			}
		})
	}
}

func TestReadV2Padded(t *testing.T) {
	payload := []byte{'\x99', '\x97', '\x98'}

	for _, tt := range []struct {
		value          []byte
		expectedHeader *Header
	}{
		// PROXY TCP IPv4
		{
			append(append(SIGV2, PROXY, TCPv4), fixtureIPv4V2Padded...),
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SrcAddr:           v4addr,
				DstAddr:           v4addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
		// PROXY TCP IPv6
		{
			append(append(SIGV2, PROXY, TCPv6), fixtureIPv6V2Padded...),
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: TCPv6,
				SrcAddr:           v6addr,
				DstAddr:           v6addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
		// PROXY UDP IPv4
		{
			append(append(SIGV2, PROXY, UDPv4), fixtureIPv4V2Padded...),
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UDPv4,
				SrcAddr:           v4addr,
				DstAddr:           v4addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
		// PROXY UDP IPv6
		{
			append(append(SIGV2, PROXY, UDPv6), fixtureIPv6V2Padded...),
			&Header{
				Version:           2,
				Command:           PROXY,
				TransportProtocol: UDPv6,
				SrcAddr:           v6addr,
				DstAddr:           v6addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
	} {
		t.Run("", func(t *testing.T) {
			br := newBufioReader(append(tt.value, payload...))
			actual, err := Read(br)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if !actual.EqualTo(tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, actual)
			}

			// Check that remaining padding bytes have been flushed
			nextBytes, err := br.Peek(len(payload))
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if !bytes.Equal(nextBytes, payload) {
				t.Fatalf("expected %#v, actual %#v", payload, nextBytes)
			}
		})
	}
}

func newBufioReader(b []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(b))
}

func catBytes(b ...[]byte) []byte {
	ret := []byte{}
	for _, b_ := range b {
		ret = append(ret, b_...)
	}
	return ret
}
