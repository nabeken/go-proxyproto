package proxyproto

import (
	"bufio"
	"bytes"
	"testing"
)

var (
	invalidBytes = []byte{'\x99'}
	proxyBytes   = []byte{PROXY}
	localBytes   = []byte{LOCAL}
	unspecBytes  = []byte{UNSPEC}
	tcpv4Bytes   = []byte{TCPv4}
	tcpv6Bytes   = []byte{TCPv6}
	udpv4Bytes   = []byte{UDPv4}
	udpv6Bytes   = []byte{UDPv6}

	// Lengths to use in tests
	paddedLen = uint16(84)

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
		bytes         []byte
		expectedError error
	}{
		{
			SIGV2[2:],
			ErrNoProxyProtocol,
		},
		{
			[]byte(NO_PROTOCOL),
			ErrNoProxyProtocol,
		},
		{
			SIGV2,
			ErrCantReadProtocolVersionAndCommand,
		},
		{
			catBytes(SIGV2, invalidBytes),
			ErrUnsupportedProtocolVersionAndCommand,
		},
		{
			catBytes(SIGV2, proxyBytes),
			ErrCantReadAddressFamilyAndProtocol,
		},
		{
			catBytes(SIGV2, proxyBytes, invalidBytes),
			ErrUnsupportedAddressFamilyAndProtocol,
		},
		{
			catBytes(SIGV2, proxyBytes, tcpv4Bytes),
			ErrCantReadLength,
		},
		{
			catBytes(SIGV2, proxyBytes, tcpv4Bytes, invalidBytes),
			ErrCantReadLength,
		},
		{
			catBytes(SIGV2, proxyBytes, tcpv4Bytes, fixedV4AddrLen[:]),
			ErrInvalidLength,
		},
		{
			catBytes(SIGV2, proxyBytes, tcpv6Bytes, fixedV6AddrLen[:]),
			ErrInvalidLength,
		},
		{
			catBytes(SIGV2, proxyBytes, tcpv4Bytes, fixedEmptyLen[:], fixtureIPv6Address),
			ErrInvalidLength,
		},
		{
			catBytes(SIGV2, proxyBytes, tcpv6Bytes, fixedV6AddrLen[:], fixtureIPv4Address),
			ErrInvalidLength,
		},
	} {
		t.Run("", func(t *testing.T) {
			if _, err := Read(newBufioReader(tt.bytes)); err != tt.expectedError {
				t.Fatalf("expected %s, actual %s", tt.expectedError, err)
			}
		})
	}
}

func TestReadWriteV2Valid_Local(t *testing.T) {
	// LOCAL
	headerBytes := catBytes(SIGV2, localBytes, unspecBytes, fixtureIPv4V2)

	{
		actual, err := Read(newBufioReader(headerBytes))
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		if actual != nil {
			t.Fatal("header must be nil since the proxy protocol shouldn't be involved")
		}
	}

	{
		buf := &bytes.Buffer{}
		_, err := (&Header{
			Version:           2,
			Command:           LOCAL,
			TransportProtocol: TCPv4,
			SrcAddr:           v4addr,
			DstAddr:           v4addr,
			SrcPort:           PORT,
			DstPort:           PORT,
		}).WriteTo(buf)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}

		br := bufio.NewReader(buf)
		actual, err := Read(br)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		if actual != nil {
			t.Fatal("header must be nil since the proxy protocol shouldn't be involved")
		}
	}
}

func TestReadWriteV2Valid(t *testing.T) {
	for _, tt := range []struct {
		bytes          []byte
		expectedHeader *Header
	}{
		// PROXY TCP IPv4
		{
			catBytes(SIGV2, proxyBytes, tcpv4Bytes, fixtureIPv4V2),
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
			catBytes(SIGV2, proxyBytes, tcpv6Bytes, fixtureIPv6V2),
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
			catBytes(SIGV2, proxyBytes, udpv4Bytes, fixtureIPv4V2),
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
			catBytes(SIGV2, proxyBytes, udpv6Bytes, fixtureIPv6V2),
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
		t.Run("Read", func(t *testing.T) {
			actual, err := Read(newBufioReader(tt.bytes))
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if !assertHeader(actual, tt.expectedHeader) {
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

			if !assertHeader(actual, tt.expectedHeader) {
				t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, actual)
			}
		})
	}
}

func TestReadV2Padded(t *testing.T) {
	payload := []byte{'\x99', '\x97', '\x98'}

	for _, tt := range []struct {
		bytes          []byte
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
			br := newBufioReader(append(tt.bytes, payload...))
			actual, err := Read(br)
			if err != nil {
				t.Fatal("unexpected error:", err)
			}
			if !assertHeader(actual, tt.expectedHeader) {
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

func catBytes(b ...[]byte) []byte {
	ret := []byte{}
	for _, b_ := range b {
		ret = append(ret, b_...)
	}
	return ret
}

func newBufioReader(b []byte) *bufio.Reader {
	return bufio.NewReader(bytes.NewReader(b))
}

// assertHeader returns true if the given two headers are equivalent or h1 is LOCAL.
func assertHeader(actual, expected *Header) bool {
	if actual == nil && expected == nil {
		return true
	}
	if actual == nil || expected == nil {
		return false
	}

	return actual.TransportProtocol == expected.TransportProtocol &&
		actual.SrcAddr.String() == expected.SrcAddr.String() &&
		actual.DstAddr.String() == expected.DstAddr.String() &&
		actual.SrcPort == expected.SrcPort &&
		actual.DstPort == expected.DstPort
}
