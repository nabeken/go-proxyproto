package proxyproto

import (
	"bufio"
	"bytes"
	"strconv"
	"strings"
	"testing"
)

var (
	tcp4AddrsPorts = IP4_ADDR + v1Sep + IP4_ADDR + v1Sep + strconv.Itoa(PORT) + v1Sep + strconv.Itoa(PORT)
	tcp6AddrsPorts = IP6_ADDR + v1Sep + IP6_ADDR + v1Sep + strconv.Itoa(PORT) + v1Sep + strconv.Itoa(PORT)
)

func TestReadV1Invalid(t *testing.T) {
	for _, tt := range []struct {
		bytes         []byte
		expectedError error
	}{
		{
			[]byte("PROX"),
			ErrNoProxyProtocol,
		},
		{
			[]byte(NO_PROTOCOL),
			ErrNoProxyProtocol,
		},
		{
			[]byte("PROXY \r\n"),
			ErrCantReadProtocolVersionAndCommand,
		},
		{
			[]byte("PROXY TCP4 " + tcp4AddrsPorts),
			ErrCantReadProtocolVersionAndCommand,
		},
		{
			[]byte("PROXY TCP6 " + tcp4AddrsPorts + CRLF),
			ErrInvalidAddress,
		},
		{
			[]byte("PROXY TCP4 " + tcp6AddrsPorts + CRLF),
			ErrInvalidAddress,
		},
	} {
		if _, err := Read(newBufioReader(tt.bytes)); err != tt.expectedError {
			t.Fatalf("'%s': expected '%s', actual '%s'", string(tt.bytes), tt.expectedError, err)
		}
	}
}

func TestReadWriteV1Valid(t *testing.T) {
	for _, tt := range []struct {
		str            string
		expectedHeader *Header
	}{
		{
			"PROXY TCP4 " + tcp4AddrsPorts + CRLF + "GET /",
			&Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv4,
				SourceAddress:      v4addr,
				DestinationAddress: v4addr,
				SourcePort:         PORT,
				DestinationPort:    PORT,
			},
		},
		{
			"PROXY TCP6 " + tcp6AddrsPorts + CRLF + "GET /",
			&Header{
				Version:            1,
				Command:            PROXY,
				TransportProtocol:  TCPv6,
				SourceAddress:      v6addr,
				DestinationAddress: v6addr,
				SourcePort:         PORT,
				DestinationPort:    PORT,
			},
		},
	} {
		t.Run("Parse valid v1 header", func(t *testing.T) {
			t.Run(tt.str, func(t *testing.T) {
				actual, err := Read(bufio.NewReader(strings.NewReader(tt.str)))
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				if !actual.EqualTo(tt.expectedHeader) {
					t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, actual)
				}
			})
		})

		t.Run("Write valid v1 header", func(t *testing.T) {
			t.Run(tt.str, func(t *testing.T) {
				var b bytes.Buffer
				bw := bufio.NewWriter(&b)
				if _, err := tt.expectedHeader.WriteTo(bw); err != nil {
					t.Fatal("unexpected error:", err)
				}
				bw.Flush()

				// Read written bytes to validate written header
				br := bufio.NewReader(&b)
				actual, err := Read(br)
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				if !actual.EqualTo(tt.expectedHeader) {
					t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, actual)
				}
			})
		})
	}
}
