package proxyproto

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strconv"
	"testing"
)

const (
	NO_PROTOCOL = "There is no spoon"
	IP4_ADDR    = "127.0.0.1"
	IP6_ADDR    = "::1"
	PORT        = 65533
)

var (
	v4addr = net.ParseIP(IP4_ADDR).To4()
	v6addr = net.ParseIP(IP6_ADDR).To16()

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
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SrcAddr:           v4addr,
				DstAddr:           v4addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
		{
			"PROXY TCP6 " + tcp6AddrsPorts + CRLF + "GET /",
			&Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv6,
				SrcAddr:           v6addr,
				DstAddr:           v6addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
		},
	} {
		t.Run("Parse valid v1 header", func(t *testing.T) {
			t.Run(tt.str, func(t *testing.T) {
				actual, err := Read(newBufioReader([]byte(tt.str)))
				if err != nil {
					t.Fatal("unexpected error:", err)
				}
				if !assertHeader(actual, tt.expectedHeader) {
					t.Fatalf("expected %#v, actual %#v", tt.expectedHeader, actual)
				}
			})
		})

		t.Run("Write valid v1 header", func(t *testing.T) {
			t.Run(tt.str, func(t *testing.T) {
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
		})
	}
}

func TestParseV1Port(t *testing.T) {
	for _, tt := range []struct {
		PortStr  string
		Expected uint16
		IsError  bool
	}{
		{
			PortStr:  "0",
			Expected: 0,
		},
		{
			PortStr:  "65535",
			Expected: 65535,
		},
		{
			PortStr: "65536",
			IsError: true,
		},
	} {
		port, err := parseV1Port(tt.PortStr)
		if tt.IsError {
			if err == nil {
				t.Error("expected error:", err)
			}
		} else {
			if err != nil {
				t.Error("unexpected error:", err)
			}
			if port != tt.Expected {
				t.Errorf("expected '%d', got '%d'", tt.Expected, port)
			}
		}
	}
}

func TestParseV1IPAddress(t *testing.T) {
	for _, tt := range []struct {
		AddrStr string
		Proto   AddressFamilyAndProtocol
		IsError bool
	}{
		{
			AddrStr: "127.0.0.1",
			Proto:   UNSPEC,
			IsError: true,
		},
		{
			AddrStr: "127.0.0.1",
			Proto:   TCPv4,
		},
		{
			AddrStr: "127.0.0.1",
			Proto:   UDPv4,
		},
		{
			AddrStr: "127.0.0.1",
			Proto:   TCPv6,
			IsError: true,
		},
		{
			AddrStr: "127.0.0.1",
			Proto:   UDPv6,
			IsError: true,
		},
		{
			AddrStr: "2001:db8:1",
			Proto:   TCPv4,
			IsError: true,
		},
		{
			AddrStr: "2001:db8::1",
			Proto:   UDPv4,
			IsError: true,
		},
		{
			AddrStr: "2001:db8::1",
			Proto:   TCPv6,
		},
		{
			AddrStr: "2001:db8::1",
			Proto:   UDPv6,
		},
	} {
		t.Run(fmt.Sprintf("Addr=%s, Proto=%v", tt.AddrStr, tt.Proto), func(t *testing.T) {
			_, err := parseV1IPAddress(tt.Proto, tt.AddrStr)
			if tt.IsError {
				if err == nil {
					t.Error("expected error:", err)
				}
			} else {
				if err != nil {
					t.Error("unexpected error:", err)
				}
			}
		})
	}
}
