package proxyproto

import (
	"net"
	"testing"
)

func TestAddressFamilyAndProtocols(t *testing.T) {
	for _, tt := range []struct {
		B      AddressFamilyAndProtocol
		TrueF  []func(AddressFamilyAndProtocol) bool
		FalseF []func(AddressFamilyAndProtocol) bool
	}{
		{
			B: UNSPEC,
			TrueF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsUnspec,
			},
			FalseF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsIPv4,
				AddressFamilyAndProtocol.IsStream,
				AddressFamilyAndProtocol.IsIPv6,
				AddressFamilyAndProtocol.IsDatagram,
			},
		},
		{
			B: TCPv4,
			TrueF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsIPv4,
				AddressFamilyAndProtocol.IsStream,
			},
			FalseF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsIPv6,
				AddressFamilyAndProtocol.IsDatagram,
				AddressFamilyAndProtocol.IsUnspec,
			},
		},
		{
			B: UDPv4,
			TrueF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsIPv4,
				AddressFamilyAndProtocol.IsDatagram,
			},
			FalseF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsIPv6,
				AddressFamilyAndProtocol.IsStream,
				AddressFamilyAndProtocol.IsUnspec,
			},
		},
		{
			B: TCPv6,
			TrueF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsIPv6,
				AddressFamilyAndProtocol.IsStream,
			},
			FalseF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsIPv4,
				AddressFamilyAndProtocol.IsDatagram,
				AddressFamilyAndProtocol.IsUnspec,
			},
		},
		{
			B: UDPv6,
			TrueF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsIPv6,
				AddressFamilyAndProtocol.IsDatagram,
			},
			FalseF: []func(AddressFamilyAndProtocol) bool{
				AddressFamilyAndProtocol.IsIPv4,
				AddressFamilyAndProtocol.IsStream,
				AddressFamilyAndProtocol.IsUnspec,
			},
		},
	} {
		t.Run(string(tt.B), func(t *testing.T) {
			for _, f := range tt.TrueF {
				t.Run("TrueF", func(t *testing.T) {
					if !f(tt.B) {
						t.Error("must be true")
					}
				})
			}
			for _, f := range tt.FalseF {
				t.Run("FalseF", func(t *testing.T) {
					if f(tt.B) {
						t.Error("must be false")
					}
				})
			}
		})
	}
}

func TestProtocolVersionAndCommand(t *testing.T) {
	for _, tt := range []struct {
		B      ProtocolVersionAndCommand
		TrueF  []func(ProtocolVersionAndCommand) bool
		FalseF []func(ProtocolVersionAndCommand) bool
	}{
		{
			B: LOCAL,
			TrueF: []func(ProtocolVersionAndCommand) bool{
				ProtocolVersionAndCommand.IsLocal,
			},
			FalseF: []func(ProtocolVersionAndCommand) bool{
				ProtocolVersionAndCommand.IsProxy,
				ProtocolVersionAndCommand.IsUnspec,
			},
		},
		{
			B: PROXY,
			TrueF: []func(ProtocolVersionAndCommand) bool{
				ProtocolVersionAndCommand.IsProxy,
			},
			FalseF: []func(ProtocolVersionAndCommand) bool{
				ProtocolVersionAndCommand.IsLocal,
				ProtocolVersionAndCommand.IsUnspec,
			},
		},
		{
			B: 0x00,
			TrueF: []func(ProtocolVersionAndCommand) bool{
				ProtocolVersionAndCommand.IsUnspec,
			},
			FalseF: []func(ProtocolVersionAndCommand) bool{
				ProtocolVersionAndCommand.IsProxy,
				ProtocolVersionAndCommand.IsLocal,
			},
		},
	} {
		t.Run(string(tt.B), func(t *testing.T) {
			for _, f := range tt.TrueF {
				t.Run("TrueF", func(t *testing.T) {
					if !f(tt.B) {
						t.Error("must be true")
					}
				})
			}
			for _, f := range tt.FalseF {
				t.Run("FalseF", func(t *testing.T) {
					if f(tt.B) {
						t.Error("must be false")
					}
				})
			}
		})
	}
}

func TestHeader_Addr(t *testing.T) {
	tcpv4Addr := &net.TCPAddr{
		IP:   v4addr,
		Port: PORT,
	}
	udpv4Addr := &net.UDPAddr{
		IP:   v4addr,
		Port: PORT,
	}
	tcpv6Addr := &net.TCPAddr{
		IP:   v6addr,
		Port: PORT,
	}
	udpv6Addr := &net.UDPAddr{
		IP:   v6addr,
		Port: PORT,
	}
	for _, tt := range []struct {
		Header       *Header
		ExpectedAddr net.Addr
	}{
		{
			Header: &Header{
				TransportProtocol: TCPv4,
				SrcAddr:           v4addr,
				DstAddr:           v4addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
			ExpectedAddr: tcpv4Addr,
		},
		{
			Header: &Header{
				TransportProtocol: UDPv4,
				SrcAddr:           v4addr,
				DstAddr:           v4addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
			ExpectedAddr: udpv4Addr,
		},
		{
			Header: &Header{
				TransportProtocol: TCPv6,
				SrcAddr:           v6addr,
				DstAddr:           v6addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
			ExpectedAddr: tcpv6Addr,
		},
		{
			Header: &Header{
				TransportProtocol: UDPv6,
				SrcAddr:           v6addr,
				DstAddr:           v6addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
			ExpectedAddr: udpv6Addr,
		},
	} {
		t.Run("", func(t *testing.T) {
			for _, actual := range []net.Addr{tt.Header.RemoteAddr(), tt.Header.LocalAddr()} {
				if actual.Network() != tt.ExpectedAddr.Network() {
					t.Errorf("expected '%s', got '%s'", tt.ExpectedAddr.Network(), actual.Network())
				}
				if actual.String() != tt.ExpectedAddr.String() {
					t.Errorf("expected '%s', got '%s'", tt.ExpectedAddr.String(), actual.String())
				}
			}
		})
	}
}
