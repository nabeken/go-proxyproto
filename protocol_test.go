package proxyproto

import (
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
