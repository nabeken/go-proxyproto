package proxyproto

import (
	"testing"
)

func TestTCPoverIPv4(t *testing.T) {
	b := byte(TCPv4)
	if !AddressFamilyAndProtocol(b).IsIPv4() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsStream() {
		t.Fail()
	}
}

func TestTCPoverIPv6(t *testing.T) {
	b := byte(TCPv6)
	if !AddressFamilyAndProtocol(b).IsIPv6() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsStream() {
		t.Fail()
	}
}

func TestUDPoverIPv4(t *testing.T) {
	b := byte(UDPv4)
	if !AddressFamilyAndProtocol(b).IsIPv4() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsDatagram() {
		t.Fail()
	}
}

func TestUDPoverIPv6(t *testing.T) {
	b := byte(UDPv6)
	if !AddressFamilyAndProtocol(b).IsIPv6() {
		t.Fail()
	}
	if !AddressFamilyAndProtocol(b).IsDatagram() {
		t.Fail()
	}
}

func TestInvalidAddressFamilyAndProtocol(t *testing.T) {
	b := byte(UNSPEC)
	if !AddressFamilyAndProtocol(b).IsUnspec() {
		t.Fail()
	}
}

func TestLocal(t *testing.T) {
	b := byte(LOCAL)
	if ProtocolVersionAndCommand(b).IsUnspec() {
		t.Fail()
	}
	if !ProtocolVersionAndCommand(b).IsLocal() {
		t.Fail()
	}
	if ProtocolVersionAndCommand(b).IsProxy() {
		t.Fail()
	}
}

func TestProxy(t *testing.T) {
	b := byte(PROXY)
	if ProtocolVersionAndCommand(b).IsUnspec() {
		t.Fail()
	}
	if ProtocolVersionAndCommand(b).IsLocal() {
		t.Fail()
	}
	if !ProtocolVersionAndCommand(b).IsProxy() {
		t.Fail()
	}
}

func TestInvalidProtocolVersion(t *testing.T) {
	if !ProtocolVersionAndCommand(0x00).IsUnspec() {
		t.Fail()
	}
}
