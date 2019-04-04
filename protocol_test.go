package proxyproto

import (
	"bufio"
	"net"
	"testing"
	"time"
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

const (
	NO_PROTOCOL = "There is no spoon"
	IP4_ADDR    = "127.0.0.1"
	IP6_ADDR    = "::1"
	PORT        = 65533
)

var (
	v4addr = net.ParseIP(IP4_ADDR).To4()
	v6addr = net.ParseIP(IP6_ADDR).To16()
)

type timeoutReader []byte

func (t *timeoutReader) Read([]byte) (int, error) {
	time.Sleep(500 * time.Millisecond)
	return 0, nil
}

func TestReadTimeoutV1Invalid(t *testing.T) {
	var b timeoutReader
	reader := bufio.NewReader(&b)
	_, err := ReadTimeout(reader, 50*time.Millisecond)
	if err == nil {
		t.Fatalf("TestReadTimeoutV1Invalid: expected error %s", ErrNoProxyProtocol)
	} else if err != ErrNoProxyProtocol {
		t.Fatalf("TestReadTimeoutV1Invalid: expected %s, actual %s", ErrNoProxyProtocol, err)
	}
}
