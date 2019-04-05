package proxyproto

import (
	"bytes"
	"net"
	"sync"
	"testing"
)

type Client struct {
	Header *Header
	Conn   net.Conn

	once sync.Once
}

func (c *Client) Write(p []byte) (int, error) {
	var err error
	c.once.Do(func() {
		_, err = c.Header.WriteTo(c.Conn)
	})
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *Client) Read(p []byte) (int, error) {
	var err error
	c.once.Do(func() {
		_, err = c.Header.WriteTo(c.Conn)
	})
	if err != nil {
		return 0, err
	}
	return c.Read(p)
}

func TestConn(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	// upgrade to proxyproto-aware listener
	pl := &Listener{Listener: ln}

	go func() {
		conn, err := net.Dial("tcp", pl.Listener.Addr().String())
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		defer conn.Close()

		conn.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("got: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}
}

func TestConn_ProxyProtoV1(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}

	// upgrade to proxyproto-aware listener
	pl := &Listener{Listener: ln}

	go func() {
		conn, err := net.Dial("tcp", pl.Listener.Addr().String())
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		defer conn.Close()

		c := &Client{
			Header: &Header{
				Version:           1,
				Command:           PROXY,
				TransportProtocol: TCPv4,
				SrcAddr:           v4addr,
				DstAddr:           v4addr,
				SrcPort:           PORT,
				DstPort:           PORT,
			},
			Conn: conn,
		}

		c.Write([]byte("ping"))
		recv := make([]byte, 4)
		_, err = conn.Read(recv)
		if err != nil {
			t.Fatal("unexpected error:", err)
		}
		if !bytes.Equal(recv, []byte("pong")) {
			t.Fatalf("got: %v", recv)
		}
	}()

	conn, err := pl.Accept()
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	defer conn.Close()

	if conn.LocalAddr().String() != v4AddrPort {
		t.Fatalf("expected '%s', got '%s'", v4addr.String(), conn.LocalAddr().String())
	}
	if conn.RemoteAddr().String() != v4AddrPort {
		t.Fatalf("expected '%s', got '%s'", v4addr.String(), conn.RemoteAddr().String())
	}

	recv := make([]byte, 4)
	_, err = conn.Read(recv)
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		t.Fatalf("bad: %v", recv)
	}

	if _, err := conn.Write([]byte("pong")); err != nil {
		t.Fatalf("err: %v", err)
	}
}
