package proxyproto

import (
	"bytes"
	"io"
	"io/ioutil"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"
)

var (
	testV1Header = &Header{
		Version:           1,
		Command:           PROXY,
		TransportProtocol: TCPv4,
		SrcAddr:           v4addr,
		DstAddr:           v4addr,
		SrcPort:           PORT,
		DstPort:           PORT,
	}
	testV2Header = &Header{
		Version:           2,
		Command:           PROXY,
		TransportProtocol: TCPv6,
		SrcAddr:           v6addr,
		DstAddr:           v6addr,
		SrcPort:           PORT,
		DstPort:           PORT,
	}

	v4AddrPort = v4addr.String() + ":" + strconv.Itoa(PORT)
	v6AddrPort = "[" + v6addr.String() + "]" + ":" + strconv.Itoa(PORT)
)

type TestConns struct {
	ServerConn net.Conn
	ClientConn net.Conn
}

func (conns *TestConns) AssertEqualToOrigin(t *testing.T) {
	if conns.ServerConn.RemoteAddr().String() != conns.ClientConn.LocalAddr().String() {
		t.Errorf(
			"server's remote is '%s' but client's local is '%s'",
			conns.ServerConn.RemoteAddr().String(),
			conns.ClientConn.LocalAddr().String(),
		)
	}
	if conns.ServerConn.LocalAddr().String() != conns.ClientConn.RemoteAddr().String() {
		t.Errorf(
			"server's local is '%s' but client's remote is '%s'",
			conns.ServerConn.LocalAddr().String(),
			conns.ClientConn.RemoteAddr().String(),
		)
	}
}

type TestReadWriteCloser struct {
	Header *Header
	Conn   net.Conn

	once sync.Once
}

func (c *TestReadWriteCloser) Write(p []byte) (int, error) {
	var err error
	c.once.Do(func() {
		_, err = c.Header.WriteTo(c.Conn)
	})
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(p)
}

func (c *TestReadWriteCloser) Read(p []byte) (int, error) {
	var err error
	c.once.Do(func() {
		_, err = c.Header.WriteTo(c.Conn)
	})
	if err != nil {
		return 0, err
	}
	return c.Conn.Read(p)
}

func (c *TestReadWriteCloser) Close() error {
	return c.Conn.Close()
}

type TestServer struct {
	ln net.Listener
	pl *Listener
	t  *testing.T

	conns *TestConns
}

func (s *TestServer) MustAccept() net.Conn {
	conn, err := s.pl.Accept()
	if err != nil {
		s.t.Fatal("err:", err)
	}
	s.conns.ServerConn = conn
	s.t.Logf("accepted connection from %s to %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
	return conn
}

func (s *TestServer) WaitConnClosed(conn net.Conn) {
	io.Copy(ioutil.Discard, conn)
}

func (s *TestServer) AssertReadPing(conn net.Conn) {
	recv := make([]byte, 4)
	if _, err := conn.Read(recv); err != nil {
		s.t.Fatal("err:", err)
	}
	if !bytes.Equal(recv, []byte("ping")) {
		s.t.Fatal("bad:", string(recv))
	}
}

func (s *TestServer) AssertWritePong(conn net.Conn) {
	if _, err := conn.Write([]byte("pong")); err != nil {
		s.t.Fatal("err:", err)
	}
}

func (s *TestServer) MustClientConn() net.Conn {
	conn, err := net.Dial("tcp", s.ln.Addr().String())
	if err != nil {
		s.t.Fatal("unexpected error:", err)
	}
	s.conns.ClientConn = conn
	return conn
}

func (s *TestServer) AssertClientReadWrite(rw io.ReadWriter) {
	rw.Write([]byte("ping"))
	recv := make([]byte, 4)
	if _, err := rw.Read(recv); err != nil {
		s.t.Fatal("unexpected error:", err)
	}
	if !bytes.Equal(recv, []byte("pong")) {
		s.t.Fatalf("got: %s", string(recv))
	}
}

func NewTestServer(t *testing.T, timeout time.Duration) *TestServer {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal("unexpected error:", err)
	}
	t.Logf("listening to %s", ln.Addr().String())
	return &TestServer{
		ln: ln,
		pl: &Listener{
			Listener:           ln,
			ProxyHeaderTimeout: timeout,
		},
		t: t,

		conns: &TestConns{},
	}
}

func TestConn_Passthrough(t *testing.T) {
	s := NewTestServer(t, 0)

	go func() {
		conn := s.MustClientConn()
		defer conn.Close()
		s.AssertClientReadWrite(conn)
	}()

	conn := s.MustAccept()
	defer conn.Close()

	s.conns.AssertEqualToOrigin(t)

	s.AssertReadPing(conn)
	s.AssertWritePong(conn)
	s.WaitConnClosed(conn)
}

func TestConn_ProxyProtoV1(t *testing.T) {
	s := NewTestServer(t, 0)

	go func() {
		rwc := &TestReadWriteCloser{
			Header: testV1Header,
			Conn:   s.MustClientConn(),
		}
		defer rwc.Close()
		s.AssertClientReadWrite(rwc)
	}()

	conn := s.MustAccept()
	defer conn.Close()

	assertV4Addr(t, conn)

	s.AssertReadPing(conn)
	s.AssertWritePong(conn)
	s.WaitConnClosed(conn)
}

func TestConn_ProxyProtoV2(t *testing.T) {
	s := NewTestServer(t, 0)

	go func() {
		rwc := &TestReadWriteCloser{
			Header: testV2Header,
			Conn:   s.MustClientConn(),
		}
		defer rwc.Close()
		s.AssertClientReadWrite(rwc)
	}()

	conn := s.MustAccept()
	defer conn.Close()

	assertV6Addr(t, conn)

	s.AssertReadPing(conn)
	s.AssertWritePong(conn)
	s.WaitConnClosed(conn)
}

func TestConn_Invalid(t *testing.T) {
	s := NewTestServer(t, 0)

	for _, b := range [][]byte{
		[]byte("PROXY \r\n"),
		catBytes(SIGV2, invalidBytes),
	} {
		go func() {
			conn := s.MustClientConn()
			if _, err := conn.Write(b); err != nil {
				t.Fatal("unexpected error:", err)
			}
		}()

		conn := s.MustAccept()
		defer conn.Close()

		if _, err := io.Copy(ioutil.Discard, conn); err == nil {
			t.Fatal("connetion must be terminated because the client sent an invalid header")
		}

		s.WaitConnClosed(conn)
	}
}

func TestConn_Timeout(t *testing.T) {
	s := NewTestServer(t, 50*time.Millisecond)

	go func() {
		conn := s.MustClientConn()
		defer conn.Close()
		time.Sleep(200 * time.Millisecond)
		s.AssertClientReadWrite(conn)
	}()

	conn := s.MustAccept()
	defer conn.Close()

	// the connection is timed out so we give up reading the header
	s.conns.AssertEqualToOrigin(t)

	s.AssertReadPing(conn)
	s.AssertWritePong(conn)
	s.WaitConnClosed(conn)
}

func assertV4Addr(t *testing.T, conn net.Conn) {
	if conn.LocalAddr().String() != v4AddrPort {
		t.Fatalf("expected '%s', got '%s'", v4AddrPort, conn.LocalAddr().String())
	}
	if conn.RemoteAddr().String() != v4AddrPort {
		t.Fatalf("expected '%s', got '%s'", v4AddrPort, conn.RemoteAddr().String())
	}
}

func assertV6Addr(t *testing.T, conn net.Conn) {
	if conn.LocalAddr().String() != v6AddrPort {
		t.Fatalf("expected '%s', got '%s'", v6AddrPort, conn.LocalAddr().String())
	}
	if conn.RemoteAddr().String() != v6AddrPort {
		t.Fatalf("expected '%s', got '%s'", v6AddrPort, conn.RemoteAddr().String())
	}
}
