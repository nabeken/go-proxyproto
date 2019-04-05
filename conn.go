// This file is derived from https://github.com/Freeaqingme/go-proxyproto/blob/d1be3b66fc764cf09c20720916d73bccb394db87/protocol.go
// This file is derived from https://github.com/armon/go-proxyproto/blob/68259f75880e8bcc207a49de82466957646af353/protocol.go
// The MIT License (MIT)
// Copyright (c) 2014 Armon Dadgar

package proxyproto

import (
	"bufio"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var (
	ErrInvalidUpstream = errors.New("proxyproto: upstream connection address not trusted for PROXY information")
)

// SourceChecker can be used to decide whether to trust the PROXY info or pass
// the original connection address through. If set, the connecting address is
// passed in as an argument. If the function returns an error due to the source
// being disallowed, it should return ErrInvalidUpstream.
//
// If error is not nil, the call to Accept() will fail. If the reason for
// triggering this failure is due to a disallowed source, it should return
// ErrInvalidUpstream.
//
// If bool is true, the PROXY-set address is used.
//
// If bool is false, the connection's remote address is used, rather than the
// address claimed in the PROXY info.
type SourceChecker func(net.Addr) (bool, error)

// Listener is used to wrap an underlying listener,
// whose connections may be using the HAProxy Proxy Protocol (version 1).
// If the connection is using the protocol, the RemoteAddr() will return
// the correct client address.
//
// Optionally define ProxyHeaderTimeout to set a maximum time to
// receive the Proxy Protocol Header. Zero means no timeout.
type Listener struct {
	Listener           net.Listener
	ProxyHeaderTimeout time.Duration
	SourceCheck        SourceChecker
}

// Conn is used to wrap and underlying connection which
// may be speaking the Proxy Protocol. If it is, the RemoteAddr() will
// return the address of the client instead of the proxy address.
type Conn struct {
	br   *bufio.Reader
	conn net.Conn

	header *Header

	useConnAddr        bool
	once               sync.Once
	proxyHeaderTimeout time.Duration
}

// Accept waits for and returns the next connection to the listener.
func (p *Listener) Accept() (net.Conn, error) {
	// Get the underlying connection
	conn, err := p.Listener.Accept()
	if err != nil {
		return nil, err
	}
	var useConnAddr bool
	if p.SourceCheck != nil {
		allowed, err := p.SourceCheck(conn.RemoteAddr())
		if err != nil {
			return nil, err
		}
		if !allowed {
			useConnAddr = true
		}
	}
	newConn := NewConn(conn, p.ProxyHeaderTimeout)
	newConn.useConnAddr = useConnAddr
	return newConn, nil
}

// Close closes the underlying listener.
func (p *Listener) Close() error {
	return p.Listener.Close()
}

// Addr returns the underlying listener's network address.
func (p *Listener) Addr() net.Addr {
	return p.Listener.Addr()
}

// NewConn is used to wrap a net.Conn that may be speaking
// the proxy protocol into a proxyproto.Conn
func NewConn(conn net.Conn, timeout time.Duration) *Conn {
	pConn := &Conn{
		br:                 bufio.NewReader(conn),
		conn:               conn,
		proxyHeaderTimeout: timeout,
	}
	return pConn
}

// Read is check for the proxy protocol header when doing
// the initial scan. If there is an error parsing the header,
// it is returned and the socket is closed.
func (p *Conn) Read(b []byte) (int, error) {
	var err error
	p.once.Do(func() { err = p.readHeader() })
	if err != nil {
		return 0, err
	}
	return p.br.Read(b)
}

func (p *Conn) Write(b []byte) (int, error) {
	return p.conn.Write(b)
}

func (p *Conn) Close() error {
	return p.conn.Close()
}

func (p *Conn) LocalAddr() net.Addr {
	p.readHeaderOnce()
	if isInvalidHeaderAddr(p.header.LocalAddr()) || p.useConnAddr {
		return p.conn.LocalAddr()
	}
	return p.header.LocalAddr()
}

// RemoteAddr returns the address of the client if the proxy
// protocol is being used, otherwise just returns the address of
// the socket peer. If there is an error parsing the header, the
// address of the client is not returned, and the socket is closed.
// Once implication of this is that the call could block if the
// client is slow. Using a Deadline is recommended if this is called
// before Read()
func (p *Conn) RemoteAddr() net.Addr {
	p.readHeaderOnce()
	if isInvalidHeaderAddr(p.header.RemoteAddr()) || p.useConnAddr {
		return p.conn.RemoteAddr()
	}
	return p.header.RemoteAddr()
}

func (p *Conn) SetDeadline(t time.Time) error {
	return p.conn.SetDeadline(t)
}

func (p *Conn) SetReadDeadline(t time.Time) error {
	return p.conn.SetReadDeadline(t)
}

func (p *Conn) SetWriteDeadline(t time.Time) error {
	return p.conn.SetWriteDeadline(t)
}

func (p *Conn) readHeaderOnce() {
	p.once.Do(func() {
		if err := p.readHeader(); err != nil && err != io.EOF {
			log.Printf("[ERR] Failed to read proxy prefix: %v", err)
			p.Close()
			p.br = bufio.NewReader(p.conn)
		}
	})
}

func (p *Conn) readHeader() error {
	if p.proxyHeaderTimeout != 0 {
		readDeadLine := time.Now().Add(p.proxyHeaderTimeout)
		p.conn.SetReadDeadline(readDeadLine)
		defer p.conn.SetReadDeadline(time.Time{})
	}

	var err error
	p.header, err = Read(p.br)
	if err != nil && err != ErrNoProxyProtocol {
		// if there is not proxy protocol signature, it should work as if  no proxy protocol
		return err
	}

	return nil
}

func isInvalidHeaderAddr(addr net.Addr) bool {
	if addr_, ok := addr.(*net.IPAddr); ok && addr_.IP == nil {
		return true
	}
	return false
}
