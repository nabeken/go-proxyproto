# go-proxyproto

[![Build Status](https://travis-ci.org/nabeken/go-proxyproto.svg?branch=master)](https://travis-ci.org/nabeken/go-proxyproto)

A Go library implementation of the [PROXY protocol, versions 1 and 2](http://www.haproxy.org/download/1.8/doc/proxy-protocol.txt),
which provides, as per specification:
> (...) a convenient way to safely transport connection
> information such as a client's address across multiple layers of NAT or TCP
> proxies. It is designed to require little changes to existing components and
> to limit the performance impact caused by the processing of the transported
> information.

## Installation

```shell
$ go get -u github.com/pires/go-proxyproto
```

## Usage

### Server

Listen and upgrade the listener to the proxy-protocol aware listener:
```go
ln, _ := net.Listen("tcp", "127.0.0.1:0")
pl: &Listener{
        Listener:           ln,
        ProxyHeaderTimeout: 3 * time.Minute,
}

conn, _ := s.pl.Accept()
log.Printf("accepted connection from %s to %s", conn.RemoteAddr().String(), conn.LocalAddr().String())
```

### Client

As of today, this library doesn't provide a dialer so you need to write a proxy protocol header by yourself:
```go
conn, _ := net.Dial("tcp", "127.0.0.1:12345")
hdr := &Header{
        Version:           1,
        Command:           PROXY,
        TransportProtocol: TCPv4,
        SrcAddr:           v4addr,
        DstAddr:           v4addr,
        SrcPort:           PORT,
        DstPort:           PORT,
}

// Write proxy protocol header to conn
hdr.WriteTo(conn)
```

## Documentation

[http://godoc.org/github.com/nabeken/go-proxyproto](http://godoc.org/github.com/nabeken/go-proxyproto)

## Acknowledgement

This implemention is heavily based on https://github.com/pires/go-proxyproto and the its WIP pull request at https://github.com/pires/go-proxyproto/pull/2 which is derived from https://github.com/armon/go-proxyproto/blob/master/protocol.go.

My fork removed several incomplete implementations (e.g. timeout handling, UNIX socket support and TLV support).
