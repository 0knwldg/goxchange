package goxchange

import (
	"bytes"
	"net"
	"testing"
)

func TestHandshake(t *testing.T) {
	l, err := net.Listen("tcp", ":1234")
	if err != nil {
		t.Fatalf("Unable to listen: %s", err)
	}
	defer l.Close()
	var clientSecret = make(chan []byte, 1)
	go func(c chan []byte) {
		conn, err := net.Dial("tcp", "127.0.0.1:1234")
		if err == nil {
			defer conn.Close()
			conn = WrapConn(conn)
			if conn.(*secureDiffieHellmanChannel).IsSecure() {
				c <- conn.(*secureDiffieHellmanChannel).secret
			}
			conn.Write([]byte("Hello World"))
		}
	}(clientSecret)
	conn, err := l.Accept()
	if err != nil {
		t.Fatalf("Unable to accept: %s", err)
	}
	defer conn.Close()
	conn = WrapConn(conn)
	if !conn.(*secureDiffieHellmanChannel).IsSecure() {
		t.Fatalf("Handshake failed")
	}
	if bytes.EqualFold(<-clientSecret, conn.(*secureDiffieHellmanChannel).secret) == false {
		t.Fatalf("Shared secret mismatch")
	}
	var data []byte = make([]byte, 1024)
	conn.Read(data)
	if bytes.EqualFold(data[:11], []byte("Hello World")) == false {
		t.Fatalf("Data mismatch")
	}
	conn.Close()
}
