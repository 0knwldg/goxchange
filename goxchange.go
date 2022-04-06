package goxchange

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/lunixbochs/struc"
)

type packet struct {
	Length int `struc:"uint32,sizeof=Data"`
	Data   []byte
}

func (p *packet) Encode() ([]byte, error) {
	var data bytes.Buffer
	if err := struc.Pack(&data, p); err != nil {
		return nil, err
	}
	return data.Bytes(), nil
}

type secureDiffieHellmanChannel struct {
	net.Conn
	*PrivateKey
	secret     []byte
	handshaked bool
}

func (c *secureDiffieHellmanChannel) Read(p []byte) (n int, err error) {
	n, err = c.Conn.Read(p)
	if err != nil {
		return n, err
	}
	dec, err := Decrypt(p[:n], c.secret)
	if err != nil {
		return n, err
	}
	dec = append(dec, bytes.Repeat([]byte{0}, n-len(dec))...)
	copy(p, dec)
	return n, nil
}

func (c *secureDiffieHellmanChannel) Write(p []byte) (n int, err error) {
	enc, err := Encrypt(p, c.secret)
	if err != nil {
		return 0, err
	}
	return c.Conn.Write(enc)
}

func (c *secureDiffieHellmanChannel) Close() error {
	return c.Conn.Close()
}

func (c *secureDiffieHellmanChannel) LocalAddr() net.Addr {
	return c.Conn.LocalAddr()
}

func (c *secureDiffieHellmanChannel) RemoteAddr() net.Addr {
	return c.Conn.RemoteAddr()
}

func (c *secureDiffieHellmanChannel) SetDeadline(t time.Time) error {
	return c.Conn.SetDeadline(t)
}

func (c *secureDiffieHellmanChannel) SetReadDeadline(t time.Time) error {
	return c.Conn.SetReadDeadline(t)
}

func (c *secureDiffieHellmanChannel) SetWriteDeadline(t time.Time) error {
	return c.Conn.SetWriteDeadline(t)
}

func (c *secureDiffieHellmanChannel) readPacket() (packet, error) {
	var size []byte = make([]byte, 4)
	if _, err := c.Conn.Read(size); err != nil {
		return packet{}, err
	}
	totalSize := binary.BigEndian.Uint32(size)
	var content []byte = make([]byte, totalSize)
	if _, err := c.Conn.Read(content); err != nil {
		return packet{}, err
	}
	return packet{int(totalSize), content}, nil
}

func (c *secureDiffieHellmanChannel) writePacket(p *packet) error {
	data, err := p.Encode()
	if err != nil {
		return err
	}
	_, err = c.Conn.Write(data)
	return err
}

func (c *secureDiffieHellmanChannel) Handshake() bool {
	pub := c.MarshalPublic()
	if err := c.writePacket(&packet{len(pub), pub}); err == nil {
		if p, err := c.readPacket(); err == nil {
			if p.Length == 64 {
				pub := c.UnmarshalPublic(p.Data)
				c.secret = c.sharedSecret(pub)
				c.handshaked = true
			}
		}
	}
	return c.handshaked
}

func (c *secureDiffieHellmanChannel) IsSecure() bool {
	return c.handshaked
}

func WrapConn(c net.Conn) net.Conn {
	channel := &secureDiffieHellmanChannel{c, newKey(), nil, false}
	if channel.Handshake() {
		return channel
	}
	return c
}
