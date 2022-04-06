# goxchange
Easy ECIES implementation in go (Elliptic Curve Integrated Encryption Scheme)

## How it works

It uses Diffie-Hellman to share Elliptic curve public keys between two parties, then calculate the shared secret and proceed to communicate using symmetric encryption (chacha20 + poly1305)

It also provide an utility to wrap a standard net.Conn in order to automagically perform handshake and create a secure channel.