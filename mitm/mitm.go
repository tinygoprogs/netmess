package mitm

import (
	"context"
	"net"
)

type Hooks interface {
	// l: server, talks to client(s)
	// r: client, talks to the server
	// hooks for l -> r and r -> l communication
	// +default impl for just io.Copy(l, r) io.Copy(r, l)
	// +default implfor hex dump to console
	//io.Reader
}

type Mitm interface {
	// in a client-server protocol lhost should be the client, rhost the server
	Mitm(ctx context.Context, lhost, rhost net.Conn) error
}
