package proxies

import (
	"net"
	"os"
)

type connection interface {
	RemoteAddr() net.Addr
	File() (*os.File, error)
}

type hybridConn interface {
	net.Conn

	GetTls() bool
}
