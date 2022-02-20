package proxies

import (
	"net"
	"time"

	"github.com/pion/transport/packetio"
)

type Conn struct {
	connection net.Conn
	buffer     *packetio.Buffer
	readErr    error
	closed     bool
}

func (connection *Conn) read() {
	for !connection.closed {
		buffer := make([]byte, 1024*4)
		length, err := connection.connection.Read(buffer)

		if err != nil {
			connection.readErr = err
		} else {
			connection.buffer.Write(buffer[:length])
		}
	}
}

func (connection *Conn) Read(buffer []byte) (length int, err error) {
	length, err = connection.buffer.Read(buffer)

	if connection.readErr != nil {
		err = connection.readErr
		return
	}

	return
}

func (connection *Conn) Write(buffer []byte) (length int, err error) {
	length, err = connection.connection.Write(buffer)
	return
}

func (connection *Conn) Close() (err error) {
	connection.closed = true
	err = connection.connection.Close()
	return
}

func (connection *Conn) LocalAddr() (address net.Addr) {
	address = connection.connection.LocalAddr()
	return
}

func (connection *Conn) RemoteAddr() (address net.Addr) {
	address = connection.connection.RemoteAddr()
	return
}

func (connection *Conn) SetDeadline(time time.Time) (err error) {
	errRead := connection.buffer.SetReadDeadline(time)
	errWrite := connection.connection.SetWriteDeadline(time)

	if errRead != nil {
		err = errRead
		return
	} else if errWrite != nil {
		err = errWrite
		return
	}

	return
}

func (connection *Conn) SetReadDeadline(time time.Time) (err error) {
	err = connection.buffer.SetReadDeadline(time)
	return
}

func (connection *Conn) SetWriteDeadline(time time.Time) (err error) {
	err = connection.connection.SetWriteDeadline(time)
	return
}

func New(rawConnection net.Conn) (connection *Conn) {
	connection = &Conn{connection: rawConnection, buffer: packetio.NewBuffer(), closed: false}
	go connection.read()

	return
}
