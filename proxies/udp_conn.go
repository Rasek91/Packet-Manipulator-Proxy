package proxies

import (
	"net"
	"time"

	"github.com/pion/transport/packetio"
)

type Conn struct {
	connection net.Conn
	buffer     *packetio.Buffer
	read_error error
	closed     bool
}

func (connection *Conn) read() {
	for !connection.closed {
		buffer := make([]byte, 1024*4)
		length, error := connection.connection.Read(buffer)

		if error != nil {
			connection.read_error = error
		} else {
			connection.buffer.Write(buffer[:length])
		}
	}
}

func (connection *Conn) Read(buffer []byte) (int, error) {
	length, error := connection.buffer.Read(buffer)

	if connection.read_error != nil {
		return length, connection.read_error
	}

	if error != nil {
		return length, error
	}

	return length, error
}

func (connection *Conn) Write(buffer []byte) (int, error) {
	return connection.connection.Write(buffer)
}

func (connection *Conn) Close() error {
	connection.closed = true
	return connection.connection.Close()
}

func (connection *Conn) LocalAddr() net.Addr {
	return connection.connection.LocalAddr()
}

func (connection *Conn) RemoteAddr() net.Addr {
	return connection.connection.RemoteAddr()
}

func (connection *Conn) SetDeadline(time time.Time) error {
	error_read := connection.buffer.SetReadDeadline(time)
	error_write := connection.connection.SetWriteDeadline(time)

	if error_read != nil {
		return error_read
	} else if error_write != nil {
		return error_write
	}

	return nil
}

func (connection *Conn) SetReadDeadline(time time.Time) error {
	return connection.buffer.SetReadDeadline(time)
}

func (connection *Conn) SetWriteDeadline(time time.Time) error {
	return connection.connection.SetWriteDeadline(time)
}

func create_conn(raw_connection net.Conn) *Conn {
	connection := &Conn{connection: raw_connection, buffer: packetio.NewBuffer(), closed: false}
	go connection.read()

	return connection
}
