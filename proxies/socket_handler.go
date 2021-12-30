package proxies

import (
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	conntrack "github.com/florianl/go-conntrack"
	log "github.com/sirupsen/logrus"
)

var to_original = make(chan Data)
var sockets = make(map[*conntrack.IPTuple]*Socket)
var data_lock = sync.RWMutex{}
var socket_lock = sync.RWMutex{}
var to_destination = make(map[*conntrack.IPTuple][]byte)

type Data struct {
	Ip_tuple *conntrack.IPTuple
	Data     []byte
	TLS      bool
}

type Socket struct {
	Connection net.Conn
	Lock       *sync.RWMutex
	TLS        bool
}

func read_and_delete_data(ip_tuple *conntrack.IPTuple) (data []byte) {
	data_lock.Lock()
	defer data_lock.Unlock()
	data = to_destination[ip_tuple]

	if data != nil {
		delete(to_destination, ip_tuple)
		log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "data": string(data)}).Trace("read and delete data")
	}

	return
}

func add_data(ip_tuple *conntrack.IPTuple, data []byte) {
	data_lock.Lock()
	defer data_lock.Unlock()

	if to_destination[ip_tuple] != nil {
		original_data := to_destination[ip_tuple]
		buffer := append(original_data, data...)
		to_destination[ip_tuple] = buffer
		log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "data": string(buffer)}).Trace("data append to")
	} else {
		buffer := make([]byte, len(data))
		copy(buffer, data)
		to_destination[ip_tuple] = buffer
		log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "data": string(buffer)}).Trace("data added")
	}
}

func add_socket(ip_tuple *conntrack.IPTuple, socket net.Conn, tls bool) {
	socket_lock.Lock()
	defer socket_lock.Unlock()
	original_socket, in := sockets[ip_tuple]

	if in {
		sockets[ip_tuple] = &Socket{Connection: socket, Lock: original_socket.Lock, TLS: tls}
	} else {
		sockets[ip_tuple] = &Socket{Connection: socket, Lock: &sync.RWMutex{}, TLS: tls}
	}

	log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": sockets[ip_tuple]}).Trace("add socket")
}

func read_socket(ip_tuple *conntrack.IPTuple) (socket *Socket) {
	socket_lock.RLock()
	defer socket_lock.RUnlock()
	socket = sockets[ip_tuple]

	return
}

func delete_socket(ip_tuple *conntrack.IPTuple) {
	socket_lock.Lock()
	defer socket_lock.Unlock()

	if sockets[ip_tuple] != nil {
		socket := sockets[ip_tuple]
		log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": sockets[ip_tuple]}).Trace("delete socket")
		delete(sockets, ip_tuple)
		log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": sockets[ip_tuple]}).Trace("close socket")
		socket.Connection.Close()
	}
}

func create_socket(ip_tuple *conntrack.IPTuple) (net.Conn, error) {
	if *ip_tuple.Proto.Number == uint8(6) {
		if ip_tuple.Dst.To4() != nil {
			return net.Dial("tcp", fmt.Sprintf("%v:%d", ip_tuple.Dst.String(), *ip_tuple.Proto.DstPort))
		} else {
			return net.Dial("tcp", fmt.Sprintf("[%v]:%d", ip_tuple.Dst.String(), *ip_tuple.Proto.DstPort))
		}
	} else if *ip_tuple.Proto.Number == uint8(17) {
		if ip_tuple.Dst.To4() != nil {
			connection, error := net.Dial("udp", fmt.Sprintf("%v:%d", ip_tuple.Dst.String(), *ip_tuple.Proto.DstPort))

			if error != nil {
				return connection, error
			} else {
				return create_conn(connection), error
			}
		} else {
			connection, error := net.Dial("udp", fmt.Sprintf("[%v]:%d", ip_tuple.Dst.String(), *ip_tuple.Proto.DstPort))

			if error != nil {
				return connection, error
			} else {
				return create_conn(connection), error
			}
		}
	}

	log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple)}).Fatal("Ip protocol number not recognized ", *ip_tuple.Proto.Number)
	return nil, nil
}

func write_data_to_original_destination(socket *Socket, data Data) {
	if data.TLS && !socket.TLS {
		error := add_tls_to_socket(data.Ip_tuple)

		if error != nil {
			log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(data.Ip_tuple)}).Warn("Error add TLS write ", error)
			return
		}

		socket = read_socket(data.Ip_tuple)

		if *data.Ip_tuple.Proto.Number == uint8(17) {
			go read_data_from_original_destination(socket, data.Ip_tuple)
		}
	}

	socket.Lock.Lock()
	_, error := socket.Connection.Write(data.Data)
	socket.Lock.Unlock()

	if error != nil {
		log.WithFields(log.Fields{"socket": socket}).Error("error write to original destination ", error)
	}

	log.WithFields(log.Fields{"socket": socket, "data": string(data.Data)}).Trace("write_data_from_original_destination sent to server")
}

func read_data_from_original_destination(socket *Socket, original_ip_tuple *conntrack.IPTuple) {
	defer delete_socket(original_ip_tuple)
	buffer := make([]byte, 1024*4)

	for {
		socket.Lock.Lock()
		socket_now := read_socket(original_ip_tuple)

		if socket_now == nil {
			break
		} else {
			if socket_now.TLS && !socket.TLS {
				socket = socket_now
			}

			error := socket.Connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

			if error != nil {
				log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(original_ip_tuple)}).Error("Error set read deadline ", error, socket_now.Connection)
				break
			}

			length, error := socket.Connection.Read(buffer)
			socket.Lock.Unlock()

			if error != nil && error != io.EOF && !os.IsTimeout(error) {
				log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(original_ip_tuple)}).Warn("Error read data ", error, socket_now.Connection)
				break
			}

			if length != 0 {
				log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(original_ip_tuple), "data": string(buffer[:length])}).Trace("read_data_from_original_destination received from server")
				add_data(original_ip_tuple, buffer[:length])
			}

			if error == io.EOF {
				break
			}

			time.Sleep(100 * time.Millisecond)
		}
	}
}

func Copy_data_to_original_destination() {
	for {
		select {
		case data_with_destination := <-to_original:
			socket := read_socket(data_with_destination.Ip_tuple)

			if socket == nil {
				connection, error := create_socket(data_with_destination.Ip_tuple)
				log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(data_with_destination.Ip_tuple), "socket": socket}).Trace("create socket")

				if error != nil {
					log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(data_with_destination.Ip_tuple), "socket": socket}).Error("Error with socket open ", error)
					return
				}

				add_socket(data_with_destination.Ip_tuple, connection, data_with_destination.TLS)
				socket = read_socket(data_with_destination.Ip_tuple)

				go read_data_from_original_destination(socket, data_with_destination.Ip_tuple)
			}

			if data_with_destination.Data != nil {
				go write_data_to_original_destination(socket, data_with_destination)
			}
		}
	}
}
