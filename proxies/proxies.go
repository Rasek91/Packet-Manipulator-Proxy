package proxies

import (
	"io"
	"net"
	"strconv"
	"time"

	"github.com/Rasek91/hybrid_tcp_tls_conn"
	"github.com/Rasek91/hybrid_udp_dtls_conn"
	"github.com/pion/udp"

	conntrack "github.com/florianl/go-conntrack"
	log "github.com/sirupsen/logrus"
)

type hybrid_conn interface {
	Read(b []byte) (n int, err error)

	Write(b []byte) (n int, err error)

	Close() error

	LocalAddr() net.Addr

	RemoteAddr() net.Addr

	SetDeadline(t time.Time) error

	SetReadDeadline(t time.Time) error

	SetWriteDeadline(t time.Time) error

	Get_TLS() bool
}

func read_routine(connection net.Conn, buffer []byte, channel_int chan int, channel_error chan error, sync *bool) {
	defer close(channel_int)
	defer close(channel_error)

	for *sync {
		length, error := connection.Read(buffer)
		channel_error <- error
		channel_int <- length
	}
}

func write_routine(original_ip_tuple *conntrack.IPTuple, channel_answer chan []byte, sync *bool) {
	defer close(channel_answer)

	for *sync {
		answer := read_and_delete_data(original_ip_tuple)

		if answer != nil {
			channel_answer <- answer
		}
	}
}

func handle_connection(original_ip_tuple *conntrack.IPTuple, connection hybrid_conn) {
	iterations := 0
	sync := new(bool)
	*sync = true
	channel_error := make(chan error)
	channel_int := make(chan int)
	channel_answer := make(chan []byte)
	defer connection.Close()
	defer delete_socket(original_ip_tuple)
	to_original <- Data{Ip_tuple: original_ip_tuple, Data: nil, TLS: connection.Get_TLS()}
	buffer := make([]byte, 1024*4)
	go read_routine(connection, buffer, channel_int, channel_error, sync)
	go write_routine(original_ip_tuple, channel_answer, sync)

	for iterations < 60 {
		select {
		case error := <-channel_error:
			length := <-channel_int

			if error != nil && error != io.EOF {
				log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(original_ip_tuple)}).Error("read error ", error)
			}

			if length != 0 {
				log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(original_ip_tuple), "data": string(buffer[:length])}).Debug("handle_connection received from client")
				iterations = 0
				to_original <- Data{Ip_tuple: original_ip_tuple, Data: buffer[:length], TLS: connection.Get_TLS()}
			}

			if error == io.EOF {
				iterations = 60
			}
		case answer := <-channel_answer:
			log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(original_ip_tuple), "data": string(answer)}).Debug("handle_connection received from server")
			iterations = 0
			connection.Write(answer)
		case <-time.After(500 * time.Millisecond):
			iterations++
		}
	}

	*sync = false
}

func Listen_tcp(ip_address, port string) error {
	port_int64, _ := strconv.ParseInt(port, 0, 64)
	port_int := int(port_int64)
	listener, error := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(ip_address), Port: port_int})

	if error != nil {
		log.Error("ListenTCP error ", error)
		return error
	}

	connection_tracker, error := conntrack.Open(&conntrack.Config{})

	if error != nil {
		log.Error("Open error ", error)
		return error
	}

	log.Info("listen_tcp ", ip_address)
	defer connection_tracker.Close()
	defer log.Info("close TCP ", ip_address)
	defer listener.Close()

	for {
		connection_raw, error := listener.Accept()

		if error != nil {
			log.Error("Accept error ", error)
			return error
		}

		connection := hybrid_tcp_tls_conn.Create_Conn(connection_raw, Server_tls_config)
		original_ip_tuple, error := get_original_ip_tuple(connection_tracker, connection_raw, nil)

		if error != nil {
			log.Panic("Get original IP tuple error ", error)
		}

		go handle_connection(original_ip_tuple, connection)
	}
}

func Listen_udp(ip_address, port string) error {
	port_int64, _ := strconv.ParseInt(port, 0, 64)
	port_int := int(port_int64)
	listener, error := udp.Listen("udp", &net.UDPAddr{IP: net.ParseIP(ip_address), Port: port_int})

	if error != nil {
		log.Error("ListenUDP error ", error)
		return error
	}

	connection_tracker, error := conntrack.Open(&conntrack.Config{})

	if error != nil {
		log.Error("Open error ", error)
		return error
	}

	log.Info("listen_udp ", ip_address)
	defer connection_tracker.Close()
	defer log.Info("close UDP ", ip_address)
	defer listener.Close()

	for {
		connection_raw, error := listener.Accept()

		if error != nil {
			log.Error("Accept error ", error)
			return error
		}

		connection := hybrid_udp_dtls_conn.Create_Conn(connection_raw, Server_dtls_config)
		original_ip_tuple, error := get_original_ip_tuple(connection_tracker, connection_raw, connection_raw.RemoteAddr().(*net.UDPAddr))

		if error != nil {
			log.Panic("Get original IP tuple error ", error)
		}

		go handle_connection(original_ip_tuple, connection)
	}
}
