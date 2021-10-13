package main

import (
	"net"
	"strconv"

	conntrack "github.com/florianl/go-conntrack"
	log "github.com/sirupsen/logrus"
)

func handle_packet_udp(original_ip_tuple *conntrack.IPTuple, connection *net.UDPConn, address *net.UDPAddr, buffer []byte) {
	log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(original_ip_tuple), "data": string(buffer)}).Debug("handle_packet_udp received from client")
	to_original <- Data{Ip_tuple: original_ip_tuple, Data: buffer}

	for {
		_, in := to_destination[original_ip_tuple]

		if in {
			answer := read_and_delete_data(original_ip_tuple)
			log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(original_ip_tuple), "data": string(answer)}).Debug("handle_packet_udp received from server")

			if answer != nil {
				connection.WriteTo(answer, address)
			}

			break
		}
	}
}

func listen_udp(ip_address, port string) error {
	port_int64, _ := strconv.ParseInt(port, 0, 64)
	port_int := int(port_int64)
	connection, error := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP(ip_address), Port: port_int})

	if error != nil {
		log.Error("ListenUDP error ", error)
		return error
	}

	connection_tracker, error := conntrack.Open(&conntrack.Config{})

	if error != nil {
		log.Error("Open error")
		return error
	}

	log.Info("listen_udp", ip_address)
	defer connection_tracker.Close()
	defer log.Info("close UDP ", ip_address)
	defer connection.Close()

	for {
		buffer := make([]byte, 1024*4)
		length, address, error := connection.ReadFromUDP(buffer)

		if error != nil {
			log.Error("error in read from UDP ", error)
			return error
		}

		original_ip_tuple, error := get_original_ip_tuple(connection_tracker, connection, address)

		if error != nil {
			log.Panic("Get original IP tuple error ", error)
		}

		go handle_packet_udp(original_ip_tuple, connection, address, buffer[:length])
	}
}
