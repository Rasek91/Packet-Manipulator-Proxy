package proxies

import (
	"errors"
	"fmt"
	"net"
	"reflect"
	"syscall"

	conntrack "github.com/florianl/go-conntrack"
	log "github.com/sirupsen/logrus"
)

const SO_ORIGINAL_DST = 80

func get_original_ip_tuple(connection_tracker *conntrack.Nfct, raw_connection net.Conn, udp_address *net.UDPAddr) (*conntrack.IPTuple, error) {
	var destination_ip net.IP
	var source_ip net.IP
	var protocol_number uint8
	var destination_port uint16
	var source_port uint16

	if udp_address == nil {
		protocol_number = 6
		connection := raw_connection.(*net.TCPConn)
		remote_address := connection.RemoteAddr().(*net.TCPAddr)

		if remote_address == nil {
			log.Error("RemoteAddr error")
			return nil, errors.New("RemoteAddr error")
		}

		source_ip = remote_address.IP
		source_port = uint16(remote_address.Port)
		connection_file, error := connection.File()

		if error != nil {
			log.Error("File error ", error)
			return nil, error
		}

		if remote_address.IP.To4() != nil {
			address, error := syscall.GetsockoptIPv6Mreq(int(connection_file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)

			if error != nil {
				log.Warn("Getsockopt error ", error)
				return get_original_ip_tuple_connection_tracker(connection_tracker, remote_address, nil)
			}

			destination_ip = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", address.Multiaddr[4], address.Multiaddr[5], address.Multiaddr[6], address.Multiaddr[7]))
			destination_port = uint16(address.Multiaddr[2])<<8 + uint16(address.Multiaddr[3])
		} else {
			address, error := syscall.GetsockoptIPv6Mreq(int(connection_file.Fd()), syscall.IPPROTO_IPV6, SO_ORIGINAL_DST)

			if error != nil {
				log.Warn("Getsockopt error ", error)
				return get_original_ip_tuple_connection_tracker(connection_tracker, remote_address, nil)
			}

			destination_ip = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", address.Multiaddr[4], address.Multiaddr[5], address.Multiaddr[6], address.Multiaddr[7]))
			destination_port = uint16(address.Multiaddr[2])<<8 + uint16(address.Multiaddr[3])
		}
	} else {
		protocol_number = 17
		//connection := raw_connection.(*udp.Conn)
		source_ip = udp_address.IP
		source_port = uint16(udp_address.Port)
		/*connection_file, error := connection.File()

		if error != nil {
			log.Error("File error ", error)
			return nil, error
		}

		if udp_address.IP.To4() != nil {
			address, error := syscall.GetsockoptIPv6Mreq(int(connection_file.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)

			if error != nil {
				log.Warn("Getsockopt error ", error)
				return get_original_ip_tuple_connection_tracker(connection_tracker, nil, udp_address)
			}

			destination_ip = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", address.Multiaddr[4], address.Multiaddr[5], address.Multiaddr[6], address.Multiaddr[7]))
			destination_port = uint16(address.Multiaddr[2])<<8 + uint16(address.Multiaddr[3])
		} else {
			address, error := syscall.GetsockoptIPv6Mreq(int(connection_file.Fd()), syscall.IPPROTO_IPV6, SO_ORIGINAL_DST)

			if error != nil {
				log.Warn("Getsockopt error ", error)
				return get_original_ip_tuple_connection_tracker(connection_tracker, nil, udp_address)
			}

			destination_ip = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", address.Multiaddr[4], address.Multiaddr[5], address.Multiaddr[6], address.Multiaddr[7]))
			destination_port = uint16(address.Multiaddr[2])<<8 + uint16(address.Multiaddr[3])
		}*/

		return get_original_ip_tuple_connection_tracker(connection_tracker, nil, udp_address)
	}

	return &conntrack.IPTuple{Src: &source_ip, Dst: &destination_ip, Proto: &conntrack.ProtoTuple{Number: &protocol_number, SrcPort: &source_port, DstPort: &destination_port}}, nil
}

func get_original_ip_tuple_connection_tracker(connection_tracker *conntrack.Nfct, tcp_address *net.TCPAddr, udp_address *net.UDPAddr) (*conntrack.IPTuple, error) {
	var connections []conntrack.Con = nil
	var error error = nil

	if tcp_address != nil {
		if tcp_address.IP.To4() != nil {
			connections, error = connection_tracker.Dump(conntrack.Conntrack, conntrack.IPv4)
		} else {
			connections, error = connection_tracker.Dump(conntrack.Conntrack, conntrack.IPv6)
		}

		if error != nil {
			log.Error("Dump error ", error)
			return nil, error
		}

		for _, connection := range connections {
			if reflect.DeepEqual(*connection.Origin.Src, tcp_address.IP) && *connection.Origin.Proto.SrcPort == uint16(tcp_address.Port) && *connection.Origin.Proto.Number == uint8(6) {
				return connection.Origin, nil
			}
		}
	} else if udp_address != nil {
		if udp_address.IP.To4() != nil {
			connections, error = connection_tracker.Dump(conntrack.Conntrack, conntrack.IPv4)
		} else {
			connections, error = connection_tracker.Dump(conntrack.Conntrack, conntrack.IPv6)
		}

		if error != nil {
			log.Error("Dump error ", error)
			return nil, error
		}

		for _, connection := range connections {
			if reflect.DeepEqual(*connection.Origin.Src, udp_address.IP) && *connection.Origin.Proto.SrcPort == uint16(udp_address.Port) && *connection.Origin.Proto.Number == uint8(17) {
				return connection.Origin, nil
			}
		}
	}

	log.Fatal("Connection not found error")
	return nil, errors.New("connection not found")
}
