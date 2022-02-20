package proxies

import (
	"fmt"
	"net"
	"reflect"
	"syscall"

	"github.com/Rasek91/Packet-Manipulator-Proxy/logging"
	"github.com/Rasek91/udp"

	conntrack "github.com/florianl/go-conntrack"
)

const (
	SO_ORIGINAL_DST = 80
)

func getOriginalIpTuple(connectionTracker *conntrack.Nfct, rawConnection connection) (originalIPTuple *logging.IPTuple, err error) {
	var destinationIp net.IP
	var sourceIp net.IP
	var protocolNumber uint8
	var destinationPort uint16
	var sourcePort uint16

	switch connection := rawConnection.(type) {
	case *net.TCPConn:
		protocolNumber = 6
		remoteAddress := connection.RemoteAddr().(*net.TCPAddr)

		if remoteAddress == nil {
			logging.Log("error", map[string]interface{}{"function": "getOriginalIpTuple", "socket": connection}, "RemoteAddr error")
			err = logging.RemoteAddr
			return
		}

		sourceIp = remoteAddress.IP
		sourcePort = uint16(remoteAddress.Port)
		connectionFile, errFile := connection.File()

		if errFile != nil {
			logging.Log("error", map[string]interface{}{"function": "getOriginalIpTuple", "socket": connection}, "File error ", errFile)
			err = errFile
			return
		}

		if remoteAddress.IP.To4() != nil {
			address, errGetSockOpt := syscall.GetsockoptIPv6Mreq(int(connectionFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)

			if errGetSockOpt != nil {
				logging.Log("warning", map[string]interface{}{"function": "getOriginalIpTuple", "socket": connection}, "Getsockopt error ", errGetSockOpt)
				originalIPTuple, err = getOriginalIpTupleConnectionTracker(connectionTracker, remoteAddress)
				return
			}

			destinationIp = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", address.Multiaddr[4], address.Multiaddr[5], address.Multiaddr[6], address.Multiaddr[7]))
			destinationPort = uint16(address.Multiaddr[2])<<8 + uint16(address.Multiaddr[3])
		} else {
			address, errGetSockOpt := syscall.GetsockoptIPv6Mreq(int(connectionFile.Fd()), syscall.IPPROTO_IPV6, SO_ORIGINAL_DST)

			if errGetSockOpt != nil {
				logging.Log("warning", map[string]interface{}{"function": "getOriginalIpTuple", "socket": connection}, "Getsockopt error ", errGetSockOpt)
				originalIPTuple, err = getOriginalIpTupleConnectionTracker(connectionTracker, remoteAddress)
				return
			}

			destinationIp = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", address.Multiaddr[4], address.Multiaddr[5], address.Multiaddr[6], address.Multiaddr[7]))
			destinationPort = uint16(address.Multiaddr[2])<<8 + uint16(address.Multiaddr[3])
		}
	case *udp.Conn:
		protocolNumber = 17
		remoteAddress := connection.RemoteAddr().(*net.UDPAddr)

		if remoteAddress == nil {
			logging.Log("error", map[string]interface{}{"function": "getOriginalIpTuple", "socket": connection}, "RemoteAddr error")
			err = logging.RemoteAddr
			return
		}

		sourceIp = remoteAddress.IP
		sourcePort = uint16(remoteAddress.Port)
		connectionFile, errFile := connection.File()

		if errFile != nil {
			logging.Log("error", map[string]interface{}{"function": "getOriginalIpTuple", "socket": connection}, "File error ", errFile)
			err = errFile
			return
		}

		if remoteAddress.IP.To4() != nil {
			address, errGetSockOpt := syscall.GetsockoptIPv6Mreq(int(connectionFile.Fd()), syscall.IPPROTO_IP, SO_ORIGINAL_DST)

			if errGetSockOpt != nil {
				logging.Log("warning", map[string]interface{}{"function": "getOriginalIpTuple", "socket": connection}, "Getsockopt error ", errGetSockOpt)
				originalIPTuple, err = getOriginalIpTupleConnectionTracker(connectionTracker, remoteAddress)
				return
			}

			destinationIp = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", address.Multiaddr[4], address.Multiaddr[5], address.Multiaddr[6], address.Multiaddr[7]))
			destinationPort = uint16(address.Multiaddr[2])<<8 + uint16(address.Multiaddr[3])
		} else {
			address, errGetSockOpt := syscall.GetsockoptIPv6Mreq(int(connectionFile.Fd()), syscall.IPPROTO_IPV6, SO_ORIGINAL_DST)

			if errGetSockOpt != nil {
				logging.Log("warning", map[string]interface{}{"function": "getOriginalIpTuple", "socket": connection}, "Getsockopt error ", errGetSockOpt)
				originalIPTuple, err = getOriginalIpTupleConnectionTracker(connectionTracker, remoteAddress)
				return
			}

			destinationIp = net.ParseIP(fmt.Sprintf("%d.%d.%d.%d", address.Multiaddr[4], address.Multiaddr[5], address.Multiaddr[6], address.Multiaddr[7]))
			destinationPort = uint16(address.Multiaddr[2])<<8 + uint16(address.Multiaddr[3])
		}

		originalIPTuple, err = getOriginalIpTupleConnectionTracker(connectionTracker, remoteAddress)
		return
	}

	originalIPTuple, err = &logging.IPTuple{Src: &sourceIp, Dst: &destinationIp, Proto: &conntrack.ProtoTuple{Number: &protocolNumber, SrcPort: &sourcePort, DstPort: &destinationPort}}, nil
	logging.Log("trace", map[string]interface{}{"function": "getOriginalIpTuple", "socket": rawConnection, "ipTuple": originalIPTuple})
	return
}

func getOriginalIpTupleConnectionTracker(connectionTracker *conntrack.Nfct, rawAddress net.Addr) (originalIPTuple *logging.IPTuple, err error) {
	var connections []conntrack.Con = nil
	var errConnTracker error = nil

	switch address := rawAddress.(type) {
	case *net.TCPAddr:
		if address.IP.To4() != nil {
			connections, errConnTracker = connectionTracker.Dump(conntrack.Conntrack, conntrack.IPv4)
		} else {
			connections, errConnTracker = connectionTracker.Dump(conntrack.Conntrack, conntrack.IPv6)
		}

		if errConnTracker != nil {
			logging.Log("error", map[string]interface{}{"function": "getOriginalIpTupleConnectionTracker", "socket": address}, "Dump error ", errConnTracker)
			err = errConnTracker
			return
		}

		for _, connection := range connections {
			if reflect.DeepEqual(*connection.Origin.Src, address.IP) && *connection.Origin.Proto.SrcPort == uint16(address.Port) && *connection.Origin.Proto.Number == uint8(6) {
				originalIPTuple, err = (*logging.IPTuple)(connection.Origin), nil
				logging.Log("trace", map[string]interface{}{"function": "getOriginalIpTupleConnectionTracker", "socket": address, "ipTuple": originalIPTuple})
				return
			}
		}
	case *net.UDPAddr:
		if address.IP.To4() != nil {
			connections, errConnTracker = connectionTracker.Dump(conntrack.Conntrack, conntrack.IPv4)
		} else {
			connections, errConnTracker = connectionTracker.Dump(conntrack.Conntrack, conntrack.IPv6)
		}

		if errConnTracker != nil {
			logging.Log("error", map[string]interface{}{"function": "getOriginalIpTupleConnectionTracker", "socket": address}, "Dump error ", errConnTracker)
			err = errConnTracker
			return
		}

		for _, connection := range connections {
			if reflect.DeepEqual(*connection.Origin.Src, address.IP) && *connection.Origin.Proto.SrcPort == uint16(address.Port) && *connection.Origin.Proto.Number == uint8(17) {
				originalIPTuple, err = (*logging.IPTuple)(connection.Origin), nil
				logging.Log("trace", map[string]interface{}{"function": "getOriginalIpTupleConnectionTracker", "socket": address, "ipTuple": originalIPTuple})
				return
			}
		}
	}

	logging.Log("fatal", map[string]interface{}{"function": "getOriginalIpTupleConnectionTracker"}, "Connection not found error")
	err = logging.ConnectionNotFound
	return
}
