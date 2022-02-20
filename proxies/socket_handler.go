package proxies

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/Rasek91/Packet-Manipulator-Proxy/logging"
	"github.com/pion/dtls"
)

type DataMap struct {
	Map  map[*logging.IPTuple][]byte
	Lock *sync.RWMutex
}

type SocketMap struct {
	Map  map[*logging.IPTuple]*Socket
	Lock *sync.RWMutex
}

type Data struct {
	IPTuple *logging.IPTuple
	Data    []byte
	TLS     bool
}

type Socket struct {
	Connection net.Conn
	Lock       *sync.RWMutex
	TLS        bool
}

func Setup() (toOriginal chan Data, sockets SocketMap, toDestination DataMap, tlsConfig *tls.Config, dtlsConfig *dtls.Config, err error) {
	sockets = SocketMap{Map: make(map[*logging.IPTuple]*Socket), Lock: &sync.RWMutex{}}
	toDestination = DataMap{Map: make(map[*logging.IPTuple][]byte), Lock: &sync.RWMutex{}}
	toOriginal = make(chan Data)

	caCert, caPrivateKey, errCa := CaCertSetup()

	if errCa != nil {
		err = errCa
		logging.Log("error", map[string]interface{}{"function": "Setup"}, "CA certificate error ", errCa)
		return
	}

	tlsConfig, errTls := TlsConfigSetup(caCert, caPrivateKey)

	if errTls != nil {
		err = errTls
		return
	}

	dtlsConfig, errDtls := DtlsConfigSetup(caCert, caPrivateKey)

	if errDtls != nil {
		err = errDtls
		return
	}

	logging.Log("trace", map[string]interface{}{"function": "Setup"}, "Proxies set up")
	return
}

func (dataMap *DataMap) readDeleteData(ipTuple *logging.IPTuple) (data []byte) {
	dataMap.Lock.Lock()
	defer dataMap.Lock.Unlock()
	data = dataMap.Map[ipTuple]

	if data != nil {
		delete(dataMap.Map, ipTuple)
		logging.Log("trace", map[string]interface{}{"function": "readDeleteData", "ipTuple": ipTuple, "data": string(data)}, "Read and delete data")
	}

	return
}

func (dataMap *DataMap) addData(ipTuple *logging.IPTuple, data []byte) {
	dataMap.Lock.Lock()
	defer dataMap.Lock.Unlock()

	if dataMap.Map[ipTuple] != nil {
		originalData := dataMap.Map[ipTuple]
		buffer := append(originalData, data...)
		dataMap.Map[ipTuple] = buffer
		logging.Log("trace", map[string]interface{}{"function": "addData", "ipTuple": ipTuple, "data": string(buffer)}, "Data appended")
	} else {
		buffer := make([]byte, len(data))
		copy(buffer, data)
		dataMap.Map[ipTuple] = buffer
		logging.Log("trace", map[string]interface{}{"function": "addData", "ipTuple": ipTuple, "data": string(buffer)}, "Data added")
	}
}

func (socket *SocketMap) addSocket(ipTuple *logging.IPTuple, connection net.Conn, tls bool) {
	socket.Lock.Lock()
	defer socket.Lock.Unlock()
	originalSocket, in := socket.Map[ipTuple]

	if in {
		socket.Map[ipTuple] = &Socket{Connection: connection, Lock: originalSocket.Lock, TLS: tls}
	} else {
		socket.Map[ipTuple] = &Socket{Connection: connection, Lock: &sync.RWMutex{}, TLS: tls}
	}

	logging.Log("trace", map[string]interface{}{"function": "addSocket", "ipTuple": ipTuple, "socket": socket.Map[ipTuple]}, "Add socket")
}

func (socket *SocketMap) readSocket(ipTuple *logging.IPTuple) (connection *Socket) {
	socket.Lock.RLock()
	defer socket.Lock.RUnlock()
	connection = socket.Map[ipTuple]
	logging.Log("trace", map[string]interface{}{"function": "readSocket", "ipTuple": ipTuple, "socket": socket.Map[ipTuple]}, "Read socket")
	return
}

func (socket *SocketMap) deleteSocket(ipTuple *logging.IPTuple) {
	socket.Lock.Lock()
	defer socket.Lock.Unlock()

	if socket.Map[ipTuple] != nil {
		connection := socket.Map[ipTuple]
		logging.Log("trace", map[string]interface{}{"function": "deleteSocket", "ipTuple": ipTuple, "socket": socket.Map[ipTuple]}, "Delete socket")
		delete(socket.Map, ipTuple)
		logging.Log("trace", map[string]interface{}{"function": "deleteSocket", "ipTuple": ipTuple, "socket": socket.Map[ipTuple]}, "Close socket")
		connection.Connection.Close()
	}
}

func createSocket(ipTuple *logging.IPTuple) (socket net.Conn, err error) {
	if *ipTuple.Proto.Number == uint8(6) {
		if ipTuple.Dst.To4() != nil {
			socket, err = net.Dial("tcp", fmt.Sprintf("%v:%d", ipTuple.Dst.String(), *ipTuple.Proto.DstPort))
			logging.Log("trace", map[string]interface{}{"function": "createSocket", "ipTuple": ipTuple, "socket": socket}, "Create IPv4 TCP socket")
			return
		} else {
			socket, err = net.Dial("tcp", fmt.Sprintf("[%v]:%d", ipTuple.Dst.String(), *ipTuple.Proto.DstPort))
			logging.Log("trace", map[string]interface{}{"function": "createSocket", "ipTuple": ipTuple, "socket": socket}, "Create IPv6 TCP socket")
			return
		}
	} else if *ipTuple.Proto.Number == uint8(17) {
		if ipTuple.Dst.To4() != nil {
			connection, errDial := net.Dial("udp", fmt.Sprintf("%v:%d", ipTuple.Dst.String(), *ipTuple.Proto.DstPort))

			if errDial != nil {
				socket, err = connection, errDial
				return
			} else {
				socket = New(connection)
				logging.Log("trace", map[string]interface{}{"function": "createSocket", "ipTuple": ipTuple, "socket": socket}, "Create IPv4 UDP socket")
				return
			}
		} else {
			connection, errDial := net.Dial("udp", fmt.Sprintf("[%v]:%d", ipTuple.Dst.String(), *ipTuple.Proto.DstPort))

			if errDial != nil {
				socket, err = connection, errDial
				return
			} else {
				socket = New(connection)
				logging.Log("trace", map[string]interface{}{"function": "createSocket", "ipTuple": ipTuple, "socket": socket}, "Create IPv6 UDP socket")
				return
			}
		}
	}

	logging.Log("fatal", map[string]interface{}{"function": "createSocket", "ipTuple": ipTuple}, "Ip protocol number not recognized ", *ipTuple.Proto.Number)
	return
}

func writeDataOriginalDestination(ctx context.Context, socket *Socket, data Data, sockets *SocketMap, toDestination *DataMap) {
	select {
	case <-ctx.Done():
		logging.Log("trace", map[string]interface{}{"function": "writeDataOriginalDestination"}, "Context canceled")
		return
	default:
		if data.TLS && !socket.TLS {
			errAddTls := addTlsSocket(data.IPTuple, sockets)

			if errAddTls != nil {
				logging.Log("warning", map[string]interface{}{"function": "writeDataOriginalDestination", "ipTuple": data.IPTuple}, "Error add TLS write ", errAddTls)
				return
			}

			socket = sockets.readSocket(data.IPTuple)

			if *data.IPTuple.Proto.Number == uint8(17) {
				go readDataOriginalDestination(ctx, socket, data.IPTuple, sockets, toDestination)
			}
		}
	}

	socket.Lock.Lock()
	_, errWrite := socket.Connection.Write(data.Data)
	socket.Lock.Unlock()

	if errWrite != nil {
		logging.Log("error", map[string]interface{}{"function": "writeDataOriginalDestination", "socket": socket}, "Error write to original destination ", errWrite)
	}

	logging.Log("trace", map[string]interface{}{"function": "writeDataOriginalDestination", "socket": socket, "data": string(data.Data)}, "Sent to server")
}

func readDataOriginalDestination(ctx context.Context, socket *Socket, originalIpTuple *logging.IPTuple, sockets *SocketMap, toDestination *DataMap) {
	defer sockets.deleteSocket(originalIpTuple)
	buffer := make([]byte, 1024*4)

	for {
		select {
		case <-ctx.Done():
			logging.Log("trace", map[string]interface{}{"function": "readDataOriginalDestination"}, "Context canceled")
			return
		default:
			socket.Lock.Lock()
			socketNow := sockets.readSocket(originalIpTuple)

			if socketNow == nil {
				return
			} else {
				if socketNow.TLS && !socket.TLS {
					socket = socketNow
				}

				errSetDeadLine := socket.Connection.SetReadDeadline(time.Now().Add(500 * time.Millisecond))

				if errSetDeadLine != nil {
					logging.Log("error", map[string]interface{}{"function": "readDataOriginalDestination", "ipTuple": originalIpTuple, "socket": socket}, "Error set read deadline ", errSetDeadLine)
					return
				}

				length, errRead := socket.Connection.Read(buffer)
				socket.Lock.Unlock()

				if errRead != nil && errRead != io.EOF && !os.IsTimeout(errRead) {
					logging.Log("error", map[string]interface{}{"function": "readDataOriginalDestination", "ipTuple": originalIpTuple, "socket": socket}, "Error read data ", errRead)
					return
				}

				if length != 0 {
					logging.Log("trace", map[string]interface{}{"function": "readDataOriginalDestination", "ipTuple": originalIpTuple, "socket": socket, "data": string(buffer[:length])}, "Received from server")
					toDestination.addData(originalIpTuple, buffer[:length])
				}

				if errRead == io.EOF {
					return
				}

				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func CopyDataOriginalDestination(ctx context.Context, waitgroup *sync.WaitGroup, toOriginal chan Data, sockets *SocketMap, toDestination *DataMap) {
	defer waitgroup.Done()

	for {
		select {
		case dataDestination := <-toOriginal:
			socket := sockets.readSocket(dataDestination.IPTuple)

			if socket == nil {
				connection, errSocket := createSocket(dataDestination.IPTuple)

				if errSocket != nil {
					logging.Log("error", map[string]interface{}{"function": "CopyDataOriginalDestination", "ipTuple": dataDestination.IPTuple, "socket": socket}, "Error with socket open ", errSocket)
					return
				}

				sockets.addSocket(dataDestination.IPTuple, connection, dataDestination.TLS)
				socket = sockets.readSocket(dataDestination.IPTuple)

				go readDataOriginalDestination(ctx, socket, dataDestination.IPTuple, sockets, toDestination)
			}

			if dataDestination.Data != nil {
				go writeDataOriginalDestination(ctx, socket, dataDestination, sockets, toDestination)
			}
		case <-ctx.Done():
			logging.Log("trace", map[string]interface{}{"function": "CopyDataOriginalDestination"}, "Context canceled")
			return
		}
	}
}
