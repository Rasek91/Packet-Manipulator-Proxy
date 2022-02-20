package proxies

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/Rasek91/Packet-Manipulator-Proxy/logging"
	"github.com/Rasek91/hybrid_tcp_tls_conn"
	"github.com/Rasek91/hybrid_udp_dtls_conn"
	"github.com/Rasek91/udp"
	"github.com/pion/dtls"

	conntrack "github.com/florianl/go-conntrack"
)

func readRoutine(ctx context.Context, connection net.Conn, buffer []byte, channelInt chan int, channelError chan error) {
	defer close(channelInt)
	defer close(channelError)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			length, err := connection.Read(buffer)
			channelError <- err
			channelInt <- length
		}
	}
}

func writeRoutine(ctx context.Context, originalIpTuple *logging.IPTuple, channelAnswer chan []byte, toDestination *DataMap) {
	defer close(channelAnswer)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			answer := toDestination.readDeleteData(originalIpTuple)

			if answer != nil {
				channelAnswer <- answer
			}
		}
	}
}

func handleConnection(ctx context.Context, originalIpTuple *logging.IPTuple, connection hybridConn, toOriginal chan Data, sockets *SocketMap, toDestination *DataMap) {
	iterations := 0
	channelError := make(chan error)
	channelInt := make(chan int)
	channelAnswer := make(chan []byte)
	defer connection.Close()
	defer sockets.deleteSocket(originalIpTuple)
	toOriginal <- Data{IPTuple: originalIpTuple, Data: nil, TLS: connection.GetTls()}
	buffer := make([]byte, 1024*4)
	go readRoutine(ctx, connection, buffer, channelInt, channelError)
	go writeRoutine(ctx, originalIpTuple, channelAnswer, toDestination)

	for iterations < 60 {
		select {
		case err := <-channelError:
			length := <-channelInt

			if err != nil && err != io.EOF {
				logging.Log("error", map[string]interface{}{"function": "handleConnection", "ipTuple": originalIpTuple}, "Read error ", err)
			}

			if length != 0 {
				logging.Log("debug", map[string]interface{}{"function": "handleConnection", "ipTuple": originalIpTuple, "data": string(buffer[:length])}, "Received from client")
				iterations = 0
				toOriginal <- Data{IPTuple: originalIpTuple, Data: buffer[:length], TLS: connection.GetTls()}
			}

			if err == io.EOF {
				iterations = 60
			}
		case answer := <-channelAnswer:
			logging.Log("debug", map[string]interface{}{"function": "handleConnection", "ipTuple": originalIpTuple, "data": string(answer)}, "Received from server")
			iterations = 0
			connection.Write(answer)
		case <-time.After(500 * time.Millisecond):
			iterations++
		case <-ctx.Done():
			logging.Log("trace", map[string]interface{}{"function": "handleConnection", "ipTuple": originalIpTuple}, "Context canceled")
			return
		}
	}
}

func ListenTcp(ctx context.Context, waitgroup *sync.WaitGroup, ipAddress, port string, toOriginal chan Data, sockets *SocketMap, toDestination *DataMap, tlsConfig *tls.Config) (err error) {
	defer waitgroup.Done()
	portInt64, _ := strconv.ParseInt(port, 0, 64)
	portInt := int(portInt64)
	listener, errListen := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP(ipAddress), Port: portInt})

	if errListen != nil {
		logging.Log("error", map[string]interface{}{"function": "ListenTcp"}, "ListenTCP error ", errListen)
		err = errListen
		return
	}

	connectionTracker, errConnTrack := conntrack.Open(&conntrack.Config{})

	if errConnTrack != nil {
		logging.Log("error", map[string]interface{}{"function": "ListenTcp"}, "Open error ", errConnTrack)
		err = errConnTrack
		return
	}

	logging.Log("info", map[string]interface{}{"function": "ListenTcp"}, "Listen TCP ", ipAddress)
	defer connectionTracker.Close()
	defer logging.Log("info", map[string]interface{}{"function": "ListenTcp"}, "Close TCP ", ipAddress)
	defer listener.Close()
	connectionChannel := make(chan net.Conn, 1)
	connectionErr := make(chan error, 1)

	for {
		go func(connectionChannel chan net.Conn, connectionErr chan error) {
			connectionRaw, errAccept := listener.Accept()
			connectionChannel <- connectionRaw
			connectionErr <- errAccept
		}(connectionChannel, connectionErr)

		select {
		case <-ctx.Done():
			logging.Log("trace", map[string]interface{}{"function": "ListenTcp"}, "Context canceled")
			return
		case errAccept := <-connectionErr:
			connectionRaw := <-connectionChannel

			if errAccept != nil {
				logging.Log("error", map[string]interface{}{"function": "ListenTcp"}, "Accept error ", errAccept)
				err = errAccept
				return
			}

			connection := hybrid_tcp_tls_conn.New(connectionRaw, tlsConfig)
			originalIpTuple, errGetIpTuple := getOriginalIpTuple(connectionTracker, connectionRaw.(*net.TCPConn))

			if errGetIpTuple != nil {
				logging.Log("panic", map[string]interface{}{"function": "ListenTcp"}, "Get original IP tuple error ", errGetIpTuple)
				err = errGetIpTuple
				return
			}

			go handleConnection(ctx, originalIpTuple, connection, toOriginal, sockets, toDestination)
		}
	}
}

func ListenUdp(ctx context.Context, waitgroup *sync.WaitGroup, ipAddress, port string, toOriginal chan Data, sockets *SocketMap, toDestination *DataMap, dtlsConfig *dtls.Config) (err error) {
	defer waitgroup.Done()
	portInt64, _ := strconv.ParseInt(port, 0, 64)
	portInt := int(portInt64)
	listener, errListen := udp.Listen("udp", &net.UDPAddr{IP: net.ParseIP(ipAddress), Port: portInt})

	if errListen != nil {
		logging.Log("error", map[string]interface{}{"function": "ListenUdp"}, "ListenUDP error ", errListen)
		err = errListen
		return
	}

	connectionTracker, errConnTrack := conntrack.Open(&conntrack.Config{})

	if errConnTrack != nil {
		logging.Log("error", map[string]interface{}{"function": "ListenUdp"}, "Open error ", errConnTrack)
		err = errConnTrack
		return
	}

	logging.Log("info", map[string]interface{}{"function": "ListenUdp"}, "Listen UDP ", ipAddress)
	defer connectionTracker.Close()
	defer logging.Log("info", map[string]interface{}{"function": "ListenUdp"}, "Close UDP ", ipAddress)
	//defer listener.Close() blocking forever
	connectionChannel := make(chan net.Conn, 1)
	connectionErr := make(chan error, 1)

	for {
		go func(connectionChannel chan net.Conn, connectionErr chan error) {
			connectionRaw, errAccept := listener.Accept()
			connectionChannel <- connectionRaw
			connectionErr <- errAccept
		}(connectionChannel, connectionErr)

		select {
		case <-ctx.Done():
			logging.Log("trace", map[string]interface{}{"function": "ListenUdp"}, "Context canceled")
			return
		case errAccept := <-connectionErr:
			connectionRaw := <-connectionChannel

			if errAccept != nil {
				logging.Log("error", map[string]interface{}{"function": "ListenUdp"}, "Accept error ", errAccept)
				err = errAccept
				return
			}

			connection := hybrid_udp_dtls_conn.New(connectionRaw, dtlsConfig)
			originalIpTuple, errGetIpTuple := getOriginalIpTuple(connectionTracker, connectionRaw.(*udp.Conn))

			if errGetIpTuple != nil {
				logging.Log("panic", map[string]interface{}{"function": "ListenUdp"}, "Get original IP tuple error ", errGetIpTuple)
				err = errGetIpTuple
				return
			}

			go handleConnection(ctx, originalIpTuple, connection, toOriginal, sockets, toDestination)
		}
	}
}
