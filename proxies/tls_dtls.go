package proxies

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	"github.com/Rasek91/Packet-Manipulator-Proxy/logging"
	"github.com/pion/dtls"
)

func CaCertSetup() (caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey, err error) {
	caCert = &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivateKey, err = rsa.GenerateKey(rand.Reader, 4096)

	/*if err != nil {
		return
	}

	caBytes, err := x509.CreateCertificate(rand.Reader, caCert, caCert, &caPrivateKey.PublicKey, caPrivateKey)

	if err != nil {
		return
	}

	caPem := new(bytes.Buffer)
	pem.Encode(caPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})

	caPrivateKeyPem := new(bytes.Buffer)
	pem.Encode(caPrivateKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(caPrivateKey),
	})*/

	logging.Log("trace", map[string]interface{}{"function": "CaCertSetup"}, "CA certificate generated")
	return
}

func DtlsConfigSetup(caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey) (config *dtls.Config, err error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		logging.Log("error", map[string]interface{}{"function": "DtlsConfigSetup"}, "DTLS certificate private key error ", err)
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivateKey.PublicKey, caPrivateKey)

	if err != nil {
		logging.Log("error", map[string]interface{}{"function": "DtlsConfigSetup"}, "DTLS create certificate error ", err)
		return
	}

	certificate, err := x509.ParseCertificate(certBytes)

	if err != nil {
		logging.Log("error", map[string]interface{}{"function": "DtlsConfigSetup"}, "DTLS parse certificate error ", err)
		return
	}

	config = &dtls.Config{
		Certificate: certificate,
		PrivateKey:  certPrivateKey,
	}

	logging.Log("trace", map[string]interface{}{"function": "DtlsConfigSetup"}, "DTLS certificate created")
	return
}

func TlsConfigSetup(caCert *x509.Certificate, caPrivateKey *rsa.PrivateKey) (config *tls.Config, err error) {
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization:  []string{"Company, INC."},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{"San Francisco"},
			StreetAddress: []string{"Golden Gate Bridge"},
			PostalCode:    []string{"94016"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certPrivateKey, err := rsa.GenerateKey(rand.Reader, 4096)

	if err != nil {
		logging.Log("error", map[string]interface{}{"function": "TlsConfigSetup"}, "TLS certificate private key error ", err)
		return
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, cert, caCert, &certPrivateKey.PublicKey, caPrivateKey)

	if err != nil {
		logging.Log("error", map[string]interface{}{"function": "TlsConfigSetup"}, "TLS create certificate error ", err)
		return
	}

	certPem := new(bytes.Buffer)
	pem.Encode(certPem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	certPrivateKeyPem := new(bytes.Buffer)
	pem.Encode(certPrivateKeyPem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivateKey),
	})

	serverCert, err := tls.X509KeyPair(certPem.Bytes(), certPrivateKeyPem.Bytes())

	if err != nil {
		logging.Log("error", map[string]interface{}{"function": "TlsConfigSetup"}, "TLS parse certificate error ", err)
		return
	}

	config = &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}

	logging.Log("trace", map[string]interface{}{"function": "TlsConfigSetup"}, "TLS certificate created")
	return
}

func addTlsSocket(ipTuple *logging.IPTuple, sockets *SocketMap) (err error) {
	socket := sockets.readSocket(ipTuple)

	if socket == nil {
		connection, errSocket := createSocket(ipTuple)

		if errSocket != nil {
			logging.Log("error", map[string]interface{}{"function": "addTlsSocket", "ipTuple": ipTuple, "socket": socket}, "Error with socket open ", errSocket)
			err = errSocket
			return
		}

		sockets.addSocket(ipTuple, connection, false)
		socket = sockets.readSocket(ipTuple)
	}

	if !socket.TLS {
		socket.Lock.Lock()
		socket.Connection.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))
		var connection net.Conn

		if *ipTuple.Proto.Number == uint8(6) {
			connection = tls.Client(socket.Connection, &tls.Config{InsecureSkipVerify: true})
			connectionTls := connection.(*tls.Conn)
			errTls := connectionTls.Handshake()
			socket.Connection.SetReadDeadline(time.Time{})
			socket.Lock.Unlock()

			if errTls != nil {
				logging.Log("error", map[string]interface{}{"function": "addTlsSocket", "ipTuple": ipTuple, "socket": socket}, "Error with tls handshake ", errTls)
				err = errTls
				return
			}
		} else if *ipTuple.Proto.Number == uint8(17) {
			connectionRaw, errDtls := dtls.Client(socket.Connection, &dtls.Config{InsecureSkipVerify: true, ExtendedMasterSecret: dtls.DisableExtendedMasterSecret})
			socket.Connection.SetReadDeadline(time.Time{})
			socket.Lock.Unlock()

			if errDtls != nil {
				logging.Log("error", map[string]interface{}{"function": "addTlsSocket", "ipTuple": ipTuple, "socket": socket}, "Error with dtls handshake ", errDtls)
				err = errDtls
				return
			}

			connection = New(connectionRaw)
		} else {
			logging.Log("fatal", map[string]interface{}{"function": "addTlsSocket", "ipTuple": ipTuple, "socket": socket}, "IP protocol number not recognized ", *ipTuple.Proto.Number)
			err = logging.IPProtocol
			return
		}

		sockets.addSocket(ipTuple, connection, true)
		logging.Log("trace", map[string]interface{}{"function": "addTlsSocket", "ipTuple": ipTuple, "socket": socket}, "TLS socket added")
	}

	return
}
