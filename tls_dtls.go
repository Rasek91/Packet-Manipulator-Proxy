package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"time"

	conntrack "github.com/florianl/go-conntrack"
	log "github.com/sirupsen/logrus"
)

var server_tls_config *tls.Config
var tls_error error

func certsetup() (*tls.Config, error) {
	ca := &x509.Certificate{
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

	ca_private_key, error := rsa.GenerateKey(rand.Reader, 4096)
	if error != nil {
		return nil, error
	}

	ca_bytes, error := x509.CreateCertificate(rand.Reader, ca, ca, &ca_private_key.PublicKey, ca_private_key)
	if error != nil {
		return nil, error
	}

	ca_pem := new(bytes.Buffer)
	pem.Encode(ca_pem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: ca_bytes,
	})

	ca_private_key_pem := new(bytes.Buffer)
	pem.Encode(ca_private_key_pem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(ca_private_key),
	})

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

	cert_private_key, error := rsa.GenerateKey(rand.Reader, 4096)
	if error != nil {
		return nil, error
	}

	cert_bytes, error := x509.CreateCertificate(rand.Reader, cert, ca, &cert_private_key.PublicKey, ca_private_key)
	if error != nil {
		return nil, error
	}

	cert_pem := new(bytes.Buffer)
	pem.Encode(cert_pem, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert_bytes,
	})

	cert_private_key_pem := new(bytes.Buffer)
	pem.Encode(cert_private_key_pem, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(cert_private_key),
	})

	server_cert, error := tls.X509KeyPair(cert_pem.Bytes(), cert_private_key_pem.Bytes())
	if error != nil {
		return nil, error
	}

	server_tls_config := &tls.Config{
		Certificates: []tls.Certificate{server_cert},
	}

	return server_tls_config, nil
}

func add_tls_to_socket(ip_tuple *conntrack.IPTuple) error {
	socket := read_socket(ip_tuple)

	if socket == nil {
		connection, error := create_socket(ip_tuple)
		log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": socket}).Trace("create socket")

		if error != nil {
			log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": socket}).Error("Error with socket open ", error)
			return error
		}

		add_socket(ip_tuple, connection, false)
		socket = read_socket(ip_tuple)
	}

	if !socket.TLS {
		socket.Lock.Lock()
		socket.Connection.SetReadDeadline(time.Now().Add(1000 * time.Millisecond))
		connection_tls := tls.Client(socket.Connection, &tls.Config{InsecureSkipVerify: true})
		error := connection_tls.Handshake()
		socket.Lock.Unlock()

		if error != nil {
			log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": socket}).Error("Error with tls handshake ", error)
			return error
		}

		add_socket(ip_tuple, connection_tls, true)
		log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": socket}).Trace("TLS socket added")
	}

	return nil
}

/*
func add_dtls_to_socket(ip_tuple *conntrack.IPTuple) {
	socket, in := read_socket(ip_tuple)

	  if in == false {

	  }
}

func add_tls_to_connection(ip_tuple *conntrack.IPTuple, connection net.Conn) *tls.Conn {
	connection_tls := tls.Server(connection, server_tls_config)
	log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": connection}).Trace("TLS socket added")
	return connection_tls
}

func add_dtls_to_connection(ip_tuple *conntrack.IPTuple, connection net.Conn) {
}

func add_tls(ip_tuple *conntrack.IPTuple, data []byte, connection net.Conn) (*tls.Conn, error) {
	var connection_tls *tls.Conn

	if *ip_tuple.Proto.Number == uint8(6) {
		error := add_tls_to_socket(ip_tuple)

		if error != nil {
			return nil, error
		}

		connection_tls = add_tls_to_connection(ip_tuple, connection)
	} else if *ip_tuple.Proto.Number == uint8(17) {
		add_dtls_to_socket(ip_tuple)
		add_dtls_to_connection(ip_tuple, connection)
	}

	return connection_tls, nil
}*/
