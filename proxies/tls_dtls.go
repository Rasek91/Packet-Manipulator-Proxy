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
	"errors"
	"math/big"
	"net"
	"time"

	"github.com/pion/dtls"

	conntrack "github.com/florianl/go-conntrack"
	log "github.com/sirupsen/logrus"
)

var CA_cert *x509.Certificate
var CA_private_key *rsa.PrivateKey
var CA_error error
var Server_tls_config *tls.Config
var TLS_error error
var Server_dtls_config *dtls.Config
var DTLS_error error

func CA_cert_setup() (ca_cert *x509.Certificate, ca_private_key *rsa.PrivateKey, error error) {
	ca_cert = &x509.Certificate{
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

	ca_private_key, error = rsa.GenerateKey(rand.Reader, 4096)

	if error != nil {
		return
	}

	ca_bytes, error := x509.CreateCertificate(rand.Reader, ca_cert, ca_cert, &ca_private_key.PublicKey, ca_private_key)

	if error != nil {
		return
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

	return
}

func DTLS_config_setup(ca_cert *x509.Certificate, ca_private_key *rsa.PrivateKey) (*dtls.Config, error) {
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

	cert_private_key, error := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if error != nil {
		return nil, error
	}

	cert_bytes, error := x509.CreateCertificate(rand.Reader, cert, ca_cert, &cert_private_key.PublicKey, ca_private_key)
	
	if error != nil {
		return nil, error
	}

	certificate, error := x509.ParseCertificate(cert_bytes)
	
	if error != nil {
		return nil, error
	}


	server_dtls_config := &dtls.Config{
			Certificate: certificate,
			PrivateKey: cert_private_key,
	}

	return server_dtls_config, nil
}

func TLS_config_setup(ca_cert *x509.Certificate, ca_private_key *rsa.PrivateKey) (*tls.Config, error) {
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

	cert_bytes, error := x509.CreateCertificate(rand.Reader, cert, ca_cert, &cert_private_key.PublicKey, ca_private_key)
	
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
		var connection net.Conn

		if *ip_tuple.Proto.Number == uint8(6) {
			connection = tls.Client(socket.Connection, &tls.Config{InsecureSkipVerify: true})
			connection_tls := connection.(*tls.Conn)
			error := connection_tls.Handshake()
			socket.Connection.SetReadDeadline(time.Time{})
			socket.Lock.Unlock()

			if error != nil {
				log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": socket}).Error("Error with tls handshake ", error)
				return error
			}
		} else if *ip_tuple.Proto.Number == uint8(17) {
			connection_raw, error := dtls.Client(socket.Connection, &dtls.Config{InsecureSkipVerify: true, ExtendedMasterSecret: dtls.DisableExtendedMasterSecret})
			socket.Connection.SetReadDeadline(time.Time{})
			socket.Lock.Unlock()

			if error != nil {
				log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": socket}).Error("Error with dtls handshake ", error)
				return error
			}

			connection = create_conn(connection_raw)
		} else {
			log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": socket}).Fatal("IP protocol number not recognized ", *ip_tuple.Proto.Number)
			return errors.New("IP protocol number not recognized")
		}

		add_socket(ip_tuple, connection, true)
		log.WithFields(log.Fields{"ip_tuple": print_ip_tuple(ip_tuple), "socket": socket}).Trace("TLS socket added")
	}

	return nil
}
