package main

import (
	"github.com/Rasek91/Packet-Manipulator-Proxy/proxies"
	log "github.com/sirupsen/logrus"
)

func main() {
	proxies.Setup_log()

	config := "proxies"

	if config == "proxies" {
		proxies.CA_cert, proxies.CA_private_key, proxies.CA_error = proxies.CA_cert_setup()

		if proxies.CA_error != nil {
			log.Fatal("CA Cert create error ", proxies.CA_error)
		}

		proxies.Server_tls_config, proxies.TLS_error = proxies.TLS_config_setup(proxies.CA_cert, proxies.CA_private_key)

		if proxies.TLS_error != nil {
			log.Fatal("TLS Cert create error ", proxies.TLS_error)
		}

		proxies.Server_dtls_config, proxies.DTLS_error = proxies.DTLS_config_setup(proxies.CA_cert, proxies.CA_private_key)

		if proxies.DTLS_error != nil {
			log.Fatal("DTLS Cert create error ", proxies.DTLS_error)
		}

		log.Info("Certificate generated")
		go proxies.Listen_udp("127.0.0.1", "7777")
		go proxies.Listen_udp("::1", "7777")
		go proxies.Listen_tcp("127.0.0.1", "7777")
		go proxies.Listen_tcp("::1", "7777")
		proxies.Copy_data_to_original_destination()
	}
}
