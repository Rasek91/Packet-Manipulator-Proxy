package main

import (
	log "github.com/sirupsen/logrus"
)

func main() {
	setup_log()
	server_tls_config, tls_error = certsetup()

	if tls_error != nil {
		log.Fatal("Cert create error ", tls_error)
	}

	log.Info("Certificate generated")
	go listen_udp("127.0.0.1", "7777")
	go listen_udp("::1", "7777")
	go listen_tcp("127.0.0.1", "7777")
	go listen_tcp("::1", "7777")
	copy_data_to_original_detination()
}
