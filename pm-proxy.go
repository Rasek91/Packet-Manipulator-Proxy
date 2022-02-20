package main

import (
	"context"
	"os"
	"os/signal"
	"sync"

	"github.com/Rasek91/Packet-Manipulator-Proxy/logging"
	"github.com/Rasek91/Packet-Manipulator-Proxy/proxies"
)

func main() {
	waitgroup := sync.WaitGroup{}
	ctx := context.Background()
	ctx, cancel := context.WithCancel(ctx)
	logging.Setup()
	signalChannel := make(chan os.Signal, 1)
	signal.Notify(signalChannel, os.Interrupt)

	config := "proxies"

	if config == "proxies" {
		toOriginal, sockets, toDestination, tlsConfig, dtlsConfig, err := proxies.Setup()

		if err != nil {
			return
		}

		logging.Log("info", map[string]interface{}{"function": "main"}, "Certificate generated")
		waitgroup.Add(1)
		go proxies.ListenUdp(ctx, &waitgroup, "127.0.0.1", "7777", toOriginal, &sockets, &toDestination, dtlsConfig)
		waitgroup.Add(1)
		go proxies.ListenUdp(ctx, &waitgroup, "::1", "7777", toOriginal, &sockets, &toDestination, dtlsConfig)
		waitgroup.Add(1)
		go proxies.ListenTcp(ctx, &waitgroup, "127.0.0.1", "7777", toOriginal, &sockets, &toDestination, tlsConfig)
		waitgroup.Add(1)
		go proxies.ListenTcp(ctx, &waitgroup, "::1", "7777", toOriginal, &sockets, &toDestination, tlsConfig)
		waitgroup.Add(1)
		go proxies.CopyDataOriginalDestination(ctx, &waitgroup, toOriginal, &sockets, &toDestination)
	}

	<-signalChannel
	logging.Log("info", map[string]interface{}{"function": "main"}, "Interupted")
	cancel()
	waitgroup.Wait()
}
