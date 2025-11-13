package main

import (
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf/link"
)

func main() {
	var objs netblockerObjects
	if err := loadNetblockerObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	ifname := "lo"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		panic(err)
	}

	link, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpNetblockerFunc,
		Interface: iface.Index,
	})
	if err != nil {
		panic(err)
	}
	defer link.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
