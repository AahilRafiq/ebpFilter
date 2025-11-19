package main

import (
	"net"
	"os"
	"os/signal"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	var objs netblockerObjects
	if err := loadNetblockerObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	ifname := "enp2s0"
	iface, err := net.InterfaceByName(ifname)
	if err != nil {
		panic(err)
	}

	link, err := link.AttachTCX(link.TCXOptions{
		Interface: iface.Index,
		Program:   objs.SockfilterNetblockerFunc,
		Attach:    ebpf.AttachType(ebpf.AttachTCXEgress),
	})

	if err != nil {
		panic(err)
	}
	defer link.Close()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
}
