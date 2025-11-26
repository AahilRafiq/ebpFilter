package main

import (
	"fmt"
	"net"
	"os"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	args := os.Args[1:]
	ifname := args[0]
	fmt.Printf("Starting dns blocker on %s\n", ifname)

	var objs netblockerObjects
	if err := loadNetblockerObjects(&objs, nil); err != nil {
		panic(err)
	}
	defer objs.Close()

	filebytes, err := os.ReadFile("dnslist.txt")
	if err != nil {
		panic(err)
	}

	blockedList := strings.Split(string(filebytes), ",")

	dnsMap := objs.netblockerMaps.Blockeddns
	for _, domain := range blockedList {
		err := dnsMap.Put(domainNameToKey(domain), int32(1))
		if err != nil {
			panic(err)
		}
	}

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

func domainNameToKey(name string) [256]byte {
	var bytes [256]byte

	i := 0
	for _, label := range strings.Split(name, ".") {
		bytes[i] = byte(len(label))
		i++
		copy(bytes[i:], []byte(label))
		i += len(label)
	}

	return bytes
}
