package main

import (
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()
	app.Static("/", "./public")
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
	defer dnsMap.Close()

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

	go app.Listen(":3000")
	fmt.Println("Started server")

	// Server route handlers
	app.Get("/api/list", func(c *fiber.Ctx) error {
		return c.JSON(blockedList)
	})

	app.Post("/api/add", func(c *fiber.Ctx) error {
		data := c.Request().Body()
		domain := string(data)
		blockedList = append(blockedList, domain)
		dnsMap.Put(domainNameToKey(domain), int32(1))
		clearDnsCmd := exec.Command("resolvectl", "flush-caches")
		err := clearDnsCmd.Run()
		if err != nil {
			fmt.Println("Error clearing dns cache")
			return c.SendStatus(500)
		}
		return c.SendStatus(200)
	})

	app.Post("/api/remove", func(c *fiber.Ctx) error {
		data := c.Request().Body()
		domain := string(data)
		newList := make([]string, 0, len(blockedList))
		for _, item := range blockedList {
			if item != domain {
				newList = append(newList, item)
			}
		}
		blockedList = newList
		dnsMap.Delete(domainNameToKey(domain))
		return c.SendStatus(200)
	})

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt)
	<-stop
	writeSliceToFile("dnslist.txt", blockedList)
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

func writeSliceToFile(filename string, data []string) error {
	fmt.Println(data)
	content := strings.Join(data, ",")
	file, err := os.Create(filename)
	if err != nil {
		fmt.Println(err.Error())
		return err
	}
	_, err = file.WriteString(content)
	if err != nil {
		fmt.Println(err.Error())
		return fmt.Errorf("failed to write to file %s: %w", filename, err)
	}
	file.Close()
	return nil
}
