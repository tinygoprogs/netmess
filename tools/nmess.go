// Simple cmd-line client using the netmess library.
package main

import (
	"log"
	"os"
	"github.com/tinygoprogs/netmess/discovery"
)

func main() {
	homenet, err := discovery.NewNetwork(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer homenet.Close()

	router, err := homenet.GetHostByIP("192.168.0.1")
	if err != nil {
		log.Fatal(err)
	}
	println("router: ", router.String())

	ip := "192.168.0.6"
	someone, err := homenet.GetHostByIP(ip)
	if err != nil {
		log.Fatal(err)
	}
	println("someone: ", someone.String())

	os.Exit(0)
}
