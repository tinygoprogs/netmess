package main

import (
	"context"
	"flag"
	"log"
	"net"
	"github.com/tinygoprogs/netmess/mitm"
	"time"
)

var listen = flag.String("listen", ":1234", "listen on ip:port")
var connect = flag.String("connect", ":4321", "connect to ip:port")

func init() {
	log.SetFlags(log.Lshortfile | log.Lmicroseconds)
	flag.Parse()
}

func main() {
	log.Printf("listening on  %s", *listen)
	log.Printf("connecting to %s", *connect)

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	lcon, err := ln.Accept()
	if err != nil {
		log.Fatal(err)
	}
	rcon, err := net.Dial("tcp", *connect)
	if err != nil {
		log.Fatal(err)
	}

	ctx, _ := context.WithTimeout(context.Background(), time.Second*30)
	monkey := mitm.SSHMitm{}
	monkey.Mitm(ctx, lcon, rcon)
}
