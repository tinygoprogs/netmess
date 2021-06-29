package main

import (
	"context"
	"flag"
	"log"
	"github.com/tinygoprogs/misc/tcolor"
	"github.com/tinygoprogs/netmess/tools/testing/util"
)

var Server = flag.String("server", ":1234", "ssh server to connect to")

func init() {
	flag.Parse()
	log.SetFlags(log.Lmicroseconds | log.Lshortfile)
	log.SetPrefix(tcolor.Yellow)
}

func main() {
	//err := simple_con(*Server)
	log.Printf("connecting to %s", *Server)
	err, _ := util.SSHShellCommand(context.Background(), &util.SSHShellCommandConfig{
		Dial: *Server,
		Op:   util.SSHOPInteractive,
	})
	if err != nil {
		log.Fatal(err)
	}
}

// vim: ts=2 sts=2 sw=2 et ai sr
