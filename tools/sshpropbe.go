package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"golang.org/x/crypto/ssh"
	"log"
	"math/rand"
	"net"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	con, err := net.Dial("tcp", ":1234")
	if err != nil {
		log.Fatal(err)
	}
	rnd := rand.New(rand.NewSource(1))
	key, err := ecdsa.GenerateKey(elliptic.P256(), rnd)
	//key, err := rsa.GenerateKey(rnd, 1024)
	if err != nil {
		log.Fatal(err)
	}
	sshpubkey, err := ssh.NewPublicKey(key.Public())
	if err != nil {
		log.Fatal(err)
	}
	sshsigner, err := ssh.NewSignerFromKey(key)
	if err != nil {
		log.Fatal(err)
	}
	cnf := ssh.ClientConfig{
		HostKeyCallback:   ssh.FixedHostKey(sshpubkey),
		HostKeyAlgorithms: []string{sshpubkey.Type()},
		ClientVersion:     "SSH-2.0-OpenSSH_5.2",
		Auth: []ssh.AuthMethod{
			ssh.Password("lol"),
			ssh.PublicKeys(sshsigner),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, echos []bool) (answers []string, err error) { return }),
		},
	}
	log.Printf("%#v", cnf)
	// XXX: v API is too high-level for probing, we just get nil,nil,nil,error
	a, b, c, d := ssh.NewClientConn(con, "?", &cnf)
	log.Print(a, b, c, d)
}
