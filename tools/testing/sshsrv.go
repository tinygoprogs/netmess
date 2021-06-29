package main

import (
	"context"
	"flag"
	"golang.org/x/crypto/ssh"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"github.com/tinygoprogs/misc/tcolor"
	"sync"
)

var Port = flag.String("port", "4321", "port to listen on")
var NConnections = flag.Int("nconnections", 1, "amount of connections before shutdown")

const hostkey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEAtdnHbtbuq5GViMNcYd6u2pUVLC0r7QckTa7wNxlO1g4BgyhS
ZI0qPR8e8+VW9npPKuoM5XxOZW8LYysBJalXREOnNdGFmDneUc2+t3bFVpZNfCQk
cOauxo9HL37tS5bfq1ZLC6JsZPLnJBgU8gdHc6P8H8s1u8qYLo9s69gn5ATD3HRL
tpjQ92TtTt6YUAdnxmD2ZVea0nSErBD21j9P1vf4RJP/7lE1iXvcv9dGLHqjeFHN
mmh83X7QoH+n8X36dZ361HEmVHpy6xkhQzoBpH5VHfjq8IUOZ5A1ldnFd9pN610F
pNmfL3rlfci2igFVlt4jmxChC87K+p2sMbrplQIDAQABAoIBAHSIS0nXB/kAATAz
6OZ6udguwvOdOtHYysXRPfRBDokTTprK4wm2gIPMhpxKshCezk60z3Db2K0dnNF+
xGxq+RYwuF0/l/m106beTsHopYrYJG1SB9wlp4hsVnS0RMI0u75jPRIGkqmaEs7J
c9qpGXuccTu6kAN4T08+79Cuotl1s5vIbjHBC2pYF2NpVAV7fwaM/wc7qz/H4H2o
Gg1S1+98KFLFvIIGWOm2G+ewk0FT1sUHcNjW+n1x+WCtOd43QMASrq0TkPK6djBx
gqwRaKIEjmFGSAJzBwxYwdXqvfFs4iopIYV8+x8nkcbnqOVu5erghUiLtgVZehr9
TTbCup0CgYEA3hNCwUD1ayv0RClYHm4FFjHTxSeqIZSkQpq/35pVDhX1hvgyE4DK
aUek6b2O7PO3bIQumgfFBUeSRBbBmLekGvT+pG0afmpaEij0rHKDBlftK0r7Elf/
iKIs8H1D4GgwgaNC9lsJWgcmsmzOefA/IRu7ZfOY7hXL47+BefGFDMMCgYEA0aFz
EcnXqsCvKUr5BfsaDufP7Ju8WBcnax/2B34PUrQ58eGE1n2v46I8isYtJNR7aDOP
y/BE5yb0nugNDluSVA5KEREdHNPpTdaFpq/C1Vz1CE+rIEU2Nvz/8iXpylY0FkCb
wNIwYgzZ+0zaRbBOyZIClc5s0JkH73zZeMiSKscCgYBClb/UNeff5GPu8/6J0S8R
Qoted9AZFXpSxhd1sc6C1K6zc0OAeYM3IdYeh0mNXl3G2bMnV+EI/jaq16/gXF+F
/aNEJbpl4Pl0rHcAJa2Hf2GLM4YoL95cV1PmH4j0hgjVNeBkAVPCfJZrtRgLk685
/BiqLunRqRNjDA6EQ5hDBQKBgQCUFC3KhP/ZWF7jFliuBuAzY0CW7LOwrjpkC6Gp
TTzZuQGtgRZqxUH31GRbyv2cpJO/2Zxb/Q9PEU9+6IBAgiLtSWK8h5A/Ctok58Jl
KobAXPehtVU2aG2Rjknl7S4mhZopld3v6QnQWS+punH9BDvDW2aEF9r5xv+6BkFA
dr35hQKBgQCeYTAN3QHyUggMcEh78m1vHn26mPOPmWqG4MvQkkY31G6X0qZodHJ7
tGjF34/Ad6YJgXldWuiHoOgfnVncYNt3IWvmx/5e/lUru9lKYI+zYl4nXq/fNALo
MEiH9gAKa/nj87A/6mXIICeYnhVR7gnqfjKSZcyW9InWji1k3F4HFA==
-----END RSA PRIVATE KEY-----
`

var noauth = ssh.ServerConfig{NoClientAuth: true}

func init() {
	flag.Parse()
	log.SetPrefix(tcolor.Green)

	log.SetFlags(log.Lmicroseconds | log.Lshortfile)

	priv, err := ssh.ParsePrivateKey([]byte(hostkey))
	if err != nil {
		log.Fatal(err)
	}
	noauth.AddHostKey(priv)
}

func HandleChannel(ctx context.Context, ch ssh.NewChannel) {
	channel, reqs, err := ch.Accept()
	if err != nil {
		log.Print("Accept failed: ", err)
		return
	}
	for {
		select {
		case rq, ok := <-reqs:
			if !ok || rq == nil {
				return
			}
			switch rq.Type {
			case "shell":
				log.Printf("%s: want-reply=%v, payload=%v", rq.Type, rq.WantReply, rq.Payload)
				if rq.WantReply {
					rq.Reply(true /*accept*/, []byte("i'm a teapot"))
				}
				go func() {
					defer channel.Close()
					cmd := exec.CommandContext(ctx, "bash", "-i")
					cmd.Stdin = channel
					cmd.Stdout = channel
					cmd.Stderr = channel
					cmd.Run()
				}()
			//case "pty-req": // pseudo terminal for interactive use
			//case "env": // ?
			//case "exec": // single command execution
			default:
				log.Print("unhandled request: ", rq.Type)
				rq.Reply(false /*deny*/, []byte{})
			}
		case <-ctx.Done():
			return
		}
	}
}

func HandleCon(ctx context.Context, con net.Conn) error {
	log.Printf("connection from %v", con.RemoteAddr())
	scon, chans, reqs, err := ssh.NewServerConn(con, &noauth)
	if err != nil {
		return err
	}
	defer scon.Close()
	log.Printf("user=%v, sessionid=%v, perms=%v",
		scon.User(), scon.SessionID(), scon.Permissions)
	go func() {
		for {
			select {
			case ch, ok := <-chans: // channels
				if !ok || ch == nil {
					return
				}
				log.Print("new ", ch.ChannelType())
				go HandleChannel(ctx, ch)
			case rq, ok := <-reqs: // requests
				if !ok || rq == nil {
					return
				}
				log.Print("unhandled request: ", rq)
			case <-ctx.Done():
				return
			}
		}
	}()
	return scon.Wait()
}

func main() {
	ln, err := net.Listen("tcp", "0.0.0.0:"+*Port)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt)
	go func() {
		select {
		case <-ch:
			cancel()          // cancel context
			err := ln.Close() // unblock pending Accept() calls
			if err != nil {
				log.Print(err)
			}
		}
	}()

	wg := sync.WaitGroup{}
	defer wg.Wait()
	N := *NConnections
	for {
		if N == 0 {
			return
		}
		select {
		case <-ctx.Done():
			return
		default:
		}
		con, err := ln.Accept()
		N--
		if err != nil {
			log.Print(err)
			continue
		}
		wg.Add(1)
		go func() {
			log.Print("done[", HandleCon(ctx, con), "]")
			wg.Done()
		}()
	}
}
