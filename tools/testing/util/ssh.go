package util

import (
	"context"
	"errors"
	"golang.org/x/crypto/ssh"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

type SSHShellCommandOperation int

const (
	SSHOPSingleCommand SSHShellCommandOperation = iota
	SSHOPInteractive
)

type SSHShellCommandConfig struct {
	// destination address
	Dial string
	// default to SSHOPSingleCommand -> execute CmdLine
	Op SSHShellCommandOperation
	// command line to execute in a requested shell
	CmdLine string
	// wait for command completion this amount
	CompletionWait time.Duration
	// log output
	Log *log.Logger
}
type SSHShellCommandResult struct {
	Stdout, Stderr string
}

func readall(i io.Reader) string {
	buf, err := ioutil.ReadAll(i)
	if err != nil {
		println("readall: %v", err)
	}
	return string(buf)
}

// request "shell" and do SSHShellCommandConfig
func SSHShellCommand(ctx context.Context, c *SSHShellCommandConfig) (error, *SSHShellCommandResult) {
	var (
		err   error
		con   net.Conn
		conf  ssh.ClientConfig
		chans <-chan ssh.NewChannel
		reqs  <-chan *ssh.Request
		clico ssh.Conn
	)

	con, err = net.Dial("tcp", c.Dial)
	if err != nil {
		return err, nil
	}
	conf = ssh.ClientConfig{
		User:            "qwerty",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{ssh.Password("hello")},
	}

	clico, chans, reqs, err = ssh.NewClientConn(con, "", &conf)
	if err != nil {
		return err, nil
	}
	c.Log.Printf("connected to %v", clico.RemoteAddr())
	defer clico.Close()

	go func() {
		for {
			select {
			case ch := <-chans:
				if ch == nil {
					return
				}
				c.Log.Print("rejecting chan: ", ch.ChannelType())
				ch.Reject(ssh.UnknownChannelType, "don't care!")
			case rq := <-reqs:
				if rq == nil {
					return
				}
				c.Log.Print("rejecting requ: ", rq.Type)
				if rq.WantReply {
					rq.Reply(false, nil)
				}
			case <-ctx.Done():
				return
			}
		}
	}()

	channel, err := createShellChannel(c, clico)
	if err != nil {
		return err, nil
	}
	c.Log.Print("got a shell!")

	switch c.Op {
	case SSHOPInteractive:
		go io.Copy(os.Stdout, channel)
		go io.Copy(os.Stdout, channel.Stderr())
		go io.Copy(channel, os.Stdin)
		<-ctx.Done()
		channel.Close()
	case SSHOPSingleCommand:
		io.Copy(channel, strings.NewReader(c.CmdLine+"\n"))
		r := SSHShellCommandResult{}
		select {
		case <-time.After(c.CompletionWait):
			break
		case <-ctx.Done():
			break
		}
		channel.Close()
		r.Stdout = readall(channel)
		r.Stderr = readall(channel.Stderr())
		//c.Log.Print("xxx stdout:", r.Stdout)
		//c.Log.Print("xxx stderr:", r.Stderr)
		return nil, &r
	}
	return clico.Wait(), nil
}

func createShellChannel(c *SSHShellCommandConfig, clico ssh.Conn) (ssh.Channel, error) {
	channel, reqs, err := clico.OpenChannel("session", []byte("session"))
	if err != nil {
		return nil, err
	}
	c.Log.Print("session established, discarding requests")
	go ssh.DiscardRequests(reqs)

	accepted, err := channel.SendRequest("shell", true, nil)
	if err != nil {
		return nil, err
	}
	if !accepted {
		return nil, errors.New("shell not accepted")
	}
	return channel, nil
}

// run cmd synchronously (via request "exec") at dial server and return
// stderr+stdout
func SSHCombinedOutput(dial, cmd string) (err error, out string) {
	conf := ssh.ClientConfig{
		User:            "qwerty",
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Auth:            []ssh.AuthMethod{ssh.Password("hello")},
	}
	cli, err := ssh.Dial("tcp", dial, &conf)
	if err != nil {
		return
	}
	sess, err := cli.NewSession()
	if err != nil {
		return
	}
	bytes, err := sess.CombinedOutput(cmd)
	return err, string(bytes)
}
