package mitm

import (
	"context"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"path"
	"runtime"
	"github.com/tinygoprogs/misc/tcolor"
	"github.com/tinygoprogs/netmess/tools/testing/util"
	"sync"
	"strings"
	"testing"
	"time"
)

var toolsdir string

// 'r !openssl genrsa 2>/dev/null'
const testkey = `
-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEA59zeePmGs6L7S8SYdUqFtY8Do3x62o9L4aFUpfRQJdC0o8tX
gZu6MvWFpG+TXioKheCcS5bIfh7cxC2x01QLUp2et8jmxB4XCruVY4UIt3z4HpQW
J9XMbK2pofvd2U/d5gNeFh97RcBQ0Jiv813ZrxaVLCCljzx16BXi/alNmQrMu4eB
VKQ6cAlEO4tq60l4fGM2IrY4GzHXi8kcM18HcEVbg8Aj3na1MmqTG0wMIjmKRWY1
kczyeVt2DD93wdQqZ8uVcnwKaHxUgW5n1//qL3hbecMEuBo0XzteV/MUctlJgGGj
hVl5UaEtnwoTEmm5YQD5CZlQ/jN+IJJosSJlPQIDAQABAoIBAHPBmjRNZ0mh0dH2
+aJ9LRoCp29kgzVAm0KvN8KOocDvXG/14d8sLx6n4yvAJJO7a3uBMqauRbRplhA/
O+tkpy580LOykjtRRnGuSxvfXAW3V2x0xEbo/2E2plzfkNegfwkJn1xuJS4ioHYz
9IwMy9QU8y6Psfg72CWhX60CbGI9xcoZno8znZtTP61tfU41B3DPV5mFgl5bPfc4
XSd3azaEJt81TOe0wrPr0ZZfuKs4pFkXCNXC0XmVq23r+HdpCCNfmU1zFgAxb8QE
jvOj40obZO8GURoyBJOOE7CTY2f0zCM+f450JSXYbNlEEVJpVZxQbskNkn9amP1z
ypJKlGECgYEA88gaNEvLzi+DNKTwFe5dGSdN/lsaBMfrHt00z0PUayS0jJvQYH14
Rcxog9DjyripJqIUrgOJMuRbWhsF9Nhqq1hT0051t+iNeJ2HMIyF66kceDGi1I2/
ea5MKKvsUXy0lA892QX8Tjq8oNIIEVLT06dcYcqt+nbB9F9AXYsndskCgYEA83vW
tBClDvju8bvTPu0Vo9Wg3GrofsBrSAiIE4Hlfbn+WhB88TKFUDa06L1Dm0wWe9Ud
0+nnhc4Tq2b1yDUtgP9mIgqj0+Too5dxTDcWgpTsGGefvr3o+ZnfEwFzTozkAnyM
4yDjmVkewbHfyXkVmJDO3zuBUNdp9iq41HLgENUCgYBvGvr+bLEldrgYzTdy92FM
7oH4dDLmjOsW9QB1mld8wYzcLMOKxoSDY0cbFKBNK15Eckh0ir4ECNmttnU/g0cS
cr45px+1wvJ/T2Rm9xSuNDP6f7zTnQrwfUTOoJSjCvAOLugkOjskuFZyAWeV5acP
Zs6O713dsjRxmNvwBlTlKQKBgBUJF+2KmpgGja44yfFfzkTPSgyA+AErYplgk1EM
IeWQ0ha54fF8qePaNhr9bv/VvQOJz//k72mx+iUOyiE35uyEJDDAtpKx7h9kEBfD
kqBJeXRKT5TNF3mo/4rGz010AqbsV8evqbov5uZZFbp0SZdau2Sx4WQ4mCD6Y+mG
2zDZAoGAFimKvdDRNx0ESJ1jePEdCk3mfHmH0vJ8ATfFgUYtvqV/9lTbIBYecY4O
W3rdeyksA4VfQI7oZf3sE9yR+69vqnhZUy8WeglJGed2dhKTPfq+jb5fWeGcdg4H
VUisHDU6QMtUQ8NAXO0UeQ50Aq0lq20qzLQM+GpzZZFq9zhAgfE=
-----END RSA PRIVATE KEY-----
`

func init() {
	log.SetFlags(log.Lshortfile | log.Lmicroseconds)
	_, cwd, _, _ := runtime.Caller(0)
	toolsdir = path.Join(path.Dir(path.Dir(cwd)), "tools", "testing")
	//println("tools @ ", toolsdir)
	log.SetPrefix(tcolor.White)
}

func execve(ctx context.Context, file string, args ...string) (out []byte, err error) {
	cmd := exec.CommandContext(ctx, file, args...)

	// new:
	//out, err = cmd.CombinedOutput()
	//cmd.Process.Kill()

	// old:
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = strings.NewReader("ls -B\n")
	cmd.Run()
	p := cmd.Process
	println("killing pid ", p.Pid)
	p.Kill()

	return
}

func simmulateSSHServer(ctx context.Context, port string, t *testing.T, wg *sync.WaitGroup) {
	binary := path.Join(toolsdir, "sshsrv")
	args := []string{"-port", port}
	if testing.Verbose() {
		t.Logf("running `%v %v`", binary, args)
	}
	out, err := execve(ctx, binary, args...)
	if err != nil {
		t.Errorf("command `%v %v` failed: %v\nFull output:\n%v", binary, args, err, string(out))
	}
	wg.Done()
}

func waitForServerStartup() {
	time.Sleep(time.Millisecond * 10)
}

func TestRequestShellAndInteractiveLsOutput(t *testing.T) {
	var (
		rcon, lcon net.Conn
		err        error
		listen     = ":1234"
		connect    = ":4321"
	)
	t.Logf("The Plan: left side (listen) on %s, right side (connected) on %s", listen, connect)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// start server and connect to it (need net.Conn for Mitm call)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go simmulateSSHServer(ctx, connect[1:], t, &wg)
	for {
		rcon, err = net.Dial("tcp", connect)
		if err == nil {
			break
		}
	}

	// listen for client and start Mitm, once he connects
	stepper := make(chan (string), 1)
	go func() {
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		stepper <- "AcceptingState"
		lcon, err = ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("connection from %v", lcon.RemoteAddr())

		monkey := SSHMitm{}
		key, err := NewMonKeyPEM(testkey)
		if err != nil {
			t.Fatal(err)
		}
		monkey.Key = key
		monkey.Mitm(ctx, lcon, rcon)
		stepper <- "MitmDone"
	}()
	if <-stepper != "AcceptingState" {
		t.Error("invalid test logic: AcceptingState")
	}

	conf := util.SSHShellCommandConfig{
		Dial:           listen,
		Op:             util.SSHOPSingleCommand,
		CmdLine:        "ls /",
		CompletionWait: time.Millisecond * 50,
		Log:            log.New(ioutil.Discard, "", 0),
	}
	if testing.Verbose() {
		conf.Log = log.New(os.Stderr, "[test] ", log.LstdFlags|log.Lmicroseconds)
	}
	err, res := util.SSHShellCommand(ctx, &conf)
	if err != nil {
		t.Error(err)
		return
	}
	if !strings.Contains(res.Stdout, "home") {
		t.Errorf("command: 'ls /', missing output: 'home'")
	}
	if <-stepper != "MitmDone" {
		t.Error("invalid test logic: AcceptingState")
	}
	wg.Wait()
}

func TestRequestExecAndLsOutput(t *testing.T) {
	var (
		rcon, lcon net.Conn
		err        error
		listen     = ":1234"
		connect    = ":4321"
	)
	t.Logf("The Plan: left side (listen) on %s, right side (connected) on %s", listen, connect)

	ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
	defer cancel()

	// start server and connect to it (need net.Conn for Mitm call)
	wg := sync.WaitGroup{}
	wg.Add(1)
	go simmulateSSHServer(ctx, connect[1:], t, &wg)
	for {
		rcon, err = net.Dial("tcp", connect)
		if err == nil {
			break
		}
	}

	// listen for client and start Mitm, once he connects
	stepper := make(chan (string), 1)
	go func() {
		ln, err := net.Listen("tcp", listen)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		stepper <- "AcceptingState"
		lcon, err = ln.Accept()
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("connection from %v", lcon.RemoteAddr())

		monkey := SSHMitm{}
		key, err := NewMonKeyPEM(testkey)
		if err != nil {
			t.Fatal(err)
		}
		monkey.Key = key
		monkey.Mitm(ctx, lcon, rcon)
		stepper <- "MitmDone"
	}()
	if <-stepper != "AcceptingState" {
		t.Error("invalid test logic: AcceptingState")
	}

	err, res := util.SSHCombinedOutput(listen, "ls /")
	if err != nil {
		t.Error(err)
		return
	}
	if !strings.Contains(res, "home") {
		t.Errorf("command: 'ls /', missing output: 'home'")
	}
	if <-stepper != "MitmDone" {
		t.Error("invalid test logic: AcceptingState")
	}
	wg.Wait()
}
