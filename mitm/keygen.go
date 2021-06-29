package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"golang.org/x/crypto/ssh"
)

// default rsa keysize
const KeyDefaultBitLen = 4096

type MonKey struct {
	Rsa    *rsa.PrivateKey
	Signer ssh.Signer
}

// generate a new rsa key with Bits bits
func NewMonKey(Bits ...int) (mk *MonKey, err error) {
	var bits int
	if len(Bits) > 1 {
		return nil, errors.New("invalid usage: supply 0||1 arguments")
	}
	if len(Bits) == 1 {
		bits = Bits[0]
	} else {
		bits = KeyDefaultBitLen
	}
	mk = &MonKey{}
	mk.Rsa, err = rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return
	}
	mk.Signer, err = ssh.NewSignerFromKey(mk.Rsa)
	return
}

// use passed key as MonKey
func NewMonKeyPEM(pem string) (mk *MonKey, err error) {
	mk = &MonKey{}
	mk.Signer, err = ssh.ParsePrivateKey([]byte(pem))
	return
}
