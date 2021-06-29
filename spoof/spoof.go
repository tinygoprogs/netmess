package spoof

type Spoof interface {
	Start() error
	Stop()
}
