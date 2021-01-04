package sip

import "fmt"

type Address struct {
	Protocal  string
	Host      string
	Port      string
	AccNumber string
	Password  string
	Name      string
}

func (a Address) String() string {
	return fmt.Sprintf("%s:%s", a.Host, a.Port)
}

func (a Address) Network() string {
	return a.Protocal
}
