package main

import (
	"fmt"
	"net/http"

	"github.com/veera83372/go-voip/proto/sip"
)

func main() {
	addr := sip.Address{Host: "10.187.7.12", Port: "5060", Protocal: "udp", Name: "Veera Pirla", AccNumber: "", Password: ""}
	headers := http.Header{}
	headers.Add("Max-Forwards", "70")
	headers.Add("Expires", "300")
	resp, _ := sip.RegisterAddBinding(addr, headers)
	fmt.Println(resp.Status)
}
