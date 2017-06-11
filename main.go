package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/jesk78/anyflow/proto/netflow"
)

type Packet struct {
	Raw   []byte
	Saddr *net.UDPAddr
	Proto string
}

func CheckError(err error) {
	if err != nil {
		fmt.Println("Error: ", err)
		os.Exit(0)
	}
}

func Parse(b []byte, addr *net.UDPAddr) (*Packet, error) {
	p := new(Packet)
	// parse for flow netflowcol
	switch b[1] {
	case 9:
		*p = Packet{Raw: b, Saddr: addr, Proto: "nf9"}
	default:
		return p, errors.New("No flow packet")
	}
	return p, nil
}

func main() {
	ServerAddr, err := net.ResolveUDPAddr("udp", ":10001")
	CheckError(err)

	ServerConn, err := net.ListenUDP("udp", ServerAddr)
	CheckError(err)

	defer ServerConn.Close()

	buf := make([]byte, 9000)

	for {
		n, addr, err := ServerConn.ReadFromUDP(buf)
		//fmt.Println("Host :", addr.IP.String())

		fmt.Println("")
		fmt.Println("+---------------------------------------+")
		fmt.Println("|               NEW PACKET              |")
		fmt.Println("+---------------------------------------+")
		fmt.Println("|Packet Source: ", addr.IP.String())

		if err != nil {
			fmt.Println("Error: ", err)
		}

		p, err := Parse(buf[:n], addr)

		if err != nil {
			fmt.Println("Error: ", err)
			continue
		}

		switch p.Proto {

		case "nf9":
			nf, err := netflow.New(p.Raw, p.Saddr)

			if err != nil {
				fmt.Println("Error: ", err)
				continue
			}

			if !nf.HasFlows() {
				continue
			}

			records, err := nf.GetFlows()

			fmt.Println("Data Record length: ", len(records))

			if err != nil {
				fmt.Println("Error: ", err)
				continue
			}

			i := 1

			for _, r := range records {

				fmt.Println("---------------------")
				fmt.Println("Flow/Record: ", i)
				fmt.Println("---------------------")

				for _, v := range r.Values {

					fmt.Printf("%v: %v\n", v.GetType(), v.GetValue())

				}

				fmt.Println("")
				i++
			}
		}
	}
}
