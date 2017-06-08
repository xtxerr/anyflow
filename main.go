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

		if err != nil {
			fmt.Println("Error: ", err)
		}

		p, err := Parse(buf[:n], addr)

		if err == nil {
			switch p.Proto {
			// netflow v9 packet processing
			case "nf9":
				nf, err := netflow.New(p.Raw, p.Saddr)
				//netflow.New(p.Raw, p.Saddr)

				// Debugging
				//fmt.Printf("Proto: %v\nSaddr: %v\nVersion: %v\nCount: %v\nUptime: %v\n"+
				//	"UnixSecs: %v\nSequence: %v\nSourceId: %v\n\n",
				//	p.Proto, p.Saddr, nf.Version, nf.Count, nf.SysUptime,
				//	nf.UnixSecs, nf.Sequence, nf.SourceId)
				//fmt.Printf("FlowSet ID: %v\nFlowSet length: %v\nTemplate ID: %v\n"+
				//	"Template Count: %v\n-------\n",
				//	nf.FlowSet.Id, nf.FlowSet.Length, nf.Template.Id,
				//	nf.Template.FieldCount)

				//spew.Dump(netflow.TemplateTable)

				if err == nil {
					//spew.Dump(nf)

					//fmt.Println("------------------------------------------------------")
					//fmt.Println("Host :", addr.IP.String())

					//records, err := nf.GetDataRecords()
					nf.GetDataRecords()

					if err == nil {
						//	for i, r := range records {
						//		fmt.Println("record no: ", i)
						//		fmt.Println("record value: ", r)
						//	}
					} else {
						fmt.Println("Error: ", err)
					}
				} else {
					fmt.Println("Error: ", err)
				}
			}
		}
	}
}
