package main

import (
	"errors"
	"fmt"
	"net"
	"os"

	"github.com/jesk78/anyflow/proto/netflow"
	"github.com/prometheus/client_golang/prometheus"
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

func receivePackets(c *UDPConn) {
	buf := make([]byte, 9000)

	for {
		n, addr, err := ServerConn.ReadFromUDP(buf)
		packetSourceIP := addr.IP.String()
		//fmt.Println("Host :", addr.IP.String())

		fmt.Println("")
		fmt.Println("+---------------------------------------+")
		fmt.Println("|               NEW PACKET              |")
		fmt.Println("+---------------------------------------+")
		fmt.Println("|Packet Source: ", packetSourceIP)

		if err != nil {
			fmt.Println("Error: ", err)
		}
		packetsTotal.WithLabelValues(packetSourceIP).Inc()

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

func init() {
	prometheus.MustRegister(packetsTotal)
}

func main() {
	listenAddress := ":8080"
	ServerAddr, err := net.ResolveUDPAddr("udp", ":10001")
	CheckError(err)

	ServerConn, err := net.ListenUDP("udp", ServerAddr)
	CheckError(err)

	defer ServerConn.Close()

	go receivePackets(ServerConn)

	http.Handle("/metrics", prometheus.Handler())
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`<html>
            <head><title>Anyflow Metrics Server</title></head>
            <body>
            <h1>Anyflow Metrics Server</h1>
            <p><a href="/metrics">Metrics</a></p>
            </body>
            </html>`))
	})

	fmt.Printf("Listening on %s\n", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		panic(fmt.Errorf("Error starting HTTP server: %s", err))
	}
}
