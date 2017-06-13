package main

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"

	log "github.com/Sirupsen/logrus"

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
		log.Fatalf("Error: ", err)
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

func receivePackets(c *net.UDPConn) {
	buf := make([]byte, 9000)

	for {
		n, addr, err := c.ReadFromUDP(buf)
		if err != nil {
			log.Errorf("Error: ", err)
			continue
		}

		packetSourceIP := addr.IP.String()
		packetsTotal.WithLabelValues(packetSourceIP).Inc()
		log.Infof("Packet source: ", packetSourceIP)

		p, err := Parse(buf[:n], addr)
		if err != nil {
			log.Errorf("Error parsing packet: ", err)
			continue
		}

		switch p.Proto {
		case "nf9":
			nf, err := netflow.New(p.Raw, p.Saddr)
			if err != nil {
				log.Errorf("Error parsing netflow nf9 packet: ", err)
				continue
			}

			if !nf.HasFlows() {
				log.Debug("No flows in nf9 packet")
				continue
			}

			records, err := nf.GetFlows()
			if err != nil {
				log.Errorf("Error getting flows from packet: ", err)
				continue
			}

			log.Infof("Number of flow packet records: ", len(records))

			for i, r := range records {
				for _, v := range r.Values {
					log.Infof("Flow record: %d type: %v value: %v", i, v.GetType(), v.GetValue())
				}
			}
		}
	}
}

func init() {
	log.SetFormatter(&log.TextFormatter{})
	log.SetOutput(os.Stdout)
	log.SetLevel(log.DebugLevel)

	prometheus.MustRegister(packetsTotal)
}

func main() {
	httpListenAddress := ":8080"
	flowListenAddress := ":10001"

	log.Infof("Flow listening on %s", flowListenAddress)
	ServerAddr, err := net.ResolveUDPAddr("udp", flowListenAddress)
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

	log.Infof("HTTP listening on %s", httpListenAddress)
	if err := http.ListenAndServe(httpListenAddress, nil); err != nil {
		panic(fmt.Errorf("Error starting HTTP server: %s", err))
	}
}
