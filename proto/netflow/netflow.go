package netflow

import (
	"errors"
	"fmt"
	"net"
)

type Netflow struct {
	Version   uint16
	Count     uint16
	SysUptime uint32
	UnixSecs  uint32
	Sequence  uint32
	SourceId  uint32
	FlowSet   []FlowSet
}

type FlowSet struct {
	Id       uint16
	Length   uint16
	Template []Template
	Data     Records
}
type Records struct {
	Record  []Record
	Padding []byte
}
type Record struct {
	Value       []byte
	Type        uint16
	Length      uint16
	Description string
}
type Template struct {
	Id         uint16
	FieldCount uint16
	Fields     []Field
}
type Field struct {
	Type   uint16
	Length uint16
}

// used as template cache
var TemplateTable = make(map[string]map[uint16]*Template)

func Get(p []byte, addr *net.UDPAddr) *Netflow {
	nf := new(Netflow)
	version := uint16(p[0])<<8 + uint16(p[1])
	if version == 9 {
		Getv9(nf, addr, p)
	}
	return nf
}

func Getv9(nf *Netflow, addr *net.UDPAddr, p []byte) {
	// version
	nf.Version = uint16(p[0])<<8 + uint16(p[1])
	// count
	nf.Count = uint16(p[2])<<8 + uint16(p[3])
	// sysuptime
	nf.SysUptime = uint32(p[4])<<24 + uint32(p[5])<<16 +
		uint32(p[6])<<8 + uint32(p[7])
	// unixsecs
	nf.UnixSecs = uint32(p[8])<<24 + uint32(p[9])<<16 +
		uint32(p[10])<<8 + uint32(p[11])
	// sequence number
	nf.Sequence = uint32(p[12])<<24 + uint32(p[13])<<16 +
		uint32(p[14])<<8 + uint32(p[15])
	// sourceid
	nf.SourceId = uint32(p[16])<<24 + uint32(p[17])<<16 +
		uint32(p[18])<<8 + uint32(p[19])

	// loop through FlowSets
	// payload starts at the beginning of the first FlowSet
	payload := p[20:]
	var count uint16 = 0
	for count < nf.Count {
		fs := new(FlowSet)
		fs.Id = uint16(payload[0])<<8 + uint16(payload[1])
		fs.Length = uint16(payload[2])<<8 + uint16(payload[3])

		switch {
		case fs.Id == 0:
			GetTemplates(nf, fs, payload[4:], &count, addr)
			payload = payload[fs.Length:]
			continue
		case fs.Id > 255:
			err := Getv9Data(nf, fs, payload, &count, addr)
			payload = payload[fs.Length:]
			continue
		}
		count = nf.Count
		payload = payload[fs.Length:]
	}
}

func Getv9Data(nf *Netflow, fs *FlowSet, payload []byte, count *uint16, addr *net.UDPAddr) error {
	// payload starts at beginning of first data record
	ip := addr.IP.String()
	// return immediately if no template for the FlowSet Id exists
	if _, ok := TemplateTable[ip][fs.Id]; !ok {
		return errors.New(fmt.Sprintf("Haven't seen NF9 template for data flowset from host %v with Id %v yet", ip, fs.Id))
	}
}

func GetTemplates(nf *Netflow, fs *FlowSet, payload []byte, count *uint16, addr *net.UDPAddr) {
	// payload starts at beginning of the first template
	ip := addr.IP.String()
	// ts = template starting byte from payload
	ts := uint16(0)
	// loop through Templates (subtracting 4 bytes for the FlowSet header)
	for ts < (fs.Length - 4) {
		t := new(Template)

		t.Id = uint16(payload[ts+0])<<8 + uint16(payload[ts+1])
		t.FieldCount = uint16(payload[ts+2])<<8 + uint16(payload[ts+3])
		t.Fields = make([]Field, t.FieldCount)
		// set ts + 4 bytes for template ID and Count header
		ts += 4

		if TemplateTable[ip] == nil {
			TemplateTable[ip] = make(map[uint16]*Template)
		}
		TemplateTable[ip][t.Id] = t

		fmt.Println("template id: ", t.Id)
		fmt.Println("template fieldcount: ", t.FieldCount)

		offset := ts + (4 * t.FieldCount)
		for i := 0; ts < offset; ts += 4 {
			t.Fields[i] = Field{
				Type:   uint16(payload[ts])<<8 + uint16(payload[ts+1]),
				Length: uint16(payload[ts+2])<<8 + uint16(payload[ts+3]),
			}
			i++
		}
		*count++
		fmt.Println("fields ", t.Fields)
		fmt.Println("ip: ", ip)
	}
}
