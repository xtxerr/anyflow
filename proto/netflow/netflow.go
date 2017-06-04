package netflow

import (
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
	FieldValue []byte
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
		fmt.Println(len(payload))
		fs.Id = uint16(payload[0])<<8 + uint16(payload[1])
		fs.Length = uint16(payload[2])<<8 + uint16(payload[3])

		// check for FlowSet ID
		switch {
		case fs.Id == '0':
			// Template FlowSet
			GetTemplates(nf, fs, payload[4:], &count, addr)
		case fs.Id > 255:
			// Data FlowSet
			// only to skip panic at the moment
			Getv9Data(nf, fs, payload, &count, addr)
		}
		payload = payload[fs.Length:]
	}
}

func Getv9Data(nf *Netflow, fs *FlowSet, payload []byte, count *uint16, addr *net.UDPAddr) {

}

func GetTemplates(nf *Netflow, fs *FlowSet, payload []byte, count *uint16, addr *net.UDPAddr) {
	// payload starts at beginning of the first template

	ip := addr.IP.String()
	// template starting byte from payload
	ts := uint16(0)
	// loop through Templates
	for ts < fs.Length {
		t := new(Template)

		t.Id = uint16(payload[ts+0])<<8 + uint16(payload[ts+1])
		t.FieldCount = uint16(payload[ts+2])<<8 + uint16(payload[ts+3])
		t.Fields = make([]Field, t.FieldCount)

		if TemplateTable[ip] == nil {
			TemplateTable[ip] = make(map[uint16]*Template)
		}
		TemplateTable[ip][t.Id] = t

		offset := ts + (4 * t.FieldCount)
		for i := 0; ts < offset; ts += 4 {
			t.Fields[i] = Field{
				Type:   uint16(payload[ts+4])<<8 + uint16(payload[ts+5]),
				Length: uint16(payload[ts+6])<<8 + uint16(payload[ts+7]),
			}
			i++
		}
		*count++
	}
}
