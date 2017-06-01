package netflow

import (
	"net"
	//"github.com/davecgh/go-spew/spew"
)

type Netflow struct {
	Version   uint16
	Count     uint16
	SysUptime uint32
	UnixSecs  uint32
	Sequence  uint32
	SourceId  uint32
	FlowSet   FlowSet
	Field     Field
	Template  Template
}

type FlowSet struct {
	Id     uint16
	Length uint16
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
		Get9(nf, addr, p)
	}
	return nf
}

func Get9(nf *Netflow, addr *net.UDPAddr, p []byte) {
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
	nf.FlowSet.Id = uint16(p[20])<<8 + uint16(p[21])
	// check for FlowSet ID
	if nf.FlowSet.Id == 0 {
		// is Template FlowSet
		GetTemplate(nf, addr, p)
	}
	if nf.FlowSet.Id > 255 {
		Get9Data(nf, addr, p)
	}
}

func Get9Data(nf *Netflow, addr *net.UDPAddr, p []byte) {

}

func GetTemplate(nf *Netflow, addr *net.UDPAddr, p []byte) {
	nf.FlowSet.Length = uint16(p[22])<<8 + uint16(p[23])
	nf.Template.Id = uint16(p[24])<<8 + uint16(p[25])
	nf.Template.FieldCount = uint16(p[26])<<8 + uint16(p[27])

	ip := addr.IP.String()

	fields := make([]Field, nf.Template.FieldCount)

	template := &Template{
		Id:         nf.Template.Id,
		FieldCount: nf.Template.FieldCount,
		Fields:     fields,
	}

	if TemplateTable[ip] == nil {
		TemplateTable[ip] = make(map[uint16]*Template)
	}
	TemplateTable[ip][nf.Template.Id] = template

	fieldsoffset := 28 + (4 * nf.Template.FieldCount)
	payload := p[28:fieldsoffset]

	i := 0
	for c := 0; c < len(payload)-1; c += 4 {
		fields[i] = Field{
			Type:   uint16(payload[c])<<8 + uint16(payload[c+1]),
			Length: uint16(payload[c+2])<<8 + uint16(payload[c+3]),
		}
		i++
	}
	//spew.Dump(TemplateTable)
}
