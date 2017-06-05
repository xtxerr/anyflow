package netflow

import (
	"errors"
	"fmt"
	"net"
)

// used as template cache
var TemplateTable = make(map[string]map[uint16]*Template)

func Get(p []byte, addr *net.UDPAddr) (*Netflow, error) {
	nf := new(Netflow)
	version := uint16(p[0])<<8 + uint16(p[1])
	if version == 9 {
		err := Getv9(nf, addr, p)
		if err != nil {
			return nf, err
		}
	}
	return nf, nil
}

func Getv9(nf *Netflow, addr *net.UDPAddr, p []byte) error {
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
		if len(payload) <= 4 {
			return errors.New("No payload in flowset")
		}
		fs := new(FlowSet)
		fs.Id = uint16(payload[0])<<8 + uint16(payload[1])
		fs.Length = uint16(payload[2])<<8 + uint16(payload[3])

		switch {
		// Temlate FlowSet Id
		case fs.Id == 0:
			err := GetTemplates(nf, fs, payload[4:], &count, addr)
			if err != nil {
				return err
			}
			payload = payload[fs.Length:]
			continue
		// Data FlowSet Id
		case fs.Id > 255:
			err := Getv9Data(nf, fs, payload, &count, addr)
			if err != nil {
				return err
			}
			payload = payload[fs.Length:]
			continue
		}
		// in case the FlowSet Id is not defined here, the packet is complete skipped
		return nil
	}
	return nil
}

func Getv9Data(nf *Netflow, fs *FlowSet, payload []byte, count *uint16, addr *net.UDPAddr) error {
	// we need the sender IP for template cache lookup
	ip := addr.IP.String()
	// return immediately if no template for the FlowSet Id exists
	t, ok := TemplateTable[ip][fs.Id]
	if !ok {
		return fmt.Errorf(
			"Haven't seen NF9 template for data flowset from host %v with Id %v yet",
			ip, fs.Id)
	}
	if len(payload) <= 4 {
		return errors.New("No payload in data")
	}
	// byte size of one complete record with all values
	var size int
	for f := range t.Fields {
		size += f.Length
	}
	// ds = data starting byte from payload
	ds := uint16(0)
	// payload length of data without FlowSet header
	length := fs.Length - 4
	// loop through records
	for ds < (fs.Length - 4) {
		// check if payload left is large enough for possible records
		if size >= (length - ds) {
			// create Record with length of defined types in template
			r = make([]Record, len(t.Fields))

			for f := range t.Fields {
				v := new(Value)
				v.Value = payload[ds:f.Length]
				v.Type = payload[ds:f.Type]
				v.Length = f.Length
				r = append(r, v)
			}
		}
	}
	return nil
}

func GetTemplates(nf *Netflow, fs *FlowSet, payload []byte, count *uint16, addr *net.UDPAddr) error {
	// we need the sender IP for template cache lookup
	ip := addr.IP.String()
	// ts = template starting byte from payload
	ts := uint16(0)
	// loop through Templates (subtracting 4 bytes for the FlowSet header)
	for ts < (fs.Length - 4) {

		if len(payload) <= 4 {
			return errors.New("No payload in template")
		}

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
			if len(payload) <= 4 {
				return errors.New("No payload in template fields")
			}
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
	return nil
}
