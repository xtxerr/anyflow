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
				fmt.Println(err)
				return err
			}
			payload = payload[fs.Length:]
			continue
		// Data FlowSet Id
		case fs.Id > 255:
			err := Getv9Data(nf, fs, payload[4:], &count, addr)
			if err != nil {
				fmt.Println(err)
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
			"Haven't seen NF9 template for data FlowSet from host %v with Id %v yet",
			ip, fs.Id)
	}
	if len(payload) <= 4 {
		return errors.New("No payload in data FlowSet")
	}
	// byte size of one complete record with all values
	var rsize uint16
	for _, f := range t.Fields {
		rsize += f.Length
	}
	// create a slice of data records
	fs.Data = make([]Record, nf.Count)
	// read marker
	rm := uint16(0)
	// payload length of data without FlowSet header
	length := fs.Length - 4
	// loop through records
	for rm < length {
		if rsize <= (length - rm) {
			// create record with template field amount
			r := Record{
				Values: make([]Value, len(t.Fields)),
			}
			for _, f := range t.Fields {
				v := Value{
					Value:  payload[rm : rm+f.Length-1],
					Type:   f.Type,
					Length: f.Length,
				}
				// add value to record
				r.Values = append(r.Values, v)
				// increase the read marker
				rm += f.Length
				// record counter
				*count++
			}
			// add record to FlowSet
			fs.Data = append(fs.Data, r)
		} else {
			// useless padding bytes
			fs.Padding = payload[rm:length]
			return nil
		}
	}
	return nil
}

func GetTemplates(nf *Netflow, fs *FlowSet, payload []byte, count *uint16, addr *net.UDPAddr) error {
	// we need the sender IP for template cache lookup
	ip := addr.IP.String()
	// read marker
	rm := uint16(0)
	// loop through Templates (subtracting 4 bytes for the FlowSet header)
	for rm < (fs.Length - 4) {

		if len(payload) <= 4 {
			return errors.New("No payload in template")
		}

		t := new(Template)

		t.Id = uint16(payload[rm+0])<<8 + uint16(payload[rm+1])
		t.FieldCount = uint16(payload[rm+2])<<8 + uint16(payload[rm+3])
		t.Fields = make([]Field, t.FieldCount)
		// set read marker + 4 bytes for template ID and Count header
		rm += 4

		if TemplateTable[ip] == nil {
			TemplateTable[ip] = make(map[uint16]*Template)
		}
		TemplateTable[ip][t.Id] = t

		fmt.Println("template id: ", t.Id)
		fmt.Println("template fieldcount: ", t.FieldCount)

		offset := rm + (4 * t.FieldCount)
		for i := 0; rm < offset; rm += 4 {
			if len(payload) <= 4 {
				return errors.New("No payload in template fields")
			}
			t.Fields[i] = Field{
				Type:   uint16(payload[rm])<<8 + uint16(payload[rm+1]),
				Length: uint16(payload[rm+2])<<8 + uint16(payload[rm+3]),
			}
			i++
		}
		// record counter
		*count++
		fmt.Println("fields ", t.Fields)
		fmt.Println("ip: ", ip)
	}
	return nil
}
