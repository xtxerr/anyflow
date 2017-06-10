package netflow

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

func (nf *Netflow) GetFlows() ([]Record, error) {
	r := make([]Record, nf.Count)
	if len(nf.FlowSet) == 0 {
		return r, errors.New("No FlowSets")
	}
	for _, fs := range nf.FlowSet {
		if len(fs.Data) != 0 {
			for _, d := range fs.Data {
				r = append(r, d)
			}
		}
	}
	if len(r) == 0 {
		return r, errors.New("No data FlowSets")
	}
	return r, nil
}

func (nf *Netflow) HasFlows() bool {
	if len(nf.FlowSet) != 0 {
		for _, fs := range nf.FlowSet {
			if len(fs.Data) != 0 {
				return true
			}
		}
	}
	return false
}

func BytesToUint64(s []byte) uint64 {
	// big endian shifting
	var a uint64
	l := len(s)
	for i, b := range s {
		shift := uint64((l - i - 1) * 8)
		a |= uint64(b) << shift
	}
	return a
}
func BytesToNumber(b []byte) string {
	i := BytesToUint64(b)
	s := strconv.FormatUint(i, 10)
	return s
}
func BytesToString(b []byte) string {
	return string(b)
}
func BytesToIpv4(ip []byte) string {
	if len(ip) != 4 {
		return "<nil>"
	}
	return strconv.Itoa(int(ip[0])) + "." +
		strconv.Itoa(int(ip[1])) + "." +
		strconv.Itoa(int(ip[2])) + "." +
		strconv.Itoa(int(ip[3]))
}
func BytesToIpv6(ip []byte) string {
	if len(ip) != 16 {
		return "<nil>"
	}
	return "SOME IPV6"
}
func BytesToMac(b []byte) string {
	return "SOME MAC"
}

func (v Value) GetType() string {
	if v.Type == 0 {
		return "value has no type"
	}
	if t, ok := Nf9FieldMap[v.Type]; ok {
		return t.Type
	} else {
		return fmt.Sprint("value type ", v.Type, " is unknown")
	}
}

func (v Value) GetValue() string {
	if len(v.Value) < 1 {
		return "no value attached"
	}
	if v.Type == 0 {
		return "value is of no type"
	}
	if t, ok := Nf9FieldMap[v.Type]; ok {
		s := t.Stringify(v.Value)
		return s
	}
	return fmt.Sprint("value type ", v.Type, " is unknown")
}

func (v Value) GetLength() string {
	return ""
}

func (v Value) GetDesc() string {
	return ""
}

func New(p []byte, addr *net.UDPAddr) (*Netflow, error) {
	nf := new(Netflow)
	version := uint16(p[0])<<8 + uint16(p[1])
	if version == 9 {
		nf, err := Getv9(nf, addr, p)
		if err != nil {
			return nf, err
		}
	}
	return nf, nil
}

func Getv9(nf *Netflow, addr *net.UDPAddr, p []byte) (*Netflow, error) {
	// parse netflow header
	nf.Version = uint16(p[0])<<8 + uint16(p[1])
	nf.Count = uint16(p[2])<<8 + uint16(p[3])
	nf.SysUptime = uint32(p[4])<<24 + uint32(p[5])<<16 +
		uint32(p[6])<<8 + uint32(p[7])
	nf.UnixSecs = uint32(p[8])<<24 + uint32(p[9])<<16 +
		uint32(p[10])<<8 + uint32(p[11])
	nf.Sequence = uint32(p[12])<<24 + uint32(p[13])<<16 +
		uint32(p[14])<<8 + uint32(p[15])
	nf.SourceId = uint32(p[16])<<24 + uint32(p[17])<<16 +
		uint32(p[18])<<8 + uint32(p[19])

	// loop through FlowSets
	// payload starts at the beginning of the first FlowSet
	payload := p[20:]
	var count uint16 = 0
	for count < nf.Count {
		if len(payload) <= 4 {
			return nf, errors.New("No more payload for parsing FlowSet")
		}
		fs := new(FlowSet)
		fs.Id = uint16(payload[0])<<8 + uint16(payload[1])
		fs.Length = uint16(payload[2])<<8 + uint16(payload[3])

		switch {
		// Template FlowSet Id
		case fs.Id == 0:
			err := GetTemplates(nf, fs, payload[4:], &count, addr)
			if err != nil {
				return nf, err
			}
			//
			nf.FlowSet = append(nf.FlowSet, *fs)
			payload = payload[fs.Length:]
			continue
		// Data FlowSet Id
		case fs.Id > 255:
			err := Getv9Data(nf, fs, payload[4:], &count, addr)
			if err != nil {
				return nf, err
			}
			nf.FlowSet = append(nf.FlowSet, *fs)
			payload = payload[fs.Length:]
			continue
		// Option FlowSet Id
		case fs.Id == 1:
			// for now add empty Option FlowSet
			nf.FlowSet = append(nf.FlowSet, *fs)
			payload = payload[fs.Length:]
			count++
			fmt.Println("Option template with length: ", fs.Length)
			continue
		}
		// in case the FlowSet Id is unknown for us, add an empty one and skip the packet
		nf.FlowSet = append(nf.FlowSet, *fs)
		return nf, errors.New("FlowSet Id unknown")
	}
	return nf, nil
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
	// create record slice with size of netflow header record count
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
				offset := rm + f.Length
				v := Value{
					Value:  payload[rm:offset],
					Type:   f.Type,
					Length: f.Length,
				}
				// add value to record
				r.Values = append(r.Values, v)
				// increase the read marker
				rm += f.Length
			}
			// add record to FlowSet
			fs.Data = append(fs.Data, r)
			// record counter
			*count++
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
		// attach template to FlowSet
		fs.Template = append(fs.Template, *t)
	}
	return nil
}
