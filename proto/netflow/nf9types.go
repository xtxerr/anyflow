package netflow

type Nf9type struct {
	Type        string
	Stringify   func(b []byte) string
	Length      uint16
	Description string
}

var Nf9FieldMap = map[uint16]Nf9type{
	1:   Nf9type{Type: "IN_BYTES", Stringify: BytesToNumber},
	2:   Nf9type{Type: "IN_PKTS", Stringify: BytesToNumber},
	3:   Nf9type{Type: "FLOWS", Stringify: BytesToNumber},
	4:   Nf9type{Type: "PROTOCOL", Stringify: BytesToNumber},
	5:   Nf9type{Type: "SRC_TOS", Stringify: BytesToNumber},
	6:   Nf9type{Type: "TCP_FLAGS", Stringify: BytesToNumber},
	7:   Nf9type{Type: "L4_SRC_PORT", Stringify: BytesToNumber},
	8:   Nf9type{Type: "IPV4_SRC_ADDR", Stringify: BytesToIpv4},
	9:   Nf9type{Type: "SRC_MASK", Stringify: BytesToNumber},
	10:  Nf9type{Type: "INPUT_SNMP", Stringify: BytesToNumber},
	11:  Nf9type{Type: "L4_DST_PORT", Stringify: BytesToNumber},
	12:  Nf9type{Type: "IPV4_DST_ADDR", Stringify: BytesToIpv4},
	13:  Nf9type{Type: "DST_MASK", Stringify: BytesToNumber},
	14:  Nf9type{Type: "OUTPUT_SNMP", Stringify: BytesToNumber},
	15:  Nf9type{Type: "IPV4_NEXT_HOP", Stringify: BytesToIpv4},
	16:  Nf9type{Type: "SRC_AS", Stringify: BytesToNumber},
	17:  Nf9type{Type: "DST_AS", Stringify: BytesToNumber},
	18:  Nf9type{Type: "BGP_IPV4_NEXT_HOP", Stringify: BytesToIpv4},
	19:  Nf9type{Type: "MUL_DST_PKTS", Stringify: BytesToNumber},
	20:  Nf9type{Type: "MUL_DST_BYTES", Stringify: BytesToNumber},
	21:  Nf9type{Type: "LAST_SWITCHED", Stringify: BytesToNumber},
	22:  Nf9type{Type: "FIRST_SWITCHED", Stringify: BytesToNumber},
	23:  Nf9type{Type: "OUT_BYTES", Stringify: BytesToNumber},
	24:  Nf9type{Type: "OUT_PKTS", Stringify: BytesToNumber},
	25:  Nf9type{Type: "MIN_PKT_LNGTH", Stringify: BytesToNumber},
	26:  Nf9type{Type: "MAX_PKT_LNGTH", Stringify: BytesToNumber},
	27:  Nf9type{Type: "IPV6_SRC_ADDR", Stringify: BytesToIpv6},
	28:  Nf9type{Type: "IPV6_DST_ADDR", Stringify: BytesToIpv6},
	29:  Nf9type{Type: "IPV6_SRC_MASK", Stringify: BytesToIpv6},
	30:  Nf9type{Type: "IPV6_DST_MASK", Stringify: BytesToIpv6},
	31:  Nf9type{Type: "IPV6_FLOW_LABEL", Stringify: BytesToNumber},
	32:  Nf9type{Type: "ICMP_TYPE", Stringify: BytesToNumber},
	33:  Nf9type{Type: "MUL_IGMP_TYPE", Stringify: BytesToNumber},
	34:  Nf9type{Type: "SAMPLING_INTERVAL", Stringify: BytesToNumber},
	35:  Nf9type{Type: "SAMPLING_ALGORITHM", Stringify: BytesToNumber},
	36:  Nf9type{Type: "FLOW_ACTIVE_TIMEOUT", Stringify: BytesToNumber},
	37:  Nf9type{Type: "FLOW_INACTIVE_TIMEOUT", Stringify: BytesToNumber},
	38:  Nf9type{Type: "ENGINE_TYPE", Stringify: BytesToNumber},
	39:  Nf9type{Type: "ENGINE_ID", Stringify: BytesToNumber},
	40:  Nf9type{Type: "TOTAL_BYTES_EXP", Stringify: BytesToNumber},
	41:  Nf9type{Type: "TOTAL_PKTS_EXP", Stringify: BytesToNumber},
	42:  Nf9type{Type: "TOTAL_FLOWS_EXP", Stringify: BytesToNumber},
	44:  Nf9type{Type: "IPV4_SRC_PREFIX", Stringify: BytesToIpv4},
	45:  Nf9type{Type: "IPV4_DST_PREFIX", Stringify: BytesToIpv4},
	46:  Nf9type{Type: "MPLS_TOP_LABEL_TYPE", Stringify: BytesToNumber},
	47:  Nf9type{Type: "MPLS_TOP_LABEL_IP_ADDR", Stringify: BytesToNumber},
	48:  Nf9type{Type: "FLOW_SAMPLER_ID", Stringify: BytesToNumber},
	49:  Nf9type{Type: "FLOW_SAMPLER_MODE", Stringify: BytesToNumber},
	50:  Nf9type{Type: "FLOW_SAMPLER_RANDOM_INTERVAL", Stringify: BytesToNumber},
	52:  Nf9type{Type: "MIN_TTL", Stringify: BytesToNumber},
	53:  Nf9type{Type: "MAX_TTL", Stringify: BytesToNumber},
	54:  Nf9type{Type: "IPV4_IDENT", Stringify: BytesToIpv4},
	55:  Nf9type{Type: "DST_TOS", Stringify: BytesToNumber},
	56:  Nf9type{Type: "IN_SRC_MAC", Stringify: BytesToMac},
	57:  Nf9type{Type: "OUT_DST_MAC", Stringify: BytesToMac},
	58:  Nf9type{Type: "SRC_VLAN", Stringify: BytesToNumber},
	59:  Nf9type{Type: "DST_VLAN", Stringify: BytesToNumber},
	60:  Nf9type{Type: "IP_PROTOCOL_VERSION", Stringify: BytesToNumber},
	61:  Nf9type{Type: "DIRECTION", Stringify: BytesToNumber},
	62:  Nf9type{Type: "IPV6_NEXT_HOP", Stringify: BytesToIpv4},
	63:  Nf9type{Type: "BPG_IPV6_NEXT_HOP", Stringify: BytesToIpv6},
	64:  Nf9type{Type: "IPV6_OPTION_HEADERS", Stringify: BytesToNumber},
	70:  Nf9type{Type: "MPLS_LABEL_1", Stringify: BytesToNumber},
	71:  Nf9type{Type: "MPLS_LABEL_2", Stringify: BytesToNumber},
	72:  Nf9type{Type: "MPLS_LABEL_3", Stringify: BytesToNumber},
	73:  Nf9type{Type: "MPLS_LABEL_4", Stringify: BytesToNumber},
	74:  Nf9type{Type: "MPLS_LABEL_5", Stringify: BytesToNumber},
	75:  Nf9type{Type: "MPLS_LABEL_6", Stringify: BytesToNumber},
	76:  Nf9type{Type: "MPLS_LABEL_7", Stringify: BytesToNumber},
	77:  Nf9type{Type: "MPLS_LABEL_8", Stringify: BytesToNumber},
	78:  Nf9type{Type: "MPLS_LABEL_9", Stringify: BytesToNumber},
	79:  Nf9type{Type: "MPLS_LABEL_10", Stringify: BytesToNumber},
	80:  Nf9type{Type: "IN_DST_MAC", Stringify: BytesToMac},
	81:  Nf9type{Type: "OUT_SRC_MAC", Stringify: BytesToMac},
	82:  Nf9type{Type: "IF_NAME", Stringify: BytesToString},
	83:  Nf9type{Type: "IF_DESC", Stringify: BytesToString},
	84:  Nf9type{Type: "SAMPLER_NAME", Stringify: BytesToNumber},
	85:  Nf9type{Type: "IN_PERMANENT_BYTES", Stringify: BytesToNumber},
	86:  Nf9type{Type: "IN_PERMANENT_PKTS", Stringify: BytesToNumber},
	88:  Nf9type{Type: "FRAGMENT_OFFSET", Stringify: BytesToNumber},
	89:  Nf9type{Type: "FORWARDING_STATUS", Stringify: BytesToNumber},
	90:  Nf9type{Type: "MPLS_PAL_RD", Stringify: BytesToNumber},
	91:  Nf9type{Type: "MPLS_PREFIX_LEN", Stringify: BytesToNumber},
	92:  Nf9type{Type: "SRC_TRAFFIC_INDEX", Stringify: BytesToNumber},
	93:  Nf9type{Type: "DST_TRAFFIC_INDEX", Stringify: BytesToNumber},
	102: Nf9type{Type: "layer2packetSectionOffset", Stringify: BytesToNumber},
	103: Nf9type{Type: "layer2packetSectionSize", Stringify: BytesToNumber},
	104: Nf9type{Type: "layer2packetSectionData", Stringify: BytesToNumber},
	128: Nf9type{Type: "BGP_ADJ_NEXT_AS", Stringify: BytesToNumber},
	129: Nf9type{Type: "BGP_ADJ_PREV_AS", Stringify: BytesToNumber},
	148: Nf9type{Type: "CONN_ID", Stringify: BytesToNumber},
	152: Nf9type{Type: "FLOW_CREATE_TIME_MSEC", Stringify: BytesToNumber},
	153: Nf9type{Type: "FLOW_END_TIME_MSEC", Stringify: BytesToNumber},
	231: Nf9type{Type: "FWD_FLOW_DELTA_BYTES", Stringify: BytesToNumber},
	232: Nf9type{Type: "REV_FLOW_DELTA_BYTES", Stringify: BytesToNumber},
	323: Nf9type{Type: "EVENT_TIME_MSEC", Stringify: BytesToNumber},
	225: Nf9type{Type: "XLATE_SRC_ADDR_IPV4", Stringify: BytesToIpv4},
	226: Nf9type{Type: "XLATE_DST_ADDR_IPV4", Stringify: BytesToIpv4},
	227: Nf9type{Type: "XLATE_SRC_PORT", Stringify: BytesToNumber},
	228: Nf9type{Type: "XLATE_DST_PORT", Stringify: BytesToNumber},
	281: Nf9type{Type: "XLATE_SRC_ADDR_IPV6", Stringify: BytesToIpv6},
	282: Nf9type{Type: "XLATE_DST_ADDR_IPV6", Stringify: BytesToIpv6},
	233: Nf9type{Type: "FW_EVENT", Stringify: BytesToNumber},
	230: Nf9type{Type: "NAT_EVENT", Stringify: BytesToNumber},
	234: Nf9type{Type: "INGRESS_VRFID", Stringify: BytesToNumber},
	235: Nf9type{Type: "EGRESS_VRFID", Stringify: BytesToNumber},
	361: Nf9type{Type: "XLATE_PORT_BLOCK_START", Stringify: BytesToNumber},
	362: Nf9type{Type: "XLATE_PORT_BLOCK_END", Stringify: BytesToNumber},
	363: Nf9type{Type: "XLATE_PORT_BLOCK_STEP", Stringify: BytesToNumber},
	364: Nf9type{Type: "XLATE_PORT_BLOCK_SIZE", Stringify: BytesToNumber},
}

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
	Data     []Record
	Padding  []byte
}
type Record struct {
	Values []Value
}
type Value struct {
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

var TemplateTable = make(map[string]map[uint16]*Template)
