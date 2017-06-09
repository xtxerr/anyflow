package netflow

type Nf9type struct {
	Type        string
	Stringify   func(b []byte) string
	Length      uint16
	Description string
}

var Nf9FieldMap = map[uint16]Nf9type{
	1:   Nf9type{Type: "IN_BYTES", Stringify: Decimal},
	2:   Nf9type{Type: "IN_PKTS", Stringify: Decimal},
	3:   Nf9type{Type: "FLOWS", Stringify: Decimal},
	4:   Nf9type{Type: "PROTOCOL", Stringify: Decimal},
	5:   Nf9type{Type: "SRC_TOS", Stringify: Decimal},
	6:   Nf9type{Type: "TCP_FLAGS", Stringify: Decimal},
	7:   Nf9type{Type: "L4_SRC_PORT", Stringify: Decimal},
	8:   Nf9type{Type: "IPV4_SRC_ADDR", Stringify: IPv4addr},
	9:   Nf9type{Type: "SRC_MASK", Stringify: Decimal},
	10:  Nf9type{Type: "INPUT_SNMP", Stringify: Decimal},
	11:  Nf9type{Type: "L4_DST_PORT", Stringify: Decimal},
	12:  Nf9type{Type: "IPV4_DST_ADDR", Stringify: IPv4addr},
	13:  Nf9type{Type: "DST_MASK", Stringify: Decimal},
	14:  Nf9type{Type: "OUTPUT_SNMP", Stringify: Decimal},
	15:  Nf9type{Type: "IPV4_NEXT_HOP", Stringify: IPv4addr},
	16:  Nf9type{Type: "SRC_AS", Stringify: Decimal},
	17:  Nf9type{Type: "DST_AS", Stringify: Decimal},
	18:  Nf9type{Type: "BGP_IPV4_NEXT_HOP", Stringify: IPv4addr},
	19:  Nf9type{Type: "MUL_DST_PKTS", Stringify: Decimal},
	20:  Nf9type{Type: "MUL_DST_BYTES", Stringify: Decimal},
	21:  Nf9type{Type: "LAST_SWITCHED", Stringify: Decimal},
	22:  Nf9type{Type: "FIRST_SWITCHED", Stringify: Decimal},
	23:  Nf9type{Type: "OUT_BYTES", Stringify: Decimal},
	24:  Nf9type{Type: "OUT_PKTS", Stringify: Decimal},
	25:  Nf9type{Type: "MIN_PKT_LNGTH", Stringify: Decimal},
	26:  Nf9type{Type: "MAX_PKT_LNGTH", Stringify: Decimal},
	27:  Nf9type{Type: "IPV6_SRC_ADDR", Stringify: IPv6addr},
	28:  Nf9type{Type: "IPV6_DST_ADDR", Stringify: IPv6addr},
	29:  Nf9type{Type: "IPV6_SRC_MASK", Stringify: IPv6addr},
	30:  Nf9type{Type: "IPV6_DST_MASK", Stringify: IPv6addr},
	31:  Nf9type{Type: "IPV6_FLOW_LABEL", Stringify: Decimal},
	32:  Nf9type{Type: "ICMP_TYPE", Stringify: Decimal},
	33:  Nf9type{Type: "MUL_IGMP_TYPE", Stringify: Decimal},
	34:  Nf9type{Type: "SAMPLING_INTERVAL", Stringify: Decimal},
	35:  Nf9type{Type: "SAMPLING_ALGORITHM", Stringify: Decimal},
	36:  Nf9type{Type: "FLOW_ACTIVE_TIMEOUT", Stringify: Decimal},
	37:  Nf9type{Type: "FLOW_INACTIVE_TIMEOUT", Stringify: Decimal},
	38:  Nf9type{Type: "ENGINE_TYPE", Stringify: Decimal},
	39:  Nf9type{Type: "ENGINE_ID", Stringify: Decimal},
	40:  Nf9type{Type: "TOTAL_BYTES_EXP", Stringify: Decimal},
	41:  Nf9type{Type: "TOTAL_PKTS_EXP", Stringify: Decimal},
	42:  Nf9type{Type: "TOTAL_FLOWS_EXP", Stringify: Decimal},
	44:  Nf9type{Type: "IPV4_SRC_PREFIX", Stringify: IPv4addr},
	45:  Nf9type{Type: "IPV4_DST_PREFIX", Stringify: IPv4addr},
	46:  Nf9type{Type: "MPLS_TOP_LABEL_TYPE", Stringify: Decimal},
	47:  Nf9type{Type: "MPLS_TOP_LABEL_IP_ADDR", Stringify: Decimal},
	48:  Nf9type{Type: "FLOW_SAMPLER_ID", Stringify: Decimal},
	49:  Nf9type{Type: "FLOW_SAMPLER_MODE", Stringify: Decimal},
	50:  Nf9type{Type: "FLOW_SAMPLER_RANDOM_INTERVAL", Stringify: Decimal},
	52:  Nf9type{Type: "MIN_TTL", Stringify: Decimal},
	53:  Nf9type{Type: "MAX_TTL", Stringify: Decimal},
	54:  Nf9type{Type: "IPV4_IDENT", Stringify: IPv4addr},
	55:  Nf9type{Type: "DST_TOS", Stringify: Decimal},
	56:  Nf9type{Type: "IN_SRC_MAC", Stringify: MAC},
	57:  Nf9type{Type: "OUT_DST_MAC", Stringify: MAC},
	58:  Nf9type{Type: "SRC_VLAN", Stringify: Decimal},
	59:  Nf9type{Type: "DST_VLAN", Stringify: Decimal},
	60:  Nf9type{Type: "IP_PROTOCOL_VERSION", Stringify: Decimal},
	61:  Nf9type{Type: "DIRECTION", Stringify: Decimal},
	62:  Nf9type{Type: "IPV6_NEXT_HOP", Stringify: IPv4addr},
	63:  Nf9type{Type: "BPG_IPV6_NEXT_HOP", Stringify: IPv6addr},
	64:  Nf9type{Type: "IPV6_OPTION_HEADERS", Stringify: Decimal},
	70:  Nf9type{Type: "MPLS_LABEL_1", Stringify: Decimal},
	71:  Nf9type{Type: "MPLS_LABEL_2", Stringify: Decimal},
	72:  Nf9type{Type: "MPLS_LABEL_3", Stringify: Decimal},
	73:  Nf9type{Type: "MPLS_LABEL_4", Stringify: Decimal},
	74:  Nf9type{Type: "MPLS_LABEL_5", Stringify: Decimal},
	75:  Nf9type{Type: "MPLS_LABEL_6", Stringify: Decimal},
	76:  Nf9type{Type: "MPLS_LABEL_7", Stringify: Decimal},
	77:  Nf9type{Type: "MPLS_LABEL_8", Stringify: Decimal},
	78:  Nf9type{Type: "MPLS_LABEL_9", Stringify: Decimal},
	79:  Nf9type{Type: "MPLS_LABEL_10", Stringify: Decimal},
	80:  Nf9type{Type: "IN_DST_MAC", Stringify: MAC},
	81:  Nf9type{Type: "OUT_SRC_MAC", Stringify: MAC},
	82:  Nf9type{Type: "IF_NAME", Stringify: Decimal},
	83:  Nf9type{Type: "IF_DESC", Stringify: Decimal},
	84:  Nf9type{Type: "SAMPLER_NAME", Stringify: Decimal},
	85:  Nf9type{Type: "IN_PERMANENT_BYTES", Stringify: Decimal},
	86:  Nf9type{Type: "IN_PERMANENT_PKTS", Stringify: Decimal},
	88:  Nf9type{Type: "FRAGMENT_OFFSET", Stringify: Decimal},
	89:  Nf9type{Type: "FORWARDING_STATUS", Stringify: Decimal},
	90:  Nf9type{Type: "MPLS_PAL_RD", Stringify: Decimal},
	91:  Nf9type{Type: "MPLS_PREFIX_LEN", Stringify: Decimal},
	92:  Nf9type{Type: "SRC_TRAFFIC_INDEX", Stringify: Decimal},
	93:  Nf9type{Type: "DST_TRAFFIC_INDEX", Stringify: Decimal},
	102: Nf9type{Type: "layer2packetSectionOffset", Stringify: Decimal},
	103: Nf9type{Type: "layer2packetSectionSize", Stringify: Decimal},
	104: Nf9type{Type: "layer2packetSectionData", Stringify: Decimal},
	128: Nf9type{Type: "BGP_ADJ_NEXT_AS", Stringify: Decimal},
	129: Nf9type{Type: "BGP_ADJ_PREV_AS", Stringify: Decimal},
	148: Nf9type{Type: "CONN_ID", Stringify: Decimal},
	152: Nf9type{Type: "FLOW_CREATE_TIME_MSEC", Stringify: Decimal},
	153: Nf9type{Type: "FLOW_END_TIME_MSEC", Stringify: Decimal},
	231: Nf9type{Type: "FWD_FLOW_DELTA_BYTES", Stringify: Decimal},
	232: Nf9type{Type: "REV_FLOW_DELTA_BYTES", Stringify: Decimal},
	323: Nf9type{Type: "EVENT_TIME_MSEC", Stringify: Decimal},
	225: Nf9type{Type: "XLATE_SRC_ADDR_IPV4", Stringify: IPv4addr},
	226: Nf9type{Type: "XLATE_DST_ADDR_IPV4", Stringify: IPv4addr},
	227: Nf9type{Type: "XLATE_SRC_PORT", Stringify: Decimal},
	228: Nf9type{Type: "XLATE_DST_PORT", Stringify: Decimal},
	281: Nf9type{Type: "XLATE_SRC_ADDR_IPV6", Stringify: IPv6addr},
	282: Nf9type{Type: "XLATE_DST_ADDR_IPV6", Stringify: IPv6addr},
	233: Nf9type{Type: "FW_EVENT", Stringify: Decimal},
	230: Nf9type{Type: "NAT_EVENT", Stringify: Decimal},
	234: Nf9type{Type: "INGRESS_VRFID", Stringify: Decimal},
	235: Nf9type{Type: "EGRESS_VRFID", Stringify: Decimal},
	361: Nf9type{Type: "XLATE_PORT_BLOCK_START", Stringify: Decimal},
	362: Nf9type{Type: "XLATE_PORT_BLOCK_END", Stringify: Decimal},
	363: Nf9type{Type: "XLATE_PORT_BLOCK_STEP", Stringify: Decimal},
	364: Nf9type{Type: "XLATE_PORT_BLOCK_SIZE", Stringify: Decimal},
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
