package netflow

type Nf9type struct {
	Type        string
	Stringify   func(b []byte) string
	Length      uint16
	Description string
}

var Nf9FieldMap = map[uint16]Nf9type{
	1:     Nf9type{Type: "IN_BYTES", Stringify: Decimal},
	2:     Nf9type{Type: "IN_PKTS", Stringify: Decimal},
	3:     Nf9type{Type: "FLOWS", Stringify: Decimal},
	4:     Nf9type{Type: "PROTOCOL", Stringify: Decimal},
	5:     Nf9type{Type: "SRC_TOS", Stringify: Decimal},
	6:     Nf9type{Type: "TCP_FLAGS", Stringify: Decimal},
	7:     Nf9type{Type: "L4_SRC_PORT", Stringify: Decimal},
	8:     Nf9type{Type: "IPV4_SRC_ADDR", Stringify: IPv4addr},
	9:     Nf9type{Type: "SRC_MASK", Stringify: Decimal},
	10:    Nf9type{Type: "INPUT_SNMP", Stringify: Decimal},
	11:    Nf9type{Type: "L4_DST_PORT", Stringify: Decimal},
	12:    Nf9type{Type: "IPV4_DST_ADDR", Stringify: IPv4addr},
	13:    Nf9type{Type: "DST_MASK", Stringify: Decimal},
	14:    Nf9type{Type: "OUTPUT_SNMP", Stringify: Decimal},
	15:    Nf9type{Type: "IPV4_NEXT_HOP", Stringify: IPv4addr},
	16:    Nf9type{Type: "SRC_AS", Stringify: Decimal},
	17:    Nf9type{Type: "DST_AS", Stringify: Decimal},
	18:    Nf9type{Type: "BGP_IPV4_NEXT_HOP", Stringify: IPv4addr},
	19:    Nf9type{Type: "MUL_DST_PKTS", Stringify: Decimal},
	20:    Nf9type{Type: "MUL_DST_BYTES", Stringify: Decimal},
	21:    Nf9type{Type: "LAST_SWITCHED", Stringify: Decimal},
	22:    Nf9type{Type: "FIRST_SWITCHED", Stringify: Decimal},
	23:    Nf9type{Type: "OUT_BYTES", Stringify: Decimal},
	24:    Nf9type{Type: "OUT_PKTS", Stringify: Decimal},
	25:    Nf9type{Type: "MIN_PKT_LNGTH", Stringify: Decimal},
	26:    Nf9type{Type: "MAX_PKT_LNGTH", Stringify: Decimal},
	27:    Nf9type{Type: "IPV6_SRC_ADDR", Stringify: IPv6addr},
	28:    Nf9type{Type: "IPV6_DST_ADDR", Stringify: IPv6addr},
	29:    Nf9type{Type: "IPV6_SRC_MASK", Stringify: IPv6addr},
	30:    Nf9type{Type: "IPV6_DST_MASK", Stringify: IPv6addr},
	31:    Nf9type{Type: "IPV6_FLOW_LABEL", Stringify: Decimal},
	32:    Nf9type{Type: "ICMP_TYPE", Stringify: Decimal},
	33:    Nf9type{Type: "MUL_IGMP_TYPE", Stringify: Decimal},
	34:    Nf9type{Type: "SAMPLING_INTERVAL", Stringify: Decimal},
	35:    Nf9type{Type: "SAMPLING_ALGORITHM", Stringify: Decimal},
	36:    Nf9type{Type: "FLOW_ACTIVE_TIMEOUT", Stringify: Decimal},
	37:    Nf9type{Type: "FLOW_INACTIVE_TIMEOUT", Stringify: Decimal},
	38:    Nf9type{Type: "ENGINE_TYPE", Stringify: Decimal},
	39:    Nf9type{Type: "ENGINE_ID", Stringify: Decimal},
	40:    Nf9type{Type: "TOTAL_BYTES_EXP", Stringify: Decimal},
	41:    Nf9type{Type: "TOTAL_PKTS_EXP", Stringify: Decimal},
	42:    Nf9type{Type: "TOTAL_FLOWS_EXP", Stringify: Decimal},
	44:    Nf9type{Type: "IPV4_SRC_PREFIX", Stringify: IPv4addr},
	45:    Nf9type{Type: "IPV4_DST_PREFIX", Stringify: IPv4addr},
	46:    Nf9type{Type: "MPLS_TOP_LABEL_TYPE", Stringify: Decimal},
	47:    Nf9type{Type: "MPLS_TOP_LABEL_IP_ADDR", Stringify: Decimal},
	48:    Nf9type{Type: "FLOW_SAMPLER_ID", Stringify: Decimal},
	49:    Nf9type{Type: "FLOW_SAMPLER_MODE", Stringify: Decimal},
	50:    Nf9type{Type: "FLOW_SAMPLER_RANDOM_INTERVAL", Stringify: Decimal},
	52:    Nf9type{Type: "MIN_TTL", Stringify: Decimal},
	53:    Nf9type{Type: "MAX_TTL", Stringify: Decimal},
	54:    Nf9type{Type: "IPV4_IDENT", Stringify: IPv4addr},
	55:    Nf9type{Type: "DST_TOS", Stringify: Decimal},
	56:    Nf9type{Type: "IN_SRC_MAC", Stringify: MAC},
	57:    Nf9type{Type: "OUT_DST_MAC", Stringify: MAC},
	58:    Nf9type{Type: "SRC_VLAN", Stringify: Decimal},
	59:    Nf9type{Type: "DST_VLAN", Stringify: Decimal},
	60:    Nf9type{Type: "IP_PROTOCOL_VERSION", Stringify: Decimal},
	61:    Nf9type{Type: "DIRECTION", Stringify: Decimal},
	62:    Nf9type{Type: "IPV6_NEXT_HOP"},
	63:    Nf9type{Type: "BPG_IPV6_NEXT_HOP"},
	64:    Nf9type{Type: "IPV6_OPTION_HEADERS"},
	70:    Nf9type{Type: "MPLS_LABEL_1"},
	71:    Nf9type{Type: "MPLS_LABEL_2"},
	72:    Nf9type{Type: "MPLS_LABEL_3"},
	73:    Nf9type{Type: "MPLS_LABEL_4"},
	74:    Nf9type{Type: "MPLS_LABEL_5"},
	75:    Nf9type{Type: "MPLS_LABEL_6"},
	76:    Nf9type{Type: "MPLS_LABEL_7"},
	77:    Nf9type{Type: "MPLS_LABEL_8"},
	78:    Nf9type{Type: "MPLS_LABEL_9"},
	79:    Nf9type{Type: "MPLS_LABEL_10"},
	80:    Nf9type{Type: "IN_DST_MAC"},
	81:    Nf9type{Type: "OUT_SRC_MAC"},
	82:    Nf9type{Type: "IF_NAME"},
	83:    Nf9type{Type: "IF_DESC"},
	84:    Nf9type{Type: "SAMPLER_NAME"},
	85:    Nf9type{Type: "IN_PERMANENT_BYTES"},
	86:    Nf9type{Type: "IN_PERMANENT_PKTS"},
	88:    Nf9type{Type: "FRAGMENT_OFFSET"},
	89:    Nf9type{Type: "FORWARDING_STATUS"},
	90:    Nf9type{Type: "MPLS_PAL_RD"},
	91:    Nf9type{Type: "MPLS_PREFIX_LEN"},
	92:    Nf9type{Type: "SRC_TRAFFIC_INDEX"},
	93:    Nf9type{Type: "DST_TRAFFIC_INDEX"},
	102:   Nf9type{Type: "layer2packetSectionOffset"},
	103:   Nf9type{Type: "layer2packetSectionSize"},
	104:   Nf9type{Type: "layer2packetSectionData"},
	128:   Nf9type{Type: "BGP_ADJ_NEXT_AS"},
	129:   Nf9type{Type: "BGP_ADJ_PREV_AS"},
	148:   Nf9type{Type: "CONN_ID"},
	152:   Nf9type{Type: "FLOW_CREATE_TIME_MSEC"},
	153:   Nf9type{Type: "FLOW_END_TIME_MSEC"},
	231:   Nf9type{Type: "FWD_FLOW_DELTA_BYTES"},
	232:   Nf9type{Type: "REV_FLOW_DELTA_BYTES"},
	323:   Nf9type{Type: "EVENT_TIME_MSEC"},
	225:   Nf9type{Type: "XLATE_SRC_ADDR_IPV4"},
	226:   Nf9type{Type: "XLATE_DST_ADDR_IPV4"},
	227:   Nf9type{Type: "XLATE_SRC_PORT"},
	228:   Nf9type{Type: "XLATE_DST_PORT"},
	281:   Nf9type{Type: "XLATE_SRC_ADDR_IPV6"},
	282:   Nf9type{Type: "XLATE_DST_ADDR_IPV6"},
	233:   Nf9type{Type: "FW_EVENT"},
	230:   Nf9type{Type: "NAT_EVENT"},
	234:   Nf9type{Type: "INGRESS_VRFID"},
	235:   Nf9type{Type: "EGRESS_VRFID"},
	361:   Nf9type{Type: "XLATE_PORT_BLOCK_START"},
	362:   Nf9type{Type: "XLATE_PORT_BLOCK_END"},
	363:   Nf9type{Type: "XLATE_PORT_BLOCK_STEP"},
	364:   Nf9type{Type: "XLATE_PORT_BLOCK_SIZE"},
	33000: Nf9type{Type: "INGRESS_ACL_ID"},
	33001: Nf9type{Type: "EGRESS_ACL_ID"},
	33002: Nf9type{Type: "FW_EXT_EVENT"},
	40000: Nf9type{Type: "USERNAME"},
	40001: Nf9type{Type: "XLATE_SRC_ADDR_84"},
	40002: Nf9type{Type: "XLATE_DST_ADDR_84"},
	40003: Nf9type{Type: "XLATE_SRC_PORT_84"},
	40004: Nf9type{Type: "XLATE_DST_PORT_84"},
	40005: Nf9type{Type: "FW_EVENT_84"},
	57554: Nf9type{Type: "NPROBE_CLIENT_NW_DELAY_SEC"},
	57555: Nf9type{Type: "NPROBE_CLIENT_NW_DELAY_USEC"},
	57556: Nf9type{Type: "NPROBE_SERVER_NW_DELAY_SEC"},
	57557: Nf9type{Type: "NPROBE_SERVER_NW_DELAY_USEC"},
	57558: Nf9type{Type: "NPROBE_APPL_LATENCY_SEC"},
	57559: Nf9type{Type: "NPROBE_APPL_LATENCY_USEC"},
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
