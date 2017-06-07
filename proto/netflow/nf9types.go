package netflow

const (
	IN_BYTES                     uint16 = 1
	IN_PKTS                      uint16 = 2
	FLOWS                        uint16 = 3
	PROTOCOL                     uint16 = 4
	SRC_TOS                      uint16 = 5
	TCP_FLAGS                    uint16 = 6
	L4_SRC_PORT                  uint16 = 7
	IPV4_SRC_ADDR                uint16 = 8
	SRC_MASK                     uint16 = 9
	INPUT_SNMP                   uint16 = 10
	L4_DST_PORT                  uint16 = 11
	IPV4_DST_ADDR                uint16 = 12
	DST_MASK                     uint16 = 13
	OUTPUT_SNMP                  uint16 = 14
	IPV4_NEXT_HOP                uint16 = 15
	SRC_AS                       uint16 = 16
	DST_AS                       uint16 = 17
	BGP_IPV4_NEXT_HOP            uint16 = 18
	MUL_DST_PKTS                 uint16 = 19
	MUL_DST_BYTES                uint16 = 20
	LAST_SWITCHED                uint16 = 21
	FIRST_SWITCHED               uint16 = 22
	OUT_BYTES                    uint16 = 23
	OUT_PKTS                     uint16 = 24
	MIN_PKT_LNGTH                uint16 = 25
	MAX_PKT_LNGTH                uint16 = 26
	IPV6_SRC_ADDR                uint16 = 27
	IPV6_DST_ADDR                uint16 = 28
	IPV6_SRC_MASK                uint16 = 29
	IPV6_DST_MASK                uint16 = 30
	IPV6_FLOW_LABEL              uint16 = 31
	ICMP_TYPE                    uint16 = 32
	MUL_IGMP_TYPE                uint16 = 33
	SAMPLING_INTERVAL            uint16 = 34
	SAMPLING_ALGORITHM           uint16 = 35
	FLOW_ACTIVE_TIMEOUT          uint16 = 36
	FLOW_INACTIVE_TIMEOUT        uint16 = 37
	ENGINE_TYPE                  uint16 = 38
	ENGINE_ID                    uint16 = 39
	TOTAL_BYTES_EXP              uint16 = 40
	TOTAL_PKTS_EXP               uint16 = 41
	TOTAL_FLOWS_EXP              uint16 = 42
	IPV4_SRC_PREFIX              uint16 = 44
	IPV4_DST_PREFIX              uint16 = 45
	MPLS_TOP_LABEL_TYPE          uint16 = 46
	MPLS_TOP_LABEL_IP_ADDR       uint16 = 47
	FLOW_SAMPLER_ID              uint16 = 48
	FLOW_SAMPLER_MODE            uint16 = 49
	FLOW_SAMPLER_RANDOM_INTERVAL uint16 = 50
	MIN_TTL                      uint16 = 52
	MAX_TTL                      uint16 = 53
	IPV4_IDENT                   uint16 = 54
	DST_TOS                      uint16 = 55
	IN_SRC_MAC                   uint16 = 56
	OUT_DST_MAC                  uint16 = 57
	SRC_VLAN                     uint16 = 58
	DST_VLAN                     uint16 = 59
	IP_PROTOCOL_VERSION          uint16 = 60
	DIRECTION                    uint16 = 61
	IPV6_NEXT_HOP                uint16 = 62
	BPG_IPV6_NEXT_HOP            uint16 = 63
	IPV6_OPTION_HEADERS          uint16 = 64
	MPLS_LABEL_1                 uint16 = 70
	MPLS_LABEL_2                 uint16 = 71
	MPLS_LABEL_3                 uint16 = 72
	MPLS_LABEL_4                 uint16 = 73
	MPLS_LABEL_5                 uint16 = 74
	MPLS_LABEL_6                 uint16 = 75
	MPLS_LABEL_7                 uint16 = 76
	MPLS_LABEL_8                 uint16 = 77
	MPLS_LABEL_9                 uint16 = 78
	MPLS_LABEL_10                uint16 = 79
	IN_DST_MAC                   uint16 = 80
	OUT_SRC_MAC                  uint16 = 81
	IF_NAME                      uint16 = 82
	IF_DESC                      uint16 = 83
	SAMPLER_NAME                 uint16 = 84
	IN_PERMANENT_BYTES           uint16 = 85
	IN_PERMANENT_PKTS            uint16 = 86
	FRAGMENT_OFFSET              uint16 = 88
	FORWARDING_STATUS            uint16 = 89
	MPLS_PAL_RD                  uint16 = 90
	MPLS_PREFIX_LEN              uint16 = 91
	SRC_TRAFFIC_INDEX            uint16 = 92
	DST_TRAFFIC_INDEX            uint16 = 93
	layer2packetSectionOffset    uint16 = 102
	layer2packetSectionSize      uint16 = 103
	layer2packetSectionData      uint16 = 104
	BGP_ADJ_NEXT_AS              uint16 = 128
	BGP_ADJ_PREV_AS              uint16 = 129
	CONN_ID                      uint16 = 148
	FLOW_CREATE_TIME_MSEC        uint16 = 152
	FLOW_END_TIME_MSEC           uint16 = 153
	FWD_FLOW_DELTA_BYTES         uint16 = 231
	REV_FLOW_DELTA_BYTES         uint16 = 232
	EVENT_TIME_MSEC              uint16 = 323
	XLATE_SRC_ADDR_IPV4          uint16 = 225
	XLATE_DST_ADDR_IPV4          uint16 = 226
	XLATE_SRC_PORT               uint16 = 227
	XLATE_DST_PORT               uint16 = 228
	XLATE_SRC_ADDR_IPV6          uint16 = 281
	XLATE_DST_ADDR_IPV6          uint16 = 282
	FW_EVENT                     uint16 = 233
	NAT_EVENT                    uint16 = 230
	INGRESS_VRFID                uint16 = 234
	EGRESS_VRFID                 uint16 = 235
	XLATE_PORT_BLOCK_START       uint16 = 361
	XLATE_PORT_BLOCK_END         uint16 = 362
	XLATE_PORT_BLOCK_STEP        uint16 = 363
	XLATE_PORT_BLOCK_SIZE        uint16 = 364
	INGRESS_ACL_ID               uint16 = 33000
	EGRESS_ACL_ID                uint16 = 33001
	FW_EXT_EVENT                 uint16 = 33002
	USERNAME                     uint16 = 40000
	XLATE_SRC_ADDR_84            uint16 = 40001
	XLATE_DST_ADDR_84            uint16 = 40002
	XLATE_SRC_PORT_84            uint16 = 40003
	XLATE_DST_PORT_84            uint16 = 40004
	FW_EVENT_84                  uint16 = 40005
	NPROBE_CLIENT_NW_DELAY_SEC   uint16 = 57554
	NPROBE_CLIENT_NW_DELAY_USEC  uint16 = 57555
	NPROBE_SERVER_NW_DELAY_SEC   uint16 = 57556
	NPROBE_SERVER_NW_DELAY_USEC  uint16 = 57557
	NPROBE_APPL_LATENCY_SEC      uint16 = 57558
	NPROBE_APPL_LATENCY_USEC     uint16 = 57559
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
