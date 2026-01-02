package junos

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/nemith/netconf"
)

type TrimmedString string

func (t *TrimmedString) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	var v string
	if err := d.DecodeElement(&v, &start); err != nil {
		return err
	}
	*t = TrimmedString(strings.TrimSpace(v))
	return nil
}

func (t TrimmedString) String() string {
	return string(t)
}

// ArpTable contains the ARP table on the device.
type ArpTable struct {
	Count   int        `xml:"arp-entry-count"`
	Entries []ArpEntry `xml:"arp-table-entry"`
}

// ArpEntry holds each individual ARP entry.
type ArpEntry struct {
	MACAddress TrimmedString `xml:"mac-address"`
	IPAddress  TrimmedString `xml:"ip-address"`
	Interface  TrimmedString `xml:"interface-name"`
}

// RoutingTable contains every routing table on the device.
type RoutingTable struct {
	RouteTables []RouteTable `xml:"route-table"`
}

// RouteTable holds all the route information for each table.
type RouteTable struct {
	Name           TrimmedString `xml:"table-name"`
	TotalRoutes    int           `xml:"total-route-count"`
	ActiveRoutes   int           `xml:"active-route-count"`
	HolddownRoutes int           `xml:"holddown-route-count"`
	HiddenRoutes   int           `xml:"hidden-routes"`
	Entries        []Route       `xml:"rt"`
}

type EnvironmentTable struct {
	EnvironmentEntries []EnvironmentItem `xml:"environment-item"`
}

type EnvironmentItem struct {
	Name        TrimmedString `xml:"name"`
	Class       TrimmedString `xml:"class"`
	Status      TrimmedString `xml:"status"`
	Temperature TrimmedString `xml:"temperature"`
}

// get-ike-security-associations-information
type IKESAs struct {
	IKESecurityAssociations []IKESecurityAssociation `xml:"ike-security-associations"`
}

type IKESecurityAssociation struct {
	IKESARemoteAddress   TrimmedString `xml:"ike-sa-remote-address"`
	IKESAIndex           int           `xml:"ike-sa-index"`
	IKESAState           TrimmedString `xml:"ike-sa-state"`
	IKESAInitiatorCookie TrimmedString `xml:"ike-sa-initiator-cookie"`
	IKESAResponderCookie TrimmedString `xml:"ike-sa-responder-cookie"`
	IKESAExchangeType    TrimmedString `xml:"ike-sa-exchange-type"`
}

// get-security-associations-information
type IPSecSAs struct {
	TotalActiveTunnels             int          `xml:"total-active-tunnels"`
	TotalIPSecSAs                  int          `xml:"total-ipsec-sas"`
	IPSecSecurityAssociationsBlock IPSecSABlock `xml:"ipsec-security-associations-block"`
}

type IPSecSABlock struct {
	SABlockState              TrimmedString              `xml:"sa-block-state"`
	IPSecSecurityAssociations []IPSecSecurityAssociation `xml:"ipsec-security-associations"`
}

type IPSecSecurityAssociation struct {
	SADirection             TrimmedString `xml:"sa-direction"`
	SATunnelIndex           int           `xml:"sa-tunnel-index"`
	SASPI                   TrimmedString `xml:"sa-spi"`
	SAAUXSPI                TrimmedString `xml:"sa-aux-spi"`
	SARemoteGateway         TrimmedString `xml:"sa-remote-gateway"`
	SAPort                  int           `xml:"sa-port"`
	SAVPNMonitoringState    TrimmedString `xml:"sa-vpn-monitoring-state"`
	SAProtocol              TrimmedString `xml:"sa-protocol"`
	SAESPEncryptionProtocol TrimmedString `xml:"sa-esp-encryption-protocol"`
	SAHMACAlgorithm         TrimmedString `xml:"sa-hmac-algorithm"`
	SAHardLifetime          int           `xml:"sa-hard-lifetime"`
	SALifesizeRemaining     TrimmedString `xml:"sa-lifesize-remaining"`
	SAVirtualSystem         TrimmedString `xml:"sa-virtual-system"`
}

// Route holds information about each individual route.
type Route struct {
	Destination           TrimmedString `xml:"rt-destination"`
	Active                TrimmedString `xml:"rt-entry>active-tag"`
	Protocol              TrimmedString `xml:"rt-entry>protocol-name"`
	Preference            int           `xml:"rt-entry>preference"`
	Age                   TrimmedString `xml:"rt-entry>age"`
	NextHop               TrimmedString `xml:"rt-entry>nh>to,omitempty"`
	NextHopInterface      TrimmedString `xml:"rt-entry>nh>via,omitempty"`
	NextHopTable          TrimmedString `xml:"rt-entry>nh>nh-table,omitempty"`
	NextHopLocalInterface TrimmedString `xml:"rt-entry>nh>nh-local-interface,omitempty"`
}

// Interfaces contains information about every interface on the device.
type Interfaces struct {
	Entries []PhysicalInterface `xml:"physical-interface"`
}

// PhysicalInterface contains information about each individual physical interface.
type PhysicalInterface struct {
	Name                    TrimmedString      `xml:"name"`
	AdminStatus             TrimmedString      `xml:"admin-status"`
	OperStatus              TrimmedString      `xml:"oper-status"`
	LocalIndex              int                `xml:"local-index"`
	SNMPIndex               int                `xml:"snmp-index"`
	LinkLevelType           TrimmedString      `xml:"link-level-type"`
	InterfaceType           TrimmedString      `xml:"if-type"`
	MTU                     TrimmedString      `xml:"mtu"`
	LinkMode                TrimmedString      `xml:"link-mode"`
	Speed                   TrimmedString      `xml:"speed"`
	FlowControl             TrimmedString      `xml:"if-flow-control"`
	AutoNegotiation         TrimmedString      `xml:"if-auto-negotiation"`
	HardwarePhysicalAddress TrimmedString      `xml:"hardware-physical-address"`
	Flapped                 TrimmedString      `xml:"interface-flapped"`
	InputBps                int                `xml:"traffic-statistics>input-bps"`
	InputPps                int                `xml:"traffic-statistics>input-pps"`
	OutputBps               int                `xml:"traffic-statistics>output-bps"`
	OutputPps               int                `xml:"traffic-statistics>output-pps"`
	LogicalInterfaces       []LogicalInterface `xml:"logical-interface"`
}

// LogicalInterface contains information about the logical interfaces tied to a physical interface.
type LogicalInterface struct {
	Name             TrimmedString   `xml:"name"`
	LocalIndex       int             `xml:"local-index"`
	SNMPIndex        int             `xml:"snmp-index"`
	Encapsulation    TrimmedString   `xml:"encapsulation"`
	LAGInputPackets  uint64          `xml:"lag-traffic-statistics>lag-bundle>input-packets"`
	LAGInputPps      int             `xml:"lag-traffic-statistics>lag-bundle>input-pps"`
	LAGInputBytes    int             `xml:"lag-traffic-statistics>lag-bundle>input-bytes"`
	LAGInputBps      int             `xml:"lag-traffic-statistics>lag-bundle>input-bps"`
	LAGOutputPackets uint64          `xml:"lag-traffic-statistics>lag-bundle>output-packets"`
	LAGOutputPps     int             `xml:"lag-traffic-statistics>lag-bundle>output-pps"`
	LAGOutputBytes   int             `xml:"lag-traffic-statistics>lag-bundle>output-bytes"`
	LAGOutputBps     int             `xml:"lag-traffic-statistics>lag-bundle>output-bps"`
	ZoneName         TrimmedString   `xml:"logical-interface-zone-name"`
	InputPackets     uint64          `xml:"traffic-statistics>input-packets"`
	OutputPackets    uint64          `xml:"traffic-statistics>output-packets"`
	AddressFamilies  []AddressFamily `xml:"address-family"`
	LinkAddress      TrimmedString   `xml:"link-address,omitempty"`
}

type AddressFamily struct {
	Name               TrimmedString `xml:"address-family-name"`
	AggregatedEthernet TrimmedString `xml:"ae-bundle-name,omitempty"`
	CIDR               TrimmedString `xml:"interface-address>ifa-destination"`
	IPAddress          TrimmedString `xml:"interface-address>ifa-local"`
	MTU                TrimmedString `xml:"mtu"`
}

// Vlans contains all of the VLAN information on the device.
type Vlans struct {
	Entries []Vlan `xml:"l2ng-l2ald-vlan-instance-group"`
}

// Vlan contains information about each individual VLAN.
type Vlan struct {
	Name             TrimmedString   `xml:"l2ng-l2rtb-vlan-name"`
	Tag              int             `xml:"l2ng-l2rtb-vlan-tag"`
	MemberInterfaces []TrimmedString `xml:"l2ng-l2rtb-vlan-member>l2ng-l2rtb-vlan-member-interface"`
}

type LLDPNeighbors struct {
	Entries []LLDPNeighbor `xml:"lldp-neighbor-information"`
}

type LLDPNeighbor struct {
	LocalPortId              TrimmedString `xml:"lldp-local-port-id"`
	LocalParentInterfaceName TrimmedString `xml:"lldp-local-parent-interface-name"`
	RemoteChassisIdSubtype   TrimmedString `xml:"lldp-remote-chassis-id-subtype"`
	RemoteChassisId          TrimmedString `xml:"lldp-remote-chassis-id"`
	RemotePortDescription    TrimmedString `xml:"lldp-remote-port-description"`
	RemotePortId             TrimmedString `xml:"lldp-remote-port-id"`
	RemoteSystemName         TrimmedString `xml:"lldp-remote-system-name"`
}

// EthernetSwitchingTable contains the ethernet-switching table on the device.
type EthernetSwitchingTable struct {
	Entries []L2MACEntry `xml:"l2ng-l2ald-mac-entry-vlan"`
}

// L2MACEntry contains information about every MAC address on each VLAN.
type L2MACEntry struct {
	GlobalMACCount  int           `xml:"mac-count-global"`
	LearnedMACCount int           `xml:"learnt-mac-count"`
	RoutingInstance TrimmedString `xml:"l2ng-l2-mac-routing-instance"`
	VlanID          int           `xml:"l2ng-l2-vlan-id"`
	MACEntries      []MACEntry    `xml:"l2ng-mac-entry"`
}

// MACEntry contains information about each individual MAC address. Flags are: S - static MAC, D - dynamic MAC,
// L - locally learned, P - persistent static, SE - statistics enabled, NM - non configured MAC, R - remote PE MAC,
// O - ovsdb MAC.
type MACEntry struct {
	VlanName         TrimmedString `xml:"l2ng-l2-mac-vlan-name"`
	MACAddress       TrimmedString `xml:"l2ng-l2-mac-address"`
	Age              TrimmedString `xml:"l2ng-l2-mac-age"`
	Flags            TrimmedString `xml:"l2ng-l2-mac-flags"`
	LogicalInterface TrimmedString `xml:"l2ng-l2-mac-logical-interface"`
}

// HardwareInventory contains all the hardware information about the device.
type HardwareInventory struct {
	Chassis []Chassis `xml:"chassis"`
}

type srxHardwareInventory struct {
	Chassis []Chassis `xml:"multi-routing-engine-item>chassis-inventory>chassis"`
}

// Storage contains information about all of the file systems on the device.
type Storage struct {
	Entries []SystemStorage `xml:"system-storage-information"`
}

type multiStorage struct {
	Entries []SystemStorage `xml:"multi-routing-engine-item>system-storage-information"`
}

// SystemStorage stores the file system information for each node, routing-engine, etc. on the device.
type SystemStorage struct {
	FileSystems []FileSystem `xml:"filesystem"`
}

// FileSystem contains the information for each partition.
type FileSystem struct {
	Name            TrimmedString `xml:"filesystem-name"`
	TotalBlocks     int           `xml:"total-blocks"`
	UsedBlocks      int           `xml:"used-blocks"`
	AvailableBlocks int           `xml:"available-blocks"`
	UsedPercent     TrimmedString `xml:"used-percent"`
	MountedOn       TrimmedString `xml:"mounted-on"`
}

// Chassis contains all of the hardware information for each chassis, such as a clustered pair of SRX's or a
// virtual-chassis configuration.
type Chassis struct {
	Name         TrimmedString `xml:"name"`
	SerialNumber TrimmedString `xml:"serial-number"`
	Description  TrimmedString `xml:"description"`
	Modules      []Module      `xml:"chassis-module"`
}

// Module contains information about each individual module.
type Module struct {
	Name         TrimmedString `xml:"name"`
	Version      TrimmedString `xml:"version,omitempty"`
	PartNumber   TrimmedString `xml:"part-number"`
	SerialNumber TrimmedString `xml:"serial-number"`
	Description  TrimmedString `xml:"description"`
	CLEICode     TrimmedString `xml:"clei-code"`
	ModuleNumber TrimmedString `xml:"module-number"`
	SubModules   []SubModule   `xml:"chassis-sub-module"`
}

// SubModule contains information about each individual sub-module.
type SubModule struct {
	Name          TrimmedString  `xml:"name"`
	Version       TrimmedString  `xml:"version,omitempty"`
	PartNumber    TrimmedString  `xml:"part-number"`
	SerialNumber  TrimmedString  `xml:"serial-number"`
	Description   TrimmedString  `xml:"description"`
	CLEICode      TrimmedString  `xml:"clei-code"`
	ModuleNumber  TrimmedString  `xml:"module-number"`
	SubSubModules []SubSubModule `xml:"chassis-sub-sub-module"`
}

// SubSubModule contains information about each sub-sub module, such as SFP's.
type SubSubModule struct {
	Name             TrimmedString     `xml:"name"`
	Version          TrimmedString     `xml:"version,omitempty"`
	PartNumber       TrimmedString     `xml:"part-number"`
	SerialNumber     TrimmedString     `xml:"serial-number"`
	Description      TrimmedString     `xml:"description"`
	SubSubSubModules []SubSubSubModule `xml:"chassis-sub-sub-sub-module"`
}

// SubSubSubModule contains information about each sub-sub-sub module, such as SFP's on a
// PIC, which is tied to a MIC on an MX.
type SubSubSubModule struct {
	Name         TrimmedString `xml:"name"`
	Version      TrimmedString `xml:"version,omitempty"`
	PartNumber   TrimmedString `xml:"part-number"`
	SerialNumber TrimmedString `xml:"serial-number"`
	Description  TrimmedString `xml:"description"`
}

// VirtualChassis contains information regarding the virtual-chassis setup for the device.
type VirtualChassis struct {
	PreProvisionedVCID   TrimmedString `xml:"preprovisioned-virtual-chassis-information>virtual-chassis-id"`
	PreProvisionedVCMode TrimmedString `xml:"preprovisioned-virtual-chassis-information>virtual-chassis-mode"`
	Members              []VCMember    `xml:"member-list>member"`
}

// VCMember contains information about each individual virtual-chassis member.
type VCMember struct {
	Status       TrimmedString      `xml:"member-status"`
	ID           int                `xml:"member-id"`
	FPCSlot      TrimmedString      `xml:"fpc-slot"`
	SerialNumber TrimmedString      `xml:"member-serial-number"`
	Model        TrimmedString      `xml:"member-model"`
	Priority     int                `xml:"member-priority"`
	MixedMode    TrimmedString      `xml:"member-mixed-mode"`
	RouteMode    TrimmedString      `xml:"member-route-mode"`
	Role         TrimmedString      `xml:"member-role"`
	Neighbors    []VCMemberNeighbor `xml:"neighbor-list>neighbor"`
}

// VCMemberNeighbor contains information about each virtual-chassis member neighbor.
type VCMemberNeighbor struct {
	ID        int           `xml:"neighbor-id"`
	Interface TrimmedString `xml:"neighbor-interface"`
}

// BGPTable contains information about every BGP peer configured on the device.
type BGPTable struct {
	TotalGroups int       `xml:"group-count"`
	TotalPeers  int       `xml:"peer-count"`
	DownPeers   int       `xml:"down-peer-count"`
	Entries     []BGPPeer `xml:"bgp-peer"`
}

// BGPPeer contains information about each individual BGP peer.
type BGPPeer struct {
	Address            TrimmedString `xml:"peer-address"`
	ASN                int           `xml:"peer-as"`
	InputMessages      int           `xml:"input-messages"`
	OutputMessages     int           `xml:"output-messages"`
	QueuedRoutes       int           `xml:"route-queue-count"`
	Flaps              int           `xml:"flap-count"`
	ElapsedTime        TrimmedString `xml:"elapsed-time"`
	State              TrimmedString `xml:"peer-state"`
	RoutingTable       TrimmedString `xml:"bgp-rib>name"`
	ActivePrefixes     int           `xml:"bgp-rib>active-prefix-count"`
	ReceivedPrefixes   int           `xml:"bgp-rib>received-prefix-count"`
	AcceptedPrefixes   int           `xml:"bgp-rib>accepted-prefix-count"`
	SuppressedPrefixes int           `xml:"bgp-rib>suppressed-prefix-count"`
}

// StaticNats contains the static NATs configured on the device.
type StaticNats struct {
	Count   int
	Entries []StaticNatEntry `xml:"static-nat-rule-entry"`
}

// srxStaticNats contains static NATs configured across a clustered-mode SRX
type srxStaticNats struct {
	Entries []StaticNatEntry `xml:"multi-routing-engine-item>static-nat-rule-information>static-nat-rule-entry"`
}

// StaticNatEntry holds each individual static NAT entry.
type StaticNatEntry struct {
	Name                    TrimmedString `xml:"rule-name"`
	SetName                 TrimmedString `xml:"rule-set-name"`
	ID                      TrimmedString `xml:"rule-id"`
	RuleMatchingPosition    int           `xml:"rule-matching-position"`
	FromContext             TrimmedString `xml:"rule-from-context"`
	FromZone                TrimmedString `xml:"rule-from-context-name"`
	SourceAddressLowRange   TrimmedString `xml:"static-source-address-range-entry>rule-source-address-low-range"`
	SourceAddressHighRange  TrimmedString `xml:"static-source-address-range-entry>rule-source-address-high-range"`
	DestinaionAddressPrefix TrimmedString `xml:"rule-destination-address-prefix"`
	DestinationPortLow      int           `xml:"rule-destination-port-low"`
	DestinationPortHigh     int           `xml:"rule-destination-port-high"`
	HostAddressPrefix       TrimmedString `xml:"rule-host-address-prefix"`
	HostPortLow             int           `xml:"rule-host-port-low"`
	HostPortHigh            int           `xml:"rule-host-port-high"`
	Netmask                 TrimmedString `xml:"rule-address-netmask"`
	RoutingInstance         TrimmedString `xml:"rule-host-routing-instance"`
	TranslationHits         int           `xml:"rule-translation-hits"`
	SuccessfulSessions      int           `xml:"succ-hits"`
	ConcurrentHits          int           `xml:"concurrent-hits"`
}

// SourceNats contains the source NATs configured on the device.
type SourceNats struct {
	Count   int
	Entries []SourceNatEntry `xml:"source-nat-rule-entry"`
}

type srxSourceNats struct {
	Entries []SourceNatEntry `xml:"multi-routing-engine-item>source-nat-rule-detail-information>source-nat-rule-entry"`
}

// SourceNatEntry holds each individual source NAT entry.
type SourceNatEntry struct {
	Name                     TrimmedString   `xml:"rule-name"`
	SetName                  TrimmedString   `xml:"rule-set-name"`
	ID                       TrimmedString   `xml:"rule-id"`
	RuleMatchingPosition     int             `xml:"rule-matching-position"`
	FromContext              TrimmedString   `xml:"rule-from-context"`
	FromZone                 TrimmedString   `xml:"rule-from-context-name"`
	ToContext                TrimmedString   `xml:"rule-to-context"`
	ToZone                   TrimmedString   `xml:"rule-to-context-name"`
	SourceAddressLowRange    TrimmedString   `xml:"source-address-range-entry>rule-source-address-low-range"`
	SourceAddressHighRange   TrimmedString   `xml:"source-address-range-entryrule-source-address-high-range"`
	SourceAddresses          []TrimmedString `xml:"source-address-range-entry>rule-source-address"`
	DestinationAddresses     []TrimmedString `xml:"destination-address-range-entry>rule-destination-address"`
	DestinationPortLow       int             `xml:"destination-port-entry>rule-destination-port-low"`
	DestinationPortHigh      int             `xml:"destination-port-entry>rule-destination-port-high"`
	SourcePortLow            int             `xml:"source-port-entry>rule-source-port-low"`
	SourcePortHigh           int             `xml:"source-port-entry>rule-source-port-high"`
	SourceNatProtocol        TrimmedString   `xml:"src-nat-protocol-entry"`
	RuleAction               TrimmedString   `xml:"source-nat-rule-action-entry>source-nat-rule-action"`
	PersistentNatType        TrimmedString   `xml:"source-nat-rule-action-entry>persistent-nat-type"`
	PersistentNatMappingType TrimmedString   `xml:"source-nat-rule-action-entry>persistent-nat-mapping-type"`
	PersistentNatTimeout     int             `xml:"source-nat-rule-action-entry>persistent-nat-timeout"`
	PersistentNatMaxSession  int             `xml:"source-nat-rule-action-entry>persistent-nat-max-session"`
	TranslationHits          int             `xml:"source-nat-rule-hits-entry>rule-translation-hits"`
	SuccessfulSessions       int             `xml:"source-nat-rule-hits-entry>succ-hits"`
	ConcurrentHits           int             `xml:"source-nat-rule-hits-entry>concurrent-hits"`
}

// FirewallPolicy contains the entire firewall policy for the device.
type FirewallPolicy struct {
	XMLName xml.Name          `xml:"security-policies"`
	Entries []SecurityContext `xml:"security-context"`
}

type srxFirewallPolicy struct {
	Entries []SecurityContext `xml:"multi-routing-engine-item>security-policies>security-context"`
}

// SecurityContext contains the policies for each context, such as rules from trust to untrust zones.
type SecurityContext struct {
	SourceZone      TrimmedString `xml:"context-information>source-zone-name"`
	DestinationZone TrimmedString `xml:"context-information>destination-zone-name"`
	Rules           []Rule        `xml:"policies>policy-information"`
}

// Rule contains each individual element that makes up a security policy rule.
type Rule struct {
	Name                 TrimmedString   `xml:"policy-name"`
	State                TrimmedString   `xml:"policy-state"`
	Identifier           int             `xml:"policy-identifier"`
	ScopeIdentifier      int             `xml:"scope-policy-identifier"`
	SequenceNumber       int             `xml:"policy-sequence-number"`
	SourceAddresses      []TrimmedString `xml:"source-addresses>source-address>address-name"`
	DestinationAddresses []TrimmedString `xml:"destination-addresses>destination-address>address-name"`
	Applications         []TrimmedString `xml:"applications>application>application-name"`
	SourceIdentities     []TrimmedString `xml:"source-identities>source-identity>role-name"`
	PolicyAction         TrimmedString   `xml:"policy-action>action-type"`
	PolicyTCPOptions     struct {
		SYNCheck      TrimmedString `xml:"policy-tcp-options-syn-check"`
		SequenceCheck TrimmedString `xml:"policy-tcp-options-sequence-check"`
	} `xml:"policy-action>policy-tcp-options"`
}

// Views contains the information for the specific views. Note that some views aren't available for specific
// hardware platforms, such as the "VirtualChassis" view on an SRX.
type Views struct {
	Arp            ArpTable
	BGP            BGPTable
	EthernetSwitch EthernetSwitchingTable
	FirewallPolicy FirewallPolicy
	Interface      Interfaces
	Inventory      HardwareInventory
	LLDPNeighbors  LLDPNeighbors
	Route          RoutingTable
	SourceNat      SourceNats
	StaticNat      StaticNats
	Storage        Storage
	VirtualChassis VirtualChassis
	Vlan           Vlans
	Environment    EnvironmentTable
	IKESAs         IKESAs
	IPSecSAs       IPSecSAs
}

var (
	viewCategories = map[string]string{
		"arp":            "<get-arp-table-information><no-resolve/></get-arp-table-information>",
		"route":          "<get-route-information/>",
		"interface":      "<get-interface-information/>",
		"vlan":           "<get-vlan-information/>",
		"lldp":           "<get-lldp-neighbors-information/>",
		"ethernetswitch": "<get-ethernet-switching-table-information/>",
		"environment":    "<get-environment-information/>",
		"inventory":      "<get-chassis-inventory/>",
		"virtualchassis": "<get-virtual-chassis-information/>",
		"bgp":            "<get-bgp-summary-information/>",
		"staticnat":      "<get-static-nat-rule-information><all/></get-static-nat-rule-information>",
		"sourcenat":      "<get-source-nat-rule-sets-information><all/></get-source-nat-rule-sets-information>",
		"storage":        "<get-system-storage/>",
		"firewallpolicy": "<get-firewall-policies/>",
		"ike":            "<get-ike-security-associations-information/>",
		"ipsec":          "<get-security-associations-information/>",
	}
)

func scalarValue(v reflect.Value) any {
	return v.Interface()
}

func (v *Views) String() string {
	if v == nil {
		return "<nil>"
	}

	rv := reflect.ValueOf(v).Elem()
	for i := 0; i < rv.NumField(); i++ {
		f := rv.Field(i)
		if !f.IsZero() {
			var b strings.Builder
			formatValue(&b, f, 0)
			return b.String()
		}
	}
	return ""
}

func formatValue(b *strings.Builder, v reflect.Value, indent int) {
	// Invalid value: nothing to do
	if !v.IsValid() {
		return
	}

	// Unwrap pointers
	for v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return
		}
		v = v.Elem()
	}

	prefix := strings.Repeat("  ", indent)

	switch v.Kind() {

	case reflect.Struct:
		t := v.Type()

		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			ft := t.Field(i)

			if ft.PkgPath != "" || f.IsZero() {
				continue
			}

			name := normalizeName(fieldName(ft))

			if isScalar(f) {
				fmt.Fprintf(
					b,
					"%s%s: %v\n",
					prefix,
					name,
					scalarValue(f),
				)
				continue
			}

			fmt.Fprintf(b, "%s%s:\n", prefix, name)
			formatValue(b, f, indent+1)
		}

	case reflect.Slice, reflect.Array:
		for i := 0; i < v.Len(); i++ {
			elem := v.Index(i)

			for elem.Kind() == reflect.Pointer {
				if elem.IsNil() {
					break
				}
				elem = elem.Elem()
			}

			if isScalar(elem) {
				fmt.Fprintf(
					b,
					"%s- %v\n",
					prefix,
					scalarValue(elem),
				)
				continue
			}

			if elem.Kind() == reflect.Struct {
				t := elem.Type()
				firstPrinted := false

				for j := 0; j < elem.NumField(); j++ {
					f := elem.Field(j)
					ft := t.Field(j)

					if ft.PkgPath != "" || f.IsZero() {
						continue
					}

					name := normalizeName(fieldName(ft))

					if !firstPrinted && isScalar(f) {
						fmt.Fprintf(
							b,
							"%s- %s: %v\n",
							prefix,
							name,
							scalarValue(f),
						)
						firstPrinted = true
						continue
					}

					if !firstPrinted {
						fmt.Fprintf(b, "%s-\n", prefix)
						firstPrinted = true
					}

					if isScalar(f) {
						fmt.Fprintf(
							b,
							"%s  %s: %v\n",
							prefix,
							name,
							scalarValue(f),
						)
						continue
					}

					fmt.Fprintf(b, "%s  %s:\n", prefix, name)
					formatValue(b, f, indent+2)
				}

				continue
			}

			fmt.Fprintf(b, "%s-\n", prefix)
			formatValue(b, elem, indent+1)
		}

	default:
		if isScalar(v) {
			fmt.Fprintf(
				b,
				"%s%v\n",
				prefix,
				scalarValue(v),
			)
		}
	}
}

func normalizeName(name string) string {
	return strings.ReplaceAll(name, ">", ".")
}

func fieldName(f reflect.StructField) string {
	if tag := f.Tag.Get("xml"); tag != "" {
		name := strings.Split(tag, ",")[0]
		if name != "" && name != "-" {
			return name
		}
	}
	return f.Name
}

func isScalar(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.String,
		reflect.Bool,
		reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	default:
		return false
	}
}

func validatePlatform(j *Junos, v string) error {
	switch v {
	case "ethernetswitch":
		if strings.Contains(j.Platform[0].Model, "SRX") || strings.Contains(j.Platform[0].Model, "MX") {
			return errors.New("ethernet-switching information is not available on this platform")
		}
	case "virtualchassis":
		if strings.Contains(j.Platform[0].Model, "SRX") || strings.Contains(j.Platform[0].Model, "MX") {
			return errors.New("virtual-chassis information is not available on this platform")
		}
	}

	return nil
}

func (j *Junos) View(view string, option ...string) (*Views, error) {
	var results Views
	var reply *netconf.Reply
	var err error

	if j == nil || j.Session == nil {
		return nil, errors.New("attempt to call View on nil Junos object")
	}

	if strings.Contains(j.Platform[0].Model, "SRX") || strings.Contains(j.Platform[0].Model, "MX") {
		if err := validatePlatform(j, view); err != nil {
			return nil, err
		}
	}

	ctx := context.Background()

	if view == "interface" && len(option) > 0 {
		rpcIntName := fmt.Sprintf(
			"<get-interface-information><interface-name>%s</interface-name></get-interface-information>",
			option[0],
		)
		reply, err = j.Session.Do(ctx, rpcIntName)
		if err != nil {
			return nil, err
		}
	} else {
		rpc, ok := viewCategories[view]
		if !ok {
			return nil, errors.New("unsupported view")
		}

		reply, err = j.Session.Do(ctx, rpc)
		if err != nil {
			return nil, err
		}
	}

	if len(reply.Errors) > 0 {
		return nil, errors.New(reply.Errors[0].Message)
	}

	if len(reply.Body) == 0 {
		return nil, errors.New("no output available - please check the syntax of your command")
	}

	data := reply.Body

	switch view {

	case "arp":
		var arpTable ArpTable
		if err := xml.Unmarshal(data, &arpTable); err != nil {
			return nil, err
		}
		results.Arp = arpTable

	case "route":
		var routingTable RoutingTable
		if err := xml.Unmarshal(data, &routingTable); err != nil {
			return nil, err
		}
		results.Route = routingTable

	case "interface":
		var ints Interfaces
		if err := xml.Unmarshal(data, &ints); err != nil {
			return nil, err
		}
		results.Interface = ints

	case "vlan":
		var vlan Vlans
		if err := xml.Unmarshal(data, &vlan); err != nil {
			return nil, err
		}
		results.Vlan = vlan

	case "lldp":
		var lldpNeighbors LLDPNeighbors
		if err := xml.Unmarshal(data, &lldpNeighbors); err != nil {
			return nil, err
		}
		results.LLDPNeighbors = lldpNeighbors

	case "environment":
		var envs EnvironmentTable
		if err := xml.Unmarshal(data, &envs); err != nil {
			return nil, err
		}
		results.Environment = envs

	case "ike":
		var ikeSAs IKESAs
		if err := xml.Unmarshal(data, &ikeSAs); err != nil {
			return nil, err
		}
		results.IKESAs = ikeSAs

	case "ipsec":
		var ipsecSAs IPSecSAs
		if err := xml.Unmarshal(data, &ipsecSAs); err != nil {
			return nil, err
		}
		results.IPSecSAs = ipsecSAs

	case "ethernetswitch":
		var ethtable EthernetSwitchingTable
		if err := xml.Unmarshal(data, &ethtable); err != nil {
			return nil, err
		}
		results.EthernetSwitch = ethtable

	case "inventory":
		var inventory HardwareInventory

		if strings.Contains(string(data), "multi-routing-engine-results") {
			var srxinventory srxHardwareInventory
			if err := xml.Unmarshal(data, &srxinventory); err != nil {
				return nil, err
			}
			inventory.Chassis = append(inventory.Chassis, srxinventory.Chassis...)
		} else {
			if err := xml.Unmarshal(data, &inventory); err != nil {
				return nil, err
			}
		}

		results.Inventory = inventory

	case "virtualchassis":
		var vc VirtualChassis
		if err := xml.Unmarshal(data, &vc); err != nil {
			return nil, err
		}
		results.VirtualChassis = vc

	case "bgp":
		var bgpTable BGPTable
		if err := xml.Unmarshal(data, &bgpTable); err != nil {
			return nil, err
		}
		results.BGP = bgpTable

	case "staticnat":
		var staticnats StaticNats

		if strings.Contains(string(data), "multi-routing-engine-results") {
			var srxstaticnats srxStaticNats
			if err := xml.Unmarshal(data, &srxstaticnats); err != nil {
				return nil, err
			}

			actualrules := len(srxstaticnats.Entries) / 2
			staticnats.Count = actualrules
			staticnats.Entries = append(staticnats.Entries, srxstaticnats.Entries[:actualrules]...)
		} else {
			if err := xml.Unmarshal(data, &staticnats); err != nil {
				return nil, err
			}
			staticnats.Count = len(staticnats.Entries)
		}

		results.StaticNat = staticnats

	case "sourcenat":
		var sourcenats SourceNats

		if strings.Contains(string(data), "multi-routing-engine-results") {
			var srxsourcenats srxSourceNats
			if err := xml.Unmarshal(data, &srxsourcenats); err != nil {
				return nil, err
			}

			actualrules := len(srxsourcenats.Entries) / 2
			sourcenats.Count = actualrules
			sourcenats.Entries = append(sourcenats.Entries, srxsourcenats.Entries[:actualrules]...)
		} else {
			if err := xml.Unmarshal(data, &sourcenats); err != nil {
				return nil, err
			}
			sourcenats.Count = len(sourcenats.Entries)
		}

		results.SourceNat = sourcenats

	case "storage":
		var storage Storage

		if strings.Contains(string(data), "multi-routing-engine-results") {
			var multistorage multiStorage
			if err := xml.Unmarshal(data, &multistorage); err != nil {
				return nil, err
			}
			storage.Entries = append(storage.Entries, multistorage.Entries...)
		} else {
			var sysstorage SystemStorage
			if err := xml.Unmarshal(data, &sysstorage); err != nil {
				return nil, err
			}
			storage.Entries = append(storage.Entries, sysstorage)
		}

		results.Storage = storage

	case "firewallpolicy":
		var fwpolicy FirewallPolicy

		if strings.Contains(string(data), "multi-routing-engine-results") {
			var multifwpolicy srxFirewallPolicy
			if err := xml.Unmarshal(data, &multifwpolicy); err != nil {
				return nil, err
			}
			fwpolicy.Entries = append(fwpolicy.Entries, multifwpolicy.Entries...)
		} else {
			if err := xml.Unmarshal(data, &fwpolicy); err != nil {
				return nil, err
			}
		}

		results.FirewallPolicy = fwpolicy
	}

	return &results, nil
}
