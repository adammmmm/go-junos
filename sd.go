package junos

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

const (
	contentAddress       = "application/vnd.net.juniper.space.address-management.address+xml;version=1"
	contentAddressPatch  = "application/vnd.net.juniper.space.address-management.address+xml;version=1;charset=UTF-8"
	contentService       = "application/vnd.net.juniper.space.service-management.service+xml;version=1"
	contentServicePatch  = "application/vnd.net.juniper.space.service-management.service+xml;version=1;charset=UTF-8"
	contentPublish       = "application/vnd.net.juniper.space.fwpolicy-management.publish+xml;version=1"
	contentUpdateDevices = "application/vnd.net.juniper.space.device-management.update-devices+xml;version=1"
	contentVariable      = "application/vnd.net.juniper.space.variable-management.variable+xml;version=1"
	contentExecDeploy    = "application/vnd.net.juniper.space.software-management.exec-deploy+xml;version=1"
	contentExecRemove    = "application/vnd.net.juniper.space.software-management.exec-remove+xml;version=1"
	contentExecStage     = "application/vnd.net.juniper.space.software-management.exec-stage+xml;version=1"
)

// Addresses contains a list of address objects.
type Addresses struct {
	Addresses []Address `xml:"address"`
}

// An Address contains information about each individual address object.
type Address struct {
	ID          int    `xml:"id"`
	Name        string `xml:"name"`
	AddressType string `xml:"address-type"`
	Description string `xml:"description"`
	IPAddress   string `xml:"ip-address"`
	Hostname    string `xml:"host-name"`
}

// GroupMembers contains a list of all the members within a address or service
// group.
type GroupMembers struct {
	Members []Member `xml:"members>member"`
}

// Member contains information about each individual group member.
type Member struct {
	ID   int    `xml:"id"`
	Name string `xml:"name"`
}

// Services contains a list of service objects.
type Services struct {
	Services []Service `xml:"service"`
}

// A Service contains information about each individual service object.
type Service struct {
	ID          int    `xml:"id"`
	Name        string `xml:"name"`
	IsGroup     bool   `xml:"is-group"`
	Description string `xml:"description"`
}

// A Policy contains information about each individual firewall policy.
type Policy struct {
	ID          int    `xml:"id"`
	Name        string `xml:"name"`
	Description string `xml:"description"`
}

// Policies contains a list of firewall policies.
type Policies struct {
	Policies []Policy `xml:"firewall-policy"`
}

// SecurityDevices contains a list of security devices.
type SecurityDevices struct {
	XMLName xml.Name         `xml:"devices"`
	Devices []SecurityDevice `xml:"device"`
}

// A SecurityDevice contains information about each individual security device.
type SecurityDevice struct {
	ID        int    `xml:"id"`
	Family    string `xml:"device-family"`
	Platform  string `xml:"platform"`
	IPAddress string `xml:"device-ip"`
	Name      string `xml:"name"`
}

// Variables contains a list of all polymorphic (variable) objects.
type Variables struct {
	Variables []Variable `xml:"variable-definition"`
}

// A Variable contains information about each individual polymorphic (variable) object.
type Variable struct {
	ID          int    `xml:"id"`
	Name        string `xml:"name"`
	Description string `xml:"description"`
}

// VariableManagement contains our session state when updating a polymorphic (variable) object.
type VariableManagement struct {
	Devices []SecurityDevice
	Space   *Space
}

// existingVariable contains all of our information in regards to said polymorphic (variable) object.
type existingVariable struct {
	XMLName            xml.Name         `xml:"variable-definition"`
	Name               string           `xml:"name"`
	Description        string           `xml:"description"`
	Type               string           `xml:"type"`
	Version            int              `xml:"edit-version"`
	DefaultName        string           `xml:"default-name"`
	DefaultValue       string           `xml:"default-value-detail>default-value"`
	VariableValuesList []variableValues `xml:"variable-values-list>variable-values"`
}

// variableValues contains the information for each device/object tied to the polymorphic (variable) object.
type variableValues struct {
	XMLName       xml.Name `xml:"variable-values"`
	DeviceMOID    string   `xml:"device>moid"`
	DeviceName    string   `xml:"device>name"`
	VariableValue string   `xml:"variable-value-detail>variable-value"`
	VariableName  string   `xml:"variable-value-detail>name"`
}

// XML for creating an address object.
var addressesXML = `
<address>
    <name>%s</name>
    <address-type>%s</address-type>
    <host-name/>
    <edit-version/>
    <members/>
    <address-version>IPV4</address-version>
    <definition-type>CUSTOM</definition-type>
    <ip-address>%s</ip-address>
    <description>%s</description>
</address>
`

// XML for creating a dns-host address object.
var dnsXML = `
<address>
    <name>%s</name>
    <address-type>%s</address-type>
    <host-name>%s</host-name>
    <edit-version/>
    <members/>
    <address-version>IPV4</address-version>
    <definition-type>CUSTOM</definition-type>
    <ip-address/>
    <description>%s</description>
</address>
`

// XML for creating a service object.
var serviceXML = `
<service>
    <name>%s</name>
    <description>%s</description>
    <is-group>false</is-group>
    <protocols>
        <protocol>
            <name>%s</name>
            <dst-port>%s</dst-port>
            <sunrpc-protocol-type>%s</sunrpc-protocol-type>
            <msrpc-protocol-type>%s</msrpc-protocol-type>
            <protocol-number>%d</protocol-number>
            <protocol-type>%s</protocol-type>
            <disable-timeout>%s</disable-timeout>
            %s
        </protocol>
    </protocols>
</service>
`

// XML for adding an address group.
var addressGroupXML = `
<address>
    <name>%s</name>
    <address-type>GROUP</address-type>
    <host-name/>
    <edit-version/>
    <address-version>IPV4</address-version>
    <definition-type>CUSTOM</definition-type>
    <description>%s</description>
</address>
`

// XML for adding a service group.
var serviceGroupXML = `
<service>
    <name>%s</name>
    <is-group>true</is-group>
    <description>%s</description>
</service>
`

// XML for removing an address or service from a group.
var removeXML = `
<diff>
    <remove sel="%s/members/member[name='%s']"/>
</diff>
`

// XML for adding addresses or services to a group.
var addGroupMemberXML = `
<diff>
    <add sel="%s/members">
        <member>
            <name>%s</name>
        </member>
    </add>
</diff>
`

// XML for renaming an address or service object.
var renameXML = `
<diff>
    <replace sel="%s/name">
        <name>%s</name>
    </replace>
</diff>
`

// XML for updating a security device.
var updateDeviceXML = `
<update-devices>
    <sd-ids>
        <id>%d</id>
    </sd-ids>
    <service-types>
        <service-type>POLICY</service-type>
    </service-types>
    <update-options>
        <enable-policy-rematch-srx-only>false</enable-policy-rematch-srx-only>
    </update-options>
</update-devices>
`

// XML for publishing a changed policy.
var publishPolicyXML = `
<publish>
    <policy-ids>
        <policy-id>%d</policy-id>
    </policy-ids>
</publish>
`

// XML for adding a new variable object.
var createVariableXML = `
<variable-definition>
    <name>%s</name>
    <type>%s</type>
	<description>%s</description>
    <context>DEVICE</context>
    <default-name>%s</default-name>
    <default-value-detail>
        <default-value>%d</default-value>
    </default-value-detail>
</variable-definition>
`

// XML for modifying variable objects.
var modifyVariableXML = `
<variable-definition>
    <name>%s</name>
    <type>%s</type>
	<description>%s</description>
	<edit-version>%d</edit-version>
    <context>DEVICE</context>
    <default-name>%s</default-name>
    <default-value-detail>
        <default-value>%s</default-value>
    </default-value-detail>
	<variable-values-list>
	%s
	</variable-values-list>
</variable-definition>
`

// getObjectID returns the ID of the address or service object.
func (s *Space) getObjectID(object any, otype string) (int, error) {
	switch v := object.(type) {

	case int:
		if v <= 0 {
			return 0, fmt.Errorf("invalid object ID: %d", v)
		}
		return v, nil

	case string:
		if v == "" {
			return 0, fmt.Errorf("object identifier cannot be empty")
		}

		// Service lookup
		if otype == "service" {
			services, err := s.Services(v)
			if err != nil {
				return 0, err
			}
			for _, svc := range services.Services {
				if svc.Name == v {
					return svc.ID, nil
				}
			}
			return 0, fmt.Errorf("service not found: %s", v)
		}

		// Address lookup
		addresses, err := s.Addresses(v)
		if err != nil {
			return 0, err
		}

		// CIDR match
		if _, _, err := net.ParseCIDR(v); err == nil {
			for _, addr := range addresses.Addresses {
				if addr.IPAddress == v {
					return addr.ID, nil
				}
			}
			return 0, fmt.Errorf("address CIDR not found: %s", v)
		}

		// Name match
		for _, addr := range addresses.Addresses {
			if addr.Name == v {
				return addr.ID, nil
			}
		}

		return 0, fmt.Errorf("address not found: %s", v)

	default:
		return 0, fmt.Errorf(
			"unsupported object identifier type %T (must be int or string)",
			object,
		)
	}
}

// getPolicyID returns the ID of a firewall policy.
func (s *Space) getPolicyID(object string) (int, error) {
	var err error
	var objectID int
	objects, err := s.Policies()
	if err != nil {
		return 0, err
	}

	for _, o := range objects.Policies {
		if o.Name == object {
			objectID = o.ID
		}
	}

	return objectID, nil
}

// getVariableID returns the ID of a polymorphic (variable) object.
func (s *Space) getVariableID(variable string) (int, error) {
	var err error
	var variableID int
	vars, err := s.Variables()
	if err != nil {
		return 0, err
	}

	for _, v := range vars.Variables {
		if v.Name == variable {
			variableID = v.ID
		}
	}

	return variableID, nil
}

// getAddrTypeIP returns the address type and IP address of the given address object.
func (s *Space) getAddrTypeIP(address string) []string {
	var addrType, ipaddr string
	r := regexp.MustCompile(`(\d+\.\d+\.\d+\.\d+)(\/\d+)?`)
	rDNS := regexp.MustCompile(`[-\w\.]*\.(com|net|org|us|gov)$`)
	match := r.FindStringSubmatch(address)

	if rDNS.MatchString(address) {
		addrType = "DNS"
		ipaddr = address

		return []string{addrType, ipaddr}
	}

	switch match[2] {
	case "", "/32":
		addrType = "IPADDRESS"
		ipaddr = match[1]
	default:
		addrType = "NETWORK"
		ipaddr = address
	}

	return []string{addrType, ipaddr}
}

// modifyVariableContent creates the XML we use when modifying an existing polymorphic (variable) object.
func (s *Space) modifyVariableContent(data *existingVariable, moid, firewall, address string, vid int) string {
	var varValuesList string
	for _, d := range data.VariableValuesList {
		varValuesList += fmt.Sprintf("<variable-values><device><moid>%s</moid><name>%s</name></device>", d.DeviceMOID, d.DeviceName)
		varValuesList += fmt.Sprintf("<variable-value-detail><variable-value>%s</variable-value><name>%s</name></variable-value-detail></variable-values>", d.VariableValue, d.VariableName)
	}
	varValuesList += fmt.Sprintf("<variable-values><device><moid>%s</moid><name>%s</name></device>", moid, firewall)
	varValuesList += fmt.Sprintf("<variable-value-detail><variable-value>net.juniper.jnap.sm.om.jpa.AddressEntity:%d</variable-value><name>%s</name></variable-value-detail></variable-values>", vid, address)

	return varValuesList
}

func (s *Space) Addresses(filter ...string) (*Addresses, error) {
	query := map[string]string{
		"filter": "(global eq '')",
	}

	if len(filter) > 0 {
		query["filter"] = fmt.Sprintf("(global eq '%s')", filter[0])
	}

	body, err := s.newRequest(
		http.MethodGet,
		"/api/juniper/sd/address-management/addresses",
		nil,
		nil,
		query,
	)
	if err != nil {
		return nil, err
	}

	var addresses Addresses
	if err := xml.Unmarshal(body, &addresses); err != nil {
		return nil, err
	}

	return &addresses, nil
}

func (s *Space) AddAddress(name, ip string, description ...string) error {
	if s == nil {
		return errors.New("attempt to call AddAddress on nil Space object")
	}

	desc := ""
	if len(description) > 0 {
		desc = description[0]
	}

	addrInfo := s.getAddrTypeIP(ip)

	// Detect DNS name vs IP/CIDR
	re := regexp.MustCompile(`[-\w\.]*\.(com|net|org|us|gov)$`)

	payload := fmt.Sprintf(
		addressesXML,
		name,
		addrInfo[0],
		addrInfo[1],
		desc,
	)

	if re.MatchString(ip) {
		payload = fmt.Sprintf(
			dnsXML,
			name,
			addrInfo[0],
			addrInfo[1],
			desc,
		)
	}

	_, err := s.newRequest(
		http.MethodPost,
		"/api/juniper/sd/address-management/addresses",
		[]byte(payload),
		map[string]string{
			"Content-Type": contentAddress,
		},
		nil,
	)

	return err
}

func (s *Space) EditAddress(name, ip string, description ...string) error {
	if s == nil {
		return errors.New("attempt to call EditAddress on nil Space object")
	}

	desc := ""
	if len(description) > 0 {
		desc = description[0]
	}

	addrInfo := s.getAddrTypeIP(ip)

	payload := fmt.Sprintf(
		addressesXML,
		name,
		addrInfo[0],
		addrInfo[1],
		desc,
	)

	_, err := s.newRequest(
		http.MethodPut,
		"/api/juniper/sd/address-management/addresses",
		[]byte(payload),
		map[string]string{
			"Content-Type": contentAddress,
		},
		nil,
	)

	return err
}

func (s *Space) AddService(
	protocol, name string,
	ports interface{},
	description string,
	timeout int,
) error {

	var protoNumber int
	protocol = strings.ToUpper(protocol)
	ptype := fmt.Sprintf("PROTOCOL_%s", protocol)

	switch protocol {
	case "UDP":
		protoNumber = 17
	default:
		protoNumber = 6
	}

	var port string
	switch v := ports.(type) {
	case int:
		port = strconv.Itoa(v)
	case string:
		parts := strings.Split(v, "-")
		port = fmt.Sprintf("%s-%s", parts[0], parts[1])
	default:
		return fmt.Errorf("invalid ports type")
	}

	inactivity := "false"
	timeoutXML := fmt.Sprintf("<inactivity-timeout>%d</inactivity-timeout>", timeout)
	if timeout == 0 {
		inactivity = "true"
		timeoutXML = "<inactivity-timeout/>"
	}

	payload := fmt.Sprintf(
		serviceXML,
		name,
		description,
		name,
		port,
		protocol,
		protocol,
		protoNumber,
		ptype,
		inactivity,
		timeoutXML,
	)

	_, err := s.newRequest(
		http.MethodPost,
		"/api/juniper/sd/service-management/services",
		[]byte(payload),
		map[string]string{"Content-Type": contentService},
		nil,
	)

	return err
}

func (s *Space) AddGroup(grouptype, name string, description ...string) error {
	desc := ""
	if len(description) > 0 {
		desc = description[0]
	}

	path := "/api/juniper/sd/address-management/addresses"
	xmlTemplate := addressGroupXML
	contentType := contentAddress

	if grouptype == "service" {
		path = "/api/juniper/sd/service-management/services"
		xmlTemplate = serviceGroupXML
		contentType = contentService
	}

	payload := fmt.Sprintf(xmlTemplate, name, desc)

	_, err := s.newRequest(
		http.MethodPost,
		path,
		[]byte(payload),
		map[string]string{"Content-Type": contentType},
		nil,
	)

	return err
}

func (s *Space) EditGroup(grouptype, action, object, name string) error {
	objectID, err := s.getObjectID(name, grouptype)
	if err != nil {
		return err
	}

	if objectID == 0 {
		return nil
	}

	var (
		path        string
		contentType string
		rel         string
		payload     string
	)

	path = fmt.Sprintf(
		"/api/juniper/sd/address-management/addresses/%d",
		objectID,
	)
	contentType = contentAddressPatch
	rel = "address"

	if grouptype == "service" {
		path = fmt.Sprintf(
			"/api/juniper/sd/service-management/services/%d",
			objectID,
		)
		contentType = contentServicePatch
		rel = "service"
	}

	switch action {
	case "add":
		payload = fmt.Sprintf(addGroupMemberXML, rel, object)
	case "remove":
		payload = fmt.Sprintf(removeXML, rel, object)
	default:
		return fmt.Errorf("invalid action: %s", action)
	}

	_, err = s.newRequest(
		http.MethodPatch,
		path,
		[]byte(payload),
		map[string]string{"Content-Type": contentType},
		nil,
	)

	return err
}

func (s *Space) RenameObject(grouptype, name, newname string) error {
	objectID, err := s.getObjectID(name, grouptype)
	if err != nil {
		return err
	}

	if objectID == 0 {
		return nil
	}

	var (
		path        string
		contentType string
		rel         string
	)

	path = fmt.Sprintf(
		"/api/juniper/sd/address-management/addresses/%d",
		objectID,
	)
	contentType = contentAddressPatch
	rel = "address"

	if grouptype == "service" {
		path = fmt.Sprintf(
			"/api/juniper/sd/service-management/services/%d",
			objectID,
		)
		contentType = contentServicePatch
		rel = "service"
	}

	payload := fmt.Sprintf(renameXML, rel, newname)

	_, err = s.newRequest(
		http.MethodPatch,
		path,
		[]byte(payload),
		map[string]string{"Content-Type": contentType},
		nil,
	)

	return err
}

func (s *Space) DeleteObject(grouptype, name string) error {
	objectID, err := s.getObjectID(name, grouptype)
	if err != nil {
		return err
	}

	if objectID == 0 {
		return nil
	}

	path := fmt.Sprintf(
		"/api/juniper/sd/address-management/addresses/%d",
		objectID,
	)

	if grouptype == "service" {
		path = fmt.Sprintf(
			"/api/juniper/sd/service-management/services/%d",
			objectID,
		)
	}

	_, err = s.newRequest(
		http.MethodDelete,
		path,
		nil,
		nil,
		nil,
	)

	return err
}

func (s *Space) DeleteAddress(name string) error {
	if s == nil {
		return errors.New("attempt to call DeleteAddress on nil Space object")
	}

	objectID, err := s.getObjectID(name, "address")
	if err != nil {
		return err
	}
	if objectID == 0 {
		return fmt.Errorf("address not found: %s", name)
	}

	_, err = s.newRequest(
		http.MethodDelete,
		fmt.Sprintf(
			"/api/juniper/sd/address-management/addresses/%d",
			objectID,
		),
		nil,
		nil,
		nil,
	)

	return err
}

func (s *Space) Services(filter ...string) (*Services, error) {
	query := map[string]string{
		"filter": "(global eq '')",
	}

	if len(filter) > 0 {
		query["filter"] = fmt.Sprintf("(global eq '%s')", filter[0])
	}

	body, err := s.newRequest(
		http.MethodGet,
		"/api/juniper/sd/service-management/services",
		nil,
		nil,
		query,
	)
	if err != nil {
		return nil, err
	}

	var services Services
	if err := xml.Unmarshal(body, &services); err != nil {
		return nil, err
	}

	return &services, nil
}

func (s *Space) GroupMembers(grouptype, name string) (*GroupMembers, error) {
	objectID, err := s.getObjectID(name, grouptype)
	if err != nil {
		return nil, err
	}

	if objectID == 0 {
		return nil, fmt.Errorf("group not found: %s", name)
	}

	path := fmt.Sprintf(
		"/api/juniper/sd/address-management/addresses/%d",
		objectID,
	)

	if grouptype == "service" {
		path = fmt.Sprintf(
			"/api/juniper/sd/service-management/services/%d",
			objectID,
		)
	}

	body, err := s.newRequest(
		http.MethodGet,
		path,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var members GroupMembers
	if err := xml.Unmarshal(body, &members); err != nil {
		return nil, err
	}

	return &members, nil
}

func (s *Space) SecurityDevices() (*SecurityDevices, error) {
	body, err := s.newRequest(
		http.MethodGet,
		"/api/juniper/sd/device-management/devices",
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var devices SecurityDevices
	if err := xml.Unmarshal(body, &devices); err != nil {
		return nil, err
	}

	return &devices, nil
}

func (s *Space) Policies() (*Policies, error) {
	body, err := s.newRequest(
		http.MethodGet,
		"/api/juniper/sd/fwpolicy-management/firewall-policies",
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var policies Policies
	if err := xml.Unmarshal(body, &policies); err != nil {
		return nil, err
	}

	return &policies, nil
}

func (s *Space) PublishPolicy(policy interface{}, update bool) (int, error) {
	var policyID int
	var err error

	switch v := policy.(type) {
	case int:
		policyID = v
	case string:
		policyID, err = s.getPolicyID(v)
		if err != nil {
			return 0, err
		}
		if policyID == 0 {
			return 0, errors.New("no policy found")
		}
	default:
		return 0, errors.New("policy must be int or string")
	}

	path := "/api/juniper/sd/fwpolicy-management/publish"
	if update {
		path += "?update=true"
	}

	payload := fmt.Sprintf(publishPolicyXML, policyID)

	body, err := s.newRequest(
		http.MethodPost,
		path,
		[]byte(payload),
		map[string]string{
			"Content-Type": contentPublish,
		},
		nil,
	)
	if err != nil {
		return 0, err
	}

	var job jobID
	if err := xml.Unmarshal(body, &job); err != nil {
		return 0, errors.New("no policy changes to publish")
	}

	return job.ID, nil
}

// UpdateDevice will update a changed security device, synchronizing it with
// Junos Space.
func (s *Space) UpdateDevice(device interface{}) (int, error) {
	if s == nil {
		return 0, errors.New("attempt to call UpdateDevice on nil Space object")
	}

	deviceID, err := s.getDeviceID(device)
	if err != nil {
		return 0, err
	}
	if deviceID == 0 {
		return 0, errors.New("device not found")
	}

	payload := fmt.Sprintf(updateDeviceXML, deviceID)

	body, err := s.newRequest(
		http.MethodPost,
		"/api/juniper/sd/device-management/update-devices",
		[]byte(payload),
		map[string]string{
			"Content-Type": contentUpdateDevices,
		},
		nil,
	)
	if err != nil {
		return 0, err
	}

	var job jobID
	if err := xml.Unmarshal(body, &job); err != nil {
		return 0, err
	}

	return job.ID, nil
}

func (s *Space) Variables() (*Variables, error) {
	body, err := s.newRequest(
		http.MethodGet,
		"/api/juniper/sd/variable-management/variable-definitions",
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var vars Variables
	if err := xml.Unmarshal(body, &vars); err != nil {
		return nil, err
	}

	return &vars, nil
}

func (s *Space) AddVariable(name, address string, description ...string) error {
	objectID, err := s.getObjectID(address, "address")
	if err != nil {
		return err
	}
	if objectID == 0 {
		return fmt.Errorf("address object not found: %s", address)
	}

	desc := ""
	if len(description) > 0 {
		desc = description[0]
	}

	payload := fmt.Sprintf(
		createVariableXML,
		name,
		"ADDRESS",
		desc,
		address,
		objectID,
	)

	_, err = s.newRequest(
		http.MethodPost,
		"/api/juniper/sd/variable-management/variable-definitions",
		[]byte(payload),
		map[string]string{
			"Content-Type": contentVariable,
		},
		nil,
	)

	return err
}

func (s *Space) DeleteVariable(name string) error {
	varID, err := s.getVariableID(name)
	if err != nil {
		return err
	}
	if varID == 0 {
		return fmt.Errorf("variable not found: %s", name)
	}

	_, err = s.newRequest(
		http.MethodDelete,
		fmt.Sprintf(
			"/api/juniper/sd/variable-management/variable-definitions/%d",
			varID,
		),
		nil,
		map[string]string{
			"Content-Type": contentVariable,
		},
		nil,
	)

	return err
}

// EditVariable creates a new state when adding/removing addresses to
// a polymorphic (variable) object. We do this to only get the list of
// security devices (SecurityDevices()) once, instead of call the function
// each time we want to modify a variable.
func (s *Space) EditVariable() (*VariableManagement, error) {
	devices, err := s.SecurityDevices()
	if err != nil {
		return nil, err
	}

	return &VariableManagement{
		Devices: devices.Devices,
		Space:   s,
	}, nil
}

func (v *VariableManagement) Add(address, name, firewall string) error {
	// Resolve variable ID
	varID, err := v.Space.getVariableID(name)
	if err != nil {
		return err
	}
	if varID == 0 {
		return fmt.Errorf("variable not found: %s", name)
	}

	// Resolve device ID
	var deviceID int
	for _, d := range v.Devices {
		if d.Name == firewall {
			deviceID = d.ID
			break
		}
	}
	if deviceID == 0 {
		return fmt.Errorf("device not found: %s", firewall)
	}

	moid := fmt.Sprintf(
		"net.juniper.jnap.sm.om.jpa.SecurityDeviceEntity:%d",
		deviceID,
	)

	// Resolve address object ID
	addrID, err := v.Space.getObjectID(address, "address")
	if err != nil {
		return err
	}
	if addrID == 0 {
		return fmt.Errorf("address not found: %s", address)
	}

	path := fmt.Sprintf(
		"/api/juniper/sd/variable-management/variable-definitions/%d",
		varID,
	)

	// Fetch existing variable definition
	body, err := v.Space.newRequest(
		http.MethodGet,
		path,
		nil,
		nil,
		nil,
	)
	if err != nil {
		return err
	}

	var varData existingVariable
	if err := xml.Unmarshal(body, &varData); err != nil {
		return err
	}

	// Modify variable content
	varContent := v.Space.modifyVariableContent(
		&varData,
		moid,
		firewall,
		address,
		addrID,
	)

	payload := fmt.Sprintf(
		modifyVariableXML,
		varData.Name,
		varData.Type,
		varData.Description,
		varData.Version,
		varData.DefaultName,
		varData.DefaultValue,
		varContent,
	)

	// Update variable definition
	_, err = v.Space.newRequest(
		http.MethodPut,
		path,
		[]byte(payload),
		map[string]string{
			"Content-Type": contentVariable,
		},
		nil,
	)

	return err
}
