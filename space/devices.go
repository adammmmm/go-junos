package space

import (
	"encoding/xml"
	"fmt"
	"net"
	"net/http"
)

const (
	contentDiscoverDevices = "application/vnd.net.juniper.space.device-management.discover-devices+xml;version=1"
	contentResync          = "application/vnd.net.juniper.space.device-management.exec-resync+xml;version=1"
)

const addDeviceHostXML = `
<discover-devices>
	<device>
		<hostname>%s</hostname>
		<user-name>%s</user-name>
		<password>%s</password>
	</device>
</discover-devices>
`

const addDeviceIPXML = `
<discover-devices>
	<device>
		<ip-address>%s</ip-address>
		<user-name>%s</user-name>
		<password>%s</password>
	</device>
</discover-devices>
`

type Device struct {
	XMLName xml.Name `xml:"device"`
	ID      int      `xml:"id"`
	Name    string   `xml:"name"`
	IP      string   `xml:"ip"`
	Type    string   `xml:"type"`
}

// Devices represents managed devices returned by Space
type Devices struct {
	XMLName xml.Name `xml:"devices"`
	Devices []Device `xml:"device"`
}

// jobID represents async job responses
type jobID struct {
	ID int `xml:"id"`
}

func (s *Space) getSoftwareID(name string) (int, error) {
	pkgs, err := s.Software()
	if err != nil {
		return 0, err
	}

	for _, p := range pkgs.Packages {
		if p.Name == name {
			return p.ID, nil
		}
	}

	return 0, fmt.Errorf("software image not found: %s", name)
}

func (s *Space) getDeviceID(device any) (int, error) {
	switch v := device.(type) {

	case int:
		if v <= 0 {
			return 0, fmt.Errorf("invalid device ID: %d", v)
		}
		return v, nil

	case string:
		if v == "" {
			return 0, fmt.Errorf("device identifier cannot be empty")
		}
		return s.findDeviceIDByString(v)

	default:
		return 0, fmt.Errorf(
			"unsupported device identifier type %T (must be int or string)",
			device,
		)
	}
}

func (s *Space) findDeviceIDByString(identifier string) (int, error) {
	devices, err := s.Devices()
	if err != nil {
		return 0, err
	}

	for _, d := range devices.Devices {
		if d.Name == identifier || d.IP == identifier {
			return d.ID, nil
		}
	}

	return 0, fmt.Errorf("device not found: %s", identifier)
}

// Devices queries the Junos Space server and returns all managed devices.
func (s *Space) Devices() (*Devices, error) {
	body, err := s.newRequest(
		http.MethodGet,
		"/api/space/device-management/devices",
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var devices Devices
	if err := xml.Unmarshal(body, &devices); err != nil {
		return nil, err
	}

	return &devices, nil
}

func (s *Space) AddDevice(host, user, password string) (int, error) {
	if host == "" || user == "" || password == "" {
		return 0, fmt.Errorf("host, user, and password must be provided")
	}

	template := addDeviceHostXML
	if net.ParseIP(host) != nil {
		template = addDeviceIPXML
	}

	payload := fmt.Sprintf(template, host, user, password)

	body, err := s.newRequest(
		http.MethodPost,
		"/api/space/device-management/discover-devices",
		[]byte(payload),
		map[string]string{
			"Content-Type": contentDiscoverDevices,
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

func (s *Space) RemoveDevice(device any) error {
	deviceID, err := s.getDeviceID(device)
	if err != nil {
		return err
	}

	_, err = s.newRequest(
		http.MethodDelete,
		fmt.Sprintf(
			"/api/space/device-management/devices/%d",
			deviceID,
		),
		nil,
		nil,
		nil,
	)

	return err
}

// Resync synchronizes the device with Junos Space.
func (s *Space) Resync(device interface{}) (int, error) {
	deviceID, err := s.getDeviceID(device)
	if err != nil {
		return 0, err
	}
	if deviceID == 0 {
		return 0, fmt.Errorf("device not found")
	}

	body, err := s.newRequest(
		http.MethodPost,
		fmt.Sprintf("/api/space/device-management/devices/%d/exec-resync", deviceID),
		nil,
		map[string]string{
			"Content-Type": contentResync,
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
