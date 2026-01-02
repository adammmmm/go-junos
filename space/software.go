package space

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
)

type SoftwarePackages struct {
	XMLName  xml.Name          `xml:"software-packages"`
	Packages []SoftwarePackage `xml:"software-package"`
}

type SoftwarePackage struct {
	ID      int    `xml:"id"`
	Name    string `xml:"name"`
	Version string `xml:"version"`
}

type SoftwareUpgrade struct {
	UseDownloaded bool
	Validate      bool
	Reboot        bool
	RebootAfter   bool
	Cleanup       bool
	RemoveAfter   bool
}

func (s *Space) resolveDeviceAndSoftware(device, image string) (int, int, error) {
	deviceID, err := s.getDeviceID(device)
	if err != nil {
		return 0, 0, err
	}
	if deviceID == 0 {
		return 0, 0, errors.New("device not found")
	}

	softwareID, err := s.getSoftwareID(image)
	if err != nil {
		return 0, 0, err
	}
	if softwareID == 0 {
		return 0, 0, errors.New("software image not found")
	}

	return deviceID, softwareID, nil
}

func (s *Space) Software() (*SoftwarePackages, error) {
	body, err := s.newRequest(
		http.MethodGet,
		"/api/space/software-management/packages",
		nil,
		nil,
		nil,
	)
	if err != nil {
		return nil, err
	}

	var software SoftwarePackages
	if err := xml.Unmarshal(body, &software); err != nil {
		return nil, err
	}

	return &software, nil
}

func (s *Space) DeploySoftware(
	device, image string,
	options *SoftwareUpgrade,
) (int, error) {

	if options == nil {
		return 0, errors.New("software upgrade options cannot be nil")
	}

	deviceID, err := s.getDeviceID(device)
	if err != nil {
		return 0, err
	}
	if deviceID == 0 {
		return 0, errors.New("device not found")
	}

	softwareID, err := s.getSoftwareID(image)
	if err != nil {
		return 0, err
	}
	if softwareID == 0 {
		return 0, errors.New("software image not found")
	}

	type deployRequest struct {
		XMLName       xml.Name `xml:"exec-deploy"`
		DeviceID      int      `xml:"device-id"`
		UseDownloaded bool     `xml:"use-downloaded"`
		Validate      bool     `xml:"validate"`
		Reboot        bool     `xml:"reboot"`
		RebootAfter   bool     `xml:"reboot-after"`
		Cleanup       bool     `xml:"cleanup"`
		RemoveAfter   bool     `xml:"remove-after"`
	}

	req := deployRequest{
		DeviceID:      deviceID,
		UseDownloaded: options.UseDownloaded,
		Validate:      options.Validate,
		Reboot:        options.Reboot,
		RebootAfter:   options.RebootAfter,
		Cleanup:       options.Cleanup,
		RemoveAfter:   options.RemoveAfter,
	}

	payload, err := xml.Marshal(req)
	if err != nil {
		return 0, err
	}

	body, err := s.newRequest(
		http.MethodPost,
		fmt.Sprintf(
			"/api/space/software-management/packages/%d/exec-deploy",
			softwareID,
		),
		payload,
		map[string]string{
			"Content-Type": contentExecDeploy,
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

func (s *Space) RemoveStagedSoftware(device, image string) (int, error) {
	deviceID, softwareID, err := s.resolveDeviceAndSoftware(device, image)
	if err != nil {
		return 0, err
	}

	type removeRequest struct {
		XMLName  xml.Name `xml:"exec-remove"`
		DeviceID int      `xml:"device-id"`
	}

	req := removeRequest{
		DeviceID: deviceID,
	}

	payload, err := xml.Marshal(req)
	if err != nil {
		return 0, err
	}

	body, err := s.newRequest(
		http.MethodPost,
		fmt.Sprintf(
			"/api/space/software-management/packages/%d/exec-remove",
			softwareID,
		),
		payload,
		map[string]string{
			"Content-Type": contentExecRemove,
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

func (s *Space) StageSoftware(device, image string, cleanup bool) (int, error) {
	deviceID, softwareID, err := s.resolveDeviceAndSoftware(device, image)
	if err != nil {
		return 0, err
	}

	type stageRequest struct {
		XMLName  xml.Name `xml:"exec-stage"`
		DeviceID int      `xml:"device-id"`
		Cleanup  bool     `xml:"cleanup"`
	}

	req := stageRequest{
		DeviceID: deviceID,
		Cleanup:  cleanup,
	}

	payload, err := xml.Marshal(req)
	if err != nil {
		return 0, err
	}

	body, err := s.newRequest(
		http.MethodPost,
		fmt.Sprintf(
			"/api/space/software-management/packages/%d/exec-stage",
			softwareID,
		),
		payload,
		map[string]string{
			"Content-Type": contentExecStage,
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
