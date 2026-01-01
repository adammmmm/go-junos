package junos

import (
	"encoding/xml"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
)

// SecurityZones contains all of our security-zone information.
type SecurityZones struct {
	XMLName xml.Name `xml:"configuration"`
	Zones   []Zone   `xml:"security>zones>security-zone"`
}

// Zone contains information about each individual security-zone.
type Zone struct {
	Name           string          `xml:"name"`
	AddressEntries []AddressEntry  `xml:"address-book>address"`
	AddressSets    []AddressSet    `xml:"address-book>address-set"`
	ZoneInterfaces []ZoneInterface `xml:"interfaces"`
}

// AddressEntry contains information about each individual address-book entry.
type AddressEntry struct {
	Name     string `xml:"name"`
	IP       string `xml:"ip-prefix,omitempty"`
	DNSName  string `xml:"dns-name>name,omitempty"`
	Wildcard string `xml:"wildcard-address>name,omitempty"`
}

// AddressSet contains all of the address-sets (groups) in the address-book.
type AddressSet struct {
	Name           string         `xml:"name"`
	AddressEntries []AddressEntry `xml:"address"`
}

// ZoneInterface contains a list of all interfaces that belong to the zone.
type ZoneInterface struct {
	Name string `xml:"name"`
}

// ConvertAddressBook will generate the configuration needed to migrate from a zone-based address
// book to a global one. You can then use Config() to apply the changes if necessary.
func (j *Junos) ConvertAddressBook() []string {
	vrx := regexp.MustCompile(`(\d+)\.(\d+)([RBISX]{1})(\d+)(\.(\d+))?`)

	for _, d := range j.Platform {
		if strings.Contains(d.Model, "FIREFLY") {
			continue
		}

		if !strings.Contains(d.Model, "SRX") {
			fmt.Printf("This device doesn't look to be an SRX (%s). You can only run this script against an SRX.\n", d.Model)
			os.Exit(0)
		}
		versionBreak := vrx.FindStringSubmatch(d.Version)
		maj, _ := strconv.Atoi(versionBreak[1])
		min, _ := strconv.Atoi(versionBreak[2])
		// rel := versionBreak[3]
		// build, _ := strconv.Atoi(versionBreak[4])

		if maj <= 11 && min < 2 {
			fmt.Println("You must be running JUNOS version 11.2 or above in order to use this conversion tool.")
			os.Exit(0)
		}
	}

	var seczones SecurityZones
	globalAddressBook := []string{}

	zoneConfig, _ := j.GetConfig("xml", "security>zones")
	if err := xml.Unmarshal([]byte(zoneConfig), &seczones); err != nil {
		fmt.Println(err)
	}

	for _, z := range seczones.Zones {
		for _, a := range z.AddressEntries {
			if a.DNSName != "" {
				globalConfig := fmt.Sprintf("set security address-book global address %s dns-name %s\n", a.Name, a.DNSName)
				globalAddressBook = append(globalAddressBook, globalConfig)
			}
			if a.Wildcard != "" {
				globalConfig := fmt.Sprintf("set security address-book global address %s wildcard-address %s\n", a.Name, a.Wildcard)
				globalAddressBook = append(globalAddressBook, globalConfig)
			}
			if a.IP != "" {
				globalConfig := fmt.Sprintf("set security address-book global address %s %s\n", a.Name, a.IP)
				globalAddressBook = append(globalAddressBook, globalConfig)
			}
		}

		for _, as := range z.AddressSets {
			for _, addr := range as.AddressEntries {
				globalConfig := fmt.Sprintf("set security address-book global address-set %s address %s\n", as.Name, addr.Name)
				globalAddressBook = append(globalAddressBook, globalConfig)
			}
		}

		removeConfig := fmt.Sprintf("delete security zones security-zone %s address-book\n", z.Name)
		globalAddressBook = append(globalAddressBook, removeConfig)
	}

	return globalAddressBook
}
