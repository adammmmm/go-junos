// Package junos provides automation for Junos (Juniper Networks) devices, as
// well as interaction with Junos Space.
package junos

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/nemith/netconf"
	ncssh "github.com/nemith/netconf/transport/ssh"
)

// All of our RPC calls we use.
var (
	rpcCommand             = "<command format=\"text\">%s</command>"
	rpcCommandXML          = "<command format=\"xml\">%s</command>"
	rpcCommit              = "<commit-configuration/>"
	rpcCommitAt            = "<commit-configuration><at-time>%s</at-time></commit-configuration>"
	rpcCommitAtLog         = "<commit-configuration><at-time>%s</at-time><log>%s</log></commit-configuration>"
	rpcCommitCheck         = "<commit-configuration><check/></commit-configuration>"
	rpcCommitConfirm       = "<commit-configuration><confirmed/><confirm-timeout>%d</confirm-timeout></commit-configuration>"
	rpcCommitFull          = "<commit-configuration><full/></commit-configuration>"
	rpcConfigFileSet       = "<load-configuration action=\"set\" format=\"text\"><configuration-set>%s</configuration-set></load-configuration>"
	rpcConfigFileText      = "<load-configuration format=\"text\"><configuration-text>%s</configuration-text></load-configuration>"
	rpcConfigFileXML       = "<load-configuration format=\"xml\"><configuration>%s</configuration></load-configuration>"
	rpcConfigURLSet        = "<load-configuration action=\"set\" format=\"text\" url=\"%s\"/>"
	rpcConfigURLText       = "<load-configuration format=\"text\" url=\"%s\"/>"
	rpcConfigURLXML        = "<load-configuration format=\"xml\" url=\"%s\"/>"
	rpcConfigStringSet     = "<load-configuration action=\"set\" format=\"text\"><configuration-set>%s</configuration-set></load-configuration>"
	rpcConfigStringText    = "<load-configuration action=\"replace\" format=\"text\"><configuration-text>%s</configuration-text></load-configuration>"
	rpcConfigStringXML     = "<load-configuration format=\"xml\"><configuration>%s</configuration></load-configuration>"
	rpcGetCandidateCompare = "<get-configuration compare=\"rollback\" rollback=\"%d\" format=\"text\"/>"
	rpcRescueConfig        = "<load-configuration rescue=\"rescue\"/>"
	rpcRescueDelete        = "<request-delete-rescue-configuration/>"
	rpcRescueSave          = "<request-save-rescue-configuration/>"
	rpcRollbackConfig      = "<load-configuration rollback=\"%d\"/>"
	rpcVersion             = "<get-software-information/>"
	rpcReboot              = "<request-reboot/>"
	rpcCommitHistory       = "<get-commit-information/>"
)

// Junos contains our session state.
type Junos struct {
	Session        *netconf.Session
	Hostname       string
	RoutingEngines int
	Platform       []RoutingEngine
	CommitTimeout  time.Duration
}

// AuthMethod defines how we want to authenticate to the device. If using a
// username and password to authenticate, the Credentials field must be populated like so:
//
// []string{"user", "password"}
//
// If you are using an SSH prviate key for authentication, you must provide the username,
// path to the private key, and passphrase. On most systems, the private key is found in
// the following location:
//
// ~/.ssh/id_rsa
//
// If you do not have a passphrase tied to your private key, then you can omit this field.
type AuthMethod struct {
	Credentials []string
	Username    string
	PrivateKey  string
	Passphrase  string
}

// CommitHistory holds all of the commit entries.
type CommitHistory struct {
	Entries []CommitEntry `xml:"commit-history"`
}

// CommitEntry holds information about each prevous commit.
type CommitEntry struct {
	Sequence  int    `xml:"sequence-number"`
	User      string `xml:"user"`
	Method    string `xml:"client"`
	Log       string `xml:"log"`
	Comment   string `xml:"comment"`
	Timestamp string `xml:"date-time"`
}

// RoutingEngine contains the hardware and software information for each route engine.
type RoutingEngine struct {
	Model   string
	Version string
}

type commandXML struct {
	Config string `xml:",innerxml"`
}

type commitError struct {
	Path    string `xml:"error-path"`
	Element string `xml:"error-info>bad-element"`
	Message string `xml:"error-message"`
}

type commitResults struct {
	XMLName xml.Name      `xml:"commit-results"`
	Errors  []commitError `xml:"rpc-error"`
}

type NetconfOK struct {
	XMLName xml.Name `xml:"ok"`
}

// cdiffXML - candidate config diff XML
type cdiffXML struct {
	XMLName xml.Name `xml:"configuration-information"`
	Error   string   `xml:"rpc-error>error-message"`
	Config  string   `xml:"configuration-output"`
}

type versionRouteEngines struct {
	XMLName xml.Name             `xml:"multi-routing-engine-results"`
	RE      []versionRouteEngine `xml:"multi-routing-engine-item>software-information"`
}

type versionRouteEngine struct {
	XMLName     xml.Name             `xml:"software-information"`
	Hostname    string               `xml:"host-name"`
	Platform    string               `xml:"product-model"`
	PackageInfo []versionPackageInfo `xml:"package-information"`
}

type versionPackageInfo struct {
	XMLName         xml.Name `xml:"package-information"`
	PackageName     []string `xml:"name"`
	SoftwareVersion []string `xml:"comment"`
}

func decodeCommitReply(data []byte) error {
	// Case 1: commit-results
	var cr commitResults
	if err := xml.Unmarshal(data, &cr); err == nil && cr.XMLName.Local == "commit-results" {
		return nil
	}

	// Case 2: simple <ok/>
	var ok NetconfOK
	if err := xml.Unmarshal(data, &ok); err == nil && ok.XMLName.Local == "ok" {
		return nil
	}

	// Otherwise: unknown response
	return fmt.Errorf("unexpected commit response: %s", strings.TrimSpace(string(data)))
}

// genSSHClientConfig is a wrapper function based around the auth method defined
// (user/password or private key) which returns the SSH client configuration used to
// connect.
// genSSHClientConfig creates an ssh.ClientConfig for password or key-based auth
func genSSHClientConfig(auth *AuthMethod) (*ssh.ClientConfig, error) {
	if auth == nil {
		return nil, errors.New("auth method is nil")
	}

	cfg := &ssh.ClientConfig{
		Timeout:         120 * time.Second,
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}

	// Username resolution (CRITICAL FIX)
	if auth.Username != "" {
		cfg.User = auth.Username
	} else if len(auth.Credentials) == 2 {
		cfg.User = auth.Credentials[0]
	} else {
		return nil, errors.New("no username provided")
	}

	// Password authentication
	if len(auth.Credentials) == 2 {
		password := auth.Credentials[1]
		cfg.Auth = []ssh.AuthMethod{
			ssh.KeyboardInteractive(
				func(user, instruction string, questions []string, echos []bool) ([]string, error) {
					answers := make([]string, len(questions))
					for i := range questions {
						answers[i] = password
					}
					return answers, nil
				},
			),
			ssh.Password(password),
		}
		return cfg, nil
	}

	// Private key authentication
	if auth.PrivateKey != "" {
		key, err := os.ReadFile(auth.PrivateKey)
		if err != nil {
			return nil, err
		}

		var signer ssh.Signer
		if auth.Passphrase != "" {
			signer, err = ssh.ParsePrivateKeyWithPassphrase(
				key,
				[]byte(auth.Passphrase),
			)
		} else {
			signer, err = ssh.ParsePrivateKey(key)
		}

		if err != nil {
			return nil, err
		}

		cfg.Auth = []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		}

		return cfg, nil
	}

	return nil, errors.New("no authentication method provided")
}

// NewSession establishes a new connection to a Junos device that we will use
// to run our commands against.
// Authentication methods are defined using the AuthMethod struct, and are as follows:
//
// username and password, SSH private key (with or without passphrase)
//
// Please view the package documentation for AuthMethod on how to use these methods.
//
// NOTE: most users should use this function, instead of the other NewSession* functions
func NewSession(host string, auth *AuthMethod) (*Junos, error) {
	clientConfig, err := genSSHClientConfig(auth)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return nil, errors.New("host is empty")
	}

	if !strings.Contains(host, ":") {
		host += ":22"
	}

	return NewSessionWithConfig(host, clientConfig)
}

// NewSessionWithConfig establishes a new connection to a Junos device that we will use
// to run our commands against.
//
// This is especially useful if you need to customize the SSH connection beyond
// what's supported in NewSession().
func NewSessionWithConfig(host string, clientConfig *ssh.ClientConfig) (*Junos, error) {
	ctx, cancel := context.WithTimeout(context.Background(), clientConfig.Timeout)
	defer cancel()

	transport, err := ncssh.Dial(ctx, "tcp", host, clientConfig)
	if err != nil {
		return nil, fmt.Errorf("error connecting to %s - %s", host, err)
	}

	sess, err := netconf.Open(transport)
	if err != nil {
		return nil, fmt.Errorf("error setting up session to %s - %s", host, err)
	}

	return NewSessionFromNetconf(sess)
}

// NewSessionFromNetconf uses an existing netconf.Session to run our commands against
//
// This is especially useful if you need to customize the SSH connection beyond
// what's supported in NewSession().
func NewSessionFromNetconf(s *netconf.Session) (*Junos, error) {
	j := &Junos{
		Session: s,
	}

	return j, j.GatherFacts()
}

func (j *Junos) GatherFacts() error {
	if j == nil {
		return errors.New("attempt to call GatherFacts on nil Junos object")
	}

	s := j.Session
	rex := regexp.MustCompile(`^.*\[(.*)\]`)
	ctx := context.Background()

	// Junos vendor-specific RPC
	reply, err := s.Do(ctx, rpcVersion)
	if err != nil {
		return err
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	formatted := strings.ReplaceAll(string(reply.Body), "\n", "")

	// Multi-routing-engine devices
	if strings.Contains(formatted, "multi-routing-engine-results") {
		var facts versionRouteEngines
		if err := xml.Unmarshal([]byte(formatted), &facts); err != nil {
			return err
		}

		numRE := len(facts.RE)
		if numRE == 0 {
			return errors.New("no routing engines found")
		}

		hostname := facts.RE[0].Hostname
		res := make([]RoutingEngine, 0, numRE)

		for i := 0; i < numRE; i++ {
			version := rex.FindStringSubmatch(
				facts.RE[i].PackageInfo[0].SoftwareVersion[0],
			)
			model := strings.ToUpper(facts.RE[i].Platform)

			switch len(version) {
			case 1:
				res = append(res, RoutingEngine{
					Model:   model,
					Version: version[0],
				})
			case 2:
				res = append(res, RoutingEngine{
					Model:   model,
					Version: version[1],
				})
			}
		}

		j.Hostname = hostname
		j.RoutingEngines = numRE
		j.Platform = res
		j.CommitTimeout = 0
		return nil
	}

	// Single routing engine
	var facts versionRouteEngine
	if err := xml.Unmarshal([]byte(formatted), &facts); err != nil {
		return err
	}

	version := rex.FindStringSubmatch(
		facts.PackageInfo[0].SoftwareVersion[0],
	)

	j.Hostname = facts.Hostname
	j.RoutingEngines = 1
	j.Platform = []RoutingEngine{
		{
			Model:   strings.ToUpper(facts.Platform),
			Version: version[1],
		},
	}
	j.CommitTimeout = 0

	return nil
}

// RPC executes an arbitrary NETCONF RPC against the device.
func (j *Junos) RPC(rpc string) (string, error) {
	if j == nil || j.Session == nil {
		return "", errors.New("attempt to call RPC on nil Junos object")
	}
	ctx := context.Background()

	reply, err := j.Session.Do(ctx, rpc)
	if err != nil {
		return "", err
	}

	type result struct {
		Output string `xml:",innerxml"`
	}

	var r result
	if err := xml.Unmarshal([]byte(reply.Body), &r); err != nil {
		return "", err
	}

	if len(reply.Errors) > 0 {
		return "", errors.New(reply.Errors[0].Message)
	}

	return strings.TrimSpace(r.Output), nil
}

// HasPendingChanges reports whether there are uncommitted candidate configuration changes.
func (j *Junos) HasPendingChanges() (bool, error) {
	if j == nil || j.Session == nil {
		return false, errors.New("attempt to call HasPendingChanges on nil Junos object")
	}

	diff, err := j.Diff(0)
	if err != nil {
		if strings.Contains(err.Error(), "no candidate") ||
			strings.Contains(err.Error(), "configuration database is not open") {
			return false, nil
		}
		return false, err
	}

	diff = strings.TrimSpace(diff)

	return diff != "", nil
}

func (j *Junos) CommandText(cmd string) (string, error) {
	out, err := j.Command(cmd)
	if err != nil {
		return "", err
	}

	type result struct {
		Output string `xml:",innerxml"`
	}

	var r result
	if err := xml.Unmarshal([]byte(out), &r); err != nil {
		return "", err
	}

	return strings.TrimSpace(r.Output), nil
}

func (j *Junos) Close() error {
	if j == nil || j.Session == nil {
		return nil
	}
	return j.Session.Close(context.Background())
}

// Command executes any operational mode command, such as "show" or "request".
// If you wish to return the results of the command, specify the format,
// which must be "text" or "xml" as the second parameter (optional).
func (j *Junos) Command(cmd string, format ...string) (string, error) {
	if j == nil {
		return "", errors.New("attempt to call Command on nil Junos object")
	}

	var command string
	command = fmt.Sprintf(rpcCommand, cmd)

	if len(format) > 0 && format[0] == "xml" {
		command = fmt.Sprintf(rpcCommandXML, cmd)
	}

	ctx := context.Background()

	reply, err := j.Session.Do(ctx, command)
	if err != nil {
		return "", err
	}

	if len(reply.Errors) > 0 {
		return "", errors.New(reply.Errors[0].Message)
	}

	if len(reply.Body) == 0 {
		return "", errors.New("no output available - please check the syntax of your command")
	}

	// Text output requires unwrapping XML
	if len(format) > 0 && format[0] == "text" {
		var output commandXML
		if err := xml.Unmarshal(reply.Body, &output); err != nil {
			return "", err
		}

		return output.Config, nil
	}

	// XML output (or default)
	return string(reply.Body), nil
}

// CommitHistory gathers all the information about the previous 5 commits.
func (j *Junos) CommitHistory() (*CommitHistory, error) {
	if j == nil || j.Session == nil {
		return nil, errors.New("attempt to call CommitHistory on nil Junos object")
	}

	var history CommitHistory
	ctx := context.Background()

	reply, err := j.Session.Do(ctx, rpcCommitHistory)
	if err != nil {
		return nil, err
	}

	if len(reply.Errors) > 0 {
		return nil, errors.New(reply.Errors[0].Message)
	}

	if len(reply.Body) == 0 {
		return nil, errors.New("could not load commit history")
	}

	formatted := strings.ReplaceAll(string(reply.Body), "\n", "")
	if err := xml.Unmarshal([]byte(formatted), &history); err != nil {
		return nil, err
	}

	return &history, nil
}

func (c CommitHistory) String() string {
	var b strings.Builder
	for _, e := range c.Entries {
		fmt.Fprintf(
			&b,
			"#%d %-8s %-8s %-24s %s\n",
			e.Sequence,
			e.User,
			e.Method,
			e.Timestamp,
			e.Comment,
		)
	}
	return b.String()
}

// Commit commits the configuration.
func (j *Junos) Commit() error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call Commit on nil Junos object")
	}

	ctx := context.Background()

	reply, err := j.Session.Do(ctx, rpcCommit)
	if err != nil {
		return err
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	if err := decodeCommitReply(reply.Body); err != nil {
		return err
	}

	if j.CommitTimeout > 0 {
		time.Sleep(j.CommitTimeout * time.Second)
	}

	return nil
}

func (j *Junos) CommitAt(timeStr string, message ...string) error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call CommitAt on nil Junos object")
	}

	ctx := context.Background()

	command := fmt.Sprintf(rpcCommitAt, timeStr)
	if len(message) > 0 {
		command = fmt.Sprintf(rpcCommitAtLog, timeStr, message[0])
	}

	reply, err := j.Session.Do(ctx, command)
	if err != nil {
		return err
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	return decodeCommitReply(reply.Body)
}

func (j *Junos) CommitCheck() error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call CommitCheck on nil Junos object")
	}

	ctx := context.Background()

	reply, err := j.Session.Do(ctx, rpcCommitCheck)
	if err != nil {
		return err
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	return decodeCommitReply(reply.Body)
}

func (j *Junos) CommitConfirm(delay int) error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call CommitConfirm on nil Junos object")
	}

	ctx := context.Background()
	command := fmt.Sprintf(rpcCommitConfirm, delay)

	reply, err := j.Session.Do(ctx, command)
	if err != nil {
		return err
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	return decodeCommitReply(reply.Body)
}

// Diff compares candidate config to current (rollback 0) or previous rollback.
// This is equivalent to 'show | compare' or 'show | compare rollback X' when
// in configuration mode.
func (j *Junos) Diff(rollback int) (string, error) {
	if j == nil || j.Session == nil {
		return "", errors.New("attempt to call Diff on nil Junos object")
	}

	var cd cdiffXML
	ctx := context.Background()

	command := fmt.Sprintf(rpcGetCandidateCompare, rollback)

	reply, err := j.Session.Do(ctx, command)
	if err != nil {
		return "", err
	}

	if len(reply.Errors) > 0 {
		return "", errors.New(reply.Errors[0].Message)
	}

	if err := xml.Unmarshal(reply.Body, &cd); err != nil {
		return "", err
	}

	if cd.Error != "" {
		return "", errors.New(strings.Trim(cd.Error, "\r\n"))
	}

	return cd.Config, nil
}

// GetConfig returns the configuration starting at the given section.
// If section is omitted, the entire configuration is returned.
// Format must be "text" or "xml".
func (j *Junos) GetConfig(format string, section ...string) (string, error) {
	if j == nil || j.Session == nil {
		return "", errors.New("attempt to call GetConfig on nil Junos object")
	}

	ctx := context.Background()

	command := fmt.Sprintf(`<get-configuration format="%s"><configuration>`, format)

	if len(section) > 0 {
		secs := strings.Split(section[0], ">")
		nSecs := len(secs) - 1

		if nSecs >= 0 {
			for i := 0; i < nSecs; i++ {
				command += fmt.Sprintf("<%s>", secs[i])
			}
			command += fmt.Sprintf("<%s/>", secs[nSecs])

			for i := nSecs - 1; i >= 0; i-- {
				command += fmt.Sprintf("</%s>", secs[i])
			}
			command += "</configuration></get-configuration>"
		}
	} else {
		command += "</configuration></get-configuration>"
	}

	reply, err := j.Session.Do(ctx, command)
	if err != nil {
		return "", err
	}

	body := reply.Body

	if len(body) < 50 {
		return "", errors.New("the section you provided is not configured on the device")
	}

	if len(reply.Errors) > 0 {
		return "", errors.New(reply.Errors[0].Message)
	}

	switch format {
	case "text":
		var output commandXML
		if err := xml.Unmarshal(body, &output); err != nil {
			return "", err
		}

		if len(output.Config) <= 1 {
			return "", errors.New("the section you provided is not configured on the device")
		}

		return output.Config, nil

	case "xml":
		return string(body), nil
	}

	return string(body), nil
}

// Config loads a given configuration file from your local machine,
// a remote (FTP or HTTP server) location, or via configuration statements
// from variables (type string or []string) within your script.
// Format must be "set", "text" or "xml".
func (j *Junos) Config(path interface{}, format string, commit bool) error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call Config on nil Junos object")
	}

	var command string

	switch format {
	case "set":
		switch v := path.(type) {
		case string:
			if strings.Contains(v, "tp://") {
				command = fmt.Sprintf(rpcConfigURLSet, v)
				break
			}

			if _, err := os.ReadFile(v); err != nil {
				command = fmt.Sprintf(rpcConfigStringSet, v)
			} else {
				data, err := os.ReadFile(v)
				if err != nil {
					return err
				}
				command = fmt.Sprintf(rpcConfigFileSet, string(data))
			}

		case []string:
			command = fmt.Sprintf(rpcConfigStringSet, strings.Join(v, "\n"))
		}

	case "text":
		switch v := path.(type) {
		case string:
			if strings.Contains(v, "tp://") {
				command = fmt.Sprintf(rpcConfigURLText, v)
				break
			}

			if _, err := os.ReadFile(v); err != nil {
				command = fmt.Sprintf(rpcConfigStringText, v)
			} else {
				data, err := os.ReadFile(v)
				if err != nil {
					return err
				}
				command = fmt.Sprintf(rpcConfigFileText, string(data))
			}

		case []string:
			command = fmt.Sprintf(rpcConfigStringText, strings.Join(v, "\n"))
		}

	case "xml":
		switch v := path.(type) {
		case string:
			if strings.Contains(v, "tp://") {
				command = fmt.Sprintf(rpcConfigURLXML, v)
				break
			}

			if _, err := os.ReadFile(v); err != nil {
				command = fmt.Sprintf(rpcConfigStringXML, v)
			} else {
				data, err := os.ReadFile(v)
				if err != nil {
					return err
				}
				command = fmt.Sprintf(rpcConfigFileXML, string(data))
			}

		case []string:
			command = fmt.Sprintf(rpcConfigStringXML, strings.Join(v, "\n"))
		}
	}

	ctx := context.Background()

	reply, err := j.Session.Do(ctx, command)
	if err != nil {
		return err
	}

	if commit {
		if err := j.Commit(); err != nil {
			return err
		}
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	return nil
}

func (j *Junos) Lock() error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call Lock on nil Junos object")
	}

	ctx := context.Background()

	if err := j.Session.Lock(ctx, netconf.Candidate); err != nil {
		return err
	}

	if j.CommitTimeout > 0 {
		time.Sleep(j.CommitTimeout * time.Second)
	}

	return nil
}

// Rescue will create or delete the rescue configuration given "save" or "delete" for the action.
func (j *Junos) Rescue(action string) error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call Rescue on nil Junos object")
	}

	var command string
	switch action {
	case "save":
		command = rpcRescueSave
	case "delete":
		command = rpcRescueDelete
	default:
		return errors.New("you must specify save or delete for a rescue config action")
	}

	ctx := context.Background()

	reply, err := j.Session.Do(ctx, command)
	if err != nil {
		return err
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	return nil
}

// Rollback loads and commits the configuration of a given rollback number
// or rescue state, by specifying "rescue".
func (j *Junos) Rollback(option interface{}) error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call Rollback on nil Junos object")
	}

	command := fmt.Sprintf(rpcRollbackConfig, option)
	if option == "rescue" {
		command = rpcRescueConfig
	}

	ctx := context.Background()

	reply, err := j.Session.Do(ctx, command)
	if err != nil {
		return err
	}

	if err := j.Commit(); err != nil {
		return err
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	return nil
}

func (j *Junos) Unlock() error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call Unlock on nil Junos object")
	}

	ctx := context.Background()

	if err := j.Session.Unlock(ctx, netconf.Candidate); err != nil {
		return err
	}

	if j.CommitTimeout > 0 {
		time.Sleep(j.CommitTimeout * time.Second)
	}

	return nil
}

// Reboot will reboot the device.
func (j *Junos) Reboot() error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call Reboot on nil Junos object")
	}

	ctx := context.Background()

	reply, err := j.Session.Do(ctx, rpcReboot)
	if err != nil {
		return err
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	return nil
}

// CommitFull does a full commit on the configuration, which requires all daemons to
// check and evaluate the new configuration. Useful for when you get an error with
// a commit or when you've changed the configuration significantly.
func (j *Junos) CommitFull() error {
	if j == nil || j.Session == nil {
		return errors.New("attempt to call CommitFull on nil Junos object")
	}

	ctx := context.Background()

	reply, err := j.Session.Do(ctx, rpcCommitFull)
	if err != nil {
		return err
	}

	if len(reply.Errors) > 0 {
		return errors.New(reply.Errors[0].Message)
	}

	return nil
}

// SetCommitTimeout will add the given delay time (in seconds) to the following commit functions: Lock(),
// Commit() and Unlock(). When configuring multiple devices, or having a large configuration to push, this can
// greatly reduce errors (especially if you're dealing with latency).
func (j *Junos) SetCommitTimeout(delay int) {
	d := time.Duration(delay)

	j.CommitTimeout = d
}
