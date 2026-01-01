package junos

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Space represents a Junos Space API client.
type Space struct {
	Host     string
	User     string
	Password string

	client *http.Client
}

// NewSpace creates a new Junos Space client.
func NewSpace(host, user, password string) *Space {
	return &Space{
		Host:     host,
		User:     user,
		Password: password,
		client: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					InsecureSkipVerify: true,
				},
			},
		},
	}
}

func (s *Space) doRequest(
	ctx context.Context,
	method string,
	path string,
	body []byte,
	headers map[string]string,
	query map[string]string,
) ([]byte, error) {

	url := fmt.Sprintf("https://%s%s", s.Host, path)

	req, err := http.NewRequestWithContext(
		ctx,
		method,
		url,
		bytes.NewReader(body),
	)
	if err != nil {
		return nil, err
	}

	if len(query) > 0 {
		q := req.URL.Query()
		for k, v := range query {
			q.Set(k, v)
		}
		req.URL.RawQuery = q.Encode()
	}

	req.SetBasicAuth(s.User, s.Password)

	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf(
			"space API error: status=%d body=%s",
			resp.StatusCode,
			string(respBody),
		)
	}

	return respBody, nil
}

func (s *Space) newRequest(
	method, path string,
	body []byte,
	headers map[string]string,
	query map[string]string,
) ([]byte, error) {
	return s.doRequest(context.Background(), method, path, body, headers, query)
}
