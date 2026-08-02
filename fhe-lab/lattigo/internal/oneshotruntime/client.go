package oneshotruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

type RemoteError struct {
	Code string
}

func (e *RemoteError) Error() string { return "operator rejected request: " + e.Code }

type OperatorClient struct {
	point   uint64
	baseURL string
	client  *http.Client
}

func NewOperatorClient(config RunnerOperator) (*OperatorClient, error) {
	if validateEndpoint(config.Endpoint) != nil {
		return nil, ErrConfig
	}
	identity, err := config.Identity.operatorIdentity()
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(config.Endpoint)
	if err != nil {
		return nil, ErrConfig
	}
	expected := identity.TransportCertFingerprint
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, // Exact leaf pin and hostname are verified below.
		VerifyConnection: func(state tls.ConnectionState) error {
			if len(state.PeerCertificates) != 1 {
				return ErrTransport
			}
			leaf := state.PeerCertificates[0]
			if sha256.Sum256(leaf.Raw) != expected || leaf.VerifyHostname(parsed.Hostname()) != nil {
				return ErrTransport
			}
			now := time.Now()
			if now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
				return ErrTransport
			}
			return nil
		},
	}
	transport := &http.Transport{
		Proxy:                 nil,
		TLSClientConfig:       tlsConfig,
		DisableCompression:    true,
		DisableKeepAlives:     false,
		MaxIdleConns:          3,
		MaxIdleConnsPerHost:   1,
		IdleConnTimeout:       30 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 5 * time.Minute,
		ExpectContinueTimeout: time.Second,
	}
	return &OperatorClient{
		point:   identity.Point,
		baseURL: config.Endpoint,
		client: &http.Client{
			Transport:     transport,
			Timeout:       6 * time.Minute,
			CheckRedirect: func(*http.Request, []*http.Request) error { return ErrTransport },
		},
	}, nil
}

func (c *OperatorClient) Close() {
	if transport, ok := c.client.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

func (c *OperatorClient) call(ctx context.Context, path string, input, output any) error {
	if c == nil || c.client == nil || !allowedClientPath(path) {
		return ErrTransport
	}
	payload, err := json.Marshal(input)
	if err != nil {
		return ErrTransport
	}
	requestBody, err := json.Marshal(wireRequest{SchemaVersion: RuntimeWireSchema, Payload: payload})
	if err != nil || len(requestBody) > maxWireBytes {
		return ErrTransport
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, bytes.NewReader(requestBody))
	if err != nil {
		return ErrTransport
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	response, err := c.client.Do(request)
	if err != nil {
		return fmt.Errorf("%w: operator %d", ErrTransport, c.point)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxWireBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxWireBytes {
		return ErrTransport
	}
	var envelope wireResponse
	if strictDecode(body, &envelope) != nil || envelope.SchemaVersion != RuntimeWireSchema {
		return ErrTransport
	}
	if response.StatusCode != http.StatusOK || !envelope.OK {
		if envelope.ErrorCode == "" {
			return ErrTransport
		}
		return &RemoteError{Code: envelope.ErrorCode}
	}
	if envelope.ErrorCode != "" || len(envelope.Payload) == 0 || strictDecode(envelope.Payload, output) != nil {
		return ErrTransport
	}
	return nil
}

func allowedClientPath(path string) bool {
	switch path {
	case "/v1/prepare", "/v1/head", "/v1/reserve", "/v1/accept-reservations", "/v1/propose-transition", "/v1/sign-transition",
		"/v1/commit-transition", "/v1/begin-secrets", "/v1/crs-commit", "/v1/accept-crs-commit", "/v1/crs-reveal",
		"/v1/accept-crs-reveal", "/v1/private-messages", "/v1/receive-private", "/v1/accept-private", "/v1/public-key-share",
		"/v1/accept-public-key", "/v1/relin-one", "/v1/accept-relin-one", "/v1/relin-two", "/v1/accept-relin-two",
		"/v1/galois-share", "/v1/accept-galois", "/v1/public-state", "/v1/set-manifest", "/v1/attest-bundle",
		"/v1/private-ready", "/v1/install-published", "/v1/set-completed", "/v1/finalize-private", "/v1/evidence", "/v1/phase":
		return true
	default:
		return false
	}
}

func remoteCode(err error) string {
	var remote *RemoteError
	if errors.As(err, &remote) {
		return remote.Code
	}
	return ""
}
