package oneshotruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

func TestRuntimeAuthorizationBoundaryProductionHandlers(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	sessionA := cluster.authorizedSession(t)
	sessionB := cluster.authorizedSession(t)
	prepareA := mustJSON(t, PrepareRequest{Context: sessionA.ContextBytes})
	if code := rawWireCode(t, runner.clients[0], "/v1/prepare", wireRequest{SchemaVersion: RuntimeWireSchema, Payload: prepareA}); code != "AUTHORIZATION_REJECTED" {
		t.Fatalf("unauthenticated prepare code = %q", code)
	}

	requestA := mustAuthorizedRequest(t, sessionA, "/v1/prepare", mustJSON(t, PrepareRequest{Context: sessionB.ContextBytes}), [32]byte{1}, 1, time.Now().UTC())
	if code := rawWireCode(t, runner.clients[0], "/v1/prepare", wireRequest{
		SchemaVersion: RuntimeWireSchema, Authorization: sessionA.AuthorizationBytes, Request: requestA,
		Payload: mustJSON(t, PrepareRequest{Context: sessionB.ContextBytes}),
	}); code != "AUTHORIZATION_REJECTED" {
		t.Fatalf("context A authorization accepted for context B: %q", code)
	}

	expiredAuthorization := sessionA.Authorization
	expiredAuthorization.ExpiresAtUnix = time.Now().Add(-time.Second).Unix()
	authority := cluster.authorityPrivate(t)
	unsigned, err := expiredAuthorization.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	copy(expiredAuthorization.Signature[:], ed25519.Sign(authority, authorizationSigningMessage(unsigned)))
	expiredAuthorizationBytes, err := expiredAuthorization.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	validRequest := mustAuthorizedRequest(t, sessionA, "/v1/prepare", prepareA, [32]byte{2}, 2, time.Now().UTC())
	if code := rawWireCode(t, runner.clients[0], "/v1/prepare", wireRequest{
		SchemaVersion: RuntimeWireSchema, Authorization: expiredAuthorizationBytes, Request: validRequest, Payload: prepareA,
	}); code != "AUTHORIZATION_REJECTED" {
		t.Fatalf("expired authorization accepted: %q", code)
	}

	expiredRequest := mustRequestValue(t, sessionA, "/v1/prepare", prepareA, [32]byte{3}, 3, time.Now().UTC())
	expiredRequest.ExpiresAtUnix = time.Now().Add(-time.Second).Unix()
	unsigned, err = expiredRequest.signingBytes()
	if err != nil {
		t.Fatal(err)
	}
	copy(expiredRequest.Signature[:], ed25519.Sign(sessionA.RequestSigningKey, authorizedRequestSigningMessage(unsigned)))
	expiredRequestBytes, err := expiredRequest.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if code := rawWireCode(t, runner.clients[0], "/v1/prepare", wireRequest{
		SchemaVersion: RuntimeWireSchema, Authorization: sessionA.AuthorizationBytes, Request: expiredRequestBytes, Payload: prepareA,
	}); code != "AUTHORIZATION_REJECTED" {
		t.Fatalf("expired request accepted: %q", code)
	}

	if err := runner.prepare(ctx, sessionA); err != nil {
		t.Fatal(err)
	}
	heads, err := runner.heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, attempt := range []struct {
		path    string
		payload []byte
	}{
		{path: "/v1/head", payload: mustJSON(t, EmptyRequest{})},
		{path: "/v1/evidence", payload: mustJSON(t, EvidenceRequest{Context: sessionA.ContextBytes})},
		{path: "/v1/reserve", payload: mustJSON(t, HeadsRequest{Heads: heads})},
		{path: "/v1/propose-transition", payload: mustJSON(t, TransitionProposalRequest{ToPhase: ceremony.PhaseAborted})},
		{path: "/v1/commit-transition", payload: mustJSON(t, CommitTransitionRequest{Record: []byte{1}})},
		{path: "/v1/crs-commit", payload: mustJSON(t, HeadsRequest{Heads: heads})},
	} {
		if code := rawWireCode(t, runner.clients[0], attempt.path, wireRequest{SchemaVersion: RuntimeWireSchema, Payload: attempt.payload}); code != "AUTHORIZATION_REJECTED" {
			t.Fatalf("unauthorized %s code = %q", attempt.path, code)
		}
	}
	var reservation ReservationResponse
	if err := runner.call(ctx, runner.clients[0], "/v1/reserve", HeadsRequest{Heads: heads}, &reservation); err != nil {
		t.Fatalf("unauthorized reserve consumed the session: %v", err)
	}
	assertAuthorizationBindings(t, sessionA)
}

func TestRuntimeExactJournalProductionHandlers(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	session := cluster.authorizedSession(t)
	if err := runner.prepare(ctx, session); err != nil {
		t.Fatal(err)
	}
	heads, err := runner.heads(ctx)
	if err != nil {
		t.Fatal(err)
	}

	reserveCall, err := runner.clients[0].prepareAuthorized(session, "/v1/reserve", HeadsRequest{Heads: heads}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.clients[0].send(ctx, reserveCall, &ReservationResponse{}, true); err != nil {
		t.Fatal(err)
	}
	var reservation0 ReservationResponse
	first, err := runner.clients[0].send(ctx, reserveCall, &reservation0, false)
	if err != nil {
		t.Fatal(err)
	}
	var reservationRetry ReservationResponse
	second, err := runner.clients[0].send(ctx, reserveCall, &reservationRetry, false)
	if err != nil || !bytes.Equal(first, second) || !bytes.Equal(reservation0.Reservation, reservationRetry.Reservation) {
		t.Fatal("reserve retry did not return the exact response")
	}

	differentPayload := mustJSON(t, HeadsRequest{Heads: heads[:2]})
	request := mustAuthorizedRequest(t, session, "/v1/reserve", differentPayload, reserveCall.request.RequestID, reserveCall.request.Sequence, time.Now().UTC())
	if code := rawWireCode(t, runner.clients[0], "/v1/reserve", wireRequest{
		SchemaVersion: RuntimeWireSchema, Authorization: session.AuthorizationBytes, Request: request, Payload: differentPayload,
	}); code != "REPLAY_REJECTED" {
		t.Fatalf("same request ID with different payload code = %q", code)
	}
	differentOperationPayload := mustJSON(t, HeadsRequest{Heads: heads})
	request = mustAuthorizedRequest(t, session, "/v1/begin-secrets", differentOperationPayload, reserveCall.request.RequestID, reserveCall.request.Sequence, time.Now().UTC())
	if code := rawWireCode(t, runner.clients[0], "/v1/begin-secrets", wireRequest{
		SchemaVersion: RuntimeWireSchema, Authorization: session.AuthorizationBytes, Request: request, Payload: differentOperationPayload,
	}); code != "REPLAY_REJECTED" {
		t.Fatalf("same request ID with different operation code = %q", code)
	}

	reservationBytes := make([][]byte, ceremony.PartyCount)
	reservationBytes[0] = reservation0.Reservation
	for index := 1; index < ceremony.PartyCount; index++ {
		var response ReservationResponse
		if err := runner.call(ctx, runner.clients[index], "/v1/reserve", HeadsRequest{Heads: heads}, &response); err != nil {
			t.Fatal(err)
		}
		reservationBytes[index] = response.Reservation
	}
	for _, client := range runner.clients {
		var response PhaseResponse
		if err := runner.call(ctx, client, "/v1/accept-reservations", ReservationsRequest{Reservations: reservationBytes}, &response); err != nil {
			t.Fatal(err)
		}
	}
	exactTransition(t, ctx, runner, ceremony.PhaseReserved)
	if _, err := runner.transition(ctx, ceremony.PhaseRunning, [32]byte{}, allOperators(), allOperators()); err != nil {
		t.Fatal(err)
	}
	heads, err = runner.heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, client := range runner.clients {
		var response PhaseResponse
		if err := runner.call(ctx, client, "/v1/begin-secrets", HeadsRequest{Heads: heads}, &response); err != nil {
			t.Fatal(err)
		}
	}
	heads, err = runner.heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	generatedCall, err := runner.clients[0].prepareAuthorized(session, "/v1/crs-commit", HeadsRequest{Heads: heads}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.clients[0].send(ctx, generatedCall, &EnvelopeResponse{}, true); err != nil {
		t.Fatal(err)
	}
	var envelope, envelopeRetry EnvelopeResponse
	first, err = runner.clients[0].send(ctx, generatedCall, &envelope, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err = runner.clients[0].send(ctx, generatedCall, &envelopeRetry, false)
	if err != nil || !bytes.Equal(first, second) || !bytes.Equal(envelope.Envelope, envelopeRetry.Envelope) {
		t.Fatal("generation retry regenerated or changed the response")
	}
}

func TestRuntimeStrictWireAndConfigurationProductionPaths(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	client := runner.clients[0]

	encodedEmpty := "e30="
	for name, body := range map[string]string{
		"duplicate outer": `{"schemaVersion":"` + RuntimeWireSchema + `","SchemaVersion":"` + RuntimeWireSchema + `","payload":"` + encodedEmpty + `"}`,
		"trailing data":   `{"schemaVersion":"` + RuntimeWireSchema + `","payload":"` + encodedEmpty + `"}{}`,
		"unknown field":   `{"schemaVersion":"` + RuntimeWireSchema + `","payload":"` + encodedEmpty + `","unknown":1}`,
	} {
		t.Run(name, func(t *testing.T) {
			if code := rawBodyCode(t, client, "/v1/reserve", []byte(body)); code != "MALFORMED_REQUEST" {
				t.Fatalf("code = %q", code)
			}
		})
	}
	for name, payload := range map[string][]byte{
		"duplicate payload case variant": []byte(`{"heads":[],"Heads":[]}`),
		"required null":                  []byte(`{"heads":null}`),
		"required absent":                []byte(`{}`),
		"required empty":                 []byte(`{"heads":[]}`),
	} {
		t.Run(name, func(t *testing.T) {
			body := mustJSON(t, wireRequest{SchemaVersion: RuntimeWireSchema, Payload: payload})
			if code := rawBodyCode(t, client, "/v1/reserve", body); code != "MALFORMED_REQUEST" {
				t.Fatalf("code = %q", code)
			}
		})
	}

	duplicateTLS := cluster.runnerConfig
	duplicateTLS.Operators = slices.Clone(duplicateTLS.Operators)
	duplicateTLS.Operators[1].Identity.TransportCertFingerprint = duplicateTLS.Operators[0].Identity.TransportCertFingerprint
	if duplicateTLS.validate() == nil {
		t.Fatal("duplicate TLS fingerprint accepted")
	}
	duplicateEndpoint := cluster.runnerConfig
	duplicateEndpoint.Operators = slices.Clone(duplicateEndpoint.Operators)
	duplicateEndpoint.Operators[1].Endpoint = duplicateEndpoint.Operators[0].Endpoint
	if duplicateEndpoint.validate() == nil {
		t.Fatal("duplicate endpoint accepted")
	}
	overlap := cluster.runnerConfig
	overlap.EvidenceRoot = filepath.Join(overlap.PublicationRoot, "evidence")
	if overlap.validate() == nil {
		t.Fatal("overlapping runner roots accepted")
	}
	sharedState := cluster.runnerConfig
	sharedState.Operators = slices.Clone(sharedState.Operators)
	sharedState.Operators[1].Identity.StateRootDigest = sharedState.Operators[0].Identity.StateRootDigest
	if sharedState.validate() == nil {
		t.Fatal("shared operator state root accepted")
	}
	operatorOverlap := cluster.configs[0]
	operatorOverlap.StateRoot = filepath.Join(filepath.Dir(operatorOverlap.SigningKeyPath), "nested-state")
	operatorOverlap.Identity.StateRootDigest = digestPath(operatorOverlap.StateRoot)
	operatorOverlap.Roster = slices.Clone(operatorOverlap.Roster)
	operatorOverlap.Roster[0] = operatorOverlap.Identity
	if operatorOverlap.validate() == nil {
		t.Fatal("overlapping operator config/state root accepted")
	}

	configPath := filepath.Join(cluster.root, "mode-test-runner.json")
	if err := WriteRunnerConfig(configPath, cluster.runnerConfig); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(configPath, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRunnerConfig(configPath); err == nil {
		t.Fatal("non-0400 finalized runner config accepted")
	}
	canonicalConfig, err := json.Marshal(cluster.runnerConfig)
	if err != nil {
		t.Fatal(err)
	}
	duplicateConfig := append([]byte(`{"schemaVersion":"`+RunnerConfigSchema+`",`), canonicalConfig[1:]...)
	duplicateConfigPath := filepath.Join(cluster.root, "duplicate-runner.json")
	if err := writeNoReplace(duplicateConfigPath, duplicateConfig, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRunnerConfig(duplicateConfigPath); err == nil {
		t.Fatal("duplicate finalized configuration key accepted")
	}
	nullExport := bytes.Replace(canonicalConfig, []byte(`"exportRoot":"`+cluster.export+`"`), []byte(`"exportRoot":null`), 1)
	nullConfigPath := filepath.Join(cluster.root, "null-runner.json")
	if bytes.Equal(nullExport, canonicalConfig) {
		t.Fatal("test could not construct null required configuration")
	}
	if err := writeNoReplace(nullConfigPath, nullExport, 0o400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadRunnerConfig(nullConfigPath); err == nil {
		t.Fatal("null required finalized configuration field accepted")
	}
}

func TestRuntimeJournalCorruptionFailsClosedOnOperatorRestart(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	runner := cluster.runner(t)
	session := cluster.authorizedSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	if err := runner.prepare(ctx, session); err != nil {
		cancel()
		runner.Close()
		cluster.stop()
		t.Fatal(err)
	}
	cancel()
	runner.Close()
	cluster.stop()

	journalRoot := filepath.Join(cluster.configs[0].StateRoot, "runtime-request-journal")
	entries, err := os.ReadDir(journalRoot)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := false
	for _, entry := range entries {
		if filepath.Ext(entry.Name()) != ".response" {
			continue
		}
		path := filepath.Join(journalRoot, entry.Name())
		file, openErr := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
		if openErr != nil {
			t.Fatal(openErr)
		}
		if _, writeErr := file.Write([]byte("corrupt")); writeErr != nil || file.Sync() != nil || file.Close() != nil {
			t.Fatal("could not persist journal corruption")
		}
		corrupted = true
		break
	}
	if !corrupted {
		t.Fatal("test did not find a journal response artifact")
	}
	configPath := filepath.Join(filepath.Dir(cluster.configs[0].SigningKeyPath), "operator.json")
	command := exec.Command(testOperatorBinary, "serve", "--config", configPath)
	output, err := command.CombinedOutput()
	if err == nil || !bytes.Contains(output, []byte("ONESHOT_OPERATOR_FAILED")) {
		t.Fatalf("operator did not fail closed on journal corruption: %v %s", err, output)
	}
}

func (c *testCluster) authorityPrivate(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	key, err := LoadSessionAuthorityPrivate(c.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func assertAuthorizationBindings(t *testing.T, session AuthorizedSession) {
	t.Helper()
	a := session.Authorization
	c := session.Context
	if a.ContextDigest != c.ContextDigest() || a.CeremonyID != c.CeremonyID() || a.SessionBindingDigest != c.SessionBindingDigest() ||
		a.SessionIdentity != c.SessionIdentity || a.SessionCommitment != c.SessionCommitment || a.RosterDigest != c.RosterDigest() ||
		a.PrivacyDomain != c.PrivacyDomain || a.ServiceID != c.ServiceID || a.ServiceVersion != c.ServiceVersion || a.ChainID != c.ChainID ||
		a.PolicyID != c.PolicyID || a.PolicyVersion != c.PolicyVersion || a.CircuitVersion != c.CircuitVersion ||
		a.CircuitDigest != c.CircuitDigest || a.ReleaseLayout != c.ReleaseLayout || a.MaximumReleaseQueries != c.MaximumReleaseQueries ||
		a.ContextActivatesAtUnix != c.ActivatesAtUnix || a.ContextExpiresAtUnix != c.ExpiresAtUnix || zero32(a.AuthorizationID) {
		t.Fatal("session authorization omitted or changed a bound context field")
	}
	for index := range c.Operators {
		if a.OrderedRoster[index] != operatorIdentityDigest(c.Operators[index]) {
			t.Fatal("authorization roster order mismatch")
		}
	}
}

func mustRequestValue(t *testing.T, session AuthorizedSession, path string, payload []byte, requestID [32]byte, sequence uint64, now time.Time) AuthorizedRequest {
	t.Helper()
	request, err := NewAuthorizedRequest(session, path, payload, requestID, sequence, now)
	if err != nil {
		t.Fatal(err)
	}
	return request
}

func mustAuthorizedRequest(t *testing.T, session AuthorizedSession, path string, payload []byte, requestID [32]byte, sequence uint64, now time.Time) []byte {
	t.Helper()
	request := mustRequestValue(t, session, path, payload, requestID, sequence, now)
	encoded, err := request.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func rawWireCode(t *testing.T, client *OperatorClient, path string, request wireRequest) string {
	t.Helper()
	return rawBodyCode(t, client, path, mustJSON(t, request))
}

func rawBodyCode(t *testing.T, client *OperatorClient, path string, body []byte) string {
	t.Helper()
	var output PhaseResponse
	_, err := client.send(context.Background(), preparedOperatorCall{path: path, body: body}, &output, false)
	if err == nil {
		return ""
	}
	return remoteCode(err)
}

func exactTransition(t *testing.T, ctx context.Context, runner *Runner, phase ceremony.Phase) {
	t.Helper()
	var proposal TransitionProposalResponse
	if err := runner.call(ctx, runner.clients[0], "/v1/propose-transition", TransitionProposalRequest{ToPhase: phase}, &proposal); err != nil {
		t.Fatal(err)
	}
	statement, err := parseWitnessStatementBytes(proposal.Statement)
	if err != nil {
		t.Fatal(err)
	}
	heads, err := runner.heads(ctx)
	if err != nil {
		t.Fatal(err)
	}
	signatures := make([]ceremony.WitnessSignature, ceremony.PartyCount)
	signCall, err := runner.clients[0].prepareAuthorized(runner.session, "/v1/sign-transition", SignTransitionRequest{Statement: proposal.Statement, Heads: heads}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.clients[0].send(ctx, signCall, &SignTransitionResponse{}, true); err != nil {
		t.Fatal(err)
	}
	var signed, signedRetry SignTransitionResponse
	first, err := runner.clients[0].send(ctx, signCall, &signed, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runner.clients[0].send(ctx, signCall, &signedRetry, false)
	if err != nil || !bytes.Equal(first, second) || !bytes.Equal(signed.Signature, signedRetry.Signature) {
		t.Fatal("transition-signature retry changed the response")
	}
	signatures[0], err = parseWitnessSignature(signed.Signature)
	if err != nil {
		t.Fatal(err)
	}
	for index := 1; index < ceremony.PartyCount; index++ {
		var response SignTransitionResponse
		if err := runner.call(ctx, runner.clients[index], "/v1/sign-transition", SignTransitionRequest{Statement: proposal.Statement, Heads: heads}, &response); err != nil {
			t.Fatal(err)
		}
		signatures[index], err = parseWitnessSignature(response.Signature)
		if err != nil {
			t.Fatal(err)
		}
	}
	record, err := ceremony.AssembleWitnessRecord(runner.context, statement, signatures)
	if err != nil {
		t.Fatal(err)
	}
	recordBytes, err := record.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	commitCall, err := runner.clients[0].prepareAuthorized(runner.session, "/v1/commit-transition", CommitTransitionRequest{Record: recordBytes}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := runner.clients[0].send(ctx, commitCall, &PhaseResponse{}, true); err != nil {
		t.Fatal(err)
	}
	var committed, committedRetry PhaseResponse
	first, err = runner.clients[0].send(ctx, commitCall, &committed, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err = runner.clients[0].send(ctx, commitCall, &committedRetry, false)
	if err != nil || !bytes.Equal(first, second) || committed != committedRetry || committed.Phase != phase {
		t.Fatal("transition-commit retry changed the response")
	}
	for index := 1; index < ceremony.PartyCount; index++ {
		var response PhaseResponse
		if err := runner.call(ctx, runner.clients[index], "/v1/commit-transition", CommitTransitionRequest{Record: recordBytes}, &response); err != nil || response.Phase != phase {
			t.Fatalf("commit operator %d: %v", index+1, err)
		}
	}
}

type responseLossTransport struct {
	base      http.RoundTripper
	mu        sync.Mutex
	remaining map[string]int
	lost      map[string]int
}

func (r *responseLossTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := r.base.RoundTrip(request)
	if err != nil {
		return response, err
	}
	r.mu.Lock()
	drop := r.remaining[request.URL.Path] > 0
	if drop {
		r.remaining[request.URL.Path]--
		r.lost[request.URL.Path]++
	}
	r.mu.Unlock()
	if !drop {
		return response, nil
	}
	_, readErr := io.Copy(io.Discard, response.Body)
	closeErr := response.Body.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.New("failed to consume simulated lost response")
	}
	return nil, errors.New("simulated response loss after durable operator completion")
}

func (r *responseLossTransport) CloseIdleConnections() {
	if closer, ok := r.base.(interface{ CloseIdleConnections() }); ok {
		closer.CloseIdleConnections()
	}
}

func (r *responseLossTransport) lostCount(path string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lost[path]
}
