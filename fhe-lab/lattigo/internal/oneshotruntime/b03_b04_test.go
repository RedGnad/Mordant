package oneshotruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestB03PendingCrashRestartIsDeterministicTerminal(t *testing.T) {
	cluster := newTestClusterWithBinary(t, testFaultOperatorBinary)
	cluster.injectFault(0, runtimeFaultAfterPending, "/v1/prepare")
	cluster.start()
	defer cluster.stop()
	client := cluster.runnerConfig.Operators[0]
	runnerClient, err := NewOperatorClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer runnerClient.Close()
	session := cluster.authorizedSession(t)
	call, err := runnerClient.prepareAuthorized(session, "/v1/prepare", PrepareRequest{Context: session.ContextBytes}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := runnerClient.send(ctx, call, &PhaseResponse{}, false); !errors.Is(err, ErrTransport) {
		t.Fatalf("pending crash did not break transport: %v", err)
	}
	runnerClient.Close()
	cluster.restartOperator(0)

	first, err := runnerClient.send(ctx, call, &PhaseResponse{}, false)
	if remoteCode(err) != indeterminateCode {
		t.Fatalf("restart retry code = %q", remoteCode(err))
	}
	second, err := runnerClient.send(ctx, call, &PhaseResponse{}, false)
	if remoteCode(err) != indeterminateCode || !bytes.Equal(first, second) || !bytes.Equal(first, indeterminateResponseBytes()) {
		t.Fatal("indeterminate retry was not byte-identical")
	}

	changed := session.Context
	changed.Nonce = sha256.Sum256([]byte("b03-new-nonce-same-bilateral-session"))
	if changed.CeremonyID() == session.Context.CeremonyID() || changed.SessionBindingDigest() != session.Context.SessionBindingDigest() {
		t.Fatal("changed nonce test did not preserve the bilateral session binding")
	}
	reauthorized, err := AuthorizeContext(cluster.runnerConfig, cluster.authorityPrivate(t), changed, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	newClient, err := NewOperatorClient(client)
	if err != nil {
		t.Fatal(err)
	}
	defer newClient.Close()
	changedCall, err := newClient.prepareAuthorized(reauthorized, "/v1/prepare", PrepareRequest{Context: reauthorized.ContextBytes}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := newClient.send(ctx, changedCall, &PhaseResponse{}, false); remoteCode(err) != indeterminateCode {
		t.Fatalf("changed nonce restored terminal session authority: %q", remoteCode(err))
	}
}

func TestB03MutationAndResponseArtifactCrashesNeverReexecute(t *testing.T) {
	for _, test := range []struct {
		name      string
		point     string
		operation string
		prepare   func(*testing.T, *testCluster, *Runner, AuthorizedSession) preparedOperatorCall
	}{
		{
			name: "after participant mutation", point: runtimeFaultAfterOperation, operation: "/v1/reserve",
			prepare: func(t *testing.T, cluster *testCluster, runner *Runner, session AuthorizedSession) preparedOperatorCall {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				if err := runner.prepare(ctx, session); err != nil {
					t.Fatal(err)
				}
				heads, err := runner.heads(ctx)
				if err != nil {
					t.Fatal(err)
				}
				call, err := runner.clients[0].prepareAuthorized(session, "/v1/reserve", HeadsRequest{Heads: heads}, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				return call
			},
		},
		{
			name: "after response artifact", point: runtimeFaultAfterResponseArtifact, operation: "/v1/prepare",
			prepare: func(t *testing.T, _ *testCluster, runner *Runner, session AuthorizedSession) preparedOperatorCall {
				call, err := runner.clients[0].prepareAuthorized(session, "/v1/prepare", PrepareRequest{Context: session.ContextBytes}, time.Now().UTC())
				if err != nil {
					t.Fatal(err)
				}
				return call
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cluster := newTestClusterWithBinary(t, testFaultOperatorBinary)
			cluster.injectFault(0, test.point, test.operation)
			cluster.start()
			defer cluster.stop()
			runner := cluster.runner(t)
			defer runner.Close()
			session := cluster.authorizedSession(t)
			call := test.prepare(t, cluster, runner, session)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			if _, err := runner.clients[0].send(ctx, call, &PhaseResponse{}, false); !errors.Is(err, ErrTransport) {
				t.Fatalf("fault did not terminate transport: %v", err)
			}
			runner.clients[0].Close()
			cluster.restartOperator(0)
			first, err := runner.clients[0].send(ctx, call, &PhaseResponse{}, false)
			if remoteCode(err) != indeterminateCode {
				t.Fatalf("restart code = %q", remoteCode(err))
			}
			second, err := runner.clients[0].send(ctx, call, &PhaseResponse{}, false)
			if remoteCode(err) != indeterminateCode || !bytes.Equal(first, second) {
				t.Fatal("ambiguous operation retry was not terminal and deterministic")
			}
		})
	}
}

func TestB03CompletedCrashReturnsExactRetainedBytes(t *testing.T) {
	cluster := newTestClusterWithBinary(t, testFaultOperatorBinary)
	cluster.injectFault(0, runtimeFaultAfterCompleted, "/v1/prepare")
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	session := cluster.authorizedSession(t)
	call, err := runner.clients[0].prepareAuthorized(session, "/v1/prepare", PrepareRequest{Context: session.ContextBytes}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := runner.clients[0].send(ctx, call, &PhaseResponse{}, false); !errors.Is(err, ErrTransport) {
		t.Fatalf("completed crash did not lose network response: %v", err)
	}
	runner.clients[0].Close()
	cluster.restartOperator(0)
	var firstPhase, secondPhase PhaseResponse
	first, err := runner.clients[0].send(ctx, call, &firstPhase, false)
	if err != nil {
		t.Fatal(err)
	}
	second, err := runner.clients[0].send(ctx, call, &secondPhase, false)
	if err != nil || !bytes.Equal(first, second) || firstPhase != secondPhase {
		t.Fatal("completed retry did not return exact retained response bytes")
	}
}

func TestB03PreAdmissionCrashAndExhaustionDoNotMutate(t *testing.T) {
	t.Run("crash after authorization", func(t *testing.T) {
		cluster := newTestClusterWithBinary(t, testFaultOperatorBinary)
		cluster.injectFault(0, runtimeFaultAfterAuthorization, "/v1/prepare")
		cluster.start()
		defer cluster.stop()
		runner := cluster.runner(t)
		defer runner.Close()
		session := cluster.authorizedSession(t)
		call, err := runner.clients[0].prepareAuthorized(session, "/v1/prepare", PrepareRequest{Context: session.ContextBytes}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if _, err := runner.clients[0].send(ctx, call, &PhaseResponse{}, false); !errors.Is(err, ErrTransport) {
			t.Fatalf("pre-admission fault did not terminate transport: %v", err)
		}
		runner.clients[0].Close()
		cluster.restartOperator(0)
		if _, err := runner.clients[0].send(ctx, call, &PhaseResponse{}, false); err != nil {
			t.Fatalf("safe pre-admission retry failed: %v", err)
		}
	})

	t.Run("journal exhaustion", func(t *testing.T) {
		cluster := newTestClusterWithBinary(t, testFaultOperatorBinary)
		cluster.setJournalLimit(0, 1024)
		cluster.start()
		defer cluster.stop()
		runner := cluster.runner(t)
		defer runner.Close()
		session := cluster.authorizedSession(t)
		call, err := runner.clients[0].prepareAuthorized(session, "/v1/prepare", PrepareRequest{Context: session.ContextBytes}, time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		if _, err := runner.clients[0].send(context.Background(), call, &PhaseResponse{}, false); remoteCode(err) != "JOURNAL_EXHAUSTED" {
			t.Fatalf("exhaustion code = %q", remoteCode(err))
		}
		var phase PhaseResponse
		if err := runner.clients[0].callPublic(context.Background(), "/v1/phase", EmptyRequest{}, &phase); err != nil || phase.Phase != 0 {
			t.Fatalf("exhaustion mutated participant state: %v %+v", err, phase)
		}
	})
}

func TestB03RunnerSequenceRestartTerminalizesSession(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	session := cluster.authorizedSession(t)
	firstClient, err := NewOperatorClient(cluster.runnerConfig.Operators[0])
	if err != nil {
		t.Fatal(err)
	}
	defer firstClient.Close()
	firstCall, err := firstClient.prepareAuthorized(session, "/v1/prepare", PrepareRequest{Context: session.ContextBytes}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := firstClient.send(context.Background(), firstCall, &PhaseResponse{}, false); err != nil {
		t.Fatal(err)
	}

	restartedClient, err := NewOperatorClient(cluster.runnerConfig.Operators[0])
	if err != nil {
		t.Fatal(err)
	}
	defer restartedClient.Close()
	restartedContext := session.Context
	restartedContext.Nonce = sha256.Sum256([]byte("b03-runner-restart-new-authorization-and-nonce"))
	reauthorized, err := AuthorizeContext(cluster.runnerConfig, cluster.authorityPrivate(t), restartedContext, time.Now().UTC())
	if err != nil || reauthorized.Context.SessionBindingDigest() != session.Context.SessionBindingDigest() ||
		reauthorized.Context.CeremonyID() == session.Context.CeremonyID() {
		t.Fatal("test could not create a reauthorized same-application session")
	}
	restartedCall, err := restartedClient.prepareAuthorized(reauthorized, "/v1/prepare", PrepareRequest{Context: reauthorized.ContextBytes}, time.Now().UTC())
	if err != nil || restartedCall.request.Sequence != 1 || restartedCall.request.RequestID == firstCall.request.RequestID {
		t.Fatal("test did not simulate runner sequence restart")
	}
	first, err := restartedClient.send(context.Background(), restartedCall, &PhaseResponse{}, false)
	if remoteCode(err) != indeterminateCode {
		t.Fatalf("sequence restart code = %q", remoteCode(err))
	}
	second, err := restartedClient.send(context.Background(), restartedCall, &PhaseResponse{}, false)
	if remoteCode(err) != indeterminateCode || !bytes.Equal(first, second) {
		t.Fatal("sequence restart terminal response was not stable")
	}

	cluster.stop()
	cluster.start()
	freshSession := cluster.authorizedSession(t)
	if freshSession.Context.SessionBindingDigest() == session.Context.SessionBindingDigest() {
		t.Fatal("fresh application session reused the terminal bilateral binding")
	}
	freshClient, err := NewOperatorClient(cluster.runnerConfig.Operators[0])
	if err != nil {
		t.Fatal(err)
	}
	defer freshClient.Close()
	freshCall, err := freshClient.prepareAuthorized(freshSession, "/v1/prepare", PrepareRequest{Context: freshSession.ContextBytes}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := freshClient.send(context.Background(), freshCall, &PhaseResponse{}, false); err != nil {
		t.Fatalf("fresh authorized application session was not accepted: %v", err)
	}
}

func TestB04CanonicalJSONUnicodeProductionPaths(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	client := runner.clients[0]
	canonicalOuter := mustJSON(t, wireRequest{SchemaVersion: RuntimeWireSchema, Payload: mustJSON(t, EmptyRequest{})})
	if code := rawBodyCode(t, client, "/v1/phase", canonicalOuter); code != "" {
		t.Fatalf("canonical ASCII request rejected: %q", code)
	}
	escapedPayload := "e30="
	outerCases := map[string][]byte{
		"alternate capitalization": []byte(`{"schemaVersion":"` + RuntimeWireSchema + `","SchemaVersion":"` + RuntimeWireSchema + `","payload":"` + escapedPayload + `"}`),
		"literal long s duplicate": []byte(`{"schemaVersion":"` + RuntimeWireSchema + `","ſchemaVersion":"` + RuntimeWireSchema + `","payload":"` + escapedPayload + `"}`),
		"escaped long s duplicate": []byte(`{"schemaVersion":"` + RuntimeWireSchema + `","\u017FchemaVersion":"` + RuntimeWireSchema + `","payload":"` + escapedPayload + `"}`),
		"literal long s alone":     []byte(`{"ſchemaVersion":"` + RuntimeWireSchema + `","payload":"` + escapedPayload + `"}`),
		"escaped long s alone":     []byte(`{"\u017FchemaVersion":"` + RuntimeWireSchema + `","payload":"` + escapedPayload + `"}`),
		"escape decoded duplicate": []byte(`{"schemaVersion":"` + RuntimeWireSchema + `","\u0073chemaVersion":"` + RuntimeWireSchema + `","payload":"` + escapedPayload + `"}`),
	}
	invalidUTF8 := []byte(`{"schemaVersion":"` + RuntimeWireSchema + `","payload":"` + escapedPayload + `","`)
	invalidUTF8 = append(invalidUTF8, 0xff)
	invalidUTF8 = append(invalidUTF8, []byte(`":1}`)...)
	outerCases["invalid UTF-8 key"] = invalidUTF8
	for name, body := range outerCases {
		t.Run(name, func(t *testing.T) {
			if code := rawBodyCode(t, client, "/v1/phase", body); code != "MALFORMED_REQUEST" {
				t.Fatalf("code = %q", code)
			}
		})
	}

	canonicalConfig, err := json.Marshal(cluster.runnerConfig)
	if err != nil {
		t.Fatal(err)
	}
	writeAndLoad := func(name string, body []byte, wantOK bool) {
		t.Helper()
		path := filepath.Join(cluster.root, name+".json")
		if err := writeNoReplace(path, body, 0o400); err != nil {
			t.Fatal(err)
		}
		_, err := LoadRunnerConfig(path)
		if (err == nil) != wantOK {
			t.Fatalf("LoadRunnerConfig(%s) error = %v", name, err)
		}
	}
	writeAndLoad("canonical-ascii", canonicalConfig, true)
	serviceID := cluster.runnerConfig.Context.ServiceID
	canonicalService := []byte(`"serviceId":"` + serviceID + `"`)
	for name, replacement := range map[string][]byte{
		"nested-literal-unicode":  []byte(`"ſerviceId":"` + serviceID + `"`),
		"nested-escaped-unicode":  []byte(`"\u017FerviceId":"` + serviceID + `"`),
		"nested-escape-duplicate": []byte(`"serviceId":"` + serviceID + `","\u0073erviceId":"` + serviceID + `"`),
	} {
		mutated := bytes.Replace(canonicalConfig, canonicalService, replacement, 1)
		if bytes.Equal(mutated, canonicalConfig) {
			t.Fatalf("%s did not mutate nested context", name)
		}
		writeAndLoad(name, mutated, false)
	}
	endpoint := cluster.runnerConfig.Operators[0].Endpoint
	canonicalEndpoint := []byte(`"endpoint":"` + endpoint + `"`)
	for name, replacement := range map[string][]byte{
		"array-literal-unicode": []byte(`"ſndpoint":"` + endpoint + `"`),
		"array-escaped-unicode": []byte(`"\u017Fndpoint":"` + endpoint + `"`),
	} {
		mutated := bytes.Replace(canonicalConfig, canonicalEndpoint, replacement, 1)
		if bytes.Equal(mutated, canonicalConfig) {
			t.Fatalf("%s did not mutate array element", name)
		}
		writeAndLoad(name, mutated, false)
	}
}
