package oneshotruntime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

var testOperatorBinary string

func TestMain(m *testing.M) {
	root, err := os.MkdirTemp("", "mordant-oneshot-runtime-tests-")
	if err != nil {
		os.Exit(1)
	}
	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		os.Exit(1)
	}
	testOperatorBinary = filepath.Join(root, "oneshot-operator")
	build := exec.Command("go", "build", "-o", testOperatorBinary, "./cmd/oneshot-operator")
	build.Dir = module
	if output, buildErr := build.CombinedOutput(); buildErr != nil {
		_, _ = os.Stderr.Write(output)
		_ = os.RemoveAll(root)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(root)
	os.Exit(code)
}

type testCluster struct {
	t            *testing.T
	root         string
	publication  string
	evidence     string
	export       string
	authorityKey string
	configs      []OperatorConfig
	runnerConfig RunnerConfig
	processes    []*exec.Cmd
	secretPaths  []string
}

func newTestCluster(t *testing.T) *testCluster {
	t.Helper()
	root := strictTestRoot(t)
	publication := filepath.Join(root, "canonical-publication")
	evidence := filepath.Join(root, "public-evidence")
	export := filepath.Join(root, "verified-export")
	authorityDirectory := filepath.Join(root, "offline-authority")
	authority, err := InitializeSessionAuthority(authorityDirectory)
	if err != nil {
		t.Fatal(err)
	}
	authorityPublicPath := filepath.Join(authorityDirectory, "session-authority-public.json")
	identities := make([]PublicIdentity, ceremony.PartyCount)
	bootstrapPaths := make([]string, ceremony.PartyCount)
	ports := make([]int, ceremony.PartyCount)
	secretPaths := make([]string, 0, ceremony.PartyCount*4)
	for index := 0; index < ceremony.PartyCount; index++ {
		ports[index] = freePort(t)
		directory := filepath.Join(root, fmt.Sprintf("operator-%d-config", index+1))
		stateRoot := filepath.Join(root, fmt.Sprintf("operator-%d-state", index+1))
		arguments := []string{"init", "--dir", directory, "--point", fmt.Sprint(index + 1), "--administrator-id", fmt.Sprintf("demo-admin/operator-%d", index+1), "--listen", fmt.Sprintf("127.0.0.1:%d", ports[index]), "--state-root", stateRoot, "--publication-root", publication, "--session-authority-public", authorityPublicPath}
		runTestCommand(t, testOperatorBinary, arguments...)
		identity, err := LoadPublicIdentity(filepath.Join(directory, "public-identity.json"))
		if err != nil {
			t.Fatal(err)
		}
		identities[index] = identity
		bootstrapPaths[index] = filepath.Join(directory, "operator.bootstrap.json")
		secretPaths = append(secretPaths, filepath.Join(directory, "signing.key"), filepath.Join(directory, "x25519.key"), filepath.Join(directory, "tls.key"))
	}
	rosterPath := filepath.Join(root, "roster.json")
	if err := WriteRoster(rosterPath, identities); err != nil {
		t.Fatal(err)
	}
	configs := make([]OperatorConfig, ceremony.PartyCount)
	runnerOperators := make([]RunnerOperator, ceremony.PartyCount)
	for index := 0; index < ceremony.PartyCount; index++ {
		configPath := filepath.Join(filepath.Dir(bootstrapPaths[index]), "operator.json")
		runTestCommand(t, testOperatorBinary, "configure", "--bootstrap", bootstrapPaths[index], "--roster", rosterPath, "--out", configPath)
		config, err := LoadOperatorConfig(configPath)
		if err != nil {
			t.Fatal(err)
		}
		configs[index] = config
		runnerOperators[index] = RunnerOperator{Endpoint: "https://" + config.ListenAddress, Identity: config.Identity}
	}
	return &testCluster{
		t: t, root: root, publication: publication, evidence: evidence, export: export, configs: configs,
		authorityKey: filepath.Join(authorityDirectory, "session-authority.key"), secretPaths: secretPaths,
		runnerConfig: RunnerConfig{SchemaVersion: RunnerConfigSchema, ProtocolVersion: ceremony.ProtocolVersion, ContextSchema: ceremony.ContextSchema, ParameterProfile: ParameterProfile, SessionAuthorityPublicKey: authority.PublicKey, PublicationRoot: publication, EvidenceRoot: evidence, ExportRoot: export, Operators: runnerOperators, Context: DefaultContextTemplate()},
	}
}

func (c *testCluster) start() {
	c.t.Helper()
	if len(c.processes) != 0 {
		c.t.Fatal("cluster already started")
	}
	c.processes = make([]*exec.Cmd, ceremony.PartyCount)
	for index, config := range c.configs {
		configPath := filepath.Join(filepath.Dir(config.SigningKeyPath), "operator.json")
		command := exec.Command(testOperatorBinary, "serve", "--config", configPath)
		command.Stdout = io.Discard
		var stderr bytes.Buffer
		command.Stderr = &stderr
		if err := command.Start(); err != nil {
			c.t.Fatal(err)
		}
		c.processes[index] = command
		waitForPort(c.t, config.ListenAddress, command, &stderr)
	}
}

func (c *testCluster) stop() {
	c.t.Helper()
	for _, process := range c.processes {
		if process == nil || process.Process == nil {
			continue
		}
		_ = process.Process.Signal(os.Interrupt)
	}
	for _, process := range c.processes {
		if process == nil {
			continue
		}
		if err := process.Wait(); err != nil {
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != -1 {
				c.t.Errorf("operator stop: %v", err)
			}
		}
	}
	c.processes = nil
}

func (c *testCluster) runner(t *testing.T) *Runner {
	t.Helper()
	params, err := RuntimeParameters()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewRunner(c.runnerConfig, params)
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func (c *testCluster) authorizedSession(t *testing.T) AuthorizedSession {
	t.Helper()
	params, err := RuntimeParameters()
	if err != nil {
		t.Fatal(err)
	}
	authority, err := LoadSessionAuthorityPrivate(c.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	values, err := FreshSessionValues()
	if err != nil {
		t.Fatal(err)
	}
	session, err := NewAuthorizedSession(c.runnerConfig, params, authority, values, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestOperatorRejectsWrongIdentityMalformedAndReplay(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	session := cluster.authorizedSession(t)
	var phase PhaseResponse
	if err := postRawWire(runner.clients[0], "/v1/prepare", wireRequest{SchemaVersion: RuntimeWireSchema, Payload: mustJSON(t, PrepareRequest{Context: session.ContextBytes})}); err == nil {
		t.Fatal("unauthenticated prepare accepted")
	}
	if err := runner.clients[0].callAuthorized(context.Background(), session, "/v1/prepare", PrepareRequest{Context: session.ContextBytes}, &phase); err != nil {
		t.Fatal(err)
	}
	malformedPayload, _ := json.Marshal(map[string]any{"heads": []any{}, "stateRoot": "/caller/path", "processInstance": "caller", "bootSession": "caller"})
	body, _ := json.Marshal(wireRequest{SchemaVersion: RuntimeWireSchema, Payload: malformedPayload})
	request, _ := http.NewRequest(http.MethodPost, runner.clients[0].baseURL+"/v1/reserve", bytes.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response, err := runner.clients[0].client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("caller-controlled local inputs accepted: %d", response.StatusCode)
	}
}

func TestRunnerWireHasNoStorageStartupOrSecretAccessor(t *testing.T) {
	for _, value := range []any{PrepareRequest{}, HeadsRequest{}, PublishedRequest{}, FinalizeRequest{}} {
		typeValue := reflect.TypeOf(value)
		for index := 0; index < typeValue.NumField(); index++ {
			name := strings.ToLower(typeValue.Field(index).Name)
			if strings.Contains(name, "path") || strings.Contains(name, "processinstance") || strings.Contains(name, "bootsession") || strings.Contains(name, "privatekey") || strings.Contains(name, "sealing") || strings.Contains(name, "share") {
				t.Fatalf("private/local caller field exposed: %s.%s", typeValue.Name(), typeValue.Field(index).Name)
			}
		}
	}
	for _, path := range []string{"/v1/private-share", "/v1/sealing-key", "/v1/private-bundle", "/v1/signing-key"} {
		if allowedClientPath(path) {
			t.Fatalf("secret accessor allowed: %s", path)
		}
	}
}

func TestSuccessfulThreeProcessCeremonyAndPublicReadback(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	losses := make([]*responseLossTransport, len(runner.clients))
	for index, client := range runner.clients {
		loss := &responseLossTransport{
			base: client.client.Transport, remaining: map[string]int{"/v1/accept-galois": 1, "/v1/finalize-private": 1},
			lost: make(map[string]int),
		}
		client.client.Transport = loss
		losses[index] = loss
	}
	session := cluster.authorizedSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	result, err := runner.RunSuccess(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	if result.Bundle.Unsigned.KeyID == ([32]byte{}) || ceremony.VerifyPublicationReceipt(result.Receipt, result.Bundle) != nil {
		t.Fatal("published bundle readback failed")
	}
	for _, operator := range result.Operators {
		if operator.Phase != ceremony.PhaseCompleted || operator.Disposition != "COMPLETED" || len(operator.TerminalTombstone) == 0 {
			t.Fatal("operator did not complete")
		}
		tombstone, err := ceremony.ParseTerminalTombstone(operator.TerminalTombstone)
		if err != nil || dispositionName(tombstone.Disposition) != operator.Disposition {
			t.Fatal("public disposition disagrees with durable terminal tombstone")
		}
	}
	for index, loss := range losses {
		if loss.lostCount("/v1/accept-galois") != 1 || loss.lostCount("/v1/finalize-private") != 1 {
			t.Fatalf("operator %d did not exercise both response-loss retries", index+1)
		}
		journalRoot := filepath.Join(cluster.configs[index].StateRoot, "runtime-request-journal")
		entries, err := os.ReadDir(journalRoot)
		if err != nil {
			t.Fatal(err)
		}
		operationCounts := make(map[string]int)
		finalizedConfirmed := false
		for _, entry := range entries {
			if !strings.HasSuffix(entry.Name(), ".meta.json") {
				continue
			}
			var record requestJournalRecord
			if err := readStrictJSONExact(filepath.Join(journalRoot, entry.Name()), &record, maxConfigBytes, 0o600); err != nil {
				t.Fatal(err)
			}
			operationCounts[record.Operation]++
			if record.Operation == "/v1/finalize-private" {
				responseBytes, err := readRestrictedExact(filepath.Join(journalRoot, record.ResponseArtifact), maxResponseBytes, 0o600)
				if err != nil {
					t.Fatal(err)
				}
				var response wireResponse
				var confirmation FinalizeResponse
				if decodeStrictJSON(responseBytes, &response) != nil || !response.OK || decodeCanonicalPayload(response.Payload, &confirmation) != nil || !confirmation.Finalized {
					t.Fatal("finalization journal lacks durable finalized=true confirmation")
				}
				finalizedConfirmed = true
			}
		}
		if operationCounts["/v1/accept-galois"] != 1 || operationCounts["/v1/finalize-private"] != 1 || !finalizedConfirmed {
			t.Fatal("response-loss retry duplicated galois acceptance or finalization")
		}
		completed, err := os.ReadDir(filepath.Join(cluster.configs[index].StateRoot, "completed-private"))
		if err != nil || len(completed) != 1 {
			t.Fatal("finalization retry created more than one completed-private artifact")
		}
	}
	knownSecrets := make([][]byte, 0, len(cluster.secretPaths))
	for _, path := range cluster.secretPaths {
		secret, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		knownSecrets = append(knownSecrets, secret)
	}
	paths, err := verifyEvidenceTree(result.EvidencePath, &cluster.runnerConfig, true)
	if err != nil || scanKnownSecretFiles(paths, knownSecrets) != nil {
		t.Fatalf("public evidence contains secret material: %v", err)
	}
	exported, err := ExportCompletedEvidence(cluster.runnerConfig, filepath.Base(result.EvidencePath))
	if err != nil {
		t.Fatalf("verified completed export: %v", err)
	}
	exportedPaths, err := verifyEvidenceTree(exported, &cluster.runnerConfig, true)
	if err != nil || scanKnownSecretFiles(exportedPaths, knownSecrets) != nil {
		t.Fatal("verified export failed public-evidence checks")
	}
	operatorRootConfig := cluster.runnerConfig
	operatorRootConfig.EvidenceRoot = cluster.configs[0].StateRoot
	operatorRootConfig.ExportRoot = filepath.Join(cluster.root, "operator-root-export")
	if _, err := ExportCompletedEvidence(operatorRootConfig, "runtime-request-journal"); err == nil {
		t.Fatal("operator state root was accepted as public evidence")
	}
	if _, err := ExportCompletedEvidence(cluster.runnerConfig, "../"+filepath.Base(result.EvidencePath)); err == nil {
		t.Fatal("non-child evidence path accepted")
	}
	privateArtifact := filepath.Join(result.EvidencePath, "operator-1", "private.bundle")
	if err := writeNoReplace(privateArtifact, []byte("completed-private-test-artifact"), 0o600); err != nil {
		t.Fatal(err)
	}
	secondExportConfig := cluster.runnerConfig
	secondExportConfig.ExportRoot = filepath.Join(cluster.root, "second-export")
	if _, err := ExportCompletedEvidence(secondExportConfig, filepath.Base(result.EvidencePath)); err == nil {
		t.Fatal("completed-private artifact entered public export")
	}
}

func TestStaleReplicaPreventsRealGeneration(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	session := cluster.authorizedSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := runner.RunStaleReplica(ctx, session)
	if err != nil {
		t.Fatal(err)
	}
	if result.Bundle.SchemaVersion != "" {
		t.Fatal("stale run emitted a public bundle")
	}
	for index, operator := range result.Operators {
		if index < ceremony.Threshold && (operator.Disposition != "POISONED" || len(operator.TerminalTombstone) == 0) ||
			index >= ceremony.Threshold && operator.Disposition != "ACTIVE" {
			t.Fatal("stale operator was not terminally poisoned")
		}
	}
}

func TestAbortTerminalRejectsExactCeremonyAfterOrdinaryRestart(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	runner := cluster.runner(t)
	session := cluster.authorizedSession(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	result, err := runner.RunAbort(ctx, session)
	cancel()
	runner.Close()
	if err != nil {
		cluster.stop()
		t.Fatal(err)
	}
	cluster.stop()
	cluster.start()
	defer cluster.stop()
	restarted := cluster.runner(t)
	defer restarted.Close()
	authority, err := LoadSessionAuthorityPrivate(cluster.authorityKey)
	if err != nil {
		t.Fatal(err)
	}
	reauthorized, err := AuthorizeContext(cluster.runnerConfig, authority, result.Context, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := restarted.VerifyRestartConsumed(ctx, reauthorized); err != nil {
		t.Fatal(err)
	}
}

func TestTransportRejectsUnpinnedOperator(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	wrong := cluster.runnerConfig.Operators[0]
	wrong.Identity.TransportCertFingerprint = strings.Repeat("01", 32)
	client, err := NewOperatorClient(wrong)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	var phase PhaseResponse
	if err := client.callPublic(context.Background(), "/v1/phase", EmptyRequest{}, &phase); err == nil {
		t.Fatal("unpinned endpoint accepted")
	}
}

func TestPublicEvidenceScannerRejectsKnownSecret(t *testing.T) {
	root := strictTestRoot(t)
	clean := []byte("public evidence only")
	if err := writeNoReplace(filepath.Join(root, "public.txt"), clean, 0o600); err != nil {
		t.Fatal(err)
	}
	secret := []byte("0123456789abcdef-private-test-material")
	if err := scanKnownSecretFiles([]string{filepath.Join(root, "public.txt")}, [][]byte{secret}); err != nil {
		t.Fatal(err)
	}
	if err := writeNoReplace(filepath.Join(root, "leak.bin"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := scanKnownSecretFiles([]string{filepath.Join(root, "leak.bin")}, [][]byte{secret}); err == nil {
		t.Fatal("known secret was not detected")
	}
}

func TestDefaultBuildGraphExposesNoObsoleteRecoverableExecutable(t *testing.T) {
	module, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command("go", "list", "./...")
	command.Dir = module
	output, err := command.Output()
	if err != nil {
		t.Fatal(err)
	}
	text := string(output)
	for _, obsolete := range []string{"cmd/ceremony-client", "cmd/ceremony-coordinator", "cmd/ceremony-evaluator", "cmd/ceremony-lab", "cmd/ceremony-operator"} {
		if strings.Contains(text, obsolete) {
			t.Fatalf("obsolete executable in default graph: %s", obsolete)
		}
	}
	for _, current := range []string{"cmd/oneshot-operator", "cmd/oneshot-runner"} {
		if !strings.Contains(text, current) {
			t.Fatalf("runtime executable missing from default graph: %s", current)
		}
	}
}

func strictTestRoot(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return root
}

func mustJSON(t *testing.T, value any) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func postRawWire(client *OperatorClient, path string, envelope wireRequest) error {
	body, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	var output PhaseResponse
	_, err = client.send(context.Background(), preparedOperatorCall{path: path, body: body}, &output, false)
	return err
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func runTestCommand(t *testing.T, executable string, arguments ...string) {
	t.Helper()
	command := exec.Command(executable, arguments...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v: %s", err, output)
	}
}

func waitForPort(t *testing.T, address string, command *exec.Cmd, stderr *bytes.Buffer) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		connection, err := net.DialTimeout("tcp", address, 100*time.Millisecond)
		if err == nil {
			_ = connection.Close()
			return
		}
		if command.ProcessState != nil && command.ProcessState.Exited() {
			t.Fatalf("operator exited: %s", stderr.String())
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("operator did not listen: %s", stderr.String())
}
