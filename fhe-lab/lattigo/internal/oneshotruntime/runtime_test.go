package oneshotruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
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
	"slices"
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
	identities := make([]PublicIdentity, ceremony.PartyCount)
	bootstrapPaths := make([]string, ceremony.PartyCount)
	ports := make([]int, ceremony.PartyCount)
	secretPaths := make([]string, 0, ceremony.PartyCount*4)
	for index := 0; index < ceremony.PartyCount; index++ {
		ports[index] = freePort(t)
		directory := filepath.Join(root, fmt.Sprintf("operator-%d-config", index+1))
		stateRoot := filepath.Join(root, fmt.Sprintf("operator-%d-state", index+1))
		arguments := []string{"init", "--dir", directory, "--point", fmt.Sprint(index + 1), "--administrator-id", fmt.Sprintf("demo-admin/operator-%d", index+1), "--listen", fmt.Sprintf("127.0.0.1:%d", ports[index]), "--state-root", stateRoot, "--publication-root", publication}
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
		t: t, root: root, publication: publication, evidence: evidence, configs: configs, secretPaths: secretPaths,
		runnerConfig: RunnerConfig{SchemaVersion: RunnerConfigSchema, ProtocolVersion: ceremony.ProtocolVersion, ContextSchema: ceremony.ContextSchema, ParameterProfile: ParameterProfile, PublicationRoot: publication, EvidenceRoot: evidence, Operators: runnerOperators, Context: DefaultContextTemplate()},
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

func TestOperatorRejectsWrongIdentityMalformedAndReplay(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	values, err := FreshSessionValues()
	if err != nil {
		t.Fatal(err)
	}
	valid, err := runner.BuildContext(values, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	wrong := valid
	wrong.Operators = slices.Clone(valid.Operators)
	wrong.Operators[0].AdministratorID = "wrong-roster-point-identity"
	wrongBytes, err := wrong.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var phase PhaseResponse
	err = runner.clients[0].call(context.Background(), "/v1/prepare", PrepareRequest{Context: wrongBytes}, &phase)
	if remoteCode(err) != "BINDING_REJECTED" {
		t.Fatalf("wrong identity accepted: %v", err)
	}
	validBytes, err := valid.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if err := runner.clients[0].call(context.Background(), "/v1/prepare", PrepareRequest{Context: validBytes}, &phase); err != nil {
		t.Fatal(err)
	}
	if err := runner.clients[0].call(context.Background(), "/v1/prepare", PrepareRequest{Context: validBytes}, &phase); remoteCode(err) != "REPLAY_REJECTED" {
		t.Fatalf("replay accepted: %v", err)
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
	values, err := FreshSessionValues()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	result, err := runner.RunSuccess(ctx, values)
	if err != nil {
		t.Fatal(err)
	}
	if result.Bundle.Unsigned.KeyID == ([32]byte{}) || ceremony.VerifyPublicationReceipt(result.Receipt, result.Bundle) != nil {
		t.Fatal("published bundle readback failed")
	}
	for _, operator := range result.Operators {
		if operator.Phase != ceremony.PhaseCompleted || operator.RuntimeState != "COMPLETED" || len(operator.TerminalTombstone) == 0 {
			t.Fatal("operator did not complete")
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
	if err := ScanPublicEvidence(result.EvidencePath, knownSecrets); err != nil {
		t.Fatalf("public evidence contains secret material: %v", err)
	}
}

func TestStaleReplicaPreventsRealGeneration(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	defer cluster.stop()
	runner := cluster.runner(t)
	defer runner.Close()
	values, err := FreshSessionValues()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := runner.RunStaleReplica(ctx, values)
	if err != nil {
		t.Fatal(err)
	}
	if result.Bundle.SchemaVersion != "" {
		t.Fatal("stale run emitted a public bundle")
	}
	for index, operator := range result.Operators {
		if operator.RuntimeState != "POISONED" || index < ceremony.Threshold && len(operator.TerminalTombstone) == 0 {
			t.Fatal("stale operator was not terminally poisoned")
		}
	}
}

func TestAbortTerminalAfterOrdinaryRestartAndNonceChange(t *testing.T) {
	cluster := newTestCluster(t)
	cluster.start()
	runner := cluster.runner(t)
	values, err := FreshSessionValues()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	result, err := runner.RunAbort(ctx, values)
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
	newNonce := sha256.Sum256([]byte("changed-nonce-after-ordinary-restart"))
	ctx, cancel = context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := restarted.VerifyRestartConsumed(ctx, result.Context, newNonce); err != nil {
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
	if err := client.call(context.Background(), "/v1/phase", EmptyRequest{}, &phase); err == nil {
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
	if err := ScanPublicEvidence(root, [][]byte{secret}); err != nil {
		t.Fatal(err)
	}
	if err := writeNoReplace(filepath.Join(root, "leak.bin"), secret, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ScanPublicEvidence(root, [][]byte{secret}); err == nil {
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
