package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"mordant.dev/fhe-lab/lattigo/internal/oneshotruntime"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ONESHOT_RUNNER_FAILED")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("missing command")
	}
	switch arguments[0] {
	case "configure":
		return runConfigure(arguments[1:])
	case "success":
		return runSuccess(arguments[1:])
	case "stale-replica":
		return runStale(arguments[1:])
	case "abort-restart":
		return runAbortRestart(arguments[1:])
	case "export-evidence":
		return runExport(arguments[1:])
	default:
		return errors.New("unknown command")
	}
}

type operatorArguments []string

func (o *operatorArguments) String() string         { return strings.Join(*o, ";") }
func (o *operatorArguments) Set(value string) error { *o = append(*o, value); return nil }

func runConfigure(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-runner configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var operators operatorArguments
	var publicationRoot, evidenceRoot, output string
	flags.Var(&operators, "operator", "point,https://ip:port,public-identity.json (repeat three times)")
	flags.StringVar(&publicationRoot, "publication-root", "", "canonical public publication root")
	flags.StringVar(&evidenceRoot, "evidence-root", "", "public evidence root")
	flags.StringVar(&output, "out", "", "runner configuration")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || len(operators) != 3 || !filepath.IsAbs(publicationRoot) || !filepath.IsAbs(evidenceRoot) || !filepath.IsAbs(output) {
		return errors.New("invalid configure arguments")
	}
	configured := make([]oneshotruntime.RunnerOperator, 3)
	for _, value := range operators {
		parts := strings.SplitN(value, ",", 3)
		if len(parts) != 3 {
			return errors.New("invalid operator")
		}
		point, err := strconv.Atoi(parts[0])
		if err != nil || point < 1 || point > 3 || configured[point-1].Endpoint != "" {
			return errors.New("invalid operator point")
		}
		identity, err := oneshotruntime.LoadPublicIdentity(parts[2])
		if err != nil || identity.Point != uint64(point) {
			return errors.New("invalid operator identity")
		}
		configured[point-1] = oneshotruntime.RunnerOperator{Endpoint: parts[1], Identity: identity}
	}
	config := oneshotruntime.RunnerConfig{
		SchemaVersion:    oneshotruntime.RunnerConfigSchema,
		ProtocolVersion:  "mordant.fhe-ceremony/oneshot-v2",
		ContextSchema:    "mordant.fhe-ceremony-context/oneshot-v2",
		ParameterProfile: oneshotruntime.ParameterProfile,
		PublicationRoot:  publicationRoot,
		EvidenceRoot:     evidenceRoot,
		Operators:        configured,
		Context:          oneshotruntime.DefaultContextTemplate(),
	}
	if err := oneshotruntime.WriteRunnerConfig(output, config); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "ONESHOT_RUNNER_CONFIGURED")
	return nil
}

func loadRunner(arguments []string, command string) (*oneshotruntime.Runner, context.Context, context.CancelFunc, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var configPath string
	flags.StringVar(&configPath, "config", "", "runner configuration")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || configPath == "" {
		return nil, nil, nil, errors.New("invalid runner arguments")
	}
	config, err := oneshotruntime.LoadRunnerConfig(configPath)
	if err != nil {
		return nil, nil, nil, err
	}
	params, err := oneshotruntime.RuntimeParameters()
	if err != nil {
		return nil, nil, nil, err
	}
	runner, err := oneshotruntime.NewRunner(config, params)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	return runner, ctx, cancel, nil
}

func runSuccess(arguments []string) error {
	runner, ctx, cancel, err := loadRunner(arguments, "oneshot-runner success")
	if err != nil {
		return err
	}
	defer runner.Close()
	defer cancel()
	values, err := oneshotruntime.FreshSessionValues()
	if err != nil {
		return err
	}
	result, err := runner.RunSuccess(ctx, values)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ONESHOT_SUCCESS ceremony=%x evidence=%s\n", result.Context.CeremonyID(), result.EvidencePath)
	return nil
}

func runStale(arguments []string) error {
	runner, ctx, cancel, err := loadRunner(arguments, "oneshot-runner stale-replica")
	if err != nil {
		return err
	}
	defer runner.Close()
	defer cancel()
	values, err := oneshotruntime.FreshSessionValues()
	if err != nil {
		return err
	}
	result, err := runner.RunStaleReplica(ctx, values)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ONESHOT_STALE_REJECTED ceremony=%x evidence=%s\n", result.Context.CeremonyID(), result.EvidencePath)
	return nil
}

func runAbortRestart(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-runner abort-restart", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var configPath, stage, runDirectory string
	flags.StringVar(&configPath, "config", "", "runner configuration")
	flags.StringVar(&stage, "stage", "", "abort or verify")
	flags.StringVar(&runDirectory, "run", "", "abort evidence directory for verify")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || configPath == "" || stage != "abort" && stage != "verify" || stage == "verify" && !filepath.IsAbs(runDirectory) {
		return errors.New("invalid abort-restart arguments")
	}
	config, err := oneshotruntime.LoadRunnerConfig(configPath)
	if err != nil {
		return err
	}
	params, err := oneshotruntime.RuntimeParameters()
	if err != nil {
		return err
	}
	runner, err := oneshotruntime.NewRunner(config, params)
	if err != nil {
		return err
	}
	defer runner.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if stage == "abort" {
		values, err := oneshotruntime.FreshSessionValues()
		if err != nil {
			return err
		}
		result, err := runner.RunAbort(ctx, values)
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stdout, "ONESHOT_ABORTED restart-required=true evidence=%s\n", result.EvidencePath)
		return nil
	}
	original, err := oneshotruntime.LoadContextFromEvidence(runDirectory)
	if err != nil {
		return err
	}
	values, err := oneshotruntime.FreshSessionValues()
	if err != nil {
		return err
	}
	if err := runner.VerifyRestartConsumed(ctx, original, values.Nonce); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "ONESHOT_RESTART_REJECTED_CONSUMED_SESSION")
	return nil
}

func runExport(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-runner export-evidence", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var source, output string
	flags.StringVar(&source, "source", "", "verified public run evidence")
	flags.StringVar(&output, "out", "", "new public evidence export directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !filepath.IsAbs(source) || !filepath.IsAbs(output) {
		return errors.New("invalid export arguments")
	}
	if err := oneshotruntime.ExportEvidence(source, output); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "ONESHOT_PUBLIC_EVIDENCE_EXPORTED")
	return nil
}
