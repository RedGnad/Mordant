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
	case "init-authority":
		return runInitAuthority(arguments[1:])
	case "authorize-session":
		return runAuthorizeSession(arguments[1:])
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

func runInitAuthority(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-runner init-authority", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var directory string
	flags.StringVar(&directory, "dir", "", "offline authority directory")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !filepath.IsAbs(directory) {
		return errors.New("invalid init-authority arguments")
	}
	if _, err := oneshotruntime.InitializeSessionAuthority(directory); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "ONESHOT_SESSION_AUTHORITY_INITIALIZED")
	return nil
}

func runAuthorizeSession(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-runner authorize-session", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var configPath, authorityKeyPath, output, evidenceRun string
	flags.StringVar(&configPath, "config", "", "runner configuration")
	flags.StringVar(&authorityKeyPath, "authority-key", "", "offline session-authority private key")
	flags.StringVar(&output, "out", "", "new offline-authorized session plan")
	flags.StringVar(&evidenceRun, "evidence-run", "", "optional prior evidence directory whose exact context is re-authorized")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !filepath.IsAbs(configPath) ||
		!filepath.IsAbs(authorityKeyPath) || !filepath.IsAbs(output) || evidenceRun != "" && !filepath.IsAbs(evidenceRun) {
		return errors.New("invalid authorize-session arguments")
	}
	config, err := oneshotruntime.LoadRunnerConfig(configPath)
	if err != nil {
		return err
	}
	authority, err := oneshotruntime.LoadSessionAuthorityPrivate(authorityKeyPath)
	if err != nil {
		return err
	}
	params, err := oneshotruntime.RuntimeParameters()
	if err != nil {
		return err
	}
	var session oneshotruntime.AuthorizedSession
	if evidenceRun == "" {
		values, valuesErr := oneshotruntime.FreshSessionValues()
		if valuesErr != nil {
			return valuesErr
		}
		session, err = oneshotruntime.NewAuthorizedSession(config, params, authority, values, time.Now().UTC())
	} else {
		contextValue, contextErr := oneshotruntime.LoadContextFromEvidence(evidenceRun)
		if contextErr != nil {
			return contextErr
		}
		session, err = oneshotruntime.AuthorizeContext(config, authority, contextValue, time.Now().UTC())
	}
	if err != nil {
		return err
	}
	if err := oneshotruntime.WriteAuthorizedSession(output, session); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "ONESHOT_SESSION_AUTHORIZED")
	return nil
}

type operatorArguments []string

func (o *operatorArguments) String() string         { return strings.Join(*o, ";") }
func (o *operatorArguments) Set(value string) error { *o = append(*o, value); return nil }

func runConfigure(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-runner configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var operators operatorArguments
	var publicationRoot, evidenceRoot, exportRoot, authorityPath, output string
	flags.Var(&operators, "operator", "point,https://ip:port,public-identity.json (repeat three times)")
	flags.StringVar(&publicationRoot, "publication-root", "", "canonical public publication root")
	flags.StringVar(&evidenceRoot, "evidence-root", "", "public evidence root")
	flags.StringVar(&exportRoot, "export-root", "", "verified completed evidence export root")
	flags.StringVar(&authorityPath, "session-authority-public", "", "fixed session-authority public document")
	flags.StringVar(&output, "out", "", "runner configuration")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || len(operators) != 3 || !filepath.IsAbs(publicationRoot) ||
		!filepath.IsAbs(evidenceRoot) || !filepath.IsAbs(exportRoot) || !filepath.IsAbs(output) {
		return errors.New("invalid configure arguments")
	}
	authority, err := oneshotruntime.LoadSessionAuthorityPublic(authorityPath)
	if err != nil {
		return err
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
		SchemaVersion: oneshotruntime.RunnerConfigSchema, ProtocolVersion: "mordant.fhe-ceremony/oneshot-v2",
		ContextSchema: "mordant.fhe-ceremony-context/oneshot-v2", ParameterProfile: oneshotruntime.ParameterProfile,
		SessionAuthorityPublicKey: authority.PublicKey, PublicationRoot: publicationRoot, EvidenceRoot: evidenceRoot,
		ExportRoot: exportRoot, Operators: configured, Context: oneshotruntime.DefaultContextTemplate(),
	}
	if err := oneshotruntime.WriteRunnerConfig(output, config); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "ONESHOT_RUNNER_CONFIGURED")
	return nil
}

func loadRunner(arguments []string, command string) (*oneshotruntime.Runner, oneshotruntime.AuthorizedSession, context.Context, context.CancelFunc, error) {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var configPath, sessionPath string
	flags.StringVar(&configPath, "config", "", "runner configuration")
	flags.StringVar(&sessionPath, "session", "", "offline-authorized session plan")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || configPath == "" || sessionPath == "" {
		return nil, oneshotruntime.AuthorizedSession{}, nil, nil, errors.New("invalid runner arguments")
	}
	config, err := oneshotruntime.LoadRunnerConfig(configPath)
	if err != nil {
		return nil, oneshotruntime.AuthorizedSession{}, nil, nil, err
	}
	session, err := oneshotruntime.LoadAuthorizedSession(sessionPath, config)
	if err != nil {
		return nil, oneshotruntime.AuthorizedSession{}, nil, nil, err
	}
	params, err := oneshotruntime.RuntimeParameters()
	if err != nil {
		return nil, oneshotruntime.AuthorizedSession{}, nil, nil, err
	}
	runner, err := oneshotruntime.NewRunner(config, params)
	if err != nil {
		return nil, oneshotruntime.AuthorizedSession{}, nil, nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Minute)
	return runner, session, ctx, cancel, nil
}

func runSuccess(arguments []string) error {
	runner, session, ctx, cancel, err := loadRunner(arguments, "oneshot-runner success")
	if err != nil {
		return err
	}
	defer runner.Close()
	defer cancel()
	result, err := runner.RunSuccess(ctx, session)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ONESHOT_SUCCESS ceremony=%x evidence=%s\n", result.Context.CeremonyID(), result.EvidencePath)
	return nil
}

func runStale(arguments []string) error {
	runner, session, ctx, cancel, err := loadRunner(arguments, "oneshot-runner stale-replica")
	if err != nil {
		return err
	}
	defer runner.Close()
	defer cancel()
	result, err := runner.RunStaleReplica(ctx, session)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ONESHOT_STALE_REJECTED ceremony=%x evidence=%s\n", result.Context.CeremonyID(), result.EvidencePath)
	return nil
}

func runAbortRestart(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-runner abort-restart", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var configPath, sessionPath, stage, runDirectory string
	flags.StringVar(&configPath, "config", "", "runner configuration")
	flags.StringVar(&sessionPath, "session", "", "offline-authorized session plan")
	flags.StringVar(&stage, "stage", "", "abort or verify")
	flags.StringVar(&runDirectory, "run", "", "abort evidence directory for verify")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !filepath.IsAbs(configPath) || !filepath.IsAbs(sessionPath) ||
		stage != "abort" && stage != "verify" || stage == "verify" && !filepath.IsAbs(runDirectory) || stage == "abort" && runDirectory != "" {
		return errors.New("invalid abort-restart arguments")
	}
	config, err := oneshotruntime.LoadRunnerConfig(configPath)
	if err != nil {
		return err
	}
	session, err := oneshotruntime.LoadAuthorizedSession(sessionPath, config)
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
		result, err := runner.RunAbort(ctx, session)
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
	if original.ContextDigest() != session.Context.ContextDigest() {
		return errors.New("restart verification requires a new authorization for the exact original context")
	}
	if err := runner.VerifyRestartConsumed(ctx, session); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "ONESHOT_RESTART_REJECTED_CONSUMED_SESSION")
	return nil
}

func runExport(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-runner export-evidence", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var configPath, runDirectory string
	flags.StringVar(&configPath, "config", "", "runner configuration")
	flags.StringVar(&runDirectory, "run", "", "direct child name under the configured evidence root")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || !filepath.IsAbs(configPath) ||
		runDirectory == "" || filepath.Base(runDirectory) != runDirectory || strings.ContainsAny(runDirectory, `/\\`) {
		return errors.New("invalid export arguments")
	}
	config, err := oneshotruntime.LoadRunnerConfig(configPath)
	if err != nil {
		return err
	}
	destination, err := oneshotruntime.ExportCompletedEvidence(config, runDirectory)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ONESHOT_PUBLIC_EVIDENCE_EXPORTED path=%s\n", destination)
	return nil
}
