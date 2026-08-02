package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"mordant.dev/fhe-lab/lattigo/internal/oneshotruntime"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "ONESHOT_OPERATOR_FAILED")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	if len(arguments) == 0 {
		return errors.New("missing command")
	}
	switch arguments[0] {
	case "init":
		return runInit(arguments[1:])
	case "configure":
		return runConfigure(arguments[1:])
	case "roster":
		return runRoster(arguments[1:])
	case "serve":
		return runServe(arguments[1:])
	default:
		return errors.New("unknown command")
	}
}

type identityArguments []string

func (i *identityArguments) String() string         { return fmt.Sprint([]string(*i)) }
func (i *identityArguments) Set(value string) error { *i = append(*i, value); return nil }

func runRoster(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-operator roster", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var identities identityArguments
	var output string
	flags.Var(&identities, "identity", "public identity file (repeat three times)")
	flags.StringVar(&output, "out", "", "fixed public roster file")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || len(identities) != 3 || output == "" {
		return errors.New("invalid roster arguments")
	}
	roster := make([]oneshotruntime.PublicIdentity, 3)
	for _, path := range identities {
		identity, err := oneshotruntime.LoadPublicIdentity(path)
		if err != nil || identity.Point < 1 || identity.Point > 3 || roster[identity.Point-1].Point != 0 {
			return errors.New("invalid roster identity")
		}
		roster[identity.Point-1] = identity
	}
	if err := oneshotruntime.WriteRoster(output, roster); err != nil {
		return err
	}
	fmt.Fprintln(os.Stdout, "ONESHOT_OPERATOR_ROSTER_WRITTEN")
	return nil
}

func runInit(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-operator init", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var options oneshotruntime.InitOptions
	var authorityPath string
	flags.StringVar(&options.Directory, "dir", "", "operator configuration directory")
	flags.Uint64Var(&options.Point, "point", 0, "fixed roster point")
	flags.StringVar(&options.AdministratorID, "administrator-id", "", "distinct operator identity label")
	flags.StringVar(&options.ListenAddress, "listen", "", "fixed IP listen address")
	flags.StringVar(&options.StateRoot, "state-root", "", "operator-local state root")
	flags.StringVar(&options.PublicationRoot, "publication-root", "", "canonical public publication root")
	flags.StringVar(&authorityPath, "session-authority-public", "", "fixed session-authority public document")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 {
		return errors.New("invalid init arguments")
	}
	authority, err := oneshotruntime.LoadSessionAuthorityPublic(authorityPath)
	if err != nil {
		return err
	}
	options.Authority = authority
	bootstrap, err := oneshotruntime.InitializeOperator(options)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ONESHOT_OPERATOR_INITIALIZED point=%d\n", bootstrap.Identity.Point)
	return nil
}

func runConfigure(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-operator configure", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var bootstrap, roster, output string
	flags.StringVar(&bootstrap, "bootstrap", "", "operator bootstrap file")
	flags.StringVar(&roster, "roster", "", "fixed public roster file")
	flags.StringVar(&output, "out", "", "immutable operator configuration")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || bootstrap == "" || roster == "" || output == "" {
		return errors.New("invalid configure arguments")
	}
	config, err := oneshotruntime.ConfigureOperator(bootstrap, roster, output)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "ONESHOT_OPERATOR_CONFIGURED point=%d\n", config.Identity.Point)
	return nil
}

func runServe(arguments []string) error {
	flags := flag.NewFlagSet("oneshot-operator serve", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var configPath string
	flags.StringVar(&configPath, "config", "", "immutable operator configuration")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || configPath == "" {
		return errors.New("invalid serve arguments")
	}
	config, err := oneshotruntime.LoadOperatorConfig(configPath)
	if err != nil {
		return err
	}
	params, err := oneshotruntime.RuntimeParameters()
	if err != nil {
		return err
	}
	service, err := oneshotruntime.NewOperatorService(config, params)
	if err != nil {
		return err
	}
	certificate, err := config.TLSCertificate()
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", config.ListenAddress)
	if err != nil {
		return err
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13})
	server := &http.Server{
		Handler:           service.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       6 * time.Minute,
		WriteTimeout:      6 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	errorsChannel := make(chan error, 1)
	go func() { errorsChannel <- server.Serve(tlsListener) }()
	fmt.Fprintf(os.Stdout, "ONESHOT_OPERATOR_READY point=%d listen=%s\n", config.Identity.Point, config.ListenAddress)
	select {
	case <-stop:
		shutdownContext, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(shutdownContext)
	case serveErr := <-errorsChannel:
		if errors.Is(serveErr, http.ErrServerClosed) {
			return nil
		}
		return serveErr
	}
}
