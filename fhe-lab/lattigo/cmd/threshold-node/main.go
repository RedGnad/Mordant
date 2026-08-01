// Command threshold-node runs exactly one Mordant threshold-share operator.
// Three independently configured processes are required for the 2-of-3 set;
// the coordinator selects two before PREPARE and has no fallback after COMMIT.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	fhe "mordant.dev/fhe-lab/lattigo"
	"mordant.dev/fhe-lab/lattigo/internal/thresholdnet"
)

const (
	maxOperatorConfigBytes = 16 << 20
	maxPublicKeyBytes      = ed25519.PublicKeySize
	maxCertificateBytes    = 1 << 20
)

type options struct {
	listen         string
	operatorConfig string
	ledger         string
	certificate    string
	privateKey     string
	clientCA       string
	coordinatorKey string
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		// Never echo paths, request bodies, ciphertexts or crypto-library errors.
		fmt.Fprintln(os.Stderr, "THRESHOLD_NODE_FAILED")
		os.Exit(1)
	}
}

func run(arguments []string) error {
	settings, err := parseOptions(arguments)
	if err != nil {
		return err
	}
	operatorBytes, err := readSecretFile(settings.operatorConfig, maxOperatorConfigBytes)
	if err != nil {
		return err
	}
	operator, err := fhe.NewThresholdOperator(operatorBytes)
	if err != nil {
		return err
	}
	coordinatorKey, err := os.ReadFile(settings.coordinatorKey)
	if err != nil || len(coordinatorKey) != maxPublicKeyBytes {
		return errors.New("invalid coordinator key")
	}
	if _, err := readSecretFile(settings.privateKey, maxCertificateBytes); err != nil {
		return err
	}
	certificate, err := tls.LoadX509KeyPair(settings.certificate, settings.privateKey)
	if err != nil {
		return err
	}
	caBytes, err := os.ReadFile(settings.clientCA)
	if err != nil || len(caBytes) == 0 || len(caBytes) > maxCertificateBytes {
		return errors.New("invalid client CA")
	}
	clientCAs := x509.NewCertPool()
	if !clientCAs.AppendCertsFromPEM(caBytes) {
		return errors.New("invalid client CA")
	}
	ledger, err := thresholdnet.Open(settings.ledger)
	if err != nil {
		return err
	}
	defer ledger.Close()

	service := &thresholdnet.OperatorServer{
		Operator:             operator,
		Ledger:               ledger,
		CoordinatorPublicKey: append(ed25519.PublicKey(nil), coordinatorKey...),
	}
	server := &http.Server{
		Addr:              settings.listen,
		Handler:           service.Handler(),
		TLSConfig:         thresholdnet.ServerTLSConfig(certificate, clientCAs),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       2 * time.Minute,
		WriteTimeout:      2 * time.Minute,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	listener, err := net.Listen("tcp", settings.listen)
	if err != nil {
		return err
	}
	tlsListener := tls.NewListener(listener, server.TLSConfig)

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	defer signal.Stop(stop)
	serveError := make(chan error, 1)
	go func() { serveError <- server.Serve(tlsListener) }()

	select {
	case <-stop:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return server.Shutdown(ctx)
	case err := <-serveError:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}

func parseOptions(arguments []string) (options, error) {
	var settings options
	flags := flag.NewFlagSet("threshold-node", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.StringVar(&settings.listen, "listen", "127.0.0.1:9443", "TLS listen address")
	flags.StringVar(&settings.operatorConfig, "operator-config", "", "0600 operator bundle")
	flags.StringVar(&settings.ledger, "ledger", "", "durable one-shot ledger")
	flags.StringVar(&settings.certificate, "tls-cert", "", "server certificate")
	flags.StringVar(&settings.privateKey, "tls-key", "", "0600 server private key")
	flags.StringVar(&settings.clientCA, "client-ca", "", "coordinator client CA")
	flags.StringVar(&settings.coordinatorKey, "coordinator-key", "", "raw Ed25519 coordinator public key")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 ||
		settings.listen == "" || settings.operatorConfig == "" || settings.ledger == "" ||
		settings.certificate == "" || settings.privateKey == "" || settings.clientCA == "" ||
		settings.coordinatorKey == "" {
		return options{}, errors.New("invalid threshold-node configuration")
	}
	return settings, nil
}

func readSecretFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("invalid secret file")
	}
	contents, err := os.ReadFile(path)
	if err != nil || int64(len(contents)) != info.Size() {
		return nil, errors.New("invalid secret file")
	}
	return contents, nil
}
