// Command mordant-fhe-inspect exposes only read-only terminal verification for
// the durable product orchestrator.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"mordant.dev/fhe-lab/lattigo/governedfhe"
)

func main() {
	mode := flag.String("mode", "public", "public or pending-private")
	publicRoot := flag.String("public-root", "", "absolute public case root")
	privateRoot := flag.String("private-root", "", "absolute private decryptor root")
	pendingPhase := flag.String("pending-phase", "", "exact pending product phase for private inspection")
	flag.Parse()
	if *publicRoot == "" {
		fail(fmt.Errorf("-public-root is required"))
	}
	var report governedfhe.ProductInspection
	var err error
	switch *mode {
	case "public":
		if *privateRoot != "" || *pendingPhase != "" {
			fail(fmt.Errorf("public inspection refuses private inputs"))
		}
		report, err = governedfhe.InspectProductCase(*publicRoot)
	case "pending-private":
		if *privateRoot == "" || *pendingPhase == "" {
			fail(fmt.Errorf("pending-private inspection requires private root and phase"))
		}
		report, err = governedfhe.InspectPendingProductPrivate(*publicRoot, *privateRoot, *pendingPhase)
	default:
		fail(fmt.Errorf("unsupported inspection mode"))
	}
	if err != nil {
		fail(err)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		fail(err)
	}
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "mordant-fhe-inspect: verification failed\n")
	os.Exit(1)
}
