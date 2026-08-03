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
	publicRoot := flag.String("public-root", "", "absolute public case root")
	privateRoot := flag.String("private-root", "", "absolute private decryptor root")
	flag.Parse()
	if *publicRoot == "" || *privateRoot == "" {
		fail(fmt.Errorf("-public-root and -private-root are required"))
	}
	report, err := governedfhe.InspectProductCase(*publicRoot, *privateRoot)
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
