// Command oneshot-provenance reports cryptographically verified provenance for
// its own concrete executable. It does not run a ceremony and cannot produce
// acceptance evidence by itself.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

func main() {
	provenance, err := oneshotceremony.CurrentExecutableProvenance()
	if err != nil {
		fmt.Fprintln(os.Stderr, "ONESHOT_PROVENANCE_FAILED")
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(provenance); err != nil {
		fmt.Fprintln(os.Stderr, "ONESHOT_PROVENANCE_FAILED")
		os.Exit(1)
	}
}
