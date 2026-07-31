package synthetic

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"golang.org/x/crypto/sha3"
	fhe "mordant.dev/fhe-lab/lattigo"
)

const (
	ChainID             = uint64(31_337)
	AuthorizationExpiry = uint64(2_100_000_000)
)

var (
	Vault    = repeat20(0x11)
	PolicyID = must32("bd26a38240747b4fb4363d5edc5d5f8d6729d1024aa343bc6115ca20013a8540")
	Role     = keccakLabel("mordant.role.facility.v1")
)

// Pair materializes synthetic private values in client-process memory only.
// Callers must never include these PlainPledge values in output or logs.
func Pair(runtime *fhe.Runtime, label string, mode fhe.IdentityMode) (fhe.PlainPledge, fhe.PlainPledge, error) {
	invoiceID := sha256.Sum256([]byte("synthetic-invoice-id"))
	link := fhe.ReceivableLinkCommitment(Vault, fhe.PolicyVersion, invoiceID, sha256.Sum256([]byte("synthetic-link-salt")))
	if mode == fhe.IdentityFullFHE256 {
		link = [32]byte{}
	}

	authA, err := runtime.SubmitterAuthorizationCommitment(authorizationClaim("a-"+label, 101))
	if err != nil {
		return fhe.PlainPledge{}, fhe.PlainPledge{}, err
	}
	authB, err := runtime.SubmitterAuthorizationCommitment(authorizationClaim("b-"+label, 102))
	if err != nil {
		return fhe.PlainPledge{}, fhe.PlainPledge{}, err
	}
	a := fhe.PlainPledge{
		ActiveFrom:                100,
		ActiveUntil:               400,
		Amount:                    fhe.Uint256{0, 0, 0, 1_000_000},
		Currency:                  sha256.Sum256([]byte("currency-usd-bytes32")),
		ObligationID:              sha256.Sum256([]byte("obligation-a-" + label)),
		ReceivableID:              invoiceID,
		Exclusive:                 true,
		ReceivableCommitment:      link,
		AuthorizationCommitment:   authA,
		PrivateMetadataCommitment: sha256.Sum256([]byte("salted-private-metadata-a-" + label)),
	}
	b := fhe.PlainPledge{
		ActiveFrom:                200,
		ActiveUntil:               500,
		Amount:                    fhe.Uint256{0, 0, 0, 900_000},
		Currency:                  sha256.Sum256([]byte("currency-usd-bytes32")),
		ObligationID:              sha256.Sum256([]byte("obligation-b-" + label)),
		ReceivableID:              invoiceID,
		Exclusive:                 true,
		ReceivableCommitment:      link,
		AuthorizationCommitment:   authB,
		PrivateMetadataCommitment: sha256.Sum256([]byte("salted-private-metadata-b-" + label)),
	}
	return a, b, nil
}

func GrantPair(runtime *fhe.Runtime, a, b fhe.PlainPledge) error {
	expiry := time.Unix(int64(AuthorizationExpiry), 0)
	if err := runtime.GrantIngress(a.AuthorizationCommitment, fhe.PolicyVersion, expiry); err != nil {
		return err
	}
	return runtime.GrantIngress(b.AuthorizationCommitment, fhe.PolicyVersion, expiry)
}

func InputContext(slot uint8, clientNonce uint64) fhe.InputCommitmentContext {
	return fhe.InputCommitmentContext{
		ChainID:       fhe.Uint256{0, 0, 0, ChainID},
		Vault:         Vault,
		PolicyID:      PolicyID,
		PolicyVersion: fhe.PolicyVersion,
		InputSlot:     slot,
		ClientNonce:   fhe.Uint256{0, 0, 0, clientNonce},
	}
}

func authorizationClaim(subject string, nonce uint64) fhe.AuthorizationClaim {
	return fhe.AuthorizationClaim{
		SubjectCommitment: sha256.Sum256([]byte("synthetic-subject-" + subject)),
		Role:              Role,
		Vault:             Vault,
		PolicyID:          PolicyID,
		PolicyVersion:     fhe.PolicyVersion,
		ValidUntil:        AuthorizationExpiry,
		Nonce:             fhe.Uint256{0, 0, 0, nonce},
	}
}

func repeat20(value byte) (out [20]byte) {
	for i := range out {
		out[i] = value
	}
	return
}

func must32(value string) (out [32]byte) {
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) {
		panic(fmt.Sprintf("invalid synthetic bytes32 constant: %q", value))
	}
	copy(out[:], decoded)
	return
}

func keccakLabel(value string) [32]byte {
	var out [32]byte
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write([]byte(value))
	copy(out[:], hash.Sum(nil))
	return out
}
