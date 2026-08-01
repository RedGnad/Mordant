package lattigospike

import (
	"errors"
	"testing"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/ring"
)

func TestProtocolBindingDigestUsesCanonicalC1Only(t *testing.T) {
	keyID := protocolTestID(0x11)
	ct := protocolTestCiphertext(t)

	original, err := ProtocolBindingDigest(keyID, ProtocolCollectiveKeySwitchToZero, ct)
	if err != nil {
		t.Fatalf("digest original ciphertext: %v", err)
	}

	c0Mutation := ct.CopyNew()
	c0Mutation.Value[0].Coeffs[0][0]++
	c0Digest, err := ProtocolBindingDigest(keyID, ProtocolCollectiveKeySwitchToZero, c0Mutation)
	if err != nil {
		t.Fatalf("digest c0 mutation: %v", err)
	}
	if c0Digest != original {
		t.Fatal("c0 mutation changed a binding for a protocol that only consumes c1")
	}

	c1Mutation := ct.CopyNew()
	c1Mutation.Value[1].Coeffs[0][0]++
	c1Digest, err := ProtocolBindingDigest(keyID, ProtocolCollectiveKeySwitchToZero, c1Mutation)
	if err != nil {
		t.Fatalf("digest c1 mutation: %v", err)
	}
	if c1Digest == original {
		t.Fatal("c1 mutation did not change the protocol binding")
	}

	copyOfSameC1 := ct.CopyNew()
	copyDigest, err := ProtocolBindingDigest(keyID, ProtocolCollectiveKeySwitchToZero, copyOfSameC1)
	if err != nil {
		t.Fatalf("digest canonical copy: %v", err)
	}
	if copyDigest != original {
		t.Fatal("identical canonical c1 bytes produced different bindings")
	}

	otherKeyDigest, err := ProtocolBindingDigest(protocolTestID(0x22), ProtocolCollectiveKeySwitchToZero, ct)
	if err != nil {
		t.Fatalf("digest with another key: %v", err)
	}
	if otherKeyDigest == original {
		t.Fatal("key epoch is not bound into the protocol digest")
	}
}

func TestProtocolBindingDigestRejectsCallerDefinedKindsAndMalformedInput(t *testing.T) {
	keyID := protocolTestID(0x33)
	ct := protocolTestCiphertext(t)

	tests := []struct {
		name string
		key  [32]byte
		kind ProtocolKind
		ct   *rlwe.Ciphertext
	}{
		{name: "empty_key", kind: ProtocolCollectiveKeySwitchToZero, ct: ct},
		{name: "caller_defined_kind", key: keyID, kind: ProtocolKind(2), ct: ct},
		{name: "nil_ciphertext", key: keyID, kind: ProtocolCollectiveKeySwitchToZero},
		{name: "degree_zero", key: keyID, kind: ProtocolCollectiveKeySwitchToZero, ct: protocolDegreeZeroCiphertext(t)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ProtocolBindingDigest(test.key, test.kind, test.ct); !errors.Is(err, ErrInvalidProtocolBinding) {
				t.Fatalf("expected ErrInvalidProtocolBinding, got %v", err)
			}
		})
	}
}

func protocolTestCiphertext(t *testing.T) *rlwe.Ciphertext {
	t.Helper()
	polys := []ring.Poly{ring.NewPoly(8, 1), ring.NewPoly(8, 1)}
	ct, err := rlwe.NewCiphertextAtLevelFromPoly(1, polys)
	if err != nil {
		t.Fatalf("construct test ciphertext: %v", err)
	}
	ct.Value[0].Coeffs[0][0] = 7
	ct.Value[0].Coeffs[1][3] = 9
	ct.Value[1].Coeffs[0][0] = 11
	ct.Value[1].Coeffs[1][3] = 13
	return ct
}

func protocolDegreeZeroCiphertext(t *testing.T) *rlwe.Ciphertext {
	t.Helper()
	ct, err := rlwe.NewCiphertextAtLevelFromPoly(0, []ring.Poly{ring.NewPoly(8, 0)})
	if err != nil {
		t.Fatalf("construct degree-zero ciphertext: %v", err)
	}
	return ct
}

func protocolTestID(value byte) [32]byte {
	var id [32]byte
	for i := range id {
		id[i] = value
	}
	return id
}
