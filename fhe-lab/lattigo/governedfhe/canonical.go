package governedfhe

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
)

const maxManifestBytes = 4 << 20

type Digest [32]byte

func (d Digest) String() string { return "sha256:" + hex.EncodeToString(d[:]) }

func (d Digest) MarshalText() ([]byte, error) { return []byte(d.String()), nil }

func (d *Digest) UnmarshalText(text []byte) error {
	const prefix = "sha256:"
	if d == nil || len(text) != len(prefix)+64 || string(text[:len(prefix)]) != prefix {
		return ErrBinding
	}
	decoded, err := hex.DecodeString(string(text[len(prefix):]))
	if err != nil || len(decoded) != 32 {
		return ErrBinding
	}
	copy(d[:], decoded)
	return nil
}

func DigestBytes(data []byte) Digest { return Digest(sha256.Sum256(data)) }

func digestCanonical(value any) (Digest, []byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return Digest{}, nil, err
	}
	return DigestBytes(encoded), encoded, nil
}

func marshalCanonical(value any) ([]byte, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func decodeStrict(data []byte, target any) error {
	if len(data) == 0 || len(data) > maxManifestBytes {
		return ErrArtifact
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: %v", ErrArtifact, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return ErrArtifact
	}
	canonical, err := marshalCanonical(target)
	if err != nil || !bytes.Equal(canonical, data) {
		return ErrArtifact
	}
	return nil
}

func signCanonical(privateKey ed25519.PrivateKey, domain string, value any) ([]byte, error) {
	if len(privateKey) != ed25519.PrivateKeySize || domain == "" {
		return nil, ErrBinding
	}
	_, encoded, err := digestCanonical(value)
	if err != nil {
		return nil, err
	}
	message := append(append([]byte(domain), 0), encoded...)
	return ed25519.Sign(privateKey, message), nil
}

func verifyCanonical(publicKey ed25519.PublicKey, domain string, value any, signature []byte) error {
	if len(publicKey) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize || domain == "" {
		return ErrBinding
	}
	_, encoded, err := digestCanonical(value)
	if err != nil {
		return err
	}
	message := append(append([]byte(domain), 0), encoded...)
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrBinding
	}
	return nil
}

func nonzero(values ...Digest) bool {
	for _, value := range values {
		if value == (Digest{}) {
			return false
		}
	}
	return true
}
