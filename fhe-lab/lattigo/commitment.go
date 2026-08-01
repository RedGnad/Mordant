package lattigospike

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/sha3"
)

const ConfidentialPolicyInputType = "ConfidentialPolicyInput(uint256 chainId,address vault,bytes32 policyId,uint32 policyVersion,bytes32 keyId,uint8 inputSlot,bytes32 ciphertextDigest,bytes32 authorizationCommitment,bytes32 receivableLinkCommitment,uint256 clientNonce)"

const (
	ReceivableLinkType                 = "MordantReceivableLink(address vault,uint32 policyVersion,bytes32 invoiceIdentifier,bytes32 salt)"
	SubmitterAuthorizationType         = "ConfidentialSubmitterAuthorization(bytes32 subjectCommitment,bytes32 role,address vault,bytes32 policyId,uint32 policyVersion,bytes32 keyId,uint64 validUntil,uint256 nonce)"
	ConfidentialPolicyResultCoreType   = "ConfidentialPolicyResultCore(uint256 chainId,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,bytes32 responsibleRole,uint64 cureDeadline,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment)"
	ConfidentialPolicyResultV3CoreType = "ConfidentialPolicyResultV3Core(uint256 chainId,address consumer,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment)"
	ProviderProofCommitmentType        = "ProviderProofCommitment(bytes32 resultCiphertextCommitment,bytes32 thresholdTranscriptCommitment,bytes32 thresholdSessionId,bytes32 thresholdKeyCommitment,bytes32 policyCircuitCommitment)"
)

type AuthorizationClaim struct {
	SubjectCommitment [32]byte
	Role              [32]byte
	Vault             [20]byte
	PolicyID          [32]byte
	PolicyVersion     uint32
	ValidUntil        uint64
	Nonce             Uint256
}

type PublicPolicyResultCore struct {
	ChainID                 Uint256
	Vault                   [20]byte
	PolicyID                [32]byte
	PolicyVersion           uint32
	InputCommitmentA        [32]byte
	InputCommitmentB        [32]byte
	ConflictConfirmed       bool
	ResponsibleRole         [32]byte
	CureDeadline            uint64
	Nonce                   Uint256
	ValidUntil              uint64
	ProviderProofCommitment [32]byte
}

// PublicPolicyResultV3Core is the parallel laboratory result with an intended consumer.
// It contains no role, deadline or economic consequence: those are derived by the consumer's
// on-chain policy after a true result is accepted.
type PublicPolicyResultV3Core struct {
	ChainID                 Uint256
	Consumer                [20]byte
	Vault                   [20]byte
	PolicyID                [32]byte
	PolicyVersion           uint32
	InputCommitmentA        [32]byte
	InputCommitmentB        [32]byte
	ConflictConfirmed       bool
	Nonce                   Uint256
	ValidUntil              uint64
	ProviderProofCommitment [32]byte
}

// ProviderProof binds the public result to the evaluated result ciphertext,
// one threshold session, its participating key epoch, the signed threshold
// transcript and the frozen policy circuit. It is evidence binding, not a
// proof that the off-chain computation was correct.
type ProviderProof struct {
	ResultCiphertextCommitment    [32]byte
	ThresholdTranscriptCommitment [32]byte
	ThresholdSessionID            [32]byte
	ThresholdKeyCommitment        [32]byte
	PolicyCircuitCommitment       [32]byte
}

// CanonicalInputCommitment computes the provider-independent Solidity value:
// keccak256(abi.encode(INPUT_TYPEHASH, ...)). Every ABI field is static and is
// therefore represented by one 32-byte word.
func (r *Runtime) CanonicalInputCommitment(pledge *CipherPledge, context InputCommitmentContext) ([32]byte, error) {
	var zero32 [32]byte
	if pledge == nil || context.ChainID == (Uint256{}) || context.Vault == ([20]byte{}) || context.PolicyID == zero32 || context.PolicyVersion != PolicyVersion || context.InputSlot > 1 {
		return zero32, ErrInvalidPlaintext
	}
	if pledge.KeyID != r.keyID || pledge.ParameterFingerprint != r.parameterFingerprint {
		return zero32, ErrWrongKeyID
	}
	if pledge.AuthorizationCommitment == zero32 {
		return zero32, ErrUnauthorizedIngress
	}
	if pledge.ReceivableIDBits == nil && pledge.ReceivableCommitment == zero32 {
		return zero32, fmt.Errorf("%w: missing public receivable link", ErrMalformedPledge)
	}
	if pledge.ReceivableIDBits != nil && pledge.ReceivableCommitment != zero32 {
		return zero32, fmt.Errorf("%w: full-FHE identity leaks public linkage", ErrMalformedPledge)
	}

	ciphertextDigest, err := cipherPledgeDigestBytes(pledge)
	if err != nil {
		return zero32, err
	}
	return canonicalInputCommitmentWords(
		context.ChainID,
		context.Vault,
		context.PolicyID,
		context.PolicyVersion,
		r.keyIDBytes,
		context.InputSlot,
		ciphertextDigest,
		pledge.AuthorizationCommitment,
		pledge.ReceivableCommitment,
		context.ClientNonce,
	), nil
}

func canonicalInputCommitmentWords(chainID Uint256, vault [20]byte, policyID [32]byte, policyVersion uint32, keyID [32]byte, inputSlot uint8, ciphertextDigest, authorizationCommitment, receivableLinkCommitment [32]byte, clientNonce Uint256) [32]byte {
	typeHash := legacyKeccak([]byte(ConfidentialPolicyInputType))
	encoded := make([]byte, 0, 11*32)
	encoded = append(encoded, typeHash[:]...)
	encoded = append(encoded, uint256Word(chainID)...)
	encoded = append(encoded, addressWord(vault)...)
	encoded = append(encoded, policyID[:]...)
	encoded = append(encoded, uint32Word(policyVersion)...)
	encoded = append(encoded, keyID[:]...)
	encoded = append(encoded, uint8Word(inputSlot)...)
	encoded = append(encoded, ciphertextDigest[:]...)
	encoded = append(encoded, authorizationCommitment[:]...)
	encoded = append(encoded, receivableLinkCommitment[:]...)
	encoded = append(encoded, uint256Word(clientNonce)...)
	return legacyKeccak(encoded)
}

// ReceivableLinkCommitment implements the public salted-link encoding from
// the shared provider-independent specification. InvoiceIdentifier and salt
// stay at the client boundary.
func ReceivableLinkCommitment(vault [20]byte, policyVersion uint32, invoiceIdentifier, salt [32]byte) [32]byte {
	typeHash := legacyKeccak([]byte(ReceivableLinkType))
	encoded := make([]byte, 0, 5*32)
	encoded = append(encoded, typeHash[:]...)
	encoded = append(encoded, addressWord(vault)...)
	encoded = append(encoded, uint32Word(policyVersion)...)
	encoded = append(encoded, invoiceIdentifier[:]...)
	encoded = append(encoded, salt[:]...)
	return legacyKeccak(encoded)
}

// SubmitterAuthorizationCommitment computes the authorization claim struct
// hash. GrantIngress is the trusted-gateway decision that this claim was
// issuer-signed, unrevoked and in scope; signature transport is out of scope
// for this local cryptographic harness.
func (r *Runtime) SubmitterAuthorizationCommitment(claim AuthorizationClaim) ([32]byte, error) {
	var zero [32]byte
	if claim.SubjectCommitment == zero || claim.Role == zero || claim.Vault == ([20]byte{}) || claim.PolicyID == zero || claim.PolicyVersion != PolicyVersion || claim.ValidUntil == 0 {
		return zero, ErrUnauthorizedIngress
	}
	typeHash := legacyKeccak([]byte(SubmitterAuthorizationType))
	encoded := make([]byte, 0, 9*32)
	encoded = append(encoded, typeHash[:]...)
	encoded = append(encoded, claim.SubjectCommitment[:]...)
	encoded = append(encoded, claim.Role[:]...)
	encoded = append(encoded, addressWord(claim.Vault)...)
	encoded = append(encoded, claim.PolicyID[:]...)
	encoded = append(encoded, uint32Word(claim.PolicyVersion)...)
	encoded = append(encoded, r.keyIDBytes[:]...)
	encoded = append(encoded, uint64Word(claim.ValidUntil)...)
	encoded = append(encoded, uint256Word(claim.Nonce)...)
	return legacyKeccak(encoded), nil
}

// ResultCommitment implements the exact shared ConfidentialPolicyResultCore
// Solidity ABI commitment consumed by the Monad adapter workflow.
func ResultCommitment(result PublicPolicyResultCore) ([32]byte, error) {
	var zero [32]byte
	if result.ChainID == (Uint256{}) || result.Vault == ([20]byte{}) || result.PolicyID == zero || result.PolicyVersion != PolicyVersion || result.InputCommitmentA == zero || result.InputCommitmentB == zero || result.ValidUntil == 0 || result.ProviderProofCommitment == zero {
		return zero, ErrInvalidPlaintext
	}
	if result.ConflictConfirmed {
		if result.ResponsibleRole == zero || result.CureDeadline == 0 {
			return zero, ErrInvalidPlaintext
		}
	} else if result.ResponsibleRole != zero || result.CureDeadline != 0 {
		return zero, ErrInvalidPlaintext
	}
	typeHash := legacyKeccak([]byte(ConfidentialPolicyResultCoreType))
	encoded := make([]byte, 0, 13*32)
	encoded = append(encoded, typeHash[:]...)
	encoded = append(encoded, uint256Word(result.ChainID)...)
	encoded = append(encoded, addressWord(result.Vault)...)
	encoded = append(encoded, result.PolicyID[:]...)
	encoded = append(encoded, uint32Word(result.PolicyVersion)...)
	encoded = append(encoded, result.InputCommitmentA[:]...)
	encoded = append(encoded, result.InputCommitmentB[:]...)
	encoded = append(encoded, boolWord(result.ConflictConfirmed)...)
	encoded = append(encoded, result.ResponsibleRole[:]...)
	encoded = append(encoded, uint64Word(result.CureDeadline)...)
	encoded = append(encoded, uint256Word(result.Nonce)...)
	encoded = append(encoded, uint64Word(result.ValidUntil)...)
	encoded = append(encoded, result.ProviderProofCommitment[:]...)
	return legacyKeccak(encoded), nil
}

// ResultCommitmentV3 implements the consumer-bound V3 ABI core commitment. It deliberately does
// not reuse the V2 type hash, so historical V2 attestations cannot cross into this laboratory path.
func ResultCommitmentV3(result PublicPolicyResultV3Core) ([32]byte, error) {
	var zero [32]byte
	if result.ChainID == (Uint256{}) || result.Consumer == ([20]byte{}) || result.Vault == ([20]byte{}) ||
		result.PolicyID == zero || result.PolicyVersion != PolicyVersion || result.InputCommitmentA == zero ||
		result.InputCommitmentB == zero || result.Nonce == (Uint256{}) || result.ValidUntil == 0 ||
		result.ProviderProofCommitment == zero {
		return zero, ErrInvalidPlaintext
	}
	typeHash := legacyKeccak([]byte(ConfidentialPolicyResultV3CoreType))
	encoded := make([]byte, 0, 12*32)
	encoded = append(encoded, typeHash[:]...)
	encoded = append(encoded, uint256Word(result.ChainID)...)
	encoded = append(encoded, addressWord(result.Consumer)...)
	encoded = append(encoded, addressWord(result.Vault)...)
	encoded = append(encoded, result.PolicyID[:]...)
	encoded = append(encoded, uint32Word(result.PolicyVersion)...)
	encoded = append(encoded, result.InputCommitmentA[:]...)
	encoded = append(encoded, result.InputCommitmentB[:]...)
	encoded = append(encoded, boolWord(result.ConflictConfirmed)...)
	encoded = append(encoded, uint256Word(result.Nonce)...)
	encoded = append(encoded, uint64Word(result.ValidUntil)...)
	encoded = append(encoded, result.ProviderProofCommitment[:]...)
	return legacyKeccak(encoded), nil
}

// ProviderProofCommitment implements the provider-neutral schema-v2 evidence
// commitment consumed by the EVM adapter and the shared JavaScript codec.
func ProviderProofCommitment(proof ProviderProof) ([32]byte, error) {
	var zero [32]byte
	if proof.ResultCiphertextCommitment == zero ||
		proof.ThresholdTranscriptCommitment == zero ||
		proof.ThresholdSessionID == zero ||
		proof.ThresholdKeyCommitment == zero ||
		proof.PolicyCircuitCommitment == zero {
		return zero, ErrInvalidPlaintext
	}
	typeHash := legacyKeccak([]byte(ProviderProofCommitmentType))
	encoded := make([]byte, 0, 6*32)
	encoded = append(encoded, typeHash[:]...)
	encoded = append(encoded, proof.ResultCiphertextCommitment[:]...)
	encoded = append(encoded, proof.ThresholdTranscriptCommitment[:]...)
	encoded = append(encoded, proof.ThresholdSessionID[:]...)
	encoded = append(encoded, proof.ThresholdKeyCommitment[:]...)
	encoded = append(encoded, proof.PolicyCircuitCommitment[:]...)
	return legacyKeccak(encoded), nil
}

func legacyKeccak(data []byte) [32]byte {
	var digest [32]byte
	hash := sha3.NewLegacyKeccak256()
	_, _ = hash.Write(data)
	copy(digest[:], hash.Sum(nil))
	return digest
}

func uint256Word(value Uint256) []byte {
	word := make([]byte, 32)
	for i, limb := range value {
		binary.BigEndian.PutUint64(word[i*8:(i+1)*8], limb)
	}
	return word
}

func addressWord(value [20]byte) []byte {
	word := make([]byte, 32)
	copy(word[12:], value[:])
	return word
}

func uint32Word(value uint32) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint32(word[28:], value)
	return word
}

func uint8Word(value uint8) []byte {
	word := make([]byte, 32)
	word[31] = value
	return word
}

func uint64Word(value uint64) []byte {
	word := make([]byte, 32)
	binary.BigEndian.PutUint64(word[24:], value)
	return word
}

func boolWord(value bool) []byte {
	word := make([]byte, 32)
	if value {
		word[31] = 1
	}
	return word
}
