// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { MordantMatchResultV5 as Outcomes } from "../identity/MordantMatchResultV5.sol";

/// @notice The canonical V5 confidential-match result core.
///
/// @dev Everything the quorum attests is inside one commitment. The V4 core
/// bound the session, the policy and the two input commitments, and left the
/// entire evaluation context outside the signature: the circuit that ran, the
/// parameters it ran under, the evaluation keys, the runtime build, the
/// ciphertexts actually evaluated and the canonical serialized output were all
/// unbound. A result was therefore transferable between circuits, builds and
/// key epochs without invalidating a single signature.
///
/// V5 binds the complete context. The field order below is normative: it is the
/// EIP-712 field order, the commitment preimage order and the order every
/// off-chain producer must use.
///
/// Two independent released bits, never one derived twice:
///
///     sameEconomicAsset = identityEqual
///     policyConflict    = identityEqual AND currencyEqual AND overlap
///                         AND exclusiveA AND exclusiveB
library MordantResultCoreV5 {
    error EmptyField();
    error NotDistinct();
    error WrongSchema(uint16 supplied, uint16 expected);
    error WrongChain(uint256 supplied, uint256 current);
    error WrongVerifier(address supplied, address current);
    error ResultExpired(uint64 expiry, uint256 currentTime);
    error InvalidResultCommitment(bytes32 supplied, bytes32 expected);

    uint16 internal constant RESULT_SCHEMA_VERSION = 5;
    /// @dev The layout of the released plaintext vector: slot 0 carries the
    /// Boolean and every other slot is zero. Bound so a future layout cannot be
    /// read under this one's rules.
    uint16 internal constant RELEASE_LAYOUT_VERSION = 1;
    uint32 internal constant CIRCUIT_VERSION = 5;

    /// @dev Flat by design. EIP-712 nested structs would add four more type
    /// strings to freeze and four more places for a producer to diverge.
    bytes32 internal constant RESULT_CORE_TYPEHASH = keccak256(
        "ConfidentialMatchResultV5Core(uint16 schemaVersion,uint256 chainId,address verifier,address binder,bytes32 policyId,uint32 policyVersion,bytes32 sessionCommitment,bytes32 sessionNullifier,bytes32 governanceContext,bytes32 sourceRecordCommitmentA,bytes32 sourceRecordCommitmentB,bytes32 enrollmentDigestA,bytes32 enrollmentDigestB,bytes32 ciphertextDigestA,bytes32 ciphertextDigestB,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool sameEconomicAsset,bool policyConflict,uint8 outcome,bytes32 outputCiphertextCommitment,bytes32 circuitHash,uint32 circuitVersion,uint16 releaseLayoutVersion,bytes32 parameterFingerprint,uint32 evaluationKeyEpoch,bytes32 evaluationKeyDigest,bytes32 runtimeFingerprint,bytes32 providerProofCommitment,uint256 nonce,uint64 expiry)"
    );

    bytes32 private constant COMMITMENT_DOMAIN = keccak256("mordant.result-core-commitment/5");

    /// @notice Who the two sides are, cryptographically, for exactly one session.
    struct SessionBinding {
        bytes32 sessionCommitment;
        bytes32 sessionNullifier;
        /// @dev Commits to the governance registry, both authorization records
        /// and the commitment block. One value so the core stays flat.
        bytes32 governanceContext;
        bytes32 sourceRecordCommitmentA;
        bytes32 sourceRecordCommitmentB;
        bytes32 enrollmentDigestA;
        bytes32 enrollmentDigestB;
    }

    /// @notice What actually ran, and under what.
    /// @dev This whole group was outside the V4 signature.
    struct EvaluationBinding {
        bytes32 ciphertextDigestA;
        bytes32 ciphertextDigestB;
        bytes32 inputCommitmentA;
        bytes32 inputCommitmentB;
        /// @dev Commitment over the canonical serialization of BOTH released
        /// output ciphertexts, in fixed order. This is the value every operator
        /// recomputed locally and compared byte for byte.
        bytes32 outputCiphertextCommitment;
        bytes32 circuitHash;
        uint32 circuitVersion;
        uint16 releaseLayoutVersion;
        bytes32 parameterFingerprint;
        uint32 evaluationKeyEpoch;
        bytes32 evaluationKeyDigest;
        /// @dev Lattigo version, Go version, GOOS/GOARCH, parameters, circuit
        /// build hash, serialization version, evaluation-key digest and release
        /// layout. A dependency upgrade changes this value, which is what makes
        /// silently mixing builds impossible rather than merely discouraged.
        bytes32 runtimeFingerprint;
        bytes32 providerProofCommitment;
    }

    struct ResultCore {
        uint16 schemaVersion;
        uint256 chainId;
        address verifier;
        address binder;
        bytes32 policyId;
        uint32 policyVersion;
        SessionBinding session;
        EvaluationBinding evaluation;
        bool sameEconomicAsset;
        bool policyConflict;
        Outcomes.Outcome outcome;
        uint256 nonce;
        uint64 expiry;
    }

    /// @notice The EIP-712 struct hash. Field order is normative.
    function structHash(ResultCore memory core) internal pure returns (bytes32) {
        // Split only to keep the stack shallow. For static types the
        // concatenation of these encodings is byte-identical to one abi.encode
        // over the whole flat field list, which is what EIP-712 requires.
        bytes memory head = abi.encode(
            RESULT_CORE_TYPEHASH,
            core.schemaVersion,
            core.chainId,
            core.verifier,
            core.binder,
            core.policyId,
            core.policyVersion
        );
        bytes memory session = abi.encode(
            core.session.sessionCommitment,
            core.session.sessionNullifier,
            core.session.governanceContext,
            core.session.sourceRecordCommitmentA,
            core.session.sourceRecordCommitmentB,
            core.session.enrollmentDigestA,
            core.session.enrollmentDigestB
        );
        bytes memory inputs = abi.encode(
            core.evaluation.ciphertextDigestA,
            core.evaluation.ciphertextDigestB,
            core.evaluation.inputCommitmentA,
            core.evaluation.inputCommitmentB,
            core.sameEconomicAsset,
            core.policyConflict,
            uint8(core.outcome)
        );
        bytes memory context = abi.encode(
            core.evaluation.outputCiphertextCommitment,
            core.evaluation.circuitHash,
            core.evaluation.circuitVersion,
            core.evaluation.releaseLayoutVersion,
            core.evaluation.parameterFingerprint,
            core.evaluation.evaluationKeyEpoch,
            core.evaluation.evaluationKeyDigest,
            core.evaluation.runtimeFingerprint,
            core.evaluation.providerProofCommitment,
            core.nonce,
            core.expiry
        );
        return keccak256(bytes.concat(head, session, inputs, context));
    }

    /// @notice The canonical result commitment.
    /// @dev Deliberately a different preimage from the EIP-712 struct hash, so
    /// a signature over one can never be replayed as the other.
    function commitmentOf(ResultCore memory core) internal pure returns (bytes32) {
        return keccak256(abi.encode(COMMITMENT_DOMAIN, structHash(core)));
    }

    /// @notice Every structural rule the core must satisfy, in one place.
    /// @dev Called by the verifier before any signature work, so a malformed
    /// core costs a revert rather than a quorum verification.
    function requireWellFormed(
        ResultCore memory core,
        address expectedVerifier,
        uint256 currentTime
    ) internal pure {
        if (core.schemaVersion != RESULT_SCHEMA_VERSION) {
            revert WrongSchema(core.schemaVersion, RESULT_SCHEMA_VERSION);
        }
        if (core.evaluation.circuitVersion != CIRCUIT_VERSION) {
            revert WrongSchema(uint16(core.evaluation.circuitVersion), uint16(CIRCUIT_VERSION));
        }
        if (core.evaluation.releaseLayoutVersion != RELEASE_LAYOUT_VERSION) {
            revert WrongSchema(core.evaluation.releaseLayoutVersion, RELEASE_LAYOUT_VERSION);
        }
        if (core.verifier != expectedVerifier) {
            revert WrongVerifier(core.verifier, expectedVerifier);
        }
        if (core.binder == address(0) || core.verifier == address(0)) revert EmptyField();
        if (core.expiry == 0 || currentTime > core.expiry) {
            revert ResultExpired(core.expiry, currentTime);
        }
        if (core.policyId == bytes32(0) || core.nonce == 0) revert EmptyField();

        SessionBinding memory session = core.session;
        if (
            session.sessionCommitment == bytes32(0) || session.sessionNullifier == bytes32(0)
                || session.governanceContext == bytes32(0)
                || session.sourceRecordCommitmentA == bytes32(0)
                || session.sourceRecordCommitmentB == bytes32(0)
                || session.enrollmentDigestA == bytes32(0)
                || session.enrollmentDigestB == bytes32(0)
        ) revert EmptyField();
        // Two sides, or it is not a bilateral result.
        if (
            session.sourceRecordCommitmentA == session.sourceRecordCommitmentB
                || session.enrollmentDigestA == session.enrollmentDigestB
        ) revert NotDistinct();

        EvaluationBinding memory evaluation = core.evaluation;
        if (
            evaluation.ciphertextDigestA == bytes32(0) || evaluation.ciphertextDigestB == bytes32(0)
                || evaluation.inputCommitmentA == bytes32(0)
                || evaluation.inputCommitmentB == bytes32(0)
                || evaluation.outputCiphertextCommitment == bytes32(0)
                || evaluation.circuitHash == bytes32(0)
                || evaluation.parameterFingerprint == bytes32(0)
                || evaluation.evaluationKeyDigest == bytes32(0)
                || evaluation.runtimeFingerprint == bytes32(0)
                || evaluation.providerProofCommitment == bytes32(0)
                || evaluation.evaluationKeyEpoch == 0
        ) revert EmptyField();
        if (
            evaluation.ciphertextDigestA == evaluation.ciphertextDigestB
                || evaluation.inputCommitmentA == evaluation.inputCommitmentB
        ) revert NotDistinct();

        // The declared outcome must be exactly what the two released bits imply.
        // `outcomeOf` reverts on the 01 state, so an invalid result cannot reach
        // any later boundary.
        Outcomes.requireOutcomeMatchesBits(
            core.outcome, core.sameEconomicAsset, core.policyConflict
        );
    }

    /// @notice Asserts the supplied commitment is the one this core produces.
    function requireCommitment(ResultCore memory core, bytes32 supplied) internal pure {
        bytes32 expected = commitmentOf(core);
        if (supplied != expected) revert InvalidResultCommitment(supplied, expected);
    }
}
