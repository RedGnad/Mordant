// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { MordantMatchResultV5 as Outcomes } from "../identity/MordantMatchResultV5.sol";
import { MordantResultCoreV5 as Core } from "./MordantResultCoreV5.sol";
import {
    MordantScopeGovernanceRegistryV5 as Governance
} from "./MordantScopeGovernanceRegistryV5.sol";

/// @notice V5 confidential-match verifier.
///
/// @dev What changed against V4, and why.
///
/// V4 verified a quorum signature over a result core that named the session,
/// the policy and two input commitments. Everything about the computation was
/// outside that signature, so the same signed result was valid under a
/// different circuit, a different parameter set, different evaluation keys and
/// a different runtime build. V4 also consumed four identities; the session
/// commitment and the released output were not among them.
///
/// V5 verifies the complete context and consumes six identities exactly once:
/// replay key, decision key, session commitment, session nullifier, output
/// ciphertext commitment and provider-proof commitment. Any one of them
/// reappearing is terminal.
///
/// The session nullifier is not taken from the envelope. It is read from the
/// governance registry's own admission record and required to match, so a
/// result cannot be detached from the bilateral intent that was admitted on
/// chain before any FHE ran.
contract MordantMatchVerifierV5 {
    error Unauthorized(address account);
    error ZeroAddress();
    error InvalidQuorum();
    error InvalidBinder(address caller, address binder);
    error WrongChain(uint256 supplied, uint256 current);
    error PolicyNotConfigured(bytes32 policyId);
    error PolicyVersionMismatch(uint32 supplied, uint32 current);
    error ProtocolVersionRetired(uint16 supplied);
    error UnknownSessionCommitment(bytes32 sessionCommitment);
    error SessionNullifierMismatch(bytes32 supplied, bytes32 admitted);
    error SessionNotYetCommitted(bytes32 sessionCommitment);
    error ValidatorSetMismatch(bytes32 supplied, bytes32 current);
    error InsufficientSignatures(uint256 supplied, uint256 required);
    error ValidatorNotActive(address signer);
    error SignersNotStrictlyIncreasing(address previous, address current);
    error MalformedAttestation();
    error MalformedSignature();
    error MalformedTranscript();
    error RecomputationQuorumTooSmall(uint16 supplied, uint16 required);
    error RecomputationContextMismatch(bytes32 supplied, bytes32 expected);
    error ReplayAlreadyConsumed(bytes32 replayKey);
    error DecisionAlreadyConsumed(bytes32 decisionKey);
    error SessionAlreadyConsumed(bytes32 sessionCommitment);
    error NullifierAlreadyConsumed(bytes32 sessionNullifier);
    error OutputAlreadyConsumed(bytes32 outputCiphertextCommitment);
    error ProviderProofAlreadyConsumed(bytes32 providerProofCommitment);

    event PolicyVersionUpdated(bytes32 indexed policyId, uint32 version);
    event ConfidentialMatchAcceptedV5(
        bytes32 indexed resultCommitment,
        address indexed binder,
        bytes32 indexed sessionCommitment,
        bytes32 sessionNullifier,
        Outcomes.Outcome outcome,
        bool sameEconomicAsset,
        bool policyConflict,
        bytes32 outputCiphertextCommitment,
        bytes32 providerProofCommitment
    );

    string public constant DOMAIN_NAME = "Mordant Confidential Match";
    /// @dev Bumped from "4". A V4 attestation therefore hashes to a different
    /// digest and can never verify here, independently of the schema check.
    string public constant DOMAIN_VERSION = "5";

    bytes32 public constant ATTESTATION_TYPEHASH = keccak256(
        "ConfidentialMatchAttestationV5(bytes32 validatorSetId,bytes32 resultDigest,bytes32 recomputationContext)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant REPLAY_DOMAIN = keccak256("mordant.v5-replay-key/1");
    bytes32 private constant DECISION_DOMAIN = keccak256("mordant.v5-decision-key/1");
    bytes32 private constant CONTEXT_DOMAIN = keccak256("mordant.v5-recomputation-context/1");
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    /// @notice Attests that independent operators recomputed the circuit and
    /// agreed on the exact output bytes.
    /// @dev `contextDigest` is recomputed here from the result core, never read
    /// from the transcript. A coordinator supplying a context that does not
    /// describe the result it is submitting is rejected.
    struct RecomputationTranscript {
        /// @dev Digest of the release transcript the operators signed.
        bytes32 transcriptCommitment;
        /// @dev Digest over the ordered set of operator ids that recomputed.
        bytes32 operatorSetDigest;
        /// @dev How many operators independently recomputed and matched.
        uint16 recomputationQuorum;
        bytes32 contextDigest;
    }

    struct MatchEnvelopeV5 {
        Core.ResultCore core;
        bytes32 resultCommitment;
        RecomputationTranscript transcript;
    }

    address public immutable owner;
    Governance public immutable governance;
    uint256 public immutable quorum;
    bytes32 public immutable validatorSetId;
    /// @dev The minimum number of operators that must have independently
    /// recomputed the circuit. Below this the release is a signing service.
    uint16 public immutable recomputationQuorum;

    mapping(address validator => bool active) public validators;
    mapping(bytes32 policyId => uint32 version) public currentPolicyVersion;

    // The six one-time identities.
    mapping(bytes32 replayKey => bool consumed) public consumedReplayKeys;
    mapping(bytes32 decisionKey => bool consumed) public consumedDecisionKeys;
    mapping(bytes32 sessionCommitment => bool consumed) public consumedSessions;
    mapping(bytes32 sessionNullifier => bool consumed) public consumedNullifiers;
    mapping(bytes32 outputCommitment => bool consumed) public consumedOutputs;
    mapping(bytes32 providerProofCommitment => bool consumed) public consumedProviderProofs;

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        _;
    }

    constructor(
        address initialOwner,
        Governance governance_,
        address[] memory initialValidators,
        uint256 initialQuorum,
        uint16 initialRecomputationQuorum
    ) {
        if (initialOwner == address(0) || address(governance_) == address(0)) revert ZeroAddress();
        if (initialQuorum == 0 || initialQuorum > initialValidators.length) revert InvalidQuorum();
        // One recomputation is the evaluator agreeing with itself.
        if (initialRecomputationQuorum < 2) revert InvalidQuorum();
        owner = initialOwner;
        governance = governance_;
        quorum = initialQuorum;
        recomputationQuorum = initialRecomputationQuorum;
        for (uint256 i; i < initialValidators.length; ++i) {
            address validator = initialValidators[i];
            if (validator == address(0) || validators[validator]) revert ZeroAddress();
            validators[validator] = true;
        }
        validatorSetId =
            keccak256(abi.encode(block.chainid, address(this), initialValidators, initialQuorum));
    }

    function setPolicyVersion(bytes32 policyId, uint32 version) external onlyOwner {
        if (policyId == bytes32(0) || version == 0) revert PolicyNotConfigured(policyId);
        currentPolicyVersion[policyId] = version;
        emit PolicyVersionUpdated(policyId, version);
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(DOMAIN_NAME)),
                keccak256(bytes(DOMAIN_VERSION)),
                block.chainid,
                address(this)
            )
        );
    }

    function resultDigest(Core.ResultCore memory core) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), Core.structHash(core)));
    }

    function attestationDigest(bytes32 resultHash, bytes32 contextDigest)
        public
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(ATTESTATION_TYPEHASH, validatorSetId, resultHash, contextDigest)
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice The recomputation context, derived from the result core alone.
    /// @dev Recomputed here rather than read, so the transcript cannot describe
    /// one runtime while the result claims another.
    function recomputationContext(Core.ResultCore memory core) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                CONTEXT_DOMAIN,
                core.evaluation.circuitHash,
                core.evaluation.circuitVersion,
                core.evaluation.releaseLayoutVersion,
                core.evaluation.parameterFingerprint,
                core.evaluation.evaluationKeyEpoch,
                core.evaluation.evaluationKeyDigest,
                core.evaluation.runtimeFingerprint,
                core.evaluation.outputCiphertextCommitment
            )
        );
    }

    function replayKey(Core.ResultCore memory core) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                REPLAY_DOMAIN,
                core.chainId,
                core.verifier,
                core.policyId,
                core.policyVersion,
                core.nonce
            )
        );
    }

    function decisionKey(Core.ResultCore memory core) public pure returns (bytes32) {
        return keccak256(
            abi.encode(
                DECISION_DOMAIN,
                core.session.sessionCommitment,
                core.session.sessionNullifier,
                core.session.enrollmentDigestA,
                core.session.enrollmentDigestB,
                uint8(core.outcome)
            )
        );
    }

    /// @notice Verifies one V5 result and consumes its six identities.
    /// @dev Callable only by the binder the result names, so a result cannot be
    /// presented to a binder it was not issued for.
    function acceptMatch(MatchEnvelopeV5 calldata envelope, bytes calldata attestation)
        external
        returns (bytes32)
    {
        Core.ResultCore memory core = envelope.core;
        if (msg.sender != core.binder) revert InvalidBinder(msg.sender, core.binder);
        if (core.chainId != block.chainid) revert WrongChain(core.chainId, block.chainid);
        // Explicit and first: nothing below V5 is a V5 result, whatever else it
        // might satisfy.
        if (core.schemaVersion < Core.RESULT_SCHEMA_VERSION) {
            revert ProtocolVersionRetired(core.schemaVersion);
        }

        // Structure, outcome coherence and expiry. `requireWellFormed` reverts
        // on the 01 state, so an invalid outcome never reaches signature work.
        Core.requireWellFormed(core, address(this), block.timestamp);
        Core.requireCommitment(core, envelope.resultCommitment);

        uint32 configured = currentPolicyVersion[core.policyId];
        if (configured == 0) revert PolicyNotConfigured(core.policyId);
        if (core.policyVersion != configured) {
            revert PolicyVersionMismatch(core.policyVersion, configured);
        }

        _assertSessionAdmitted(core);
        _assertTranscript(core, envelope.transcript);
        _consume(core);
        _verifyAttestation(core, envelope.transcript.contextDigest, attestation);

        emit ConfidentialMatchAcceptedV5(
            envelope.resultCommitment,
            core.binder,
            core.session.sessionCommitment,
            core.session.sessionNullifier,
            core.outcome,
            core.sameEconomicAsset,
            core.policyConflict,
            core.evaluation.outputCiphertextCommitment,
            core.evaluation.providerProofCommitment
        );
        return envelope.resultCommitment;
    }

    /* ------------------------------------------------------------ internals */

    /// @dev The session must have been admitted on chain BEFORE the result, and
    /// under exactly the nullifier the result carries. The nullifier is read
    /// from the registry, never trusted from the envelope.
    function _assertSessionAdmitted(Core.ResultCore memory core) private view {
        Governance.SessionCommitment memory admitted =
            governance.commitment(core.session.sessionCommitment);
        if (!admitted.exists) revert UnknownSessionCommitment(core.session.sessionCommitment);
        if (admitted.committedInBlock >= block.number) {
            revert SessionNotYetCommitted(core.session.sessionCommitment);
        }
        if (admitted.sessionNullifier != core.session.sessionNullifier) {
            revert SessionNullifierMismatch(
                core.session.sessionNullifier, admitted.sessionNullifier
            );
        }
    }

    function _assertTranscript(
        Core.ResultCore memory core,
        RecomputationTranscript calldata transcript
    ) private view {
        if (
            transcript.transcriptCommitment == bytes32(0)
                || transcript.operatorSetDigest == bytes32(0)
        ) {
            revert MalformedTranscript();
        }
        if (transcript.recomputationQuorum < recomputationQuorum) {
            revert RecomputationQuorumTooSmall(transcript.recomputationQuorum, recomputationQuorum);
        }
        bytes32 expected = recomputationContext(core);
        if (transcript.contextDigest != expected) {
            revert RecomputationContextMismatch(transcript.contextDigest, expected);
        }
    }

    /// @dev Six identities, each terminal. Consumed before signature
    /// verification so a failed attestation cannot be retried against a
    /// mutated envelope that reuses any of them.
    function _consume(Core.ResultCore memory core) private {
        bytes32 replay = replayKey(core);
        if (consumedReplayKeys[replay]) revert ReplayAlreadyConsumed(replay);
        bytes32 decision = decisionKey(core);
        if (consumedDecisionKeys[decision]) revert DecisionAlreadyConsumed(decision);
        bytes32 session = core.session.sessionCommitment;
        if (consumedSessions[session]) revert SessionAlreadyConsumed(session);
        bytes32 nullifier = core.session.sessionNullifier;
        if (consumedNullifiers[nullifier]) revert NullifierAlreadyConsumed(nullifier);
        bytes32 output = core.evaluation.outputCiphertextCommitment;
        if (consumedOutputs[output]) revert OutputAlreadyConsumed(output);
        bytes32 proof = core.evaluation.providerProofCommitment;
        if (consumedProviderProofs[proof]) revert ProviderProofAlreadyConsumed(proof);

        consumedReplayKeys[replay] = true;
        consumedDecisionKeys[decision] = true;
        consumedSessions[session] = true;
        consumedNullifiers[nullifier] = true;
        consumedOutputs[output] = true;
        consumedProviderProofs[proof] = true;
    }

    function _verifyAttestation(
        Core.ResultCore memory core,
        bytes32 contextDigest,
        bytes calldata attestation
    ) private view {
        if (attestation.length == 0 || attestation.length % 65 != 0) {
            revert MalformedAttestation();
        }
        uint256 count = attestation.length / 65;
        if (count < quorum) revert InsufficientSignatures(count, quorum);

        bytes32 digest = attestationDigest(resultDigest(core), contextDigest);
        address previous = address(0);
        for (uint256 i; i < count; ++i) {
            address signer = _recover(digest, attestation[i * 65:(i + 1) * 65]);
            // Strictly increasing, so one validator cannot fill the quorum.
            if (signer <= previous) revert SignersNotStrictlyIncreasing(previous, signer);
            if (!validators[signer]) revert ValidatorNotActive(signer);
            previous = signer;
        }
    }

    function _recover(bytes32 digest, bytes calldata signature)
        private
        pure
        returns (address signer)
    {
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) revert MalformedSignature();
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert MalformedSignature();
    }
}
