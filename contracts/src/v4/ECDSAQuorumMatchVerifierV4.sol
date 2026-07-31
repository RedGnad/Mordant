// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MordantMatchResult as Match} from "../identity/MordantMatchResult.sol";

/// @notice V4 quorum verifier for confidential match results.
/// @dev Parallel to the deployed V3 verifier, which is untouched. The V3 verifier
/// keys policy configuration by vault; V4 cannot, because a pre-binding result
/// names no vault. It keys on policy and on an allowlist of authorized scopes.
///
/// The verifier authenticates who endorsed a result. It does not prove the FHE
/// computation was correct, and nothing here should be read as doing so.
contract ECDSAQuorumMatchVerifierV4 {
    error Unauthorized(address account);
    error ZeroAddress();
    error InvalidQuorum();
    error InvalidBinder(address caller, address binder);
    error WrongChain(uint256 supplied, uint256 current);
    error PolicyNotConfigured(bytes32 policyId);
    error PolicyVersionMismatch(uint32 supplied, uint32 current);
    error ScopeNotAuthorized(bytes32 scopeCommitment);
    error ResultExpired(uint64 validUntil, uint256 currentTime);
    error InvalidResultCommitment(bytes32 supplied, bytes32 expected);
    error ValidatorSetMismatch(bytes32 supplied, bytes32 current);
    error InsufficientSignatures(uint256 supplied, uint256 required);
    error ValidatorNotActive(address signer);
    error SignersNotStrictlyIncreasing(address previous, address current);
    error MalformedAttestation();
    error MalformedSignature();
    error ReplayAlreadyConsumed(bytes32 replayKey);
    error DecisionAlreadyConsumed(bytes32 decisionKey);
    error MatchAlreadyConsumed(bytes32 matchCommitment);
    error ProviderProofAlreadyConsumed(bytes32 providerProofCommitment);

    event PolicyVersionUpdated(bytes32 indexed policyId, uint32 version);
    event ScopeAuthorized(bytes32 indexed scopeCommitment, bool authorized);
    event ConfidentialMatchAccepted(
        bytes32 indexed resultCommitment,
        address indexed binder,
        bytes32 indexed policyId,
        bytes32 sessionId,
        bytes32 matchCommitment,
        bool conflictConfirmed,
        bytes32 providerProofCommitment
    );

    string public constant DOMAIN_NAME = "Mordant Confidential Match";
    string public constant DOMAIN_VERSION = "4";

    bytes32 public constant RESULT_CORE_TYPEHASH = keccak256(
        "ConfidentialMatchResultV4Core(uint256 chainId,address binder,bytes32 policyId,uint32 policyVersion,bytes32 sessionId,bytes32 scopeCommitmentA,bytes32 scopeCommitmentB,bytes32 inputCommitmentA,bytes32 inputCommitmentB,uint8 outcome,bool conflictConfirmed,bytes32 matchCommitment,uint8 anchorCount,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment)"
    );
    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256("ConfidentialMatchAttestation(bytes32 validatorSetId,bytes32 resultDigest)");
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    /// @notice The public envelope the quorum signs. It names no vault and no
    /// receivable identifier: both would defeat the mode.
    struct MatchEnvelope {
        uint256 chainId;
        address binder;
        bytes32 policyId;
        uint32 policyVersion;
        uint256 nonce;
        uint64 validUntil;
        bytes32 resultCommitment;
        Match.ConfidentialMatchResultV4 result;
    }

    address public immutable owner;
    uint256 public immutable quorum;
    bytes32 public immutable validatorSetId;

    mapping(address validator => bool active) public validators;
    mapping(bytes32 policyId => uint32 version) public currentPolicyVersion;
    mapping(bytes32 scopeCommitment => bool authorized) public authorizedScope;
    mapping(bytes32 replayKey => bool consumed) public consumedReplayKeys;
    mapping(bytes32 decisionKey => bool consumed) public consumedDecisionKeys;
    mapping(bytes32 matchCommitment => bool consumed) public consumedMatchCommitments;
    mapping(bytes32 providerProofCommitment => bool consumed) public consumedProviderProofCommitments;

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        _;
    }

    constructor(address initialOwner, address[] memory initialValidators, uint256 initialQuorum) {
        if (initialOwner == address(0)) revert ZeroAddress();
        if (initialQuorum == 0 || initialQuorum > initialValidators.length) revert InvalidQuorum();
        owner = initialOwner;
        quorum = initialQuorum;
        for (uint256 i; i < initialValidators.length; ++i) {
            address validator = initialValidators[i];
            if (validator == address(0) || validators[validator]) revert ZeroAddress();
            validators[validator] = true;
        }
        validatorSetId =
            keccak256(abi.encode(block.chainid, address(this), initialValidators, initialQuorum));
    }

    function setPolicyVersion(bytes32 policyId, uint32 version) external onlyOwner {
        if (policyId == bytes32(0) || version == 0) revert ZeroAddress();
        currentPolicyVersion[policyId] = version;
        emit PolicyVersionUpdated(policyId, version);
    }

    function setScopeAuthorized(bytes32 scopeCommitment, bool authorized) external onlyOwner {
        if (scopeCommitment == bytes32(0)) revert ZeroAddress();
        authorizedScope[scopeCommitment] = authorized;
        emit ScopeAuthorized(scopeCommitment, authorized);
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

    /// @notice Recomputed on-chain. A result commitment is never asserted.
    function resultCoreCommitment(MatchEnvelope calldata envelope) public pure returns (bytes32) {
        bytes32 scope = keccak256(
            abi.encode(
                envelope.result.sessionId,
                envelope.result.scopeCommitmentA,
                envelope.result.scopeCommitmentB,
                envelope.result.inputCommitmentA,
                envelope.result.inputCommitmentB
            )
        );
        bytes32 verdict = keccak256(
            abi.encode(
                uint8(envelope.result.outcome),
                envelope.result.conflictConfirmed,
                envelope.result.matchCommitment,
                envelope.result.anchorCount,
                envelope.result.providerProofCommitment
            )
        );
        return keccak256(
            abi.encode(
                RESULT_CORE_TYPEHASH,
                envelope.chainId,
                envelope.binder,
                envelope.policyId,
                envelope.policyVersion,
                envelope.nonce,
                envelope.validUntil,
                scope,
                verdict
            )
        );
    }

    function resultDigest(MatchEnvelope calldata envelope) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked("\x19\x01", domainSeparator(), resultCoreCommitment(envelope))
        );
    }

    function attestationDigest(bytes32 setId, bytes32 resultHash) public view returns (bytes32) {
        return keccak256(
            abi.encodePacked(
                "\x19\x01",
                domainSeparator(),
                keccak256(abi.encode(ATTESTATION_TYPEHASH, setId, resultHash))
            )
        );
    }

    function replayKey(MatchEnvelope calldata envelope) public pure returns (bytes32) {
        return keccak256(
            abi.encode(envelope.chainId, envelope.binder, envelope.policyId, envelope.nonce)
        );
    }

    function decisionKey(MatchEnvelope calldata envelope) public pure returns (bytes32) {
        (bytes32 first, bytes32 second) =
            envelope.result.inputCommitmentA < envelope.result.inputCommitmentB
            ? (envelope.result.inputCommitmentA, envelope.result.inputCommitmentB)
            : (envelope.result.inputCommitmentB, envelope.result.inputCommitmentA);
        return keccak256(
            abi.encode(
                envelope.chainId, envelope.binder, envelope.policyId, envelope.policyVersion, first, second
            )
        );
    }

    /// @notice Accepts one confidential match result on behalf of its binder.
    /// @dev Only an EXACT_MATCH may be accepted. A candidate result is refused
    /// by the result invariants before any signature is checked, so the tolerant
    /// path can never consume a one-time identity or reach the chain.
    function acceptMatch(MatchEnvelope calldata envelope, bytes calldata attestation)
        external
        returns (bytes32 key)
    {
        if (msg.sender != envelope.binder) revert InvalidBinder(msg.sender, envelope.binder);
        if (envelope.chainId != block.chainid) revert WrongChain(envelope.chainId, block.chainid);

        // The result must be a coherent, bindable EXACT_MATCH. `requireBindable`
        // is given `true` for the pre-commitment because the binder is the party
        // that consults the pre-commit registry; it is re-checked there.
        Match.requireBindable(envelope.result, true);

        bytes32 expected = resultCoreCommitment(envelope);
        if (expected != envelope.resultCommitment) {
            revert InvalidResultCommitment(envelope.resultCommitment, expected);
        }
        uint32 configured = currentPolicyVersion[envelope.policyId];
        if (configured == 0) revert PolicyNotConfigured(envelope.policyId);
        if (configured != envelope.policyVersion) {
            revert PolicyVersionMismatch(envelope.policyVersion, configured);
        }
        if (!authorizedScope[envelope.result.scopeCommitmentA]) {
            revert ScopeNotAuthorized(envelope.result.scopeCommitmentA);
        }
        if (!authorizedScope[envelope.result.scopeCommitmentB]) {
            revert ScopeNotAuthorized(envelope.result.scopeCommitmentB);
        }
        if (block.timestamp > envelope.validUntil) {
            revert ResultExpired(envelope.validUntil, block.timestamp);
        }

        key = replayKey(envelope);
        if (consumedReplayKeys[key]) revert ReplayAlreadyConsumed(key);
        bytes32 canonicalDecisionKey = decisionKey(envelope);
        if (consumedDecisionKeys[canonicalDecisionKey]) {
            revert DecisionAlreadyConsumed(canonicalDecisionKey);
        }
        // One positive match binds once. This is what stops a single match being
        // bound to two different anchors.
        if (consumedMatchCommitments[envelope.result.matchCommitment]) {
            revert MatchAlreadyConsumed(envelope.result.matchCommitment);
        }
        if (consumedProviderProofCommitments[envelope.result.providerProofCommitment]) {
            revert ProviderProofAlreadyConsumed(envelope.result.providerProofCommitment);
        }

        _verifyAttestation(envelope, attestation);

        consumedReplayKeys[key] = true;
        consumedDecisionKeys[canonicalDecisionKey] = true;
        consumedMatchCommitments[envelope.result.matchCommitment] = true;
        consumedProviderProofCommitments[envelope.result.providerProofCommitment] = true;

        emit ConfidentialMatchAccepted(
            envelope.resultCommitment,
            envelope.binder,
            envelope.policyId,
            envelope.result.sessionId,
            envelope.result.matchCommitment,
            envelope.result.conflictConfirmed,
            envelope.result.providerProofCommitment
        );
    }

    function _verifyAttestation(MatchEnvelope calldata envelope, bytes calldata attestation)
        private
        view
    {
        (bytes32 suppliedSetId, bytes[] memory signatures) =
            abi.decode(attestation, (bytes32, bytes[]));
        if (keccak256(attestation) != keccak256(abi.encode(suppliedSetId, signatures))) {
            revert MalformedAttestation();
        }
        if (suppliedSetId != validatorSetId) {
            revert ValidatorSetMismatch(suppliedSetId, validatorSetId);
        }
        if (signatures.length < quorum) revert InsufficientSignatures(signatures.length, quorum);
        bytes32 digest = attestationDigest(suppliedSetId, resultDigest(envelope));
        address previous;
        for (uint256 i; i < signatures.length; ++i) {
            address signer = _recover(digest, signatures[i]);
            if (!validators[signer]) revert ValidatorNotActive(signer);
            if (signer <= previous) revert SignersNotStrictlyIncreasing(previous, signer);
            previous = signer;
        }
    }

    function _recover(bytes32 digest, bytes memory signature) private pure returns (address signer) {
        if (signature.length != 65) revert MalformedSignature();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly ("memory-safe") {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) revert MalformedSignature();
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert MalformedSignature();
    }
}
