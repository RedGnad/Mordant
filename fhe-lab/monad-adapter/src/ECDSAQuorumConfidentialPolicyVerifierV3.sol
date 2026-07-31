// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    ConfidentialPolicyResultV3,
    IConfidentialPolicyVerifierV3
} from "./interfaces/IConfidentialPolicyVerifierV3.sol";

/// @notice Laboratory V3 verifier for a consumer-bound, quorum-attested confidential result.
/// @dev This contract authenticates endorsed commitments only. It does not prove FHE correctness,
/// source truth, transaction privacy or private settlement. V2 remains unchanged beside it.
contract ECDSAQuorumConfidentialPolicyVerifierV3 is IConfidentialPolicyVerifierV3 {
    error Unauthorized(address account);
    error ZeroAddress();
    error InvalidQuorum();
    error InvalidConsumer(address caller, address consumer);
    error WrongChain(uint256 supplied, uint256 current);
    error InvalidVault();
    error PolicyNotConfigured(address vault, bytes32 policyId);
    error PolicyVersionMismatch(uint32 supplied, uint32 current);
    error ResultExpired(uint64 validUntil, uint256 currentTime);
    error InvalidProviderProofCommitment();
    error InvalidResultCommitment(bytes32 supplied, bytes32 expected);
    error ValidatorSetMismatch(bytes32 supplied, bytes32 current);
    error InsufficientSignatures(uint256 supplied, uint256 required);
    error ValidatorNotActive(address signer);
    error SignersNotStrictlyIncreasing(address previous, address current);
    error MalformedAttestation();
    error MalformedSignature();
    error ReplayAlreadyConsumed(bytes32 replayKey);
    error DecisionAlreadyConsumed(bytes32 decisionKey);
    error ProviderProofAlreadyConsumed(bytes32 providerProofCommitment);

    event PolicyVersionUpdated(address indexed vault, bytes32 indexed policyId, uint32 version);
    event ConfidentialPolicyResultV3Accepted(
        bytes32 indexed resultCommitment,
        address indexed consumer,
        address indexed vault,
        bytes32 policyId,
        uint32 policyVersion,
        uint256 nonce,
        bool conflictConfirmed,
        bytes32 providerProofCommitment
    );

    string public constant DOMAIN_NAME = "Mordant Confidential Policy";
    string public constant DOMAIN_VERSION = "3";
    bytes32 public constant RESULT_CORE_TYPEHASH = keccak256(
        "ConfidentialPolicyResultV3Core(uint256 chainId,address consumer,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment)"
    );
    bytes32 public constant RESULT_TYPEHASH = keccak256(
        "ConfidentialPolicyResultV3(uint256 chainId,address consumer,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,uint256 nonce,uint64 validUntil,bytes32 providerProofCommitment,bytes32 resultCommitment)"
    );
    bytes32 public constant ATTESTATION_TYPEHASH =
        keccak256("ConfidentialPolicyAttestation(bytes32 validatorSetId,bytes32 resultDigest)");
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public immutable owner;
    uint256 public immutable quorum;
    bytes32 public immutable validatorSetId;
    mapping(address validator => bool active) public validators;
    mapping(address vault => mapping(bytes32 policyId => uint32 version)) public
        currentPolicyVersion;
    mapping(bytes32 replayKey => bool consumed) public consumedReplayKeys;
    mapping(bytes32 decisionKey => bool consumed) public consumedDecisionKeys;
    mapping(bytes32 providerProofCommitment => bool consumed) public
        consumedProviderProofCommitments;

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

    function setPolicyVersion(address vault, bytes32 policyId, uint32 version) external onlyOwner {
        if (vault == address(0) || version == 0) revert ZeroAddress();
        currentPolicyVersion[vault][policyId] = version;
        emit PolicyVersionUpdated(vault, policyId, version);
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

    function resultCoreCommitment(ConfidentialPolicyResultV3 calldata result)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                RESULT_CORE_TYPEHASH,
                result.chainId,
                result.consumer,
                result.vault,
                result.policyId,
                result.policyVersion,
                result.inputCommitmentA,
                result.inputCommitmentB,
                result.conflictConfirmed,
                result.nonce,
                result.validUntil,
                result.providerProofCommitment
            )
        );
    }

    function resultDigest(ConfidentialPolicyResultV3 calldata result)
        public
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encode(
                RESULT_TYPEHASH,
                result.chainId,
                result.consumer,
                result.vault,
                result.policyId,
                result.policyVersion,
                result.inputCommitmentA,
                result.inputCommitmentB,
                result.conflictConfirmed,
                result.nonce,
                result.validUntil,
                result.providerProofCommitment,
                result.resultCommitment
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
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

    function replayKey(ConfidentialPolicyResultV3 calldata result) public pure returns (bytes32) {
        return keccak256(
            abi.encode(result.chainId, result.consumer, result.vault, result.policyId, result.nonce)
        );
    }

    function decisionKey(ConfidentialPolicyResultV3 calldata result) public pure returns (bytes32) {
        (bytes32 first, bytes32 second) = result.inputCommitmentA < result.inputCommitmentB
            ? (result.inputCommitmentA, result.inputCommitmentB)
            : (result.inputCommitmentB, result.inputCommitmentA);
        return keccak256(
            abi.encode(
                result.chainId,
                result.consumer,
                result.vault,
                result.policyId,
                result.policyVersion,
                first,
                second
            )
        );
    }

    function acceptResult(ConfidentialPolicyResultV3 calldata result, bytes calldata attestation)
        external
        override
        returns (bytes32 key)
    {
        if (msg.sender != result.consumer) revert InvalidConsumer(msg.sender, result.consumer);
        if (result.chainId != block.chainid) revert WrongChain(result.chainId, block.chainid);
        if (result.vault == address(0)) revert InvalidVault();
        if (result.providerProofCommitment == bytes32(0)) revert InvalidProviderProofCommitment();
        bytes32 expected = resultCoreCommitment(result);
        if (expected != result.resultCommitment) {
            revert InvalidResultCommitment(result.resultCommitment, expected);
        }
        uint32 configured = currentPolicyVersion[result.vault][result.policyId];
        if (configured == 0) revert PolicyNotConfigured(result.vault, result.policyId);
        if (configured != result.policyVersion) {
            revert PolicyVersionMismatch(result.policyVersion, configured);
        }
        if (block.timestamp > result.validUntil) {
            revert ResultExpired(result.validUntil, block.timestamp);
        }
        key = replayKey(result);
        if (consumedReplayKeys[key]) revert ReplayAlreadyConsumed(key);
        bytes32 canonicalDecisionKey = decisionKey(result);
        if (consumedDecisionKeys[canonicalDecisionKey]) {
            revert DecisionAlreadyConsumed(canonicalDecisionKey);
        }
        if (consumedProviderProofCommitments[result.providerProofCommitment]) {
            revert ProviderProofAlreadyConsumed(result.providerProofCommitment);
        }
        _verifyAttestation(result, attestation);
        consumedReplayKeys[key] = true;
        consumedDecisionKeys[canonicalDecisionKey] = true;
        consumedProviderProofCommitments[result.providerProofCommitment] = true;
        emit ConfidentialPolicyResultV3Accepted(
            result.resultCommitment,
            result.consumer,
            result.vault,
            result.policyId,
            result.policyVersion,
            result.nonce,
            result.conflictConfirmed,
            result.providerProofCommitment
        );
    }

    function _verifyAttestation(
        ConfidentialPolicyResultV3 calldata result,
        bytes calldata attestation
    ) private view {
        (bytes32 suppliedSetId, bytes[] memory signatures) =
            abi.decode(attestation, (bytes32, bytes[]));
        if (keccak256(attestation) != keccak256(abi.encode(suppliedSetId, signatures))) {
            revert MalformedAttestation();
        }
        if (suppliedSetId != validatorSetId) {
            revert ValidatorSetMismatch(suppliedSetId, validatorSetId);
        }
        if (signatures.length < quorum) revert InsufficientSignatures(signatures.length, quorum);
        bytes32 digest = attestationDigest(suppliedSetId, resultDigest(result));
        address previous;
        for (uint256 i; i < signatures.length; ++i) {
            address signer = _recover(digest, signatures[i]);
            if (!validators[signer]) revert ValidatorNotActive(signer);
            if (signer <= previous) revert SignersNotStrictlyIncreasing(previous, signer);
            previous = signer;
        }
    }

    function _recover(bytes32 digest, bytes memory signature)
        private
        pure
        returns (address signer)
    {
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
