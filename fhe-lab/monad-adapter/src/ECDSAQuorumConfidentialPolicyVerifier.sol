// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    ConfidentialPolicyResult,
    IConfidentialPolicyVerifier
} from "./interfaces/IConfidentialPolicyVerifier.sol";

/// @notice Minimal provider-neutral ECDSA quorum for committed confidential-policy results.
/// @dev This verifies attestations over commitments. It neither verifies the private computation nor
///      modifies a Mordant vault.
contract ECDSAQuorumConfidentialPolicyVerifier is IConfidentialPolicyVerifier {
    error Unauthorized(address account);
    error ZeroAddress();
    error EmptyValidatorSet();
    error InvalidQuorum(uint256 requested, uint256 validatorCount);
    error QuorumUnchanged(uint256 quorum);
    error ValidatorStateUnchanged(address validator, bool active);
    error QuorumWouldBecomeImpossible(uint256 quorum, uint256 remainingValidators);
    error PolicyNotConfigured(address vault, bytes32 policyId);
    error PolicyVersionMismatch(uint32 supplied, uint32 current);
    error PolicyVersionNotIncreasing(uint32 supplied, uint32 latest);
    error WrongChain(uint256 supplied, uint256 current);
    error InvalidVault();
    error ResultExpired(uint64 validUntil, uint256 currentTime);
    error InvalidResultCommitment(bytes32 supplied, bytes32 expected);
    error InvalidNegativeResult(bytes32 responsibleRole, uint64 cureDeadline);
    error InvalidPositiveResult(bytes32 responsibleRole, uint64 cureDeadline);
    error ValidatorSetMismatch(bytes32 supplied, bytes32 current);
    error ReplayAlreadyConsumed(bytes32 replayKey);
    error DecisionAlreadyConsumed(bytes32 decisionKey);
    error InsufficientSignatures(uint256 supplied, uint256 required);
    error MalformedAttestation();
    error MalformedSignature();
    error ValidatorNotActive(address signer);
    error SignersNotStrictlyIncreasing(address previous, address current);

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);
    event ValidatorUpdated(address indexed validator, bool active);
    event QuorumUpdated(uint256 previousQuorum, uint256 newQuorum);
    event ValidatorSetRotated(
        bytes32 indexed previousValidatorSetId,
        bytes32 indexed newValidatorSetId,
        uint64 epoch,
        uint256 quorum,
        uint256 validatorCount
    );
    event PolicyVersionUpdated(
        address indexed vault, bytes32 indexed policyId, uint32 previousVersion, uint32 newVersion
    );
    event ConfidentialPolicyResultAccepted(
        bytes32 indexed resultCommitment,
        bytes32 indexed policyId,
        address indexed vault,
        uint32 policyVersion,
        uint256 nonce,
        bool conflictConfirmed
    );

    string public constant DOMAIN_NAME = "Mordant Confidential Policy";
    string public constant DOMAIN_VERSION = "1";

    bytes32 public constant CONFIDENTIAL_POLICY_RESULT_CORE_TYPEHASH = keccak256(
        "ConfidentialPolicyResultCore(uint256 chainId,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,bytes32 responsibleRole,uint64 cureDeadline,uint256 nonce,uint64 validUntil)"
    );
    bytes32 public constant CONFIDENTIAL_POLICY_RESULT_TYPEHASH = keccak256(
        "ConfidentialPolicyResult(uint256 chainId,address vault,bytes32 policyId,uint32 policyVersion,bytes32 inputCommitmentA,bytes32 inputCommitmentB,bool conflictConfirmed,bytes32 responsibleRole,uint64 cureDeadline,uint256 nonce,uint64 validUntil,bytes32 resultCommitment)"
    );
    bytes32 public constant CONFIDENTIAL_POLICY_ATTESTATION_TYPEHASH =
        keccak256("ConfidentialPolicyAttestation(bytes32 validatorSetId,bytes32 resultDigest)");

    bytes32 private constant _EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    bytes32 private constant _NAME_HASH = keccak256(bytes(DOMAIN_NAME));
    bytes32 private constant _VERSION_HASH = keccak256(bytes(DOMAIN_VERSION));
    uint256 private constant _SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    address public owner;
    uint256 public quorum;
    uint256 public validatorCount;
    uint64 public validatorSetEpoch;
    bytes32 public validatorSetId;

    mapping(address validator => bool active) public validators;
    mapping(address vault => mapping(bytes32 policyId => uint32 version)) public
        currentPolicyVersion;
    mapping(address vault => mapping(bytes32 policyId => uint32 version)) public
        latestPolicyVersion;
    mapping(bytes32 replayKey => bool consumed) public consumedReplayKeys;
    mapping(bytes32 decisionKey => bool consumed) public consumedDecisionKeys;

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        _;
    }

    constructor(address initialOwner, address[] memory initialValidators, uint256 initialQuorum) {
        if (initialOwner == address(0)) revert ZeroAddress();
        if (initialValidators.length == 0) revert EmptyValidatorSet();

        owner = initialOwner;
        emit OwnershipTransferred(address(0), initialOwner);

        for (uint256 index; index < initialValidators.length; ++index) {
            address validator = initialValidators[index];
            if (validator == address(0)) revert ZeroAddress();
            if (validators[validator]) revert ValidatorStateUnchanged(validator, true);
            validators[validator] = true;
            ++validatorCount;
            emit ValidatorUpdated(validator, true);
        }
        if (initialQuorum == 0 || initialQuorum > validatorCount) {
            revert InvalidQuorum(initialQuorum, validatorCount);
        }
        quorum = initialQuorum;
        emit QuorumUpdated(0, initialQuorum);
        _rotateValidatorSet(keccak256(abi.encode("INITIAL", initialValidators, initialQuorum)));
    }

    function transferOwnership(address newOwner) external onlyOwner {
        if (newOwner == address(0)) revert ZeroAddress();
        address previousOwner = owner;
        owner = newOwner;
        emit OwnershipTransferred(previousOwner, newOwner);
    }

    /// @notice Add or revoke a validator and rotate the attestation epoch.
    function setValidator(address validator, bool active) external onlyOwner {
        if (validator == address(0)) revert ZeroAddress();
        if (validators[validator] == active) revert ValidatorStateUnchanged(validator, active);

        if (active) {
            validators[validator] = true;
            ++validatorCount;
        } else {
            uint256 remaining = validatorCount - 1;
            if (remaining < quorum) revert QuorumWouldBecomeImpossible(quorum, remaining);
            validators[validator] = false;
            validatorCount = remaining;
        }
        emit ValidatorUpdated(validator, active);
        _rotateValidatorSet(keccak256(abi.encode("VALIDATOR", validator, active)));
    }

    /// @notice Change quorum and rotate the attestation epoch.
    function setQuorum(uint256 newQuorum) external onlyOwner {
        if (newQuorum == 0 || newQuorum > validatorCount) {
            revert InvalidQuorum(newQuorum, validatorCount);
        }
        uint256 previousQuorum = quorum;
        if (newQuorum == previousQuorum) revert QuorumUnchanged(newQuorum);
        quorum = newQuorum;
        emit QuorumUpdated(previousQuorum, newQuorum);
        _rotateValidatorSet(keccak256(abi.encode("QUORUM", previousQuorum, newQuorum)));
    }

    /// @notice Configure the only policy version accepted for a vault and policy identifier.
    /// @dev Version zero disables the policy.
    function setPolicyVersion(address vault, bytes32 policyId, uint32 newVersion)
        external
        onlyOwner
    {
        if (vault == address(0)) revert ZeroAddress();
        uint32 previousVersion = currentPolicyVersion[vault][policyId];
        uint32 latestVersion = latestPolicyVersion[vault][policyId];
        if (newVersion != 0) {
            if (newVersion <= latestVersion) {
                revert PolicyVersionNotIncreasing(newVersion, latestVersion);
            }
            latestPolicyVersion[vault][policyId] = newVersion;
        }
        currentPolicyVersion[vault][policyId] = newVersion;
        emit PolicyVersionUpdated(vault, policyId, previousVersion, newVersion);
    }

    function domainSeparator() public view returns (bytes32) {
        return keccak256(
            abi.encode(
                _EIP712_DOMAIN_TYPEHASH, _NAME_HASH, _VERSION_HASH, block.chainid, address(this)
            )
        );
    }

    /// @notice Canonical commitment to every result field except `resultCommitment` itself.
    function resultCoreCommitment(ConfidentialPolicyResult calldata result)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                CONFIDENTIAL_POLICY_RESULT_CORE_TYPEHASH,
                result.chainId,
                result.vault,
                result.policyId,
                result.policyVersion,
                result.inputCommitmentA,
                result.inputCommitmentB,
                result.conflictConfirmed,
                result.responsibleRole,
                result.cureDeadline,
                result.nonce,
                result.validUntil
            )
        );
    }

    function resultStructHash(ConfidentialPolicyResult calldata result)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                CONFIDENTIAL_POLICY_RESULT_TYPEHASH,
                result.chainId,
                result.vault,
                result.policyId,
                result.policyVersion,
                result.inputCommitmentA,
                result.inputCommitmentB,
                result.conflictConfirmed,
                result.responsibleRole,
                result.cureDeadline,
                result.nonce,
                result.validUntil,
                result.resultCommitment
            )
        );
    }

    /// @notice EIP-712 result digest nested into `ConfidentialPolicyAttestation`.
    function resultDigest(ConfidentialPolicyResult calldata result) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), resultStructHash(result)));
    }

    function attestationDigest(bytes32 setId, bytes32 resultHash) public view returns (bytes32) {
        bytes32 structHash =
            keccak256(abi.encode(CONFIDENTIAL_POLICY_ATTESTATION_TYPEHASH, setId, resultHash));
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function replayKey(ConfidentialPolicyResult calldata result) public pure returns (bytes32) {
        return keccak256(abi.encode(result.chainId, result.vault, result.policyId, result.nonce));
    }

    /// @notice Canonical decision identity independent of input order, nonce, and output.
    function decisionKey(ConfidentialPolicyResult calldata result) public pure returns (bytes32) {
        (bytes32 firstCommitment, bytes32 secondCommitment) = result.inputCommitmentA
            < result.inputCommitmentB
            ? (result.inputCommitmentA, result.inputCommitmentB)
            : (result.inputCommitmentB, result.inputCommitmentA);
        return keccak256(
            abi.encode(
                result.chainId,
                result.vault,
                result.policyId,
                result.policyVersion,
                firstCommitment,
                secondCommitment
            )
        );
    }

    function verifyResult(ConfidentialPolicyResult calldata result, bytes calldata attestation)
        external
        view
        override
        returns (bool)
    {
        _verifyResult(result, attestation);
        return true;
    }

    function acceptResult(ConfidentialPolicyResult calldata result, bytes calldata attestation)
        external
        returns (bytes32 acceptedReplayKey)
    {
        bytes32 key = _verifyResult(result, attestation);
        bytes32 canonicalDecisionKey = decisionKey(result);

        consumedReplayKeys[key] = true;
        consumedDecisionKeys[canonicalDecisionKey] = true;
        emit ConfidentialPolicyResultAccepted(
            result.resultCommitment,
            result.policyId,
            result.vault,
            result.policyVersion,
            result.nonce,
            result.conflictConfirmed
        );
        return key;
    }

    function _verifyResult(ConfidentialPolicyResult calldata result, bytes calldata attestation)
        private
        view
        returns (bytes32 key)
    {
        bytes32 suppliedSetId;
        bytes[] memory signatures;
        (suppliedSetId, signatures) = abi.decode(attestation, (bytes32, bytes[]));
        if (keccak256(attestation) != keccak256(abi.encode(suppliedSetId, signatures))) {
            revert MalformedAttestation();
        }

        bytes32 expectedCommitment = resultCoreCommitment(result);
        if (result.resultCommitment != expectedCommitment) {
            revert InvalidResultCommitment(result.resultCommitment, expectedCommitment);
        }
        if (result.conflictConfirmed) {
            if (result.responsibleRole == bytes32(0) || result.cureDeadline == 0) {
                revert InvalidPositiveResult(result.responsibleRole, result.cureDeadline);
            }
        } else if (result.responsibleRole != bytes32(0) || result.cureDeadline != 0) {
            revert InvalidNegativeResult(result.responsibleRole, result.cureDeadline);
        }

        if (result.chainId != block.chainid) {
            revert WrongChain(result.chainId, block.chainid);
        }
        if (result.vault == address(0)) revert InvalidVault();

        uint32 configuredVersion = currentPolicyVersion[result.vault][result.policyId];
        if (configuredVersion == 0) revert PolicyNotConfigured(result.vault, result.policyId);
        if (result.policyVersion != configuredVersion) {
            revert PolicyVersionMismatch(result.policyVersion, configuredVersion);
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
        if (suppliedSetId != validatorSetId) {
            revert ValidatorSetMismatch(suppliedSetId, validatorSetId);
        }
        if (signatures.length < quorum) {
            revert InsufficientSignatures(signatures.length, quorum);
        }

        bytes32 resultHash = resultDigest(result);
        bytes32 signedDigest = attestationDigest(suppliedSetId, resultHash);
        address previousSigner;
        for (uint256 index; index < signatures.length; ++index) {
            address signer = _recover(signedDigest, signatures[index]);
            if (!validators[signer]) revert ValidatorNotActive(signer);
            if (signer <= previousSigner) {
                revert SignersNotStrictlyIncreasing(previousSigner, signer);
            }
            previousSigner = signer;
        }
    }

    function _rotateValidatorSet(bytes32 mutationHash) private {
        bytes32 previousSetId = validatorSetId;
        ++validatorSetEpoch;
        validatorSetId = keccak256(
            abi.encode(
                block.chainid,
                address(this),
                validatorSetEpoch,
                previousSetId,
                quorum,
                validatorCount,
                mutationHash
            )
        );
        emit ValidatorSetRotated(
            previousSetId, validatorSetId, validatorSetEpoch, quorum, validatorCount
        );
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

        if (uint256(s) > _SECP256K1_HALF_ORDER || (v != 27 && v != 28)) {
            revert MalformedSignature();
        }
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert MalformedSignature();
    }
}
