// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";

import {MordantIssuerRegistry} from "./MordantIssuerRegistry.sol";

/// @notice Pre-commitments that authorize an exact matching session.
/// @dev Owner decision 10: after a tolerant candidate signal, an authorized
/// source must pre-commit an exact identity or an equivalence before a new exact
/// session may begin. This registry is where that pre-commitment lives.
///
/// It is append-only and one-shot per session, so the sequence is forced:
///
///   tolerant candidate signal (private, non-binding)
///     -> human reconciliation off-chain
///     -> issuer pre-commits the corrected strict identity or an equivalence
///     -> a NEW exact session runs and may bind
///
/// The tolerant result itself is never referenced again. There is no function
/// here that upgrades it, and a session id may be pre-committed only once.
contract MordantSessionPrecommitRegistry {
    error InvalidPrecommitment();
    error SessionAlreadyPrecommitted(bytes32 sessionId);
    error NonceConsumed(bytes32 issuerKeyId, uint256 nonce);
    error MalformedSignature();
    error CandidateSessionCannotBePrecommitted(bytes32 sessionId);

    event ExactSessionPrecommitted(
        bytes32 indexed sessionId,
        bytes32 indexed issuerKeyId,
        bytes32 strictAssetCommitment,
        bytes32 equivalenceOf,
        bytes32 supersedesCandidateSession
    );

    string internal constant DOMAIN_NAME = "Mordant Exact Session Precommitment";
    string internal constant DOMAIN_VERSION = "1";

    bytes32 public constant PRECOMMIT_TYPEHASH = keccak256(
        "ExactSessionPrecommitment(uint256 chainId,address registry,bytes32 sessionId,bytes32 strictAssetCommitment,bytes32 equivalenceOf,bytes32 supersedesCandidateSession,bytes32 issuerKeyId,uint32 identityEpoch,uint64 validUntil,uint256 nonce)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct ExactSessionPrecommitment {
        uint256 chainId;
        address registry;
        bytes32 sessionId; // the exact session this authorizes
        bytes32 strictAssetCommitment; // the anchor's binding commitment
        /// @dev Non-zero when the issuer asserts that its corrected strict
        /// identity is equivalent to a previously recorded one.
        bytes32 equivalenceOf;
        /// @dev The candidate session that prompted reconciliation, recorded for
        /// audit. It is never a source of authority.
        bytes32 supersedesCandidateSession;
        bytes32 issuerKeyId;
        uint32 identityEpoch;
        uint64 validUntil;
        uint256 nonce;
    }

    struct Precommitment {
        bytes32 strictAssetCommitment;
        bytes32 issuerKeyId;
        bytes32 supersedesCandidateSession;
        uint64 recordedAt;
        bool recorded;
    }

    MordantIssuerRegistry public immutable issuerRegistry;

    mapping(bytes32 sessionId => Precommitment record) public precommitments;
    mapping(bytes32 sessionId => bool candidate) public candidateSessions;
    mapping(bytes32 issuerKeyId => mapping(uint256 nonce => bool used)) public consumedNonce;

    constructor(MordantIssuerRegistry registry) {
        if (address(registry) == address(0)) revert InvalidPrecommitment();
        issuerRegistry = registry;
    }

    /// @notice Marks a session as having run the tolerant path.
    /// @dev A candidate session can never later be pre-committed as exact, which
    /// is what stops a tolerant result being upgraded in place.
    function markCandidateSession(bytes32 sessionId) external {
        if (sessionId == bytes32(0)) revert InvalidPrecommitment();
        if (precommitments[sessionId].recorded) revert SessionAlreadyPrecommitted(sessionId);
        candidateSessions[sessionId] = true;
    }

    function precommitExactSession(
        ExactSessionPrecommitment calldata precommitment,
        bytes calldata signature
    ) external {
        if (
            precommitment.chainId != block.chainid || precommitment.registry != address(this)
                || precommitment.sessionId == bytes32(0)
                || precommitment.strictAssetCommitment == bytes32(0)
                || precommitment.issuerKeyId == bytes32(0) || precommitment.identityEpoch == 0
                || precommitment.nonce == 0
        ) revert InvalidPrecommitment();
        if (block.timestamp > precommitment.validUntil) revert InvalidPrecommitment();
        // The session that produced the tolerant signal is not the session that
        // may bind. They must be different sessions.
        if (candidateSessions[precommitment.sessionId]) {
            revert CandidateSessionCannotBePrecommitted(precommitment.sessionId);
        }
        if (
            precommitment.supersedesCandidateSession != bytes32(0)
                && precommitment.supersedesCandidateSession == precommitment.sessionId
        ) revert CandidateSessionCannotBePrecommitted(precommitment.sessionId);
        if (precommitments[precommitment.sessionId].recorded) {
            revert SessionAlreadyPrecommitted(precommitment.sessionId);
        }
        if (consumedNonce[precommitment.issuerKeyId][precommitment.nonce]) {
            revert NonceConsumed(precommitment.issuerKeyId, precommitment.nonce);
        }

        address signer = _recover(_digest(precommitment), signature);
        issuerRegistry.requireAuthorized(
            precommitment.issuerKeyId, signer, precommitment.identityEpoch
        );

        consumedNonce[precommitment.issuerKeyId][precommitment.nonce] = true;
        precommitments[precommitment.sessionId] = Precommitment({
            strictAssetCommitment: precommitment.strictAssetCommitment,
            issuerKeyId: precommitment.issuerKeyId,
            supersedesCandidateSession: precommitment.supersedesCandidateSession,
            recordedAt: uint64(block.timestamp),
            recorded: true
        });

        emit ExactSessionPrecommitted(
            precommitment.sessionId,
            precommitment.issuerKeyId,
            precommitment.strictAssetCommitment,
            precommitment.equivalenceOf,
            precommitment.supersedesCandidateSession
        );
    }

    /// @notice The answer a binder must consult. It is never a caller assertion.
    function isSessionPrecommitted(bytes32 sessionId, bytes32 strictAssetCommitment)
        external
        view
        returns (bool)
    {
        Precommitment memory record = precommitments[sessionId];
        return record.recorded && record.strictAssetCommitment == strictAssetCommitment
            && !candidateSessions[sessionId];
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

    function digestOf(ExactSessionPrecommitment calldata precommitment)
        external
        view
        returns (bytes32)
    {
        return _digest(precommitment);
    }

    function _digest(ExactSessionPrecommitment calldata precommitment)
        private
        view
        returns (bytes32)
    {
        bytes32 structHash = keccak256(
            abi.encodePacked(
                abi.encode(
                    PRECOMMIT_TYPEHASH,
                    precommitment.chainId,
                    precommitment.registry,
                    precommitment.sessionId,
                    precommitment.strictAssetCommitment,
                    precommitment.equivalenceOf
                ),
                abi.encode(
                    precommitment.supersedesCandidateSession,
                    precommitment.issuerKeyId,
                    precommitment.identityEpoch,
                    precommitment.validUntil,
                    precommitment.nonce
                )
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    function _recover(bytes32 hash, bytes calldata signature) private pure returns (address) {
        if (signature.length != 65) revert MalformedSignature();
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) revert MalformedSignature();
        address signer = ECDSA.recover(hash, v, r, s);
        if (signer == address(0)) revert MalformedSignature();
        return signer;
    }
}
