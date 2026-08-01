// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { MordantAssetIdentity } from "../identity/MordantAssetIdentity.sol";
import { MordantIssuerRegistry } from "../identity/MordantIssuerRegistry.sol";
import { MordantSourceAttestation } from "../identity/MordantSourceAttestation.sol";

/// @notice Opaque admission for a non-vault receivable source.
///
/// @dev External audit finding C-01. The V4 registry took the entire
/// `SourceAssetAttestation` as an ABI argument to `register`. Omitting
/// `controller` from the emitted event protected nothing: transaction calldata
/// is public and permanent, so anyone could decode `attestation.controller` and
/// join it against the vault's public `originatorTreasury`. In the M-PRIV8 run
/// both sides used the same originator address, so the two participants were
/// linkable BEFORE the session was even committed.
///
/// RC2 publishes one salted commitment and nothing else. The controller, the
/// invoice root, the asset and terms commitments, the schemes, the epochs and
/// the issuer signature all live in the preimage, which is revealed exactly
/// once, at binding, by an authorized binder, after both parties have consented.
///
/// Public state before binding is exactly:
///
///   - the opaque source-record commitment;
///   - its timestamp and block number;
///   - the policy-authorized submitter address.
///
/// The submitter is deliberately not the source principal, and the reveal path
/// refuses a commitment whose submitter turns out to be the revealed controller.
contract MordantSourceCommitmentRegistry {
    error Unauthorized(address account);
    error InvalidConfiguration();
    error SubmitterNotAuthorized(address submitter);
    error SubmitterIsTheSourceController(address submitter);
    error CommitmentExists(bytes32 sourceRecordCommitment);
    error UnknownCommitment(bytes32 sourceRecordCommitment);
    error CommitmentAlreadyRevealed(bytes32 sourceRecordCommitment);
    error CommitmentMismatch(bytes32 recomputed, bytes32 supplied);
    error SchemeMismatch(uint16 supplied, uint16 expected);
    error AttestationExpired(uint64 validUntil, uint256 nowTimestamp);
    error NonceConsumed(bytes32 issuerKeyId, uint256 nonce);

    /// @dev The only pre-binding artifact. One hash, one timestamp, one block,
    /// one submitter. Deliberately carries no controller, no invoice root, no
    /// asset commitment and no issuer identity.
    event SourceCommitted(
        bytes32 indexed sourceRecordCommitment, uint64 committedAt, uint64 committedInBlock
    );
    /// @dev Emitted only at binding, when both parties have consented.
    event SourceRevealed(
        bytes32 indexed sourceRecordCommitment,
        bytes32 indexed issuerKeyId,
        bytes32 assetCommitment,
        address revealedBy
    );
    event SubmitterSet(address indexed submitter, bool allowed);
    event RevealerSet(address indexed revealer, bool allowed);

    bytes32 private constant COMMITMENT_DOMAIN = keccak256("mordant.source-record-commitment/1");

    struct SourceCommitment {
        uint64 committedAt;
        /// @dev Finding M-03: a timestamp cannot order two operations inside one
        /// block. The block number can, and the binder compares block numbers
        /// strictly.
        uint64 committedInBlock;
        address submitter;
        bool exists;
        bool revealed;
    }

    /// @notice What the binder learns at reveal. None of it was public before.
    struct RevealedSource {
        bytes32 sourceRecordCommitment;
        bytes32 assetCommitment;
        bytes32 initialTermsCommitment;
        bytes32 issuerKeyId;
        address issuerSigner;
        address controller;
        uint16 identitySchemeVersion;
        uint16 termsSchemeVersion;
        uint32 identityEpoch;
        uint64 committedAt;
        uint64 committedInBlock;
    }

    address public immutable governor;
    MordantIssuerRegistry public immutable issuerRegistry;

    mapping(bytes32 sourceRecordCommitment => SourceCommitment) private _commitments;
    mapping(address submitter => bool allowed) public authorizedSubmitter;
    mapping(address revealer => bool allowed) public authorizedRevealer;
    mapping(bytes32 issuerKeyId => mapping(uint256 nonce => bool used)) public consumedNonce;

    modifier onlyGovernor() {
        if (msg.sender != governor) revert Unauthorized(msg.sender);
        _;
    }

    constructor(address initialGovernor, MordantIssuerRegistry registry) {
        if (initialGovernor == address(0) || address(registry) == address(0)) {
            revert InvalidConfiguration();
        }
        governor = initialGovernor;
        issuerRegistry = registry;
    }

    /// @notice A policy-authorized, non-principal submitter.
    /// @dev "Policy-authorized", not "neutral": this is a governor allowlist, not
    /// a cryptographic guarantee. Its only structural effect is that the sender
    /// of a source commitment is not, by policy and by the reveal-time check,
    /// the controller of the source it publishes.
    function setAuthorizedSubmitter(address submitter, bool allowed) external onlyGovernor {
        if (submitter == address(0)) revert InvalidConfiguration();
        authorizedSubmitter[submitter] = allowed;
        emit SubmitterSet(submitter, allowed);
    }

    function setAuthorizedRevealer(address revealer, bool allowed) external onlyGovernor {
        if (revealer == address(0)) revert InvalidConfiguration();
        authorizedRevealer[revealer] = allowed;
        emit RevealerSet(revealer, allowed);
    }

    /// @notice Recomputed from the preimage. Never asserted by a caller.
    /// @dev Binds the complete attestation, the issuer's signature over it, and
    /// a high-entropy salt, all scoped to this chain and this registry.
    function sourceCommitmentOf(
        MordantSourceAttestation.SourceAssetAttestation calldata attestation,
        bytes calldata issuerSignature,
        bytes32 salt
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                COMMITMENT_DOMAIN,
                block.chainid,
                address(this),
                MordantSourceAttestation.structHash(attestation),
                keccak256(issuerSignature),
                salt
            )
        );
    }

    /// @notice Publishes one opaque source-record commitment.
    /// @dev The submitter receives only this 32-byte value. It learns nothing
    /// about the source it is publishing.
    function commitSource(bytes32 sourceRecordCommitment) external {
        if (!authorizedSubmitter[msg.sender]) revert SubmitterNotAuthorized(msg.sender);
        if (sourceRecordCommitment == bytes32(0)) revert InvalidConfiguration();
        if (_commitments[sourceRecordCommitment].exists) {
            revert CommitmentExists(sourceRecordCommitment);
        }
        _commitments[sourceRecordCommitment] = SourceCommitment({
            committedAt: uint64(block.timestamp),
            committedInBlock: uint64(block.number),
            submitter: msg.sender,
            exists: true,
            revealed: false
        });
        emit SourceCommitted(sourceRecordCommitment, uint64(block.timestamp), uint64(block.number));
    }

    /// @notice When a source commitment was published, or zero if it never was.
    /// @dev The only public fact about a source before binding. It answers "did
    /// this exist beforehand" without answering "whose".
    function committedInBlock(bytes32 sourceRecordCommitment) external view returns (uint64) {
        return _commitments[sourceRecordCommitment].committedInBlock;
    }

    function commitment(bytes32 sourceRecordCommitment)
        external
        view
        returns (SourceCommitment memory)
    {
        return _commitments[sourceRecordCommitment];
    }

    /// @notice Opens one committed source, once, for an authorized binder.
    /// @dev Reveal is the moment the source principal becomes public, so it must
    /// not be something a bystander can force.
    function revealSource(
        MordantSourceAttestation.SourceAssetAttestation calldata attestation,
        bytes calldata issuerSignature,
        bytes32 salt
    ) external returns (RevealedSource memory revealed) {
        if (!authorizedRevealer[msg.sender]) revert Unauthorized(msg.sender);

        bytes32 key = sourceCommitmentOf(attestation, issuerSignature, salt);
        SourceCommitment storage stored = _commitments[key];
        if (!stored.exists) revert UnknownCommitment(key);
        if (stored.revealed) revert CommitmentAlreadyRevealed(key);

        // Finding L-03: V4 signed `termsSchemeVersion` but never checked or
        // stored it, so two sources could be compared while interpreting their
        // terms commitments under incompatible schemes.
        if (attestation.identitySchemeVersion != MordantAssetIdentity.IDENTITY_SCHEME_VERSION) {
            revert SchemeMismatch(
                attestation.identitySchemeVersion, MordantAssetIdentity.IDENTITY_SCHEME_VERSION
            );
        }
        if (attestation.termsSchemeVersion != MordantAssetIdentity.TERMS_SCHEME_VERSION) {
            revert SchemeMismatch(
                attestation.termsSchemeVersion, MordantAssetIdentity.TERMS_SCHEME_VERSION
            );
        }
        if (block.timestamp > attestation.validUntil) {
            revert AttestationExpired(attestation.validUntil, block.timestamp);
        }
        if (consumedNonce[attestation.issuerKeyId][attestation.nonce]) {
            revert NonceConsumed(attestation.issuerKeyId, attestation.nonce);
        }

        (address signer,) =
            MordantSourceAttestation.recover(attestation, issuerSignature, address(this));
        issuerRegistry.requireAuthorized(attestation.issuerKeyId, signer, attestation.identityEpoch);

        // The allowlist is a policy statement, not proof. A submitter that turns
        // out to be the revealed controller was never a non-principal relayer.
        if (stored.submitter == attestation.controller) {
            revert SubmitterIsTheSourceController(stored.submitter);
        }

        stored.revealed = true;
        consumedNonce[attestation.issuerKeyId][attestation.nonce] = true;

        revealed = RevealedSource({
            sourceRecordCommitment: key,
            assetCommitment: attestation.assetCommitment,
            initialTermsCommitment: attestation.initialTermsCommitment,
            issuerKeyId: attestation.issuerKeyId,
            issuerSigner: signer,
            controller: attestation.controller,
            identitySchemeVersion: attestation.identitySchemeVersion,
            termsSchemeVersion: attestation.termsSchemeVersion,
            identityEpoch: attestation.identityEpoch,
            committedAt: stored.committedAt,
            committedInBlock: stored.committedInBlock
        });
        emit SourceRevealed(key, attestation.issuerKeyId, attestation.assetCommitment, msg.sender);
    }
}
