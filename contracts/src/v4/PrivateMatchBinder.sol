// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MordantAssetIdentity} from "../identity/MordantAssetIdentity.sol";
import {MordantMatchResult as Match} from "../identity/MordantMatchResult.sol";
import {MordantSessionPrecommitRegistry} from "../identity/MordantSessionPrecommitRegistry.sol";
import {MordantSourceIdentityRegistry} from "../identity/MordantSourceIdentityRegistry.sol";
import {ECDSAQuorumMatchVerifierV4} from "./ECDSAQuorumMatchVerifierV4.sol";
import {IAnchoredReceivable} from "./IAnchoredReceivable.sol";

/// @notice Binds a confidential exact match to a real tokenized receivable and
/// opens one non-economic recourse record.
///
/// @dev What this contract does NOT do is the point of it.
///
/// It never learns an `assetId`. The only identity value that reaches the chain
/// is the anchor's own salted `assetCommitment`, which the anchor already
/// published at creation, and the session's input commitments. Nothing here
/// opens either one.
///
/// It is non-economic. It holds no balance, has no token interface, and reaches
/// the receivable only through a view-only interface, so a confirmed conflict
/// produces a record and nothing else. Whether that record has consequences is a
/// question for the anchor's own protection machinery, not for this contract.
///
/// The binding sequence is fixed and each step is an independent authority:
///
///   1. the anchor published its identity commitment when it was created
///   2. an authorized issuer pre-committed THIS session against THAT commitment
///   3. the session ran and returned a coherent EXACT_MATCH
///   4. both scope controllers consented to disclose it
///   5. a 2-of-3 validator quorum endorsed the result
///
/// No single party holds two of these, and dropping any one of them fails closed.
contract PrivateMatchBinder {
    error Unauthorized(address account);
    error ZeroAddress();
    error InvalidConfiguration();
    error EnvelopeNotForThisBinder(address supplied);
    error UnexpectedPolicy(bytes32 policyId, uint32 policyVersion);
    error AnchorNotDeployed(address anchor);
    error AnchorSchemeMismatch(uint16 supplied, uint16 expected);
    error AnchorCommitmentNotInSession(bytes32 anchorCommitment);
    error SelfMatch(bytes32 inputCommitment);
    error SessionNotPrecommittedForAnchor(bytes32 sessionId, bytes32 anchorCommitment);
    error PrecommitmentIssuerMismatch(bytes32 recorded, bytes32 anchorIssuer);
    error CounterpartyCommitmentMismatch(bytes32 observed, bytes32 expected);
    error CounterpartyNotAnchored();
    error AnchorCountMismatch(uint8 supplied);
    error AnchorNotOutstanding(uint8 receivableState);
    error AnchorProtectionInactive(uint8 protectionState);
    error AnchorHasNoUnits();
    error SessionAlreadyBound(bytes32 sessionId);
    error ScopeControllerUnknown(bytes32 scopeCommitment);
    error DisclosureConsentMissing(bytes32 scopeCommitment);
    error DisclosureConsentExpired(bytes32 scopeCommitment, uint64 validUntil);
    error MalformedSignature();

    event ScopeControllerSet(bytes32 indexed scopeCommitment, address indexed controller);
    event PrivateMatchBound(
        bytes32 indexed sessionId,
        address indexed anchor,
        bytes32 indexed matchCommitment,
        bytes32 anchorCommitment,
        bytes32 counterpartyCommitment,
        bytes32 policyId,
        uint32 policyVersion,
        bool conflictConfirmed,
        uint64 cureDeadline
    );

    /// @dev Mirrored from MordantInvoiceVault. Only these two states make a
    /// recourse record meaningful.
    uint8 public constant RECEIVABLE_OUTSTANDING = 1;
    uint8 public constant PROTECTION_ACTIVE = 1;
    /// @dev An exact match is between exactly two anchored submissions.
    uint8 public constant EXPECTED_ANCHOR_COUNT = 2;

    string public constant DOMAIN_NAME = "Mordant Private Match Binder";
    string public constant DOMAIN_VERSION = "1";

    bytes32 public constant DISCLOSURE_CONSENT_TYPEHASH = keccak256(
        "DisclosureConsent(uint256 chainId,address binder,bytes32 sessionId,bytes32 resultCommitment,bytes32 scopeCommitment,address anchor,uint64 validUntil)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    /// @notice How the counterparty side of the session is anchored.
    /// @dev Both sides must have committed to their identity before the session,
    /// so the counterparty is either a registered non-vault source or another
    /// vault carrying an identity anchor. There is no third option, and there is
    /// no path that accepts an unanchored counterparty.
    enum CounterpartyKind {
        None,
        RegisteredSource,
        VaultAnchor
    }

    struct Counterparty {
        CounterpartyKind kind;
        /// @dev Source attestation digest, for a registered non-vault source.
        bytes32 anchorId;
        /// @dev Vault address, for an on-chain counterparty anchor.
        address vault;
    }

    /// @notice One side's consent to disclose that this session matched.
    /// @dev A confirmed conflict is publishable only if both scope controllers
    /// sign for it. Without this a single platform could publish that a
    /// counterparty is double-financing, which is exactly the disclosure the
    /// private mode exists to prevent.
    struct DisclosureConsent {
        bytes32 scopeCommitment;
        uint64 validUntil;
        bytes signature;
    }

    struct RecourseRecord {
        bytes32 sessionId;
        bytes32 resultCommitment;
        bytes32 matchCommitment;
        bytes32 anchorCommitment;
        bytes32 counterpartyCommitment;
        bytes32 providerProofCommitment;
        address anchor;
        bytes32 policyId;
        uint32 policyVersion;
        bool conflictConfirmed;
        uint64 boundAt;
        uint64 cureDeadline;
        bool open;
    }

    address public immutable owner;
    ECDSAQuorumMatchVerifierV4 public immutable verifier;
    MordantSessionPrecommitRegistry public immutable precommitRegistry;
    MordantSourceIdentityRegistry public immutable sourceRegistry;
    bytes32 public immutable policyId;
    uint32 public immutable policyVersion;
    bytes32 public immutable responsibleRole;
    uint64 public immutable curePeriod;
    bytes32 public immutable consequenceId;

    mapping(bytes32 scopeCommitment => address controller) public scopeController;
    mapping(bytes32 sessionId => RecourseRecord record) public recourses;

    modifier onlyOwner() {
        if (msg.sender != owner) revert Unauthorized(msg.sender);
        _;
    }

    constructor(
        address initialOwner,
        ECDSAQuorumMatchVerifierV4 verifier_,
        MordantSessionPrecommitRegistry precommitRegistry_,
        MordantSourceIdentityRegistry sourceRegistry_,
        bytes32 policyId_,
        uint32 policyVersion_,
        bytes32 responsibleRole_,
        uint64 curePeriod_,
        bytes32 consequenceId_
    ) {
        if (
            initialOwner == address(0) || address(verifier_) == address(0)
                || address(precommitRegistry_) == address(0) || address(sourceRegistry_) == address(0)
        ) revert ZeroAddress();
        if (
            policyId_ == bytes32(0) || policyVersion_ == 0 || responsibleRole_ == bytes32(0)
                || curePeriod_ == 0 || consequenceId_ == bytes32(0)
        ) revert InvalidConfiguration();
        owner = initialOwner;
        verifier = verifier_;
        precommitRegistry = precommitRegistry_;
        sourceRegistry = sourceRegistry_;
        policyId = policyId_;
        policyVersion = policyVersion_;
        responsibleRole = responsibleRole_;
        curePeriod = curePeriod_;
        consequenceId = consequenceId_;
    }

    function setScopeController(bytes32 scopeCommitment, address controller) external onlyOwner {
        if (scopeCommitment == bytes32(0)) revert ZeroAddress();
        scopeController[scopeCommitment] = controller;
        emit ScopeControllerSet(scopeCommitment, controller);
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

    function consentDigest(
        bytes32 sessionId,
        bytes32 resultCommitment,
        bytes32 scopeCommitment,
        address anchor,
        uint64 validUntil
    ) public view returns (bytes32) {
        bytes32 structHash = keccak256(
            abi.encode(
                DISCLOSURE_CONSENT_TYPEHASH,
                block.chainid,
                address(this),
                sessionId,
                resultCommitment,
                scopeCommitment,
                anchor,
                validUntil
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice Binds one confirmed exact match to `anchor` and opens a record.
    /// @param envelope The quorum-signed result. Its `binder` must be this contract.
    /// @param attestation The validator attestation, passed through unread.
    /// @param anchor The local tokenized receivable this side of the match owns.
    /// @param counterparty How the other side of the session is anchored.
    /// @param consentA Disclosure consent from the controller of scope A.
    /// @param consentB Disclosure consent from the controller of scope B.
    function bindRecourse(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope calldata envelope,
        bytes calldata attestation,
        IAnchoredReceivable anchor,
        Counterparty calldata counterparty,
        DisclosureConsent calldata consentA,
        DisclosureConsent calldata consentB
    ) external returns (bytes32 sessionId) {
        sessionId = envelope.result.sessionId;
        if (envelope.binder != address(this)) revert EnvelopeNotForThisBinder(envelope.binder);
        if (envelope.policyId != policyId || envelope.policyVersion != policyVersion) {
            revert UnexpectedPolicy(envelope.policyId, envelope.policyVersion);
        }
        if (recourses[sessionId].open) revert SessionAlreadyBound(sessionId);

        bytes32 anchorCommitment = _assertAnchorLive(anchor);
        bytes32 counterpartyCommitment =
            _resolveSides(envelope.result, anchorCommitment, counterparty);

        // The pre-commitment is the registry's answer, never the caller's claim,
        // and it is the reason `requireBindable` can be trusted at all: the
        // issuer named this session against this anchor's commitment BEFORE the
        // session ran, so a match cannot be shopped to a convenient anchor after
        // the fact.
        bool precommitted = precommitRegistry.isSessionPrecommitted(sessionId, anchorCommitment);
        if (!precommitted) revert SessionNotPrecommittedForAnchor(sessionId, anchorCommitment);
        Match.requireBindable(envelope.result, precommitted);
        _assertPrecommitmentIssuer(sessionId, anchor.issuerKeyId());

        _requireBilateralConsent(envelope, address(anchor), consentA, consentB);

        // The quorum is checked last, and it is the step that consumes the
        // result's one-time identities. Everything above is free to revert
        // without burning a valid result.
        verifier.acceptMatch(envelope, attestation);

        _open(envelope, address(anchor), anchorCommitment, counterpartyCommitment);
    }

    /// @dev Split out of `bindRecourse` only to keep the stack shallow. The
    /// policy is written from the immutables, which were already checked to equal
    /// the envelope's.
    function _open(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope calldata envelope,
        address anchor,
        bytes32 anchorCommitment,
        bytes32 counterpartyCommitment
    ) private {
        uint64 boundAt = uint64(block.timestamp);
        uint64 cureDeadline = boundAt + curePeriod;
        recourses[envelope.result.sessionId] = RecourseRecord({
            sessionId: envelope.result.sessionId,
            resultCommitment: envelope.resultCommitment,
            matchCommitment: envelope.result.matchCommitment,
            anchorCommitment: anchorCommitment,
            counterpartyCommitment: counterpartyCommitment,
            providerProofCommitment: envelope.result.providerProofCommitment,
            anchor: anchor,
            policyId: policyId,
            policyVersion: policyVersion,
            conflictConfirmed: envelope.result.conflictConfirmed,
            boundAt: boundAt,
            cureDeadline: cureDeadline,
            open: true
        });

        emit PrivateMatchBound(
            envelope.result.sessionId,
            anchor,
            envelope.result.matchCommitment,
            anchorCommitment,
            counterpartyCommitment,
            policyId,
            policyVersion,
            envelope.result.conflictConfirmed,
            cureDeadline
        );
    }

    function recourseOf(bytes32 sessionId) external view returns (RecourseRecord memory) {
        return recourses[sessionId];
    }

    /// @notice Whether the receivable behind a record is still in the state that
    /// makes the record meaningful.
    function anchorLive(bytes32 sessionId) external view returns (bool) {
        RecourseRecord memory record = recourses[sessionId];
        if (!record.open || record.anchor.code.length == 0) return false;
        IAnchoredReceivable anchor = IAnchoredReceivable(record.anchor);
        return anchor.assetCommitment() == record.anchorCommitment
            && anchor.receivableState() == RECEIVABLE_OUTSTANDING
            && anchor.protectionState() == PROTECTION_ACTIVE;
    }

    /// @dev Reads the anchor's own commitment. It is never supplied by a caller.
    function _assertAnchorLive(IAnchoredReceivable anchor) private view returns (bytes32) {
        if (address(anchor).code.length == 0) revert AnchorNotDeployed(address(anchor));
        uint16 scheme = anchor.identitySchemeVersion();
        if (scheme != MordantAssetIdentity.IDENTITY_SCHEME_VERSION) {
            revert AnchorSchemeMismatch(scheme, MordantAssetIdentity.IDENTITY_SCHEME_VERSION);
        }
        uint8 receivable = anchor.receivableState();
        if (receivable != RECEIVABLE_OUTSTANDING) revert AnchorNotOutstanding(receivable);
        uint8 protection = anchor.protectionState();
        if (protection != PROTECTION_ACTIVE) revert AnchorProtectionInactive(protection);
        if (anchor.totalSupply() == 0) revert AnchorHasNoUnits();
        bytes32 commitment = anchor.assetCommitment();
        if (commitment == bytes32(0)) revert InvalidConfiguration();
        return commitment;
    }

    /// @dev Places the anchor on one side of the session and proves the other
    /// side was anchored too. The two commitments are salted independently, so
    /// they are never equal and this contract cannot and does not compare them
    /// for identity: that equality is what the FHE evaluation established.
    function _resolveSides(
        Match.ConfidentialMatchResultV4 calldata result,
        bytes32 anchorCommitment,
        Counterparty calldata counterparty
    ) private view returns (bytes32 counterpartyCommitment) {
        if (result.anchorCount != EXPECTED_ANCHOR_COUNT) {
            revert AnchorCountMismatch(result.anchorCount);
        }
        // An anchor matched against itself is not a conflict.
        if (result.inputCommitmentA == result.inputCommitmentB) {
            revert SelfMatch(result.inputCommitmentA);
        }
        if (anchorCommitment == result.inputCommitmentA) {
            counterpartyCommitment = result.inputCommitmentB;
        } else if (anchorCommitment == result.inputCommitmentB) {
            counterpartyCommitment = result.inputCommitmentA;
        } else {
            revert AnchorCommitmentNotInSession(anchorCommitment);
        }

        bytes32 observed;
        if (counterparty.kind == CounterpartyKind.RegisteredSource) {
            observed = sourceRegistry.assetCommitmentOf(counterparty.anchorId);
        } else if (counterparty.kind == CounterpartyKind.VaultAnchor) {
            if (counterparty.vault.code.length == 0) revert AnchorNotDeployed(counterparty.vault);
            observed = IAnchoredReceivable(counterparty.vault).assetCommitment();
        } else {
            revert CounterpartyNotAnchored();
        }
        if (observed != counterpartyCommitment) {
            revert CounterpartyCommitmentMismatch(observed, counterpartyCommitment);
        }
    }

    /// @dev The issuer that pre-committed the session must be the issuer that
    /// attested the anchor. Otherwise any authorized issuer could pre-commit a
    /// session against someone else's published commitment.
    function _assertPrecommitmentIssuer(bytes32 sessionId, bytes32 anchorIssuer) private view {
        (, bytes32 recordedIssuer,,,) = precommitRegistry.precommitments(sessionId);
        if (recordedIssuer != anchorIssuer) {
            revert PrecommitmentIssuerMismatch(recordedIssuer, anchorIssuer);
        }
    }

    function _requireBilateralConsent(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope calldata envelope,
        address anchor,
        DisclosureConsent calldata consentA,
        DisclosureConsent calldata consentB
    ) private view {
        // Consents are matched to scopes by content, not by argument order, so a
        // caller cannot satisfy both sides with two signatures from one party.
        if (
            consentA.scopeCommitment != envelope.result.scopeCommitmentA
                || consentB.scopeCommitment != envelope.result.scopeCommitmentB
        ) revert DisclosureConsentMissing(consentA.scopeCommitment);
        _requireConsent(envelope, anchor, consentA);
        _requireConsent(envelope, anchor, consentB);
    }

    function _requireConsent(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope calldata envelope,
        address anchor,
        DisclosureConsent calldata consent
    ) private view {
        address controller = scopeController[consent.scopeCommitment];
        if (controller == address(0)) revert ScopeControllerUnknown(consent.scopeCommitment);
        if (block.timestamp > consent.validUntil) {
            revert DisclosureConsentExpired(consent.scopeCommitment, consent.validUntil);
        }
        bytes32 digest = consentDigest(
            envelope.result.sessionId,
            envelope.resultCommitment,
            consent.scopeCommitment,
            anchor,
            consent.validUntil
        );
        if (_recover(digest, consent.signature) != controller) {
            revert DisclosureConsentMissing(consent.scopeCommitment);
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
