// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {MordantAssetIdentity} from "../identity/MordantAssetIdentity.sol";
import {MordantIssuerRegistry} from "../identity/MordantIssuerRegistry.sol";
import {MordantMatchResult as Match} from "../identity/MordantMatchResult.sol";
import {MordantSourceIdentityRegistry} from "../identity/MordantSourceIdentityRegistry.sol";
import {ECDSAQuorumMatchVerifierV4} from "./ECDSAQuorumMatchVerifierV4.sol";
import {IAnchoredReceivable} from "./IAnchoredReceivable.sol";
import {MordantScopeGovernanceRegistry as Governance} from "./MordantScopeGovernanceRegistry.sol";

/// @notice Reveals one committed bilateral session, binds its confirmed exact
/// match to a real tokenized receivable, and opens a non-economic recourse
/// record.
///
/// @dev This contract is where a private session becomes public, and it is the
/// only place that happens. Everything it verifies was committed beforehand and
/// kept opaque until both parties consented.
///
/// What it does NOT do is the point of it.
///
/// It never learns an `assetId`. The identity values that reach the chain are
/// the anchors' own salted commitments, which the anchors already published at
/// creation. Nothing here opens one.
///
/// It is non-economic. It holds no balance, has no token interface, and reaches
/// the receivable only through a view-only interface, so a confirmed conflict
/// produces a record and nothing else.
///
/// Six independently verified authorization conditions, each resolved from state
/// that existed before the private result did:
///
///   1. both scope authorizations existed and were live when the session was
///      committed, and neither has been emergency-revoked since
///   2. both controllers signed the identical session intent, before commitment
///   3. an authorized issuer signed the same intent, naming this anchor's
///      commitment, so the anchor was pre-authorized rather than chosen after
///   4. both anchors were registered before the commitment was published
///   5. both controllers, as named by the frozen records, consented to disclose
///      this specific result
///   6. a validator quorum endorsed the result against that same commitment
///
/// Organizational independence between those conditions is a production
/// deployment property. It holds only once the administrative domains are
/// actually separated, and this contract does not and cannot establish it.
contract PrivateMatchBinder {
    error ZeroAddress();
    error InvalidConfiguration();
    error EnvelopeNotForThisBinder(address supplied);
    error UnexpectedPolicy(bytes32 policyId, uint32 policyVersion);
    error IntentPolicyMismatch(bytes32 policyId, uint32 policyVersion);
    error AnchorNotDeployed(address anchor);
    error AnchorSchemeMismatch(uint16 supplied, uint16 expected);
    error AnchorCommitmentNotInSession(bytes32 anchorCommitment);
    error AnchorNotPreAuthorized(bytes32 observed, bytes32 intended);
    error AnchorSourceMismatch(bytes32 observed, bytes32 intended);
    error SelfMatch(bytes32 inputCommitment);
    error CounterpartyCommitmentMismatch(bytes32 observed, bytes32 expected);
    error CounterpartyRegisteredAfterCommitment(uint64 registeredAt, uint64 committedAt);
    error AnchorCountMismatch(uint8 supplied);
    error AnchorNotOutstanding(uint8 receivableState);
    error AnchorProtectionInactive(uint8 protectionState);
    error AnchorHasNoUnits();
    error SessionAlreadyBound(bytes32 sessionCommitment);
    error RevealNotForEnvelope(bytes32 revealed, bytes32 supplied);
    error ConsentRecordNotFrozenForSession(bytes32 scopeCommitment, bytes32 governanceRecord);
    error ConsentScopeMismatch(bytes32 supplied, bytes32 expected);
    error DisclosureConsentMissing(bytes32 scopeCommitment);
    error DisclosureConsentExpired(bytes32 scopeCommitment, uint64 validUntil);
    error DisclosureVersionMismatch(uint32 supplied, uint32 expected);
    error ConsentNonceConsumed(bytes32 scopeCommitment, uint256 nonce);
    error ControllerEmergencyRevoked(bytes32 recordDigest, uint64 hardRevokedAt);
    error MalformedSignature();

    event PrivateMatchBound(
        bytes32 indexed sessionCommitment,
        address indexed anchor,
        bytes32 indexed matchCommitment,
        bytes32 anchorCommitment,
        bytes32 counterpartyCommitment,
        bool conflictConfirmed,
        uint64 cureDeadline
    );

    /// @dev Mirrored from MordantInvoiceVault. Only these states make a recourse
    /// record meaningful.
    uint8 public constant RECEIVABLE_OUTSTANDING = 1;
    uint8 public constant PROTECTION_ACTIVE = 1;
    /// @dev An exact match is between exactly two anchored submissions.
    uint8 public constant EXPECTED_ANCHOR_COUNT = 2;
    /// @dev The disclosure semantics a consent signs under.
    uint32 public constant DISCLOSURE_VERSION = 1;

    string public constant DOMAIN_NAME = "Mordant Private Match Binder";
    string public constant DOMAIN_VERSION = "1";

    bytes32 public constant DISCLOSURE_CONSENT_TYPEHASH = keccak256(
        "DisclosureConsent(uint256 chainId,address binder,bytes32 policyId,uint32 policyVersion,bytes32 sessionCommitment,bytes32 resultCommitment,bytes32 matchCommitment,bytes32 scopeCommitment,bytes32 governanceRecord,bytes32 controllerKeyId,uint32 controllerEpoch,uint32 scopeAuthorizationVersion,address anchor,uint32 disclosureVersion,uint64 validUntil,uint256 nonce)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    /// @notice The preimage of the opaque commitment, opened once at binding.
    struct SessionReveal {
        Governance.BilateralSessionIntent intent;
        bytes32 salt;
        Governance.InitiationSignatures signatures;
    }

    /// @notice One side's consent to disclose that this session matched.
    /// @dev A confirmed conflict is publishable only if both frozen controllers
    /// sign for it. Without this a single platform could publish that a
    /// counterparty is double-financing, which is exactly the disclosure the
    /// private mode exists to prevent.
    ///
    /// `governanceRecord` names the historical authorization the consent is made
    /// under. It must be one of the two records the intent named, so a controller
    /// appointed later cannot consent for an earlier session, and a controller
    /// since retired still can.
    struct DisclosureConsent {
        bytes32 scopeCommitment;
        bytes32 governanceRecord;
        uint32 disclosureVersion;
        uint64 validUntil;
        uint256 nonce;
        bytes signature;
    }

    struct RecourseRecord {
        bytes32 sessionCommitment;
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

    ECDSAQuorumMatchVerifierV4 public immutable verifier;
    Governance public immutable governance;
    MordantIssuerRegistry public immutable issuerRegistry;
    MordantSourceIdentityRegistry public immutable sourceRegistry;
    bytes32 public immutable policyId;
    uint32 public immutable policyVersion;
    bytes32 public immutable responsibleRole;
    uint64 public immutable curePeriod;
    bytes32 public immutable consequenceId;

    mapping(bytes32 sessionCommitment => RecourseRecord record) public recourses;
    mapping(bytes32 scopeCommitment => mapping(uint256 nonce => bool used)) public consumedConsentNonce;

    /// @dev There is deliberately no owner and no setter on this contract. Every
    /// authority it consults is versioned and timestamped somewhere else, so
    /// there is nothing here an administrator could retroactively change.
    constructor(
        ECDSAQuorumMatchVerifierV4 verifier_,
        Governance governance_,
        MordantIssuerRegistry issuerRegistry_,
        MordantSourceIdentityRegistry sourceRegistry_,
        bytes32 policyId_,
        uint32 policyVersion_,
        bytes32 responsibleRole_,
        uint64 curePeriod_,
        bytes32 consequenceId_
    ) {
        if (
            address(verifier_) == address(0) || address(governance_) == address(0)
                || address(issuerRegistry_) == address(0) || address(sourceRegistry_) == address(0)
        ) revert ZeroAddress();
        if (
            policyId_ == bytes32(0) || policyVersion_ == 0 || responsibleRole_ == bytes32(0)
                || curePeriod_ == 0 || consequenceId_ == bytes32(0)
        ) revert InvalidConfiguration();
        verifier = verifier_;
        governance = governance_;
        issuerRegistry = issuerRegistry_;
        sourceRegistry = sourceRegistry_;
        policyId = policyId_;
        policyVersion = policyVersion_;
        responsibleRole = responsibleRole_;
        curePeriod = curePeriod_;
        consequenceId = consequenceId_;
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

    /// @notice The digest a scope controller signs to authorize disclosure.
    /// @dev The controller identity, epoch and authorization version are read
    /// from the named governance record, not supplied by the caller, so a consent
    /// cannot be presented under a governance record it was not signed for.
    function consentDigest(
        bytes32 sessionCommitment,
        bytes32 resultCommitment,
        bytes32 matchCommitment,
        address anchor,
        DisclosureConsent memory consent
    ) public view returns (bytes32) {
        Governance.ScopeAuthorization memory authorization =
            governance.record(consent.governanceRecord);
        bytes32 structHash = keccak256(
            abi.encodePacked(
                abi.encode(
                    DISCLOSURE_CONSENT_TYPEHASH,
                    block.chainid,
                    address(this),
                    policyId,
                    policyVersion,
                    sessionCommitment,
                    resultCommitment
                ),
                abi.encode(
                    matchCommitment,
                    consent.scopeCommitment,
                    consent.governanceRecord,
                    authorization.controllerKeyId,
                    authorization.controllerEpoch,
                    authorization.authorizationVersion
                ),
                abi.encode(anchor, consent.disclosureVersion, consent.validUntil, consent.nonce)
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice Binds one confirmed exact match and opens a recourse record.
    /// @param envelope The quorum-signed result. Its `binder` must be this contract.
    /// @param attestation The validator attestation, passed through unread.
    /// @param reveal The committed session's preimage and initiation signatures.
    /// @param anchor The local tokenized receivable this side of the match owns.
    /// @param consentA Disclosure consent for scope A, under its frozen record.
    /// @param consentB Disclosure consent for scope B, under its frozen record.
    function bindRecourse(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope calldata envelope,
        bytes calldata attestation,
        SessionReveal calldata reveal,
        IAnchoredReceivable anchor,
        DisclosureConsent calldata consentA,
        DisclosureConsent calldata consentB
    ) external returns (bytes32 sessionCommitment) {
        sessionCommitment = envelope.sessionCommitment;
        if (envelope.binder != address(this)) revert EnvelopeNotForThisBinder(envelope.binder);
        if (envelope.policyId != policyId || envelope.policyVersion != policyVersion) {
            revert UnexpectedPolicy(envelope.policyId, envelope.policyVersion);
        }
        if (reveal.intent.policyId != policyId || reveal.intent.policyVersion != policyVersion) {
            revert IntentPolicyMismatch(reveal.intent.policyId, reveal.intent.policyVersion);
        }
        if (recourses[sessionCommitment].open) revert SessionAlreadyBound(sessionCommitment);

        // Opening the commitment is the moment the pairing becomes public. It
        // verifies both initiation signatures, both governance records, the
        // neutrality of the submitter and the one-time use of the commitment.
        Governance.ResolvedSession memory session =
            governance.resolveSession(reveal.intent, reveal.salt, reveal.signatures);
        if (session.sessionCommitment != sessionCommitment) {
            revert RevealNotForEnvelope(session.sessionCommitment, sessionCommitment);
        }
        // The issuer that pre-authorized this anchor must have been an authorized
        // issuer key. This is the pre-commitment, carried privately.
        issuerRegistry.requireAuthorized(
            session.issuerKeyId, session.issuerSigner, session.identityEpoch
        );

        bytes32 anchorCommitment = _assertAnchorLive(anchor, session);
        bytes32 counterpartyCommitment =
            _resolveSides(envelope.result, anchorCommitment, session);
        _requireBilateralConsent(envelope, session, address(anchor), consentA, consentB);

        // The quorum is checked last, and it is the step that consumes the
        // result's one-time identities.
        verifier.acceptMatch(envelope, attestation);

        _consumeConsent(consentA);
        _consumeConsent(consentB);
        _open(envelope, address(anchor), anchorCommitment, counterpartyCommitment);
    }

    function recourseOf(bytes32 sessionCommitment) external view returns (RecourseRecord memory) {
        return recourses[sessionCommitment];
    }

    /// @notice Whether the receivable behind a record is still in the state that
    /// makes the record meaningful.
    function anchorLive(bytes32 sessionCommitment) external view returns (bool) {
        RecourseRecord memory record = recourses[sessionCommitment];
        if (!record.open || record.anchor.code.length == 0) return false;
        IAnchoredReceivable anchor = IAnchoredReceivable(record.anchor);
        return anchor.assetCommitment() == record.anchorCommitment
            && anchor.receivableState() == RECEIVABLE_OUTSTANDING
            && anchor.protectionState() == PROTECTION_ACTIVE;
    }

    /// @dev Split out of `bindRecourse` only to keep the stack shallow.
    function _open(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope calldata envelope,
        address anchor,
        bytes32 anchorCommitment,
        bytes32 counterpartyCommitment
    ) private {
        uint64 boundAt = uint64(block.timestamp);
        uint64 cureDeadline = boundAt + curePeriod;
        recourses[envelope.sessionCommitment] = RecourseRecord({
            sessionCommitment: envelope.sessionCommitment,
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
            envelope.sessionCommitment,
            anchor,
            envelope.result.matchCommitment,
            anchorCommitment,
            counterpartyCommitment,
            envelope.result.conflictConfirmed,
            cureDeadline
        );
    }

    /// @dev Reads the anchor's own commitment and checks the issuer named exactly
    /// this anchor in the intent it signed before the session was committed.
    function _assertAnchorLive(
        IAnchoredReceivable anchor,
        Governance.ResolvedSession memory session
    ) private view returns (bytes32) {
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
        if (commitment != session.strictAssetCommitmentA) {
            revert AnchorNotPreAuthorized(commitment, session.strictAssetCommitmentA);
        }
        bytes32 attestationDigest = anchor.sourceAttestationDigest();
        if (attestationDigest != session.sourceRecordA) {
            revert AnchorSourceMismatch(attestationDigest, session.sourceRecordA);
        }
        return commitment;
    }

    /// @dev Places the anchor on one side of the session and proves the other
    /// side was registered before the commitment was published. The two
    /// commitments are salted independently, so they are never equal and this
    /// contract cannot and does not compare them for identity: that equality is
    /// what the FHE evaluation established.
    function _resolveSides(
        Match.ConfidentialMatchResultV4 calldata result,
        bytes32 anchorCommitment,
        Governance.ResolvedSession memory session
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

        MordantSourceIdentityRegistry.SourceAnchor memory source =
            sourceRegistry.anchor(session.sourceRecordB);
        if (source.assetCommitment != counterpartyCommitment) {
            revert CounterpartyCommitmentMismatch(source.assetCommitment, counterpartyCommitment);
        }
        // A source produced after the commitment was not anticipated by it, so a
        // result cannot be attached to a counterparty invented afterwards.
        if (source.registeredAt > session.committedAt) {
            revert CounterpartyRegisteredAfterCommitment(source.registeredAt, session.committedAt);
        }
    }

    function _requireBilateralConsent(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope calldata envelope,
        Governance.ResolvedSession memory session,
        address anchor,
        DisclosureConsent calldata consentA,
        DisclosureConsent calldata consentB
    ) private view {
        // Consents are matched to sides by content, not by argument order, so a
        // caller cannot satisfy both sides with two signatures from one party.
        if (consentA.scopeCommitment != envelope.result.scopeCommitmentA) {
            revert ConsentScopeMismatch(consentA.scopeCommitment, envelope.result.scopeCommitmentA);
        }
        if (consentB.scopeCommitment != envelope.result.scopeCommitmentB) {
            revert ConsentScopeMismatch(consentB.scopeCommitment, envelope.result.scopeCommitmentB);
        }
        _requireConsent(envelope, session.governanceRecordA, anchor, consentA);
        _requireConsent(envelope, session.governanceRecordB, anchor, consentB);
    }

    /// @dev `frozenRecord` comes from the intent both controllers signed. A
    /// consent made under any other record, whether a later rotation or an
    /// earlier one, is refused before its signature is even recovered.
    function _requireConsent(
        ECDSAQuorumMatchVerifierV4.MatchEnvelope calldata envelope,
        bytes32 frozenRecord,
        address anchor,
        DisclosureConsent calldata consent
    ) private view {
        if (consent.governanceRecord != frozenRecord) {
            revert ConsentRecordNotFrozenForSession(consent.scopeCommitment, consent.governanceRecord);
        }
        if (consent.disclosureVersion != DISCLOSURE_VERSION) {
            revert DisclosureVersionMismatch(consent.disclosureVersion, DISCLOSURE_VERSION);
        }
        if (block.timestamp > consent.validUntil) {
            revert DisclosureConsentExpired(consent.scopeCommitment, consent.validUntil);
        }
        if (consent.nonce == 0 || consumedConsentNonce[consent.scopeCommitment][consent.nonce]) {
            revert ConsentNonceConsumed(consent.scopeCommitment, consent.nonce);
        }
        Governance.ScopeAuthorization memory authorization = governance.record(frozenRecord);
        if (authorization.scopeCommitment != consent.scopeCommitment) {
            revert ConsentScopeMismatch(consent.scopeCommitment, authorization.scopeCommitment);
        }
        // A compromised key does not get to consent, and a consent it gave
        // before the compromise was noticed does not get to bind afterwards.
        if (authorization.hardRevokedAt != 0) {
            revert ControllerEmergencyRevoked(frozenRecord, authorization.hardRevokedAt);
        }
        bytes32 digest = consentDigest(
            envelope.sessionCommitment,
            envelope.resultCommitment,
            envelope.result.matchCommitment,
            anchor,
            consent
        );
        if (_recover(digest, consent.signature) != authorization.controller) {
            revert DisclosureConsentMissing(consent.scopeCommitment);
        }
    }

    function _consumeConsent(DisclosureConsent calldata consent) private {
        consumedConsentNonce[consent.scopeCommitment][consent.nonce] = true;
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
