// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import { IAnchoredReceivable } from "../v4/IAnchoredReceivable.sol";
import { MordantAssetIdentity } from "../identity/MordantAssetIdentity.sol";
import { MordantMatchResultV5 as Outcomes } from "../identity/MordantMatchResultV5.sol";
import {
    MordantSourceAttestation as SourceAttestation
} from "../identity/MordantSourceAttestation.sol";
import { MordantMatchVerifierV5 as Verifier } from "./MordantMatchVerifierV5.sol";
import { MordantResultCoreV5 as Core } from "./MordantResultCoreV5.sol";
import {
    MordantScopeGovernanceRegistryV5 as Governance
} from "./MordantScopeGovernanceRegistryV5.sol";
import { MordantSourceCommitmentRegistry as Sources } from "./MordantSourceCommitmentRegistry.sol";

/// @notice The admission surface a genuine anchor must appear in.
/// @dev Implemented by the frozen V2 factory, which is read and never modified.
interface IFactoryAdmission {
    function vaultForAttestation(bytes32 attestationDigest) external view returns (address);
}

/// @notice V5 recourse binder.
///
/// @dev Findings M-06 and L-01. The V4 binder established that the anchor
/// *behaved* like an anchored receivable: it checked the interface, the scheme
/// version, the state, the protection and the unit supply. It never established
/// that the anchor *was* one. Any contract implementing `IAnchoredReceivable`
/// and returning the expected values passed every check, so a generic
/// interface-compatible mock, or a real anchor from a foreign factory, could
/// open a recourse record.
///
/// V5 proves provenance: the anchor's own source-attestation digest must resolve
/// back to the anchor's own address in the configured authorized Factory V2.
/// A mock has no such entry, and a foreign anchor resolves in a different
/// factory.
///
/// The other V5 change is that the two source records are opened HERE, once, at
/// binding, from the opaque pre-session commitments (finding C-01). Before this
/// moment nothing correlatable about either party is public.
contract PrivateMatchBinderV5 {
    error ZeroAddress();
    error InvalidConfiguration();
    error EnvelopeNotForThisBinder(address supplied);
    error UnexpectedPolicy(bytes32 policyId, uint32 policyVersion);
    error ResultNotBindable(Outcomes.Outcome outcome);
    error AnchorNotDeployed(address anchor);
    error AnchorNotFromAuthorizedFactory(address anchor, address admitted);
    error AnchorSchemeMismatch(uint16 supplied, uint16 expected);
    error AnchorTermsSchemeMismatch(uint16 supplied, uint16 expected);
    error AnchorNotOutstanding(uint8 receivableState);
    error AnchorProtectionInactive(uint8 protectionState);
    error AnchorHasNoUnits();
    error AnchorCommitmentMismatch(bytes32 observed, bytes32 revealed);
    error AnchorSourceMismatch(bytes32 observed, bytes32 expected);
    error SourceRecordMismatch(bytes32 revealed, bytes32 expected);
    error SourceNotBeforeSession(uint64 sourceBlock, uint64 sessionBlock);
    error SessionCommitmentMismatch(bytes32 resolved, bytes32 inResult);
    error SessionAlreadyBound(bytes32 sessionCommitment);
    error ResultAlreadyBound(bytes32 resultCommitment);
    error DecisionAlreadyBound(bytes32 decisionKey);
    error SourceAlreadyBound(bytes32 sourceRecordCommitment);
    error SelfMatch(bytes32 sourceRecordCommitment);
    error ConsentScopeMismatch(bytes32 supplied, bytes32 expected);
    error ConsentRecordNotForSession(bytes32 scopeCommitment, bytes32 governanceRecord);
    error DisclosureConsentExpired(bytes32 scopeCommitment, uint64 validUntil);
    error DisclosureVersionMismatch(uint32 supplied, uint32 expected);
    error ConsentNonceConsumed(bytes32 scopeCommitment, uint256 nonce);
    error ConsentNotSignedByController(address expected, address recovered);
    error MalformedSignature();

    event RecourseOpened(
        bytes32 indexed sessionCommitment,
        bytes32 indexed resultCommitment,
        address indexed anchor,
        bytes32 anchorCommitment,
        bytes32 counterpartyCommitment,
        uint64 cureDeadline
    );

    string public constant DOMAIN_NAME = "Mordant Private Match Binder";
    string public constant DOMAIN_VERSION = "5";

    bytes32 public constant CONSENT_TYPEHASH = keccak256(
        "DisclosureConsentV5(uint256 chainId,address binder,bytes32 policyId,uint32 policyVersion,bytes32 sessionCommitment,bytes32 sessionNullifier,bytes32 resultCommitment,bytes32 scopeCommitment,bytes32 governanceRecord,bytes32 sourceRecordCommitment,address anchor,uint32 disclosureVersion,uint64 validUntil,uint256 nonce)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    uint8 public constant RECEIVABLE_OUTSTANDING = 1;
    uint8 public constant PROTECTION_ACTIVE = 1;

    /// @notice The preimage of the opaque session commitment, opened once here.
    struct SessionReveal {
        Governance.BilateralSessionIntentV5 intent;
        bytes32 salt;
        Governance.InitiationSignatures signatures;
    }

    /// @notice The preimage of one opaque source-record commitment.
    struct SourceReveal {
        SourceAttestation.SourceAssetAttestation attestation;
        bytes issuerSignature;
        bytes32 salt;
    }

    /// @notice One side's consent to disclose that this session matched.
    /// @dev A confirmed conflict is publishable only if both frozen controllers
    /// sign for it. Without this a single platform could publish that a
    /// counterparty is double-financing, which is exactly the disclosure the
    /// private mode exists to prevent.
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
        bytes32 sessionNullifier;
        bytes32 resultCommitment;
        bytes32 anchorCommitment;
        bytes32 counterpartyCommitment;
        bytes32 providerProofCommitment;
        address anchor;
        bytes32 policyId;
        uint32 policyVersion;
        uint64 boundAt;
        uint64 cureDeadline;
        bool open;
    }

    Verifier public immutable verifier;
    Governance public immutable governance;
    Sources public immutable sourceRegistry;
    /// @dev The single authorized anchor factory. An anchor that does not
    /// resolve here is not an anchor this binder recognises, whatever it
    /// implements.
    IFactoryAdmission public immutable factory;
    bytes32 public immutable policyId;
    uint32 public immutable policyVersion;
    uint64 public immutable curePeriod;
    bytes32 public immutable consequenceId;

    mapping(bytes32 sessionCommitment => RecourseRecord record) public recourses;
    mapping(bytes32 resultCommitment => bool bound) public boundResults;
    mapping(bytes32 decisionKey => bool bound) public boundDecisions;
    mapping(bytes32 sourceRecordCommitment => bool bound) public boundSources;
    mapping(bytes32 scopeCommitment => mapping(uint256 nonce => bool used)) public
        consumedConsentNonce;

    /// @dev No owner and no setter. Every authority this contract consults is
    /// versioned and block-stamped somewhere else, so there is nothing here an
    /// administrator could retroactively change.
    constructor(
        Verifier verifier_,
        Governance governance_,
        Sources sourceRegistry_,
        IFactoryAdmission factory_,
        bytes32 policyId_,
        uint32 policyVersion_,
        uint64 curePeriod_,
        bytes32 consequenceId_
    ) {
        if (
            address(verifier_) == address(0) || address(governance_) == address(0)
                || address(sourceRegistry_) == address(0) || address(factory_) == address(0)
        ) revert ZeroAddress();
        if (
            policyId_ == bytes32(0) || policyVersion_ == 0 || curePeriod_ == 0
                || consequenceId_ == bytes32(0)
        ) {
            revert InvalidConfiguration();
        }
        verifier = verifier_;
        governance = governance_;
        sourceRegistry = sourceRegistry_;
        factory = factory_;
        policyId = policyId_;
        policyVersion = policyVersion_;
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

    /// @notice The digest a controller signs to consent to disclosure.
    ///
    /// @dev The producer calls this BEFORE binding, so it must not read state
    /// that only exists after binding. Everything it needs is a parameter, and
    /// the binding path calls the very same encoder, so the value signed here
    /// is by construction the value verified there.
    ///
    /// `sourceRecordCommitment` is the CONSENTING side's own opaque source
    /// record, not the counterparty's: a controller consents to disclose its
    /// own participation.
    function consentDigest(
        bytes32 sessionCommitment,
        bytes32 sessionNullifier,
        bytes32 resultCommitment,
        bytes32 sourceRecordCommitment,
        address anchor,
        DisclosureConsent calldata consent
    ) public view returns (bytes32) {
        return _consentDigest(
            sessionCommitment,
            sessionNullifier,
            resultCommitment,
            sourceRecordCommitment,
            anchor,
            consent
        );
    }

    function _consentDigest(
        bytes32 sessionCommitment,
        bytes32 sessionNullifier,
        bytes32 resultCommitment,
        bytes32 sourceRecordCommitment,
        address anchor,
        DisclosureConsent calldata consent
    ) private view returns (bytes32) {
        bytes32 structHash = keccak256(
            bytes.concat(
                abi.encode(
                    CONSENT_TYPEHASH,
                    block.chainid,
                    address(this),
                    policyId,
                    policyVersion,
                    sessionCommitment,
                    sessionNullifier,
                    resultCommitment
                ),
                abi.encode(
                    consent.scopeCommitment,
                    consent.governanceRecord,
                    sourceRecordCommitment,
                    anchor,
                    consent.disclosureVersion,
                    consent.validUntil,
                    consent.nonce
                )
            )
        );
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), structHash));
    }

    /// @notice Opens a recourse record for a confirmed policy conflict.
    function bindRecourse(
        Verifier.MatchEnvelopeV5 calldata envelope,
        bytes calldata attestation,
        SessionReveal calldata reveal,
        SourceReveal calldata anchoredSource,
        SourceReveal calldata counterpartySource,
        IAnchoredReceivable anchor,
        DisclosureConsent calldata consentA,
        DisclosureConsent calldata consentB
    ) external returns (bytes32 resultCommitment) {
        Core.ResultCore calldata core = envelope.core;
        if (core.binder != address(this)) revert EnvelopeNotForThisBinder(core.binder);
        if (core.policyId != policyId || core.policyVersion != policyVersion) {
            revert UnexpectedPolicy(core.policyId, core.policyVersion);
        }

        // The three explicit conditions, stated separately and all required.
        // `requireBindableOutcome` also reverts on the 01 state.
        if (!core.sameEconomicAsset || !core.policyConflict) {
            revert ResultNotBindable(core.outcome);
        }
        if (core.outcome != Outcomes.Outcome.SameAssetPolicyConflict) {
            revert ResultNotBindable(core.outcome);
        }
        Outcomes.requireBindableOutcome(core.outcome, core.sameEconomicAsset, core.policyConflict);

        // The verifier consumes its six identities and reverts on any reuse.
        resultCommitment = verifier.acceptMatch(envelope, attestation);

        if (recourses[core.session.sessionCommitment].open) {
            revert SessionAlreadyBound(core.session.sessionCommitment);
        }
        if (boundResults[resultCommitment]) revert ResultAlreadyBound(resultCommitment);
        bytes32 decision = verifier.decisionKey(core);
        if (boundDecisions[decision]) revert DecisionAlreadyBound(decision);

        _open(
            core,
            resultCommitment,
            decision,
            reveal,
            anchoredSource,
            counterpartySource,
            anchor,
            consentA,
            consentB
        );
    }

    function recourseOf(bytes32 sessionCommitment) external view returns (RecourseRecord memory) {
        return recourses[sessionCommitment];
    }

    /* ------------------------------------------------------------ internals */

    struct OpenContext {
        Governance.ResolvedSession session;
        Sources.RevealedSource anchored;
        Sources.RevealedSource counterparty;
    }

    function _open(
        Core.ResultCore calldata core,
        bytes32 resultCommitment,
        bytes32 decision,
        SessionReveal calldata reveal,
        SourceReveal calldata anchoredSource,
        SourceReveal calldata counterpartySource,
        IAnchoredReceivable anchor,
        DisclosureConsent calldata consentA,
        DisclosureConsent calldata consentB
    ) private {
        OpenContext memory context;

        // Opening the session enforces block chronology, the relayer/controller
        // separation and the one-shot nullifier inside the registry.
        context.session = governance.resolveSession(reveal.intent, reveal.salt, reveal.signatures);
        if (context.session.sessionCommitment != core.session.sessionCommitment) {
            revert SessionCommitmentMismatch(
                context.session.sessionCommitment, core.session.sessionCommitment
            );
        }

        // Open both opaque source records, once, now.
        context.anchored = sourceRegistry.revealSource(
            anchoredSource.attestation, anchoredSource.issuerSignature, anchoredSource.salt
        );
        context.counterparty = sourceRegistry.revealSource(
            counterpartySource.attestation,
            counterpartySource.issuerSignature,
            counterpartySource.salt
        );
        if (context.anchored.sourceRecordCommitment != core.session.sourceRecordCommitmentA) {
            revert SourceRecordMismatch(
                context.anchored.sourceRecordCommitment, core.session.sourceRecordCommitmentA
            );
        }
        if (context.counterparty.sourceRecordCommitment != core.session.sourceRecordCommitmentB) {
            revert SourceRecordMismatch(
                context.counterparty.sourceRecordCommitment, core.session.sourceRecordCommitmentB
            );
        }
        if (context.anchored.sourceRecordCommitment == context.counterparty.sourceRecordCommitment)
        {
            revert SelfMatch(context.anchored.sourceRecordCommitment);
        }
        if (boundSources[context.anchored.sourceRecordCommitment]) {
            revert SourceAlreadyBound(context.anchored.sourceRecordCommitment);
        }
        if (boundSources[context.counterparty.sourceRecordCommitment]) {
            revert SourceAlreadyBound(context.counterparty.sourceRecordCommitment);
        }

        // Both sources must predate the session, in blocks, strictly.
        uint64 sessionBlock = context.session.committedInBlock;
        if (context.anchored.committedInBlock >= sessionBlock) {
            revert SourceNotBeforeSession(context.anchored.committedInBlock, sessionBlock);
        }
        if (context.counterparty.committedInBlock >= sessionBlock) {
            revert SourceNotBeforeSession(context.counterparty.committedInBlock, sessionBlock);
        }

        _assertAnchorGenuine(anchor, context.anchored);
        _requireBilateralConsent(
            core, resultCommitment, address(anchor), context.session, consentA, consentB
        );

        boundResults[resultCommitment] = true;
        boundDecisions[decision] = true;
        boundSources[context.anchored.sourceRecordCommitment] = true;
        boundSources[context.counterparty.sourceRecordCommitment] = true;

        uint64 cureDeadline = uint64(block.timestamp) + curePeriod;
        recourses[core.session.sessionCommitment] = RecourseRecord({
            sessionCommitment: core.session.sessionCommitment,
            sessionNullifier: core.session.sessionNullifier,
            resultCommitment: resultCommitment,
            anchorCommitment: context.anchored.assetCommitment,
            counterpartyCommitment: context.counterparty.assetCommitment,
            providerProofCommitment: core.evaluation.providerProofCommitment,
            anchor: address(anchor),
            policyId: policyId,
            policyVersion: policyVersion,
            boundAt: uint64(block.timestamp),
            cureDeadline: cureDeadline,
            open: true
        });

        emit RecourseOpened(
            core.session.sessionCommitment,
            resultCommitment,
            address(anchor),
            context.anchored.assetCommitment,
            context.counterparty.assetCommitment,
            cureDeadline
        );
    }

    /// @dev Findings M-06 and L-01. Behaviour is not provenance.
    function _assertAnchorGenuine(
        IAnchoredReceivable anchor,
        Sources.RevealedSource memory revealed
    ) private view {
        if (address(anchor).code.length == 0) {
            revert AnchorNotDeployed(address(anchor));
        }

        // Provenance first: the anchor's own attestation digest must resolve
        // back to the anchor's own address in the one authorized factory. A
        // generic interface-compatible mock has no entry, and an anchor from a
        // foreign factory resolves elsewhere.
        bytes32 attestationDigest = anchor.sourceAttestationDigest();
        if (attestationDigest == bytes32(0)) revert AnchorNotDeployed(address(anchor));
        address admitted = factory.vaultForAttestation(attestationDigest);
        if (admitted != address(anchor)) {
            revert AnchorNotFromAuthorizedFactory(address(anchor), admitted);
        }

        uint16 scheme = anchor.identitySchemeVersion();
        if (scheme != MordantAssetIdentity.IDENTITY_SCHEME_VERSION) {
            revert AnchorSchemeMismatch(scheme, MordantAssetIdentity.IDENTITY_SCHEME_VERSION);
        }
        uint16 termsScheme = anchor.termsSchemeVersion();
        if (termsScheme != MordantAssetIdentity.TERMS_SCHEME_VERSION) {
            revert AnchorTermsSchemeMismatch(termsScheme, MordantAssetIdentity.TERMS_SCHEME_VERSION);
        }
        // The revealed source must describe the same schemes.
        if (revealed.identitySchemeVersion != scheme) {
            revert AnchorSchemeMismatch(revealed.identitySchemeVersion, scheme);
        }
        if (revealed.termsSchemeVersion != termsScheme) {
            revert AnchorTermsSchemeMismatch(revealed.termsSchemeVersion, termsScheme);
        }

        uint8 receivable = anchor.receivableState();
        if (receivable != RECEIVABLE_OUTSTANDING) revert AnchorNotOutstanding(receivable);
        uint8 protection = anchor.protectionState();
        if (protection != PROTECTION_ACTIVE) revert AnchorProtectionInactive(protection);
        if (anchor.totalSupply() == 0) revert AnchorHasNoUnits();

        // The anchor must be the receivable the revealed source describes.
        bytes32 commitment = anchor.assetCommitment();
        if (commitment == bytes32(0)) revert InvalidConfiguration();
        if (commitment != revealed.assetCommitment) {
            revert AnchorCommitmentMismatch(commitment, revealed.assetCommitment);
        }
        // The two attestations are scoped to different verifying contracts, the
        // factory and the source registry, so their digests are necessarily
        // different and comparing them would be a check that can never pass.
        // What must agree is the issuer: the same issuer key that attested the
        // anchor must have attested the source revealed for it.
        if (anchor.issuerKeyId() != revealed.issuerKeyId) {
            revert AnchorSourceMismatch(anchor.issuerKeyId(), revealed.issuerKeyId);
        }
    }

    function _requireBilateralConsent(
        Core.ResultCore calldata core,
        bytes32 resultCommitment,
        address anchor,
        Governance.ResolvedSession memory session,
        DisclosureConsent calldata consentA,
        DisclosureConsent calldata consentB
    ) private {
        _requireConsent(
            core,
            resultCommitment,
            anchor,
            session.scopeCommitmentA,
            session.governanceRecordA,
            core.session.sourceRecordCommitmentA,
            session.controllerA,
            consentA
        );
        _requireConsent(
            core,
            resultCommitment,
            anchor,
            session.scopeCommitmentB,
            session.governanceRecordB,
            core.session.sourceRecordCommitmentB,
            session.controllerB,
            consentB
        );
    }

    function _requireConsent(
        Core.ResultCore calldata core,
        bytes32 resultCommitment,
        address anchor,
        bytes32 expectedScope,
        bytes32 expectedRecord,
        bytes32 sourceRecordCommitment,
        address controller,
        DisclosureConsent calldata consent
    ) private {
        if (consent.scopeCommitment != expectedScope) {
            revert ConsentScopeMismatch(consent.scopeCommitment, expectedScope);
        }
        // The consent must be made under the historical authorization the intent
        // named, so a controller appointed later cannot consent for an earlier
        // session, and a controller since retired still can.
        if (consent.governanceRecord != expectedRecord) {
            revert ConsentRecordNotForSession(consent.scopeCommitment, consent.governanceRecord);
        }
        if (consent.validUntil == 0 || block.timestamp > consent.validUntil) {
            revert DisclosureConsentExpired(consent.scopeCommitment, consent.validUntil);
        }
        if (consent.disclosureVersion != core.policyVersion) {
            revert DisclosureVersionMismatch(consent.disclosureVersion, core.policyVersion);
        }
        if (consumedConsentNonce[consent.scopeCommitment][consent.nonce]) {
            revert ConsentNonceConsumed(consent.scopeCommitment, consent.nonce);
        }
        consumedConsentNonce[consent.scopeCommitment][consent.nonce] = true;

        bytes32 digest = _consentDigest(
            core.session.sessionCommitment,
            core.session.sessionNullifier,
            resultCommitment,
            sourceRecordCommitment,
            anchor,
            consent
        );
        address recovered = _recover(digest, consent.signature);
        if (recovered != controller) revert ConsentNotSignedByController(controller, recovered);
    }

    function _recover(bytes32 digest, bytes calldata signature)
        private
        pure
        returns (address signer)
    {
        if (signature.length != 65) revert MalformedSignature();
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) revert MalformedSignature();
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert MalformedSignature();
    }
}
