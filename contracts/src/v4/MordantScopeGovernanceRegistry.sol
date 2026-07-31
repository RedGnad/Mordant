// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Append-only scope governance, plus opaque bilateral session
/// commitments.
///
/// @dev Two problems are solved here, and they pull in opposite directions.
///
/// The first is temporal authority: an authority must not be created or replaced
/// after a private result is known and then applied to that result. That is
/// solved by versioned, immutable, never-back-dated records.
///
/// The second is pre-binding privacy: nothing about a session may be public
/// before both parties consent to disclose it. A session that publishes its two
/// governance records publishes the pairing of two organizations, which is
/// itself the sensitive fact. So a session is committed as ONE opaque hash and
/// nothing else. The pairing, the scopes, the controllers, the organizations and
/// the anchors all live in the preimage, which is revealed exactly once, at
/// binding, by the binder.
///
/// The two requirements meet in the commitment: the intent names the historical
/// governance records by digest, both controllers sign it before it is
/// committed, and at reveal every named record must have been authorized before
/// the commitment existed. Authority is therefore frozen in advance and proven
/// afterwards, without ever being announced in between.
///
/// The commitment binds the three authorization signatures as well as the intent
/// fields. Binding the intent alone would prove only that the FIELDS existed
/// beforehand, leaving room to commit a session and assemble bilateral consent
/// and issuer authorization for it afterwards. With the signature bundle inside
/// the preimage, the commitment proves that both controllers and the issuer had
/// already authorized this exact session when it was published.
///
/// PUBLIC METADATA, before binding, is exactly and only:
///
///   - the opaque session commitment;
///   - its timestamp and block number;
///   - the policy-authorized non-controller relayer address that submitted it.
///
/// Not public before binding: participants, scopes, governance records,
/// controllers, organizations, anchors, asset commitments, input commitments,
/// permissions, budgets or outcome.
///
/// A session that is committed and never bound leaves that metadata and nothing
/// else. It is a deliberate, irreducible residue: it shows that some two parties
/// ran some comparison, and nothing more. It does not identify them, does not
/// link to any anchor, and does not distinguish a negative result from a
/// declined disclosure.
contract MordantScopeGovernanceRegistry {
    error Unauthorized(address account);
    error InvalidAuthorization();
    error UnknownRecord(bytes32 recordDigest);
    error RecordExists(bytes32 recordDigest);
    error VersionNotSequential(uint32 supplied, uint32 expected);
    error NonceConsumed(bytes32 scopeCommitment, uint256 nonce);
    error AlreadyRetired(bytes32 recordDigest);
    error AlreadyHardRevoked(bytes32 recordDigest);
    error ControllerEmergencyRevoked(bytes32 recordDigest, uint64 hardRevokedAt);
    error RecordNotLiveAtCommitment(bytes32 recordDigest, uint64 committedAt);
    error RelayerNotAuthorized(address submitter);
    error RelayerIsController(address submitter);
    error CommitmentExists(bytes32 sessionCommitment);
    error UnknownCommitment(bytes32 sessionCommitment);
    error CommitmentConsumed(bytes32 sessionCommitment);
    error CommitmentMismatch(bytes32 recomputed, bytes32 supplied);
    error IntentExpired(uint64 expiry, uint256 currentTime);
    error WrongChain(uint256 supplied, uint256 current);
    error WrongRegistry(address supplied, address current);
    error SameScope(bytes32 scopeCommitment);
    error SameOrganization(bytes32 organizationId);
    error SameController(address controller);
    error IntentRecordMismatch(bytes32 recordDigest);
    error IntentNotBilateral(address expected, address recovered);
    error MalformedSignature();
    error InvalidIntent();

    event ScopeAuthorized(
        bytes32 indexed recordDigest,
        bytes32 indexed scopeCommitment,
        address indexed controller,
        bytes32 organizationId,
        uint32 controllerEpoch,
        uint32 authorizationVersion,
        uint64 validFrom
    );
    event ScopeRetired(bytes32 indexed recordDigest, uint64 retiredAt);
    event ScopeEmergencyRevoked(bytes32 indexed recordDigest, uint64 hardRevokedAt);
    event RelayerSet(address indexed relayer, bool allowed);
    event BinderSet(address indexed binder, bool allowed);

    /// @dev The only pre-binding artifact. One hash, one timestamp, one block.
    /// Deliberately carries no scope, no record, no controller, no organization,
    /// no anchor and no participant.
    event SessionCommitted(bytes32 indexed sessionCommitment, uint64 committedAt);
    /// @dev Emitted only at binding, when both parties have consented.
    event SessionRevealed(
        bytes32 indexed sessionCommitment,
        bytes32 indexed governanceRecordA,
        bytes32 indexed governanceRecordB,
        address binder
    );

    bytes32 private constant RECORD_DOMAIN = keccak256("mordant.scope-authorization/2");
    bytes32 private constant COMMITMENT_DOMAIN = keccak256("mordant.bilateral-session-commitment/2");
    bytes32 private constant SIGNATURE_DOMAIN = keccak256("mordant.session-initiation-signatures/1");
    string internal constant DOMAIN_NAME = "Mordant Bilateral Session Intent";
    string internal constant DOMAIN_VERSION = "1";

    bytes32 public constant INTENT_TYPEHASH = keccak256(
        "BilateralSessionIntent(uint256 chainId,address governanceRegistry,bytes32 policyId,uint32 policyVersion,bytes32 governanceRecordA,bytes32 governanceRecordB,bytes32 controllerKeyIdA,bytes32 controllerKeyIdB,uint32 controllerEpochA,uint32 controllerEpochB,uint32 scopeAuthorizationVersionA,uint32 scopeAuthorizationVersionB,bytes32 sourceRecordA,bytes32 sourceRecordB,bytes32 issuerKeyId,uint32 identityEpoch,bytes32 strictAssetCommitmentA,bytes32 supersedesCandidateSession,bool candidateAuthorized,uint32 exactBudget,uint32 candidateBudget,uint256 sessionNonce,uint64 expiry,uint32 disclosureVersion)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct ScopeAuthorization {
        bytes32 scopeCommitment;
        address controller;
        bytes32 controllerKeyId;
        bytes32 organizationId;
        uint32 controllerEpoch;
        uint32 authorizationVersion;
        uint64 validFrom;
        /// @dev Normal rotation. Closes the window forward. A session committed
        /// while the record was live is unaffected.
        uint64 retiredAt;
        /// @dev Emergency revocation. Terminal, and it reaches into unfinished
        /// sessions: a compromised key must not be able to consent or bind, even
        /// for a session committed before the compromise was noticed.
        uint64 hardRevokedAt;
        uint256 nonce;
        bool exists;
    }

    struct AuthorizationRequest {
        bytes32 scopeCommitment;
        address controller;
        bytes32 controllerKeyId;
        bytes32 organizationId;
        uint32 controllerEpoch;
        uint32 authorizationVersion;
        uint256 nonce;
    }

    /// @notice What both controllers and the issuer sign before a session exists.
    struct BilateralSessionIntent {
        uint256 chainId;
        address governanceRegistry;
        bytes32 policyId;
        uint32 policyVersion;
        bytes32 governanceRecordA;
        bytes32 governanceRecordB;
        bytes32 controllerKeyIdA;
        bytes32 controllerKeyIdB;
        uint32 controllerEpochA;
        uint32 controllerEpochB;
        uint32 scopeAuthorizationVersionA;
        uint32 scopeAuthorizationVersionB;
        /// @dev The two anchors. Side A is the tokenized receivable's source
        /// attestation digest; side B is a source-identity registration.
        bytes32 sourceRecordA;
        bytes32 sourceRecordB;
        /// @dev Issuer pre-authorization for side A's anchor, replacing the
        /// public pre-commitment. Same authority, same ordering, not announced.
        bytes32 issuerKeyId;
        uint32 identityEpoch;
        bytes32 strictAssetCommitmentA;
        bytes32 supersedesCandidateSession;
        bool candidateAuthorized;
        uint32 exactBudget;
        uint32 candidateBudget;
        uint256 sessionNonce;
        uint64 expiry;
        uint32 disclosureVersion;
    }

    /// @notice The three signatures that bring a session into existence.
    /// @dev Bundled into one calldata struct rather than three parameters: the
    /// outer frame then carries one pointer instead of three, which is what keeps
    /// `resolveSession` inside the stack limit.
    struct InitiationSignatures {
        bytes controllerA;
        bytes controllerB;
        bytes issuer;
    }

    struct SessionCommitment {
        uint64 committedAt;
        uint64 committedInBlock;
        address submitter;
        bool exists;
        bool consumed;
    }

    /// @notice What the binder learns at reveal. Nothing here was public before.
    struct ResolvedSession {
        bytes32 sessionCommitment;
        bytes32 governanceRecordA;
        bytes32 governanceRecordB;
        address controllerA;
        address controllerB;
        bytes32 sourceRecordA;
        bytes32 sourceRecordB;
        bytes32 strictAssetCommitmentA;
        bytes32 issuerKeyId;
        address issuerSigner;
        uint32 identityEpoch;
        uint64 committedAt;
    }

    address public immutable governor;

    mapping(bytes32 recordDigest => ScopeAuthorization) private _records;
    mapping(bytes32 scopeCommitment => uint32 version) public latestVersion;
    mapping(bytes32 scopeCommitment => mapping(uint32 version => bytes32 recordDigest)) public
        versionRecord;
    mapping(bytes32 scopeCommitment => mapping(uint256 nonce => bool used)) public consumedNonce;
    mapping(bytes32 sessionCommitment => SessionCommitment) private _commitments;
    mapping(address relayer => bool allowed) public authorizedRelayer;
    mapping(address binder => bool allowed) public authorizedBinder;

    modifier onlyGovernor() {
        if (msg.sender != governor) revert Unauthorized(msg.sender);
        _;
    }

    constructor(address initialGovernor) {
        if (initialGovernor == address(0)) revert InvalidAuthorization();
        governor = initialGovernor;
    }

    /* ------------------------------------------------------- authorization */

    /// @notice Appends one authorization record. Never edits an existing one.
    /// @dev `validFrom` is not a parameter. A record becomes valid at the block
    /// that creates it and not one second earlier, which is what makes
    /// retroactive authorization impossible rather than merely discouraged.
    function authorize(AuthorizationRequest calldata request)
        external
        onlyGovernor
        returns (bytes32 recordDigest)
    {
        if (
            request.scopeCommitment == bytes32(0) || request.controller == address(0)
                || request.controllerKeyId == bytes32(0) || request.organizationId == bytes32(0)
                || request.controllerEpoch == 0 || request.nonce == 0
        ) revert InvalidAuthorization();

        uint32 expected = latestVersion[request.scopeCommitment] + 1;
        if (request.authorizationVersion != expected) {
            revert VersionNotSequential(request.authorizationVersion, expected);
        }
        if (consumedNonce[request.scopeCommitment][request.nonce]) {
            revert NonceConsumed(request.scopeCommitment, request.nonce);
        }

        uint64 validFrom = uint64(block.timestamp);
        recordDigest = _recordDigest(request, validFrom);
        if (_records[recordDigest].exists) revert RecordExists(recordDigest);

        consumedNonce[request.scopeCommitment][request.nonce] = true;
        latestVersion[request.scopeCommitment] = request.authorizationVersion;
        versionRecord[request.scopeCommitment][request.authorizationVersion] = recordDigest;
        _records[recordDigest] = ScopeAuthorization({
            scopeCommitment: request.scopeCommitment,
            controller: request.controller,
            controllerKeyId: request.controllerKeyId,
            organizationId: request.organizationId,
            controllerEpoch: request.controllerEpoch,
            authorizationVersion: request.authorizationVersion,
            validFrom: validFrom,
            retiredAt: 0,
            hardRevokedAt: 0,
            nonce: request.nonce,
            exists: true
        });

        emit ScopeAuthorized(
            recordDigest,
            request.scopeCommitment,
            request.controller,
            request.organizationId,
            request.controllerEpoch,
            request.authorizationVersion,
            validFrom
        );
    }

    /// @notice Normal rotation: closes a record's window at the current time.
    /// @dev Forward-only and non-retroactive. A session committed while the
    /// record was live still resolves under it, so an orderly handover does not
    /// strand work in flight.
    function retire(bytes32 recordDigest) external onlyGovernor {
        ScopeAuthorization storage stored = _records[recordDigest];
        if (!stored.exists) revert UnknownRecord(recordDigest);
        if (stored.retiredAt != 0) revert AlreadyRetired(recordDigest);
        stored.retiredAt = uint64(block.timestamp);
        emit ScopeRetired(recordDigest, stored.retiredAt);
    }

    /// @notice Emergency revocation: the controller key is compromised.
    /// @dev Unlike retirement, this reaches into sessions already committed but
    /// not yet bound. Those parties must open a new session under replacement
    /// governance records. Terminal, and never back-dated.
    function emergencyRevoke(bytes32 recordDigest) external onlyGovernor {
        ScopeAuthorization storage stored = _records[recordDigest];
        if (!stored.exists) revert UnknownRecord(recordDigest);
        if (stored.hardRevokedAt != 0) revert AlreadyHardRevoked(recordDigest);
        stored.hardRevokedAt = uint64(block.timestamp);
        if (stored.retiredAt == 0) stored.retiredAt = uint64(block.timestamp);
        emit ScopeEmergencyRevoked(recordDigest, stored.hardRevokedAt);
    }

    /// @notice Registers a policy-authorized non-controller relayer.
    /// @dev "Policy-authorized non-controller", not "neutral": this is an
    /// allowlist decision by the governor, not a cryptographic or organizational
    /// guarantee. All it establishes is that the sender of a commitment
    /// transaction is not, by policy and by the reveal-time check, one of the two
    /// controllers of that session.
    function setAuthorizedRelayer(address relayer, bool allowed) external onlyGovernor {
        if (relayer == address(0)) revert InvalidAuthorization();
        authorizedRelayer[relayer] = allowed;
        emit RelayerSet(relayer, allowed);
    }

    function setAuthorizedBinder(address binder, bool allowed) external onlyGovernor {
        if (binder == address(0)) revert InvalidAuthorization();
        authorizedBinder[binder] = allowed;
        emit BinderSet(binder, allowed);
    }

    /* ---------------------------------------------------------- commitment */

    /// @notice Publishes one opaque bilateral session commitment.
    /// @dev The relayer receives only this 32-byte value. It never needs the
    /// intent, the salt or the signatures, and cannot derive them from the
    /// commitment, so relaying carries no knowledge of the session.
    ///
    /// The sender must be a policy-authorized non-controller relayer. If a
    /// participant posted its own commitments, the sender address would
    /// re-identify one side of every session, which is the leak the commitment
    /// exists to prevent.
    function commitSession(bytes32 sessionCommitment) external {
        if (!authorizedRelayer[msg.sender]) revert RelayerNotAuthorized(msg.sender);
        if (sessionCommitment == bytes32(0)) revert InvalidIntent();
        if (_commitments[sessionCommitment].exists) revert CommitmentExists(sessionCommitment);
        _commitments[sessionCommitment] = SessionCommitment({
            committedAt: uint64(block.timestamp),
            committedInBlock: uint64(block.number),
            submitter: msg.sender,
            exists: true,
            consumed: false
        });
        emit SessionCommitted(sessionCommitment, uint64(block.timestamp));
    }

    /// @notice When a commitment was published, or zero if it never was.
    /// @dev The only public fact about a session before binding. It answers
    /// "did this exist beforehand" without answering "who" or "about what".
    function committedAt(bytes32 sessionCommitment) external view returns (uint64) {
        return _commitments[sessionCommitment].committedAt;
    }

    function commitment(bytes32 sessionCommitment) external view returns (SessionCommitment memory) {
        return _commitments[sessionCommitment];
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

    function intentHash(BilateralSessionIntent calldata intent) public pure returns (bytes32) {
        bytes32 authority = keccak256(
            abi.encode(
                intent.governanceRecordA,
                intent.governanceRecordB,
                intent.controllerKeyIdA,
                intent.controllerKeyIdB,
                intent.controllerEpochA,
                intent.controllerEpochB,
                intent.scopeAuthorizationVersionA,
                intent.scopeAuthorizationVersionB
            )
        );
        bytes32 anchors = keccak256(
            abi.encode(
                intent.sourceRecordA,
                intent.sourceRecordB,
                intent.issuerKeyId,
                intent.identityEpoch,
                intent.strictAssetCommitmentA,
                intent.supersedesCandidateSession
            )
        );
        bytes32 permissions = keccak256(
            abi.encode(
                intent.candidateAuthorized,
                intent.exactBudget,
                intent.candidateBudget,
                intent.sessionNonce,
                intent.expiry,
                intent.disclosureVersion
            )
        );
        return keccak256(
            abi.encode(
                INTENT_TYPEHASH,
                intent.chainId,
                intent.governanceRegistry,
                intent.policyId,
                intent.policyVersion,
                authority,
                anchors,
                permissions
            )
        );
    }

    function intentDigest(BilateralSessionIntent calldata intent) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), intentHash(intent)));
    }

    /// @notice Canonical digest of the three authorization signatures.
    /// @dev Order is fixed (controller A, controller B, issuer), so swapping two
    /// signatures produces a different bundle and therefore a different session.
    function signatureBundleDigest(InitiationSignatures calldata signatures)
        public
        pure
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                SIGNATURE_DOMAIN,
                keccak256(signatures.controllerA),
                keccak256(signatures.controllerB),
                keccak256(signatures.issuer)
            )
        );
    }

    /// @notice Recomputed from the preimage. Never asserted by a caller.
    /// @dev The signature bundle is inside the preimage, so the commitment proves
    /// that bilateral initiation and issuer authorization already existed when it
    /// was published, not merely that the intent fields did.
    function sessionCommitmentOf(
        BilateralSessionIntent calldata intent,
        InitiationSignatures calldata signatures,
        bytes32 salt
    ) public view returns (bytes32) {
        return keccak256(
            abi.encode(
                COMMITMENT_DOMAIN,
                block.chainid,
                address(this),
                intentHash(intent),
                signatureBundleDigest(signatures),
                salt
            )
        );
    }

    /* -------------------------------------------------------------- reveal */

    /// @notice Opens one committed session, once, for an authorized binder.
    /// @dev Callable only by a registered binder. Reveal is the moment the
    /// pairing becomes public, so it must not be something a bystander can force.
    function resolveSession(
        BilateralSessionIntent calldata intent,
        bytes32 salt,
        InitiationSignatures calldata signatures
    ) external returns (ResolvedSession memory resolved) {
        if (!authorizedBinder[msg.sender]) revert Unauthorized(msg.sender);
        if (intent.chainId != block.chainid) revert WrongChain(intent.chainId, block.chainid);
        if (intent.governanceRegistry != address(this)) {
            revert WrongRegistry(intent.governanceRegistry, address(this));
        }
        if (block.timestamp > intent.expiry) revert IntentExpired(intent.expiry, block.timestamp);

        bytes32 key = sessionCommitmentOf(intent, signatures, salt);
        SessionCommitment storage stored = _commitments[key];
        if (!stored.exists) revert UnknownCommitment(key);
        if (stored.consumed) revert CommitmentConsumed(key);

        (address controllerA, address controllerB) =
            _checkedControllers(intent, stored.committedAt);
        // The allowlist is a policy statement, not proof. If the relayer turns
        // out to be one of the two controllers, the session cannot be opened.
        if (stored.submitter == controllerA || stored.submitter == controllerB) {
            revert RelayerIsController(stored.submitter);
        }

        stored.consumed = true;
        resolved = _resolved(
            intent,
            key,
            stored.committedAt,
            controllerA,
            controllerB,
            _initiationSigner(intent, controllerA, controllerB, signatures)
        );
        emit SessionRevealed(key, intent.governanceRecordA, intent.governanceRecordB, msg.sender);
    }

    function record(bytes32 recordDigest) external view returns (ScopeAuthorization memory) {
        return _requireRecord(recordDigest);
    }

    function isLiveAt(bytes32 recordDigest, uint64 at) external view returns (bool) {
        ScopeAuthorization memory stored = _records[recordDigest];
        return stored.exists && _isLiveAt(stored, at);
    }

    /* ------------------------------------------------------------ internals */

    /// @dev Both records must exist, must be the two distinct sides of a genuine
    /// bilateral pair, must match what the intent claims about them, must have
    /// been authorized before the commitment was published, and must not be
    /// emergency-revoked now.
    function _checkedControllers(BilateralSessionIntent calldata intent, uint64 at)
        private
        view
        returns (address, address)
    {
        ScopeAuthorization memory a = _requireRecord(intent.governanceRecordA);
        ScopeAuthorization memory b = _requireRecord(intent.governanceRecordB);
        if (a.scopeCommitment == b.scopeCommitment) revert SameScope(a.scopeCommitment);
        if (a.organizationId == b.organizationId) revert SameOrganization(a.organizationId);
        if (a.controller == b.controller) revert SameController(a.controller);

        if (
            a.controllerKeyId != intent.controllerKeyIdA
                || a.controllerEpoch != intent.controllerEpochA
                || a.authorizationVersion != intent.scopeAuthorizationVersionA
        ) revert IntentRecordMismatch(intent.governanceRecordA);
        if (
            b.controllerKeyId != intent.controllerKeyIdB
                || b.controllerEpoch != intent.controllerEpochB
                || b.authorizationVersion != intent.scopeAuthorizationVersionB
        ) revert IntentRecordMismatch(intent.governanceRecordB);

        if (a.hardRevokedAt != 0) revert ControllerEmergencyRevoked(intent.governanceRecordA, a.hardRevokedAt);
        if (b.hardRevokedAt != 0) revert ControllerEmergencyRevoked(intent.governanceRecordB, b.hardRevokedAt);
        if (!_isLiveAt(a, at)) revert RecordNotLiveAtCommitment(intent.governanceRecordA, at);
        if (!_isLiveAt(b, at)) revert RecordNotLiveAtCommitment(intent.governanceRecordB, at);
        return (a.controller, b.controller);
    }

    /// @dev Both controllers must sign the identical intent. One party alone
    /// cannot bring a bilateral comparison into existence, which is what stops a
    /// unilateral session being announced about someone who never agreed to it.
    function _initiationSigner(
        BilateralSessionIntent calldata intent,
        address controllerA,
        address controllerB,
        InitiationSignatures calldata signatures
    ) private view returns (address issuerSigner) {
        bytes32 digest = intentDigest(intent);
        address recoveredA = _recover(digest, signatures.controllerA);
        if (recoveredA != controllerA) revert IntentNotBilateral(controllerA, recoveredA);
        address recoveredB = _recover(digest, signatures.controllerB);
        if (recoveredB != controllerB) revert IntentNotBilateral(controllerB, recoveredB);
        issuerSigner = _recover(digest, signatures.issuer);
    }

    /// @dev Split out only to keep the stack shallow.
    function _resolved(
        BilateralSessionIntent calldata intent,
        bytes32 key,
        uint64 at,
        address controllerA,
        address controllerB,
        address issuerSigner
    ) private pure returns (ResolvedSession memory) {
        return ResolvedSession({
            sessionCommitment: key,
            governanceRecordA: intent.governanceRecordA,
            governanceRecordB: intent.governanceRecordB,
            controllerA: controllerA,
            controllerB: controllerB,
            sourceRecordA: intent.sourceRecordA,
            sourceRecordB: intent.sourceRecordB,
            strictAssetCommitmentA: intent.strictAssetCommitmentA,
            issuerKeyId: intent.issuerKeyId,
            issuerSigner: issuerSigner,
            identityEpoch: intent.identityEpoch,
            committedAt: at
        });
    }

    function _requireRecord(bytes32 recordDigest)
        private
        view
        returns (ScopeAuthorization memory stored)
    {
        stored = _records[recordDigest];
        if (!stored.exists) revert UnknownRecord(recordDigest);
    }

    function _isLiveAt(ScopeAuthorization memory stored, uint64 at) private pure returns (bool) {
        return at >= stored.validFrom && (stored.retiredAt == 0 || at < stored.retiredAt);
    }

    /// @dev Split into two halves to keep the stack shallow.
    function _recordDigest(AuthorizationRequest calldata request, uint64 validFrom)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                abi.encode(
                    RECORD_DOMAIN,
                    block.chainid,
                    address(this),
                    request.scopeCommitment,
                    request.controller
                ),
                abi.encode(
                    request.controllerKeyId,
                    request.organizationId,
                    request.controllerEpoch,
                    request.authorizationVersion,
                    validFrom,
                    request.nonce
                )
            )
        );
    }

    function _recover(bytes32 digest, bytes calldata signature) private pure returns (address signer) {
        if (signature.length != 65) revert MalformedSignature();
        bytes32 r = bytes32(signature[0:32]);
        bytes32 s = bytes32(signature[32:64]);
        uint8 v = uint8(signature[64]);
        if (uint256(s) > SECP256K1_HALF_ORDER || (v != 27 && v != 28)) revert MalformedSignature();
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert MalformedSignature();
    }
}
