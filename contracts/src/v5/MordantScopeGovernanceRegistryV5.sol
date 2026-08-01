// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice RC2 scope governance and opaque bilateral session admission.
///
/// @dev Three external audit findings are corrected here, and each of them was
/// a case of the V4 registry being unable to order two things it claimed to
/// order.
///
/// **M-02, session one-shot.** V4 signed a `sessionNonce` and per-session
/// budgets but consumed neither. Because the commitment also took a free salt,
/// one signed intent and its three signatures produced unlimited distinct
/// commitments, each accepted as a fresh session. RC2 derives a nullifier from
/// the intent WITHOUT the salt and consumes it at commitment admission, so the
/// same authorization admits exactly one session however the salt is chosen.
///
/// **M-03/M-04, chronology.** V4 compared `block.timestamp` values, which are
/// identical for every operation in a block. A relayer contract could commit a
/// session and register a source in one transaction and satisfy
/// `registeredAt <= committedAt`; and a normal retirement in the commit block
/// made `committedAt == retiredAt`, stranding a session the comment promised
/// would survive. RC2 records block numbers and compares them strictly, so
/// same-block ambiguity fails closed in both directions.
///
/// The opaque-commitment property from V4 is preserved: a session is one hash
/// plus its metadata, and the pairing lives in a preimage revealed once, at
/// binding, by an authorized binder.
contract MordantScopeGovernanceRegistryV5 {
    error Unauthorized(address account);
    error InvalidAuthorization();
    error UnknownRecord(bytes32 recordDigest);
    error RecordExists(bytes32 recordDigest);
    error VersionNotSequential(uint32 supplied, uint32 expected);
    error NonceConsumed(bytes32 scopeCommitment, uint256 nonce);
    error AlreadyRetired(bytes32 recordDigest);
    error AlreadyHardRevoked(bytes32 recordDigest);
    error ControllerEmergencyRevoked(bytes32 recordDigest, uint64 hardRevokedAtBlock);
    error RecordNotLiveAtBlock(bytes32 recordDigest, uint64 blockNumber);
    error RecordNotStrictlyBeforeCommitment(bytes32 recordDigest, uint64 recordBlock, uint64 commitBlock);
    error RelayerNotAuthorized(address submitter);
    error RelayerIsController(address submitter);
    error CommitmentExists(bytes32 sessionCommitment);
    error UnknownCommitment(bytes32 sessionCommitment);
    error CommitmentConsumed(bytes32 sessionCommitment);
    error NullifierConsumed(bytes32 sessionNullifier);
    error NullifierMismatch(bytes32 recomputed, bytes32 published);
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
        uint64 validFromBlock
    );
    event ScopeRetired(bytes32 indexed recordDigest, uint64 retiredAtBlock);
    event ScopeEmergencyRevoked(bytes32 indexed recordDigest, uint64 hardRevokedAtBlock);
    event RelayerSet(address indexed relayer, bool allowed);
    event BinderSet(address indexed binder, bool allowed);

    /// @dev The only pre-binding artifact. Both values are opaque: the nullifier
    /// is a hash over the governance records and a high-entropy session nonce,
    /// so publishing it orders the session without naming its participants.
    event SessionCommitted(
        bytes32 indexed sessionCommitment,
        bytes32 indexed sessionNullifier,
        uint64 committedAt,
        uint64 committedInBlock
    );
    event SessionRevealed(
        bytes32 indexed sessionCommitment,
        bytes32 indexed governanceRecordA,
        bytes32 indexed governanceRecordB,
        address binder
    );

    bytes32 private constant RECORD_DOMAIN = keccak256("mordant.scope-authorization/3");
    bytes32 private constant COMMITMENT_DOMAIN = keccak256("mordant.bilateral-session-commitment/3");
    bytes32 private constant SIGNATURE_DOMAIN = keccak256("mordant.session-initiation-signatures/2");
    bytes32 private constant NULLIFIER_DOMAIN = keccak256("mordant.session-nullifier/1");
    string internal constant DOMAIN_NAME = "Mordant Bilateral Session Intent";
    string internal constant DOMAIN_VERSION = "2";

    bytes32 public constant INTENT_TYPEHASH = keccak256(
        "BilateralSessionIntentV5(uint256 chainId,address governanceRegistry,bytes32 policyId,uint32 policyVersion,bytes32 governanceRecordA,bytes32 governanceRecordB,bytes32 controllerKeyIdA,bytes32 controllerKeyIdB,uint32 controllerEpochA,uint32 controllerEpochB,uint32 scopeAuthorizationVersionA,uint32 scopeAuthorizationVersionB,bytes32 sourceRecordCommitmentA,bytes32 sourceRecordCommitmentB,bytes32 scopeCommitmentA,bytes32 scopeCommitmentB,bytes32 issuerKeyId,uint32 identityEpoch,bytes32 strictAssetCommitmentA,bool candidateAuthorized,uint32 exactBudget,uint32 candidateBudget,uint256 sessionNonce,uint64 expiry,uint32 disclosureVersion)"
    );
    bytes32 private constant EIP712_DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    uint256 private constant SECP256K1_HALF_ORDER =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    struct ScopeAuthorization {
        bytes32 scopeCommitment;
        address controller;
        bytes32 controllerKeyId;
        bytes32 organizationId;
        uint32 controllerEpoch;
        uint32 authorizationVersion;
        /// @dev Block numbers, not timestamps. Two operations in one block share
        /// a timestamp and cannot be ordered by it.
        uint64 validFromBlock;
        uint64 retiredAtBlock;
        uint64 hardRevokedAtBlock;
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
    /// @dev Side B is now a source-record COMMITMENT rather than a registration
    /// id, so the intent itself names nothing correlatable (finding C-01). Both
    /// scope commitments are carried explicitly so each enrollment can bind its
    /// own scope and its expected counterparty (finding H-01).
    struct BilateralSessionIntentV5 {
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
        bytes32 sourceRecordCommitmentA;
        bytes32 sourceRecordCommitmentB;
        bytes32 scopeCommitmentA;
        bytes32 scopeCommitmentB;
        bytes32 issuerKeyId;
        uint32 identityEpoch;
        bytes32 strictAssetCommitmentA;
        bool candidateAuthorized;
        uint32 exactBudget;
        uint32 candidateBudget;
        uint256 sessionNonce;
        uint64 expiry;
        uint32 disclosureVersion;
    }

    struct InitiationSignatures {
        bytes controllerA;
        bytes controllerB;
        bytes issuer;
    }

    struct SessionCommitment {
        bytes32 sessionNullifier;
        uint64 committedAt;
        uint64 committedInBlock;
        address submitter;
        bool exists;
        bool consumed;
    }

    struct ResolvedSession {
        bytes32 sessionCommitment;
        bytes32 sessionNullifier;
        bytes32 governanceRecordA;
        bytes32 governanceRecordB;
        address controllerA;
        address controllerB;
        bytes32 scopeCommitmentA;
        bytes32 scopeCommitmentB;
        bytes32 sourceRecordCommitmentA;
        bytes32 sourceRecordCommitmentB;
        bytes32 strictAssetCommitmentA;
        bytes32 issuerKeyId;
        address issuerSigner;
        uint32 identityEpoch;
        uint64 committedAt;
        uint64 committedInBlock;
    }

    address public immutable governor;

    mapping(bytes32 recordDigest => ScopeAuthorization) private _records;
    mapping(bytes32 scopeCommitment => uint32 version) public latestVersion;
    mapping(bytes32 scopeCommitment => mapping(uint32 version => bytes32 recordDigest)) public
        versionRecord;
    mapping(bytes32 scopeCommitment => mapping(uint256 nonce => bool used)) public consumedNonce;
    mapping(bytes32 sessionCommitment => SessionCommitment) private _commitments;
    /// @dev Finding M-02. One signed intent admits exactly one session.
    mapping(bytes32 sessionNullifier => bool used) public consumedNullifier;
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
    /// @dev `validFromBlock` is not a parameter. A record becomes valid in the
    /// block that creates it, which is what makes retroactive authorization
    /// impossible rather than merely discouraged.
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

        uint64 validFromBlock = uint64(block.number);
        recordDigest = _recordDigest(request, validFromBlock);
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
            validFromBlock: validFromBlock,
            retiredAtBlock: 0,
            hardRevokedAtBlock: 0,
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
            validFromBlock
        );
    }

    /// @notice Normal rotation: closes a record's window at the current block.
    /// @dev Forward-only. A session committed in a STRICTLY EARLIER block still
    /// resolves under it, so an orderly handover does not strand work in flight.
    function retire(bytes32 recordDigest) external onlyGovernor {
        ScopeAuthorization storage stored = _records[recordDigest];
        if (!stored.exists) revert UnknownRecord(recordDigest);
        if (stored.retiredAtBlock != 0) revert AlreadyRetired(recordDigest);
        stored.retiredAtBlock = uint64(block.number);
        emit ScopeRetired(recordDigest, stored.retiredAtBlock);
    }

    /// @notice Emergency revocation: the controller key is compromised.
    /// @dev Unlike retirement, this reaches into sessions already committed but
    /// not yet bound. Terminal, and never back-dated.
    function emergencyRevoke(bytes32 recordDigest) external onlyGovernor {
        ScopeAuthorization storage stored = _records[recordDigest];
        if (!stored.exists) revert UnknownRecord(recordDigest);
        if (stored.hardRevokedAtBlock != 0) revert AlreadyHardRevoked(recordDigest);
        stored.hardRevokedAtBlock = uint64(block.number);
        if (stored.retiredAtBlock == 0) stored.retiredAtBlock = uint64(block.number);
        emit ScopeEmergencyRevoked(recordDigest, stored.hardRevokedAtBlock);
    }

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

    /// @notice Publishes one opaque session commitment and its nullifier.
    /// @dev The relayer receives only these two 32-byte values and cannot derive
    /// the intent, the salt or the signatures from either.
    ///
    /// The nullifier is consumed HERE, at admission, not at reveal. Consuming it
    /// at reveal would still allow unlimited private evaluations under one
    /// authorization, which is exactly the probing surface finding M-02 named.
    function commitSession(bytes32 sessionCommitment, bytes32 sessionNullifier) external {
        if (!authorizedRelayer[msg.sender]) revert RelayerNotAuthorized(msg.sender);
        if (sessionCommitment == bytes32(0) || sessionNullifier == bytes32(0)) revert InvalidIntent();
        if (_commitments[sessionCommitment].exists) revert CommitmentExists(sessionCommitment);
        if (consumedNullifier[sessionNullifier]) revert NullifierConsumed(sessionNullifier);

        consumedNullifier[sessionNullifier] = true;
        _commitments[sessionCommitment] = SessionCommitment({
            sessionNullifier: sessionNullifier,
            committedAt: uint64(block.timestamp),
            committedInBlock: uint64(block.number),
            submitter: msg.sender,
            exists: true,
            consumed: false
        });
        emit SessionCommitted(
            sessionCommitment, sessionNullifier, uint64(block.timestamp), uint64(block.number)
        );
    }

    function committedInBlock(bytes32 sessionCommitment) external view returns (uint64) {
        return _commitments[sessionCommitment].committedInBlock;
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

    function intentHash(BilateralSessionIntentV5 calldata intent) public pure returns (bytes32) {
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
                intent.sourceRecordCommitmentA,
                intent.sourceRecordCommitmentB,
                intent.scopeCommitmentA,
                intent.scopeCommitmentB,
                intent.issuerKeyId,
                intent.identityEpoch,
                intent.strictAssetCommitmentA
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

    function intentDigest(BilateralSessionIntentV5 calldata intent) public view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator(), intentHash(intent)));
    }

    /// @notice The one-shot identity of a signed intent.
    /// @dev Deliberately excludes the salt. Changing the salt changes the
    /// commitment but NOT the nullifier, so one authorization admits one session
    /// however many commitments a holder of the signatures can construct.
    ///
    /// It stays opaque: the preimage is two record digests, an issuer key id and
    /// a high-entropy session nonce, so publishing it names no participant.
    function sessionNullifierOf(BilateralSessionIntentV5 calldata intent)
        public
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encode(
                NULLIFIER_DOMAIN,
                block.chainid,
                address(this),
                intent.issuerKeyId,
                intent.governanceRecordA,
                intent.governanceRecordB,
                intent.sessionNonce
            )
        );
    }

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

    function sessionCommitmentOf(
        BilateralSessionIntentV5 calldata intent,
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
    function resolveSession(
        BilateralSessionIntentV5 calldata intent,
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
        // The published nullifier must be the one this intent derives, so a
        // commitment cannot be admitted under one authorization and revealed
        // under another.
        bytes32 nullifier = sessionNullifierOf(intent);
        if (stored.sessionNullifier != nullifier) {
            revert NullifierMismatch(nullifier, stored.sessionNullifier);
        }

        (address controllerA, address controllerB) =
            _checkedControllers(intent, stored.committedInBlock);
        if (stored.submitter == controllerA || stored.submitter == controllerB) {
            revert RelayerIsController(stored.submitter);
        }

        address issuerSigner = _initiationSigner(intent, controllerA, controllerB, signatures);
        stored.consumed = true;
        resolved = _resolved(intent, key, nullifier, controllerA, controllerB, issuerSigner);
        resolved.committedAt = stored.committedAt;
        resolved.committedInBlock = stored.committedInBlock;
        emit SessionRevealed(key, intent.governanceRecordA, intent.governanceRecordB, msg.sender);
    }

    function record(bytes32 recordDigest) external view returns (ScopeAuthorization memory) {
        return _requireRecord(recordDigest);
    }

    /// @notice Whether a record was live in a given block.
    /// @dev Strictly before the commitment block, and not retired on or before
    /// it. Same-block coincidence fails closed at both ends.
    function isLiveForCommitmentInBlock(bytes32 recordDigest, uint64 commitBlock)
        external
        view
        returns (bool)
    {
        ScopeAuthorization memory stored = _records[recordDigest];
        return stored.exists && _isLiveForCommitmentInBlock(stored, commitBlock);
    }

    /* ------------------------------------------------------------ internals */

    function _checkedControllers(BilateralSessionIntentV5 calldata intent, uint64 commitBlock)
        private
        view
        returns (address, address)
    {
        ScopeAuthorization memory a = _requireRecord(intent.governanceRecordA);
        ScopeAuthorization memory b = _requireRecord(intent.governanceRecordB);
        if (a.scopeCommitment == b.scopeCommitment) revert SameScope(a.scopeCommitment);
        if (a.organizationId == b.organizationId) revert SameOrganization(a.organizationId);
        if (a.controller == b.controller) revert SameController(a.controller);

        // The intent names each side's scope explicitly, and it must be the
        // scope the record actually authorizes.
        if (
            a.controllerKeyId != intent.controllerKeyIdA
                || a.controllerEpoch != intent.controllerEpochA
                || a.authorizationVersion != intent.scopeAuthorizationVersionA
                || a.scopeCommitment != intent.scopeCommitmentA
        ) revert IntentRecordMismatch(intent.governanceRecordA);
        if (
            b.controllerKeyId != intent.controllerKeyIdB
                || b.controllerEpoch != intent.controllerEpochB
                || b.authorizationVersion != intent.scopeAuthorizationVersionB
                || b.scopeCommitment != intent.scopeCommitmentB
        ) revert IntentRecordMismatch(intent.governanceRecordB);

        if (a.hardRevokedAtBlock != 0) {
            revert ControllerEmergencyRevoked(intent.governanceRecordA, a.hardRevokedAtBlock);
        }
        if (b.hardRevokedAtBlock != 0) {
            revert ControllerEmergencyRevoked(intent.governanceRecordB, b.hardRevokedAtBlock);
        }
        if (!_isLiveForCommitmentInBlock(a, commitBlock)) {
            revert RecordNotStrictlyBeforeCommitment(intent.governanceRecordA, a.validFromBlock, commitBlock);
        }
        if (!_isLiveForCommitmentInBlock(b, commitBlock)) {
            revert RecordNotStrictlyBeforeCommitment(intent.governanceRecordB, b.validFromBlock, commitBlock);
        }
        return (a.controller, b.controller);
    }

    function _initiationSigner(
        BilateralSessionIntentV5 calldata intent,
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

    /// @dev Split out purely to keep the stack shallow; the commitment's block
    /// metadata is attached by the caller.
    function _resolved(
        BilateralSessionIntentV5 calldata intent,
        bytes32 key,
        bytes32 nullifier,
        address controllerA,
        address controllerB,
        address issuerSigner
    ) private pure returns (ResolvedSession memory) {
        return ResolvedSession({
            sessionCommitment: key,
            sessionNullifier: nullifier,
            governanceRecordA: intent.governanceRecordA,
            governanceRecordB: intent.governanceRecordB,
            controllerA: controllerA,
            controllerB: controllerB,
            scopeCommitmentA: intent.scopeCommitmentA,
            scopeCommitmentB: intent.scopeCommitmentB,
            sourceRecordCommitmentA: intent.sourceRecordCommitmentA,
            sourceRecordCommitmentB: intent.sourceRecordCommitmentB,
            strictAssetCommitmentA: intent.strictAssetCommitmentA,
            issuerKeyId: intent.issuerKeyId,
            issuerSigner: issuerSigner,
            identityEpoch: intent.identityEpoch,
            committedAt: 0,
            committedInBlock: 0
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

    /// @dev Strict on both sides. A record authorized in the commitment block is
    /// not earlier than the commitment, and a record retired in the commitment
    /// block was not still live when the commitment landed.
    function _isLiveForCommitmentInBlock(ScopeAuthorization memory stored, uint64 commitBlock)
        private
        pure
        returns (bool)
    {
        if (stored.validFromBlock >= commitBlock) return false;
        if (stored.retiredAtBlock != 0 && stored.retiredAtBlock <= commitBlock) return false;
        return true;
    }

    function _recordDigest(AuthorizationRequest calldata request, uint64 validFromBlock)
        private
        view
        returns (bytes32)
    {
        return keccak256(
            abi.encodePacked(
                abi.encode(
                    RECORD_DOMAIN, block.chainid, address(this), request.scopeCommitment, request.controller
                ),
                abi.encode(
                    request.controllerKeyId,
                    request.organizationId,
                    request.controllerEpoch,
                    request.authorizationVersion,
                    validFromBlock,
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
