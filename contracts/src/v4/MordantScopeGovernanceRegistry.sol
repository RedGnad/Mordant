// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

/// @notice Append-only, versioned scope governance: who was authorized to act
/// for a scope, and when.
///
/// @dev This replaces the binder's mutable owner-set controller mapping and the
/// verifier's mutable scope allowlist. Both had the same defect: an authority
/// could be chosen or replaced AFTER a private result was known and then become
/// valid for that earlier session. That is the same temporal integrity failure
/// as post-match anchor mapping, and it is closed the same way, by freezing the
/// authority before the fact and never letting a later action reach backwards.
///
/// Three properties do the work:
///
///   1. `validFrom` is always the authorizing block's timestamp. There is no
///      parameter for it, so a record can never be back-dated.
///   2. Records are immutable once written. Rotation appends a new version;
///      it does not edit the old one. Retirement only ever closes a window at
///      the current time, so a historical window cannot be erased.
///   3. A session freezes exactly two records at initiation. Every later step
///      resolves authority through those frozen records, never through the
///      registry's current head.
///
/// The governor is therefore able to change who acts for a scope in the future,
/// and is structurally unable to change who acted for a session already opened.
contract MordantScopeGovernanceRegistry {
    error Unauthorized(address account);
    error InvalidAuthorization();
    error UnknownRecord(bytes32 recordDigest);
    error RecordExists(bytes32 recordDigest);
    error VersionNotSequential(uint32 supplied, uint32 expected);
    error NonceConsumed(bytes32 scopeCommitment, uint256 nonce);
    error AlreadyRetired(bytes32 recordDigest);
    error RecordNotLive(bytes32 recordDigest, uint64 at);
    error SessionAlreadyOpened(bytes32 sessionId);
    error SessionNotOpened(bytes32 sessionId);
    error SameScope(bytes32 scopeCommitment);
    error SameOrganization(bytes32 organizationId);
    error NotAController(address account);

    event ScopeAuthorized(
        bytes32 indexed recordDigest,
        bytes32 indexed scopeCommitment,
        address indexed controller,
        bytes32 organizationId,
        uint32 controllerEpoch,
        uint32 authorizationVersion,
        uint64 validFrom
    );
    event ScopeRetired(bytes32 indexed recordDigest, bytes32 indexed scopeCommitment, uint64 retiredAt);
    event SessionOpened(
        bytes32 indexed sessionId,
        bytes32 indexed recordA,
        bytes32 indexed recordB,
        bytes32 contextDigest,
        uint64 openedAt
    );

    bytes32 private constant RECORD_DOMAIN = keccak256("mordant.scope-authorization/1");
    bytes32 private constant CONTEXT_DOMAIN = keccak256("mordant.session-governance-context/1");

    struct ScopeAuthorization {
        bytes32 scopeCommitment;
        address controller;
        /// @dev Stable identity of the controlling organization's key, so an
        /// address rotation inside one organization is distinguishable from a
        /// change of organization.
        bytes32 controllerKeyId;
        bytes32 organizationId;
        uint32 controllerEpoch;
        uint32 authorizationVersion;
        uint64 validFrom;
        /// @dev Zero while live. Never back-dated.
        uint64 retiredAt;
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

    /// @notice The authority frozen for one bilateral session at initiation.
    struct SessionGovernance {
        bytes32 recordA;
        bytes32 recordB;
        uint64 openedAt;
        bytes32 contextDigest;
        bool opened;
    }

    address public immutable governor;

    mapping(bytes32 recordDigest => ScopeAuthorization) private _records;
    mapping(bytes32 scopeCommitment => uint32 version) public latestVersion;
    mapping(bytes32 scopeCommitment => mapping(uint32 version => bytes32 recordDigest)) public
        versionRecord;
    mapping(bytes32 scopeCommitment => mapping(uint256 nonce => bool used)) public consumedNonce;
    mapping(bytes32 sessionId => SessionGovernance) private _sessions;

    modifier onlyGovernor() {
        if (msg.sender != governor) revert Unauthorized(msg.sender);
        _;
    }

    constructor(address initialGovernor) {
        if (initialGovernor == address(0)) revert InvalidAuthorization();
        governor = initialGovernor;
    }

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
        recordDigest = _digest(request, validFrom);
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

    /// @notice Closes a record's validity window at the current time.
    /// @dev Retirement is forward-only and terminal. It cannot shorten a window
    /// that has already been used to open a session, because sessions resolve
    /// authority at their own `openedAt`, which is in the past.
    function retire(bytes32 recordDigest) external onlyGovernor {
        ScopeAuthorization storage stored = _records[recordDigest];
        if (!stored.exists) revert UnknownRecord(recordDigest);
        if (stored.retiredAt != 0) revert AlreadyRetired(recordDigest);
        stored.retiredAt = uint64(block.timestamp);
        emit ScopeRetired(recordDigest, stored.scopeCommitment, stored.retiredAt);
    }

    /// @notice Freezes the two authorities for one bilateral session.
    /// @dev Callable only by one of the two controllers, and only once per
    /// session. After this returns, no governor action can change who is
    /// authorized for this session.
    function openSession(bytes32 sessionId, bytes32 recordA, bytes32 recordB)
        external
        returns (bytes32 contextDigest)
    {
        if (sessionId == bytes32(0)) revert InvalidAuthorization();
        if (_sessions[sessionId].opened) revert SessionAlreadyOpened(sessionId);

        ScopeAuthorization memory a = _requireRecord(recordA);
        ScopeAuthorization memory b = _requireRecord(recordB);
        uint64 openedAt = uint64(block.timestamp);
        if (!_isLiveAt(a, openedAt)) revert RecordNotLive(recordA, openedAt);
        if (!_isLiveAt(b, openedAt)) revert RecordNotLive(recordB, openedAt);
        if (a.scopeCommitment == b.scopeCommitment) revert SameScope(a.scopeCommitment);
        // A conflict between two scopes of one organization is a self-match.
        if (a.organizationId == b.organizationId) revert SameOrganization(a.organizationId);
        if (msg.sender != a.controller && msg.sender != b.controller) {
            revert NotAController(msg.sender);
        }

        contextDigest = keccak256(
            abi.encode(
                CONTEXT_DOMAIN, block.chainid, address(this), sessionId, recordA, recordB, openedAt
            )
        );
        _sessions[sessionId] = SessionGovernance({
            recordA: recordA,
            recordB: recordB,
            openedAt: openedAt,
            contextDigest: contextDigest,
            opened: true
        });
        emit SessionOpened(sessionId, recordA, recordB, contextDigest, openedAt);
    }

    function record(bytes32 recordDigest) external view returns (ScopeAuthorization memory) {
        return _requireRecord(recordDigest);
    }

    function sessionGovernance(bytes32 sessionId) external view returns (SessionGovernance memory) {
        SessionGovernance memory session = _sessions[sessionId];
        if (!session.opened) revert SessionNotOpened(sessionId);
        return session;
    }

    function isSessionOpened(bytes32 sessionId) external view returns (bool) {
        return _sessions[sessionId].opened;
    }

    function isLiveAt(bytes32 recordDigest, uint64 at) external view returns (bool) {
        ScopeAuthorization memory stored = _records[recordDigest];
        return stored.exists && _isLiveAt(stored, at);
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
    function _digest(AuthorizationRequest calldata request, uint64 validFrom)
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
}
