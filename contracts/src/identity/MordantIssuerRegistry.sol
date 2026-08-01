// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";

/// @notice Registry of accountable identity issuers.
/// @dev Source truth stays an attributable issuer assertion; this contract is
/// what makes it attributable and revocable. It is deliberately separate from
/// the Cleanverse eligibility verifier: eligibility answers "may this address
/// hold this role", identity issuance answers "may this key assert what an
/// anchor's economic asset is". The two are different authorities and are kept
/// apart so a Cleanverse adapter can be swapped without touching identity.
contract MordantIssuerRegistry is Ownable {
    error InvalidIssuer();
    error IssuerAlreadyRegistered(bytes32 issuerKeyId);
    error IssuerRevoked(bytes32 issuerKeyId);

    event IssuerRegistered(bytes32 indexed issuerKeyId, address indexed signer, uint32 fromEpoch);
    event IssuerRevoked_(bytes32 indexed issuerKeyId, uint64 at);
    event IssuerEpochAdvanced(bytes32 indexed issuerKeyId, uint32 epoch);

    struct Issuer {
        address signer; // the EIP-712 signing address
        uint32 minEpoch; // attestations below this epoch are refused
        uint64 revokedAt; // 0 while authorized
        bool registered;
    }

    mapping(bytes32 issuerKeyId => Issuer record) public issuers;

    constructor(address initialOwner) Ownable(initialOwner) {}

    /// @notice The issuer key id is bound to its signer, so a signer cannot be
    /// silently swapped underneath an existing key id.
    function issuerKeyIdFor(address signer) public pure returns (bytes32) {
        return keccak256(abi.encode(keccak256("mordant.identity-issuer/1"), signer));
    }

    function registerIssuer(address signer, uint32 fromEpoch) external onlyOwner {
        if (signer == address(0) || fromEpoch == 0) revert InvalidIssuer();
        bytes32 keyId = issuerKeyIdFor(signer);
        if (issuers[keyId].registered) revert IssuerAlreadyRegistered(keyId);
        issuers[keyId] = Issuer({signer: signer, minEpoch: fromEpoch, revokedAt: 0, registered: true});
        emit IssuerRegistered(keyId, signer, fromEpoch);
    }

    /// @notice Revocation is terminal for this key id. A revoked issuer can
    /// never be re-enabled, which is what stops a compromised key being quietly
    /// restored after it has attested anchors.
    function revokeIssuer(bytes32 issuerKeyId) external onlyOwner {
        Issuer storage record = issuers[issuerKeyId];
        if (!record.registered) revert InvalidIssuer();
        if (record.revokedAt != 0) revert IssuerRevoked(issuerKeyId);
        record.revokedAt = uint64(block.timestamp);
        emit IssuerRevoked_(issuerKeyId, record.revokedAt);
    }

    /// @notice Advances the minimum acceptable identity epoch, retiring older
    /// salts and scheme versions without revoking the issuer.
    function advanceEpoch(bytes32 issuerKeyId, uint32 epoch) external onlyOwner {
        Issuer storage record = issuers[issuerKeyId];
        if (!record.registered || record.revokedAt != 0) revert InvalidIssuer();
        if (epoch <= record.minEpoch) revert InvalidIssuer();
        record.minEpoch = epoch;
        emit IssuerEpochAdvanced(issuerKeyId, epoch);
    }

    /// @notice Authorization check used at anchor admission.
    function requireAuthorized(bytes32 issuerKeyId, address signer, uint32 identityEpoch)
        external
        view
    {
        Issuer memory record = issuers[issuerKeyId];
        if (!record.registered || record.signer != signer) revert InvalidIssuer();
        if (record.revokedAt != 0) revert IssuerRevoked(issuerKeyId);
        if (identityEpoch < record.minEpoch) revert InvalidIssuer();
    }

    function isAuthorized(bytes32 issuerKeyId) external view returns (bool) {
        Issuer memory record = issuers[issuerKeyId];
        return record.registered && record.revokedAt == 0;
    }
}
