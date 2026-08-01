// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {ReentrancyGuard} from "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

import {MordantInvoiceVault} from "./MordantInvoiceVault.sol";
import {MordantInvoiceVaultV2} from "./MordantInvoiceVaultV2.sol";
import {ICvaAdapter} from "./interfaces/ICvaAdapter.sol";
import {ICviVerifier} from "./interfaces/ICviVerifier.sol";
import {IMordantFactory} from "./interfaces/IMordantFactory.sol";
import {MordantAssetIdentity} from "./identity/MordantAssetIdentity.sol";
import {MordantIssuerRegistry} from "./identity/MordantIssuerRegistry.sol";
import {MordantSourceAttestation} from "./identity/MordantSourceAttestation.sol";

/// @notice V2 admission: a receivable vault may only be created from parameters
/// an authorized issuer attested before the vault existed.
/// @dev V2 is a new admission model, not a migration. V1 vaults keep working and
/// V1's factory is untouched; a V1 vault simply has no economic-asset identity
/// and can only serve Mode A.
///
/// The vault is deployed with CREATE2 salted by the attestation digest, so its
/// address is a pure function of what the issuer signed. The issuer therefore
/// commits to the exact anchor before it exists without needing to know the
/// address in advance, and there is no post-deployment mapping step anywhere.
contract MordantFactoryV2 is IMordantFactory, Ownable, ReentrancyGuard {
    using MordantSourceAttestation for MordantSourceAttestation.SourceAssetAttestation;

    uint8 private constant ROLE_BUYER = 1;
    uint8 private constant ROLE_ORIGINATOR = 2;

    struct InvoiceConfig {
        address cvaAdapter;
        address settlementToken;
        bytes32 invoiceRoot;
        bytes32 currency;
        address buyer;
        address originatorTreasury;
        address initialOriginatorSigner;
        uint256 initialUnits;
        uint256 advanceAmount;
        uint256 faceValue;
        uint16 bondBps;
        uint64 protectionEnd;
        uint64 revealPeriod;
        uint64 curePeriod;
    }

    error InvalidConfiguration();
    error Unauthorized();
    error AlreadyBound();
    error NotApproved();
    error RoleOverlap();
    error AttestationReplayed(bytes32 issuerKeyId, uint256 nonce);
    error CreationDigestMismatch(bytes32 observed, bytes32 attested);
    error SchemeMismatch(uint16 supplied, uint16 expected);

    event FacilitySet(address indexed facility, bool enabled);
    event CvaAdapterSet(address indexed adapter, bool enabled);
    event SettlementTokenSet(address indexed token, bool enabled);
    /// @dev Carries the identity metadata and the attestation digest. It carries
    /// neither the economic asset identity nor the salt.
    event IdentityAnchoredVaultCreated(
        bytes32 indexed invoiceRoot,
        address indexed vault,
        bytes32 indexed issuerKeyId,
        bytes32 assetCommitment,
        bytes32 initialTermsCommitment,
        uint16 identitySchemeVersion,
        uint16 termsSchemeVersion,
        uint32 identityEpoch,
        bytes32 sourceAttestationDigest
    );

    ICviVerifier public immutable cviVerifier;
    MordantIssuerRegistry public immutable issuerRegistry;

    mapping(address facility => bool registered) public override isFacility;
    mapping(address adapter => bool approved) public approvedCvaAdapter;
    mapping(address token => bool approved) public approvedSettlementToken;
    mapping(bytes32 invoiceRoot => address vault) public vaultForRoot;
    mapping(address cvaToken => bytes32 invoiceRoot) public rootForCva;
    mapping(bytes32 issuerKeyId => mapping(uint256 nonce => bool used)) public consumedNonce;
    mapping(bytes32 attestationDigest => address vault) public vaultForAttestation;

    constructor(address initialOwner, ICviVerifier verifier, MordantIssuerRegistry registry)
        Ownable(initialOwner)
    {
        if (address(verifier) == address(0) || address(registry) == address(0)) {
            revert InvalidConfiguration();
        }
        cviVerifier = verifier;
        issuerRegistry = registry;
    }

    function setFacility(address facility, bool enabled) external onlyOwner {
        if (facility == address(0)) revert InvalidConfiguration();
        isFacility[facility] = enabled;
        emit FacilitySet(facility, enabled);
    }

    function setCvaAdapter(address adapter, bool enabled) external onlyOwner {
        if (adapter == address(0)) revert InvalidConfiguration();
        approvedCvaAdapter[adapter] = enabled;
        emit CvaAdapterSet(adapter, enabled);
    }

    function setSettlementToken(address token, bool enabled) external onlyOwner {
        if (token == address(0)) revert InvalidConfiguration();
        approvedSettlementToken[token] = enabled;
        emit SettlementTokenSet(token, enabled);
    }

    /// @notice Deterministic identity of the vault that a set of parameters
    /// creates. The issuer signs this, not an address, so the attestation can be
    /// produced before any deployment.
    function creationDigest(InvoiceConfig calldata config) public view returns (bytes32) {
        // Encoded in two halves purely to stay within stack limits. Both halves
        // are fixed-width `abi.encode`, so no field boundary is ambiguous and a
        // single changed parameter always changes the digest.
        bytes32 parties = keccak256(
            abi.encode(
                config.cvaAdapter,
                config.settlementToken,
                config.invoiceRoot,
                config.currency,
                config.buyer,
                config.originatorTreasury,
                config.initialOriginatorSigner
            )
        );
        bytes32 economics = keccak256(
            abi.encode(
                config.initialUnits,
                config.advanceAmount,
                config.faceValue,
                config.bondBps,
                config.protectionEnd,
                config.revealPeriod,
                config.curePeriod
            )
        );
        return keccak256(
            abi.encode(
                keccak256("mordant.vault-creation-request/2"),
                block.chainid,
                address(this),
                parties,
                economics
            )
        );
    }

    /// @notice Address the vault will occupy, derivable from the attestation
    /// digest alone once the init code is known.
    function predictVaultAddress(bytes32 attestationDigest, bytes memory initCode)
        public
        view
        returns (address)
    {
        return address(
            uint160(
                uint256(
                    keccak256(
                        abi.encodePacked(
                            bytes1(0xff), address(this), attestationDigest, keccak256(initCode)
                        )
                    )
                )
            )
        );
    }

    /// @notice Creates an identity-anchored receivable vault.
    /// @dev Every check below runs before deployment. There is no code path that
    /// attaches, changes or re-points an identity afterwards.
    function createIdentityAnchoredVault(
        InvoiceConfig calldata config,
        MordantSourceAttestation.SourceAssetAttestation calldata attestation,
        bytes calldata signature
    ) external nonReentrant returns (MordantInvoiceVaultV2 vault) {
        if (msg.sender != config.buyer) revert Unauthorized();
        _validateConfig(config);

        // 1. The attestation must be scoped to this chain and this factory, be
        //    unexpired, and be signed by a key that is authorized right now.
        (address signer, bytes32 attestationDigest) =
            MordantSourceAttestation.recover(attestation, signature, address(this));
        issuerRegistry.requireAuthorized(attestation.issuerKeyId, signer, attestation.identityEpoch);
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

        // 2. One attestation, one anchor, once.
        if (consumedNonce[attestation.issuerKeyId][attestation.nonce]) {
            revert AttestationReplayed(attestation.issuerKeyId, attestation.nonce);
        }
        if (vaultForAttestation[attestationDigest] != address(0)) {
            revert AttestationReplayed(attestation.issuerKeyId, attestation.nonce);
        }

        // 3. The deployment parameters must be exactly the ones attested. A
        //    single changed field yields a different digest and is refused.
        bytes32 observed = creationDigest(config);
        if (observed != attestation.creationDigest) {
            revert CreationDigestMismatch(observed, attestation.creationDigest);
        }
        if (attestation.invoiceRoot != config.invoiceRoot) revert InvalidConfiguration();
        if (attestation.controller != config.originatorTreasury) revert Unauthorized();

        address cvaToken = ICvaAdapter(config.cvaAdapter).asset();
        if (cvaToken == address(0)) revert InvalidConfiguration();
        if (rootForCva[cvaToken] != bytes32(0)) revert AlreadyBound();

        consumedNonce[attestation.issuerKeyId][attestation.nonce] = true;

        MordantInvoiceVault.Init memory init = MordantInvoiceVault.Init({
            factory: address(this),
            cviVerifier: address(cviVerifier),
            cvaAdapter: config.cvaAdapter,
            settlementToken: config.settlementToken,
            invoiceRoot: config.invoiceRoot,
            currency: config.currency,
            buyer: config.buyer,
            originatorTreasury: config.originatorTreasury,
            initialOriginatorSigner: config.initialOriginatorSigner,
            initialUnits: config.initialUnits,
            advanceAmount: config.advanceAmount,
            faceValue: config.faceValue,
            bondBps: config.bondBps,
            protectionEnd: config.protectionEnd,
            revealPeriod: config.revealPeriod,
            curePeriod: config.curePeriod
        });
        MordantInvoiceVaultV2.IdentityInit memory identity = MordantInvoiceVaultV2.IdentityInit({
            assetCommitment: attestation.assetCommitment,
            initialTermsCommitment: attestation.initialTermsCommitment,
            identitySchemeVersion: attestation.identitySchemeVersion,
            termsSchemeVersion: attestation.termsSchemeVersion,
            identityEpoch: attestation.identityEpoch,
            issuerKeyId: attestation.issuerKeyId,
            sourceAttestationDigest: attestationDigest
        });

        // 4. CREATE2 salted by the attestation digest: the address is a pure
        //    function of what was signed.
        vault = new MordantInvoiceVaultV2{salt: attestationDigest}(init, identity);

        vaultForRoot[config.invoiceRoot] = address(vault);
        rootForCva[cvaToken] = config.invoiceRoot;
        vaultForAttestation[attestationDigest] = address(vault);

        _emitCreated(address(vault), attestationDigest, attestation);
    }

    /// @dev Split out purely to keep the creation path within stack limits.
    function _emitCreated(
        address vault,
        bytes32 attestationDigest,
        MordantSourceAttestation.SourceAssetAttestation calldata attestation
    ) private {
        emit IdentityAnchoredVaultCreated(
            attestation.invoiceRoot,
            vault,
            attestation.issuerKeyId,
            attestation.assetCommitment,
            attestation.initialTermsCommitment,
            attestation.identitySchemeVersion,
            attestation.termsSchemeVersion,
            attestation.identityEpoch,
            attestationDigest
        );
    }

    function _validateConfig(InvoiceConfig calldata config) private view {
        if (!approvedCvaAdapter[config.cvaAdapter] || !approvedSettlementToken[config.settlementToken])
        {
            revert NotApproved();
        }
        if (
            !cviVerifier.isEligible(config.buyer, ROLE_BUYER)
                || !cviVerifier.isEligible(config.initialOriginatorSigner, ROLE_ORIGINATOR)
                || !cviVerifier.isEligible(config.originatorTreasury, ROLE_ORIGINATOR)
        ) revert Unauthorized();
        if (
            config.buyer == config.originatorTreasury
                || config.buyer == config.initialOriginatorSigner || isFacility[config.buyer]
                || isFacility[config.originatorTreasury]
                || isFacility[config.initialOriginatorSigner]
        ) revert RoleOverlap();
        if (
            config.cvaAdapter == address(0) || config.settlementToken == address(0)
                || config.invoiceRoot == bytes32(0)
                || vaultForRoot[config.invoiceRoot] != address(0)
        ) revert InvalidConfiguration();
    }
}
