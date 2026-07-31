// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {
    ECDSAQuorumConfidentialPolicyVerifierV3
} from "../src/ECDSAQuorumConfidentialPolicyVerifierV3.sol";
import {ReceivableAnchoredRecourseConsumer} from "../src/ReceivableAnchoredRecourseConsumer.sol";
import {
    ConfidentialPolicyResultV3,
    IConfidentialPolicyVerifierV3
} from "../src/interfaces/IConfidentialPolicyVerifierV3.sol";
import {IReceivableAnchor} from "../src/interfaces/IReceivableAnchor.sol";

interface VmA {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest)
        external
        returns (uint8 v, bytes32 r, bytes32 s);
    function expectRevert(bytes4 revertData) external;
    function expectRevert(bytes calldata revertData) external;
    function expectRevert() external;
}

/// @notice Minimal stand-in exposing exactly the receivable surface the consumer
/// reads. The production anchor is MordantInvoiceVault; this double lets the
/// tests drive states the live vault will not enter on demand.
contract AnchorDouble is IReceivableAnchor {
    bytes32 public invoiceRoot;
    bytes32 public currency;
    uint8 public receivableState;
    uint8 public protectionState;
    uint256 public totalSupply;

    constructor(bytes32 root, bytes32 currency_, uint8 receivable, uint8 protection, uint256 supply) {
        invoiceRoot = root;
        currency = currency_;
        receivableState = receivable;
        protectionState = protection;
        totalSupply = supply;
    }

    function setInvoiceRoot(bytes32 value) external { invoiceRoot = value; }
    function setCurrency(bytes32 value) external { currency = value; }
    function setReceivableState(uint8 value) external { receivableState = value; }
    function setProtectionState(uint8 value) external { protectionState = value; }
}

contract ReceivableAnchoredRecourseTest {
    VmA private constant VM = VmA(address(uint160(uint256(keccak256("hevm cheat code")))));
    uint256 private constant KEY_A = 0xA11CE;
    uint256 private constant KEY_B = 0xB0B;
    uint256 private constant KEY_C = 0xCAFE;
    bytes32 private constant ROOT = keccak256("mordant.v4.receivable-root");
    bytes32 private constant CURRENCY = bytes32("USD");
    bytes32 private constant POLICY = keccak256("mordant.v4.conflict-policy");
    uint32 private constant VERSION = 1;
    bytes32 private constant ROLE = keccak256("mordant.role.facility.v1");
    bytes32 private constant CONSEQUENCE = keccak256("mordant.consequence.review-required.v1");

    ECDSAQuorumConfidentialPolicyVerifierV3 private verifier;
    ReceivableAnchoredRecourseConsumer private consumer;
    AnchorDouble private anchor;

    function setUp() public {
        address[] memory validators = new address[](3);
        validators[0] = VM.addr(KEY_A);
        validators[1] = VM.addr(KEY_B);
        validators[2] = VM.addr(KEY_C);
        verifier = new ECDSAQuorumConfidentialPolicyVerifierV3(address(this), validators, 2);
        anchor = new AnchorDouble(ROOT, CURRENCY, 1, 1, 100_000_000);
        verifier.setPolicyVersion(address(anchor), POLICY, VERSION);
        consumer = _consumer(anchor);
    }

    function _consumer(AnchorDouble target)
        private
        returns (ReceivableAnchoredRecourseConsumer)
    {
        return new ReceivableAnchoredRecourseConsumer(
            IConfidentialPolicyVerifierV3(address(verifier)),
            IReceivableAnchor(address(target)),
            POLICY,
            VERSION,
            ROLE,
            1 hours,
            CONSEQUENCE
        );
    }

    function testAnchoredRecourseOpensAgainstTheRealReceivable() public {
        ConfidentialPolicyResultV3 memory result = _result(true, address(anchor));
        consumer.openRecourse(result, _attestation(result, 2));

        (
            bytes32 resultCommitment,
            bytes32 providerProofCommitment,
            ,
            ,
            bytes32 policyId,
            uint32 policyVersion,
            bytes32 responsibleRole,
            bytes32 consequenceId,
            bytes32 invoiceRoot,
            uint64 acceptedAt,
            uint64 cureDeadline,
            ReceivableAnchoredRecourseConsumer.RecourseStatus status
        ) = consumer.recourses(result.resultCommitment);

        require(resultCommitment == result.resultCommitment, "result commitment");
        require(providerProofCommitment == result.providerProofCommitment, "proof commitment");
        require(policyId == POLICY && policyVersion == VERSION, "policy");
        require(responsibleRole == ROLE && consequenceId == CONSEQUENCE, "derived consequence");
        // The record carries the receivable's own root, taken from the anchor.
        require(invoiceRoot == ROOT, "invoice root");
        require(cureDeadline == acceptedAt + 1 hours, "cure deadline");
        require(status == ReceivableAnchoredRecourseConsumer.RecourseStatus.Open, "status");
        require(consumer.anchorLive(), "anchor live");
    }

    /// A codeless address cannot be bound at all: the constructor calls the
    /// anchor, and an address with no code cannot answer.
    function testCodelessAnchorCannotBeConfigured() public {
        VM.expectRevert();
        new ReceivableAnchoredRecourseConsumer(
            IConfidentialPolicyVerifierV3(address(verifier)),
            IReceivableAnchor(address(0xDEAD)),
            POLICY,
            VERSION,
            ROLE,
            1 hours,
            CONSEQUENCE
        );
    }

    function testAnchorMustBeOutstandingWithUnitsAtConfiguration() public {
        AnchorDouble unissued = new AnchorDouble(ROOT, CURRENCY, 0, 1, 100);
        VM.expectRevert(
            abi.encodeWithSelector(ReceivableAnchoredRecourseConsumer.AnchorNotOutstanding.selector, uint8(0))
        );
        _consumer(unissued);

        AnchorDouble empty = new AnchorDouble(ROOT, CURRENCY, 1, 1, 0);
        VM.expectRevert(ReceivableAnchoredRecourseConsumer.AnchorHasNoUnits.selector);
        _consumer(empty);
    }

    /// A result naming any vault other than the bound receivable is refused
    /// before the verifier is ever called, so no identity is consumed.
    function testResultForAnotherVaultIsRefusedAndConsumesNothing() public {
        AnchorDouble other = new AnchorDouble(ROOT, CURRENCY, 1, 1, 100);
        ConfidentialPolicyResultV3 memory result = _result(true, address(other));
        bytes memory attestation = _attestation(result, 2);
        VM.expectRevert(
            abi.encodeWithSelector(
                ReceivableAnchoredRecourseConsumer.AnchorMismatch.selector,
                address(other),
                address(anchor)
            )
        );
        consumer.openRecourse(result, attestation);
        require(!verifier.consumedReplayKeys(verifier.replayKey(result)), "replay key consumed");
        require(
            !verifier.consumedProviderProofCommitments(result.providerProofCommitment),
            "provider proof consumed"
        );
    }

    function testRedeemedReceivableStopsRecourse() public {
        anchor.setReceivableState(2);
        ConfidentialPolicyResultV3 memory result = _result(true, address(anchor));
        bytes memory attestation = _attestation(result, 2);
        VM.expectRevert(
            abi.encodeWithSelector(ReceivableAnchoredRecourseConsumer.AnchorNotOutstanding.selector, uint8(2))
        );
        consumer.openRecourse(result, attestation);
        require(!consumer.anchorLive(), "anchor should not be live");
    }

    function testInactiveProtectionStopsRecourse() public {
        anchor.setProtectionState(0);
        ConfidentialPolicyResultV3 memory result = _result(true, address(anchor));
        bytes memory attestation = _attestation(result, 2);
        VM.expectRevert(
            abi.encodeWithSelector(
                ReceivableAnchoredRecourseConsumer.AnchorProtectionInactive.selector, uint8(0)
            )
        );
        consumer.openRecourse(result, attestation);
    }

    /// If the anchor's identity changes underneath a bound consumer, recourse
    /// stops rather than silently attaching to a different receivable.
    function testMutatedAnchorIdentityStopsRecourse() public {
        anchor.setInvoiceRoot(keccak256("substituted-receivable"));
        ConfidentialPolicyResultV3 memory result = _result(true, address(anchor));
        bytes memory attestation = _attestation(result, 2);
        VM.expectRevert(
            abi.encodeWithSelector(
                ReceivableAnchoredRecourseConsumer.AnchorRootMismatch.selector,
                keccak256("substituted-receivable"),
                ROOT
            )
        );
        consumer.openRecourse(result, attestation);

        anchor.setInvoiceRoot(ROOT);
        anchor.setCurrency(bytes32("EUR"));
        ConfidentialPolicyResultV3 memory second = _result(true, address(anchor));
        bytes memory secondAttestation = _attestation(second, 2);
        VM.expectRevert(
            abi.encodeWithSelector(
                ReceivableAnchoredRecourseConsumer.AnchorCurrencyMismatch.selector,
                bytes32("EUR"),
                CURRENCY
            )
        );
        consumer.openRecourse(second, secondAttestation);
    }

    function testFalseResultAndWrongPolicyAreRefused() public {
        ConfidentialPolicyResultV3 memory clean = _result(false, address(anchor));
        bytes memory cleanAttestation = _attestation(clean, 2);
        VM.expectRevert(ReceivableAnchoredRecourseConsumer.ResultNotConflict.selector);
        consumer.openRecourse(clean, cleanAttestation);

        ConfidentialPolicyResultV3 memory wrongPolicy = _result(true, address(anchor));
        wrongPolicy.policyVersion = VERSION + 1;
        wrongPolicy.resultCommitment = verifier.resultCoreCommitment(wrongPolicy);
        bytes memory wrongAttestation = _attestation(wrongPolicy, 2);
        VM.expectRevert(ReceivableAnchoredRecourseConsumer.UnexpectedPolicy.selector);
        consumer.openRecourse(wrongPolicy, wrongAttestation);
    }

    function testSecondRecourseForTheSameResultIsRefused() public {
        ConfidentialPolicyResultV3 memory result = _result(true, address(anchor));
        bytes memory attestation = _attestation(result, 2);
        consumer.openRecourse(result, attestation);
        VM.expectRevert(
            abi.encodeWithSelector(
                ReceivableAnchoredRecourseConsumer.AlreadyOpened.selector, result.resultCommitment
            )
        );
        consumer.openRecourse(result, attestation);
    }

    function testSingleSignatureIsNotAQuorum() public {
        ConfidentialPolicyResultV3 memory result = _result(true, address(anchor));
        bytes memory attestation = _attestation(result, 1);
        VM.expectRevert(
            abi.encodeWithSelector(
                ECDSAQuorumConfidentialPolicyVerifierV3.InsufficientSignatures.selector, uint256(1), uint256(2)
            )
        );
        consumer.openRecourse(result, attestation);
    }

    function _result(bool conflict, address vault)
        private
        view
        returns (ConfidentialPolicyResultV3 memory result)
    {
        result = ConfidentialPolicyResultV3({
            chainId: block.chainid,
            consumer: address(consumer),
            vault: vault,
            policyId: POLICY,
            policyVersion: VERSION,
            inputCommitmentA: keccak256("anchored-input-a"),
            inputCommitmentB: keccak256("anchored-input-b"),
            conflictConfirmed: conflict,
            nonce: 4242,
            validUntil: uint64(block.timestamp + 10 minutes),
            providerProofCommitment: keccak256("provider-proof-v4"),
            resultCommitment: bytes32(0)
        });
        result.resultCommitment = verifier.resultCoreCommitment(result);
    }

    function _attestation(ConfidentialPolicyResultV3 memory result, uint256 count)
        private
        returns (bytes memory)
    {
        uint256[] memory keys = new uint256[](count);
        keys[0] = KEY_A;
        if (count > 1) keys[1] = KEY_B;
        if (count > 2) keys[2] = KEY_C;
        bytes32 digest =
            verifier.attestationDigest(verifier.validatorSetId(), verifier.resultDigest(result));
        bytes[] memory signatures = new bytes[](count);
        address[] memory signers = new address[](count);
        for (uint256 i; i < count; ++i) {
            signers[i] = VM.addr(keys[i]);
            signatures[i] = _signature(keys[i], digest);
        }
        for (uint256 i; i < count; ++i) {
            for (uint256 j = i + 1; j < count; ++j) {
                if (signers[j] < signers[i]) {
                    (signers[i], signers[j]) = (signers[j], signers[i]);
                    (signatures[i], signatures[j]) = (signatures[j], signatures[i]);
                }
            }
        }
        return abi.encode(verifier.validatorSetId(), signatures);
    }

    function _signature(uint256 key, bytes32 digest) private returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = VM.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }
}
