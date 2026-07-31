// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @notice Versioned, field-specific canonicalization profiles.
/// @dev Scheme 1 stripped all punctuation from every identifier. That is lossy
/// in a way that matters: it silently merges `INV-001` with `INV-0-01`, and it
/// destroys leading zeros that are significant in DUNS and GLN. Each namespace
/// now declares the profile its registry actually mandates, and the profile id
/// is part of the identity, so two platforms using different profiles for the
/// same namespace cannot silently produce the same value.
///
/// Every profile fails closed. A byte outside printable ASCII is rejected rather
/// than transliterated: Unicode folding (NFKC and friends) maps distinct
/// characters onto each other, which would manufacture collisions between
/// genuinely different identifiers.
library MordantNormalization {
    error UnsupportedCharacter(uint8 position);
    error WrongLength(uint256 observed, uint256 expected);
    error EmptyIdentifier();
    error MalformedIdentifier();
    error UnknownProfile(uint8 profile);

    /// @dev Profile ids are permanent. Changing what a profile means requires a
    /// new id, never a redefinition.
    uint8 internal constant PROFILE_NONE = 0;
    /// Uppercase [A-Z0-9] only, fixed length. ISO 17442 LEI.
    uint8 internal constant PROFILE_ALNUM_UPPER_FIXED = 1;
    /// Digits only, fixed length, leading zeros significant. DUNS, GLN.
    uint8 internal constant PROFILE_DIGITS_FIXED = 2;
    /// Uppercase, strips only space, dot and hyphen, then requires two leading
    /// letters. EU VAT convention.
    uint8 internal constant PROFILE_VAT = 3;
    /// `0x` + 40 hex, lowercased. EIP-55 casing is display-only.
    uint8 internal constant PROFILE_HEX_ADDRESS = 4;
    /// Printable ASCII preserved exactly. Case and punctuation are significant.
    uint8 internal constant PROFILE_INVOICE_CASE_SENSITIVE = 5;
    /// Uppercase, strips non-alphanumeric. Tolerant of formatting, and lossy:
    /// see the collision analysis in the specification before selecting it.
    uint8 internal constant PROFILE_INVOICE_CASE_INSENSITIVE = 6;

    /// @notice Normalizes `value` under `profile` and returns a domain-separated
    /// digest that carries the profile id.
    /// @dev The profile is inside the digest, so the same characters under two
    /// profiles never collide.
    function normalize(uint8 profile, string memory value, uint256 fixedLength)
        internal
        pure
        returns (bytes32)
    {
        bytes memory out = canonicalBytes(profile, value, fixedLength);
        return keccak256(abi.encode(keccak256("mordant.normalized-field/2"), profile, out));
    }

    function canonicalBytes(uint8 profile, string memory value, uint256 fixedLength)
        internal
        pure
        returns (bytes memory)
    {
        bytes memory raw = bytes(value);
        _requirePrintableAscii(raw);
        if (profile == PROFILE_ALNUM_UPPER_FIXED) return _alnumUpperFixed(raw, fixedLength);
        if (profile == PROFILE_DIGITS_FIXED) return _digitsFixed(raw, fixedLength);
        if (profile == PROFILE_VAT) return _vat(raw);
        if (profile == PROFILE_HEX_ADDRESS) return _hexAddress(raw);
        if (profile == PROFILE_INVOICE_CASE_SENSITIVE) return _caseSensitive(raw);
        if (profile == PROFILE_INVOICE_CASE_INSENSITIVE) return _caseInsensitiveAlnum(raw);
        revert UnknownProfile(profile);
    }

    /// @notice Namespace labels are their own tiny profile: lowercase letters
    /// and digits, nothing else.
    function namespace(string memory value) internal pure returns (bytes32) {
        bytes memory raw = bytes(value);
        _requirePrintableAscii(raw);
        bytes memory out = new bytes(raw.length);
        for (uint256 i; i < raw.length; ++i) {
            uint8 character = uint8(raw[i]);
            if (character >= 0x41 && character <= 0x5A) {
                out[i] = bytes1(character + 32);
            } else if ((character >= 0x61 && character <= 0x7A) || (character >= 0x30 && character <= 0x39)) {
                out[i] = bytes1(character);
            } else {
                revert UnsupportedCharacter(uint8(i));
            }
        }
        if (raw.length == 0) revert EmptyIdentifier();
        return keccak256(abi.encode(keccak256("mordant.namespace/2"), out));
    }

    function _requirePrintableAscii(bytes memory raw) private pure {
        if (raw.length == 0) revert EmptyIdentifier();
        for (uint256 i; i < raw.length; ++i) {
            uint8 character = uint8(raw[i]);
            // Reject control bytes and everything above ASCII. No transliteration.
            if (character < 0x20 || character > 0x7E) revert UnsupportedCharacter(uint8(i));
        }
    }

    function _alnumUpperFixed(bytes memory raw, uint256 fixedLength)
        private
        pure
        returns (bytes memory out)
    {
        out = new bytes(raw.length);
        for (uint256 i; i < raw.length; ++i) {
            uint8 character = uint8(raw[i]);
            if (character >= 0x61 && character <= 0x7A) {
                out[i] = bytes1(character - 32);
            } else if (
                (character >= 0x41 && character <= 0x5A) || (character >= 0x30 && character <= 0x39)
            ) {
                out[i] = bytes1(character);
            } else {
                // Strict registries do not permit separators at all.
                revert UnsupportedCharacter(uint8(i));
            }
        }
        if (fixedLength != 0 && raw.length != fixedLength) {
            revert WrongLength(raw.length, fixedLength);
        }
    }

    function _digitsFixed(bytes memory raw, uint256 fixedLength)
        private
        pure
        returns (bytes memory out)
    {
        // Leading zeros are significant: `000000001` and `1` are different
        // DUNS numbers, so nothing is trimmed and the length is enforced.
        for (uint256 i; i < raw.length; ++i) {
            uint8 character = uint8(raw[i]);
            if (character < 0x30 || character > 0x39) revert UnsupportedCharacter(uint8(i));
        }
        if (fixedLength != 0 && raw.length != fixedLength) {
            revert WrongLength(raw.length, fixedLength);
        }
        out = raw;
    }

    function _vat(bytes memory raw) private pure returns (bytes memory out) {
        out = new bytes(raw.length);
        uint256 length;
        for (uint256 i; i < raw.length; ++i) {
            uint8 character = uint8(raw[i]);
            // Only the three separators VAT registries actually print.
            if (character == 0x20 || character == 0x2E || character == 0x2D) continue;
            if (character >= 0x61 && character <= 0x7A) {
                out[length++] = bytes1(character - 32);
            } else if (
                (character >= 0x41 && character <= 0x5A) || (character >= 0x30 && character <= 0x39)
            ) {
                out[length++] = bytes1(character);
            } else {
                revert UnsupportedCharacter(uint8(i));
            }
        }
        if (length < 3) revert MalformedIdentifier();
        assembly {
            mstore(out, length)
        }
        // A VAT identifier is country-scoped by its own two leading letters, so
        // no separate jurisdiction field is needed or permitted.
        if (!_isUpperAlpha(uint8(out[0])) || !_isUpperAlpha(uint8(out[1]))) {
            revert MalformedIdentifier();
        }
    }

    function _hexAddress(bytes memory raw) private pure returns (bytes memory out) {
        if (raw.length != 42) revert WrongLength(raw.length, 42);
        if (raw[0] != 0x30 || (raw[1] != 0x78 && raw[1] != 0x58)) revert MalformedIdentifier();
        out = new bytes(42);
        out[0] = 0x30;
        out[1] = 0x78;
        for (uint256 i = 2; i < 42; ++i) {
            uint8 character = uint8(raw[i]);
            if (character >= 0x41 && character <= 0x46) {
                out[i] = bytes1(character + 32);
            } else if (
                (character >= 0x30 && character <= 0x39) || (character >= 0x61 && character <= 0x66)
            ) {
                out[i] = bytes1(character);
            } else {
                revert UnsupportedCharacter(uint8(i));
            }
        }
    }

    function _caseSensitive(bytes memory raw) private pure returns (bytes memory) {
        // Nothing is stripped or folded. Two strings are equal only if their
        // bytes are equal, so this profile admits no collisions at all.
        return raw;
    }

    function _caseInsensitiveAlnum(bytes memory raw) private pure returns (bytes memory out) {
        out = new bytes(raw.length);
        uint256 length;
        for (uint256 i; i < raw.length; ++i) {
            uint8 character = uint8(raw[i]);
            if (character >= 0x61 && character <= 0x7A) {
                out[length++] = bytes1(character - 32);
            } else if (
                (character >= 0x41 && character <= 0x5A) || (character >= 0x30 && character <= 0x39)
            ) {
                out[length++] = bytes1(character);
            }
            // Everything else is dropped. This is the lossy profile.
        }
        if (length == 0) revert EmptyIdentifier();
        assembly {
            mstore(out, length)
        }
    }

    function _isUpperAlpha(uint8 character) private pure returns (bool) {
        return character >= 0x41 && character <= 0x5A;
    }
}
