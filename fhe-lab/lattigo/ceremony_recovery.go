package lattigospike

// Durable private recovery for the existing dealerless ceremony.
//
// This is deliberately a serialization of one operator's already-created
// state, not a second ceremony construction.  In particular it never samples
// a replacement RLWE secret, Shamir polynomial, CRS contribution or
// relinearization ephemeral during recovery.  Callers must keep the resulting
// bytes in that operator's 0600 ledger only.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"sort"

	"github.com/tuneinsight/lattigo/v6/core/rlwe"
	"github.com/tuneinsight/lattigo/v6/multiparty"
	"github.com/tuneinsight/lattigo/v6/ring/ringqp"
	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	"github.com/tuneinsight/lattigo/v6/utils/sampling"
	"github.com/tuneinsight/lattigo/v6/utils/structs"
)

const (
	ceremonyRecoveryMagic   = "MCR1"
	ceremonyRecoveryVersion = uint16(1)
	ceremonyRecoveryCap     = 64 << 20
)

// MarshalPrivateRecoveryState returns this operator's private, resumable
// ceremony state.  It is intentionally not a public wire format and must
// never be copied into a runner journal, evidence bundle, log, or shared
// directory.
func (state *CeremonyOperatorState) MarshalPrivateRecoveryState() ([]byte, error) {
	if state == nil || len(state.signingKey) != ed25519.PrivateKeySize {
		return nil, ErrCeremonyState
	}
	if state.round > roundSealed || state.galoisDone < 0 || state.galoisDone > len(rotationSteps) {
		return nil, ErrCeremonyState
	}
	if state.sealed != (state.round == roundSealed) {
		return nil, ErrCeremonyState
	}

	var out bytes.Buffer
	out.WriteString(ceremonyRecoveryMagic)
	_ = binary.Write(&out, binary.BigEndian, ceremonyRecoveryVersion)
	out.Write(state.rosterHash[:])
	_ = binary.Write(&out, binary.BigEndian, uint64(state.point))
	out.WriteByte(byte(state.round))
	if state.sealed {
		out.WriteByte(1)
	} else {
		out.WriteByte(0)
	}
	_ = binary.Write(&out, binary.BigEndian, uint16(state.galoisDone))
	out.Write(state.contribution[:])
	out.Write(state.crsCommitment[:])

	if err := writeOptionalSecret(&out, state.secretKey); err != nil {
		return nil, err
	}
	if err := writeOptionalSecret(&out, state.ephemeral); err != nil {
		return nil, err
	}
	if err := writeOptionalShare(&out, state.share); err != nil {
		return nil, err
	}
	if err := writePolynomial(&out, state.polynomial); err != nil {
		return nil, err
	}
	if err := writeContributions(&out, state.contributions); err != nil {
		return nil, err
	}
	if err := writePointSet(&out, state.received); err != nil {
		return nil, err
	}
	if err := writePointSet(&out, state.emitted); err != nil {
		return nil, err
	}
	if out.Len() > ceremonyRecoveryCap {
		return nil, ErrCeremonyMaterial
	}
	return out.Bytes(), nil
}

// RestoreCeremonyOperatorState reopens a private operator snapshot.  The
// caller independently supplies the locally loaded parameters, roster, point,
// and signing key so a snapshot cannot be transplanted across ceremonies or
// operators.
func RestoreCeremonyOperatorState(
	params bgv.Parameters,
	roster CeremonyRoster,
	point uint64,
	signingKey ed25519.PrivateKey,
	encoded []byte,
) (*CeremonyOperatorState, error) {
	if err := roster.validate(); err != nil || len(signingKey) != ed25519.PrivateKeySize || !roster.contains(point) ||
		len(encoded) == 0 || len(encoded) > ceremonyRecoveryCap {
		return nil, ErrCeremonyBinding
	}
	parameterBytes, err := params.MarshalBinary()
	if err != nil || sha256.Sum256(parameterBytes) != roster.ParameterFingerprint {
		return nil, ErrCeremonyBinding
	}
	declared, ok := roster.signingKeyFor(point)
	if !ok || !bytes.Equal(declared, signingKey.Public().(ed25519.PublicKey)) {
		return nil, ErrCeremonyBinding
	}

	reader := bytes.NewReader(encoded)
	magic := make([]byte, len(ceremonyRecoveryMagic))
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != ceremonyRecoveryMagic {
		return nil, ErrCeremonyMaterial
	}
	var version uint16
	var snapshotRoster [32]byte
	var snapshotPoint uint64
	var roundByte, sealedByte byte
	var galoisDone uint16
	var contribution, commitment [32]byte
	if binary.Read(reader, binary.BigEndian, &version) != nil || version != ceremonyRecoveryVersion ||
		recoveryReadFull(reader, snapshotRoster[:]) != nil || binary.Read(reader, binary.BigEndian, &snapshotPoint) != nil ||
		binary.Read(reader, binary.BigEndian, &roundByte) != nil || binary.Read(reader, binary.BigEndian, &sealedByte) != nil ||
		binary.Read(reader, binary.BigEndian, &galoisDone) != nil ||
		recoveryReadFull(reader, contribution[:], commitment[:]) != nil {
		return nil, ErrCeremonyMaterial
	}
	rosterHash := roster.Digest()
	if snapshotRoster != rosterHash || snapshotPoint != point || roundByte > byte(roundSealed) || sealedByte > 1 ||
		int(galoisDone) > len(rotationSteps) || (sealedByte == 1) != (ceremonyRound(roundByte) == roundSealed) {
		return nil, ErrCeremonyBinding
	}

	secretKey, err := readOptionalSecret(reader, params)
	if err != nil {
		return nil, err
	}
	ephemeral, err := readOptionalSecret(reader, params)
	if err != nil {
		return nil, err
	}
	share, err := readOptionalShare(reader, params)
	if err != nil {
		return nil, err
	}
	polynomial, err := readPolynomial(reader, params)
	if err != nil {
		return nil, err
	}
	contributions, err := readContributions(reader, roster)
	if err != nil {
		return nil, err
	}
	received, err := readPointSet(reader, roster)
	if err != nil {
		return nil, err
	}
	emitted, err := readPointSet(reader, roster)
	if err != nil || reader.Len() != 0 {
		return nil, ErrCeremonyMaterial
	}
	if own, ok := contributions[point]; !ok || own != contribution {
		return nil, ErrCeremonyBinding
	}

	round := ceremonyRound(roundByte)
	if round == roundCRSContribution {
		if secretKey == nil || share != nil || len(polynomial.Value) != 0 || len(contributions) != 1 || commitment != ([32]byte{}) ||
			ephemeral != nil || len(received) != 0 || len(emitted) != 0 || galoisDone != 0 {
			return nil, ErrCeremonyMaterial
		}
	}
	if round >= roundPrivateShares && round != roundSealed {
		if secretKey == nil || share == nil || len(contributions) != len(roster.Operators) {
			return nil, ErrCeremonyMaterial
		}
		_, derived := ceremonyCRSSeed(roster, contributions)
		if commitment != derived {
			return nil, ErrCeremonyBinding
		}
	}
	if round == roundPrivateShares {
		if len(polynomial.Value) != int(roster.Threshold) || ephemeral != nil || galoisDone != 0 {
			return nil, ErrCeremonyMaterial
		}
	} else if len(polynomial.Value) != 0 {
		return nil, ErrCeremonyMaterial
	}
	if (round == roundRelinTwo || round == roundGalois) && ephemeral == nil {
		return nil, ErrCeremonyMaterial
	}
	if round != roundRelinTwo && round != roundGalois && ephemeral != nil {
		return nil, ErrCeremonyMaterial
	}
	if round == roundSealed && (secretKey != nil || ephemeral != nil || share == nil || !sealedByteBool(sealedByte)) {
		return nil, ErrCeremonyMaterial
	}

	state := &CeremonyOperatorState{
		params:        params,
		roster:        roster,
		rosterHash:    rosterHash,
		point:         multiparty.ShamirPublicPoint(point),
		signingKey:    append(ed25519.PrivateKey(nil), signingKey...),
		secretKey:     secretKey,
		polynomial:    polynomial,
		ephemeral:     ephemeral,
		contribution:  contribution,
		contributions: contributions,
		received:      received,
		emitted:       emitted,
		galoisDone:    int(galoisDone),
		crsCommitment: commitment,
		sealed:        sealedByteBool(sealedByte),
		round:         round,
		thresholdizer: multiparty.NewThresholdizer(params),
		publicKeyGen:  multiparty.NewPublicKeyGenProtocol(params),
		relinGen:      multiparty.NewRelinearizationKeyGenProtocol(params),
		galoisGen:     multiparty.NewGaloisKeyGenProtocol(params),
	}
	if share != nil {
		state.share = *share
	}
	if round >= roundPrivateShares && round != roundSealed {
		seed, derived := ceremonyCRSSeed(roster, contributions)
		if derived != commitment {
			return nil, ErrCeremonyBinding
		}
		state.crs, err = sampling.NewKeyedPRNG(seed[:])
		if err != nil {
			return nil, err
		}
		if err := advanceRecoveryCRS(state); err != nil {
			return nil, err
		}
	}
	return state, nil
}

func sealedByteBool(value byte) bool { return value == 1 }

func advanceRecoveryCRS(state *CeremonyOperatorState) error {
	if state.crs == nil {
		return ErrCeremonyMaterial
	}
	advancePublic := func() { _ = state.publicKeyGen.SampleCRP(state.crs) }
	advanceRelin := func() { _ = state.relinGen.SampleCRP(state.crs) }
	advanceGalois := func() { _ = state.galoisGen.SampleCRP(state.crs) }
	switch state.round {
	case roundPrivateShares, roundPublicKey:
		return nil
	case roundRelinOne:
		advancePublic()
	case roundRelinTwo:
		advancePublic()
		advanceRelin()
	case roundGalois:
		advancePublic()
		advanceRelin()
		for index := 0; index < state.galoisDone; index++ {
			advanceGalois()
		}
	default:
		return ErrCeremonyState
	}
	return nil
}

func writeOptionalSecret(out *bytes.Buffer, value *rlwe.SecretKey) error {
	if value == nil {
		out.WriteByte(0)
		return nil
	}
	encoded, err := value.MarshalBinary()
	if err != nil {
		return err
	}
	out.WriteByte(1)
	return writeRecoveryBytes(out, encoded)
}

func readOptionalSecret(reader *bytes.Reader, params bgv.Parameters) (*rlwe.SecretKey, error) {
	present, err := reader.ReadByte()
	if err != nil || present > 1 {
		return nil, ErrCeremonyMaterial
	}
	if present == 0 {
		return nil, nil
	}
	encoded, err := readRecoveryBytes(reader)
	if err != nil {
		return nil, err
	}
	secret := rlwe.NewSecretKey(params)
	if err := secret.UnmarshalBinary(encoded); err != nil {
		return nil, ErrCeremonyMaterial
	}
	return secret, nil
}

func writeOptionalShare(out *bytes.Buffer, value multiparty.ShamirSecretShare) error {
	if value.Poly.Q.Coeffs == nil {
		out.WriteByte(0)
		return nil
	}
	encoded, err := value.MarshalBinary()
	if err != nil {
		return err
	}
	out.WriteByte(1)
	return writeRecoveryBytes(out, encoded)
}

func readOptionalShare(reader *bytes.Reader, params bgv.Parameters) (*multiparty.ShamirSecretShare, error) {
	present, err := reader.ReadByte()
	if err != nil || present > 1 {
		return nil, ErrCeremonyMaterial
	}
	if present == 0 {
		return nil, nil
	}
	encoded, err := readRecoveryBytes(reader)
	if err != nil {
		return nil, err
	}
	thresholdizer := multiparty.NewThresholdizer(params)
	share := thresholdizer.AllocateThresholdSecretShare()
	if err := share.UnmarshalBinary(encoded); err != nil {
		return nil, ErrCeremonyMaterial
	}
	return &share, nil
}

func writePolynomial(out *bytes.Buffer, polynomial multiparty.ShamirPolynomial) error {
	if len(polynomial.Value) > maxCeremonyOperators {
		return ErrCeremonyMaterial
	}
	_ = binary.Write(out, binary.BigEndian, uint16(len(polynomial.Value)))
	for _, coefficient := range polynomial.Value {
		encoded, err := coefficient.MarshalBinary()
		if err != nil {
			return err
		}
		if err := writeRecoveryBytes(out, encoded); err != nil {
			return err
		}
	}
	return nil
}

func readPolynomial(reader *bytes.Reader, params bgv.Parameters) (multiparty.ShamirPolynomial, error) {
	var count uint16
	if binary.Read(reader, binary.BigEndian, &count) != nil || count > maxCeremonyOperators {
		return multiparty.ShamirPolynomial{}, ErrCeremonyMaterial
	}
	coefficients := make(structs.Vector[ringqp.Poly], count)
	for index := range coefficients {
		encoded, err := readRecoveryBytes(reader)
		if err != nil {
			return multiparty.ShamirPolynomial{}, err
		}
		coefficients[index] = params.GetRLWEParameters().RingQP().NewPoly()
		if err := coefficients[index].UnmarshalBinary(encoded); err != nil {
			return multiparty.ShamirPolynomial{}, ErrCeremonyMaterial
		}
	}
	return multiparty.ShamirPolynomial{Value: coefficients}, nil
}

func writeContributions(out *bytes.Buffer, values map[uint64][32]byte) error {
	if len(values) == 0 || len(values) > maxCeremonyOperators {
		return ErrCeremonyMaterial
	}
	points := make([]uint64, 0, len(values))
	for point := range values {
		points = append(points, point)
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	_ = binary.Write(out, binary.BigEndian, uint16(len(points)))
	for _, point := range points {
		value := values[point]
		_ = binary.Write(out, binary.BigEndian, point)
		out.Write(value[:])
	}
	return nil
}

func readContributions(reader *bytes.Reader, roster CeremonyRoster) (map[uint64][32]byte, error) {
	var count uint16
	if binary.Read(reader, binary.BigEndian, &count) != nil || count == 0 || int(count) > len(roster.Operators) {
		return nil, ErrCeremonyMaterial
	}
	values := make(map[uint64][32]byte, count)
	var previous uint64
	for index := 0; index < int(count); index++ {
		var point uint64
		var value [32]byte
		if binary.Read(reader, binary.BigEndian, &point) != nil || recoveryReadFull(reader, value[:]) != nil || !roster.contains(point) ||
			value == ([32]byte{}) || (index > 0 && point <= previous) {
			return nil, ErrCeremonyMaterial
		}
		values[point] = value
		previous = point
	}
	return values, nil
}

func writePointSet(out *bytes.Buffer, values map[uint64]struct{}) error {
	if len(values) > maxCeremonyOperators {
		return ErrCeremonyMaterial
	}
	points := make([]uint64, 0, len(values))
	for point := range values {
		points = append(points, point)
	}
	sort.Slice(points, func(i, j int) bool { return points[i] < points[j] })
	_ = binary.Write(out, binary.BigEndian, uint16(len(points)))
	for _, point := range points {
		_ = binary.Write(out, binary.BigEndian, point)
	}
	return nil
}

func readPointSet(reader *bytes.Reader, roster CeremonyRoster) (map[uint64]struct{}, error) {
	var count uint16
	if binary.Read(reader, binary.BigEndian, &count) != nil || int(count) > len(roster.Operators) {
		return nil, ErrCeremonyMaterial
	}
	values := make(map[uint64]struct{}, count)
	var previous uint64
	for index := 0; index < int(count); index++ {
		var point uint64
		if binary.Read(reader, binary.BigEndian, &point) != nil || !roster.contains(point) || (index > 0 && point <= previous) {
			return nil, ErrCeremonyMaterial
		}
		values[point] = struct{}{}
		previous = point
	}
	return values, nil
}

func writeRecoveryBytes(out *bytes.Buffer, value []byte) error {
	if len(value) == 0 || len(value) > ceremonyRecoveryCap {
		return ErrCeremonyMaterial
	}
	_ = binary.Write(out, binary.BigEndian, uint32(len(value)))
	_, err := out.Write(value)
	return err
}

func readRecoveryBytes(reader *bytes.Reader) ([]byte, error) {
	var length uint32
	if binary.Read(reader, binary.BigEndian, &length) != nil || length == 0 || int(length) > ceremonyRecoveryCap || int(length) > reader.Len() {
		return nil, ErrCeremonyMaterial
	}
	value := make([]byte, length)
	if _, err := io.ReadFull(reader, value); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCeremonyMaterial, err)
	}
	return value, nil
}

func recoveryReadFull(reader io.Reader, values ...[]byte) error {
	for _, value := range values {
		if _, err := io.ReadFull(reader, value); err != nil {
			return err
		}
	}
	return nil
}
