package thresholdnet

// The ceremony ledger is private to one operator process.  It stores immutable
// atomic capsules, each containing the operator's state *after* one transition
// and the exact response (or peer share) produced by that transition.  A
// complete renamed capsule is therefore enough to recover even if the process
// died before the response left the socket; an incomplete temporary capsule is
// never authority and no response is sent before its fsync succeeds.

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	spike "mordant.dev/fhe-lab/lattigo"
)

const (
	ceremonyLedgerMagic      = "MCL1"
	ceremonyLedgerVersion    = uint16(1)
	ceremonyLedgerFilePrefix = "checkpoint-"
	ceremonyLedgerFileSuffix = ".bin"
	ceremonyLedgerMaxState   = 64 << 20
	ceremonyLedgerMaxData    = 384 << 20
	ceremonyLedgerMaxAux     = 32 << 20
	ceremonyLedgerMaxMeta    = 1 << 20
)

type ceremonyLedgerKind uint8

const (
	ledgerState ceremonyLedgerKind = iota + 1
	ledgerOperation
	ledgerOutboundShare
	ledgerInboundShare
)

var ErrCeremonyLedger = errors.New("invalid ceremony private ledger")

type ceremonyLedgerMeta struct {
	Operation     CeremonyOperation `json:"operation,omitempty"`
	PayloadDigest string            `json:"payloadDigest,omitempty"`
	ManifestInput string            `json:"manifestInput,omitempty"`
	Detail        string            `json:"detail,omitempty"`
	Point         uint64            `json:"point,omitempty"`
	At            string            `json:"at"`
}

type ceremonyLedgerCapsule struct {
	Sequence uint64
	Kind     ceremonyLedgerKind
	Previous [32]byte
	// StateDigest remains in compacted historical capsules. Only the latest
	// capsule retains State bytes, so historical public responses do not each
	// duplicate a multi-megabyte private snapshot.
	StateDigest [32]byte
	State       []byte
	Meta        ceremonyLedgerMeta
	Data        []byte
	Aux         []byte
	Digest      [32]byte
}

// CeremonyPrivateLedger is the only persistence authority for one operator's
// in-progress ceremony.  It has no API for reading a secret key or final share;
// callers can obtain only the in-process state object, cached protocol replies,
// public step records, or the operator's own sealed bundle for local install.
type CeremonyPrivateLedger struct {
	mu        sync.Mutex
	directory string
	state     *spike.CeremonyOperatorState
	sequence  uint64
	last      [32]byte
	responses map[string][]byte
	reshare   []byte
	outbound  map[uint64][]byte
	inbound   map[uint64][32]byte
	bundle    []byte
	finalKeys *spike.CeremonyKeyDigests
	steps     []CeremonyStepRecord
	poisoned  error
}

// OpenCeremonyPrivateLedger creates or restores exactly one operator ledger.
// Every snapshot is rebound to the independently loaded local roster, point,
// parameters, and signing key while the immutable hash chain is replayed.
func OpenCeremonyPrivateLedger(
	directory string,
	params bgv.Parameters,
	roster spike.CeremonyRoster,
	point uint64,
	signingKey ed25519.PrivateKey,
) (*CeremonyPrivateLedger, error) {
	if directory == "" {
		return nil, fmt.Errorf("%w: empty directory", ErrCeremonyLedger)
	}
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return nil, err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return nil, err
	}
	ledger := &CeremonyPrivateLedger{
		directory: directory,
		responses: make(map[string][]byte),
		outbound:  make(map[uint64][]byte),
		inbound:   make(map[uint64][32]byte),
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasPrefix(name, ceremonyLedgerFilePrefix) || !strings.HasSuffix(name, ceremonyLedgerFileSuffix) {
			if strings.HasSuffix(name, ".tmp") {
				// An unrenamed temp file was never committed and no response was
				// allowed to leave after it. It is ignored as non-authoritative.
				_ = os.Remove(filepath.Join(directory, name))
				continue
			}
			return nil, fmt.Errorf("%w: unexpected entry %q", ErrCeremonyLedger, name)
		}
		files = append(files, name)
	}
	sort.Strings(files)
	if len(files) == 0 {
		state, err := spike.NewCeremonyOperatorState(params, roster, point, signingKey)
		if err != nil {
			return nil, err
		}
		ledger.state = state
		if err := ledger.appendLocked(ledgerState, ceremonyLedgerMeta{Detail: "operator-state-created"}, nil, nil); err != nil {
			return nil, err
		}
		return ledger, nil
	}

	for index, name := range files {
		expected := ceremonyLedgerFilename(uint64(index + 1))
		if name != expected {
			return nil, fmt.Errorf("%w: checkpoint gap at %q", ErrCeremonyLedger, name)
		}
		path := filepath.Join(directory, name)
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
			return nil, fmt.Errorf("%w: unsafe checkpoint %q", ErrCeremonyLedger, name)
		}
		capsule, err := readCeremonyLedgerCapsule(path)
		if err != nil {
			return nil, err
		}
		if capsule.Sequence != uint64(index+1) || capsule.Previous != ledger.last {
			return nil, fmt.Errorf("%w: broken checkpoint chain", ErrCeremonyLedger)
		}
		if len(capsule.State) != 0 {
			state, err := spike.RestoreCeremonyOperatorState(params, roster, point, signingKey, capsule.State)
			if err != nil {
				return nil, fmt.Errorf("%w: state restore: %v", ErrCeremonyLedger, err)
			}
			ledger.state = state
		}
		ledger.sequence = capsule.Sequence
		ledger.last = capsule.Digest
		if err := ledger.absorb(capsule); err != nil {
			return nil, err
		}
	}
	if ledger.state == nil {
		return nil, fmt.Errorf("%w: no recoverable latest state", ErrCeremonyLedger)
	}
	lastCapsule, err := readCeremonyLedgerCapsule(filepath.Join(directory, files[len(files)-1]))
	if err != nil || len(lastCapsule.State) == 0 {
		return nil, fmt.Errorf("%w: latest state was compacted", ErrCeremonyLedger)
	}
	for _, name := range files[:len(files)-1] {
		if err := compactCeremonyLedgerCapsule(filepath.Join(directory, name)); err != nil {
			return nil, err
		}
	}
	return ledger, nil
}

func (ledger *CeremonyPrivateLedger) State() *spike.CeremonyOperatorState {
	if ledger == nil {
		return nil
	}
	return ledger.state
}

func (ledger *CeremonyPrivateLedger) Cached(operation CeremonyOperation, payload []byte) ([]byte, bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return nil, false, err
	}
	value, ok := ledger.responses[ceremonyOperationCacheKey(operation, payload)]
	return append([]byte(nil), value...), ok, nil
}

// CachedReshare returns the completed roster-bound re-sharing response. The
// transport URLs are deliberately not part of this semantic cache: they are
// ephemeral process coordinates and may change after a restart, while the
// roster points and the already persisted private wires remain immutable.
func (ledger *CeremonyPrivateLedger) CachedReshare() ([]byte, bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return nil, false, err
	}
	return append([]byte(nil), ledger.reshare...), len(ledger.reshare) != 0, nil
}

func (ledger *CeremonyPrivateLedger) Outbound(point uint64) ([]byte, bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return nil, false, err
	}
	value, ok := ledger.outbound[point]
	return append([]byte(nil), value...), ok, nil
}

func (ledger *CeremonyPrivateLedger) InboundDigest(point uint64) ([32]byte, bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return [32]byte{}, false, err
	}
	value, ok := ledger.inbound[point]
	return value, ok, nil
}

// SaveOutbound atomically commits the mutated emitted-set and the exact
// recipient-bound private wire before that wire may be sent to the peer.
func (ledger *CeremonyPrivateLedger) SaveOutbound(point uint64, wire []byte) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return err
	}
	if existing, ok := ledger.outbound[point]; ok {
		if !bytes.Equal(existing, wire) {
			return ledger.poison(fmt.Errorf("%w: outbound share drift for point %d", ErrCeremonyLedger, point))
		}
		return nil
	}
	if point == 0 || len(wire) == 0 || len(wire) > ceremonyLedgerMaxData {
		return ledger.poison(fmt.Errorf("%w: invalid outbound share", ErrCeremonyLedger))
	}
	return ledger.appendLocked(ledgerOutboundShare, ceremonyLedgerMeta{Point: point, Detail: "private-share-prepared"}, wire, nil)
}

// SaveInbound commits only the authenticated wire digest alongside the
// already-aggregated local state. The sender's individual re-sharing payload
// is not retained after aggregation, while an exact transport retry remains
// distinguishable from a conflicting second contribution.
func (ledger *CeremonyPrivateLedger) SaveInbound(point uint64, wire []byte) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return err
	}
	digest := sha256.Sum256(wire)
	if existing, ok := ledger.inbound[point]; ok {
		if existing != digest {
			return ledger.poison(fmt.Errorf("%w: inbound share drift for point %d", ErrCeremonyLedger, point))
		}
		return nil
	}
	if point == 0 || len(wire) == 0 || len(wire) > ceremonyLedgerMaxData {
		return ledger.poison(fmt.Errorf("%w: invalid inbound share", ErrCeremonyLedger))
	}
	return ledger.appendLocked(ledgerInboundShare, ceremonyLedgerMeta{Point: point, Detail: "private-share-accepted"}, digest[:], nil)
}

// SaveState persists a peer-share acceptance before the receiver acknowledges
// it. The peer retains its identical cached wire if this checkpoint fails.
func (ledger *CeremonyPrivateLedger) SaveState(detail string) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return err
	}
	return ledger.appendLocked(ledgerState, ceremonyLedgerMeta{Detail: boundedLedgerDetail(detail)}, nil, nil)
}

// CommitOperation stores the post-operation state and the exact public reply
// as one immutable capsule.  Optional aux bytes are the operator's own sealed
// bundle and occur only for the final manifest operation.
func (ledger *CeremonyPrivateLedger) CommitOperation(
	operation CeremonyOperation,
	payload, response []byte,
	detail string,
	aux []byte,
) error {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return err
	}
	if operation == OpReshare && len(ledger.reshare) != 0 {
		if !bytes.Equal(ledger.reshare, response) {
			return ledger.poison(fmt.Errorf("%w: completed re-sharing response drift", ErrCeremonyLedger))
		}
		return nil
	}
	key := ceremonyOperationCacheKey(operation, payload)
	if existing, ok := ledger.responses[key]; ok {
		if !bytes.Equal(existing, response) {
			return ledger.poison(fmt.Errorf("%w: cached response drift", ErrCeremonyLedger))
		}
		if len(aux) != 0 && !bytes.Equal(ledger.bundle, aux) {
			return ledger.poison(fmt.Errorf("%w: sealed bundle drift", ErrCeremonyLedger))
		}
		return nil
	}
	payloadDigest := sha256.Sum256(payload)
	meta := ceremonyLedgerMeta{
		Operation:     operation,
		PayloadDigest: hex.EncodeToString(payloadDigest[:]),
		Detail:        boundedLedgerDetail(detail),
	}
	if operation == OpSealManifest {
		if len(payload) != 160 {
			return ledger.poison(fmt.Errorf("%w: invalid final digest payload", ErrCeremonyLedger))
		}
		meta.ManifestInput = hex.EncodeToString(payload)
	}
	return ledger.appendLocked(ledgerOperation, meta, response, aux)
}

func (ledger *CeremonyPrivateLedger) Steps() []CeremonyStepRecord {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return append([]CeremonyStepRecord(nil), ledger.steps...)
}

func (ledger *CeremonyPrivateLedger) SealedBundle() ([]byte, bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return nil, false, err
	}
	return append([]byte(nil), ledger.bundle...), len(ledger.bundle) != 0, nil
}

func (ledger *CeremonyPrivateLedger) FinalKeyDigests() (spike.CeremonyKeyDigests, bool, error) {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	if err := ledger.healthy(); err != nil {
		return spike.CeremonyKeyDigests{}, false, err
	}
	if ledger.finalKeys == nil {
		return spike.CeremonyKeyDigests{}, false, nil
	}
	return *ledger.finalKeys, true, nil
}

func (ledger *CeremonyPrivateLedger) CheckpointCount() uint64 {
	ledger.mu.Lock()
	defer ledger.mu.Unlock()
	return ledger.sequence
}

func (ledger *CeremonyPrivateLedger) appendLocked(kind ceremonyLedgerKind, meta ceremonyLedgerMeta, data, aux []byte) error {
	if ledger.state == nil || (kind != ledgerState && kind != ledgerOperation && kind != ledgerOutboundShare && kind != ledgerInboundShare) ||
		len(data) > ceremonyLedgerMaxData || len(aux) > ceremonyLedgerMaxAux {
		return ledger.poison(fmt.Errorf("%w: invalid checkpoint", ErrCeremonyLedger))
	}
	state, err := ledger.state.MarshalPrivateRecoveryState()
	if err != nil {
		return ledger.poison(err)
	}
	meta.At = time.Now().UTC().Format(time.RFC3339Nano)
	capsule := ceremonyLedgerCapsule{
		Sequence: ledger.sequence + 1,
		Kind:     kind,
		Previous: ledger.last,
		State:    state,
		Meta:     meta,
		Data:     append([]byte(nil), data...),
		Aux:      append([]byte(nil), aux...),
	}
	encoded, digest, err := marshalCeremonyLedgerCapsule(capsule)
	if err != nil {
		return ledger.poison(err)
	}
	path := filepath.Join(ledger.directory, ceremonyLedgerFilename(capsule.Sequence))
	if err := writeCeremonyLedgerAtomic(path, encoded); err != nil {
		return ledger.poison(err)
	}
	capsule.Digest = digest
	ledger.sequence = capsule.Sequence
	ledger.last = digest
	if err := ledger.absorb(capsule); err != nil {
		return ledger.poison(err)
	}
	if capsule.Sequence > 1 {
		previous := filepath.Join(ledger.directory, ceremonyLedgerFilename(capsule.Sequence-1))
		if err := compactCeremonyLedgerCapsule(previous); err != nil {
			return ledger.poison(err)
		}
	}
	return nil
}

func (ledger *CeremonyPrivateLedger) absorb(capsule ceremonyLedgerCapsule) error {
	switch capsule.Kind {
	case ledgerState:
		return nil
	case ledgerOutboundShare:
		if capsule.Meta.Point == 0 || len(capsule.Data) == 0 {
			return fmt.Errorf("%w: invalid outbound checkpoint", ErrCeremonyLedger)
		}
		if existing, exists := ledger.outbound[capsule.Meta.Point]; exists && !bytes.Equal(existing, capsule.Data) {
			return fmt.Errorf("%w: conflicting outbound checkpoint", ErrCeremonyLedger)
		}
		ledger.outbound[capsule.Meta.Point] = append([]byte(nil), capsule.Data...)
		return nil
	case ledgerInboundShare:
		if capsule.Meta.Point == 0 || len(capsule.Data) != sha256.Size {
			return fmt.Errorf("%w: invalid inbound checkpoint", ErrCeremonyLedger)
		}
		var digest [32]byte
		copy(digest[:], capsule.Data)
		if existing, exists := ledger.inbound[capsule.Meta.Point]; exists && existing != digest {
			return fmt.Errorf("%w: conflicting inbound checkpoint", ErrCeremonyLedger)
		}
		ledger.inbound[capsule.Meta.Point] = digest
		return nil
	case ledgerOperation:
		payloadDigest, err := hex.DecodeString(capsule.Meta.PayloadDigest)
		if err != nil || len(payloadDigest) != sha256.Size || capsule.Meta.Operation < OpContribution || capsule.Meta.Operation > OpSealManifest {
			return fmt.Errorf("%w: invalid operation checkpoint", ErrCeremonyLedger)
		}
		if capsule.Meta.Operation == OpReshare {
			if len(capsule.Data) != 1 {
				return fmt.Errorf("%w: invalid persisted re-sharing response", ErrCeremonyLedger)
			}
			if len(ledger.reshare) != 0 && !bytes.Equal(ledger.reshare, capsule.Data) {
				return fmt.Errorf("%w: conflicting persisted re-sharing response", ErrCeremonyLedger)
			}
			ledger.reshare = append([]byte(nil), capsule.Data...)
		}
		key := fmt.Sprintf("%d:%s", capsule.Meta.Operation, capsule.Meta.PayloadDigest)
		if existing, exists := ledger.responses[key]; exists && !bytes.Equal(existing, capsule.Data) {
			return fmt.Errorf("%w: conflicting operation checkpoint", ErrCeremonyLedger)
		}
		ledger.responses[key] = append([]byte(nil), capsule.Data...)
		if capsule.Meta.Operation == OpSealManifest {
			raw, err := hex.DecodeString(capsule.Meta.ManifestInput)
			if err != nil || len(raw) != 160 {
				return fmt.Errorf("%w: invalid persisted final digests", ErrCeremonyLedger)
			}
			var digests spike.CeremonyKeyDigests
			copy(digests.CRSCommitment[:], raw[0:32])
			copy(digests.PublicKeyCommitment[:], raw[32:64])
			copy(digests.RelinearizationKeyDigest[:], raw[64:96])
			copy(digests.GaloisKeyCommitment[:], raw[96:128])
			copy(digests.PolicyCircuitCommitment[:], raw[128:160])
			if ledger.finalKeys != nil && *ledger.finalKeys != digests {
				return fmt.Errorf("%w: conflicting persisted final digests", ErrCeremonyLedger)
			}
			ledger.finalKeys = &digests
		}
		if len(capsule.Aux) != 0 {
			if len(ledger.bundle) != 0 && !bytes.Equal(ledger.bundle, capsule.Aux) {
				return fmt.Errorf("%w: conflicting sealed bundle", ErrCeremonyLedger)
			}
			ledger.bundle = append([]byte(nil), capsule.Aux...)
		}
		ledger.steps = append(ledger.steps, CeremonyStepRecord{
			Operation: capsule.Meta.Operation,
			Name:      ceremonyOperationNames[capsule.Meta.Operation],
			At:        capsule.Meta.At,
			Detail:    capsule.Meta.Detail,
		})
		return nil
	default:
		return fmt.Errorf("%w: unknown checkpoint kind", ErrCeremonyLedger)
	}
}

func (ledger *CeremonyPrivateLedger) healthy() error {
	if ledger == nil || ledger.poisoned != nil {
		if ledger != nil && ledger.poisoned != nil {
			return ledger.poisoned
		}
		return ErrCeremonyLedger
	}
	return nil
}

func (ledger *CeremonyPrivateLedger) poison(err error) error {
	if ledger.poisoned == nil {
		ledger.poisoned = err
	}
	return ledger.poisoned
}

func ceremonyOperationCacheKey(operation CeremonyOperation, payload []byte) string {
	digest := sha256.Sum256(payload)
	return fmt.Sprintf("%d:%s", operation, hex.EncodeToString(digest[:]))
}

func ceremonyLedgerFilename(sequence uint64) string {
	return fmt.Sprintf("%s%020d%s", ceremonyLedgerFilePrefix, sequence, ceremonyLedgerFileSuffix)
}

func boundedLedgerDetail(value string) string {
	if len(value) > 256 {
		return value[:256]
	}
	return value
}

func marshalCeremonyLedgerCapsule(capsule ceremonyLedgerCapsule) ([]byte, [32]byte, error) {
	var zero [32]byte
	meta, err := json.Marshal(capsule.Meta)
	if err != nil || len(meta) == 0 || len(meta) > ceremonyLedgerMaxMeta || len(capsule.State) > ceremonyLedgerMaxState ||
		len(capsule.Data) > ceremonyLedgerMaxData || len(capsule.Aux) > ceremonyLedgerMaxAux || capsule.Sequence == 0 {
		return nil, zero, ErrCeremonyLedger
	}
	if len(capsule.State) != 0 {
		observed := sha256.Sum256(capsule.State)
		if capsule.StateDigest != ([32]byte{}) && capsule.StateDigest != observed {
			return nil, zero, ErrCeremonyLedger
		}
		capsule.StateDigest = observed
	} else if capsule.StateDigest == ([32]byte{}) {
		return nil, zero, ErrCeremonyLedger
	}
	logical := bytes.Buffer{}
	logical.WriteString(ceremonyLedgerMagic)
	_ = binary.Write(&logical, binary.BigEndian, ceremonyLedgerVersion)
	_ = binary.Write(&logical, binary.BigEndian, capsule.Sequence)
	logical.WriteByte(byte(capsule.Kind))
	logical.Write(capsule.Previous[:])
	logical.Write(capsule.StateDigest[:])
	for _, value := range [][]byte{meta, capsule.Data, capsule.Aux} {
		_ = binary.Write(&logical, binary.BigEndian, uint32(len(value)))
		logical.Write(value)
	}
	digest := sha256.Sum256(logical.Bytes())
	var body bytes.Buffer
	body.WriteString(ceremonyLedgerMagic)
	_ = binary.Write(&body, binary.BigEndian, ceremonyLedgerVersion)
	_ = binary.Write(&body, binary.BigEndian, capsule.Sequence)
	body.WriteByte(byte(capsule.Kind))
	body.Write(capsule.Previous[:])
	body.Write(capsule.StateDigest[:])
	for _, value := range [][]byte{capsule.State, meta, capsule.Data, capsule.Aux} {
		_ = binary.Write(&body, binary.BigEndian, uint32(len(value)))
		body.Write(value)
	}
	body.Write(digest[:])
	return body.Bytes(), digest, nil
}

func readCeremonyLedgerCapsule(path string) (ceremonyLedgerCapsule, error) {
	var capsule ceremonyLedgerCapsule
	file, err := os.Open(path)
	if err != nil {
		return capsule, err
	}
	defer file.Close()
	info, err := file.Stat()
	maxSize := int64(ceremonyLedgerMaxState + ceremonyLedgerMaxMeta + ceremonyLedgerMaxData + ceremonyLedgerMaxAux + 256)
	if err != nil || info.Size() <= 0 || info.Size() > maxSize {
		return capsule, ErrCeremonyLedger
	}
	encoded, err := io.ReadAll(io.LimitReader(file, maxSize+1))
	if err != nil || len(encoded) < sha256.Size+len(ceremonyLedgerMagic)+2+8+1+32+16 {
		return capsule, ErrCeremonyLedger
	}
	body, trailer := encoded[:len(encoded)-sha256.Size], encoded[len(encoded)-sha256.Size:]
	reader := bytes.NewReader(body)
	magic := make([]byte, len(ceremonyLedgerMagic))
	var version uint16
	var kind byte
	if _, err := io.ReadFull(reader, magic); err != nil || string(magic) != ceremonyLedgerMagic ||
		binary.Read(reader, binary.BigEndian, &version) != nil || version != ceremonyLedgerVersion ||
		binary.Read(reader, binary.BigEndian, &capsule.Sequence) != nil ||
		binary.Read(reader, binary.BigEndian, &kind) != nil ||
		recoveryReadFull(reader, capsule.Previous[:], capsule.StateDigest[:]) != nil {
		return capsule, ErrCeremonyLedger
	}
	capsule.Kind = ceremonyLedgerKind(kind)
	values := make([][]byte, 4)
	limits := []int{ceremonyLedgerMaxState, ceremonyLedgerMaxMeta, ceremonyLedgerMaxData, ceremonyLedgerMaxAux}
	for index := range values {
		var length uint32
		if binary.Read(reader, binary.BigEndian, &length) != nil || int(length) > limits[index] || int(length) > reader.Len() {
			return capsule, ErrCeremonyLedger
		}
		values[index] = make([]byte, length)
		if _, err := io.ReadFull(reader, values[index]); err != nil {
			return capsule, ErrCeremonyLedger
		}
	}
	if reader.Len() != 0 || len(values[1]) == 0 || capsule.StateDigest == ([32]byte{}) {
		return capsule, ErrCeremonyLedger
	}
	if len(values[0]) != 0 && sha256.Sum256(values[0]) != capsule.StateDigest {
		return capsule, fmt.Errorf("%w: state digest", ErrCeremonyLedger)
	}
	decoder := json.NewDecoder(bytes.NewReader(values[1]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&capsule.Meta); err != nil {
		return capsule, ErrCeremonyLedger
	}
	capsule.State, capsule.Data, capsule.Aux = values[0], values[2], values[3]
	logical := bytes.Buffer{}
	logical.WriteString(ceremonyLedgerMagic)
	_ = binary.Write(&logical, binary.BigEndian, ceremonyLedgerVersion)
	_ = binary.Write(&logical, binary.BigEndian, capsule.Sequence)
	logical.WriteByte(byte(capsule.Kind))
	logical.Write(capsule.Previous[:])
	logical.Write(capsule.StateDigest[:])
	for _, value := range [][]byte{values[1], capsule.Data, capsule.Aux} {
		_ = binary.Write(&logical, binary.BigEndian, uint32(len(value)))
		logical.Write(value)
	}
	capsule.Digest = sha256.Sum256(logical.Bytes())
	if !bytes.Equal(capsule.Digest[:], trailer) {
		return capsule, fmt.Errorf("%w: checkpoint digest", ErrCeremonyLedger)
	}
	return capsule, nil
}

func compactCeremonyLedgerCapsule(path string) error {
	capsule, err := readCeremonyLedgerCapsule(path)
	if err != nil || len(capsule.State) == 0 {
		return err
	}
	capsule.State = nil
	encoded, digest, err := marshalCeremonyLedgerCapsule(capsule)
	if err != nil || digest != capsule.Digest {
		return fmt.Errorf("%w: compaction changed checkpoint authority", ErrCeremonyLedger)
	}
	return writeCeremonyLedgerAtomic(path, encoded)
}

func writeCeremonyLedgerAtomic(path string, encoded []byte) error {
	temporary := path + ".tmp"
	file, err := os.OpenFile(temporary, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		_ = file.Close()
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	if _, err := file.Write(encoded); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporary, path); err != nil {
		return err
	}
	removeTemporary = false
	directory, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer directory.Close()
	if err := directory.Sync(); err != nil && !errors.Is(err, os.ErrInvalid) {
		return err
	}
	return nil
}

func recoveryReadFull(reader io.Reader, values ...[]byte) error {
	for _, value := range values {
		if _, err := io.ReadFull(reader, value); err != nil {
			return err
		}
	}
	return nil
}
