package oneshotruntime

import (
	"context"
	"crypto/sha256"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/tuneinsight/lattigo/v6/schemes/bgv"
	ceremony "mordant.dev/fhe-lab/lattigo/oneshotceremony"
)

type SessionValues struct {
	SessionIdentity   [32]byte
	SessionCommitment [32]byte
	Nonce             [32]byte
}

type RunResult struct {
	Scenario       string
	Context        ceremony.Context
	Reservations   []ceremony.AttemptReservation
	Bundle         ceremony.PublicBundle
	Receipt        ceremony.PublicationReceipt
	Operators      []OperatorEvidenceResponse
	StartedAt      time.Time
	EndedAt        time.Time
	OperationCount int
	EvidencePath   string
}

type Runner struct {
	config         RunnerConfig
	params         bgv.Parameters
	clients        []*OperatorClient
	context        ceremony.Context
	contextBytes   []byte
	reservations   []ceremony.AttemptReservation
	operationCount int
}

func NewRunner(config RunnerConfig, params bgv.Parameters) (*Runner, error) {
	if config.validate() != nil {
		return nil, ErrConfig
	}
	clients := make([]*OperatorClient, len(config.Operators))
	for index := range clients {
		client, err := NewOperatorClient(config.Operators[index])
		if err != nil {
			for _, opened := range clients {
				if opened != nil {
					opened.Close()
				}
			}
			return nil, err
		}
		clients[index] = client
	}
	return &Runner{config: config, params: params, clients: clients}, nil
}

func (r *Runner) Close() {
	for _, client := range r.clients {
		client.Close()
	}
}

func FreshSessionValues() (SessionValues, error) {
	identity, err := random32()
	if err != nil {
		return SessionValues{}, err
	}
	commitment, err := random32()
	if err != nil {
		return SessionValues{}, err
	}
	nonce, err := random32()
	if err != nil {
		return SessionValues{}, err
	}
	return SessionValues{SessionIdentity: identity, SessionCommitment: commitment, Nonce: nonce}, nil
}

func (r *Runner) BuildContext(values SessionValues, now time.Time) (ceremony.Context, error) {
	if values.SessionIdentity == ([32]byte{}) || values.SessionCommitment == ([32]byte{}) || values.Nonce == ([32]byte{}) {
		return ceremony.Context{}, ErrConfig
	}
	rosterPublic := identitiesFromRunner(r.config)
	revision, err := sourceRevision(rosterPublic)
	if err != nil {
		return ceremony.Context{}, err
	}
	roster := make([]ceremony.OperatorIdentity, len(rosterPublic))
	for index := range roster {
		roster[index], err = rosterPublic[index].operatorIdentity()
		if err != nil {
			return ceremony.Context{}, err
		}
	}
	template := r.config.Context
	privacy := mustDecode32(template.PrivacyDomain)
	service := mustDecode32(template.ServiceID)
	policy := mustDecode32(template.PolicyID)
	circuit := mustDecode32(template.CircuitDigest)
	contextInput := ceremony.Context{
		PrivacyDomain:         privacy,
		ServiceID:             service,
		ServiceVersion:        template.ServiceVersion,
		SessionIdentity:       values.SessionIdentity,
		SessionCommitment:     values.SessionCommitment,
		Nonce:                 values.Nonce,
		AttemptOrdinal:        ceremony.MVPAttemptOrdinal,
		ChainID:               template.ChainID,
		PolicyID:              policy,
		PolicyVersion:         template.PolicyVersion,
		CircuitVersion:        template.CircuitVersion,
		CircuitDigest:         circuit,
		ReleaseLayout:         template.ReleaseLayout,
		MaximumReleaseQueries: template.MaximumReleaseQueries,
		GaloisElements:        []uint64{r.params.GaloisElementForColRotation(1)},
		ActivatesAtUnix:       now.Unix(),
		ExpiresAtUnix:         now.Add(time.Duration(template.LifetimeSeconds) * time.Second).Unix(),
		SourceCommit:          revision,
		Operators:             roster,
	}
	return ceremony.NewContext(r.params, contextInput)
}

func (r *Runner) RunSuccess(ctx context.Context, values SessionValues) (RunResult, error) {
	started := time.Now().UTC()
	if err := r.prepare(ctx, values); err != nil {
		return RunResult{}, err
	}
	if err := r.reserveAndStart(ctx, true); err != nil {
		return RunResult{}, err
	}

	heads, err := r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	commits, err := r.collectEnvelopes(ctx, "/v1/crs-commit", HeadsRequest{Heads: heads})
	if err != nil {
		return RunResult{}, err
	}
	if err := r.acceptEnvelopes(ctx, "/v1/accept-crs-commit", commits, nil); err != nil {
		return RunResult{}, err
	}
	if _, err := r.transition(ctx, ceremony.PhaseCRSCommitted, [32]byte{}, allOperators(), allOperators()); err != nil {
		return RunResult{}, err
	}

	heads, err = r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	reveals, err := r.collectEnvelopes(ctx, "/v1/crs-reveal", HeadsRequest{Heads: heads})
	if err != nil {
		return RunResult{}, err
	}
	if err := r.acceptEnvelopes(ctx, "/v1/accept-crs-reveal", reveals, heads); err != nil {
		return RunResult{}, err
	}
	if _, err := r.transition(ctx, ceremony.PhaseCRSRevealed, [32]byte{}, allOperators(), allOperators()); err != nil {
		return RunResult{}, err
	}

	heads, err = r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	privateMessages := make([][]byte, 0, ceremony.PartyCount*ceremony.PartyCount)
	for _, client := range r.clients {
		var response PrivateMessagesResponse
		if err := r.call(ctx, client, "/v1/private-messages", HeadsRequest{Heads: heads}, &response); err != nil {
			return RunResult{}, err
		}
		privateMessages = append(privateMessages, response.Messages...)
	}
	if len(privateMessages) != ceremony.PartyCount*ceremony.PartyCount {
		return RunResult{}, ErrProtocol
	}
	heads, err = r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	receiptByRecipient := make([][][]byte, ceremony.PartyCount)
	for index, client := range r.clients {
		var response PrivateReceiptsResponse
		if err := r.call(ctx, client, "/v1/receive-private", PrivateMessagesRequest{Messages: privateMessages, Heads: heads}, &response); err != nil {
			return RunResult{}, err
		}
		if len(response.Receipts) != ceremony.PartyCount {
			return RunResult{}, ErrProtocol
		}
		receiptByRecipient[index] = response.Receipts
	}
	receipts := make([][]byte, 0, ceremony.PartyCount*ceremony.PartyCount)
	for sender := 0; sender < ceremony.PartyCount; sender++ {
		for recipient := 0; recipient < ceremony.PartyCount; recipient++ {
			receipts = append(receipts, receiptByRecipient[recipient][sender])
		}
	}
	for _, client := range r.clients {
		var response PhaseResponse
		if err := r.call(ctx, client, "/v1/accept-private", PrivateStageRequest{Messages: privateMessages, Receipts: receipts}, &response); err != nil {
			return RunResult{}, err
		}
	}
	if _, err := r.transition(ctx, ceremony.PhasePrivateShares, [32]byte{}, allOperators(), allOperators()); err != nil {
		return RunResult{}, err
	}

	if err := r.runEnvelopeStage(ctx, "/v1/public-key-share", "/v1/accept-public-key", ceremony.PhasePublicKey); err != nil {
		return RunResult{}, err
	}
	if err := r.runEnvelopeStage(ctx, "/v1/relin-one", "/v1/accept-relin-one", ceremony.PhaseRelinOne); err != nil {
		return RunResult{}, err
	}
	if err := r.runEnvelopeStage(ctx, "/v1/relin-two", "/v1/accept-relin-two", ceremony.PhaseRelinTwo); err != nil {
		return RunResult{}, err
	}
	for index := range r.context.GaloisElements {
		heads, err = r.heads(ctx)
		if err != nil {
			return RunResult{}, err
		}
		shares := make([][]byte, len(r.clients))
		for operator, client := range r.clients {
			var response EnvelopeResponse
			if err := r.call(ctx, client, "/v1/galois-share", GaloisRequest{Index: index, Heads: heads}, &response); err != nil {
				return RunResult{}, err
			}
			shares[operator] = response.Envelope
		}
		for _, client := range r.clients {
			var response PhaseResponse
			if err := r.call(ctx, client, "/v1/accept-galois", AcceptGaloisRequest{Index: index, Envelopes: shares, Heads: heads}, &response); err != nil {
				return RunResult{}, err
			}
		}
		if _, err := r.transition(ctx, ceremony.PhaseGalois, [32]byte{}, allOperators(), allOperators()); err != nil {
			return RunResult{}, err
		}
	}

	heads, err = r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	states := make([]PublicStateResponse, len(r.clients))
	for index, client := range r.clients {
		if err := r.call(ctx, client, "/v1/public-state", HeadsRequest{Heads: heads}, &states[index]); err != nil {
			return RunResult{}, err
		}
	}
	if !publicStatesEqual(states) {
		return RunResult{}, ErrProtocol
	}
	transcript, err := ceremony.ParseTranscript(r.context, states[0].Transcript)
	if err != nil {
		return RunResult{}, err
	}
	material := ceremony.PublicMaterial{PublicKeyBytes: states[0].PublicKey, RelinearizationBytes: states[0].RelinearizationKey, GaloisKeyBytes: states[0].GaloisKeys}
	unsigned, err := ceremony.BuildUnsignedPublicBundle(r.params, r.context, transcript, material, states[0].PreManifestWitness)
	if err != nil {
		return RunResult{}, err
	}
	unsignedBytes, err := unsigned.MarshalBinary()
	if err != nil {
		return RunResult{}, err
	}
	for _, client := range r.clients {
		var response PhaseResponse
		if err := r.call(ctx, client, "/v1/set-manifest", DigestRequest{Digest: unsigned.Digest()}, &response); err != nil {
			return RunResult{}, err
		}
	}
	if _, err := r.transition(ctx, ceremony.PhaseManifest, [32]byte{}, allOperators(), allOperators()); err != nil {
		return RunResult{}, err
	}
	heads, err = r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	attestations := make([]ceremony.SignedEnvelope, len(r.clients))
	ready := make([]ceremony.SignedEnvelope, len(r.clients))
	for index, client := range r.clients {
		var response EnvelopeResponse
		if err := r.call(ctx, client, "/v1/attest-bundle", UnsignedBundleRequest{UnsignedBundle: unsignedBytes, Heads: heads}, &response); err != nil {
			return RunResult{}, err
		}
		attestations[index], err = ceremony.ParseSignedEnvelope(response.Envelope)
		if err != nil {
			return RunResult{}, err
		}
	}
	heads, err = r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	for index, client := range r.clients {
		var response EnvelopeResponse
		if err := r.call(ctx, client, "/v1/private-ready", UnsignedBundleRequest{UnsignedBundle: unsignedBytes, Heads: heads}, &response); err != nil {
			return RunResult{}, err
		}
		ready[index], err = ceremony.ParseSignedEnvelope(response.Envelope)
		if err != nil {
			return RunResult{}, err
		}
	}
	bundle, err := ceremony.BuildPublicBundle(unsigned, attestations, ready)
	if err != nil {
		return RunResult{}, err
	}
	bundleBytes, err := bundle.MarshalBinary()
	if err != nil {
		return RunResult{}, err
	}
	receipt, err := ceremony.PublishPublicBundle(r.config.PublicationRoot, bundle)
	if err != nil {
		return RunResult{}, err
	}
	if ceremony.VerifyPublicationReceipt(receipt, bundle) != nil {
		return RunResult{}, ErrProtocol
	}
	for _, client := range r.clients {
		var response PhaseResponse
		if err := r.call(ctx, client, "/v1/install-published", PublishedRequest{Bundle: bundleBytes, Receipt: receipt}, &response); err != nil {
			return RunResult{}, err
		}
	}
	if _, err := r.transition(ctx, ceremony.PhasePublished, [32]byte{}, allOperators(), allOperators()); err != nil {
		return RunResult{}, err
	}
	for _, client := range r.clients {
		var response PhaseResponse
		if err := r.call(ctx, client, "/v1/set-completed", PublishedRequest{Bundle: bundleBytes, Receipt: receipt}, &response); err != nil {
			return RunResult{}, err
		}
	}
	if _, err := r.transition(ctx, ceremony.PhaseCompleted, [32]byte{}, allOperators(), allOperators()); err != nil {
		return RunResult{}, err
	}

	heads, err = r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	operatorEvidence, replicas, err := r.collectEvidence(ctx, r.context)
	if err != nil {
		return RunResult{}, err
	}
	if ceremony.VerifyPublishedCeremony(r.context, bundle, receipt, replicas...) != nil {
		return RunResult{}, ErrProtocol
	}
	replicaBytes := make([][][]byte, len(operatorEvidence))
	for index := range operatorEvidence {
		replicaBytes[index] = operatorEvidence[index].Records
	}
	for _, client := range r.clients {
		var response FinalizeResponse
		if err := r.call(ctx, client, "/v1/finalize-private", FinalizeRequest{Bundle: bundleBytes, Receipt: receipt, Heads: heads, Replicas: replicaBytes}, &response); err != nil || !response.Finalized {
			return RunResult{}, ErrProtocol
		}
	}
	ended := time.Now().UTC()
	result := RunResult{Scenario: "SUCCESS", Context: r.context, Reservations: slices.Clone(r.reservations), Bundle: bundle, Receipt: receipt, Operators: operatorEvidence, StartedAt: started, EndedAt: ended, OperationCount: r.operationCount}
	result.EvidencePath, err = ExportRunEvidence(r.config.EvidenceRoot, result)
	return result, err
}

func (r *Runner) RunStaleReplica(ctx context.Context, values SessionValues) (RunResult, error) {
	started := time.Now().UTC()
	if err := r.prepare(ctx, values); err != nil {
		return RunResult{}, err
	}
	if err := r.reserveAndStart(ctx, true); err != nil {
		return RunResult{}, err
	}
	heads, err := r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	commits, err := r.collectEnvelopes(ctx, "/v1/crs-commit", HeadsRequest{Heads: heads})
	if err != nil {
		return RunResult{}, err
	}
	if err := r.acceptEnvelopes(ctx, "/v1/accept-crs-commit", commits, nil); err != nil {
		return RunResult{}, err
	}
	if _, err := r.transition(ctx, ceremony.PhaseCRSCommitted, [32]byte{}, allOperators(), []int{0, 1}); err != nil {
		return RunResult{}, err
	}
	divergent, err := r.heads(ctx)
	if err != nil {
		return RunResult{}, err
	}
	var envelope EnvelopeResponse
	if err := r.call(ctx, r.clients[0], "/v1/crs-reveal", HeadsRequest{Heads: divergent}, &envelope); err == nil {
		return RunResult{}, ErrProtocol
	}
	if err := r.call(ctx, r.clients[1], "/v1/crs-reveal", HeadsRequest{Heads: divergent}, &envelope); err == nil {
		return RunResult{}, ErrProtocol
	}
	if err := r.call(ctx, r.clients[2], "/v1/crs-commit", HeadsRequest{Heads: divergent}, &envelope); err == nil {
		return RunResult{}, ErrProtocol
	}
	evidence, _, err := r.collectEvidence(ctx, r.context)
	if err != nil {
		return RunResult{}, err
	}
	for index, item := range evidence {
		if item.RuntimeState != "POISONED" || index < ceremony.Threshold && len(item.TerminalTombstone) == 0 {
			return RunResult{}, ErrProtocol
		}
	}
	ended := time.Now().UTC()
	result := RunResult{Scenario: "STALE_REPLICA", Context: r.context, Reservations: slices.Clone(r.reservations), Operators: evidence, StartedAt: started, EndedAt: ended, OperationCount: r.operationCount}
	result.EvidencePath, err = ExportRunEvidence(r.config.EvidenceRoot, result)
	return result, err
}

func (r *Runner) RunAbort(ctx context.Context, values SessionValues) (RunResult, error) {
	started := time.Now().UTC()
	if err := r.prepare(ctx, values); err != nil {
		return RunResult{}, err
	}
	if err := r.reserveAndStart(ctx, true); err != nil {
		return RunResult{}, err
	}
	reason := sha256.Sum256([]byte("mordant-oneshot-mvp-operator-abort"))
	if _, err := r.transition(ctx, ceremony.PhaseAborted, reason, []int{0, 1}, allOperators()); err != nil {
		return RunResult{}, err
	}
	evidence, _, err := r.collectEvidence(ctx, r.context)
	if err != nil {
		return RunResult{}, err
	}
	for _, item := range evidence {
		if item.Phase != ceremony.PhaseAborted || item.RuntimeState != "ABORTED" || len(item.TerminalTombstone) == 0 {
			return RunResult{}, ErrProtocol
		}
	}
	ended := time.Now().UTC()
	result := RunResult{Scenario: "ABORT", Context: r.context, Reservations: slices.Clone(r.reservations), Operators: evidence, StartedAt: started, EndedAt: ended, OperationCount: r.operationCount}
	result.EvidencePath, err = ExportRunEvidence(r.config.EvidenceRoot, result)
	return result, err
}

func (r *Runner) VerifyRestartConsumed(ctx context.Context, original ceremony.Context, newNonce [32]byte) error {
	if newNonce == ([32]byte{}) || newNonce == original.Nonce {
		return ErrConfig
	}
	values := SessionValues{SessionIdentity: original.SessionIdentity, SessionCommitment: original.SessionCommitment, Nonce: newNonce}
	if err := r.prepare(ctx, values); err != nil {
		return err
	}
	heads, err := r.heads(ctx)
	if err != nil {
		return err
	}
	for _, client := range r.clients {
		var reservation ReservationResponse
		err := r.call(ctx, client, "/v1/reserve", HeadsRequest{Heads: heads}, &reservation)
		if err == nil || remoteCode(err) != "REPLAY_REJECTED" && remoteCode(err) != "PERSISTENCE_REJECTED" {
			return ErrProtocol
		}
		var phase PhaseResponse
		if beginErr := r.call(ctx, client, "/v1/begin-secrets", HeadsRequest{Heads: heads}, &phase); beginErr == nil {
			return ErrProtocol
		}
	}
	return nil
}

func (r *Runner) prepare(ctx context.Context, values SessionValues) error {
	contextValue, err := r.BuildContext(values, time.Now().UTC())
	if err != nil {
		return err
	}
	encoded, err := contextValue.MarshalBinary()
	if err != nil {
		return err
	}
	r.context, r.contextBytes, r.reservations = contextValue, encoded, nil
	for _, client := range r.clients {
		var response PhaseResponse
		if err := r.call(ctx, client, "/v1/prepare", PrepareRequest{Context: encoded}, &response); err != nil {
			return err
		}
		if response.Phase != ceremony.PhaseNotStarted {
			return ErrProtocol
		}
	}
	return nil
}

func (r *Runner) reserveAndStart(ctx context.Context, beginSecrets bool) error {
	heads, err := r.heads(ctx)
	if err != nil {
		return err
	}
	r.reservations = make([]ceremony.AttemptReservation, len(r.clients))
	reservationBytes := make([][]byte, len(r.clients))
	for index, client := range r.clients {
		var response ReservationResponse
		if err := r.call(ctx, client, "/v1/reserve", HeadsRequest{Heads: heads}, &response); err != nil {
			return err
		}
		reservation, err := ceremony.ParseAttemptReservation(response.Reservation)
		if err != nil || ceremony.VerifyAttemptReservation(r.context, reservation) != nil || reservation.OperatorPoint != uint64(index+1) {
			return ErrProtocol
		}
		r.reservations[index], reservationBytes[index] = reservation, response.Reservation
	}
	for _, client := range r.clients {
		var response PhaseResponse
		if err := r.call(ctx, client, "/v1/accept-reservations", ReservationsRequest{Reservations: reservationBytes}, &response); err != nil {
			return err
		}
	}
	if _, err := r.transition(ctx, ceremony.PhaseReserved, [32]byte{}, allOperators(), allOperators()); err != nil {
		return err
	}
	if _, err := r.transition(ctx, ceremony.PhaseRunning, [32]byte{}, allOperators(), allOperators()); err != nil {
		return err
	}
	if beginSecrets {
		heads, err = r.heads(ctx)
		if err != nil {
			return err
		}
		for _, client := range r.clients {
			var response PhaseResponse
			if err := r.call(ctx, client, "/v1/begin-secrets", HeadsRequest{Heads: heads}, &response); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *Runner) transition(ctx context.Context, to ceremony.Phase, reason [32]byte, signers, committers []int) (ceremony.WitnessRecord, error) {
	if len(signers) == 0 || len(committers) == 0 {
		return ceremony.WitnessRecord{}, ErrProtocol
	}
	var proposal TransitionProposalResponse
	if err := r.call(ctx, r.clients[signers[0]], "/v1/propose-transition", TransitionProposalRequest{ToPhase: to, ReasonDigest: reason}, &proposal); err != nil {
		return ceremony.WitnessRecord{}, err
	}
	heads, err := r.heads(ctx)
	if err != nil {
		return ceremony.WitnessRecord{}, err
	}
	signatures := make([]ceremony.WitnessSignature, len(signers))
	for index, signer := range signers {
		var response SignTransitionResponse
		if err := r.call(ctx, r.clients[signer], "/v1/sign-transition", SignTransitionRequest{Statement: proposal.Statement, Heads: heads}, &response); err != nil {
			return ceremony.WitnessRecord{}, err
		}
		signatures[index] = response.Signature
	}
	record, err := ceremony.AssembleWitnessRecord(r.context, proposal.Statement, signatures)
	if err != nil {
		return ceremony.WitnessRecord{}, err
	}
	encoded, err := record.MarshalBinary()
	if err != nil {
		return ceremony.WitnessRecord{}, err
	}
	for _, committer := range committers {
		var response PhaseResponse
		if err := r.call(ctx, r.clients[committer], "/v1/commit-transition", CommitTransitionRequest{Record: encoded}, &response); err != nil {
			return ceremony.WitnessRecord{}, err
		}
		if response.Phase != to {
			return ceremony.WitnessRecord{}, ErrProtocol
		}
	}
	return record, nil
}

func (r *Runner) heads(ctx context.Context) ([]ceremony.ReplicaHeadAttestation, error) {
	heads := make([]ceremony.ReplicaHeadAttestation, len(r.clients))
	for index, client := range r.clients {
		var response HeadResponse
		if err := r.call(ctx, client, "/v1/head", EmptyRequest{}, &response); err != nil {
			return nil, err
		}
		heads[index] = response.Head
	}
	return heads, nil
}

func (r *Runner) runEnvelopeStage(ctx context.Context, generate, accept string, phase ceremony.Phase) error {
	heads, err := r.heads(ctx)
	if err != nil {
		return err
	}
	envelopes, err := r.collectEnvelopes(ctx, generate, HeadsRequest{Heads: heads})
	if err != nil {
		return err
	}
	if err := r.acceptEnvelopes(ctx, accept, envelopes, heads); err != nil {
		return err
	}
	_, err = r.transition(ctx, phase, [32]byte{}, allOperators(), allOperators())
	return err
}

func (r *Runner) collectEnvelopes(ctx context.Context, path string, request any) ([][]byte, error) {
	result := make([][]byte, len(r.clients))
	for index, client := range r.clients {
		var response EnvelopeResponse
		if err := r.call(ctx, client, path, request, &response); err != nil {
			return nil, err
		}
		if _, err := ceremony.ParseSignedEnvelope(response.Envelope); err != nil {
			return nil, err
		}
		result[index] = response.Envelope
	}
	return result, nil
}

func (r *Runner) acceptEnvelopes(ctx context.Context, path string, envelopes [][]byte, heads []ceremony.ReplicaHeadAttestation) error {
	for _, client := range r.clients {
		var response PhaseResponse
		var err error
		if path == "/v1/accept-crs-commit" {
			err = r.call(ctx, client, path, EnvelopesRequest{Envelopes: envelopes}, &response)
		} else {
			request := struct {
				Envelopes [][]byte                          `json:"envelopes"`
				Heads     []ceremony.ReplicaHeadAttestation `json:"heads"`
			}{Envelopes: envelopes, Heads: heads}
			err = r.call(ctx, client, path, request, &response)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *Runner) collectEvidence(ctx context.Context, contextValue ceremony.Context) ([]OperatorEvidenceResponse, [][]ceremony.WitnessRecord, error) {
	contextBytes, err := contextValue.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	evidence := make([]OperatorEvidenceResponse, len(r.clients))
	replicas := make([][]ceremony.WitnessRecord, len(r.clients))
	for index, client := range r.clients {
		if err := r.call(ctx, client, "/v1/evidence", EvidenceRequest{Context: contextBytes}, &evidence[index]); err != nil {
			return nil, nil, err
		}
		if !sameIdentity(evidence[index].Identity, r.config.Operators[index].Identity) {
			return nil, nil, ErrProtocol
		}
		replicas[index] = make([]ceremony.WitnessRecord, len(evidence[index].Records))
		for recordIndex, encoded := range evidence[index].Records {
			record, err := ceremony.ParseWitnessRecord(encoded)
			if err != nil {
				return nil, nil, err
			}
			replicas[index][recordIndex] = record
		}
	}
	return evidence, replicas, nil
}

func (r *Runner) call(ctx context.Context, client *OperatorClient, path string, input, output any) error {
	r.operationCount++
	return client.call(ctx, path, input, output)
}

func allOperators() []int { return []int{0, 1, 2} }

func publicStatesEqual(states []PublicStateResponse) bool {
	if len(states) != ceremony.PartyCount {
		return false
	}
	first := states[0]
	for _, state := range states[1:] {
		if !slices.Equal(first.Transcript, state.Transcript) || !slices.Equal(first.PublicKey, state.PublicKey) ||
			!slices.Equal(first.RelinearizationKey, state.RelinearizationKey) || first.PreManifestWitness != state.PreManifestWitness ||
			len(first.GaloisKeys) != len(state.GaloisKeys) {
			return false
		}
		for index := range first.GaloisKeys {
			if !slices.Equal(first.GaloisKeys[index], state.GaloisKeys[index]) {
				return false
			}
		}
	}
	return true
}

func LoadContextFromEvidence(path string) (ceremony.Context, error) {
	data, err := os.ReadFile(filepath.Join(path, "context.bin"))
	if err != nil {
		return ceremony.Context{}, ErrEvidence
	}
	return ceremony.ParseContext(data)
}
