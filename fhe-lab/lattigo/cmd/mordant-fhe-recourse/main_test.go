package main

import "testing"

func TestRecourseRequestRejectsCallerClockAndRecordDate(t *testing.T) {
	valid := []byte(`{"assetIdentity":"sha256:1111111111111111111111111111111111111111111111111111111111111111","caseId":"sha256:2222222222222222222222222222222222222222222222222222222222222222","expectedPins":{"participantArtifactDigestA":"sha256:1111111111111111111111111111111111111111111111111111111111111111","participantArtifactDigestB":"sha256:1111111111111111111111111111111111111111111111111111111111111111","evaluatedArtifactDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","recomputedResultCiphertextDigest":"sha256:1111111111111111111111111111111111111111111111111111111111111111","resultCiphertextCommitment":"sha256:1111111111111111111111111111111111111111111111111111111111111111","decryptorProvenance":"sha256:1111111111111111111111111111111111111111111111111111111111111111","releaseMode":"governed-decryptor-v1","releaseAuthorityId":"sha256:1111111111111111111111111111111111111111111111111111111111111111"}}`)
	var request recourseRequest
	if err := decodeStrictRequest(valid, &request); err != nil {
		t.Fatalf("valid bounded request: %v", err)
	}
	for _, extra := range []string{`,"recordDateUnix":1}`, `,"nowUnix":1}`, `,"chronology":[]}`} {
		candidate := append(append([]byte(nil), valid[:len(valid)-1]...), []byte(extra)...)
		if err := decodeStrictRequest(candidate, &recourseRequest{}); err == nil {
			t.Fatalf("caller-controlled field accepted: %s", extra)
		}
	}
}
