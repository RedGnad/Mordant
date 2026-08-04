package governedfhe

import (
	"encoding/json"
	"testing"
)

// Builds a structurally valid V2 custom-supervised binding from the retained A8
// material, so the only differences from V1 are the discriminating members.
func v2Binding(t *testing.T) MordantProtectionBinding {
	t.Helper()
	binding := a8Binding(t)
	binding.SchemaVersion = ProtectionBindingSchemaV2
	binding.ProductScenario = ""
	binding.ExecutionVariant = ExecutionVariantCustomSupervised
	allocation, err := protectionHolderAllocationDigest(binding)
	if err != nil {
		t.Fatalf("allocation: %v", err)
	}
	caseID, err := protectionFHECaseID(binding, allocation)
	if err != nil {
		t.Fatalf("v2 case id: %v", err)
	}
	binding.FHECaseID = caseID
	return binding
}

func TestV2BindingIsAccepted(t *testing.T) {
	if err := v2Binding(t).Validate(); err != nil {
		t.Fatalf("a well-formed V2 custom binding must validate: %v", err)
	}
}

// The V2 binding must carry no product scenario at all, in the struct and in
// its serialized bytes.
func TestV2BindingCarriesNoExpectedResult(t *testing.T) {
	encoded, err := json.Marshal(v2Binding(t))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := decoded["productScenario"]; present {
		t.Fatalf("V2 binding must omit productScenario entirely: %s", encoded)
	}
	if decoded["executionVariant"] != ExecutionVariantCustomSupervised {
		t.Fatalf("V2 binding must carry the neutral execution variant: %s", encoded)
	}
	for _, forbidden := range []string{`"conflict"`, `"no-conflict"`} {
		if containsToken(string(encoded), forbidden) {
			t.Fatalf("V2 binding leaked %s: %s", forbidden, encoded)
		}
	}
}

func containsToken(haystack, needle string) bool {
	for index := 0; index+len(needle) <= len(haystack); index++ {
		if haystack[index:index+len(needle)] == needle {
			return true
		}
	}
	return false
}

// The V2 case ID must be deterministic and must differ from the V1 derivation
// over otherwise identical material, because the domain and members differ.
func TestV2CaseIDIsDeterministicAndDomainSeparated(t *testing.T) {
	binding := v2Binding(t)
	allocation, _ := protectionHolderAllocationDigest(binding)
	first, err := protectionFHECaseID(binding, allocation)
	if err != nil {
		t.Fatalf("v2 case id: %v", err)
	}
	second, err := protectionFHECaseID(binding, allocation)
	if err != nil || first != second {
		t.Fatalf("V2 case id must be deterministic")
	}
	if first.String() == a8ConflictFHECaseID {
		t.Fatalf("V2 case id must not collide with the V1 derivation")
	}
}

// Two custom runs whose only difference is the pledge windows are invisible
// here by construction: the binding never sees a window. Same case nonce plus
// same neutral variant must yield exactly the same binding shape and case id.
func TestV2BindingShapeIsIndependentOfAnyOutcome(t *testing.T) {
	overlapping := v2Binding(t)
	disjoint := v2Binding(t)
	overlappingBytes, _ := json.Marshal(overlapping)
	disjointBytes, _ := json.Marshal(disjoint)
	if string(overlappingBytes) != string(disjointBytes) {
		t.Fatalf("the V2 binding must not vary with anything outcome-related")
	}
	if overlapping.FHECaseID != disjoint.FHECaseID {
		t.Fatalf("V2 case id must not vary with anything outcome-related")
	}
}

func TestV2AndV1MalformedShapesAreRejected(t *testing.T) {
	for name, mutate := range map[string]func(*MordantProtectionBinding){
		"unknown schema": func(b *MordantProtectionBinding) {
			b.SchemaVersion = "mordant.protection-binding/3"
		},
		"v2 carrying a product scenario": func(b *MordantProtectionBinding) {
			b.ProductScenario = "conflict"
		},
		"v2 missing the execution variant": func(b *MordantProtectionBinding) {
			b.ExecutionVariant = ""
		},
		"v2 with an unexpected execution variant": func(b *MordantProtectionBinding) {
			b.ExecutionVariant = "CUSTOM_OTHER"
		},
		"v2 with a stale v1 case id": func(b *MordantProtectionBinding) {
			var caseID Digest
			_ = caseID.UnmarshalText([]byte(a8ConflictFHECaseID))
			b.FHECaseID = caseID
		},
		"v2 with a mismatched asset": func(b *MordantProtectionBinding) {
			b.CleanverseAssetRecordDigest = Digest{}
		},
	} {
		binding := v2Binding(t)
		mutate(&binding)
		if err := binding.Validate(); err == nil {
			t.Fatalf("V2 mutation %q must be rejected", name)
		}
	}

	// V1 must reject the V2 discriminator, and must keep rejecting an unknown
	// product scenario.
	for name, mutate := range map[string]func(*MordantProtectionBinding){
		"v1 carrying an execution variant": func(b *MordantProtectionBinding) {
			b.ExecutionVariant = ExecutionVariantCustomSupervised
		},
		"v1 with an unknown product scenario": func(b *MordantProtectionBinding) {
			b.ProductScenario = "custom-supervised"
		},
		"v1 with an empty product scenario": func(b *MordantProtectionBinding) {
			b.ProductScenario = ""
		},
	} {
		binding := a8Binding(t)
		mutate(&binding)
		if err := binding.Validate(); err == nil {
			t.Fatalf("V1 mutation %q must be rejected", name)
		}
	}
}
