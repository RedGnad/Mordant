import assert from "node:assert/strict";
import { test } from "node:test";

import { EVIDENCE_BOUNDARIES, MORDANT_LEXICON, MORDANT_TERMS, lexiconEntry } from "./lexicon";

test("defines every official term for participant, operator, technical, and error contexts", () => {
  assert.equal(MORDANT_TERMS.length, 12);
  assert.deepEqual(Object.keys(MORDANT_LEXICON), [...MORDANT_TERMS]);

  for (const term of MORDANT_TERMS) {
    const entry = lexiconEntry(term);
    assert.ok(entry.label.length > 0);
    assert.ok(entry.participant.length > 20);
    assert.ok(entry.operator.length > 20);
    assert.ok(entry.technical.length > 20);
    assert.ok(entry.error.length > 20);
  }
});

test("keeps claims and redemption effects inside their separate domains", () => {
  assert.match(MORDANT_LEXICON.claim.operator, /does not burn or transfer invoice units/i);
  assert.match(MORDANT_LEXICON.redemption.operator, /receivable-only/i);
  assert.match(MORDANT_LEXICON.reserve.participant, /separately/i);
});

test("defines the four evidence boundaries without overclaiming", () => {
  assert.deepEqual(
    Object.values(EVIDENCE_BOUNDARIES).map((boundary) => boundary.label),
    ["Observed", "Attested", "Derived", "Not established"],
  );
  assert.match(EVIDENCE_BOUNDARIES.external.meaning, /cannot establish/i);
});
