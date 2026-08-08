# Governed recourse policy experiment evidence

These fixtures are experimental and are deliberately separated from Mordant's hardened evidence.
They make no production, legal, settlement, or institutional-authorization claim.

- `policy-a-facility-protection.json` is the immutable signed Policy A fixture.
- `policy-b-manual-escalation.json` is the immutable signed Policy B fixture.
- `same-conflict-two-policy-paths.json` binds the same retained governed conflict result to both
  policy paths and retains each selection, approval, proposed action, state history, and action
  receipt.

Regenerate deterministically with:

```bash
pnpm recourse-policy:evidence
```

Verify the focused experiment with:

```bash
pnpm recourse-policy:test
```

The source governed result remains at
`docs/evidence/conflicting-pledge-protection/conflict.json`; it is referenced and verified, not copied
or modified by the experiment.
