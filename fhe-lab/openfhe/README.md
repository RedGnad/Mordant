# OpenFHE gate result

## Candidate

- OpenFHE `1.5.1`, released 10 April 2026.
- BSD-2-Clause.
- Official repository: <https://github.com/openfheorg/openfhe-development/tree/v1.5.1>
- License: <https://github.com/openfheorg/openfhe-development/blob/v1.5.1/LICENSE>

## What works independently

OpenFHE exposes exact Boolean/integer comparison through BinFHE/FHEW (`EvalSign`) and documents
threshold extensions for BGV, BFV, and CKKS. It also supports binary and JSON serialization. Those
capabilities are useful separately, but the Mordant policy requires comparison and threshold
decryption in the same circuit.

Relevant official examples and documentation:

- exact sign/comparison example:
  <https://github.com/openfheorg/openfhe-development/blob/v1.5.1/src/binfhe/examples/eval-sign.cpp>
- threshold documentation:
  <https://github.com/openfheorg/openfhe-development/blob/v1.5.1/docs/static_docs/Threshold_FHE.md>
- serialization examples:
  <https://github.com/openfheorg/openfhe-development/tree/v1.5.1/src/pke/examples>

## Blocking compatibility result

The official threshold support covers BGV, BFV, and CKKS, not threshold FHEW. Scheme switching for
comparison still requires an FHEW secret/bootstrap key. An OpenFHE maintainer stated that threshold
FHEW is not implemented:

<https://openfhe.discourse.group/t/does-large-precision-comparison-have-any-relevant-reference-papers-can-the-current-threshold-version-of-ckks-be-used-for-scheme-switching-fhew-and-comparison/1228>

The issue remains current in June 2026. A maintainer confirmed that the scheme-switching parameters
were tested for the single-key path; combining current multiparty key generation with scheme
switching can produce probabilistically incorrect comparisons:

<https://openfhe.discourse.group/t/multiparty-sceheme-switching-non-probibalistic/2325>

## Decision

`NO-GO OPENFHE FOR THIS TEN-DAY SLICE`

This is not a rejection of OpenFHE generally. It is a rejection of claiming a reliable, exact,
threshold comparison circuit with the current supported combination. A single-key OpenFHE circuit
would not satisfy Mordant's target trust model and would duplicate the only part Lattigo can test
without resolving the decisive threshold question.

Re-evaluate when OpenFHE ships and tests threshold BinFHE/FHEW or officially supports multiparty
scheme switching with correctness parameters for exact comparisons.
