# Test-vector execution

The manifest contains scenario labels and expected **public** outcomes, never pledge values. A
provider harness owns a client-runtime profile resolver. That resolver must not be callable from the
evaluator process and must not serialize its material.

For each normal case the harness creates two encrypted envelopes and evaluates:

```text
sameReceivable
AND sameCurrency
AND (a.activeFrom < b.activeUntil)
AND (b.activeFrom < a.activeUntil)
AND a.exclusive
AND b.exclusive
AND authorizedA
AND authorizedB
```

The `periods-adjacent-no-overlap` case is the boundary condition: if one period ends exactly when the
other starts, at least one strict comparison is false and the final result is false.

Rejected-ingress cases must emit only their stable `errorCode`. They must not include a decoded
field, ciphertext fragment, parser offset tied to confidential material, stack dump, or serialized
exception. Monad-rejected cases use a correctly constructed public result except for the declared
mutation, so the intended guard is tested rather than an earlier accidental failure.
