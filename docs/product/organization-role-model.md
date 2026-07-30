# Organization-first role model

Status: future product specification only. Organization creation, invitations, SSO, RBAC, and wallet connection are not implemented.

An organization is the tenancy, policy, and accountability boundary. A user may hold one or more roles inside it. An authorized wallet is a signing instrument assigned under organizational policy; it is not an identity, a user, or a permission system.

| Role or object | Data visible | Actions allowed | Required approvals | Signature capability |
| --- | --- | --- | --- | --- |
| **Organization** | Its portfolios, policies, users, participants, incidents, evidence, and audit history | Own configuration and retention boundaries through authorized users | Organizational acceptance of pilot scope and policy | None; an organization does not sign |
| **Admin** | Organization settings, memberships, role assignments, and pilot scope; sensitive deal data only when separately granted | Manage users, roles, authorized sources, retention, and pilot access | A second admin or agreed control for sensitive role and wallet changes | Cannot sign by role alone |
| **Credit operator** | Assigned portfolios, receivable facts, exceptions, responsibility, deadlines, consequences, and non-technical evidence | Triage, assign, recommend, request information, and submit a decision for review | Human approval for consequential decisions and all production-bound actions | May request a signature; cannot sign unless separately mapped to an authorized wallet |
| **Compliance / legal reviewer** | Decision basis, policy, participant assertions, exceptions, evidence, and audit trail | Approve, reject, annotate, or escalate a decision; define evidence requirements | Required where client policy, jurisdiction, or consequence demands review | No signing by default; may co-approve under organization policy |
| **Technical operator** | Integrations, source health, schemas, contract events, hashes, receipts, and diagnostics; business data minimized | Configure authorized sources, investigate failures, replay safe reads, and export technical proof | Approval for source changes, credential rotation, or any write-capable integration | May operate an authorized technical wallet only when explicitly assigned |
| **External participant** | Only the deals, requests, deadlines, consequences, and proof shared with that participant | Respond, provide an assertion, acknowledge, or perform an explicitly assigned action | Organization review before material external submissions affect a decision | May sign a bounded assertion with an authorized wallet when policy requires it |
| **Authorized wallet** | No independent visibility; inherits the narrow context of the requesting user and action | Sign only allowlisted messages or transactions within value, contract, network, and time limits | User authorization plus any organizational approval required for that action | Yes, within its explicit policy; never grants application access by itself |

## Permission principles

- Default deny and least privilege.
- Portfolio and deal scope are separate from role.
- Visibility does not imply action permission.
- Action permission does not imply approval authority.
- Approval authority does not imply signing capability.
- Every signature resolves to an authenticated user, organization, approved intent, policy, and audit entry.
- External participants never gain organization-wide visibility.
- Technical proof may expose hashes and methods while withholding unnecessary commercial data.

The first shadow pilot may implement these controls operationally outside the product. Product RBAC starts only after discovery proves which boundaries recur across clients.
