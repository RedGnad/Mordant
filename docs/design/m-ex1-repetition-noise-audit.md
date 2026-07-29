# M-EX1 — Repetition and noise audit

Audit réalisé sur `main` à partir des surfaces intégrées avant M-EX1. Les `<details>` fermés sont exclus du niveau visible. Les variantes lexicales portant la même vérité métier sont regroupées.

## Diagnostic global

1. Protocol répète l’absence d’after-state six fois, son code technique cinq fois et la commande de récupération quatre fois.
2. Workspace répète quatre fois l’invariance des unités de créance et quatre fois chacun des états receivable/protection.
3. Participant répète trois fois la créance inchangée et deux fois la condition de protection au premier niveau.
4. Workspace et Protocol exposent encore des identifiants avant le mode de preuve.
5. Les tests actuels vérifient surtout l’unicité des composants, pas l’unicité sémantique.

## Deal Workspace — `Scan → Isolate → Act`

La queue, le record et la décision restent simultanés. Sélectionner un deal change son contenu sans encore retirer le portefeuille.

| Information | Occurrences visibles | Niveau cible | Décision |
|---|---:|---|---|
| Nom du deal sélectionné | 2 desktop ; 3 mobile | Isolate | **merge** — une occurrence lorsque le deal est isolé |
| Folio | 3 desktop ; 4 mobile | Evidence | **move** — aucun identifiant dans Scan/Isolate |
| État protection | 4, plus une paraphrase dans le titre | Isolate · current truth | **merge** en un seul objet dominant |
| État receivable | 4 | Isolate · Anchor | **merge** avec le montant de créance |
| Responsable | 2 | Scan ou Isolate | **merge** par transformation de composition |
| Deadline | 2 | Isolate | **merge** ; la retirer de la queue lorsque le deal s’ouvre |
| Verdict disponible | 2 dans le même panneau | Act | **merge** en une conclusion |
| Action de cure | 2 formulations | Act | **merge** en une action sûre |
| Créance non affectée | 4 formulations | Isolate · Anchor | **merge** en une phrase stable |
| Montant receivable | 1 | Isolate | **keep** |
| Montant protection | 1 | Isolate | **keep** |
| Entrée Evidence | 3 | Evidence | **merge** en un seul changement de mode |
| Mention synthetic/test | 4+ | Shell/context | **keep** une fois ; **remove** des copies locales |

Dans le mode Evidence actuel, l’état protection apparaît encore quatre fois, l’état receivable trois à quatre fois, le policy ID trois fois et l’invoice root sous deux formes. La cible est un enregistrement canonique, pas plusieurs rails qui répètent les mêmes états.

## Participant Deal Room — `Reassure → Explain → Prove`

| Information | Occurrences visibles | Niveau cible | Décision |
|---|---:|---|---|
| Conclusion personnelle | 1 | Reassure | **keep** comme objet dominant |
| Créance inchangée / reste à vous | 3 | Reassure · Anchor | **merge** en une vérité |
| Responsable Facility B | 1 | Reassure | **keep** |
| Deadline | 1 | Reassure | **keep** |
| Montant receivable | 1 | Reassure | **keep** |
| Montant potential protection | 1 | Reassure | **keep** |
| Protection reserve | 2 | Reassure · conséquence | **merge** ; utiliser un pronom après le montant |
| Condition unresolved | 2 | Reassure · conséquence | **merge** |
| Sortie vers Portfolio | 1 | Reassure | **keep** |
| Facility B dans Why | 2 au même niveau | Explain | **merge** en responsable + prochaine étape |
| Source / confirmé / non confirmé | 1 chacun | Trust | **keep** |
| Refus de capacité/rôle | environ 3 | Proof | **merge** en un résultat canonique |
| Transition absente | 2 | Proof | **merge** |
| Signature absente | 2 | Proof | **merge** |
| Invoice root | 1 | Proof | **keep** |

La règle prototype est : une seule phrase d’ancrage pour la créance ; la conséquence ne répète ensuite que le montant de protection et sa condition.

## Protocol Operations — `Locate → Diagnose → Recover`

La surface possède actuellement plus de cinq régions perceptibles. La cible M-EX1 est une séquence dominante et trois régions maximum.

| Information | Occurrences visibles | Niveau cible | Décision |
|---|---:|---|---|
| Recovery required | 3 | Locate | **merge** en un état dominant |
| Absence d’after-state | 6 formulations | Locate puis Diagnose | **merge** en une vérité humaine et un fait diagnostic |
| `after_state_unavailable` | 5 | Retained proof | **move** ; une occurrence technique |
| Dernier état sûr | 2 | Diagnose | **merge** |
| Impact receivable | 2 formulations | Locate | **merge** en « Receivable units unchanged » |
| Responsable Protocol Operations | 2 | Recover | **merge** |
| Commande de récupération | 4 | Recover puis Proof | **keep** une fois dans le runbook ; **move** une copie dans Proof |
| Folio | 4 | Proof | **move** ; une occurrence |
| Block | 3 | Proof | **merge** en une observation |
| Transition non reconstruite | 2 contiguës | Diagnose/Proof | **merge** |
| Légende de syntaxe Evidence | 1, en plus des labels | Proof | **remove** |
| Cinq préconditions | 5 | Proof | **move** le vecteur ; garder seulement la gate bloquée dans Diagnose |
| Service plate | 6 champs | Proof | **move** sous divulgation |
| Observation live non configurée | 3 messages | Proof/configuration | **merge** en une limite |

## Contrat de réduction

Les itérations suivantes doivent mesurer un budget sémantique par état : exactement un objet dominant, trois régions visibles maximum, aucun identifiant dans Decision ou Reason et une seule occurrence de chaque vérité métier par niveau.
