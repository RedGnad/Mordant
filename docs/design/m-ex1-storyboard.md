# M-EX1 — Experience storyboard

## Continuité factuelle

Le storyboard utilise exclusivement le deal synthétique `wrong-role` : Holder A détient 60/100 unités, soit `1,488,000 aUSDC` de créance et `148,800 aUSDC` de protection potentielle. Facility B est responsable avant le 29 juillet 2026 à `12:00 UTC`. La transition de cure `Cure Period → Active` est modélisée ; aucune transaction de cure n’est observée.

Les fixtures `healthy`, `wrong-role` et `protection-settled` ont des IDs et des invoice roots distincts. Elles ne sont jamais concaténées pour simuler un seul deal.

## Six frames, une seule scène

| Frame | Objet dominant | Information retirée | Rupture de grille | Transition |
|---|---|---|---|---|
| **1. Calm portfolio** | La créance financée et stable | Responsable, deadline, décision, diagnostics, preuve et identifiants | **Aucune — Anchor.** Créance et protection partagent la grille. | L’exception déplace uniquement la protection ; la créance conserve son slot DOM et ses coordonnées. |
| **2. Exception appears** | `A conflict was detected.` porté par la protection | Reste du portefeuille, filtres, compteurs, causes techniques | La protection descend et sort d’une colonne ; aucun autre objet ne rompt le rythme. | Le deal s’isole dans la même scène ; aucune nouvelle page n’est chargée. |
| **3. Deal isolated** | `Facility B must resolve by 12:00 UTC.` | Queue, folio, états répétés, machines, allocations et preuve | La prochaine étape sûre `Wait` sort du rythme ; aucune action n’est adressée au holder. | La perspective passe au holder sans déplacer l’Anchor. |
| **4. Participant informed** | `Nothing you need to do.` et la conclusion personnelle | Workspace, action contractuelle, readiness, wallet, réseau, identifiants | La protection potentielle est indentée ; la créance reste alignée. | Le contrôle narratif avance au point de décision, sans compteur animé. |
| **5. Action or deadline consequence** | `12:00 UTC.` | Navigation, explication, diagnostics et preuve | La responsabilité traverse l’axe ; le montant de protection n’apparaît que dans la conséquence. | Deux issues sont énoncées : cure avant deadline ou protection potentiellement claimable. Le prototype suit la branche de cure modélisée. |
| **6. Resolved state and proof** | `A cure would restore protection.` qualifié `Modeled outcome` | Incident, deadline, responsable, conséquence et couleur de tension | **Aucune — Resolution.** Les deux domaines retrouvent l’alignement de la frame 1 dans la branche modélisée. | `Open retained record` remplace la décision par le résumé de confiance, puis les références techniques sur demande. |

## Règles de transition

- La route reste `/design-lab/mordant-experience` pendant les six frames.
- Le même nœud receivable reste monté et immobile des frames 1 à 5.
- Un seul élément porte `data-rupture` dans chaque état anormal.
- Le changement dure `180ms` au maximum et devient immédiat en reduced motion.
- Sur mobile, Displacement devient une indentation verticale sans débordement horizontal.
- La preuve remplace la décision ; elle n’est jamais ajoutée sous la scène.

## Storyboard mobile — perspective participant

Le cadre mobile reste la même scène à quatre colonnes. Il ne devient ni une pile de cartes, ni une version réduite du Workspace.

| Frame mobile | Premier écran | Information retirée | Rupture et continuité | Geste suivant |
|---|---|---|---|---|
| **4. Participant informed** | `Nothing you need to do.` domine ; le montant de créance reste dans son emplacement stable, suivi de la protection potentielle | Queue, navigation métier, wallet, readiness, diagnostics et preuve | La protection est indentée d’une colonne. La créance ne bouge pas. Le responsable et la date restent dans une troisième région courte. | `Advance to the deadline` |
| **5. Deadline consequence** | `12:00 UTC.` devient le seul objet dominant ; la créance est encore visible et inchangée | La carte protection, l’explication, les diagnostics et tout identifiant | La responsabilité se décale de `24px` et porte seule la conséquence potentielle. Le montant de protection n’existe qu’ici. | `Show the modeled resolution` |
| **6. Modeled resolution / proof** | `A cure would restore protection.` puis, sur action, un résumé de confiance qui remplace toute la scène | Responsable, date et tension ; ensuite toute la décision lorsque Proof s’ouvre | Les domaines se réalignent avant le changement de mode. La preuve ne s’empile jamais sous la décision. | `Open retained record`, puis disclosure technique volontaire |

À `390px` comme à `320px`, l’ordre de lecture reste conclusion → domaines économiques → responsabilité → contrôle. Les cibles restent à `44px` minimum et reduced motion conserve les mêmes étapes sans interpolation.

## Honnêteté de la frame finale

La résolution est une projection issue de la conséquence de l’action modélisée. Le résumé de confiance doit afficher explicitement `Configured`, `Derived`, `Not observed` et `Not established`. Une véritable preuve finalisée de cure exige une donnée absente de cette mission et ne peut pas être empruntée au deal `protection-settled`.
