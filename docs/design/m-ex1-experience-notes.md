# M-EX1 — Notes de direction

## Ce qui a été supprimé

Le prototype retire volontairement le shell produit, la queue, la recherche, les filtres, la readiness complète, les machines, les allocations, le wallet, le réseau, les identifiants, les répétitions de montant et la preuve persistante. Ces éléments ne sont pas rapetissés : ils quittent le niveau de décision.

Dans les états critiques, il ne reste que la vérité actuelle, la créance inchangée, le responsable, la deadline, la conséquence et la prochaine action sûre. Le montant de protection disparaît de sa région habituelle à la deadline pour n’exister qu’une fois, dans la conséquence. La preuve remplace ensuite la décision et les identifiants restent repliés dans `Technical record`.

Ont également été supprimés comme signatures : codes-barres, rootlines, folios, motifs décoratifs, badges d’état, pictogrammes sans tâche, nested cards, animations ambiantes et panneaux dont la seule fonction serait d’expliquer l’interface.

## Pourquoi cette composition raconte Mordant

Un SaaS financier générique conserverait son dashboard, ajouterait une alerte et multiplierait les statuts. Mordant fait l’inverse : la conséquence soustrait l’interface. La créance reste physiquement stable parce qu’un incident de protection ne doit ni la déplacer ni suggérer qu’elle est consommée par un claim. La protection seule rompt la grille ; la responsabilité et la deadline prennent ensuite le relais ; la composition se réaligne dans l’issue modélisée.

Cette continuité donne une forme visible aux frontières du produit : créance et protection sont deux domaines économiques séparés, l’acteur responsable n’est pas le holder, et une preuve ne vaut que pour ce qu’elle établit. Le moment signature n’est donc pas un motif graphique mais un comportement : plus la conséquence augmente, plus le monde devient silencieux.

## Film de revue

Le film desktop parcourt le même deal et la même route pendant `36.44 s` : entrée calme → incident → isolation → participant → deadline → issue modélisée → résumé de confiance → preuve technique volontaire.

- Fichier : [`assets/m-ex1-review-film.webm`](./assets/m-ex1-review-film.webm)
- Reproduction : `node scripts/record-m-ex1-review-film.mjs` pendant que l’application répond sur `http://127.0.0.1:3100`.
- Le film documente le prototype ; il ne constitue ni une observation on-chain ni une autorisation de migration.
