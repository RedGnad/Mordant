# M-VF1 — Chillax typography lock

## Source archive

- Package: `Chillax_Complete`
- Family: Chillax by Fontshare / Indian Type Foundry
- Font version: 1.000 (internal font metadata; the archive has no separate semantic-version manifest)
- Web asset: `src/app/fonts/Chillax-Variable.woff2`
- SHA-256: `4554fa2df4959226daea1f25a22cd54a7e5d2539e59769d0071547713d416106`
- License: Fontshare Free Font EULA, archived at `src/app/fonts/Chillax-FFL.txt`
- Files are retained unmodified from the official package.

## Loading

`next/font/local` self-hosts the variable WOFF2 with `display: swap`; there is no external font request. The fallback chain is Arial, then the platform sans-serif. The candidate uses only Regular (400), Medium (500), and Semibold (600).

## Type sets

- Expressive: Chillax Semibold, 56–72 px desktop, 38–44 px mobile, line-height 0.98–1.00. One dominant conclusion only.
- Productive: Chillax Regular/Medium, 14–16 px body copy at 1.4–1.55 line-height; neutral tracking and sentence case.
- Data: Chillax Medium for amounts, states, dates, and currency symbols. Chillax has proportional figures: shaping with `tnum` enabled produced identical proportional advances, so tabular figures are not claimed or enabled.
- Technical: IBM Plex Mono only for hashes, contract identifiers, methods, events, commands, and technical values that need alignment.

The explicit data specimen covers `110.00`, `10.00`, `1,488,000`, `29 Jul, 23:30 UTC`, `0 / O`, and `1 / I / l`. Glyph advances distinguish zero from O and one from I/l without relying on color.

## Status

CHILLAX TYPOGRAPHY STUDY: READY FOR HUMAN REVIEW  
TYPOGRAPHY TOKENS: PROPOSED, NOT LOCKED  

