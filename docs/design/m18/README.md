# M-18 static validation compositions

These three fixed compositions test the selected contemporary security-document direction before
production migration begins in M-19:

- `workspace.html` — daily Deal Workspace at 100% density;
- `participant-critical.html` — critical Participant Deal Room at 60% density;
- `protocol-diagnostic.html` — proof and recovery diagnostic at 120% density.

The PNGs are the review artefacts at exactly `1280×800`. The HTML files are deliberately static and
must not be imported into the application. They share `composition.css` only to prove that one
language can survive all three contexts.

The source compositions load Newsreader and IBM Plex from Google Fonts. The checked-in PNGs preserve
the selected typography when offline.

From the repository root, regenerate and validate them with:

```bash
node docs/design/m18/render.mjs
```

The validator checks fixed viewport bounds, the 56 px chrome limit, critical above-fold content,
minimum 11 px auxiliary text, 44 px actions, mobile horizontal overflow and the approved AA text
contrast pairs. It does not replace an accessibility audit of the eventual production components.
