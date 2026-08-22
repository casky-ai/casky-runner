# Vendored copy of `@casky/ui-kit`

This directory is a **snapshot** of `packages/ui-kit/` from the separate
`claude-skills-security` monorepo, copied into this repo **at build time**
(see `casky-ui/package.json`'s `"@casky/ui-kit": "file:./vendor/ui-kit"`
dependency) because that package is not yet published to public npm.

## Why this exists

`casky-ui` (this app) needs the same presentational components, types, and
design tokens that `claude-skills-security/apps/web` uses — `SeverityBadge`,
`FindingCard`, `MitreTechniqueChip`, `RemediationTable`, `KeyFindingsTable`,
`MarkdownReport`, `InvestigationStepRow`, `ConfidenceMeter` — so that both
apps render findings/investigations identically. Until `@casky/ui-kit` is
published, the only way to consume it from this separate repo is to vendor
a copy of its source.

## What to do once `@casky/ui-kit` is published to npm

1. Delete this entire `casky-ui/vendor/ui-kit/` directory.
2. In `casky-ui/package.json`, change:
   ```diff
   -  "@casky/ui-kit": "file:./vendor/ui-kit",
   +  "@casky/ui-kit": "^0.0.1",
   ```
   (or whatever semver range is appropriate at publish time).
3. Run `npm install` (or the app's package manager equivalent) in `casky-ui/`.

No other changes are needed — every `import { ... } from '@casky/ui-kit'`
in `casky-ui/` resolves the same way before and after this swap, because
the package name never changes, only where it resolves from.

## Do not edit the files in `src/` here directly

If a bug or missing prop is found, fix it upstream in
`claude-skills-security/packages/ui-kit/src/` and re-copy, rather than
patching this vendored snapshot — otherwise the two copies drift and the
eventual npm swap becomes a real merge instead of a one-line dependency bump.
