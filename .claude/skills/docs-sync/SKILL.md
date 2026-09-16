---
name: docs-sync
description: Review a branch or PR for documentation and comment drift - stale docs, outdated doc-comments and @code examples, numeric constants in docs that no longer match the code, and inline comments elsewhere in the tree that describe changed behavior. Use before opening or merging a PR, or when asked whether the docs are still accurate.
user-invocable: true
allowed-tools: Read, Grep, Glob, Bash
---

# Documentation Sync Review

Review the change under review for documentation drift it introduces or sits
next to. Report findings only; do not edit files. The normative rules live in
`docs/conventions.md` ("Documentation"); this checklist applies them to a
diff.

## Scope

Determine the diff: if `$ARGUMENTS` contains a PR number, use
`gh pr diff <N>`; otherwise diff the current branch against main
(`git diff main...HEAD`), falling back to uncommitted changes
(`git diff HEAD`) if the branch has no commits yet. If the review
environment already supplies the diff (for example an automated PR review),
review that diff directly instead of computing one.

Documentation drift is a defect in this project: a behavior change is not
complete until every description of that behavior is updated in the same PR.

## Sync surfaces

For every behavioral or API change in the diff, check each of these:

1. **`docs/internals.md`**: threading, draining, connection lifecycle, sync
   task, time sync, and ordering-guarantee changes must be reflected. This
   file describes how the current code works; anything it says that the diff
   makes untrue is a finding.
2. **`docs/integration-guide.md`**: public API shape, listener contracts,
   configuration reference, enums reference, and the thread-safety summary.
3. **`CLAUDE.md`**: the key-class list, project layout, and conventions
   sections, when the structure they describe changes.
4. **`README.md`** and **`examples/`**: features and usage that the diff
   renames, removes, or reshapes.
5. **Header doc-comments** in `include/sendspin/`: `@brief`/`@param`/`@return`
   text, threading notes, and especially `@code` usage examples, which must
   construct current types with current fields in the current order.
6. **`config.h` field docs**: defaults and semantics quoted in doc comments.
7. **Inline comments anywhere in the tree**: grep for the names of functions,
   constants, messages, and fields the diff changes, and read the surrounding
   comments in files the diff does NOT touch. A comment describing the old
   behavior of a changed function is a finding even three files away.

## Checks

- **Numbers match**: any numeric value quoted in a doc or comment (defaults,
  capacities, timeouts, filter constants, version numbers) must match the
  code after the diff. Verify against the source, not the diff hunk alone.
- **Symbols exist**: docs and examples must not reference removed or renamed
  types, fields, methods, or config options. Removal is sync too: a deleted
  feature must be pruned from every doc that mentions it.
- **Behavior derived from current code**: descriptions must state what the
  code does now. Flag text that describes a removed workaround, preserves a
  superseded rationale, or narrates history ("previously", "now uses").
- **Workarounds are not laundered**: if the diff adds a workaround, the docs
  must not present it as designed behavior.
- **New behavior is documented**: a new public API, config field, listener
  callback, or threading requirement with no corresponding guide/header doc
  update is a finding.
- **The diff's own new docs match the diff's own new code**: doc text and
  doc comments added or rewritten by the diff are checked against the
  implementation the same way pre-existing docs are. A brand-new comment
  claiming an overhead calculation, default, or behavior the adjacent new
  code does not actually perform is drift from day one; verify each concrete
  claim in added doc text against the code it describes.

## Scope discipline

Only require fixes for drift the diff introduces or that lives in sections
the diff touches. Pre-existing drift elsewhere is reported separately as
"out of scope, worth a follow-up" and must not block the branch.

## Report format

Two sections: **In scope** (must fix before merge) and **Out of scope**
(pre-existing drift, note only). For each finding give the doc location
(file:line), what the doc says, what the code actually does (file:line), and
the minimal correction.
