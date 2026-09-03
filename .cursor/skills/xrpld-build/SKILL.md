---
name: xrpld-build
description: >-
  Orchestrates xrpld / rippled implementation as a Custom Mode. Splits a spec
  into multiple PRs, launches one subagent per PR, and enforces this repo's
  conventions (amendments, transactors, jtx, levelization, clang-format). Use
  when building, implementing, or coding a feature, amendment, XLS, transaction
  type, ledger object, RPC, bug fix, or protocol change in this codebase.
icon: code
color: orange
---

# xrpld-build

Playbook for building in this repo. Keep this skill on as a Custom Mode
(`/xrpld-build`, then Option+Enter / Use as Mode).

The main agent works as an orchestrator. There should always be near 100%
unit test coverage. Subagents should be used to break out the spec into
multiple PRs. Each of those PRs should be implemented with a different
subagent.

Honor every `.cursor/rules` file. If a rule forbids `gh`, the GitHub API, or
inspecting prior PRs/branches, do not do those things — still produce isolated
branches and reviewable diffs.

Read [conventions.md](conventions.md) before any implementer starts coding.

## Orchestrator role

The main agent does **not** implement a feature end-to-end in this chat.

1. Read the spec (XLS, issue, or user brief). Ask only if a requirement is
   actually ambiguous.
2. Map the work onto this repo's layers (see [PR slices](#pr-slices)).
3. Publish a split plan and wait for approval unless the user already said
   to proceed.
4. Launch **one new `generalPurpose` Task subagent per PR**. Never reuse the
   same subagent ID for two PRs. Never implement a planned PR yourself.
5. After each subagent returns: review the diff against this playbook, run
   the scoped tests, then start the next slice (or the next independent
   slice in parallel).
6. Integrate: stacked branches stay rebaseable; each commit builds and its
   tests pass.

Use `explore` only for read-only research (find files, existing patterns).
Use `generalPurpose` for implementation.

### Subagent brief (required)

Every implementer prompt must include:

- PR title (`feat:` / `fix:` / `refactor:` / `test:` …) and one-paragraph
  scope
- Allowed paths (and what is **out** of scope)
- Base branch
- Neighbor files to copy (a concrete transactor, jtx helper, or test)
- Test command for this slice
- "Follow `.cursor/skills/xrpld-build/SKILL.md` and `conventions.md`"
- "Do not use `gh` or inspect remote PRs/branches if project rules forbid it"
- "Near 100% unit test coverage for code this PR introduces"

## PR slices

Default to **independent** PRs off the default branch. Stack only when the
dependency is real (protocol macros before transactors before RPC).

Typical amendment / new-tx split:

| Order | Slice | Touches |
| --- | --- | --- |
| 1 | Protocol surface | `features.macro`, `sfields.macro`, `transactions.macro` / `ledger_entries.macro`, `TER.h`, `TxFlags.h`, `jss.h`, then `code_gen` |
| 2 | Transactors + helpers | `include/xrpl/tx/transactors/…`, `src/libxrpl/tx/…`, ledger helpers, indexes/keylets |
| 3 | Invariants | `visitInvariantEntry` / `finalizeInvariants`, `src/test/app/Invariants_test.cpp` if the object needs one |
| 4 | jtx + unit tests | `src/test/jtx/…`, `src/test/app/…_test.cpp` (or `src/tests` for new gtest) |
| 5 | RPC / API | handlers, docs in `API-CHANGELOG.md` only if the RPC surface changed |

Do **not** dump protocol, apply logic, and tests into one PR. A bug fix that
touches one function can stay a single PR — still give it its own subagent.

Each PR must be well-formed on its own: it compiles, its tests pass, and a
reviewer can understand it without the later slices.

## Coverage

There should always be near 100% unit test coverage of **new and changed**
apply/preflight/preclaim/helper/RPC paths.

Minimum for every behavior this work adds:

- Amendment **off** → `temDISABLED` (or the existing disabled TER)
- Amendment **on**, happy path, ledger fields, owner-count / reserve
- Every distinct `tec` / `tem` / `tef` this code can return
- Flag and field combinations the spec names
- Delete / expire / replace if the object has a lifecycle
- Invariant failures if you added invariant checks
- RPC request/response fields if you added or changed a handler

Put tests next to the behavior: `src/test/app` (beast + jtx) for transactors;
`src/tests` (gtest) only when matching that tree. Prefer extending an existing
suite over a new file.

Offline tests must finish in under 60 seconds (`xrpld --unittest …`).

Do not claim done without running the suites this slice owns:

```bash
xrpld --unittest SuiteName --unittest-jobs=<cores>
```

## Implementation gates

Stop and fix before the next slice if any of these fail:

- clang-format 21 (`.clang-format`); `clang-format off` only when unreadability
  is worse than the formatter
- clang-tidy (`.clang-tidy`)
- Header includes stay [levelized](../../../.github/scripts/levelization)
- New protocol macros regenerated: `cmake --build . --target code_gen`
- No new cyclic includes; if you fix a cycle, regenerate levelization results
- Transaction-processing changes are behind `view.rules().enabled(featureX)`
- New amendment: `Supported::No`, `VoteBehavior::DefaultNo` until the feature
  is complete — never flip a released `Supported::Yes` back to `No`

## Definition of done (whole spec)

- [ ] Split plan published; one subagent per PR; main agent did not implement
      those PRs
- [ ] Each PR is a logical commit (or a short logical sequence), imperative
      subject ≤50 chars, body explains why
- [ ] Near 100% unit test coverage on new/changed paths; suites run
- [ ] Format, tidy, levelization, codegen clean
- [ ] Existing project rules (including XLS from-scratch constraints) held
