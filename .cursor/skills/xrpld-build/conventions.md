# xrpld conventions

Copy neighboring files. Do not invent layouts, naming, or test harnesses.

## Layout

| Kind | Headers | Sources |
| --- | --- | --- |
| libxrpl | `include/xrpl/…` | `src/libxrpl/…` |
| xrpld app | — | `src/xrpld/…` |
| beast/jtx tests | `src/test/jtx/…` | `src/test/…` |
| gtest (new) | — | `src/tests/…` |

Transactors live as a pair:

- `include/xrpl/tx/transactors/<area>/<Name>.h`
- `src/libxrpl/tx/transactors/<area>/<Name>.cpp`

Do not hand-edit `include/xrpl/protocol_autogen/**`. Edit
`include/xrpl/protocol/detail/*.macro` (and templates under
`cmake/scripts/codegen/` if needed), then:

```bash
cmake --build . --target setup_code_gen   # once
cmake --build . --target code_gen
```

Commit the regenerated headers with the macro change.

## Naming

- Types / files: `TitleCase`
- Functions / variables: `camelCase`
- Namespaces / folders: `lowercase`
- Constants: `kName`
- Serialized fields: `sfFieldName`
- JSON keys: `JSS(FieldName)` in `include/xrpl/protocol/jss.h`
- Features: `featureName` / `fixName` from `features.macro`

## Amendments

Add at the **top** of `include/xrpl/protocol/detail/features.macro`
(reverse chronological):

```
XRPL_FEATURE(Name, Supported::No, VoteBehavior::DefaultNo)
```

Gate new apply paths with `view.rules().enabled(featureName)` (or the
equivalent `Rules` on the preflight context).

Do not mark `Supported::Yes` until the feature is complete. Leave
`VoteBehavior::DefaultNo` unless this is a communicated high-priority fix.
Never change a released `Supported::Yes` back to `No` (amendment-block risk);
use `VoteBehavior::Obsolete` instead.

Feature names: ASCII printable, length ≠ 32, ≤ 63.

## Protocol surface

New transaction: `TRANSACTION(...)` in
`include/xrpl/protocol/detail/transactions.macro` with the
`#if TRANSACTION_INCLUDE` header include next to it. Privileges are the
invariant bitfield — set them deliberately.

New ledger object: `LEDGER_ENTRY(...)` in
`include/xrpl/protocol/detail/ledger_entries.macro`, plus a keylet.

New field: next free code of the right type in
`include/xrpl/protocol/detail/sfields.macro`. Do not reuse codes.

New result: add to `include/xrpl/protocol/TER.h`. `preflight` returns
`NotTEC` (`tem*` / `tef*` / `tesSUCCESS`). `preclaim` / `doApply` return
`TER` (may include `tec*`).

## Transactors

Subclass `xrpl::Transactor`. Match this shape unless a neighbor omits a hook:

```cpp
static constexpr auto kConsequencesFactory = ConsequencesFactoryType::Normal;
static bool checkExtraFeatures(PreflightContext const&);
static NotTEC preflight(PreflightContext const&);
static TER preclaim(PreclaimContext const&);
TER doApply() override;
void visitInvariantEntry(...) override;
bool finalizeInvariants(...) override;
```

`preflight` = syntactic / flag / feature checks (no ledger). `preclaim` =
ledger reads, authorization, existence. `doApply` = mutations.

`temDISABLED` when the amendment is off. Do not crash on bad user input.

Optional ST fields: `x[sfFoo]` (default if missing), `x[~sfFoo]` (absent if
missing). See `include/xrpl/protocol/README.md`.

## Contracts

Outside unit tests and `constexpr` functions:

- `XRPL_ASSERT(cond, "ns::fn : expected cond")` — not `assert`
- `UNREACHABLE("ns::fn : unexpected situation")` — not `assert(false)` or
  `std::unreachable`

Names must be stable (no line numbers, no full signatures). Do not assert
conditions an attacker or the network can violate.

Unreachable / defensive paths that tests cannot hit: `// LCOV_EXCL_LINE` or
`LCOV_EXCL_START` / `LCOV_EXCL_STOP` (see existing transactors).

## Style (CONTRIBUTING)

Must: clang-format 21, clang-tidy, levelized includes (angle brackets,
`.clang-format` include categories).

Avoid: near-duplicate code, new files/classes you could extend, deep
inheritance, raw `new`, macros/heavy templates/clever lambdas unless they
pay for themselves, new third-party libraries, arch-specific code.

Seek: extend existing types; readable apply logic; inline one-off helpers;
comments a competent reader needs for non-obvious invariants — not narration.

Includes: `"<test/…>"` then `"<xrpld/…>"` then `"<xrpl/…>"` then Boost then
the rest. Never include `src/test` from `xrpl` / `xrpld`.

## Tests (jtx)

```cpp
struct Feature_test : public beast::unit_test::Suite
{
    void testDisabled(FeatureBitset features) { /* temDISABLED */ }
    void testSuccess(FeatureBitset features) { /* … */ }

    void run() override
    {
        testDisabled(testableAmendments() - featureName);
        testSuccess(testableAmendments() | featureName);
    }
};
BEAST_DEFINE_TESTSUITE(Feature, app, xrpl);
```

Patterns to copy: `src/test/app/Credentials_test.cpp`,
`src/test/jtx/credentials.h`, `src/test/app/Delegate_test.cpp`.

- `Env env{*this, features};` then `env.fund(XRP(…), alice, bob);`
- Submit: `env(jtxHelper(...), ter(tecCODE));` then `env.close();`
- Assert ledger: `env.le(keylet)`, `BEAST_EXPECT(...)`, `ownerCount`
- Add a small jtx helper in `src/test/jtx/` rather than repeating JSON

gtest belongs only under `src/tests`. Do not mix harnesses in one file.

## Commits and PRs

Branch prefixes: `XLS-00xx/…`, `<github-user>/…`, or `<org>/…`.

PR title: `feat: Add …` (type, colon, space, Capital). Types: `build`,
`feat`, `fix`, `docs`, `test`, `ci`, `style`, `refactor`, `perf`, `chore`.

Commits: logical, signed, each builds and passes tests. Subject imperative,
~50 chars, no trailing period. Body = why.

Base `develop` unless the change is an RC fix (`release`) or hotfix
(`master`). Draft early when project rules allow GitHub. Do not force-push a
PR that is already under review.

## Commands

```bash
clang-format -i <file>…
TIDY=1 pre-commit run clang-tidy
pre-commit run --all-files
xrpld --unittest SuiteName --unittest-jobs=<cores>
```
