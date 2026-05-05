# Build GitHub-ready SARIF output from Composer audit JSON

This ExecPlan is a living document. The sections `Progress`, `Surprises & Discoveries`, `Decision Log`, and `Outcomes & Retrospective` must be kept up to date as work proceeds.

## Purpose / Big Picture

After this change, someone will be able to run `comsarif --audit path/to/audit.json --lock path/to/composer.lock [--root path]` and receive a SARIF 2.1.0 document on standard output that GitHub code scanning can ingest without extra noise. The report will contain one result per advisory and one result per abandoned package, all pointing at the matching `composer.lock` version line. The behavior is observable by running the CLI against repo-local fixtures, confirming that standard output is valid SARIF JSON, and verifying that exit codes and standard error match the documented failure modes.

## Progress

- [x] (2026-05-05 22:26Z) Researched the scaffold, project policies, sample inputs, and GitHub’s SARIF subset requirements.
- [x] (2026-05-05 22:26Z) Identified the ambiguous parts of the input format and SARIF mapping, then resolved them in this plan.
- [x] (2026-05-05 22:26Z) Drafted the initial execution plan in `plans/init.md`.
- [x] (2026-05-06 00:13Z) Revised the plan after user confirmation to lock the hashing and ID assumptions, change region-column guidance, and strengthen the testing and URI requirements.
- [x] (2026-05-06) Implemented Milestone 1 root-package parsing and composer.lock location indexing with table-driven tests.
- [x] (2026-05-06) Implemented Milestone 2 SARIF builder with a private minimal model, deterministic advisory and abandoned result generation, and table-driven SARIF tests.
- [x] (2026-05-06) Implemented CLI flag parsing, path validation, root-relative lock URI handling, and exit-code mapping in `cmd/comsarif/main.go` while keeping the CLI thin around `BuildReport`.
- [x] (2026-05-06) Added table-driven `run` tests plus end-to-end `testscript` fixtures covering success, explicit-root relative URIs, and representative failure modes.
- [x] (2026-05-06) Ran `golangci-lint fmt`, `go test ./...`, and `golangci-lint run` after the final lint-only refactors, fixed the reported `cyclop`, `gosec`, and `nonamedreturns` issues, and verified the repository is clean.

## Surprises & Discoveries

- Observation: The sample audit file does not encode `advisories` or `ignored-advisories` as plain arrays; each is a JSON object keyed by package name whose values are arrays of advisory objects.
  Evidence: the sample audit content shows `"advisories": { "phpunit/phpunit": [ ... ] }` and `"ignored-advisories": { ... }`.

- Observation: The sample `composer.lock` contains nested `"packages"` arrays inside package metadata, so a plain text search for a package name finds false positives outside the top-level `packages` and `packages-dev` arrays.
  Evidence: the sample lock file contains nested package entries under `composer/installers`, while the real top-level `packages-dev` array begins much later and contains the actual `phpunit/phpunit` entry used for reporting.

- Observation: GitHub code scanning only uses `partialFingerprints.primaryLocationLineHash`; it also needs each result to carry a `message`, at least one `location`, and rule metadata with `id`, `shortDescription.text`, `fullDescription.text`, and `help.text`.
  Evidence: the GitHub SARIF support notes from research explicitly call these fields required and say only `primaryLocationLineHash` is consumed from `partialFingerprints`.

- Observation: The checked-in `github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif` package is not a good final encoder for this task because many optional fields are declared without `omitempty`, which would emit `null`, empty arrays, or default values that the user asked to omit.
  Evidence: the vendored type definitions for `Run`, `Tool`, `Location`, and `ToolComponent` expose fields such as `addresses`, `invocations`, `extensions`, `annotations`, and `rules` without `omitempty`.

- Observation: `encoding/json.Decoder.InputOffset()` is sufficient to recover the `version` key line without regex parsing because the offset recorded immediately after a key token still falls on that same line.
  Evidence: the Milestone 1 composer-lock tests exercise line-number and column extraction against indented inline JSON and pass using the offset from the `version` key token.

- Observation: the plan’s advisory description and message fallbacks work best when treated as two different chains: rule descriptions prefer `title`, then the sentence fallback, while result summaries prefer the full normalized `title`, then the same sentence fallback.
  Evidence: Milestone 2 tests initially failed when descriptions used the sentence form even when a title was present; aligning the builder with the explicit title-first wording fixed the mismatch and kept both fallback chains deterministic.

- Observation: `testscript` only compares files inside its temporary work directory, and `cmpenv` is unsafe for SARIF goldens because it expands `$schema` as if it were an environment variable.
  Evidence: initial Milestone 3 script runs could not see repo-side fixture files until `Setup` copied them into `$WORK`, and `cmpenv` turned the expected JSON key `"$schema"` into an empty-string key.

## Decision Log

- Decision: Build a tiny repository-local SARIF encoder with custom structs instead of marshaling the third-party SARIF structs.
  Rationale: the final JSON must omit optional SARIF fields unless GitHub or the user explicitly requires them, and the third-party structs would leak unwanted fields.
  Date/Author: 2026-05-05 / ExecPlan Architect

- Decision: Treat `advisories` and `ignored-advisories` as JSON objects keyed by package name whose values are advisory arrays, and reject any advisory whose `packageName` does not exactly match its enclosing key.
  Rationale: this matches the observed input and prevents silent mis-association of findings to the wrong package.
  Date/Author: 2026-05-05 / ExecPlan Architect

- Decision: Use lowercase hexadecimal SHA-256 for every required hash.
  Rationale: the user asked for hashes but did not specify an algorithm; SHA-256 is stable, common, collision-resistant for this scale, and short enough to fit comfortably in rule IDs and fingerprints.
  Date/Author: 2026-05-05 / ExecPlan Architect

- Decision: Make advisory `reportingDescriptor.id` and advisory `result.ruleId` identical, both equal to `sha256("advisory$$$<advisoryId>$$$<packageName>")`.
  Rationale: GitHub expects `result.ruleId` to reference the matching rule ID, and the user’s advisory rule and result instructions conflict on this point. GitHub compatibility takes precedence.
  Date/Author: 2026-05-05 / ExecPlan Architect

- Decision: Use `sha256("<advisoryId>$$$<packageName>")` for advisory `partialFingerprints.primaryLocationLineHash`, and `sha256("abandoned$$$<packageName>")` for abandoned-package fingerprints.
  Rationale: the user supplied a usable advisory fingerprint formula but no valid abandoned one because abandoned entries have no advisory ID.
  Date/Author: 2026-05-05 / ExecPlan Architect

- Decision: Emit `run.tool.driver.name = "composer"` and `run.tool.extensions = [{"name":"comsarif","rules":[]}]`, but keep all real rules under `tool.driver.rules`.
  Rationale: this is the valid SARIF shape that best matches the user’s intent while keeping GitHub rule resolution simple.
  Date/Author: 2026-05-05 / ExecPlan Architect

- Decision: Report the `version` line in `composer.lock` from the first non-whitespace rune through one rune past the final rune of the line.
  Rationale: the user clarified the desired `startColumn`, and this span still satisfies GitHub’s region expectations without depending on a brittle character-range parser.
  Date/Author: 2026-05-05 / ExecPlan Architect

- Decision: Keep every result `artifactLocation.uri` as the forward-slash path of `--lock` relative to the resolved `--root`, never as an absolute URI.
  Rationale: the user explicitly wants root-relative location URIs, and GitHub file matching is more stable when results use relative paths.
  Date/Author: 2026-05-06 / ExecPlan Architect

- Decision: Treat unreadable paths, missing required flags, unknown flags, non-directory roots, and “lock is outside root” failures as exit code `2`, and treat malformed JSON, invalid advisory content, missing package matches, and duplicate logical IDs as exit code `1`.
  Rationale: this cleanly separates argument or validation failures from execution or data failures and matches the CLI contract.
  Date/Author: 2026-05-05 / ExecPlan Architect

- Decision: Sort package-keyed collections alphabetically and preserve original array order inside each advisory array.
  Rationale: Go maps are not ordered; deterministic output prevents flaky tests and noisy GitHub diffs while still honoring source ordering where the input is already ordered.
  Date/Author: 2026-05-05 / ExecPlan Architect

- Decision: Every new automated test in this feature should be table-driven with named cases, and extra cases must be added whenever a new edge case or regression is discovered.
  Rationale: the repository explicitly prefers table-driven tests, and expanding the case tables is the safest way to turn future bugs into permanent regression coverage.
  Date/Author: 2026-05-06 / ExecPlan Architect

## Outcomes & Retrospective

Milestone 1 is implemented. The root package now normalizes and validates audit JSON, rejects duplicate advisory identities across `advisories` and `ignored-advisories`, and token-walks `composer.lock` to capture top-level package version-line regions while ignoring nested fake package lists. Focused Milestone 1 verification passed with `go test . -run 'TestParseAuditJSON|TestParseComposerLock'`.

Milestone 2 is implemented. The root package now exposes `BuildOptions` and `BuildReport`, builds compact SARIF 2.1.0 JSON through a private minimal model, preserves deterministic ordering across rules and results, emits advisory and abandoned findings with the required hashes and fallback text, and omits unwanted optional SARIF fields by leaving optional data nil unless needed. Focused Milestone 2 verification passed with `go test . -run 'TestBuildReport|TestSARIF'`, and a full root-package verification also passed with `go test .`. Remaining work is Milestone 3 CLI wiring, path validation, exit-code handling, and end-to-end script coverage.

Milestone 3 is implemented. The CLI now validates `--audit`, `--lock`, and `--root`, defaults `--root` from the provided lock path, resolves symlinks before checking that `composer.lock` stays inside the root, maps argument/path failures to exit code `2` and post-validation build failures to `1`, and writes SARIF plus a trailing newline to stdout on success. Focused Milestone 3 verification passed with `go test ./cmd/comsarif -run 'TestRun|TestScripts'`. Remaining planned work is the final full-project verification and retrospective update after that broader pass.

Final verification is complete. A cleanup pass split a few high-branching helpers into smaller pure functions, removed the named return in `lineBounds`, switched CLI file reads and test fixture file operations to rooted filesystem access, and tightened test-only file and directory modes so strict linting passes without changing the CLI contract or SARIF output. `golangci-lint fmt` completed cleanly, `go test ./...` passed for both packages, and `golangci-lint run` now reports `0 issues`.

Verification note: the first post-edit `go test ./...` run failed because the revised rooted fixture copy helper attempted to open the destination root before creating it. Creating `dstRoot` before `os.OpenRoot(dstRoot)` fixed that regression, and the subsequent full verification pass was clean.

## Context and Orientation

The repository is a very small Go scaffold. The root package lives in `audit.go` and currently contains only placeholder types. The CLI lives in `cmd/comsarif/main.go`; today it accepts no flags, performs no work, and returns `nil`. The test harness for the CLI already exists in `cmd/comsarif/main_test.go` and uses `github.com/rogpeppe/go-internal/testscript`, but there are not yet any script files under `cmd/comsarif/testdata/script/`.

A “SARIF report” is a JSON document that static-analysis tools upload to GitHub code scanning. In this repository the important SARIF words are simple. A “rule” is the description of one kind of finding. A “result” is one concrete alert that points at a file and line. A “tool component” is the metadata block that names the tool. A “fingerprint” is a stable string GitHub uses to decide whether a result from two different runs is the same alert. A “region” is the line and column span that GitHub annotates.

An “advisory” in this task is one security record from the audit JSON. Each advisory must become exactly one SARIF rule and exactly one SARIF result. An “abandoned package” is a package listed under the audit JSON’s `abandoned` object. All abandoned-package results share one SARIF rule named `abandoned`. The only source file we ever point at is `composer.lock`, and the relevant line for each result is the line that contains the matched package’s `version` field in the top-level `packages` or `packages-dev` arrays. In every SARIF result, `artifactLocation.uri` must be the forward-slash path of `composer.lock` relative to the resolved `--root`; it must never be an absolute URI.

GitHub code scanning accepts only a subset of SARIF 2.1.0. The implementation therefore needs to be intentionally small: required SARIF fields must be present, user-requested fields must be present, and everything else should be omitted. The core implementation constraint is not JSON generation; it is generating the smallest correct JSON while still giving GitHub enough information to create stable alerts. This repository also prefers table-driven tests, so every new automated test described below should use named cases with `t.Run`, and new edge cases should be added as extra rows whenever they are discovered.

## Plan of Work

The work should be done in three milestones. Each milestone leaves the repository in a runnable state, and each one adds tests before or alongside implementation so behavior is pinned down as it is introduced.

### Milestone 1: Parse and validate inputs, then locate the correct `composer.lock` version line

This milestone creates the domain model in the root package and proves that the program can understand both input files without yet emitting SARIF. At the end of this milestone, the repository will be able to read raw audit JSON bytes, normalize advisory data, reject malformed inputs, and scan `composer.lock` to find the exact top-level package entry and its `version` line while ignoring nested fake package lists.

Replace the placeholder contents of `audit.go` with real domain types. Define `Advisory`, `AdvisorySource`, and `AuditDocument`, and keep their fields limited to the data the report builder needs: `advisoryId`, `packageName`, `affectedVersions`, `title`, `cve`, `link`, `reportedAt`, `severity`, `ignoreReason`, `composerRepository`, `sources`, and the `abandoned` replacement string. Use raw helper structs with pointer fields during JSON decoding so that `null` can be distinguished from a real empty string. Normalize optional strings by trimming surrounding whitespace and converting empty strings to “not given”. Required fields must fail validation if they are absent, `null`, or normalize to empty text. Normalize `severity` to lowercase for mapping, but do not attempt to parse `reportedAt` into a time type; keep it as a plain string exactly as required.

The audit parser must decode `advisories` and `ignored-advisories` as `map[string][]rawAdvisory`. After decoding, flatten them into a deterministic ordered slice of findings inside the builder layer by sorting package keys and preserving array order within each package. Reject any advisory whose `packageName` disagrees with the enclosing map key. Reject duplicate advisory identities across both collections after normalizing to the tuple `(advisoryId, packageName)` because each advisory rule must have exactly one result and duplicate logical IDs would make the SARIF ambiguous.

Add a new file `composer_lock.go`. Do not parse this file with regular expressions or simple line scanning; that would break on minified JSON and on nested `packages` arrays. Instead, read the raw bytes once, precompute newline offsets, and use `encoding/json.Decoder` with `Token()` to walk the JSON token stream. The scanner only cares about objects that are direct elements of the top-level `packages` or `packages-dev` arrays. For each such object, collect the package `name`, its `version`, and the line number on which the `version` key token appears. Ignore nested arrays and nested objects inside that package object. After each top-level package object ends, store one `lockedPackageLocation` record containing the package name, version, SARIF URI for the lock file, and a `region` span that starts at the first non-whitespace rune on the version line and ends one rune past the final rune on that same line. If the same package name appears more than once across the top-level arrays, fail fast; the report cannot point to two different version lines for one logical package name.

Keep filesystem validation in the CLI, not in the root package. The CLI should be responsible for proving that `--audit` and `--lock` are readable files, that `--root` exists and is a directory, and that the real path of `composer.lock` is within the real path of `--root`. That comparison must use `filepath.EvalSymlinks` plus absolute cleaned paths, not lexical string prefixes. Once the CLI has validated paths, it should compute two URI values for the builder: `RootURI`, which is a `file://` URI for the resolved root directory, and `LockURI`, which is the forward-slash relative path from the resolved root to the resolved lock file. `LockURI` becomes every result’s `artifactLocation.uri`, so it must always stay relative to `--root`. Using a relative lock URI keeps GitHub file matching stable, while the working-directory file URI satisfies the user’s explicit requirement for `invocation.workingDirectory.uri`.

Start this milestone with tests, because the line-location logic is the most failure-prone part of the task. All tests in this milestone must be table-driven with descriptive `name` fields and `t.Run` subtests, and more named rows should be added whenever a new malformed input or location edge case is found. Expand `audit_test.go` into table-driven tests named along the lines of `TestParseAuditJSON`. Start the table with cases such as: advisory with title and cve; advisory with title but no cve; null and empty optional strings omitted; missing `advisoryId`; missing `packageName`; missing `affectedVersions`; mismatched `packageName` versus enclosing key; mixed-case severity normalization; empty `advisories`; empty `ignored-advisories`; and duplicate advisory identity across the two collections. Add a new `composer_lock_test.go` with table-driven subtests such as: top-level `packages` match; top-level `packages-dev` match; nested fake `packages` arrays ignored; malformed JSON rejected; duplicate top-level package names rejected; leading indentation produces `startColumn` at the first non-whitespace rune; `endColumn` reaches one rune past the end of the line; and the stored SARIF URI remains relative to `--root`. The composer-lock tests should use tiny inline JSON strings, not the large external sample, so failures stay readable, and extra cases should be appended whenever new fixtures expose another edge case.

Acceptance for this milestone is simple. Running the library-only tests must prove that the repository can extract the exact top-level line numbers for package versions and can reject malformed audit data before any SARIF is built.

### Milestone 2: Build the smallest GitHub-compatible SARIF report that satisfies the feature contract

This milestone adds the actual report generator in the root package. At the end of it, the library can accept validated raw inputs plus resolved URIs and produce a complete SARIF 2.1.0 JSON document with one run, the required GitHub fields, the user-requested fields, and no extra optional data.

Add a new file `sarif.go` that defines a minimal private SARIF model. Do not expose the raw SARIF structs as part of the public package API. The root package should instead expose one top-level function, for example:

    type BuildOptions struct {
        RootURI string
        LockURI string
    }

    func BuildReport(auditJSON, composerLockJSON []byte, opts BuildOptions) ([]byte, error)

`BuildReport` should call the unexported audit parser and composer-lock scanner from Milestone 1, assemble the minimal SARIF structure, and return compact JSON bytes. Use `json.Marshal` or `json.Encoder` with `SetEscapeHTML(false)`. Emit a trailing newline only in the CLI layer, not from the library function, so unit tests can compare raw bytes deterministically.

The minimal SARIF model must intentionally distinguish required arrays from optional arrays. Required arrays such as `runs`, `tool.driver.rules`, and `results` must always serialize as arrays, even when empty. Optional arrays and maps must stay `nil` until needed so that they disappear from the JSON instead of becoming `null` or `[]`. This is the whole reason not to use the third-party SARIF structs directly.

The top-level SARIF object must use `$schema = "https://json.schemastore.org/sarif-2.1.0.json"` and `version = "2.1.0"`. Emit exactly one run. That run must contain `tool`, `invocations`, and `results`. `run.tool.driver.name` must be `"composer"`. `run.tool.extensions` must be a one-element array containing a tool component with `name = "comsarif"` and `rules = []`. The driver’s `rules` array holds every actual rule. `run.invocations` must contain exactly one object whose `workingDirectory.uri` is the resolved root `file://` URI. Every result location’s `artifactLocation.uri` must be `LockURI`, meaning the forward-slash path of `--lock` relative to the resolved `--root`; never emit an absolute lock-file URI in results.

Define one internal helper for each distinct SARIF transformation. The important helpers are `buildAdvisoryRule`, `buildAdvisoryResult`, `buildAbandonedRule`, `buildAbandonedResult`, `truncateRunes`, `firstNonEmptyLine`, `hashStable`, `securitySeverityFor`, and `formatAdvisoryMessage`. Keep them small and deterministic. The rule builder should never inspect the filesystem; it only consumes normalized domain objects and precomputed location data.

For advisory rules, implement the user’s requested fallbacks exactly, then apply GitHub safety limits. `id` and the matching `result.ruleId` must be `sha256("advisory$$$<advisoryId>$$$<packageName>")`. `name` must be `cve`, then the first non-empty line of `title`, then `advisoryId`, truncated to 255 Unicode code points to stay under GitHub’s limit. `shortDescription.text` and `fullDescription.text` must share the same fallback chain and be truncated to 1024 Unicode code points after the fallback text is chosen. `help.text` is always `Upgrade to patched versions or remove the package.`. `properties.tags` is exactly `["composer","dependency","security"]`. `properties.precision` is always `very-high`. `properties.problem.severity` is `error` for `advisories` and `warning` for `ignored-advisories`. `properties.security-severity` is emitted only when the normalized severity is one of `critical`, `high`, `medium`, or `low`, using the exact string values `9.0`, `7.0`, `4.0`, or `0.1`.

For advisory results, use the precomputed composer-lock location for the advisory package. The result must have exactly one location. `partialFingerprints.primaryLocationLineHash` must be `sha256("<advisoryId>$$$<packageName>")`. The result message must start with the full normalized title when one exists; otherwise it must start with the same fallback sentence used for descriptions. After that summary block, append a blank line and a labeled field list in this exact order: `advisoryId`, `packageName`, `affectedVersions`, then optional `cve`, `link`, `reportedAt`, normalized `severity`, `ignoreReason`, `composerRepository`, and `sources`. Only include a line when the value is present after normalization. Format `sources` as one indented line per source entry, preserving input order and using `name: remoteId` when both are present.

For the abandoned rule, emit it only when the `abandoned` object is non-empty. `id` must be `abandoned`. `name` must be `Composer audit (abandoned)`. `shortDescription.text` is `Abandoned Composer package`. `fullDescription.text` is `Abandoned Composer package installed.`. `defaultConfiguration.level` is `note`. `help.text` is `Remove the package.`. `properties.tags` is exactly `["composer","dependency"]`. `properties.precision` is `high`. `properties.problem.severity` is `warning`.

For each abandoned result, locate the package in the same top-level composer-lock index. Use `ruleId = "abandoned"`. The only location is the package’s version line in the lock file. `partialFingerprints.primaryLocationLineHash` must be `sha256("abandoned$$$<packageName>")`. `message.text` must be exactly two lines: the first line is `Package <packageName> is abandoned, you should avoid using it.` and the second line is either `No replacement was suggested.` or `Use <replacement> instead.` after normalizing the replacement string.

At the end of this milestone, add a new `sarif_test.go`. All tests in this milestone must be table-driven, and new named rows must be added whenever a new serialization, fallback, or GitHub-compatibility edge case is discovered. The tests must decode the generated JSON into generic maps and assert both presence and absence. Presence checks should prove that all GitHub-required and user-requested fields exist. Absence checks should prove that extra optional fields, empty strings, and irrelevant arrays are not serialized. Start with cases such as: advisory with title and cve; advisory without title but with cve fallback; advisory without title and without cve falling back to advisoryId text; ignored advisory uses warning severity; severity mapping for `critical`, `high`, `medium`, `low`, and unknown values; short and full description truncation at 1024 Unicode code points; rule-name truncation at 255 Unicode code points; `artifactLocation.uri` equals `composer.lock` when `--root` is the lock directory; `artifactLocation.uri` equals `subdir/composer.lock` when `--root` is a parent directory; `startColumn` equals the first non-whitespace rune on the version line; abandoned package with replacement; abandoned package without replacement; deterministic ordering of rules and results; duplicate advisory IDs rejected; empty input still emits one run with empty `rules` and `results`; and repeated builds produce identical bytes. Add more cases whenever another omission rule, fallback chain, or URI edge case appears.

Acceptance for this milestone is a passing `go test .` and a decoded SARIF structure that contains only the intended keys. A reader should be able to inspect the JSON and see no `null` values, no empty optional collections, and no stray SARIF fields.

### Milestone 3: Wire the CLI, map exit codes correctly, and prove the end-to-end behavior

This milestone connects the parser and builder to the existing command entry point. At the end of it, a user can run the CLI with real files and get SARIF on `stdout`, human-readable diagnostics on `stderr`, and the exact exit codes from the contract.

Edit `cmd/comsarif/main.go` so that `main` becomes a one-liner around `os.Exit(run(...))`. Change `run` to return `int`, not `error`. Keep the existing `context.Context` parameter even if it is unused for now; that avoids needless churn and keeps future cancellation options open. Parse flags with a private `flag.FlagSet` using `ContinueOnError`. The three flags are `--audit`, `--lock`, and `--root`. Both `--audit` and `--lock` are required. If `--root` is omitted, default it to the directory portion of the `--lock` argument exactly as provided, then resolve that directory before validation. Unknown flags, missing required flags, unreadable files, invalid root directories, and “lock outside root” must print a concise error message to `stderr`, print nothing to `stdout`, and return exit code `2`.

Once the flags are validated, read the audit and lock files, compute `RootURI` and `LockURI`, and call `comsarif.BuildReport`. Any failure that happens after successful flag and path validation must return exit code `1`. That includes invalid JSON, invalid advisory content, duplicate logical IDs, missing package matches, duplicate top-level package names, and marshal failures. On success, write the report bytes plus a trailing newline to `stdout`, write nothing to `stderr`, and return `0`.

Do not put the business logic in the CLI package. `cmd/comsarif/main.go` should stay thin: parse flags, validate paths, read files, call the root package, and handle exit codes. This keeps the root package testable with unit tests and keeps the CLI easy to review.

Extend `cmd/comsarif/main_test.go` with table-driven tests that call `run` directly. These tests are where exact exit codes should be asserted, and they should stay table-driven as the feature evolves. Use `t.TempDir()` to create temporary audit and lock files. Cover at least these cases: success with default root; success with explicit parent root and a lock file in a subdirectory; missing `--audit`; missing `--lock`; unreadable audit path; unreadable lock path; nonexistent `--root`; file-valued `--root`; lock outside root; invalid audit JSON; invalid composer-lock JSON; advisory package missing from `composer.lock`; duplicate advisory identity; and a success case that proves the emitted `artifactLocation.uri` is relative to `--root`. Each case must assert the exact exit code, whether `stdout` is empty or non-empty, and the key substring expected in `stderr`. Add more named cases whenever a new CLI regression or path-validation edge case is found.

Retain the existing `TestScripts` harness and add real script files under `cmd/comsarif/testdata/script/`. Use these scripts for true end-to-end behavior, not for every failure permutation. One success script should build a small but representative repo-local fixture set that includes a normal advisory, an ignored advisory, one abandoned package with a replacement, and one without a replacement. Its lock file must also contain a nested fake `packages` array so the end-to-end test proves the location scanner ignores nested matches. The script should `exec comsarif ...`, compare `stdout` against a checked-in expected SARIF file, and assert that `stderr` stays empty. A second script should exercise an explicit `--root` that is a parent directory of the lock file and prove that the emitted `artifactLocation.uri` becomes a relative subpath such as `subdir/composer.lock`. Add more scripts whenever a newly discovered end-to-end edge case cannot be expressed clearly in the unit-test tables.

Acceptance for this milestone is that `go test ./cmd/comsarif` passes, the direct `run` tests show the exact exit codes `0`, `1`, and `2`, and the end-to-end script fixtures demonstrate that the emitted JSON is both valid and stable.

## Concrete Steps

All commands below run from the repository root `/Users/work/Code/comsarif`.

Before editing code, confirm the current baseline:

    go test .
    go test ./cmd/comsarif

The first command should currently pass trivially because the root package has almost no tests. The second should pass because the script harness exists even though no scripts are present yet.

After finishing the Milestone 1 parser work and its tests, run:

    go test . -run 'TestParseAuditJSON|TestParseComposerLock'

Expected shape of the output:

    ok   github.com/typisttech/comsarif  0.xxxs

After finishing the Milestone 2 SARIF builder, run:

    go test . -run 'TestBuildReport|TestSARIF'

Expected shape of the output:

    ok   github.com/typisttech/comsarif  0.xxxs

After wiring the CLI and adding direct `run` tests plus script tests, run:

    go test ./cmd/comsarif -run 'TestRun|TestScripts'

Expected shape of the output:

    ok   github.com/typisttech/comsarif/cmd/comsarif  0.xxxs

Run the full project verification before considering the work complete:

    golangci-lint fmt
    go test ./...
    golangci-lint run

Expected shape of the output is a clean `ok` line for every tested package and no lint diagnostics.

Do one manual CLI smoke test from the repository root using a repo-local success fixture after it has been checked in:

    go run ./cmd/comsarif --audit ./cmd/comsarif/testdata/script/fixtures/success/audit.json --lock ./cmd/comsarif/testdata/script/fixtures/success/composer.lock

The command must print one compact SARIF JSON document to `stdout`, print nothing to `stderr`, and exit with status `0`. The first bytes of `stdout` should look like this:

    {"$schema":"https://json.schemastore.org/sarif-2.1.0.json","version":"2.1.0","runs":[{"tool":{"driver":{"name":"composer"

Do one second manual smoke test after the explicit-root fixture is in place to prove that `artifactLocation.uri` is relative to `--root`:

    go run ./cmd/comsarif --audit ./cmd/comsarif/testdata/script/fixtures/success/audit.json --lock ./cmd/comsarif/testdata/script/fixtures/success/composer.lock --root ./cmd/comsarif/testdata/script/fixtures

The command must print SARIF to `stdout`, print nothing to `stderr`, and exit with status `0`. The JSON should contain this substring:

    "uri":"success/composer.lock"

Do one manual failure smoke test after the path-validation logic exists:

    go run ./cmd/comsarif --audit ./cmd/comsarif/testdata/script/fixtures/success/audit.json --lock ./cmd/comsarif/testdata/script/fixtures/success/composer.lock --root ./plans

The command must print nothing to `stdout`, print a concise error to `stderr`, and exit with status `2`. The error text should contain the phrase:

    resolved composer.lock path

## Validation and Acceptance

The work is accepted only when all of the following behaviors are demonstrably true.

On success, `comsarif` reads the two input files, validates the resolved paths, and prints a SARIF 2.1.0 document to standard output. That document has exactly one run. The run contains a driver named `composer`, one extension named `comsarif`, one invocation with the root file URI, and a result count equal to the total number of advisories plus ignored advisories plus abandoned packages. Every advisory has its own rule and exactly one result. Every abandoned package produces exactly one result under the shared `abandoned` rule.

Every result must point at the `composer.lock` version line for the matching top-level package entry. The location scanner is correct only if a package name that appears inside nested JSON structures does not affect the chosen line. The success tests must explicitly prove this by using a lock file with deceptive nested matches. Every result location must use `artifactLocation.uri` as the forward-slash path from the resolved `--root` to the resolved `--lock`, never as an absolute URI. The region must start at the first non-whitespace rune on the version line and end one rune past the final rune on that line.

The SARIF JSON is accepted only if it includes every GitHub-required field relevant to this task and omits optional fields that were not requested. The implementation must therefore prove the presence of `$schema`, `version`, `runs`, `tool.driver.name`, `tool.driver.rules`, each rule’s `id`, `shortDescription.text`, `fullDescription.text`, and `help.text`, and each result’s `ruleId`, `message.text`, `locations[0].physicalLocation.artifactLocation.uri`, `locations[0].physicalLocation.region.startLine`, `startColumn`, `endLine`, `endColumn`, and `partialFingerprints.primaryLocationLineHash`. It must also prove the absence of `null` values, empty optional arrays, empty optional maps, and empty strings.

The CLI contract is accepted only if `run` returns `0` for success, `2` for invalid flags or invalid resolved paths, and `1` for all other failures. Success must leave `stderr` empty. Any failure must leave `stdout` empty. Unknown flags, missing `--audit`, missing `--lock`, unreadable `--audit`, unreadable `--lock`, nonexistent `--root`, non-directory `--root`, and “lock outside root” must all exercise exit code `2`. Invalid JSON, malformed advisory data, duplicate logical IDs, duplicate top-level package names, and unresolved package matches must all exercise exit code `1`.

The GitHub-compatibility portion is accepted only if rule IDs and fingerprints are stable across repeated runs with identical inputs, `shortDescription.text` and `fullDescription.text` are truncated to 1024 Unicode code points, rule names are truncated to 255 Unicode code points, and the lock file URI is always relative to the resolved `--root` using forward slashes. A repeated call to `BuildReport` with identical bytes and identical options must produce byte-for-byte identical output. Every new behavior above must be covered by named table-driven tests, and any newly discovered edge case must be captured by adding another case row or targeted script fixture.

## Idempotence and Recovery

The implementation steps in this plan are additive and safe to repeat. Running the test commands multiple times is safe. Re-reading the same input files must yield identical output bytes. The only stateful artifact likely to be added during implementation is checked-in test data under `cmd/comsarif/testdata/script/`; if a golden file changes unexpectedly, revert that file and rerun the focused tests before updating it intentionally.

If the token-based `composer.lock` scanner fails midway through implementation, do not fall back to regex parsing. Instead, keep the failing test that proves the bug, repair the token-state logic, and rerun the focused composer-lock tests. Add the discovered edge case as another named row in the relevant table-driven test before or alongside the fix. If script outputs change intentionally, refresh only the specific expected files or use the project’s documented script-update workflow intentionally; do not blanket-regenerate outputs without first confirming the behavioral change in unit tests.

If lint fails because a helper grew too large or too complex, prefer splitting the helper into smaller pure functions rather than suppressing the linter. If JSON output includes unwanted optional fields, fix the custom SARIF struct tags or zero-value handling instead of post-processing the marshaled bytes.

## Artifacts and Notes

The most important end-state artifact is a compact JSON document whose top-level shape looks like this:

    {
      "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
      "version": "2.1.0",
      "runs": [
        {
          "tool": {
            "driver": {
              "name": "composer",
              "rules": [ ... advisory rules ..., ... optional abandoned rule ... ]
            },
            "extensions": [
              {
                "name": "comsarif",
                "rules": []
              }
            ]
          },
          "invocations": [
            {
              "workingDirectory": {
                "uri": "file:///absolute/root/path"
              }
            }
          ],
          "results": [ ... ]
        }
      ]
    }

In result locations, `artifactLocation.uri` is always relative to `--root`, so it should look like `composer.lock` when `--root` is the lock file’s directory or like `subdir/composer.lock` when `--root` is a parent directory.

A representative advisory result should look like this after placeholder hashes are replaced:

    {
      "ruleId": "4d6f...",
      "message": {
        "text": "Package foo/bar is vulnerable to CVE-2026-0001.

advisoryId: GHSA-...
packageName: foo/bar
affectedVersions: <1.2.3
cve: CVE-2026-0001
severity: high"
      },
      "locations": [
        {
          "physicalLocation": {
            "artifactLocation": {
              "uri": "composer.lock"
            },
            "region": {
              "startLine": 12,
              "startColumn": 13,
              "endLine": 12,
              "endColumn": 33
            }
          }
        }
      ],
      "partialFingerprints": {
        "primaryLocationLineHash": "9abc..."
      }
    }

A representative abandoned result message should look exactly like this:

    Package inpsyde/more-menu-fields is abandoned, you should avoid using it.
    No replacement was suggested.

and, when a replacement exists:

    Package nunomaduro/pao is abandoned, you should avoid using it.
    Use laravel/pao instead.

A representative argument-validation error should look like this:

    error: resolved composer.lock path "/tmp/real/composer.lock" is outside root "/tmp/project"

## Interfaces and Dependencies

Use only the Go standard library in production code. Do not add a new runtime dependency for SARIF generation. The repository already carries `github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif`, and it is permitted by lint rules, but it should not be the final encoder for this task because it cannot omit enough optional fields. Tests may use the standard library and `github.com/google/go-cmp/cmp`. Follow the repository’s table-driven testing convention for all new tests, with descriptive `name` fields and `t.Run` subtests, and append extra named cases whenever another edge case or regression appears.

In `cmd/comsarif/main.go`, keep the public command surface minimal and explicit:

    func main()
    func run(ctx context.Context, args []string, stdout, stderr io.Writer) int

`run` must never call `os.Exit`; only `main` may do that.

In the root package, add one exported entry point for report generation:

    type BuildOptions struct {
        RootURI string
        LockURI string
    }

    func BuildReport(auditJSON, composerLockJSON []byte, opts BuildOptions) ([]byte, error)

`BuildOptions.LockURI` must always be the forward-slash path of `--lock` relative to the resolved `--root`, because that exact value becomes every result’s `artifactLocation.uri`.

Everything else may stay unexported. The following helper names should exist, even if some are split across files during implementation, because they represent the stable conceptual boundaries of the feature:

    parseAuditJSON(data []byte) (auditDocument, error)
    parseComposerLock(data []byte, lockURI string) (composerLockIndex, error)
    buildAdvisoryRule(finding advisoryFinding) sarifRule
    buildAdvisoryResult(finding advisoryFinding, loc lockedPackageLocation) (sarifResult, error)
    buildAbandonedRule() sarifRule
    buildAbandonedResult(packageName string, replacement string, loc lockedPackageLocation) sarifResult
    hashStable(parts ...string) string
    truncateRunes(s string, limit int) string
    firstNonEmptyLine(s string) string
    securitySeverityFor(s string) (string, bool)
    toFileURI(path string) string

Keep the custom SARIF structs private to `sarif.go`. They only need the fields required by GitHub and this feature. Use plain English field names inside comments so a new contributor can cross-check the generated JSON against GitHub’s subset without leaving the repository.

## Change Note

2026-05-05 / ExecPlan Architect: Created the initial execution plan after researching the scaffold, the example audit and `composer.lock` files, and GitHub’s SARIF ingestion requirements. The plan resolves the input-shape and rule-ID ambiguities up front so implementation can proceed without external context.
2026-05-06 / ExecPlan Architect: Revised the plan after user confirmation to lock the approved assumptions, change the version-line `startColumn` to the first non-whitespace rune, emphasize root-relative `artifactLocation.uri`, and strengthen table-driven testing guidance across all milestones.
