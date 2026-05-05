## Toolchain
- `go.mod` pins Go `1.26.2`. The code intentionally uses newer stdlib/testing features (`sync.WaitGroup.Go`, `testing/synctest`, `os.OpenRoot`, `json:",omitzero"`); do not treat those as compatibility bugs.
- `mise.toml` pins `golangci-lint` `2.12`; run lint as `golangci-lint run` and formatting as `golangci-lint fmt`.

## Layout
- Root package `github.com/typisttech/comsarif` is the library
- `cmd/comsarif` is the CLI

## Verification
- Full suite: `go test ./...`
- Library-only loop: `go test .`
- CLI/testscript loop: `go test ./cmd/comsarif`
- Refresh `testscript` golden files only when output intentionally changed: `COMSARIF_UPDATE_SCRIPTS=1 go test ./cmd/comsarif`
- For non-trivial changes, also run `golangci-lint run`

## Gotchas
- CLI script tests live in `cmd/comsarif/testdata/script/*.txt`
- `.golangci.yml` uses strict `depguard`: non-test code is limited to stdlib, `golang.org/x` and this module. Tests must not add `testify`; use stdlib or `github.com/google/go-cmp/cmp`.

## Go Table-Driven Tests

Always prefer table-driven tests: structure test cases as slices of structs with descriptive `name` fields and use subtests (`t.Run`) for each case. This keeps tests consistent, easy to extend, and reduces duplication across similar scenarios.
