## Cmmands

```bash
# Run all tests
go test -race -shuffle=on ./...

# Integration tests use the testscript framework; scripts live in `cmd/comsarif/testdata/script/*.txt`
# To regenerate golden output
UPDATE_SCRIPTS=1 go test ./cmd/comsarif

# Run linters
golangci-lint run
# Fix linting issues
golangci-lint run --fix
```
