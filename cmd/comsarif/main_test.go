package main

import (
	"bytes"
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/rogpeppe/go-internal/testscript"
)

func TestMain(m *testing.M) {
	testscript.Main(m, map[string]func(){
		"comsarif": main,
	})
}

func TestScripts(t *testing.T) {
	var updateScripts bool
	if slices.Contains([]string{"1", "true"}, os.Getenv("COMSARIF_UPDATE_SCRIPTS")) {
		t.Log("Updating test scripts")
		updateScripts = true
	}

	testscript.Run(t, testscript.Params{
		Dir:                 "testdata/script",
		UpdateScripts:       updateScripts,
		RequireExplicitExec: true,
		RequireUniqueNames:  true,
		Setup: func(env *testscript.Env) error {
			if err := copyTree(filepath.Join("testdata", "script", "fixtures"), filepath.Join(env.WorkDir, "fixtures")); err != nil {
				return err
			}
			workRoot, err := os.OpenRoot(env.WorkDir)
			if err != nil {
				return err
			}
			defer workRoot.Close()

			scriptRoot, err := os.OpenRoot(filepath.Join("testdata", "script"))
			if err != nil {
				return err
			}
			defer scriptRoot.Close()

			for _, name := range []string{"success.stdout", "explicit_root.stdout"} {
				data, err := scriptRoot.ReadFile(name)
				if err != nil {
					return err
				}
				data = []byte(strings.ReplaceAll(string(data), "__WORKDIR__", env.WorkDir))
				if err := workRoot.WriteFile(name, data, 0o600); err != nil {
					return err
				}
			}
			return nil
		},
	})
}

func TestRun(t *testing.T) {
	tests := []struct {
		name           string
		setup          func(t *testing.T, tempDir string) []string
		wantExit       int
		wantStdout     bool
		wantStderr     string
		wantStdoutText string
	}{
		{
			name: "success with default root",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, lockPath := writeSuccessFixture(t, tempDir)
				return []string{"--audit", auditPath, "--lock", lockPath}
			},
			wantExit:   0,
			wantStdout: true,
		},
		{
			name: "success with explicit parent root keeps relative uri",
			setup: func(t *testing.T, tempDir string) []string {
				root := filepath.Join(tempDir, "repo")
				auditPath, lockPath := writeSuccessFixture(t, filepath.Join(root, "subdir"))
				_ = auditPath
				return []string{"--audit", auditPath, "--lock", lockPath, "--root", root}
			},
			wantExit:       0,
			wantStdout:     true,
			wantStdoutText: `"uri":"subdir/composer.lock"`,
		},
		{
			name: "missing audit flag",
			setup: func(t *testing.T, tempDir string) []string {
				_, lockPath := writeSuccessFixture(t, tempDir)
				return []string{"--lock", lockPath}
			},
			wantExit:   2,
			wantStderr: "missing required --audit flag",
		},
		{
			name: "missing lock flag",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, _ := writeSuccessFixture(t, tempDir)
				return []string{"--audit", auditPath}
			},
			wantExit:   2,
			wantStderr: "missing required --lock flag",
		},
		{
			name: "unknown flag",
			setup: func(t *testing.T, tempDir string) []string {
				_, _ = writeSuccessFixture(t, tempDir)
				return []string{"--nope"}
			},
			wantExit:   2,
			wantStderr: "flag provided but not defined",
		},
		{
			name: "unreadable audit path",
			setup: func(t *testing.T, tempDir string) []string {
				_, lockPath := writeSuccessFixture(t, tempDir)
				return []string{"--audit", filepath.Join(tempDir, "missing-audit.json"), "--lock", lockPath}
			},
			wantExit:   2,
			wantStderr: "resolve audit file",
		},
		{
			name: "unreadable lock path",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, _ := writeSuccessFixture(t, tempDir)
				return []string{"--audit", auditPath, "--lock", filepath.Join(tempDir, "missing-composer.lock")}
			},
			wantExit:   2,
			wantStderr: "resolve composer.lock file",
		},
		{
			name: "nonexistent root",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, lockPath := writeSuccessFixture(t, tempDir)
				return []string{"--audit", auditPath, "--lock", lockPath, "--root", filepath.Join(tempDir, "missing-root")}
			},
			wantExit:   2,
			wantStderr: "resolve root path",
		},
		{
			name: "file valued root",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, lockPath := writeSuccessFixture(t, tempDir)
				return []string{"--audit", auditPath, "--lock", lockPath, "--root", auditPath}
			},
			wantExit:   2,
			wantStderr: "is not a directory",
		},
		{
			name: "lock outside root",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, lockPath := writeSuccessFixture(t, tempDir)
				root := filepath.Join(tempDir, "other")
				if err := os.MkdirAll(root, 0o750); err != nil {
					t.Fatalf("MkdirAll(%q): %v", root, err)
				}
				return []string{"--audit", auditPath, "--lock", lockPath, "--root", root}
			},
			wantExit:   2,
			wantStderr: "resolved composer.lock path",
		},
		{
			name: "invalid audit json",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, lockPath := writeSuccessFixture(t, tempDir)
				writeFile(t, auditPath, "{")
				return []string{"--audit", auditPath, "--lock", lockPath}
			},
			wantExit:   1,
			wantStderr: "parse audit JSON",
		},
		{
			name: "invalid composer lock json",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, lockPath := writeSuccessFixture(t, tempDir)
				writeFile(t, lockPath, "{")
				return []string{"--audit", auditPath, "--lock", lockPath}
			},
			wantExit:   1,
			wantStderr: "parse composer.lock JSON",
		},
		{
			name: "advisory package missing from composer lock",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, lockPath := writeSuccessFixture(t, tempDir)
				writeFile(t, auditPath, validAuditJSON(`"vendor/missing"`, `"vendor/missing"`))
				return []string{"--audit", auditPath, "--lock", lockPath}
			},
			wantExit:   1,
			wantStderr: `package "vendor/missing" not found in composer.lock`,
		},
		{
			name: "duplicate advisory identity",
			setup: func(t *testing.T, tempDir string) []string {
				auditPath, lockPath := writeSuccessFixture(t, tempDir)
				writeFile(t, auditPath, `{
					"advisories": {
						"vendor/pkg": [{
							"advisoryId": "GHSA-1",
							"packageName": "vendor/pkg",
							"affectedVersions": "<1.2.4"
						}]
					},
					"ignored-advisories": {
						"vendor/pkg": [{
							"advisoryId": "GHSA-1",
							"packageName": "vendor/pkg",
							"affectedVersions": "<1.2.4"
						}]
					}
				}`)
				return []string{"--audit", auditPath, "--lock", lockPath}
			},
			wantExit:   1,
			wantStderr: "duplicate advisory identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tempDir := t.TempDir()
			args := tt.setup(t, tempDir)

			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := run(context.Background(), args, &stdout, &stderr)

			if exitCode != tt.wantExit {
				t.Fatalf("run() exitCode = %d, want %d", exitCode, tt.wantExit)
			}

			gotStdout := stdout.Len() > 0
			if gotStdout != tt.wantStdout {
				t.Fatalf("stdout present = %v, want %v\nstdout: %q\nstderr: %q", gotStdout, tt.wantStdout, stdout.String(), stderr.String())
			}

			if tt.wantStdoutText != "" && !strings.Contains(stdout.String(), tt.wantStdoutText) {
				t.Fatalf("stdout %q does not contain %q", stdout.String(), tt.wantStdoutText)
			}

			if tt.wantStderr == "" {
				if stderr.Len() != 0 {
					t.Fatalf("stderr = %q, want empty", stderr.String())
				}
			} else if !strings.Contains(stderr.String(), tt.wantStderr) {
				t.Fatalf("stderr %q does not contain %q", stderr.String(), tt.wantStderr)
			}

			if tt.wantExit != 0 && stdout.Len() != 0 {
				t.Fatalf("stdout = %q, want empty on failure", stdout.String())
			}
		})
	}
}

func writeSuccessFixture(t *testing.T, dir string) (string, string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatalf("MkdirAll(%q): %v", dir, err)
	}

	auditPath := filepath.Join(dir, "audit.json")
	lockPath := filepath.Join(dir, "composer.lock")
	writeFile(t, auditPath, validAuditJSON(`"vendor/pkg"`, `"vendor/pkg"`))
	writeFile(t, lockPath, `{
		"packages": [
			{
				"name": "vendor/pkg",
				"packages": [{
					"name": "vendor/fake",
					"version": "9.9.9"
				}],
				"version": "1.2.3"
			}
		]
	}`)
	return auditPath, lockPath
}

func writeFile(t *testing.T, path, contents string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
		t.Fatalf("WriteFile(%q): %v", path, err)
	}
}

func validAuditJSON(groupPackageName, advisoryPackageName string) string {
	return `{
		"advisories": {
			` + groupPackageName + `: [{
				"advisoryId": "GHSA-1",
				"packageName": ` + advisoryPackageName + `,
				"affectedVersions": "<1.2.4",
				"title": "Package vulnerability",
				"severity": "high"
			}]
		}
	}`
}

func copyTree(srcRoot, dstRoot string) error {
	srcFS := os.DirFS(srcRoot)
	if err := os.MkdirAll(dstRoot, 0o750); err != nil {
		return err
	}
	dst, err := os.OpenRoot(dstRoot)
	if err != nil {
		return err
	}
	defer dst.Close()

	return filepath.WalkDir(srcRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, err := filepath.Rel(srcRoot, path)
		if err != nil {
			return err
		}
		if d.IsDir() {
			return dst.MkdirAll(rel, 0o750)
		}

		data, err := fs.ReadFile(srcFS, rel)
		if err != nil {
			return err
		}
		return dst.WriteFile(rel, data, 0o600)
	})
}
