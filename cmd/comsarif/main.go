package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	comsarif "github.com/typisttech/comsarif"
)

func main() {
	os.Exit(run(context.Background(), os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	_ = ctx

	auditPath, lockPath, rootPath, err := parseArgs(args)
	if err != nil {
		writeError(stderr, "%v", err)
		return 2
	}

	rootResolved, lockURI, err := validatePaths(auditPath, lockPath, rootPath)
	if err != nil {
		writeError(stderr, "%v", err)
		return 2
	}

	report, err := buildReport(auditPath, lockPath, rootResolved, lockURI)
	if err != nil {
		writeError(stderr, "%v", err)
		return 1
	}

	if _, err := stdout.Write(report); err != nil {
		writeError(stderr, "write stdout: %v", err)
		return 1
	}
	if _, err := stdout.Write([]byte{'\n'}); err != nil {
		writeError(stderr, "write stdout: %v", err)
		return 1
	}

	return 0
}

func parseArgs(args []string) (string, string, string, error) {
	flags := flag.NewFlagSet("comsarif", flag.ContinueOnError)
	flags.SetOutput(io.Discard)

	var auditPath string
	var lockPath string
	var rootPath string
	flags.StringVar(&auditPath, "audit", "", "path to composer audit JSON")
	flags.StringVar(&lockPath, "lock", "", "path to composer.lock")
	flags.StringVar(&rootPath, "root", "", "root directory for relative SARIF locations")

	if err := flags.Parse(args); err != nil {
		return "", "", "", err
	}
	if flags.NArg() != 0 {
		return "", "", "", fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}
	if auditPath == "" {
		return "", "", "", fmt.Errorf("missing required --audit flag")
	}
	if lockPath == "" {
		return "", "", "", fmt.Errorf("missing required --lock flag")
	}
	if rootPath == "" {
		rootPath = filepath.Dir(lockPath)
	}

	return auditPath, lockPath, rootPath, nil
}

func validatePaths(auditPath, lockPath, rootPath string) (string, string, error) {
	_, err := resolveReadableFile("audit file", auditPath)
	if err != nil {
		return "", "", err
	}

	rootResolved, err := resolveDirectory(rootPath)
	if err != nil {
		return "", "", err
	}

	lockResolved, err := resolveReadableFile("composer.lock file", lockPath)
	if err != nil {
		return "", "", err
	}

	lockURI, err := lockURIWithinRoot(rootResolved, lockResolved)
	if err != nil {
		return "", "", err
	}

	return rootResolved, lockURI, nil
}

func buildReport(auditPath, lockPath, rootResolved, lockURI string) ([]byte, error) {
	auditJSON, err := readResolvedFile(auditPath)
	if err != nil {
		return nil, fmt.Errorf("read audit file %q: %w", auditPath, err)
	}

	composerLockJSON, err := readResolvedFile(lockPath)
	if err != nil {
		return nil, fmt.Errorf("read composer.lock file %q: %w", lockPath, err)
	}

	return comsarif.BuildReport(auditJSON, composerLockJSON, comsarif.BuildOptions{
		RootURI: toFileURI(rootResolved),
		LockURI: lockURI,
	})
}

func writeError(w io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(w, "error: "+format+"\n", args...)
}

func resolveReadableFile(pathLabel, path string) (string, error) {
	resolved, info, err := resolvePath(path)
	if err != nil {
		return "", fmt.Errorf("resolve %s %q: %w", pathLabel, path, err)
	}
	if info.IsDir() {
		return "", fmt.Errorf("%s %q is a directory", pathLabel, path)
	}

	file, err := openResolvedFile(resolved)
	if err != nil {
		return "", fmt.Errorf("open %s %q: %w", pathLabel, path, err)
	}
	defer file.Close()

	return resolved, nil
}

func readResolvedFile(path string) ([]byte, error) {
	file, err := openPathFile(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	return io.ReadAll(file)
}

func openResolvedFile(path string) (*os.File, error) {
	return openPathFile(path)
}

func openPathFile(path string) (*os.File, error) {
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(filepath.Dir(resolved))
	if err != nil {
		return nil, err
	}

	file, err := root.Open(filepath.Base(resolved))
	if err != nil {
		_ = root.Close()
		return nil, err
	}
	if err := root.Close(); err != nil {
		_ = file.Close()
		return nil, err
	}

	return file, nil
}

func resolveDirectory(path string) (string, error) {
	resolved, info, err := resolvePath(path)
	if err != nil {
		return "", fmt.Errorf("resolve root path %q: %w", path, err)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("root path %q is not a directory", path)
	}
	return resolved, nil
}

func resolvePath(path string) (string, os.FileInfo, error) {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return "", nil, err
	}
	absPath = filepath.Clean(absPath)

	resolved, err := filepath.EvalSymlinks(absPath)
	if err != nil {
		return "", nil, err
	}

	info, err := os.Stat(resolved)
	if err != nil {
		return "", nil, err
	}

	return resolved, info, nil
}

func lockURIWithinRoot(rootPath, lockPath string) (string, error) {
	rel, err := filepath.Rel(rootPath, lockPath)
	if err != nil {
		return "", fmt.Errorf("make composer.lock path %q relative to root %q: %w", lockPath, rootPath, err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", fmt.Errorf("resolved composer.lock path %q is outside root %q", lockPath, rootPath)
	}
	return filepath.ToSlash(rel), nil
}

func toFileURI(path string) string {
	return (&url.URL{Scheme: "file", Path: filepath.ToSlash(path)}).String()
}
