package main

import (
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"

	"github.com/typisttech/comsarif"
)

func main() {
	err := run(os.Args, os.Stdout)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string, stdout io.Writer) error {
	cfg := mustParseFlags(args)

	auditPath, err := filepath.Abs(cfg.auditPath)
	if err != nil {
		return fmt.Errorf("normalize audit path %q to absolute: %v", cfg.auditPath, err)
	}
	rootPath, err := filepath.Abs(cfg.rootPath)
	if err != nil {
		return fmt.Errorf("normalize root path %q to absolute: %v", cfg.auditPath, err)
	}
	lockPath, err := filepath.Abs(cfg.lockPath)
	if err != nil {
		return fmt.Errorf("normalize composer.lock path %q to absolute: %v", cfg.auditPath, err)
	}
	lockRelPath, err := filepath.Rel(rootPath, lockPath)
	if err != nil {
		return fmt.Errorf("normalize composer.lock path %q relative to root %q: %v", lockPath, rootPath, err)
	}

	//gosec:disable G304 -- We want to open users' audit files.
	audit, err := os.Open(auditPath)
	if err != nil {
		return fmt.Errorf("open audit path %q: %w", auditPath, err)
	}
	defer audit.Close()

	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return fmt.Errorf("open root path %q: %v", rootPath, err)
	}
	defer root.Close()

	lock, err := root.Open(lockRelPath)
	if err != nil {
		return fmt.Errorf("open lock path %q: %v", lockRelPath, err)
	}
	defer lock.Close()

	rootURI := (&url.URL{Scheme: "file", Path: rootPath}).String()

	report, err := comsarif.NewReport(audit, lock, rootURI, lockRelPath)
	if err != nil {
		return err
	}

	if err := report.Write(stdout); err != nil {
		return fmt.Errorf("render report: %v", err)
	}

	fmt.Fprintln(stdout, "")

	return nil
}
