package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
)

const art = `
 ▄▄▄▄  ▄▄▄  ▄▄   ▄▄  ▄▄▄▄  ▄▄▄  ▄▄▄▄  ▄▄ ▄▄▄▄▄
██▀▀▀ ██▀██ ██▀▄▀██ ███▄▄ ██▀██ ██▄█▄ ██ ██▄▄
▀████ ▀███▀ ██   ██ ▄▄██▀ ██▀██ ██ ██ ██ ██
`

const ads = `
SUPPORT COMSARIF:
  If you find this tool useful, please consider supporting its development.
  Every contribution counts, regardless how big or small.
  I am eternally grateful to all sponsors who fund my open source journey.

GitHub Sponsor  https://github.com/sponsors/tangrufus

HIRE TANG RUFUS:
  I am looking for my next role, freelance or full-time.
  If you find this tool useful, I can build you more weird stuff like this.
  Let's talk if you are hiring PHP / Ruby / Go developers.

Contact         https://typist.tech/contact/
`

const usage = `
USAGE:
  %[1]s [<flags>...] --audit <audit.json> --lock <composer.lock>
`

const examples = `
EXAMPLES:
  # Generate SARIF based on composer.lock
  $ composer audit --locked --format json > audit.json
  $ %[1]s --audit audit.json --lock composer.lock

  # Generate SARIF based on installed packages
  $ composer install
  $ composer audit --format json > audit.json
  $ %[1]s --audit audit.json --lock composer.lock
`

const version = `
%-16[1]s%[2]s

Generate SARIF from Composer audit reports.
%[3]s

Built with %[4]s %[5]s/%[6]s
`

type config struct {
	auditPath string
	lockPath  string
	rootPath  string
}

func mustParseFlags(args []string) config {
	var cfg config

	flags := flag.NewFlagSet(args[0], flag.ExitOnError)

	w := flags.Output()

	flags.Usage = func() {
		fmt.Fprintf(w, usage, args[0])

		fmt.Fprint(w, "\nFLAGS:\n")
		flags.PrintDefaults()

		fmt.Fprintf(w, examples, args[0])
		fmt.Fprint(w, ads)
	}

	flags.StringVar(&cfg.auditPath, "audit", "", "path to Composer audit JSON")
	flags.StringVar(&cfg.lockPath, "lock", "", "path to composer.lock")
	flags.StringVar(&cfg.rootPath, "root", "", "path to repository root. Default to current directory")

	var ver bool
	flags.BoolVar(&ver, "version", false, "Print version")
	flags.BoolVar(&ver, "v", false, "Print version")

	// Ignore error because of flag.ExitOnError
	err := flags.Parse(args[1:])
	if errors.Is(err, flag.ErrHelp) {
		flags.Usage()
		os.Exit(0)
	}

	if ver {
		printVersion(w)
		os.Exit(0)
	}

	if flags.NArg() != 0 {
		fmt.Fprintf(w, "unexpected arguments: %s", strings.Join(flags.Args(), " "))
		flags.Usage()
		os.Exit(2)
	}
	if cfg.auditPath == "" {
		fmt.Fprint(w, "missing required --audit flag")
		flags.Usage()
		os.Exit(2)
	}
	if cfg.lockPath == "" {
		fmt.Fprint(w, "missing required --lock flag")
		flags.Usage()
		os.Exit(2)
	}
	if cfg.rootPath == "" {
		wd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(w, "error getting current working directory: %v", err)
			os.Exit(1)
		}
		cfg.rootPath = wd
	}

	return cfg
}

func printVersion(w io.Writer) {
	ver := "(devel)"
	dirty := true
	var revision string

	if bi, ok := debug.ReadBuildInfo(); ok {
		ver = bi.Main.Version

		for _, kv := range bi.Settings {
			switch kv.Key {
			case "vcs.modified":
				dirty = kv.Value != "false"
			case "vcs.revision":
				revision = kv.Value
			}
		}
	}

	url := "https://github.com/typisttech/comsarif"
	switch {
	case strings.HasPrefix(ver, "v") && strings.Count(ver, "-") < 2:
		url = fmt.Sprintf("%s/releases/tag/%s", url, ver)
	case !dirty && revision != "":
		url = fmt.Sprintf("%s/tree/%s", url, revision)
	}

	fmt.Fprint(w, art)

	fmt.Fprintf(w, version,
		"WPry",
		ver,
		url,
		runtime.Version(),
		runtime.GOOS,
		runtime.GOARCH,
	)

	fmt.Fprint(w, ads)
}
