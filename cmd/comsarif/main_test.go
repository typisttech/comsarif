package main

import (
	"os"
	"slices"
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
	if slices.Contains([]string{"1", "true"}, os.Getenv("UPDATE_SCRIPTS")) {
		t.Log("Updating test scripts")
		updateScripts = true
	}

	testscript.Run(t, testscript.Params{
		Dir:                 "testdata/script",
		UpdateScripts:       updateScripts,
		RequireExplicitExec: true,
		RequireUniqueNames:  true,
	})
}
