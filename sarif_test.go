package comsarif

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/owenrumney/go-sarif/v3/pkg/report/v210/sarif"
)

func TestTruncate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		s      string
		maxLen int
		want   string
	}{
		{"empty_string", "", 10, ""},
		{"shorter_than_maxLen", "hello", 10, "hello"},
		{"exactly_maxLen", "hello", 5, "hello"},
		{"longer_than_maxLen", "hello world", 5, "hello"},
		{"maxLen_0", "hello", 0, ""},
		{"maxLen_1", "hello", 1, "h"},
		{"multi_byte_utf8_by_rune_count", "héllo", 3, "hél"},
		{"emoji_single", "😀hello", 1, "😀"},
		{"emoji_truncated", "😀😁😂", 2, "😀😁"},
		{"chinese_characters", "你好世界", 2, "你好"},
		{"mixed_ascii_and_chinese", "ab你cd", 3, "ab你"},
		{"very_large_maxLen", "hi", 1000, "hi"},
		{"all_spaces", "   ", 2, "  "},
		{"newlines", "a\nb\nc", 3, "a\nb"},
		{"unicode_accents", "café", 3, "caf"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := truncate(tt.s, tt.maxLen)
			if got != tt.want {
				t.Errorf("truncate(%q, %d) = %q, want %q", tt.s, tt.maxLen, got, tt.want)
			}
		})
	}
}

func TestNewRegionsHashes(t *testing.T) {
	t.Parallel()

	composerLock := `{
	  "packages": [
	    {"name": "vendor/pkg"},
	    {"name": "vendor/pkg-two"}
	  ],
	  "packages-dev": [
	    {"name": "vendor/dev"}
	  ]
	}`

	regs, err := newRegions(strings.NewReader(composerLock))
	if err != nil {
		t.Fatalf("newRegions() unexpected error: %v", err)
	}

	lineHashes := primaryLocationLineHashesByLine([]byte(composerLock))
	for pkg, reg := range regs {
		if got, want := reg.hash, lineHashes[reg.line]; got != want {
			t.Errorf("newRegions() fingerprint for %q = %q, want %q", pkg, got, want)
		}
	}
}

func TestNewLocation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		reg             region
		wantStartLine   *int
		wantStartColumn *int
		wantEndColumn   *int
	}{
		{"basic_region", region{line: 10, startColumn: 5, endColumn: 20, hash: "dummy"}, new(10), new(5), new(20)},
		{"line_1", region{line: 1, startColumn: 1, endColumn: 10, hash: "dummy"}, new(1), new(1), new(10)},
		{"zero_values", region{line: 0, startColumn: 0, endColumn: 0, hash: "dummy"}, new(0), new(0), new(0)},
		{"large_line_number", region{line: 9999, startColumn: 3, endColumn: 50, hash: "dummy"}, new(9999), new(3), new(50)},
		{"start_equals_end_column", region{line: 5, startColumn: 7, endColumn: 7, hash: "dummy"}, new(5), new(7), new(7)},
		{"end_column_less_than_start", region{line: 2, startColumn: 15, endColumn: 3, hash: "dummy"}, new(2), new(15), new(3)},
		{"single_char_region", region{line: 3, startColumn: 1, endColumn: 2, hash: "dummy"}, new(3), new(1), new(2)},
		{"line_100", region{line: 100, startColumn: 10, endColumn: 40, hash: "dummy"}, new(100), new(10), new(40)},
		{"wide_column_range", region{line: 50, startColumn: 1, endColumn: 1000, hash: "dummy"}, new(50), new(1), new(1000)},
		{"all_ones", region{line: 1, startColumn: 1, endColumn: 1, hash: "dummy"}, new(1), new(1), new(1)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			aLoc := sarif.NewSimpleArtifactLocation("composer.lock")

			loc := newLocation(tt.reg, aLoc)
			if loc == nil {
				t.Fatal("newLocation() returned nil")
			}

			pl := loc.PhysicalLocation
			if pl == nil {
				t.Fatal("newLocation() PhysicalLocation is nil")
			}

			r := pl.Region
			if r == nil {
				t.Fatal("newLocation() Region is nil")
			}
			if diff := cmp.Diff(tt.wantStartLine, r.StartLine); diff != "" {
				t.Errorf("newLocation() StartLine mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantStartColumn, r.StartColumn); diff != "" {
				t.Errorf("newLocation() StartColumn mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(tt.wantEndColumn, r.EndColumn); diff != "" {
				t.Errorf("newLocation() EndColumn mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestAdvisoryFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		advisories  []advisory
		wantRules   int
		wantResults int
		wantErr     bool
	}{
		{"no_advisories", nil, 0, 0, false},
		{
			"single_advisory",
			[]advisory{{
				id: "ADV-001", packageName: "vendor/pkg",
				affectedVersions: ">=1.0", cve: "CVE-2023-1234",
			}},
			1, 1, false,
		},
		{
			"two_advisories_same_package",
			[]advisory{
				{id: "ADV-001", packageName: "vendor/pkg", affectedVersions: ">=1.0"},
				{id: "ADV-002", packageName: "vendor/pkg", affectedVersions: "<2.0"},
			},
			2, 2, false,
		},
		{
			"two_advisories_different_packages",
			[]advisory{
				{id: "ADV-001", packageName: "vendor/pkg", affectedVersions: ">=1.0"},
				{id: "ADV-002", packageName: "a/b", affectedVersions: "<2.0"},
			},
			2, 2, false,
		},
		{
			"three_advisories",
			[]advisory{
				{id: "ADV-001", packageName: "vendor/pkg", affectedVersions: ">=1.0"},
				{id: "ADV-002", packageName: "a/b", affectedVersions: "<2.0"},
				{id: "ADV-003", packageName: "c/d", affectedVersions: "<3.0"},
			},
			3, 3, false,
		},
		{
			"package_not_in_regions",
			[]advisory{{
				id: "ADV-001", packageName: "unknown/pkg", affectedVersions: ">=1.0",
			}},
			0, 0, true,
		},
		{
			"advisory_with_severity",
			[]advisory{{
				id: "ADV-001", packageName: "vendor/pkg",
				affectedVersions: ">=1.0", severity: severityCritical,
			}},
			1, 1, false,
		},
		{
			"advisory_with_no_cve_uses_id",
			[]advisory{{
				id: "ADV-001", packageName: "vendor/pkg",
				affectedVersions: ">=1.0",
			}},
			1, 1, false,
		},
		{
			"long_description_truncated",
			[]advisory{{
				id: "ADV-001", packageName: "vendor/pkg",
				affectedVersions: ">=1.0",
				cve:              strings.Repeat("X", 2000),
			}},
			1, 1, false,
		},
		{
			"advisory_with_low_severity",
			[]advisory{{
				id: "ADV-001", packageName: "vendor/pkg",
				affectedVersions: ">=1.0", severity: severityLow,
			}},
			1, 1, false,
		},
		{
			"four_advisories_different_packages",
			[]advisory{
				{id: "ADV-001", packageName: "vendor/pkg", affectedVersions: ">=1.0"},
				{id: "ADV-002", packageName: "a/b", affectedVersions: "<2.0"},
				{id: "ADV-003", packageName: "c/d", affectedVersions: "<3.0"},
				{id: "ADV-004", packageName: "vendor/pkg", affectedVersions: "~1.5"},
			},
			4, 4, false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			aLoc := sarif.NewSimpleArtifactLocation("composer.lock")
			regs := regions{
				"vendor/pkg": {line: 5, startColumn: 1, endColumn: 20, hash: "hash-5:1"},
				"a/b":        {line: 10, startColumn: 2, endColumn: 15, hash: "hash-10:1"},
				"c/d":        {line: 20, startColumn: 3, endColumn: 25, hash: "hash-20:1"},
			}

			rules, results, err := advisoryFindings(regs, aLoc, tt.advisories...)
			if tt.wantErr {
				if err == nil {
					t.Error("advisoryFindings() unexpected success")
				}
				return
			}
			if err != nil {
				t.Fatalf("advisoryFindings() unexpected error: %v", err)
			}
			if len(rules) != tt.wantRules {
				t.Errorf("advisoryFindings() rules len = %d, want %d", len(rules), tt.wantRules)
			}
			if len(results) != tt.wantResults {
				t.Errorf("advisoryFindings() results len = %d, want %d", len(results), tt.wantResults)
			}
		})
	}
}

func TestAdvisoryFindingsRuleAndResultContent(t *testing.T) {
	t.Parallel()

	aLoc := sarif.NewSimpleArtifactLocation("composer.lock")
	regs := regions{
		"vendor/pkg": {line: 5, startColumn: 1, endColumn: 20, hash: "linehash:1"},
	}

	adv := advisory{
		id:               "ADV-001",
		packageName:      "vendor/pkg",
		affectedVersions: ">=1.0",
		cve:              "CVE-2023-1234",
		severity:         severityHigh,
	}

	rules, results, err := advisoryFindings(regs, aLoc, adv)
	if err != nil {
		t.Fatalf("advisoryFindings() unexpected error: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("advisoryFindings() rules len = %d, want 1", len(rules))
	}
	if len(results) != 1 {
		t.Errorf("advisoryFindings() results len = %d, want 1", len(results))
	}

	wantRuleID := adv.ruleID()
	if rules[0].ID == nil || *rules[0].ID != wantRuleID {
		t.Errorf("advisoryFindings() rule ID = %v, want %q", rules[0].ID, wantRuleID)
	}

	if results[0].RuleID == nil || *results[0].RuleID != wantRuleID {
		t.Errorf("advisoryFindings() result RuleID = %v, want %q", results[0].RuleID, wantRuleID)
	}

	if results[0].Message.Text == nil || !strings.Contains(*results[0].Message.Text, "vendor/pkg") {
		t.Errorf("advisoryFindings() result message missing vendor/pkg: %v", results[0].Message.Text)
	}

	fp := results[0].PartialFingerprints
	if got := fp["primaryLocationLineHash"]; got != "linehash:1" {
		t.Errorf("advisoryFindings() result fingerprint = %q, want %q", got, "linehash:1")
	}
}

func TestAbandonedFindings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		abandonments []abandonment
		wantResults  int
		wantErr      bool
	}{
		{"no_abandonments", nil, 0, false},
		{"single_abandonment_with_replacement", []abandonment{{packageName: "vendor/old", replacement: "vendor/new"}}, 1, false},
		{"single_abandonment_no_replacement", []abandonment{{packageName: "vendor/old", replacement: ""}}, 1, false},
		{
			"two_abandonments",
			[]abandonment{
				{packageName: "vendor/old", replacement: "vendor/new"},
				{packageName: "another/pkg", replacement: ""},
			},
			2, false,
		},
		{
			"three_abandonments",
			[]abandonment{
				{packageName: "vendor/old", replacement: ""},
				{packageName: "another/pkg", replacement: ""},
				{packageName: "third/pkg", replacement: "new/pkg"},
			},
			3, false,
		},
		{"package_not_in_regions", []abandonment{{packageName: "unknown/pkg", replacement: ""}}, 0, true},
		{
			"second_package_not_in_regions",
			[]abandonment{
				{packageName: "vendor/old", replacement: ""},
				{packageName: "unknown/pkg", replacement: ""},
			},
			0, true,
		},
		{"abandonment_with_long_replacement", []abandonment{{packageName: "vendor/old", replacement: strings.Repeat("r", 200)}}, 1, false},
		{
			"two_replacements_provided",
			[]abandonment{
				{packageName: "vendor/old", replacement: "new/one"},
				{packageName: "another/pkg", replacement: "new/two"},
			},
			2, false,
		},
		{
			"three_abandonments_all_with_replacements",
			[]abandonment{
				{packageName: "vendor/old", replacement: "new/a"},
				{packageName: "another/pkg", replacement: "new/b"},
				{packageName: "third/pkg", replacement: "new/c"},
			},
			3, false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			aLoc := sarif.NewSimpleArtifactLocation("composer.lock")
			regs := regions{
				"vendor/old":  {line: 5, startColumn: 1, endColumn: 20, hash: "hash-5:1"},
				"another/pkg": {line: 10, startColumn: 2, endColumn: 15, hash: "hash-10:1"},
				"third/pkg":   {line: 20, startColumn: 3, endColumn: 25, hash: "hash-20:1"},
			}

			rule, results, err := abandonedFindings(regs, aLoc, tt.abandonments)
			if tt.wantErr {
				if err == nil {
					t.Error("abandonedFindings() unexpected success")
				}
				return
			}
			if err != nil {
				t.Fatalf("abandonedFindings() unexpected error: %v", err)
			}
			if rule == nil {
				t.Fatal("abandonedFindings() rule is nil")
			}
			if rule.ID == nil || *rule.ID != "abandoned" {
				t.Errorf("abandonedFindings() rule ID = %v, want %q", rule.ID, "abandoned")
			}
			if len(results) != tt.wantResults {
				t.Errorf("abandonedFindings() results len = %d, want %d", len(results), tt.wantResults)
			}
		})
	}
}

func TestAbandonedFindingsResultContent(t *testing.T) {
	t.Parallel()

	aLoc := sarif.NewSimpleArtifactLocation("composer.lock")
	regs := regions{
		"vendor/old": {line: 5, startColumn: 1, endColumn: 20, hash: "linehash:1"},
	}

	ab := abandonment{packageName: "vendor/old", replacement: "vendor/new"}
	rule, results, err := abandonedFindings(regs, aLoc, []abandonment{ab})
	if err != nil {
		t.Fatalf("abandonedFindings() unexpected error: %v", err)
	}

	if rule.ID == nil || *rule.ID != "abandoned" {
		t.Errorf("abandonedFindings() rule ID = %v, want abandoned", rule.ID)
	}
	if rule.ShortDescription == nil || rule.ShortDescription.Text == nil || *rule.ShortDescription.Text == "" {
		t.Error("abandonedFindings() rule ShortDescription not set")
	}

	if len(results) != 1 {
		t.Fatalf("abandonedFindings() results len = %d , want 1", len(results))
	}
	res := results[0]
	if res.RuleID == nil || *res.RuleID != "abandoned" {
		t.Errorf("abandonedFindings() result RuleID = %v, want abandoned", res.RuleID)
	}
	if res.Message.Text == nil || !strings.Contains(*res.Message.Text, "vendor/old") {
		t.Errorf("abandonedFindings() result message missing vendor/old: %v", res.Message.Text)
	}
	if got := res.PartialFingerprints["primaryLocationLineHash"]; got != "linehash:1" {
		t.Errorf("abandonedFindings() result fingerprint = %q, want %q", got, "linehash:1")
	}
}

func TestBuild(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		aud         audit
		wantRules   int
		wantResults int
		wantErr     bool
	}{
		{"empty_audit", audit{}, 0, 0, false},
		{
			"one_advisory_no_abandonments",
			audit{
				advisories: []advisory{{
					id: "ADV-001", packageName: "vendor/pkg", affectedVersions: ">=1.0",
				}},
			},
			1, 1, false,
		},
		{
			"no_advisories_one_abandonment",
			audit{
				abandonments: []abandonment{{packageName: "vendor/old", replacement: ""}},
			},
			1, 1, false,
		},
		{
			"one_advisory_one_abandonment",
			audit{
				advisories: []advisory{{
					id: "ADV-001", packageName: "vendor/pkg", affectedVersions: ">=1.0",
				}},
				abandonments: []abandonment{{packageName: "vendor/old", replacement: ""}},
			},
			2, 2, false,
		},
		{
			"two_advisories_two_abandonments",
			audit{
				advisories: []advisory{
					{id: "ADV-001", packageName: "vendor/pkg", affectedVersions: ">=1.0"},
					{id: "ADV-002", packageName: "a/b", affectedVersions: "<2.0"},
				},
				abandonments: []abandonment{
					{packageName: "vendor/old", replacement: ""},
					{packageName: "a/b", replacement: "new/pkg"},
				},
			},
			3, 4, false,
		},
		{
			"advisory_package_not_in_regions",
			audit{
				advisories: []advisory{{
					id: "ADV-001", packageName: "unknown/pkg", affectedVersions: ">=1.0",
				}},
			},
			0, 0, true,
		},
		{
			"abandoned_package_not_in_regions",
			audit{
				abandonments: []abandonment{{packageName: "unknown/pkg", replacement: ""}},
			},
			0, 0, true,
		},
		{
			"two_advisories_no_abandonments",
			audit{
				advisories: []advisory{
					{id: "ADV-001", packageName: "vendor/pkg", affectedVersions: ">=1.0"},
					{id: "ADV-002", packageName: "a/b", affectedVersions: "<2.0"},
				},
			},
			2, 2, false,
		},
		{
			"advisory_with_severity_high",
			audit{
				advisories: []advisory{{
					id: "ADV-001", packageName: "vendor/pkg",
					affectedVersions: ">=1.0", severity: severityHigh,
				}},
			},
			1, 1, false,
		},
		{
			"one_advisory_one_abandonment_same_package",
			audit{
				advisories: []advisory{{
					id: "ADV-001", packageName: "vendor/pkg", affectedVersions: ">=1.0",
				}},
				abandonments: []abandonment{{packageName: "vendor/pkg", replacement: ""}},
			},
			2, 2, false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			aLoc := sarif.NewSimpleArtifactLocation("composer.lock")
			regs := regions{
				"vendor/pkg": {line: 5, startColumn: 1, endColumn: 20, hash: "hash-5:1"},
				"a/b":        {line: 10, startColumn: 2, endColumn: 15, hash: "hash-10:1"},
				"vendor/old": {line: 15, startColumn: 3, endColumn: 25, hash: "hash-15:1"},
			}

			rules, results, err := build(tt.aud, regs, aLoc)
			if tt.wantErr {
				if err == nil {
					t.Error("build() unexpected success")
				}
				return
			}
			if err != nil {
				t.Fatalf("build() unexpected error: %v", err)
			}
			if len(rules) != tt.wantRules {
				t.Errorf("build() rules len = %d, want %d", len(rules), tt.wantRules)
			}
			if len(results) != tt.wantResults {
				t.Errorf("build() results len = %d, want %d", len(results), tt.wantResults)
			}
		})
	}
}

func TestNewReport(t *testing.T) {
	t.Parallel()

	validComposerLock := `{"packages":[{"name":"vendor/pkg"}],"packages-dev":[]}`
	validAuditEmpty := `{"advisories":[],"abandoned":[]}`
	validAuditWithAdvisory := `{
		"advisories":{
			"vendor/pkg":[{
				"advisoryId":"ADV-001",
				"packageName":"vendor/pkg",
				"affectedVersions":">=1.0",
				"title":"Test Advisory"
			}]
		},
		"abandoned":[]
	}`
	validAuditWithAbandonment := `{
		"advisories":[],
		"abandoned":{"vendor/pkg":null}
	}`
	validAuditBoth := `{
		"advisories":{
			"vendor/pkg":[{
				"advisoryId":"ADV-001",
				"packageName":"vendor/pkg",
				"affectedVersions":">=1.0",
				"title":"Test"
			}]
		},
		"abandoned":{"vendor/pkg":null}
	}`

	tests := []struct {
		name             string
		auditJSON        string
		composerLockJSON string
		rootURI          string
		lockURI          string
		wantErr          bool
	}{
		{"empty_audit_and_lock", validAuditEmpty, validComposerLock, "/path/to/root", "composer.lock", false},
		{"audit_with_advisory", validAuditWithAdvisory, validComposerLock, "/path/to/root", "composer.lock", false},
		{"audit_with_abandonment", validAuditWithAbandonment, validComposerLock, "/path/to/root", "composer.lock", false},
		{"audit_with_both_advisory_and_abandonment", validAuditBoth, validComposerLock, "/path/to/root", "composer.lock", false},
		{"empty_rootURI_and_lockURI", validAuditEmpty, validComposerLock, "", "", false},
		{"invalid_audit_JSON", `not json`, validComposerLock, "", "", true},
		{"invalid_composer_lock_JSON", validAuditEmpty, `not json`, "", "", true},
		{
			"advisory_references_package_not_in_composer_lock",
			`{"advisories":{"missing/pkg":[{"advisoryId":"ADV-001","packageName":"missing/pkg","affectedVersions":">=1.0"}]},"abandoned":[]}`,
			validComposerLock, "", "", true,
		},
		{
			"abandonment_references_package_not_in_composer_lock",
			`{"advisories":[],"abandoned":{"missing/pkg":null}}`,
			validComposerLock, "", "", true,
		},
		{
			"composer_lock_with_packages_dev_only",
			validAuditEmpty,
			`{"packages":[],"packages-dev":[{"name":"vendor/pkg"}]}`,
			"/root", "composer.lock", false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			report, err := NewReport(
				strings.NewReader(tt.auditJSON),
				strings.NewReader(tt.composerLockJSON),
				tt.rootURI,
				tt.lockURI,
			)
			if tt.wantErr {
				if err == nil {
					t.Error("NewReport() unexpected success")
				}
				return
			}
			if err != nil {
				t.Fatalf("NewReport() unexpected error: %v", err)
			}
			if report == nil {
				t.Fatal("NewReport() report is nil")
			}
		})
	}
}

func TestNewReport_Structure(t *testing.T) {
	t.Parallel()

	auditJSON := `{"advisories":[],"abandoned":[]}`
	composerLock := `{"packages":[{"name":"vendor/pkg"}],"packages-dev":[]}`

	report, err := NewReport(
		strings.NewReader(auditJSON),
		strings.NewReader(composerLock),
		"/root",
		"composer.lock",
	)
	if err != nil {
		t.Fatalf("NewReport() unexpected error: %v", err)
	}
	if report == nil {
		t.Fatal("NewReport() report is nil")
	}
	if len(report.Runs) != 1 {
		t.Fatalf("NewReport() runs len = %d, want 1", len(report.Runs))
	}
	run := report.Runs[0]
	if run.Tool.Driver.Name == nil || *run.Tool.Driver.Name != "composer" {
		t.Errorf("NewReport() tool name = %v, want composer", run.Tool.Driver.Name)
	}
}
