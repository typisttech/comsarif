package comsarif

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

func TestNormalizeString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		value *string
		want  string
	}{
		{"nil_pointer", nil, ""},
		{"empty_string", new(""), ""},
		{"plain_string", new("hello"), "hello"},
		{"leading_space", new("  hello"), "hello"},
		{"trailing_space", new("hello  "), "hello"},
		{"both_spaces", new("  hello  "), "hello"},
		{"only_spaces", new("   "), ""},
		{"tab_only", new("\t"), ""},
		{"newline_only", new("\n"), ""},
		{"mixed_whitespace", new("\t hello \n"), "hello"},
		{"already_clean", new("vendor/pkg"), "vendor/pkg"},
		{"unicode", new("  héllo  "), "héllo"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := normalizeString(tt.value)
			if got != tt.want {
				t.Errorf("normalizeString() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNewAdvisorySeverity(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		severity string
		want     advisorySeverity
	}{
		{"critical_lowercase", "critical", severityCritical},
		{"critical_uppercase", "CRITICAL", severityCritical},
		{"critical_mixed", "Critical", severityCritical},
		{"high", "high", severityHigh},
		{"high_uppercase", "HIGH", severityHigh},
		{"medium", "medium", severityMedium},
		{"medium_uppercase", "MEDIUM", severityMedium},
		{"low", "low", severityLow},
		{"low_uppercase", "LOW", severityLow},
		{"none", "none", severityNone},
		{"none_uppercase", "NONE", severityNone},
		{"empty", "", severityUnknown},
		{"unknown_string", "bogus", severityUnknown},
		{"whitespace_only", "   ", severityUnknown},
		{"leading_space_critical", "  critical  ", severityCritical},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := newAdvisorySeverity(tt.severity)
			if got != tt.want {
				t.Errorf("newAdvisorySeverity(%q) = %q, want %q", tt.severity, got, tt.want)
			}
		})
	}
}

func TestAdvisorySeverity_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		as   advisorySeverity
		want string
	}{
		{"critical", severityCritical, "critical"},
		{"high", severityHigh, "high"},
		{"medium", severityMedium, "medium"},
		{"low", severityLow, "low"},
		{"none", severityNone, "none"},
		{"unknown", severityUnknown, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.as.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdvisorySeverity_Score(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		as   advisorySeverity
		want string
	}{
		{"critical", severityCritical, "9.0"},
		{"high", severityHigh, "7.0"},
		{"medium", severityMedium, "4.0"},
		{"low", severityLow, "0.1"},
		{"none", severityNone, ""},
		{"unknown", severityUnknown, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.as.score()
			if got != tt.want {
				t.Errorf("score() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdvisorySource_String(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		as   advisorySource
		want string
	}{
		{"both_set", advisorySource{name: "GitHub", remoteID: "GHSA-1234"}, "GHSA-1234 (GitHub)"},
		{"name_empty", advisorySource{name: "", remoteID: "GHSA-5678"}, "GHSA-5678"},
		{"both_empty", advisorySource{name: "", remoteID: ""}, ""},
		{"name_only", advisorySource{name: "FriendsOfPHP", remoteID: ""}, "FriendsOfPHP"},
		{"remoteID_with_special_chars", advisorySource{name: "FOP", remoteID: "FOP/2023/001"}, "FOP/2023/001 (FOP)"},
		{"name_with_spaces", advisorySource{name: "Friends Of PHP", remoteID: "FOP-001"}, "FOP-001 (Friends Of PHP)"},
		{"name_with_parens", advisorySource{name: "(Source)", remoteID: "ID-001"}, "ID-001 ((Source))"},
		{"unicode", advisorySource{name: "漢字", remoteID: "ADV-001"}, "ADV-001 (漢字)"},
		{"numeric_remoteID", advisorySource{name: "", remoteID: "12345"}, "12345"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.as.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAbandonment_Message(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		ab   abandonment
		want string
	}{
		{
			"with_replacement",
			abandonment{packageName: "vendor/old", replacement: "vendor/new"},
			"Package vendor/old is abandoned, you should avoid using it. Use vendor/new instead.",
		},
		{
			"without_replacement",
			abandonment{packageName: "vendor/old", replacement: ""},
			"Package vendor/old is abandoned, you should avoid using it. No replacement was suggested.",
		},
		{
			"empty_package_name_no_replacement",
			abandonment{packageName: "", replacement: ""},
			"Package  is abandoned, you should avoid using it. No replacement was suggested.",
		},
		{
			"empty_package_name_with_replacement",
			abandonment{packageName: "", replacement: "new/pkg"},
			"Package  is abandoned, you should avoid using it. Use new/pkg instead.",
		},
		{
			"special_chars_in_package",
			abandonment{packageName: "foo/bar-baz", replacement: ""},
			"Package foo/bar-baz is abandoned, you should avoid using it. No replacement was suggested.",
		},
		{
			"replacement_with_slash",
			abandonment{packageName: "a/b", replacement: "c/d/e"},
			"Package a/b is abandoned, you should avoid using it. Use c/d/e instead.",
		},
		{
			"unicode_package_name",
			abandonment{packageName: "漢字/pkg", replacement: ""},
			"Package 漢字/pkg is abandoned, you should avoid using it. No replacement was suggested.",
		},
		{
			"replacement_with_spaces",
			abandonment{packageName: "pkg", replacement: "new pkg"},
			"Package pkg is abandoned, you should avoid using it. Use new pkg instead.",
		},
		{
			"single_char_names",
			abandonment{packageName: "a", replacement: "b"},
			"Package a is abandoned, you should avoid using it. Use b instead.",
		},
		{
			"only_replacement_empty_string_explicit",
			abandonment{packageName: "mypkg", replacement: ""},
			"Package mypkg is abandoned, you should avoid using it. No replacement was suggested.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.ab.message()
			if got != tt.want {
				t.Errorf("message() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMarkdownRow(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		field, value string
		want         string
	}{
		{"simple", "Field", "Value", "| Field | Value |\n"},
		{"pipe_in_value_escaped", "Link", "a|b", "| Link | a\\|b |\n"},
		{"newline_removed", "Title", "hello\nworld", "| Title | helloworld |\n"},
		{"empty_value", "X", "", "| X |  |\n"},
		{"empty_field", "", "Y", "|  | Y |\n"},
		{"both_empty", "", "", "|  |  |\n"},
		{"multiple_pipes", "F", "a|b|c", "| F | a\\|b\\|c |\n"},
		{"multiple_newlines", "F", "a\nb\nc", "| F | abc |\n"},
		{"pipe_and_newline_combined", "F", "a|b\nc", "| F | a\\|bc |\n"},
		{"unicode", "名前", "値", "| 名前 | 値 |\n"},
		{"special_markdown_chars", "F", "**bold**", "| F | **bold** |\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := markdownRow(tt.field, tt.value)
			if got != tt.want {
				t.Errorf("markdownRow(%q, %q) = %q, want %q", tt.field, tt.value, got, tt.want)
			}
		})
	}
}

func TestAdvisory_RuleID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		adv  advisory
		want string
	}{
		{"normal", advisory{packageName: "vendor/pkg", id: "ADV-001"}, "advisory/vendor/pkg/ADV-001"},
		{"empty_id", advisory{packageName: "vendor/pkg", id: ""}, "advisory/vendor/pkg/"},
		{"empty_package", advisory{packageName: "", id: "ADV-001"}, "advisory//ADV-001"},
		{"both_empty", advisory{}, "advisory//"},
		{"slashes_in_id", advisory{packageName: "a/b", id: "C/D"}, "advisory/a/b/C/D"},
		{"numeric_id", advisory{packageName: "p/q", id: "12345"}, "advisory/p/q/12345"},
		{"WPSEC_id", advisory{packageName: "wp/plugin", id: "WPSECADV/WF/001"}, "advisory/wp/plugin/WPSECADV/WF/001"},
		{"unicode", advisory{packageName: "漢字/pkg", id: "ADV"}, "advisory/漢字/pkg/ADV"},
		{"spaces_in_fields", advisory{packageName: "a b", id: "c d"}, "advisory/a b/c d"},
		{"hyphen_package", advisory{packageName: "foo-bar/baz", id: "X-001"}, "advisory/foo-bar/baz/X-001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.adv.ruleID()
			if got != tt.want {
				t.Errorf("ruleID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdvisory_ExternalID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		adv  advisory
		want string
	}{
		{"cve_set_returns_cve", advisory{id: "ADV-001", cve: "CVE-2023-1234"}, "CVE-2023-1234"},
		{"cve_empty_returns_id", advisory{id: "ADV-001", cve: ""}, "ADV-001"},
		{"both_empty", advisory{id: "", cve: ""}, ""},
		{"cve_whitespace_returned_as_is", advisory{id: "ADV-001", cve: "  "}, "  "},
		{"id_whitespace", advisory{id: "  ", cve: ""}, "  "},
		{"long_cve", advisory{id: "ADV-001", cve: "CVE-2023-99999"}, "CVE-2023-99999"},
		{"cve_with_special_chars", advisory{id: "ADV-001", cve: "CVE-2023/001"}, "CVE-2023/001"},
		{"unicode_cve", advisory{id: "ID", cve: "漢字"}, "漢字"},
		{"id_with_slashes_no_cve", advisory{id: "WPSECADV/WF/001", cve: ""}, "WPSECADV/WF/001"},
		{"cve_zero_value_struct", advisory{}, ""},
		{"ghsa_returned_when_no_cve", advisory{id: "ADV-001", cve: "", sources: []advisorySource{{remoteID: "GHSA-2345-6789-cfrv"}}}, "GHSA-2345-6789-cfrv"},
		{"cve_wins_over_ghsa", advisory{id: "ADV-001", cve: "CVE-2023-1", sources: []advisorySource{{remoteID: "GHSA-2345-6789-cfrv"}}}, "CVE-2023-1"},
		{"first_ghsa_source_used", advisory{id: "ADV-001", cve: "", sources: []advisorySource{{remoteID: "GHSA-2345-6789-cfrv"}, {remoteID: "GHSA-wxyz-abcd-1234"}}}, "GHSA-2345-6789-cfrv"},
		{"non_ghsa_remote_id_ignored", advisory{id: "ADV-001", cve: "", sources: []advisorySource{{remoteID: "NOT-A-GHSA"}}}, "ADV-001"},
		{"ghsa_uppercase_rejected", advisory{id: "ADV-001", cve: "", sources: []advisorySource{{remoteID: "GHSA-2345-WXYZ-cfgr"}}}, "ADV-001"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.adv.externalID()
			if got != tt.want {
				t.Errorf("externalID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdvisory_Description(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		adv  advisory
		want string
	}{
		{"empty_title", advisory{title: ""}, ""},
		{"zero_value_struct", advisory{}, ""},
		{"whitespace_only", advisory{title: "   "}, ""},
		{"single_line", advisory{title: "SQL Injection"}, "SQL Injection"},
		{"multi_line_first_wins", advisory{title: "First Line\nSecond Line"}, "First Line"},
		{"leading_blank_lines", advisory{title: "\n\nThird Line"}, "Third Line"},
		{"title_trimmed", advisory{title: "  Leading spaces  "}, "Leading spaces"},
		{"no_wpsec_special_handling", advisory{id: "WPSECADV/WF/001", title: "Plugin Name - Missing Auth"}, "Plugin Name - Missing Auth"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.adv.description()
			if got != tt.want {
				t.Errorf("description() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdvisory_Message(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		adv  advisory
		want string
	}{
		{
			"with_title_and_cve",
			advisory{packageName: "vendor/pkg", affectedVersions: ">=1.0,<1.5", id: "ADV-001", cve: "CVE-2023-1234", title: "SQL Injection"},
			"Package vendor/pkg (>=1.0,<1.5) is vulnerable to CVE-2023-1234: SQL Injection",
		},
		{
			"empty_title_omits_suffix",
			advisory{packageName: "vendor/pkg", affectedVersions: "1.0", id: "ADV-001", cve: "CVE-2023-1234", title: ""},
			"Package vendor/pkg (1.0) is vulnerable to CVE-2023-1234",
		},
		{
			"no_cve_uses_id",
			advisory{packageName: "vendor/pkg", affectedVersions: "1.0", id: "ADV-001", cve: "", title: "Remote Code Execution"},
			"Package vendor/pkg (1.0) is vulnerable to ADV-001: Remote Code Execution",
		},
		{
			"multi_line_title_first_line_used",
			advisory{packageName: "a/b", affectedVersions: "*", id: "ADV", title: "First Line\nSecond Line"},
			"Package a/b (*) is vulnerable to ADV: First Line",
		},
		{
			"ghsa_source",
			advisory{packageName: "vendor/pkg", affectedVersions: "1.0", id: "ADV-001", cve: "", title: "XSS Vulnerability", sources: []advisorySource{{remoteID: "GHSA-2345-6789-cfrv"}}},
			"Package vendor/pkg (1.0) is vulnerable to GHSA-2345-6789-cfrv: XSS Vulnerability",
		},
		{
			"cve_preferred_over_id",
			advisory{packageName: "a/b", affectedVersions: "1.0", id: "ADV-999", cve: "CVE-0000-0000", title: "Bug"},
			"Package a/b (1.0) is vulnerable to CVE-0000-0000: Bug",
		},
		{
			"zero_value",
			advisory{},
			"Package  () is vulnerable to ",
		},
		{
			"unicode_package",
			advisory{packageName: "漢字/pkg", affectedVersions: "1.0", id: "ADV", cve: "", title: "XSS"},
			"Package 漢字/pkg (1.0) is vulnerable to ADV: XSS",
		},
		{
			"non_wpsec_hyphen_title_no_special_handling",
			advisory{packageName: "vendor/pkg", affectedVersions: "1.0", id: "ADV-001", title: "Plugin - Missing Auth"},
			"Package vendor/pkg (1.0) is vulnerable to ADV-001: Plugin - Missing Auth",
		},
		{
			"wpsec_simple_suffix",
			advisory{packageName: "wp/plugin", affectedVersions: "<=7.1.0", id: "WPSECADV/WF/001", title: "Foo Bar - Baz Quz <= 7.1.0 - Missing Authorization"},
			"Package wp/plugin (<=7.1.0) is vulnerable to WPSECADV/WF/001: Missing Authorization",
		},
		{
			"wpsec_version_range_segment",
			advisory{packageName: "wp/core", affectedVersions: "5.4-5.8", id: "WPSECADV/WF/002", title: "WordPress Core 5.4 - 5.8 - Sensitive Information Disclosure"},
			"Package wp/core (5.4-5.8) is vulnerable to WPSECADV/WF/002: Sensitive Information Disclosure",
		},
		{
			"wpsec_no_plugin_prefix",
			advisory{packageName: "wp/plugin", affectedVersions: "*", id: "WPSECADV/WF/003", title: "Foo Bar - Authenticated (Subscriber+) Stored Cross-Site Scripting via Multiple Shortcodes"},
			"Package wp/plugin (*) is vulnerable to WPSECADV/WF/003: Authenticated (Subscriber+) Stored Cross-Site Scripting via Multiple Shortcodes",
		},
		{
			"wpsec_no_pattern_match_uses_full_title",
			advisory{packageName: "wp/plugin", affectedVersions: "1.0", id: "WPSECADV/WF/004", title: "Simple Advisory Title"},
			"Package wp/plugin (1.0) is vulnerable to WPSECADV/WF/004: Simple Advisory Title",
		},
		{
			"wpsec_empty_title_omits_suffix",
			advisory{packageName: "wp/plugin", affectedVersions: "1.0", id: "WPSECADV/WF/001", title: ""},
			"Package wp/plugin (1.0) is vulnerable to WPSECADV/WF/001",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.adv.message()
			if got != tt.want {
				t.Errorf("message() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAdvisory_Help(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		adv          advisory
		wantContains []string
		wantAbsent   []string
	}{
		{
			"minimal_fields",
			advisory{
				id:               "ADV-001",
				packageName:      "vendor/pkg",
				affectedVersions: ">=1.0,<2.0",
				title:            "A vulnerability",
			},
			[]string{"A vulnerability", "ADV-001", "vendor/pkg", ">=1.0,<2.0"},
			[]string{"CVE", "Severity", "Link", "Reported At", "Composer Repository"},
		},
		{
			"cve_included",
			advisory{
				id:               "ADV-002",
				packageName:      "a/b",
				affectedVersions: "<1.0",
				title:            "Title",
				cve:              "CVE-2023-1234",
			},
			[]string{"CVE-2023-1234", "CVE"},
			nil,
		},
		{
			"severity_included",
			advisory{
				id:               "ADV-003",
				packageName:      "a/b",
				affectedVersions: "<1.0",
				title:            "Title",
				severity:         severityHigh,
			},
			[]string{"high", "Severity"},
			nil,
		},
		{
			"severity_none_omitted",
			advisory{
				id:               "ADV-004",
				packageName:      "a/b",
				affectedVersions: "<1.0",
				title:            "Title",
				severity:         severityNone,
			},
			[]string{"none"},
			nil,
		},
		{
			"severity_unknown_omitted",
			advisory{
				id:               "ADV-005",
				packageName:      "a/b",
				affectedVersions: "<1.0",
				title:            "Title",
				severity:         severityUnknown,
			},
			nil,
			[]string{"Severity"},
		},
		{
			"link_included",
			advisory{
				id:               "ADV-006",
				packageName:      "a/b",
				affectedVersions: "<1.0",
				title:            "Title",
				link:             "https://example.com",
			},
			[]string{"https://example.com", "Link"},
			nil,
		},
		{
			"reportedAt_included",
			advisory{
				id:               "ADV-007",
				packageName:      "a/b",
				affectedVersions: "<1.0",
				title:            "Title",
				reportedAt:       "2023-01-01",
			},
			[]string{"2023-01-01", "Reported At"},
			nil,
		},
		{
			"composerRepository_included",
			advisory{
				id:                 "ADV-008",
				packageName:        "a/b",
				affectedVersions:   "<1.0",
				title:              "Title",
				composerRepository: "https://repo.example.com",
			},
			[]string{"https://repo.example.com", "Composer Repository"},
			nil,
		},
		{
			"sources_included",
			advisory{
				id:               "ADV-009",
				packageName:      "a/b",
				affectedVersions: "<1.0",
				title:            "Title",
				sources:          []advisorySource{{name: "GitHub", remoteID: "GHSA-0001"}},
			},
			[]string{"GHSA-0001", "GitHub", "Source"},
			nil,
		},
		{
			"WPSEC_title_newlines_replaced",
			advisory{
				id:               "WPSECADV/WF/001",
				packageName:      "wp/plugin",
				affectedVersions: "<1.0",
				title:            "Title\n### Section",
			},
			[]string{"Title\n\nSection"},
			nil,
		},
		{
			"non_WPSEC_title_newlines_preserved",
			advisory{
				id:               "ADV-010",
				packageName:      "a/b",
				affectedVersions: "<1.0",
				title:            "Line1\n### Section",
			},
			[]string{"Line1\n### Section"},
			nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.adv.help()
			for _, want := range tt.wantContains {
				if !strings.Contains(got, want) {
					t.Errorf("help() missing %q in:\n%s", want, got)
				}
			}
			for _, absent := range tt.wantAbsent {
				if strings.Contains(got, absent) {
					t.Errorf("help() should not contain %q in:\n%s", absent, got)
				}
			}
		})
	}
}

func TestUnmarshalJSONObjectOrEmptyArray(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
		want map[string]string
	}{
		{"empty_object", `{}`, map[string]string{}},
		{"empty_array", `[]`, map[string]string{}},
		{"null", `null`, nil},
		{"empty_bytes_nil_result", ``, nil},
		{"whitespace_then_null", `  null  `, nil},
		{"object_with_entry", `{"a":"b"}`, map[string]string{"a": "b"}},
		{"object_multiple_entries", `{"x":"1","y":"2"}`, map[string]string{"x": "1", "y": "2"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var dst map[string]string
			err := unmarshalJSONObjectOrEmptyArray([]byte(tt.json), "field", &dst)
			if err != nil {
				t.Fatalf("unmarshalJSONObjectOrEmptyArray() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, dst); diff != "" {
				t.Errorf("unmarshalJSONObjectOrEmptyArray() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestUnmarshalJSONObjectOrEmptyArray_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
	}{
		{"non_empty_array", `["x"]`},
		{"invalid_json", `not json`},
		{"number", `42`},
		{"boolean", `true`},
		{"string_literal", `"hello"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var dst map[string]string
			err := unmarshalJSONObjectOrEmptyArray([]byte(tt.json), "field", &dst)
			if err == nil {
				t.Errorf("unmarshalJSONObjectOrEmptyArray() unexpected success")
			}
		})
	}
}

func TestRawAdvisories_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
		want rawAdvisories
	}{
		{"empty_object", `{}`, rawAdvisories{}},
		{"empty_array", `[]`, rawAdvisories{}},
		{"null", `null`, nil},
		{"whitespace_then_null", `  null  `, nil},
		{"object_with_single_package_no_advisories", `{"vendor/pkg":[]}`, rawAdvisories{"vendor/pkg": {}}},
		{
			"object_with_single_advisory",
			`{"vendor/pkg":[{"advisoryId":"ADV-001","packageName":"vendor/pkg","affectedVersions":">=1.0"}]}`,
			rawAdvisories{"vendor/pkg": {{AdvisoryID: new("ADV-001"), PackageName: new("vendor/pkg"), AffectedVersions: new(">=1.0")}}},
		},
		{"object_multiple_packages", `{"a/b":[],"c/d":[]}`, rawAdvisories{"a/b": {}, "c/d": {}}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got rawAdvisories
			err := got.UnmarshalJSON([]byte(tt.json))
			if err != nil {
				t.Fatalf("UnmarshalJSON() unexpected error: %v", err)
			}
			if diff := cmp.Diff(map[string][]rawAdvisory(tt.want), map[string][]rawAdvisory(got)); diff != "" {
				t.Errorf("UnmarshalJSON() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRawAdvisories_UnmarshalJSON_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
	}{
		{"non_empty_array", `["x"]`},
		{"invalid_json", `not json`},
		{"plain_number", `42`},
		{"boolean", `true`},
		{"string_literal", `"hello"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got rawAdvisories
			err := got.UnmarshalJSON([]byte(tt.json))
			if err == nil {
				t.Errorf("UnmarshalJSON() unexpected success")
			}
		})
	}
}

func TestRawAdvisories_Normalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawAdvs rawAdvisories
		want    []advisory
	}{
		{
			"empty_map",
			rawAdvisories{},
			nil,
		},
		{
			"single_package_no_advisories",
			rawAdvisories{"vendor/pkg": {}},
			nil,
		},
		{
			"valid_single_advisory",
			rawAdvisories{
				"vendor/pkg": {{
					AdvisoryID:       new("ADV-001"),
					PackageName:      new("vendor/pkg"),
					AffectedVersions: new(">=1.0"),
					Title:            new("Test"),
				}},
			},
			[]advisory{{
				id:               "ADV-001",
				packageName:      "vendor/pkg",
				affectedVersions: ">=1.0",
				title:            "Test",
				sources:          []advisorySource{},
			}},
		},
		{
			"multiple_packages_multiple_advisories",
			rawAdvisories{
				"a/b": {{AdvisoryID: new("ADV-A1"), PackageName: new("a/b"), AffectedVersions: new("<1.0")}},
				"c/d": {{AdvisoryID: new("ADV-C1"), PackageName: new("c/d"), AffectedVersions: new("<2.0")}},
			},
			[]advisory{
				{id: "ADV-A1", packageName: "a/b", affectedVersions: "<1.0", sources: []advisorySource{}},
				{id: "ADV-C1", packageName: "c/d", affectedVersions: "<2.0", sources: []advisorySource{}},
			},
		},
		{
			"whitespace_fields_normalized",
			rawAdvisories{
				"p/q": {{
					AdvisoryID:       new("  ADV-999  "),
					PackageName:      new("  p/q  "),
					AffectedVersions: new("  <3.0  "),
				}},
			},
			[]advisory{{id: "ADV-999", packageName: "p/q", affectedVersions: "<3.0", sources: []advisorySource{}}},
		},
		{
			"advisory_with_severity",
			rawAdvisories{
				"x/y": {{
					AdvisoryID:       new("ADV-SEV"),
					PackageName:      new("x/y"),
					AffectedVersions: new("<1.0"),
					Severity:         new("high"),
				}},
			},
			[]advisory{{id: "ADV-SEV", packageName: "x/y", affectedVersions: "<1.0", severity: severityHigh, sources: []advisorySource{}}},
		},
		{
			"advisory_with_source_included",
			rawAdvisories{
				"a/b": {{
					AdvisoryID:       new("ADV-SRC"),
					PackageName:      new("a/b"),
					AffectedVersions: new("<1.0"),
					Sources:          []rawAdvisorySource{{Name: new("GitHub"), RemoteID: new("GHSA-001")}},
				}},
			},
			[]advisory{{
				id:               "ADV-SRC",
				packageName:      "a/b",
				affectedVersions: "<1.0",
				sources:          []advisorySource{{name: "GitHub", remoteID: "GHSA-001"}},
			}},
		},
		{
			"multiple_advisories_same_package",
			rawAdvisories{
				"a/b": {
					{AdvisoryID: new("ADV-1"), PackageName: new("a/b"), AffectedVersions: new("<1.0")},
					{AdvisoryID: new("ADV-2"), PackageName: new("a/b"), AffectedVersions: new("<2.0")},
				},
			},
			[]advisory{
				{id: "ADV-1", packageName: "a/b", affectedVersions: "<1.0", sources: []advisorySource{}},
				{id: "ADV-2", packageName: "a/b", affectedVersions: "<2.0", sources: []advisorySource{}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.rawAdvs.normalize()
			if err != nil {
				t.Fatalf("normalize() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(advisory{}, advisorySource{}), cmpopts.SortSlices(func(a, b advisory) bool { return a.id < b.id })); diff != "" {
				t.Errorf("normalize() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRawAdvisories_Normalize_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		rawAdvs rawAdvisories
	}{
		{
			"missing_id_nil",
			rawAdvisories{
				"vendor/pkg": {{AdvisoryID: nil, PackageName: new("vendor/pkg"), AffectedVersions: new(">=1.0")}},
			},
		},
		{
			"missing_id_empty",
			rawAdvisories{
				"vendor/pkg": {{AdvisoryID: new(""), PackageName: new("vendor/pkg"), AffectedVersions: new(">=1.0")}},
			},
		},
		{
			"missing_package_name",
			rawAdvisories{
				"a/b": {{AdvisoryID: new("ADV-001"), PackageName: nil, AffectedVersions: new("<1.0")}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ra := tt.rawAdvs
			_, err := ra.normalize()
			if err == nil {
				t.Error("normalize() unexpected success")
			}
		})
	}
}

func TestRawAdvisories_Normalize_NilReceiver(t *testing.T) {
	t.Parallel()
	var ra *rawAdvisories
	got, err := ra.normalize()
	if err != nil {
		t.Fatalf("normalize() unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("normalize() = %v, want nil", got)
	}
}

func TestRawAdvisory_Normalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		rawAdv rawAdvisory
		want   advisory
	}{
		{
			"minimal_required_fields",
			rawAdvisory{
				AdvisoryID:       new("ADV-001"),
				PackageName:      new("vendor/pkg"),
				AffectedVersions: new(">=1.0"),
			},
			advisory{
				id:               "ADV-001",
				packageName:      "vendor/pkg",
				affectedVersions: ">=1.0",
				sources:          []advisorySource{},
			},
		},
		{
			"all_fields_set",
			rawAdvisory{
				AdvisoryID:         new("ADV-002"),
				PackageName:        new("a/b"),
				AffectedVersions:   new("<2.0"),
				Title:              new("A Title"),
				CVE:                new("CVE-2023-1234"),
				Link:               new("https://example.com"),
				ReportedAt:         new("2023-01-01"),
				Severity:           new("high"),
				ComposerRepository: new("https://repo.example.com"),
			},
			advisory{
				id:                 "ADV-002",
				packageName:        "a/b",
				affectedVersions:   "<2.0",
				title:              "A Title",
				cve:                "CVE-2023-1234",
				link:               "https://example.com",
				reportedAt:         "2023-01-01",
				severity:           severityHigh,
				composerRepository: "https://repo.example.com",
				sources:            []advisorySource{},
			},
		},
		{
			"whitespace_trimmed",
			rawAdvisory{
				AdvisoryID:       new("  ADV-003  "),
				PackageName:      new("  c/d  "),
				AffectedVersions: new("  <1.0  "),
			},
			advisory{
				id:               "ADV-003",
				packageName:      "c/d",
				affectedVersions: "<1.0",
				sources:          []advisorySource{},
			},
		},
		{
			"source_with_remoteID_included",
			rawAdvisory{
				AdvisoryID:       new("ADV-004"),
				PackageName:      new("p/q"),
				AffectedVersions: new("<1.0"),
				Sources:          []rawAdvisorySource{{RemoteID: new("GHSA-001"), Name: new("GitHub")}},
			},
			advisory{
				id:               "ADV-004",
				packageName:      "p/q",
				affectedVersions: "<1.0",
				sources:          []advisorySource{{remoteID: "GHSA-001", name: "GitHub"}},
			},
		},
		{
			"source_without_remoteID_skipped",
			rawAdvisory{
				AdvisoryID:       new("ADV-005"),
				PackageName:      new("p/q"),
				AffectedVersions: new("<1.0"),
				Sources:          []rawAdvisorySource{{RemoteID: nil, Name: new("GitHub")}},
			},
			advisory{
				id:               "ADV-005",
				packageName:      "p/q",
				affectedVersions: "<1.0",
				sources:          []advisorySource{},
			},
		},
		{
			"severity_normalized",
			rawAdvisory{
				AdvisoryID:       new("ADV-006"),
				PackageName:      new("p/q"),
				AffectedVersions: new("<1.0"),
				Severity:         new("CRITICAL"),
			},
			advisory{
				id:               "ADV-006",
				packageName:      "p/q",
				affectedVersions: "<1.0",
				severity:         severityCritical,
				sources:          []advisorySource{},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.rawAdv.normalize()
			if err != nil {
				t.Fatalf("normalize() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(advisory{}, advisorySource{})); diff != "" {
				t.Errorf("normalize() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRawAdvisory_Normalize_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		rawAdv rawAdvisory
	}{
		{
			"missing_advisory_id_nil",
			rawAdvisory{
				AdvisoryID:       nil,
				PackageName:      new("a/b"),
				AffectedVersions: new("<1.0"),
			},
		},
		{
			"missing_advisory_id_empty",
			rawAdvisory{
				AdvisoryID:       new(""),
				PackageName:      new("a/b"),
				AffectedVersions: new("<1.0"),
			},
		},
		{
			"missing_advisory_id_whitespace_only",
			rawAdvisory{
				AdvisoryID:       new("   "),
				PackageName:      new("a/b"),
				AffectedVersions: new("<1.0"),
			},
		},
		{
			"missing_package_name_nil",
			rawAdvisory{
				AdvisoryID:       new("ADV-001"),
				PackageName:      nil,
				AffectedVersions: new("<1.0"),
			},
		},
		{
			"missing_package_name_empty",
			rawAdvisory{
				AdvisoryID:       new("ADV-001"),
				PackageName:      new(""),
				AffectedVersions: new("<1.0"),
			},
		},
		{
			"missing_affected_versions_nil",
			rawAdvisory{
				AdvisoryID:       new("ADV-001"),
				PackageName:      new("a/b"),
				AffectedVersions: nil,
			},
		},
		{
			"missing_affected_versions_empty",
			rawAdvisory{
				AdvisoryID:       new("ADV-001"),
				PackageName:      new("a/b"),
				AffectedVersions: new(""),
			},
		},
		{
			"missing_affected_versions_whitespace",
			rawAdvisory{
				AdvisoryID:       new("ADV-001"),
				PackageName:      new("a/b"),
				AffectedVersions: new("  "),
			},
		},
		{
			"all_required_fields_nil",
			rawAdvisory{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := tt.rawAdv.normalize()
			if err == nil {
				t.Error("normalize() unexpected success")
			}
		})
	}
}

func TestRawAdvisorySource_Normalize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rawAdvSrc rawAdvisorySource
		want      advisorySource
	}{
		{
			"both_set",
			rawAdvisorySource{Name: new("GitHub"), RemoteID: new("GHSA-001")},
			advisorySource{name: "GitHub", remoteID: "GHSA-001"},
		},
		{
			"name_nil",
			rawAdvisorySource{Name: nil, RemoteID: new("GHSA-002")},
			advisorySource{name: "", remoteID: "GHSA-002"},
		},
		{
			"name_empty",
			rawAdvisorySource{Name: new(""), RemoteID: new("GHSA-003")},
			advisorySource{name: "", remoteID: "GHSA-003"},
		},
		{
			"name_whitespace_trimmed",
			rawAdvisorySource{Name: new("  GitHub  "), RemoteID: new("GHSA-004")},
			advisorySource{name: "GitHub", remoteID: "GHSA-004"},
		},
		{
			"remoteID_whitespace_trimmed",
			rawAdvisorySource{Name: new("GitHub"), RemoteID: new("  GHSA-005  ")},
			advisorySource{name: "GitHub", remoteID: "GHSA-005"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.rawAdvSrc.normalize()
			if err != nil {
				t.Fatalf("normalize() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(advisorySource{})); diff != "" {
				t.Errorf("normalize() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRawAdvisorySource_Normalize_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		rawAdvSrc rawAdvisorySource
	}{
		{"remoteID_nil", rawAdvisorySource{Name: new("GitHub"), RemoteID: nil}},
		{"remoteID_empty_string", rawAdvisorySource{Name: new("GitHub"), RemoteID: new("")}},
		{"remoteID_whitespace_only", rawAdvisorySource{Name: new("GitHub"), RemoteID: new("   ")}},
		{"both_nil", rawAdvisorySource{Name: nil, RemoteID: nil}},
		{"both_empty", rawAdvisorySource{Name: new(""), RemoteID: new("")}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := tt.rawAdvSrc.normalize()
			if err == nil {
				t.Error("normalize() unexpected success")
			}
		})
	}
}

func TestRawAbandonments_UnmarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
		want rawAbandonments
	}{
		{"empty_object", `{}`, rawAbandonments{}},
		{"empty_array", `[]`, rawAbandonments{}},
		{"null", `null`, nil},
		{"with_entry", `{"vendor/old":"vendor/new"}`, rawAbandonments{"vendor/old": new("vendor/new")}},
		{"with_null_replacement", `{"vendor/old":null}`, rawAbandonments{"vendor/old": nil}},
		{"multiple_entries", `{"a/b":"c/d","e/f":"g/h"}`, rawAbandonments{"a/b": new("c/d"), "e/f": new("g/h")}},
		{"whitespace_then_null", `  null  `, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got rawAbandonments
			err := got.UnmarshalJSON([]byte(tt.json))
			if err != nil {
				t.Fatalf("UnmarshalJSON() unexpected error: %v", err)
			}
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("UnmarshalJSON() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRawAbandonments_UnmarshalJSON_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
	}{
		{"non_empty_array", `["x"]`},
		{"invalid_json", `not json`},
		{"number", `42`},
		{"boolean", `true`},
		{"string_literal", `"hello"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var got rawAbandonments
			err := got.UnmarshalJSON([]byte(tt.json))
			if err == nil {
				t.Errorf("UnmarshalJSON() unexpected success")
			}
		})
	}
}

func TestRawAbandonments_Normalize(t *testing.T) {
	t.Parallel()

	sortByPkg := cmpopts.SortSlices(func(a, b abandonment) bool {
		return a.packageName < b.packageName
	})

	tests := []struct {
		name   string
		rawAbs rawAbandonments
		want   []abandonment
	}{
		{
			"empty_map",
			rawAbandonments{},
			[]abandonment{},
		},
		{
			"single_entry_with_replacement",
			rawAbandonments{"vendor/old": new("vendor/new")},
			[]abandonment{{packageName: "vendor/old", replacement: "vendor/new"}},
		},
		{
			"single_entry_nil_replacement",
			rawAbandonments{"vendor/old": nil},
			[]abandonment{{packageName: "vendor/old", replacement: ""}},
		},
		{
			"whitespace_package_name_skipped",
			rawAbandonments{"   ": new("vendor/new")},
			[]abandonment{},
		},
		{
			"replacement_whitespace_trimmed",
			rawAbandonments{"vendor/old": new("  vendor/new  ")},
			[]abandonment{{packageName: "vendor/old", replacement: "vendor/new"}},
		},
		{
			"multiple_entries",
			rawAbandonments{"a/b": new("c/d"), "e/f": new("g/h"), "i/j": nil},
			[]abandonment{
				{packageName: "a/b", replacement: "c/d"},
				{packageName: "e/f", replacement: "g/h"},
				{packageName: "i/j", replacement: ""},
			},
		},
		{
			"empty_package_name_skipped",
			rawAbandonments{"": new("vendor/new")},
			[]abandonment{},
		},
		{
			"unicode_package_name",
			rawAbandonments{"漢字/pkg": new("new/pkg")},
			[]abandonment{{packageName: "漢字/pkg", replacement: "new/pkg"}},
		},
		{
			"replacement_empty_string",
			rawAbandonments{"vendor/old": new("")},
			[]abandonment{{packageName: "vendor/old", replacement: ""}},
		},
		{
			"package_name_trimmed",
			rawAbandonments{"vendor/old": new("new/pkg")},
			[]abandonment{{packageName: "vendor/old", replacement: "new/pkg"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ra := tt.rawAbs
			got := ra.normalize()
			if diff := cmp.Diff(tt.want, got, cmp.AllowUnexported(abandonment{}), sortByPkg); diff != "" {
				t.Errorf("normalize() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestRawAbandonments_Normalize_NilReceiver(t *testing.T) {
	t.Parallel()
	var ra *rawAbandonments
	got := ra.normalize()
	if got != nil {
		t.Errorf("normalize() = %v, want nil", got)
	}
}

func TestNewAudit(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name            string
		json            string
		wantAdvisoryLen int
		wantAbandonLen  int
	}{
		{
			"empty_advisories_and_abandoned_as_objects",
			`{"advisories":{},"ignored-advisories":{},"abandoned":{}}`,
			0,
			0,
		},
		{
			"empty_advisories_and_abandoned_as_arrays",
			`{"advisories":[],"ignored-advisories":[],"abandoned":[]}`,
			0,
			0,
		},
		{
			"null_fields",
			`{"advisories":null,"ignored-advisories":null,"abandoned":null}`,
			0,
			0,
		},
		{
			"single_advisory",
			`{
					"advisories":{
						"vendor/pkg":[{
							"advisoryId":"ADV-001",
							"packageName":"vendor/pkg",
							"affectedVersions":">=1.0"
						}]
					},
					"ignored-advisories":{},
					"abandoned":{}
				}`,
			1,
			0,
		},
		{
			"advisory_and_ignored_advisory_both_included",
			`{
					"advisories":{
						"a/b":[{"advisoryId":"ADV-A","packageName":"a/b","affectedVersions":"<1.0"}]
					},
					"ignored-advisories":{
						"c/d":[{"advisoryId":"ADV-C","packageName":"c/d","affectedVersions":"<2.0"}]
					},
					"abandoned":{}
				}`,
			2,
			0,
		},
		{
			"abandoned_entry",
			`{
					"advisories":{},
					"ignored-advisories":{},
					"abandoned":{"vendor/old":"vendor/new"}
				}`,
			0,
			1,
		},
		{
			"abandoned_null_replacement",
			`{
					"advisories":{},
					"ignored-advisories":{},
					"abandoned":{"vendor/old":null}
				}`,
			0,
			1,
		},
		{
			"mixed_advisories_and_abandonments",
			`{
					"advisories":{
						"a/b":[{"advisoryId":"ADV-001","packageName":"a/b","affectedVersions":"<1.0"}]
					},
					"ignored-advisories":{},
					"abandoned":{"c/d":"e/f"}
				}`,
			1,
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := newAudit(strings.NewReader(tt.json))
			if err != nil {
				t.Fatalf("newAudit() unexpected error: %v", err)
			}
			if len(got.advisories) != tt.wantAdvisoryLen {
				t.Errorf("newAudit() advisories = %d, want %d", len(got.advisories), tt.wantAdvisoryLen)
			}
			if len(got.abandonments) != tt.wantAbandonLen {
				t.Errorf("newAudit() abandonments = %d, want %d", len(got.abandonments), tt.wantAbandonLen)
			}
		})
	}
}

func TestNewAudit_Error(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		json string
	}{
		{"empty_input", ``},
		{"invalid_json", `not json`},
		{"advisory_missing_id", `{"advisories":{"a/b":[{"packageName":"a/b","affectedVersions":"<1.0"}]},"ignored-advisories":{},"abandoned":{}}`},
		{"advisory_missing_package", `{"advisories":{"a/b":[{"advisoryId":"ADV","affectedVersions":"<1.0"}]},"ignored-advisories":{},"abandoned":{}}`},
		{"advisory_missing_affected_versions", `{"advisories":{"a/b":[{"advisoryId":"ADV","packageName":"a/b"}]},"ignored-advisories":{},"abandoned":{}}`},
		{"advisories_non_empty_array", `{"advisories":["x"],"ignored-advisories":{},"abandoned":{}}`},
		{"ignored_advisories_non_empty_array", `{"advisories":{},"ignored-advisories":["x"],"abandoned":{}}`},
		{"abandoned_non_empty_array", `{"advisories":{},"ignored-advisories":{},"abandoned":["x"]}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			_, err := newAudit(strings.NewReader(tt.json))
			if err == nil {
				t.Errorf("newAudit() unexpected success")
			}
		})
	}
}
