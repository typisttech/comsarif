package comsarif

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildReport(t *testing.T) {
	const composerLock = "{\n" +
		"  \"packages\": [\n" +
		"    {\n" +
		"      \"name\": \"abandoned/no-replacement\",\n" +
		"      \"version\": \"0.1.0\"\n" +
		"    },\n" +
		"    {\n" +
		"      \"name\": \"vendor/a\",\n" +
		"      \"version\": \"1.0.0\"\n" +
		"    },\n" +
		"    {\n" +
		"      \"name\": \"vendor/b\",\n" +
		"      \"version\": \"2.0.0\"\n" +
		"    }\n" +
		"  ],\n" +
		"  \"packages-dev\": [\n" +
		"    {\n" +
		"      \"name\": \"abandoned/with-replacement\",\n" +
		"      \"version\": \"3.0.0\"\n" +
		"    },\n" +
		"    {\n" +
		"      \"name\": \"vendor/ignored\",\n" +
		"      \"version\": \"4.0.0\"\n" +
		"    }\n" +
		"  ]\n" +
		"}"

	longName := strings.Repeat("界", 300)
	longDesc := strings.Repeat("語", 1100)

	tests := []struct {
		name          string
		auditJSON     string
		lockURI       string
		check         func(t *testing.T, report map[string]any, raw []byte)
		wantErr       string
		checkRepeatEq bool
	}{
		{
			name: "advisory title cve severity sources and abandoned results",
			auditJSON: `{
				"advisories": {
					"vendor/a": [{
						"advisoryId": "GHSA-a",
						"packageName": "vendor/a",
						"affectedVersions": "<1.0.1",
						"title": "Package A issue",
						"cve": "CVE-2026-0001",
						"link": "https://example.test/a",
						"reportedAt": "2026-05-06T00:00:00Z",
						"severity": "high",
						"composerRepository": "packagist",
						"sources": [
							{"name": "FriendsOfPHP", "remoteId": "100"},
							{"remoteId": "remote-only"}
						]
					}]
				},
				"ignored-advisories": {
					"vendor/ignored": [{
						"advisoryId": "GHSA-ignored",
						"packageName": "vendor/ignored",
						"affectedVersions": "<4.0.1",
						"title": "Ignored issue",
						"severity": "critical",
						"ignoreReason": "accepted risk"
					}]
				},
				"abandoned": {
					"abandoned/no-replacement": null,
					"abandoned/with-replacement": "new/pkg"
				}
			}`,
			lockURI:       "composer.lock",
			checkRepeatEq: true,
			check: func(t *testing.T, report map[string]any, raw []byte) {
				run := firstRun(t, report)
				assertString(t, report, "$schema", "https://json.schemastore.org/sarif-2.1.0.json")
				assertString(t, report, "version", "2.1.0")

				tool := mustMap(t, run["tool"])
				driver := mustMap(t, tool["driver"])
				assertString(t, driver, "name", "composer")
				rules := mustSlice(t, driver["rules"])
				if len(rules) != 3 {
					t.Fatalf("len(driver.rules) = %d, want 3", len(rules))
				}

				extensions := mustSlice(t, tool["extensions"])
				if len(extensions) != 1 {
					t.Fatalf("len(tool.extensions) = %d, want 1", len(extensions))
				}
				extension := mustMap(t, extensions[0])
				assertString(t, extension, "name", "comsarif")
				if extRules := mustSlice(t, extension["rules"]); len(extRules) != 0 {
					t.Fatalf("len(extension.rules) = %d, want 0", len(extRules))
				}

				invocations := mustSlice(t, run["invocations"])
				if len(invocations) != 1 {
					t.Fatalf("len(invocations) = %d, want 1", len(invocations))
				}
				invocation := mustMap(t, invocations[0])
				workingDirectory := mustMap(t, invocation["workingDirectory"])
				assertString(t, workingDirectory, "uri", "file:///repo")

				results := mustSlice(t, run["results"])
				if len(results) != 4 {
					t.Fatalf("len(results) = %d, want 4", len(results))
				}

				rule0 := mustMap(t, rules[0])
				assertString(t, rule0, "id", hashStable("advisory", "GHSA-a", "vendor/a"))
				assertString(t, rule0, "name", "CVE-2026-0001")
				assertString(t, mustMap(t, rule0["shortDescription"]), "text", "Package A issue")
				assertString(t, mustMap(t, rule0["fullDescription"]), "text", "Package A issue")
				assertString(t, mustMap(t, rule0["help"]), "text", "Upgrade to patched versions or remove the package.")
				props0 := mustMap(t, rule0["properties"])
				assertString(t, mustMap(t, props0["problem"]), "severity", "error")
				assertString(t, props0, "security-severity", "7.0")
				assertTags(t, props0["tags"], []string{"composer", "dependency", "security"})
				assertString(t, props0, "precision", "very-high")
				assertAbsent(t, rule0, "defaultConfiguration")

				rule1 := mustMap(t, rules[1])
				assertString(t, rule1, "id", hashStable("advisory", "GHSA-ignored", "vendor/ignored"))
				assertString(t, mustMap(t, mustMap(t, rule1["properties"])["problem"]), "severity", "warning")
				assertString(t, mustMap(t, rule1["properties"]), "security-severity", "9.0")

				rule2 := mustMap(t, rules[2])
				assertString(t, rule2, "id", "abandoned")
				assertString(t, rule2, "name", "Composer audit (abandoned)")
				assertString(t, mustMap(t, rule2["defaultConfiguration"]), "level", "note")
				assertTags(t, mustMap(t, rule2["properties"])["tags"], []string{"composer", "dependency"})

				result0 := mustMap(t, results[0])
				assertString(t, result0, "ruleId", hashStable("advisory", "GHSA-a", "vendor/a"))
				assertString(t, mustMap(t, mustMap(t, result0["partialFingerprints"])), "primaryLocationLineHash", hashStable("GHSA-a", "vendor/a"))
				message0 := mustMap(t, result0["message"])
				text0 := stringField(t, message0, "text")
				for _, want := range []string{
					"Package A issue",
					"advisoryId: GHSA-a",
					"packageName: vendor/a",
					"affectedVersions: <1.0.1",
					"cve: CVE-2026-0001",
					"link: https://example.test/a",
					"reportedAt: 2026-05-06T00:00:00Z",
					"severity: high",
					"composerRepository: packagist",
					"sources:\n  FriendsOfPHP: 100\n  remote-only",
				} {
					if !strings.Contains(text0, want) {
						t.Fatalf("result message missing %q in %q", want, text0)
					}
				}

				physical0 := firstPhysicalLocation(t, result0)
				assertString(t, mustMap(t, physical0["artifactLocation"]), "uri", "composer.lock")
				region0 := mustMap(t, physical0["region"])
				assertNumber(t, region0, "startLine", 9)
				assertNumber(t, region0, "startColumn", 7)
				assertNumber(t, region0, "endLine", 9)
				assertNumber(t, region0, "endColumn", 25)

				result2 := mustMap(t, results[2])
				assertString(t, result2, "ruleId", "abandoned")
				assertString(t, mustMap(t, result2["message"]), "text", "Package abandoned/no-replacement is abandoned, you should avoid using it.\nNo replacement was suggested.")

				result3 := mustMap(t, results[3])
				assertString(t, result3, "ruleId", "abandoned")
				assertString(t, mustMap(t, result3["message"]), "text", "Package abandoned/with-replacement is abandoned, you should avoid using it.\nUse new/pkg instead.")

				if strings.Contains(string(raw), "null") {
					t.Fatalf("report unexpectedly contains null: %s", raw)
				}
				for _, unwanted := range []string{"automationDetails", "columnKind", "defaultSourceLanguage", "taxa"} {
					if strings.Contains(string(raw), unwanted) {
						t.Fatalf("report unexpectedly contains %q: %s", unwanted, raw)
					}
				}
			},
		},
		{
			name: "fallbacks truncation relative uri and deterministic ordering",
			auditJSON: `{
				"advisories": {
					"vendor/a": [{
						"advisoryId": "GHSA-z",
						"packageName": "vendor/a",
						"affectedVersions": "<1.0.1",
						"title": "` + longDesc + `",
						"severity": "unknown"
					}],
					"vendor/b": [{
						"advisoryId": "GHSA-b",
						"packageName": "vendor/b",
						"affectedVersions": "<2.0.1",
						"cve": "CVE-2026-0002"
					}],
					"vendor/ignored": [{
						"advisoryId": "GHSA-c",
						"packageName": "vendor/ignored",
						"affectedVersions": "<4.0.1",
						"title": "\n\n` + longName + `"
					}]
				}
			}`,
			lockURI: "subdir/composer.lock",
			check: func(t *testing.T, report map[string]any, _ []byte) {
				run := firstRun(t, report)
				rules := mustSlice(t, mustMap(t, mustMap(t, run["tool"])["driver"])["rules"])
				results := mustSlice(t, run["results"])
				if len(rules) != 3 || len(results) != 3 {
					t.Fatalf("len(rules) = %d len(results) = %d, want 3/3", len(rules), len(results))
				}

				rule0 := mustMap(t, rules[0])
				assertString(t, rule0, "id", hashStable("advisory", "GHSA-z", "vendor/a"))
				short0 := stringField(t, mustMap(t, rule0["shortDescription"]), "text")
				if got := len([]rune(short0)); got != 1024 {
					t.Fatalf("len(shortDescription) = %d, want 1024", got)
				}
				assertAbsent(t, mustMap(t, rule0["properties"]), "security-severity")

				rule1 := mustMap(t, rules[1])
				assertString(t, rule1, "name", "CVE-2026-0002")
				assertString(t, mustMap(t, rule1["shortDescription"]), "text", "Package vendor/b is vulnerable to CVE-2026-0002.")

				rule2 := mustMap(t, rules[2])
				if got := len([]rune(stringField(t, rule2, "name"))); got != 255 {
					t.Fatalf("len(rule.name) = %d, want 255", got)
				}
				assertString(t, mustMap(t, rule2["shortDescription"]), "text", truncateRunes(longName, 1024))

				result0 := mustMap(t, results[0])
				assertString(t, mustMap(t, firstPhysicalLocation(t, result0)["artifactLocation"]), "uri", "subdir/composer.lock")
				assertString(t, mustMap(t, result0["message"]), "text", truncateRunes(longDesc, len([]rune(longDesc)))+"\n\nadvisoryId: GHSA-z\npackageName: vendor/a\naffectedVersions: <1.0.1\nseverity: unknown")

				result1 := mustMap(t, results[1])
				if got := stringField(t, mustMap(t, result1["message"]), "text"); !strings.HasPrefix(got, "Package vendor/b is vulnerable to CVE-2026-0002.") {
					t.Fatalf("result1 summary = %q, want cve fallback", got)
				}

				result2 := mustMap(t, results[2])
				if got := stringField(t, mustMap(t, result2["message"]), "text"); !strings.HasPrefix(got, longName) {
					t.Fatalf("result2 summary = %q, want title fallback", got)
				}
			},
		},
		{
			name:      "empty input emits empty rule and result arrays",
			auditJSON: `{"advisories": {}, "ignored-advisories": {}, "abandoned": {}}`,
			lockURI:   "composer.lock",
			check: func(t *testing.T, report map[string]any, _ []byte) {
				run := firstRun(t, report)
				rules := mustSlice(t, mustMap(t, mustMap(t, run["tool"])["driver"])["rules"])
				results := mustSlice(t, run["results"])
				if len(rules) != 0 {
					t.Fatalf("len(rules) = %d, want 0", len(rules))
				}
				if len(results) != 0 {
					t.Fatalf("len(results) = %d, want 0", len(results))
				}
			},
		},
		{
			name: "duplicate advisory ids rejected",
			auditJSON: `{
				"advisories": {
					"vendor/a": [{
						"advisoryId": "GHSA-dup",
						"packageName": "vendor/a",
						"affectedVersions": "<1"
					}]
				},
				"ignored-advisories": {
					"vendor/a": [{
						"advisoryId": "GHSA-dup",
						"packageName": "vendor/a",
						"affectedVersions": "<1"
					}]
				}
			}`,
			lockURI: "composer.lock",
			wantErr: "duplicate advisory identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw, err := BuildReport([]byte(tt.auditJSON), []byte(composerLock), BuildOptions{
				RootURI: "file:///repo",
				LockURI: tt.lockURI,
			})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("BuildReport() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("BuildReport() error = %v", err)
			}

			if tt.checkRepeatEq {
				raw2, err := BuildReport([]byte(tt.auditJSON), []byte(composerLock), BuildOptions{
					RootURI: "file:///repo",
					LockURI: tt.lockURI,
				})
				if err != nil {
					t.Fatalf("second BuildReport() error = %v", err)
				}
				if string(raw) != string(raw2) {
					t.Fatalf("repeated BuildReport() output differs\nfirst:  %s\nsecond: %s", raw, raw2)
				}
			}

			var report map[string]any
			if err := json.Unmarshal(raw, &report); err != nil {
				t.Fatalf("json.Unmarshal(report) error = %v\nreport: %s", err, raw)
			}

			tt.check(t, report, raw)
		})
	}
}

func TestSARIFHelpers(t *testing.T) {
	tests := []struct {
		name string
		fn   func(t *testing.T)
	}{
		{
			name: "first non empty line",
			fn: func(t *testing.T) {
				if got := firstNonEmptyLine("\n  \n first \nsecond"); got != "first" {
					t.Fatalf("firstNonEmptyLine() = %q, want %q", got, "first")
				}
			},
		},
		{
			name: "truncate runes",
			fn: func(t *testing.T) {
				if got := truncateRunes("界界界", 2); got != "界界" {
					t.Fatalf("truncateRunes() = %q, want %q", got, "界界")
				}
			},
		},
		{
			name: "security severity mapping",
			fn: func(t *testing.T) {
				want := map[string]string{"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "0.1"}
				for input, expected := range want {
					got, ok := securitySeverityFor(input)
					if !ok || got != expected {
						t.Fatalf("securitySeverityFor(%q) = %q, %v want %q, true", input, got, ok, expected)
					}
				}
				if got, ok := securitySeverityFor("unknown"); ok || got != "" {
					t.Fatalf("securitySeverityFor(unknown) = %q, %v want empty, false", got, ok)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, tt.fn)
	}
}

func firstRun(t *testing.T, report map[string]any) map[string]any {
	t.Helper()
	runs := mustSlice(t, report["runs"])
	if len(runs) != 1 {
		t.Fatalf("len(runs) = %d, want 1", len(runs))
	}
	return mustMap(t, runs[0])
}

func firstPhysicalLocation(t *testing.T, result map[string]any) map[string]any {
	t.Helper()
	locations := mustSlice(t, result["locations"])
	if len(locations) != 1 {
		t.Fatalf("len(locations) = %d, want 1", len(locations))
	}
	return mustMap(t, mustMap(t, locations[0])["physicalLocation"])
}

func mustMap(t *testing.T, v any) map[string]any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("value %T is not map[string]any", v)
	}
	return m
}

func mustSlice(t *testing.T, v any) []any {
	t.Helper()
	s, ok := v.([]any)
	if !ok {
		t.Fatalf("value %T is not []any", v)
	}
	return s
}

func assertString(t *testing.T, m map[string]any, key, want string) {
	t.Helper()
	if got := stringField(t, m, key); got != want {
		t.Fatalf("%s = %q, want %q", key, got, want)
	}
}

func assertNumber(t *testing.T, m map[string]any, key string, want int) {
	t.Helper()
	got, ok := m[key].(float64)
	if !ok {
		t.Fatalf("%s is %T, want float64", key, m[key])
	}
	if int(got) != want {
		t.Fatalf("%s = %d, want %d", key, int(got), want)
	}
}

func assertAbsent(t *testing.T, m map[string]any, key string) {
	t.Helper()
	if _, ok := m[key]; ok {
		t.Fatalf("unexpected key %q in %#v", key, m)
	}
}

func assertTags(t *testing.T, v any, want []string) {
	t.Helper()
	items := mustSlice(t, v)
	if len(items) != len(want) {
		t.Fatalf("len(tags) = %d, want %d", len(items), len(want))
	}
	for i, wantItem := range want {
		got, ok := items[i].(string)
		if !ok || got != wantItem {
			t.Fatalf("tags[%d] = %v, want %q", i, items[i], wantItem)
		}
	}
}

func stringField(t *testing.T, m map[string]any, key string) string {
	t.Helper()
	got, ok := m[key].(string)
	if !ok {
		t.Fatalf("%s is %T, want string", key, m[key])
	}
	return got
}
