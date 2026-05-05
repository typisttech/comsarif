package comsarif

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseAuditJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    AuditDocument
		wantErr string
	}{
		{
			name: "advisory with title cve and normalized fields",
			input: `{
				"advisories": {
					"vendor/package": [
						{
							"advisoryId": " GHSA-123 ",
							"packageName": "vendor/package",
							"affectedVersions": " <1.2.3 ",
							"title": " Package issue ",
							"cve": " CVE-2026-0001 ",
							"link": " https://example.test/advisory ",
							"reportedAt": " 2026-05-05T00:00:00Z ",
							"severity": " HiGh ",
							"composerRepository": " packagist ",
							"sources": [
								{"name": " FriendsOfPHP ", "remoteId": " 123 "},
								{"name": "", "remoteId": "  "}
							]
						}
					]
				},
				"ignored-advisories": {},
				"abandoned": {
					"old/package": " replacement/package "
				}
			}`,
			want: AuditDocument{
				Advisories: map[string][]Advisory{
					"vendor/package": {
						{
							AdvisoryID:         "GHSA-123",
							PackageName:        "vendor/package",
							AffectedVersions:   "<1.2.3",
							Title:              "Package issue",
							CVE:                "CVE-2026-0001",
							Link:               "https://example.test/advisory",
							ReportedAt:         "2026-05-05T00:00:00Z",
							Severity:           "high",
							ComposerRepository: "packagist",
							Sources: []AdvisorySource{
								{Name: "FriendsOfPHP", RemoteID: "123"},
							},
						},
					},
				},
				IgnoredAdvisories: map[string][]Advisory{},
				Abandoned: map[string]string{
					"old/package": "replacement/package",
				},
			},
		},
		{
			name: "advisory with title but no cve",
			input: `{
				"advisories": {
					"vendor/package": [
						{
							"advisoryId": "GHSA-123",
							"packageName": "vendor/package",
							"affectedVersions": "<1.2.3",
							"title": "Package issue"
						}
					]
				}
			}`,
			want: AuditDocument{
				Advisories: map[string][]Advisory{
					"vendor/package": {
						{
							AdvisoryID:       "GHSA-123",
							PackageName:      "vendor/package",
							AffectedVersions: "<1.2.3",
							Title:            "Package issue",
						},
					},
				},
				IgnoredAdvisories: map[string][]Advisory{},
				Abandoned:         map[string]string{},
			},
		},
		{
			name: "null and empty optional strings omitted",
			input: `{
				"advisories": {
					"vendor/package": [
						{
							"advisoryId": "GHSA-123",
							"packageName": "vendor/package",
							"affectedVersions": "<1.2.3",
							"title": null,
							"cve": "   ",
							"link": "",
							"reportedAt": null,
							"severity": "  ",
							"ignoreReason": "",
							"composerRepository": null,
							"sources": [
								{"name": null, "remoteId": "  "}
							]
						}
					]
				},
				"abandoned": {
					"unused/package": null
				}
			}`,
			want: AuditDocument{
				Advisories: map[string][]Advisory{
					"vendor/package": {
						{
							AdvisoryID:       "GHSA-123",
							PackageName:      "vendor/package",
							AffectedVersions: "<1.2.3",
						},
					},
				},
				IgnoredAdvisories: map[string][]Advisory{},
				Abandoned: map[string]string{
					"unused/package": "",
				},
			},
		},
		{
			name: "missing advisoryId",
			input: `{
				"advisories": {
					"vendor/package": [{
						"packageName": "vendor/package",
						"affectedVersions": "<1.2.3"
					}]
				}
			}`,
			wantErr: "missing advisoryId",
		},
		{
			name: "missing packageName",
			input: `{
				"advisories": {
					"vendor/package": [{
						"advisoryId": "GHSA-123",
						"affectedVersions": "<1.2.3"
					}]
				}
			}`,
			wantErr: "missing packageName",
		},
		{
			name: "missing affectedVersions",
			input: `{
				"advisories": {
					"vendor/package": [{
						"advisoryId": "GHSA-123",
						"packageName": "vendor/package"
					}]
				}
			}`,
			wantErr: "missing affectedVersions",
		},
		{
			name: "mismatched packageName versus enclosing key",
			input: `{
				"advisories": {
					"vendor/package": [{
						"advisoryId": "GHSA-123",
						"packageName": "other/package",
						"affectedVersions": "<1.2.3"
					}]
				}
			}`,
			wantErr: "does not match enclosing key",
		},
		{
			name: "mixed-case severity normalization in ignored advisories",
			input: `{
				"ignored-advisories": {
					"vendor/package": [{
						"advisoryId": "GHSA-123",
						"packageName": "vendor/package",
						"affectedVersions": "<1.2.3",
						"severity": "CrItIcAl",
						"ignoreReason": " accepted risk "
					}]
				}
			}`,
			want: AuditDocument{
				Advisories: map[string][]Advisory{},
				IgnoredAdvisories: map[string][]Advisory{
					"vendor/package": {
						{
							AdvisoryID:       "GHSA-123",
							PackageName:      "vendor/package",
							AffectedVersions: "<1.2.3",
							Severity:         "critical",
							IgnoreReason:     "accepted risk",
						},
					},
				},
				Abandoned: map[string]string{},
			},
		},
		{
			name:  "empty advisories",
			input: `{"advisories": {}, "ignored-advisories": {}}`,
			want: AuditDocument{
				Advisories:        map[string][]Advisory{},
				IgnoredAdvisories: map[string][]Advisory{},
				Abandoned:         map[string]string{},
			},
		},
		{
			name:  "empty ignored advisories",
			input: `{"ignored-advisories": {}}`,
			want: AuditDocument{
				Advisories:        map[string][]Advisory{},
				IgnoredAdvisories: map[string][]Advisory{},
				Abandoned:         map[string]string{},
			},
		},
		{
			name: "duplicate advisory identity across collections",
			input: `{
				"advisories": {
					"vendor/package": [{
						"advisoryId": "GHSA-123",
						"packageName": "vendor/package",
						"affectedVersions": "<1.2.3"
					}]
				},
				"ignored-advisories": {
					"vendor/package": [{
						"advisoryId": "GHSA-123",
						"packageName": "vendor/package",
						"affectedVersions": "<1.2.3"
					}]
				}
			}`,
			wantErr: "duplicate advisory identity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseAuditJSON([]byte(tt.input))
			if tt.wantErr != "" {
				if err == nil || !contains(err.Error(), tt.wantErr) {
					t.Fatalf("parseAuditJSON() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseAuditJSON() error = %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("parseAuditJSON() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
