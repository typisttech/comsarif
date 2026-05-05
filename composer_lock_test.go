package comsarif

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseComposerLock(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		lockURI string
		want    composerLockIndex
		wantErr string
	}{
		{
			name:    "top-level packages match",
			lockURI: "composer.lock",
			input: "{\n" +
				"  \"packages\": [\n" +
				"    {\n" +
				"      \"name\": \"acme/pkg\",\n" +
				"      \"version\": \"1.2.3\"\n" +
				"    }\n" +
				"  ]\n" +
				"}",
			want: composerLockIndex{
				"acme/pkg": {
					PackageName: "acme/pkg",
					Version:     "1.2.3",
					URI:         "composer.lock",
					Region:      region{StartLine: 5, StartColumn: 7, EndLine: 5, EndColumn: 25},
				},
			},
		},
		{
			name:    "top-level packages-dev match",
			lockURI: "composer.lock",
			input: "{\n" +
				"  \"packages\": [],\n" +
				"  \"packages-dev\": [\n" +
				"    {\n" +
				"      \"name\": \"dev/pkg\",\n" +
				"      \"version\": \"2.0.0\"\n" +
				"    }\n" +
				"  ]\n" +
				"}",
			want: composerLockIndex{
				"dev/pkg": {
					PackageName: "dev/pkg",
					Version:     "2.0.0",
					URI:         "composer.lock",
					Region:      region{StartLine: 6, StartColumn: 7, EndLine: 6, EndColumn: 25},
				},
			},
		},
		{
			name:    "nested fake packages arrays ignored",
			lockURI: "composer.lock",
			input: "{\n" +
				"  \"packages\": [\n" +
				"    {\n" +
				"      \"name\": \"outer/pkg\",\n" +
				"      \"packages\": [{\n" +
				"        \"name\": \"fake/pkg\",\n" +
				"        \"version\": \"9.9.9\"\n" +
				"      }],\n" +
				"      \"version\": \"1.0.0\"\n" +
				"    }\n" +
				"  ],\n" +
				"  \"packages-dev\": [\n" +
				"    {\n" +
				"      \"name\": \"fake/pkg\",\n" +
				"      \"version\": \"2.0.0\"\n" +
				"    }\n" +
				"  ]\n" +
				"}",
			want: composerLockIndex{
				"outer/pkg": {
					PackageName: "outer/pkg",
					Version:     "1.0.0",
					URI:         "composer.lock",
					Region:      region{StartLine: 9, StartColumn: 7, EndLine: 9, EndColumn: 25},
				},
				"fake/pkg": {
					PackageName: "fake/pkg",
					Version:     "2.0.0",
					URI:         "composer.lock",
					Region:      region{StartLine: 15, StartColumn: 7, EndLine: 15, EndColumn: 25},
				},
			},
		},
		{
			name:    "malformed JSON rejected",
			lockURI: "composer.lock",
			input:   `{"packages": [`,
			wantErr: "parse composer.lock JSON",
		},
		{
			name:    "duplicate top-level package names rejected",
			lockURI: "composer.lock",
			input: "{\n" +
				"  \"packages\": [{\"name\": \"dup/pkg\", \"version\": \"1.0.0\"}],\n" +
				"  \"packages-dev\": [{\"name\": \"dup/pkg\", \"version\": \"2.0.0\"}]\n" +
				"}",
			wantErr: "duplicate top-level package",
		},
		{
			name:    "stored SARIF URI remains relative to root",
			lockURI: "subdir/composer.lock",
			input: "{\n" +
				"  \"packages\": [\n" +
				"    {\n" +
				"      \"name\": \"acme/pkg\",\n" +
				"      \"version\": \"1.2.3\"\n" +
				"    }\n" +
				"  ]\n" +
				"}",
			want: composerLockIndex{
				"acme/pkg": {
					PackageName: "acme/pkg",
					Version:     "1.2.3",
					URI:         "subdir/composer.lock",
					Region:      region{StartLine: 5, StartColumn: 7, EndLine: 5, EndColumn: 25},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseComposerLock([]byte(tt.input), tt.lockURI)
			if tt.wantErr != "" {
				if err == nil || !stringContains(err.Error(), tt.wantErr) {
					t.Fatalf("parseComposerLock() error = %v, want substring %q", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseComposerLock() error = %v", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("parseComposerLock() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func stringContains(s, substr string) bool {
	return strings.Contains(s, substr)
}
